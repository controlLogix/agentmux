//go:build linux

package launcher

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"golang.org/x/sys/unix"
)

func installedCLIBuild(t *testing.T, target, output string) {
	t.Helper()
	module, err := filepath.Abs("..")
	if err != nil {
		t.Fatal("module path unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(goruntime.GOROOT(), "bin", "go"), "build", "-mod=readonly", "-trimpath", "-o", output, target)
	cmd.Dir = module
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOENV=off", "GOWORK=off")
	cmd.WaitDelay = time.Second
	if cmd.Run() != nil || os.Chmod(output, 0700) != nil {
		t.Fatal("actual installed executable build failed")
	}
}

// Each case re-signs its actual role image and rebinds the private scope. The
// pending case never executes the inert fixture roles. Completion uses the
// actual agentmux-kernel executable, not in-process actors.
func installedCLIRoleFixture(t *testing.T, kernel []byte) bridgeFixture {
	t.Helper()
	f := pendingRealBridgeFixture(t)
	if kernel == nil {
		return f
	}
	policy := copyLocalAdmissionPolicy(*f.config.admissionPolicy)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("test signing key unavailable")
	}
	release := releaseTestFixture{policy: policy.ExternalRelease, private: private}
	release.policy.PublicKey = public
	raw, err := os.ReadFile(filepath.Join(release.policy.PackageDirectory, "release-manifest.json"))
	if err != nil || json.Unmarshal(raw, &release.manifest) != nil || json.Unmarshal(f.config.Assembly, &release.assembly) != nil {
		t.Fatal("actual release fixture unavailable")
	}
	for _, member := range release.assembly["plugins"].([]any) {
		m := member.(map[string]any)
		if os.WriteFile(filepath.Join(release.policy.PackageDirectory, m["entrypoint"].(string)), kernel, 0700) != nil {
			t.Fatal("actual kernel image enrollment failed")
		}
		m["binaryDigest"] = releaseDigest(kernel)
	}
	release.refresh(t)
	policy.ExternalRelease = release.policy
	scope := f.config.Kernel.Scope
	scope.AssemblyDigest = release.authorization.AssemblyDigest
	policy.OwnerBridge.Scope = scope
	trust := protocol.ServerTrustRecord{SchemaVersion: protocol.Version, Endpoint: f.profile.NATSEndpoint, ServerName: f.config.LocalTLS.ServerName(), RootsPEM: string(f.config.LocalTLS.RootsPEM()), LeafCertificateSHA256: f.config.LocalTLS.LeafCertificateSHA256(), Scope: scope}
	trustRaw := mustStatusJSON(trust)
	f.profile.ServerTrustDigest = releaseDigest(trustRaw)
	releaseTestWrite(t, f.profile.ProfileDirectory, localServerTrustFile, trustRaw)
	releaseTestWrite(t, f.profile.ProfileDirectory, "profile.json", mustStatusJSON(f.profile))
	for _, role := range protocol.Roles() {
		releaseTestWrite(t, f.profile.ProfileDirectory, role+".json", mustStatusJSON(protocol.Credentials{SchemaVersion: protocol.Version, Role: role, Username: role, Password: f.users[role], NATSURL: f.profile.NATSEndpoint, Scope: scope}))
	}
	for role, name := range map[string]string{deployment.OwnerBridgeServerUser: f.enrollment.Credentials.Server, deployment.OwnerBridgeClientUser: f.enrollment.Credentials.Client} {
		password := f.config.OwnerBridge.ClientPassword
		if role == deployment.OwnerBridgeServerUser {
			password = f.config.OwnerBridge.ServerPassword
		}
		releaseTestWrite(t, f.profile.ProfileDirectory, name, mustStatusJSON(OwnerBridgeCredential{protocol.Version, role, scope, f.enrollment.Owner, password}))
	}
	f.config, err = LoadBootstrapConfig(policy)
	if err != nil {
		t.Fatal("actual signed kernel admission failed", err)
	}
	f.policy.KernelScope = scope
	f.owner, err = LoadOwnerStatus(f.policy)
	if err != nil {
		t.Fatal("actual rebound owner rejected")
	}
	return f
}

func installedCLIPolicy(t *testing.T, f *bridgeFixture, executable string) (HostPolicySelection, hostPolicyRecord) {
	t.Helper()
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("private installed fixture unavailable")
	}
	content, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal("actual runtime image unavailable")
	}
	installed := filepath.Join(root, "agentmux-runtime")
	if os.WriteFile(installed, content, 0700) != nil {
		t.Fatal("actual runtime installation failed")
	}
	// The protected child environment intentionally excludes fixture variables.
	// This fixed test inspector supplies its one private fixture path itself.
	// Inspection remains synthetic; the TLS broker and FILE storage are real.
	spec := filepath.Join(root, "inspection.json")
	if os.WriteFile(spec, mustStatusJSON(bridgeDockerSpec{f.profile, f.raw, f.config.BrokerImage, f.config.LocalTLS.ServerCertificatePEM(), f.config.LocalTLS.ServerKeyPEM()}), 0600) != nil {
		t.Fatal("private inspection fixture unavailable")
	}
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal("inspection executable unavailable")
	}
	wrapperSource := filepath.Join(root, "inspector.go")
	body := fmt.Sprintf("package main\nimport(\"os\";\"os/exec\")\nfunc main(){c:=exec.Command(%q,os.Args[1:]...);c.Env=append(os.Environ(),%q,\"GORACE=atexit_sleep_ms=0\");c.Stdout=os.Stdout;c.Stderr=os.Stderr;if c.Run()!=nil{os.Exit(3)}}\n", testBinary, "AMX_OWNER_BRIDGE_DOCKER_FIXTURE="+spec)
	if os.WriteFile(wrapperSource, []byte(body), 0600) != nil {
		t.Fatal("fixed inspector source unavailable")
	}
	wrapper := filepath.Join(root, "inspector")
	installedCLIBuild(t, wrapperSource, wrapper)
	f.profile.Docker.Executable = wrapper
	releaseTestWrite(t, f.profile.ProfileDirectory, "profile.json", mustStatusJSON(f.profile))
	policy := copyLocalAdmissionPolicy(*f.config.admissionPolicy)
	f.config, err = LoadBootstrapConfig(policy)
	if err != nil {
		t.Fatal("fixed inspector admission failed", err)
	}
	p := policy.ExternalRelease
	r := hostPolicyRecord{SchemaVersion: protocol.Version, OwnerUID: f.profile.OwnerUID, ProfileDirectory: f.profile.ProfileDirectory, ProfileID: f.profile.ProfileID, InstanceID: f.profile.InstanceID, Owner: f.enrollment.Owner, ServerName: f.policy.ServerName, Domain: f.policy.Domain, PublicEndpoint: f.profile.NATSEndpoint, PublicContextName: f.profile.Docker.Context, RuntimeExecutable: hostPolicyExecutable{installed, releaseDigest(content)}, Limits: hostPolicyLimits{30000, 3000, 10000, 2000, 2000}, OwnerBridge: &f.enrollment.Credentials, Release: hostPolicyRelease{p.PackageDirectory, hex.EncodeToString(p.PublicKey), p.ReleaseManifestDigest, p.ReleaseAuthority, p.ReleaseVersion, p.KernelAPIMajor}}
	s := HostPolicySelection{Path: filepath.Join(root, "host-policy.json"), OwnerUID: f.profile.OwnerUID, WorkspaceRoots: append([]string(nil), policy.Profile.WorkspaceRoots...)}
	writeInstalledHostPolicy(t, s.Path, r)
	if _, err := LoadEnrolledHostPolicy(s); err != nil {
		t.Fatal("real installed policy rejected", err)
	}
	return s, r
}

// Child identities come from the live creator's kernel child lists, never a
// report PID. Pin a candidate first, then check its live parent, literal argv
// and held executable bytes before using that exact handle for cleanup.
func installedCLIChildren(parent int) []int {
	var result []int
	tasks, _ := os.ReadDir(fmt.Sprintf("/proc/%d/task", parent))
	for _, task := range tasks {
		raw, _ := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/children", parent, task.Name()))
		for _, word := range strings.Fields(string(raw)) {
			if pid, err := strconv.Atoi(word); err == nil {
				result = append(result, pid)
			}
		}
	}
	return result
}

func installedCLIPinChild(parent int, expectedDigest string, expectedArgs []string) (int, int) {
	for _, pid := range installedCLIChildren(parent) {
		fd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			continue
		}
		status, se := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		args, ae := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		image, ie := os.ReadFile(fmt.Sprintf("/proc/%d/exe", pid))
		actualArgs := strings.Split(strings.TrimSuffix(string(args), "\x00"), "\x00")
		parentOK := strings.Contains(string(status), fmt.Sprintf("PPid:\t%d\n", parent))
		argvOK := len(actualArgs) > 0 && (expectedArgs == nil || reflect.DeepEqual(actualArgs[1:], expectedArgs))
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, pe := unix.Poll(poll, 0)
		if se == nil && ae == nil && ie == nil && parentOK && argvOK && releaseDigest(image) == expectedDigest && pe == nil && n == 0 {
			return fd, pid
		}
		unix.Close(fd)
	}
	return -1, 0
}

func installedCLIStop(t *testing.T, fd int) {
	t.Helper()
	defer unix.Close(fd)
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	if n, err := unix.Poll(poll, 0); err == nil && n == 1 {
		return
	}
	if unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0) != nil {
		t.Error("exact installed host stop failed")
		return
	}
	if n, err := unix.Poll(poll, 6000); err != nil || n != 1 {
		unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
		if n, err = unix.Poll(poll, 2000); err != nil || n != 1 {
			t.Error("exact installed host exit was not joined")
		}
		t.Error("installed host required forced cleanup")
	}
}

func TestInstalledCLIGenuineStartupAndDetachedLifetime(t *testing.T) {
	dir := t.TempDir()
	runtimeBinary, kernelBinary := filepath.Join(dir, "agentmux-runtime"), filepath.Join(dir, "agentmux-kernel")
	installedCLIBuild(t, "./cmd/agentmux-runtime", runtimeBinary)
	installedCLIBuild(t, "./cmd/agentmux-kernel", kernelBinary)
	kernel, err := os.ReadFile(kernelBinary)
	if err != nil {
		t.Fatal("actual kernel image unavailable")
	}
	for _, completion := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "completion"}[completion], func(t *testing.T) {
			var roles []byte
			if completion {
				roles = kernel
			}
			f := installedCLIRoleFixture(t, roles)
			f.startBroker(t)
			if _, err := deployment.ProvisionAndProbe(context.Background(), f.config.Health); err != nil {
				t.Fatal("actual FILE probe unavailable", err)
			}
			s, r := installedCLIPolicy(t, &f, runtimeBinary)
			leaseCtx, cancelLease := context.WithTimeout(context.Background(), time.Second)
			lease, err := AcquireBootstrapLock(leaseCtx, f.profile.ProfileDirectory, f.profile.InstanceID, f.profile.Docker.EngineID)
			cancelLease()
			if err != nil {
				t.Fatal("actual bootstrap arbitration unavailable")
			}
			defer lease.Close()
			args := []string{"ensure", "--host-policy", s.Path}
			for _, root := range s.WorkspaceRoots {
				args = append(args, "--workspace", root)
			}
			front := exec.Command(r.RuntimeExecutable.Path, args...)
			var stdout, stderr bytes.Buffer
			front.Stdout, front.Stderr = &stdout, &stderr
			started := time.Now()
			if front.Start() != nil {
				t.Fatal("actual installed frontend failed")
			}
			done := make(chan error, 1)
			var exited time.Time
			go func() { err := front.Wait(); exited = time.Now(); done <- err }()
			joined := false
			t.Cleanup(func() {
				if !joined {
					front.Process.Signal(unix.SIGTERM)
					select {
					case <-done:
					case <-time.After(3 * time.Second):
						front.Process.Kill()
						<-done
					}
					joined = true
				}
			})
			hostFD, hostPID := -1, 0
			hostAttempt := ""
			var kernelHandles []int
			deadline := started.Add(10 * time.Second)
			for hostFD < 0 && time.Now().Before(deadline) {
				for _, pid := range installedCLIChildren(front.Process.Pid) {
					cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
					parts := strings.Split(strings.TrimSuffix(string(cmdline), "\x00"), "\x00")
					if len(parts) < 6 || parts[1] != "host" || parts[2] != "--host-policy" || parts[3] != s.Path || parts[4] != "--invocation-id" {
						continue
					}
					if !ownerBridgeInvocation.MatchString(parts[5]) {
						continue
					}
					expected := []string{"host", "--host-policy", s.Path, "--invocation-id", parts[5]}
					for _, root := range s.WorkspaceRoots {
						expected = append(expected, "--workspace", root)
					}
					hostFD, hostPID = installedCLIPinChild(front.Process.Pid, r.RuntimeExecutable.Digest, expected)
					if hostFD >= 0 {
						hostAttempt = parts[5]
						break
					}
				}
				if hostFD < 0 {
					time.Sleep(time.Millisecond)
				}
			}
			if hostFD < 0 {
				t.Fatal("actual creator-owned host handle unavailable")
			}
			t.Cleanup(func() {
				installedCLIStop(t, hostFD)
				for _, fd := range kernelHandles {
					poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
					if n, e := unix.Poll(poll, 1000); e != nil || n != 1 {
						t.Error("protected child retained after owned host cleanup")
					}
					unix.Close(fd)
				}
			})
			t.Logf("Exact host handle established after %s", time.Since(started))
			select {
			case err := <-done:
				joined = true
				if err != nil {
					t.Fatal("actual frontend did not return authenticated startup", stderr.String())
				}
			case <-time.After(time.Until(deadline)):
				select {
				case <-done:
					joined = true
					t.Logf("Frontend actually exited after %s; output bytes %d; safe error bytes %d", exited.Sub(started), stdout.Len(), stderr.Len())
					if root := os.Getenv("AGENTMUX_INSTALLED_CLI_OUTPUTS"); root != "" {
						os.WriteFile(filepath.Join(root, "deadline-stdout.json"), stdout.Bytes(), 0600)
						os.WriteFile(filepath.Join(root, "deadline-stderr.txt"), stderr.Bytes(), 0600)
					}
				case <-time.After(3 * time.Second):
				}
				t.Fatal("actual frontend exceeded ten seconds")
			}
			if time.Since(started) > 10*time.Second {
				t.Fatal("actual invocation entry exceeded ten seconds")
			}
			t.Logf("Actual frontend exited after %s", exited.Sub(started))
			if root := os.Getenv("AGENTMUX_INSTALLED_CLI_OUTPUTS"); root != "" {
				os.WriteFile(filepath.Join(root, t.Name()[strings.LastIndex(t.Name(), "/")+1:]+"-stdout.json"), stdout.Bytes(), 0600)
				os.WriteFile(filepath.Join(root, t.Name()[strings.LastIndex(t.Name(), "/")+1:]+"-timing.json"), mustStatusJSON(map[string]any{"entryToExitNanoseconds": exited.Sub(started).Nanoseconds(), "boundNanoseconds": int64(10 * time.Second)}), 0600)
			}
			var out StartupStatusObservation
			if json.Unmarshal(stdout.Bytes(), &out) != nil || out.Disposition != "starting" || out.StartupAttemptID == nil || *out.StartupAttemptID != hostAttempt || !bridgeStartingUnknown(out) {
				t.Fatal("actual frontend returned no authenticated starting frame")
			}
			cold := *out.StartupAttemptID
			client, err := LoadOwnerBridgeClient(f.config, f.enrollment)
			if err != nil {
				t.Fatal("actual refresh client unavailable")
			}
			outer := "attempt_" + strings.Repeat("e", 32)
			request, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			fresh, err := client.Request(request, "status", outer)
			cancel()
			if err != nil || fresh.Disposition != "starting" || fresh.StartupAttemptID == nil || *fresh.StartupAttemptID != cold || cold == outer {
				t.Fatal("frontend exit lost owning operation or cold correlation", err)
			}
			poll := []unix.PollFd{{Fd: int32(hostFD), Events: unix.POLLIN}}
			if n, err := unix.Poll(poll, 0); err != nil || n != 0 {
				t.Fatal("owning host exited with frontend")
			}
			if !completion {
				return
			}
			if lease.Close() != nil {
				t.Fatal("actual starter lease release failed")
			}
			deadline = time.Now().Add(15 * time.Second)
			for {
				request, cancel = context.WithTimeout(context.Background(), 5*time.Second)
				fresh, err = client.Request(request, "status", outer)
				cancel()
				if err != nil {
					t.Fatal("actual kernel completion observation failed", err)
				}
				if fresh.Disposition == "started" || fresh.Disposition == "reused" {
					break
				}
				if fresh.Disposition != "starting" || time.Now().After(deadline) {
					t.Fatal("actual protected kernel did not complete startup")
				}
			}
			if fresh.Instance.RunningVersion == nil || fresh.Instance.Readiness != "degraded" {
				t.Fatal("actual completed runtime lacks ready kernel evidence")
			}
			for _, role := range protocol.Roles() {
				found := false
				for _, service := range fresh.Instance.Services {
					if service.ServiceID == role && service.Readiness == "ready" && service.ObservedAt != nil && service.SourceRevision != nil {
						found = true
					}
				}
				if !found {
					t.Fatal("completed protected role lacks current readiness evidence")
				}
			}
			seenRoles := map[string]bool{}
			for _, pid := range installedCLIChildren(hostPID) {
				fd, e := unix.PidfdOpen(pid, 0)
				if e != nil {
					continue
				}
				image, e := os.ReadFile(fmt.Sprintf("/proc/%d/exe", pid))
				status, se := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
				env, ee := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
				args, ae := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
				role := ""
				for _, candidate := range protocol.Roles() {
					for _, value := range strings.Split(string(env), "\x00") {
						if value == "AGENTMUX_NATS_CREDS_FILE="+filepath.Join(f.profile.ProfileDirectory, candidate+".json") {
							role = candidate
						}
					}
				}
				poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
				n, pe := unix.Poll(poll, 0)
				if e != nil || se != nil || ee != nil || ae != nil || pe != nil || n != 0 || role == "" || seenRoles[role] || !strings.Contains(string(status), fmt.Sprintf("PPid:\t%d\n", hostPID)) || len(strings.Split(strings.TrimSuffix(string(args), "\x00"), "\x00")) != 1 || releaseDigest(image) != releaseDigest(kernel) {
					unix.Close(fd)
					continue
				}
				kernelHandles = append(kernelHandles, fd)
				seenRoles[role] = true
			}
			if len(kernelHandles) != 4 {
				t.Fatal("actual completed host does not own four kernel processes")
			}
			// Stop the exact pinned host and require all pinned protected children
			// to exit through their actual inherited lifetime channel.
			if unix.PidfdSendSignal(hostFD, unix.SIGTERM, nil, 0) != nil {
				t.Fatal("actual completed host stop failed")
			}
			for _, fd := range append(append([]int(nil), kernelHandles...), hostFD) {
				poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
				if n, e := unix.Poll(poll, 6000); e != nil || n != 1 {
					t.Fatal("actual protected descendant exit was not joined")
				}
			}
		})
	}
}
