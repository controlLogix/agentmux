//go:build darwin && cgo && agentmux_darwin_install

package runtime

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These native tests qualify installed host process ownership, not Docker,
// full kernel startup, NATS observations or the complete macOS product.
func darwinHostFixtureAuthorization(t *testing.T) {
	t.Helper()
	if os.Getenv("AMX_DARWIN_INSTALL_AUTHORIZED") != "1" || os.Geteuid() == 0 {
		t.Fatal("an authorized ordinary-user native install fixture is required")
	}
}
func darwinHostFixtureCommand(t *testing.T, ctx context.Context, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, "/usr/bin/sudo", append([]string{"-n"}, args...)...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	cmd.WaitDelay = time.Second
	if cmd.Run() != nil {
		t.Fatal("bounded privileged installed-host fixture operation failed")
	}
}
func darwinHostFixtureBuild(t *testing.T, ctx context.Context, source string, cgo string) string {
	t.Helper()
	directory := t.TempDir()
	file := filepath.Join(directory, "main.go")
	binary := filepath.Join(directory, "fixture")
	if os.WriteFile(file, []byte(source), 0600) != nil {
		t.Fatal("native host fixture source write failed")
	}
	cmd := exec.CommandContext(ctx, filepath.Join(goruntime.GOROOT(), "bin", "go"), "build", "-o", binary, file)
	cmd.Env = append(os.Environ(), "CGO_ENABLED="+cgo, "GOTOOLCHAIN=local", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off")
	cmd.WaitDelay = time.Second
	if cmd.Run() != nil {
		t.Fatal("native installed-host fixture build failed")
	}
	return binary
}
func darwinHostFixtureInstall(t *testing.T, ctx context.Context, source string) (string, string) {
	t.Helper()
	for _, directory := range []string{"/Library/Application Support", "/Library/Application Support/Agentmux", "/Library/Application Support/Agentmux/Protected", darwinReleaseBase} {
		assertDarwinFixtureDirectory(t, filepath.Dir(directory))
		if _, err := os.Lstat(directory); os.IsNotExist(err) {
			darwinHostFixtureCommand(t, ctx, "/bin/mkdir", directory)
		} else if err != nil {
			t.Fatal("native host fixture ancestor unavailable")
		}
		assertDarwinFixtureDirectory(t, directory)
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal("native host fixture version unavailable")
	}
	directory := filepath.Join(darwinReleaseBase, hex.EncodeToString(nonce[:]))
	darwinHostFixtureCommand(t, ctx, "/bin/mkdir", directory)
	assertDarwinFixtureDirectory(t, directory)
	path := filepath.Join(directory, "agentmux-runtime-fixture")
	darwinHostFixtureCommand(t, ctx, "/usr/bin/install", "-o", "root", "-g", "wheel", "-m", "0555", source, path)
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal("native host fixture digest unavailable")
	}
	sum := sha256.Sum256(raw)
	return path, "sha256:" + hex.EncodeToString(sum[:])
}

const darwinHostFixtureSource = `package main
import("encoding/json";"os";"os/signal";"syscall";"time")
func main(){if len(os.Args)!=8||os.Args[1]!="host"||os.Args[2]!="--host-policy"||os.Args[4]!="--invocation-id"||os.Args[6]!="--workspace"{os.Exit(3)};signals:=make(chan os.Signal,1);signal.Notify(signals,syscall.SIGTERM);raw,_:=json.Marshal(map[string]int{"pid":os.Getpid(),"parentPid":os.Getppid()});if os.WriteFile(os.Args[3],raw,0600)!=nil{os.Exit(4)};select{case <-signals:case <-time.After(10*time.Second):}}
`

func TestDarwinInstalledHostSurvivesFrontendExit(t *testing.T) {
	darwinHostFixtureAuthorization(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	host := darwinHostFixtureBuild(t, ctx, darwinHostFixtureSource, "0")
	path, want := darwinHostFixtureInstall(t, ctx, host)
	const frontendSource = `package main
import("context";"os";"os/signal";"syscall";"time";p "github.com/controlLogix/agentmux/platform/runtime")
func run()(code int){if len(os.Args)!=6{return 2};ctx,cancel:=signal.NotifyContext(context.Background(),syscall.SIGTERM);defer cancel();image,e:=p.PrepareProtectedInstalledHost(ctx,os.Args[1],os.Args[2],128*1024*1024);if e!=nil{return 3};child,e:=image.StartHost(ctx,p.HostInvocation{PolicyPath:os.Args[3],InvocationID:"attempt_00000000000000000000000000000000",WorkspaceRoots:[]string{os.Args[4]}});image.Close();if e!=nil{return 4};handoff:=false;defer func(){if !handoff{stop,c:=context.WithTimeout(context.Background(),2*time.Second);defer c();stopErr:=child.Stop(stop);c();wait,finish:=context.WithTimeout(context.Background(),12*time.Second);defer finish();waitErr:=child.Wait(wait);if stopErr!=nil||waitErr!=nil{code=6}}}();until:=time.Now().Add(5*time.Second);for time.Now().Before(until){select{case <-ctx.Done():return 0;default:};if raw,e:=os.ReadFile(os.Args[5]);e==nil&&string(raw)=="exit"{handoff=true;return 0};time.Sleep(10*time.Millisecond)};return 5}
func main(){os.Exit(run())}
`

	frontend := darwinHostFixtureBuild(t, ctx, frontendSource, "1")
	for _, stage := range []string{"report-decode-failure", "watch-registration-failure", "gate-write-failure", "handoff"} {
		t.Run(stage, func(t *testing.T) {
			childContext, childCancel := context.WithCancel(ctx)
			defer childCancel()
			ctx, cancel := childContext, childCancel
			directory := t.TempDir()
			report, gate := filepath.Join(directory, "host.json"), filepath.Join(directory, "frontend-exit")
			cmd := exec.CommandContext(ctx, frontend, path, want, report, directory, gate)
			cmd.WaitDelay = 16 * time.Second
			cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
			if cmd.Start() != nil {
				t.Fatal("native frontend fixture failed to start")
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait(); close(done) }()
			queue := -1
			watcherAdmitted, childExitObserved := false, false
			handedOff := false
			var childPID int
			defer func() {
				cancel()
				<-done
				if !handedOff && (cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 0) {
					t.Error("frontend did not confirm exact child cleanup before handoff")
				}
				if queue >= 0 {
					defer unix.Close(queue)
				}
				if watcherAdmitted && !childExitObserved {
					events := make([]unix.Kevent_t, 1)
					wait := unix.NsecToTimespec(int64(12 * time.Second))
					count, err := unix.Kevent(queue, nil, events, &wait)
					if err != nil || count != 1 || events[0].Ident != uint64(childPID) || events[0].Fflags&unix.NOTE_EXIT == 0 {
						t.Error("fixture cleanup did not observe the established native child exit")
					}
				}
			}()
			// The child has a fixed ten-second lifetime. No PID obtained from its report
			// grants signal authority; the exact kqueue process event observes its exit.
			var record struct {
				PID       int `json:"pid"`
				ParentPID int `json:"parentPid"`
			}
			until := time.Now().Add(3 * time.Second)
			for time.Now().Before(until) {
				raw, err := os.ReadFile(report)
				if err == nil && json.Unmarshal(raw, &record) == nil && record.PID > 0 {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if record.PID <= 0 || record.ParentPID != cmd.Process.Pid {
				t.Fatal("native host was not created by the actual frontend")
			}
			if stage == "report-decode-failure" {
				// The authentic report establishes actual child creation. This
				// corrupt local input controls a later decode failure, not disk IO.
				var invalid struct {
					PID int `json:"pid"`
				}
				if json.Unmarshal([]byte(`{"pid":`), &invalid) == nil {
					t.Fatal("report decode failure control did not fail")
				}
				return
			}
			var err error
			queue, err = unix.Kqueue()
			if err != nil {
				t.Fatal("native process observation unavailable")
			}
			change := []unix.Kevent_t{{Ident: uint64(record.PID), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT}}
			zero := unix.Timespec{}
			if stage == "watch-registration-failure" {
				// A deliberate invalid descriptor controls a real syscall error.
				// It does not claim failure of native Kqueue creation itself.
				if _, err := unix.Kevent(-1, change, nil, &zero); err == nil {
					t.Fatal("watch registration failure control did not fail")
				}
				return
			}
			registrationEvents := make([]unix.Kevent_t, 1)
			if count, err := unix.Kevent(queue, change, registrationEvents, &zero); err != nil || count != 0 {
				t.Fatal("exact native child exit observation failed")
			}
			watcherAdmitted = true
			childPID = record.PID
			if stage == "gate-write-failure" {
				if os.Mkdir(gate, 0700) != nil {
					t.Fatal("gate failure control setup failed")
				}
				if os.WriteFile(gate, []byte("exit"), 0600) == nil {
					t.Fatal("gate failure control did not fail")
				}
				return
			}
			if os.WriteFile(gate, []byte("exit"), 0600) != nil {
				t.Fatal("frontend exit gate failed")
			}
			handedOff = true
			select {
			case err := <-done:
				if err != nil {
					t.Fatal("native frontend failed to exit cleanly")
				}
			case <-ctx.Done():
				t.Fatal("native frontend exit deadline")
			}
			events := make([]unix.Kevent_t, 1)
			short := unix.NsecToTimespec(int64(100 * time.Millisecond))
			if count, err := unix.Kevent(queue, nil, events, &short); err != nil || count != 0 {
				if err == nil && count == 1 && events[0].Ident == uint64(childPID) && events[0].Fflags&unix.NOTE_EXIT != 0 {
					childExitObserved = true
				}
				t.Fatal("installed host exited with its frontend")
			}
			deadline := unix.NsecToTimespec(int64(12 * time.Second))
			count, err := unix.Kevent(queue, nil, events, &deadline)
			if err != nil || count != 1 || events[0].Ident != uint64(record.PID) || events[0].Fflags&unix.NOTE_EXIT == 0 {
				t.Fatal("bounded exact installed host exit was not observed")
			}
			childExitObserved = true
		})
	}

}

func TestDarwinInstalledHostReplacementRefusal(t *testing.T) {
	darwinHostFixtureAuthorization(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	source := darwinHostFixtureBuild(t, ctx, darwinHostFixtureSource, "0")
	path, want := darwinHostFixtureInstall(t, ctx, source)
	image, err := PrepareProtectedInstalledHost(ctx, path, want, 128*1024*1024)
	if err != nil {
		t.Fatal("protected installed host was not admitted")
	}
	defer image.Close()
	if os.Rename(path, path+"-ordinary-replacement") == nil || os.WriteFile(path, []byte("replacement"), 0555) == nil {
		t.Fatal("ordinary process replaced protected host")
	}
	protected := image.image.(*protectedDarwinExecutable)
	if protected.validateForStart(ctx) != nil {
		t.Fatal("ordinary refusal changed admitted host")
	}
	// Execute the separately built CGO0 API on the same valid protected path.
	// Its refusal is distinct from the CGO1 installation and execution proof.
	const noCGOSource = `package main
import("context";"errors";"os";p "github.com/controlLogix/agentmux/platform/runtime")
func main(){if len(os.Args)!=3{os.Exit(2)};image,e:=p.PrepareProtectedInstalledHost(context.Background(),os.Args[1],os.Args[2],128*1024*1024);if image!=nil||!errors.Is(e,p.ErrPlatformUnqualified){os.Exit(3)}}
`
	noCGO := darwinHostFixtureBuild(t, ctx, noCGOSource, "0")
	refusal := exec.CommandContext(ctx, noCGO, path, want)
	refusal.WaitDelay = time.Second
	if refusal.Run() != nil {
		t.Fatal("native CGO0 protected path did not refuse execution")
	}
	t.Log("Native CGO0 refused the valid protected path; it is not a supported execution backend.")
	// A privileged fixture replacement is permitted only in this fresh retained
	// version. Replacing the inode with equal bytes must still invalidate it.
	replacement := filepath.Join(filepath.Dir(path), "replacement-fixture")
	assertDarwinFixtureDirectory(t, filepath.Dir(path))
	darwinHostFixtureCommand(t, ctx, "/usr/bin/install", "-o", "root", "-g", "wheel", "-m", "0555", source, replacement)
	darwinHostFixtureCommand(t, ctx, "/bin/mv", replacement, path)
	invocation := HostInvocation{PolicyPath: filepath.Join(t.TempDir(), "never-written"), InvocationID: "attempt_00000000000000000000000000000000", WorkspaceRoots: []string{t.TempDir()}}
	child, startErr := image.StartHost(ctx, invocation)
	if child != nil {
		t.Cleanup(func() { stopDarwinFixtureHost(t, child) })
	}
	if startErr == nil || child != nil || startErr.Error() != "installed_host_image_changed" {
		t.Fatal("changed protected host reached spawn")
	}
	if image.consumed || len(protected.files) == 0 {
		t.Fatal("start refusal lost retained descriptors")
	}
}

func stopDarwinFixtureHost(t *testing.T, child *HostProcess) {
	t.Helper()
	stop, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	err := child.Stop(stop)
	cancel()
	if err != nil {
		t.Error("exact owned native fixture stop failed")
	}
	wait, finish := context.WithTimeout(context.Background(), 12*time.Second)
	defer finish()
	if child.Wait(wait) != nil {
		t.Error("exact owned native fixture wait failed")
	}
}

func TestDarwinInstalledHostOwnedStopAndWait(t *testing.T) {
	darwinHostFixtureAuthorization(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	source := darwinHostFixtureBuild(t, ctx, darwinHostFixtureSource, "0")
	path, want := darwinHostFixtureInstall(t, ctx, source)
	image, err := PrepareProtectedInstalledHost(ctx, path, want, 128*1024*1024)
	if err != nil {
		t.Fatal("native owned host image unavailable")
	}
	defer image.Close()
	directory := t.TempDir()
	child, err := image.StartHost(ctx, HostInvocation{PolicyPath: filepath.Join(directory, "host.json"), InvocationID: "attempt_00000000000000000000000000000000", WorkspaceRoots: []string{directory}})
	if child != nil {
		t.Cleanup(func() { stopDarwinFixtureHost(t, child) })
	}
	if err != nil || child == nil {
		t.Fatal("native owned host did not start")
	}
	// Cleanup is installed before observing readiness or making any assertion.
	until := time.Now().Add(3 * time.Second)
	observed := false
	for time.Now().Before(until) {
		if _, err := os.Stat(filepath.Join(directory, "host.json")); err == nil {
			observed = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !observed {
		t.Fatal("native owned host did not report its actual startup")
	}
	stopDarwinFixtureHost(t, child)
	select {
	case <-child.Done():
	default:
		t.Fatal("owned native host was not joined")
	}
}
