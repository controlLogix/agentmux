//go:build linux

package launcher

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

var pendingImageOnce sync.Once
var pendingImage []byte
var pendingImageFailure bool

// This replaces the fixture's synthetic member bytes with one real static
// executable and separately signs the changed assembly. It never executes that
// image: the pending test cancels before cold protected role startup.
func pendingRealBridgeFixture(t *testing.T) bridgeFixture {
	t.Helper()
	pendingImageOnce.Do(func() {
		directory := t.TempDir()
		binary := filepath.Join(directory, "static-role")
		module, err := filepath.Abs("..")
		if err != nil {
			pendingImageFailure = true
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, filepath.Join(goruntime.GOROOT(), "bin", "go"), "build", "-mod=readonly", "-trimpath", "-o", binary, "./runtime/testdata/role")
		command.Dir = module
		command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOENV=off", "GOWORK=off")
		if command.Run() != nil {
			pendingImageFailure = true
			return
		}
		pendingImage, err = os.ReadFile(binary)
		pendingImageFailure = err != nil
	})
	if pendingImageFailure || len(pendingImage) == 0 {
		t.Fatal("prepared static fixture image unavailable")
	}
	f := newBridgeFixture(t)
	policy := copyLocalAdmissionPolicy(*f.config.admissionPolicy)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("fixture release key unavailable")
	}
	release := releaseTestFixture{policy: policy.ExternalRelease, private: private}
	release.policy.PublicKey = public
	raw, err := os.ReadFile(filepath.Join(policy.ExternalRelease.PackageDirectory, "release-manifest.json"))
	if err != nil || json.Unmarshal(raw, &release.manifest) != nil {
		t.Fatal("fixture public manifest unavailable")
	}
	if json.Unmarshal(f.config.Assembly, &release.assembly) != nil {
		t.Fatal("fixture assembly unavailable")
	}
	for _, member := range release.assembly["plugins"].([]any) {
		m := member.(map[string]any)
		if os.WriteFile(filepath.Join(release.policy.PackageDirectory, m["entrypoint"].(string)), pendingImage, 0700) != nil {
			t.Fatal("static contained fixture image unavailable")
		}
		m["binaryDigest"] = releaseDigest(pendingImage)
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
		t.Fatal("actual changed signed enrollment rejected", err)
	}
	f.policy.KernelScope = scope
	f.owner, err = LoadOwnerStatus(f.policy)
	if err != nil {
		t.Fatal("actual rebound owner rejected")
	}
	return f
}

func TestOwnerBridgeRunPublishesGenuinePendingAndJoins(t *testing.T) {
	f := pendingRealBridgeFixture(t)
	f.startBroker(t)
	if _, err := deployment.ProvisionAndProbe(context.Background(), f.config.Health); err != nil {
		t.Fatal("actual FILE health fixture unavailable")
	}
	startup, cancelStartup := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelStartup()
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	defer cancelLifetime()
	// This is a real held bootstrap lease, not a substituted Bootstrap function.
	lease, err := AcquireBootstrapLock(startup, f.profile.ProfileDirectory, f.profile.InstanceID, f.profile.Docker.EngineID)
	if err != nil {
		t.Fatal("actual arbitration lease unavailable")
	}
	defer lease.Close()
	server, err := LoadOwnerBridgeServer(f.config, f.owner, f.enrollment)
	if err != nil {
		t.Fatal("server enrollment rejected")
	}
	client, err := LoadOwnerBridgeClient(f.config, f.enrollment)
	if err != nil {
		t.Fatal("client enrollment rejected")
	}
	cold := "attempt_" + strings.Repeat("a", 32)
	outer := "attempt_" + strings.Repeat("b", 32)
	done := make(chan error, 1)
	go func() { done <- server.Run(startup, lifetime, cold) }()
	request, cancelRequest := context.WithTimeout(context.Background(), 5*time.Second)
	out, err := client.Request(request, "ensure", outer)
	cancelRequest()
	if err != nil || out.Disposition != "starting" || out.StartupAttemptID == nil || *out.StartupAttemptID != cold || !bridgeStartingUnknown(out) {
		t.Fatal("actual in-flight bootstrap pending result unavailable", err)
	}
	if validateOwnerBridgeJSON(mustStatusJSON(out), "startup-status-observation", ownerBridgeReplyLimit) != nil {
		t.Fatal("actual starting output violates L04")
	}
	select {
	case <-done:
		t.Fatal("pending response came from completed Run")
	default:
	}
	if directory := os.Getenv("AGENTMUX_OWNER_BRIDGE_OUTPUTS"); directory != "" {
		os.WriteFile(filepath.Join(directory, "actual-run-starting.json"), mustStatusJSON(out), 0600)
	}
	cancelLifetime()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("actual cancelled Bootstrap completion cause discarded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not cancel and join actual Bootstrap")
	}
	retry, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	service, err := AcquireBootstrapLock(retry, f.profile.ProfileDirectory, f.profile.InstanceID, "owner-status-service")
	if err != nil {
		t.Fatal("joined Run retained service lease")
	}
	if service.Close() != nil {
		t.Fatal("reacquired service lease cleanup failed")
	}
}

func TestOwnerBridgeStartingBoundHasNoReadyFacts(t *testing.T) {
	op, f, _, _, _ := pendingOperationFixture(t)
	if op.enter(op.startup, f.config, f.profile, op.attemptID) != nil {
		t.Fatal("component entry rejected")
	}
	out, err := f.owner.mapStartingContext(context.Background(), op)
	outer := "attempt_" + strings.Repeat("b", 32)
	if err != nil || !bridgeObservationBound(out, f.enrollment, outer, time.Now()) {
		t.Fatal("otherwise-valid separate cold attempt rejected")
	}
	for _, secret := range []string{f.profile.ProfileDirectory, f.config.OwnerBridge.ClientPassword, f.config.OwnerBridge.ServerPassword} {
		if bytes.Contains(mustStatusJSON(out), []byte(secret)) {
			t.Fatal("starting output disclosed private data")
		}
	}
	for _, fault := range []string{"ready_instance", "running_version", "dashboard", "ready_service", "service_receipt", "service_revision", "duplicate_service", "persistence_available", "persistence_ready", "storage_known", "replicas_known", "work_zero", "known_empty_hubs", "attempt_nil", "scope"} {
		t.Run(fault, func(t *testing.T) {
			candidate := out
			candidate.Instance.Services = append([]StartupStatusService(nil), out.Instance.Services...)
			switch fault {
			case "ready_instance":
				candidate.Instance.Readiness = "ready"
			case "running_version":
				candidate.Instance.RunningVersion = statusString("1.2.3")
			case "dashboard":
				candidate.Instance.Dashboard = statusString("https://dashboard.example.invalid")
			case "ready_service":
				candidate.Instance.Services[0].Readiness = "ready"
			case "service_receipt":
				candidate.Instance.Services[0].ObservedAt = statusString(statusTimestamp(time.Now()))
			case "service_revision":
				candidate.Instance.Services[0].SourceRevision = statusRevision(1)
			case "duplicate_service":
				candidate.Instance.Services[1] = candidate.Instance.Services[0]
			case "persistence_available":
				candidate.Persistence.Availability = "available"
			case "persistence_ready":
				candidate.Persistence.Readiness = "ready"
			case "storage_known":
				candidate.Persistence.StoragePressure.PercentUsed = new(float64)
			case "replicas_known":
				candidate.Persistence.ReplicationHealth.Replicas = statusRevision(1)
			case "work_zero":
				candidate.Work.Active = statusRevision(0)
			case "known_empty_hubs":
				candidate.Hubs.InventoryState = "known"
			case "attempt_nil":
				candidate.StartupAttemptID = nil
			case "scope":
				candidate.Caller.Scope.OrganizationID = "another_org"
			}
			if bridgeObservationBound(candidate, f.enrollment, outer, time.Now()) {
				t.Fatal("starting exception admitted unsupported fact")
			}
		})
	}
	candidate := out
	candidate.Disposition = "reused"
	if bridgeObservationBound(candidate, f.enrollment, outer, time.Now()) {
		t.Fatal("different cold attempt escaped starting-only exception")
	}
}

func TestOwnerBridgeRunPendingTransitionsToActualReuse(t *testing.T) {
	f := pendingRealBridgeFixture(t)
	f.startBroker(t)
	if _, err := deployment.ProvisionAndProbe(context.Background(), f.config.Health); err != nil {
		t.Fatal("actual FILE probe unavailable")
	}
	startup, cancelStartup := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelStartup()
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	defer cancelLifetime()
	// Hold actual startup arbitration until the independently running fixture
	// roles have produced a complete ready frame; partial frames remain refused.
	lease, err := AcquireBootstrapLock(startup, f.profile.ProfileDirectory, f.profile.InstanceID, f.profile.Docker.EngineID)
	if err != nil {
		t.Fatal("actual starter arbitration unavailable")
	}
	defer lease.Close()
	server, err := LoadOwnerBridgeServer(f.config, f.owner, f.enrollment)
	if err != nil {
		t.Fatal("server rejected")
	}
	client, err := LoadOwnerBridgeClient(f.config, f.enrollment)
	if err != nil {
		t.Fatal("client rejected")
	}
	cold := "attempt_" + strings.Repeat("c", 32)
	outer := "attempt_" + strings.Repeat("d", 32)
	done := make(chan error, 1)
	go func() { done <- server.Run(startup, lifetime, cold) }()
	out, err := client.Request(startup, "ensure", outer)
	if err != nil || out.Disposition != "starting" || out.StartupAttemptID == nil || *out.StartupAttemptID != cold {
		t.Fatal("actual early pending unavailable", err)
	}
	// Four real in-process role actors now supply scoped TLS snapshots. This is
	// not a four-PID protected process or engine/Compose demonstration.
	f.startActors(t)
	if lease.Close() != nil {
		t.Fatal("actual starter lease release failed")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		out, err = client.Request(startup, "status", outer)
		if err != nil {
			t.Fatal("completed authenticated observation unavailable", err)
		}
		if out.Disposition == "reused" {
			break
		}
		if out.Disposition != "starting" || time.Now().After(deadline) {
			t.Fatal("actual completion did not replace pending")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if out.StartupAttemptID == nil || *out.StartupAttemptID != outer || out.Persistence.Readiness == "ready" || out.Instance.RunningVersion == nil {
		t.Fatal("reuse correlation or unsupported write readiness invented")
	}
	if directory := os.Getenv("AGENTMUX_OWNER_BRIDGE_OUTPUTS"); directory != "" {
		os.WriteFile(filepath.Join(directory, "actual-run-pending-reused.json"), mustStatusJSON(out), 0600)
	}
	cancelLifetime()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("actual reused Run cleanup failed", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("completed Run did not join")
	}
	frame, err := ObserveKernel(startup, f.config.Kernel)
	if err != nil || frame.KernelReadiness != "ready" {
		t.Fatal("reused host adopted or stopped existing role actors", err)
	}
}

func TestOwnerBridgeRunPendingFailureReleasesActualLease(t *testing.T) {
	f := pendingRealBridgeFixture(t)
	f.startBroker(t)
	if _, err := deployment.ProvisionAndProbe(context.Background(), f.config.Health); err != nil {
		t.Fatal("actual FILE probe unavailable")
	}
	// An actual bounded bootstrap expires while waiting for missing role facts.
	// There is no injected return value or simulated Bootstrap function.
	f.config.StartupTimeout = 2 * time.Second
	startup, cancelStartup := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelStartup()
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	defer cancelLifetime()
	server, err := LoadOwnerBridgeServer(f.config, f.owner, f.enrollment)
	if err != nil {
		t.Fatal("server rejected")
	}
	client, err := LoadOwnerBridgeClient(f.config, f.enrollment)
	if err != nil {
		t.Fatal("client rejected")
	}
	cold := "attempt_" + strings.Repeat("e", 32)
	outer := "attempt_" + strings.Repeat("f", 32)
	done := make(chan error, 1)
	go func() { done <- server.Run(startup, lifetime, cold) }()
	first, err := client.Request(startup, "ensure", outer)
	if err != nil || first.Disposition != "starting" {
		t.Fatal("genuine pending failure setup unavailable", err)
	}
	var out StartupStatusObservation
	for {
		out, err = client.Request(startup, "status", outer)
		if err != nil {
			t.Fatal("actual failed completion reply unavailable", err)
		}
		if out.Disposition == "failed" {
			break
		}
		if out.Disposition != "starting" {
			t.Fatal("failed bootstrap invented terminal readiness")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if out.Instance.RunningVersion != nil || out.Persistence.Readiness == "ready" {
		t.Fatal("actual failure invented readiness")
	}
	select {
	case err := <-done:
		if err == nil || err.Error() != "owner_bridge_startup_failed" {
			t.Fatal("actual terminal failure lost", err)
		}
	case <-time.After(time.Second):
		t.Fatal("failed reply did not retire service")
	}
	retry, cancelRetry := context.WithTimeout(context.Background(), time.Second)
	defer cancelRetry()
	lease, err := AcquireBootstrapLock(retry, f.profile.ProfileDirectory, f.profile.InstanceID, "owner-status-service")
	if err != nil {
		t.Fatal("actual failed Run prevented later service acquisition")
	}
	if lease.Close() != nil {
		t.Fatal("actual retry lease cleanup failed")
	}
	if directory := os.Getenv("AGENTMUX_OWNER_BRIDGE_OUTPUTS"); directory != "" {
		os.WriteFile(filepath.Join(directory, "actual-run-pending-failed.json"), mustStatusJSON(out), 0600)
	}
}

func TestOwnerBridgeReceiptActualEntryAndDepartedFrontend(t *testing.T) {
	for _, closed := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted", true: "peer_departed"}[closed], func(t *testing.T) {
			f := pendingRealBridgeFixture(t)
			f.startBroker(t)
			if _, err := deployment.ProvisionAndProbe(context.Background(), f.config.Health); err != nil {
				t.Fatal("actual FILE probe unavailable")
			}
			startup, cancelStartup := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancelStartup()
			lifetime, cancelLifetime := context.WithCancel(context.Background())
			defer cancelLifetime()
			lease, err := AcquireBootstrapLock(startup, f.profile.ProfileDirectory, f.profile.InstanceID, f.profile.Docker.EngineID)
			if err != nil {
				t.Fatal("actual startup arbitration unavailable")
			}
			defer lease.Close()
			server, err := LoadOwnerBridgeServer(f.config, f.owner, f.enrollment)
			if err != nil {
				t.Fatal("server rejected")
			}
			client, err := LoadOwnerBridgeClient(f.config, f.enrollment)
			if err != nil {
				t.Fatal("client rejected")
			}
			cold := "attempt_" + strings.Repeat("1", 32)
			outer := "attempt_" + strings.Repeat("2", 32)
			reader := attachReceiptFixture(t, server, cold)
			if closed {
				reader.Close()
			}
			done := make(chan error, 1)
			go func() { done <- server.Run(startup, lifetime, cold) }()
			joined := false
			defer func() {
				cancelStartup()
				cancelLifetime()
				if !joined {
					select {
					case <-done:
						joined = true
					case <-time.After(3 * time.Second):
						t.Error("receipt Run cleanup did not join actual bootstrap")
					}
				}
			}()
			if !closed {
				frame := readReceiptFrame(t, reader)
				if frame.Outcome != "accepted" || frame.Binding.ColdInvocationID != cold {
					t.Fatal("genuine entered control receipt missing")
				}
			}
			out, err := client.Request(startup, "ensure", outer)
			if err != nil || out.Disposition != "starting" || out.StartupAttemptID == nil || *out.StartupAttemptID != cold {
				t.Fatal("receipt transport changed admitted Bootstrap", err)
			}
			cancelLifetime()
			select {
			case err := <-done:
				joined = true
				if err == nil {
					t.Fatal("actual cancelled completion cause discarded")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("receipt Run did not join actual bootstrap")
			}
		})
	}
}
