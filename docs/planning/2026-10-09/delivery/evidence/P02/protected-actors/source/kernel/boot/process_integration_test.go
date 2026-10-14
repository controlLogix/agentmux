//go:build linux

package boot_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/assembly"
	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
	"github.com/nats-io/nats.go"
)

func processDigest(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

type releaseAuthorization struct {
	AssemblyDigest        string             `json:"assemblyDigest"`
	ReleaseManifestDigest string             `json:"releaseManifestDigest"`
	ReleaseVersion        string             `json:"releaseVersion"`
	Authority             assembly.Authority `json:"authority"`
	KernelAPIMajor        int                `json:"kernelApiMajor"`
}

// This fixture verifies real signatures against a separately supplied enrollment key.
// It does not add a production installer/enrollment service to the protected kernel.
func trustedFixtureRelease(claim releaseAuthorization, signature []byte, enrolledKey ed25519.PublicKey) (assembly.Trust, error) {
	bytes, err := json.Marshal(claim)
	if err != nil || !ed25519.Verify(enrolledKey, bytes, signature) {
		return assembly.Trust{}, errors.New("fixture_release_signature_invalid")
	}
	return assembly.Trust{AssemblyDigest: claim.AssemblyDigest, ReleaseManifestDigest: claim.ReleaseManifestDigest, ReleaseVersion: claim.ReleaseVersion, ReleaseAuthority: claim.Authority, KernelAPIMajor: claim.KernelAPIMajor}, nil
}

func staticKernelFixture(t *testing.T, f *fixture) (string, []byte, assembly.Trust, [4]protected.RoleOptions) {
	t.Helper()
	module, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "static-kernel")
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	tool := filepath.Join(goruntime.GOROOT(), "bin", "go")
	cmd := exec.CommandContext(ctx, tool, "build", "-mod=readonly", "-trimpath", "-o", binary, "./cmd/agentmux-kernel")
	cmd.Dir = module
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOENV=off", "GOFLAGS=", "GOWORK=off")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("static fixture build failed: %s", output)
	}
	image, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	packageDir := filepath.Join(dir, "release")
	if err := os.Mkdir(packageDir, 0700); err != nil {
		t.Fatal(err)
	}
	authority := assembly.Authority{ID: "fixture_release_authority", OwnerHubID: f.scope.HubID, Revision: 1}
	parentBytes := []byte(`{"product":"fixture-agentmux","releaseVersion":"1.0.0","protectedApiMajor":1}`)
	parentDigest := processDigest(parentBytes)
	plugins := []map[string]string{}
	for _, role := range protocol.Roles() {
		if err := os.WriteFile(filepath.Join(packageDir, role), image, 0500); err != nil {
			t.Fatal(err)
		}
		plugins = append(plugins, map[string]string{"id": role, "entrypoint": role, "binaryDigest": processDigest(image)})
	}
	raw, err := json.Marshal(map[string]any{"schemaVersion": "1.0.0", "releaseVersion": "1.0.0", "releaseManifestDigest": parentDigest, "releaseAuthorityRef": authority, "kernelApiMajor": 1, "plugins": plugins})
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("fixture enrollment entropy unavailable")
	}
	claim := releaseAuthorization{processDigest(raw), parentDigest, "1.0.0", authority, 1}
	signed, _ := json.Marshal(claim)
	signature := ed25519.Sign(private, signed)
	trust, err := trustedFixtureRelease(claim, signature, public)
	if err != nil {
		t.Fatal("fixture trust verification failed")
	}
	changed := claim
	changed.AssemblyDigest = "sha256:" + strings.Repeat("c", 64)
	if _, err := trustedFixtureRelease(changed, signature, public); err == nil {
		t.Fatal("altered signed assembly binding accepted")
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trustedFixtureRelease(claim, signature, other); err == nil {
		t.Fatal("message key substituted for enrolled release key")
	}
	f.scope.AssemblyDigest = trust.AssemblyDigest
	f.scope.ReleaseManifestDigest = trust.ReleaseManifestDigest
	f.scope.ReleaseVersion = trust.ReleaseVersion
	configs := filepath.Join(dir, "role-configs")
	if err := os.Mkdir(configs, 0700); err != nil {
		t.Fatal(err)
	}
	var options [4]protected.RoleOptions
	for i, role := range protocol.Roles() {
		creds := protocol.Credentials{SchemaVersion: protocol.Version, Role: role, Username: role, Password: f.secrets[role], NATSURL: f.url, Scope: f.scope}
		bytes, _ := json.Marshal(creds)
		path := filepath.Join(configs, role+".json")
		if err := os.WriteFile(path, bytes, 0400); err != nil {
			t.Fatal("private role fixture write failed")
		}
		options[i] = protected.RoleOptions{ID: role, Env: map[string]string{"AGENTMUX_NATS_URL": f.url, "AGENTMUX_NATS_CREDS_FILE": path, "AGENTMUX_INSTANCE_ID": f.scope.InstanceID, "AGENTMUX_PROFILE_ID": f.scope.ProfileID}}
	}
	t.Log("fixtureReleaseSignatureVerified=true enrolledKeySeparatelyTrusted=true staticKernel=true")
	return packageDir, raw, trust, options
}

func processSnapshot(t *testing.T, sub *nats.Subscription, scope protocol.Scope, predicate func(protocol.Snapshot) bool) protocol.Snapshot {
	t.Helper()
	until := time.Now().Add(10 * time.Second)
	for time.Now().Before(until) {
		message, err := sub.NextMsg(time.Second)
		if err != nil {
			continue
		}
		snapshot, err := protocol.DecodeSnapshot(message.Data, scope, time.Now(), 3*time.Second)
		if err != nil {
			t.Fatal("real process snapshot failed validation")
		}
		if predicate(snapshot) {
			return snapshot
		}
	}
	t.Fatal("real protected process observation deadline exceeded")
	return protocol.Snapshot{}
}

func TestFourSealedProtectedProcessesSignedReleaseAndOwnedShutdown(t *testing.T) {
	f := setup(t)
	packageDir, raw, trust, options := staticKernelFixture(t, &f)
	prepareCtx, prepareCancel := context.WithTimeout(context.Background(), 10*time.Second)
	prepared, err := protected.Prepare(prepareCtx, raw, packageDir, trust, protected.Limits{})
	prepareCancel()
	if err != nil {
		t.Fatal("signed static assembly preparation failed:", err)
	}
	defer prepared.Close()
	parent, parentCancel := context.WithCancel(context.Background())
	defer parentCancel()
	group, err := prepared.Start(parent, options, protected.Deadlines{StartTimeout: 5 * time.Second, StopGrace: time.Second, ReapTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal("real four-role start failed:", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if err := group.Stop(ctx); err != nil {
			t.Error("owned cleanup incomplete:", err)
		}
	})
	processes := group.Status()
	if len(processes) != 4 {
		t.Fatal("protected assembly did not create four children")
	}
	seen := map[int]bool{}
	for _, process := range processes {
		if process.PID <= 0 || seen[process.PID] || process.Exited {
			t.Fatal("protected child identity is not distinct and live")
		}
		seen[process.PID] = true
	}
	reader := f.client(t, communication.OrdinaryPlugin)
	sub, err := reader.SubscribeSync(f.wire.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	reader.FlushTimeout(time.Second)
	first := processSnapshot(t, sub, f.scope, func(s protocol.Snapshot) bool { return s.KernelReadiness == "ready" })
	late := f.client(t, communication.OrdinaryPlugin)
	lateSub, err := late.SubscribeSync(f.wire.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	updates, err := late.SubscribeSync(f.wire.Update)
	if err != nil {
		t.Fatal(err)
	}
	late.FlushTimeout(time.Second)
	next := processSnapshot(t, lateSub, f.scope, func(s protocol.Snapshot) bool { return s.KernelReadiness == "ready" })
	if next.Incarnation != first.Incarnation || next.Revision <= first.Revision {
		t.Fatal("late real-process snapshot lost revision/source continuity")
	}
	update, err := updates.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatal("real process update missing")
	}
	if _, err := protocol.DecodeSnapshot(update.Data, f.scope, time.Now(), 3*time.Second); err != nil {
		t.Fatal("real process update invalid")
	}
	for _, process := range group.Status() {
		if process.Exited {
			t.Fatal("role exited before controlled failure")
		}
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
	err = group.StopRole(stopCtx, "internal-communication")
	stopCancel()
	if err != nil {
		t.Fatal("owned role failure cleanup incomplete:", err)
	}
	lost := processSnapshot(t, sub, f.scope, func(s protocol.Snapshot) bool {
		for _, m := range s.Members {
			if m.Role == "internal-communication" && m.State != "ready" && m.State != "unknown" {
				return true
			}
		}
		return false
	})
	if lost.KernelReadiness == "ready" {
		t.Fatal("failed actual role left kernel healthy")
	}
	for _, process := range group.Status() {
		if process.Role == "internal-communication" {
			if !process.Exited {
				t.Fatal("failed role was not actually reaped")
			}
		} else if process.Exited {
			t.Fatal("per-role stop affected another protected process")
		}
	}
	processSnapshot(t, sub, f.scope, func(s protocol.Snapshot) bool {
		for _, m := range s.Members {
			if m.Role == "internal-communication" && m.State == "stale" {
				return true
			}
		}
		return false
	})
	shutdown, shutdownCancel := context.WithTimeout(context.Background(), 4*time.Second)
	err = group.Stop(shutdown)
	shutdownCancel()
	if err != nil {
		t.Fatal("owned shutdown incomplete:", err)
	}
	select {
	case <-group.Done():
	default:
		t.Fatal("all protected child Wait results not complete")
	}
	for _, process := range group.Status() {
		if !process.Exited {
			t.Fatal("owned child remained alive after shutdown")
		}
		bytes, truncated := group.Output(process.Role)
		if truncated || len(bytes) != 0 {
			t.Fatal("healthy kernel role emitted unexpected process diagnostics")
		}
	}
	t.Log("independentProtectedPIDs=4 realBrokerStatus=true lateSnapshot=true ownedRoleReaped=true expiredRoleStale=true allOwnedChildrenReaped=true")
}
