//go:build linux

package launcher

import (
	"bytes"
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
	"sync"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/assembly"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

var sessionLifecycleImageOnce sync.Once
var sessionLifecycleImage []byte
var sessionLifecycleBuildError error

func sessionLifecycleDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func sessionLifecycleFixture(t *testing.T) (*Session, *OwnerStatus, *protected.Group) {
	t.Helper()
	sessionLifecycleImageOnce.Do(func() {
		dir := t.TempDir()
		module, err := filepath.Abs("..")
		if err != nil {
			sessionLifecycleBuildError = err
			return
		}
		binary := filepath.Join(dir, "static-role")
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, filepath.Join(goruntime.GOROOT(), "bin", "go"), "build", "-mod=readonly", "-trimpath", "-o", binary, "./runtime/testdata/role")
		cmd.Dir = module
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOENV=off", "GOWORK=off")
		var output bytes.Buffer
		cmd.Stdout, cmd.Stderr = &output, &output
		if err := cmd.Run(); err != nil {
			sessionLifecycleBuildError = errors.New("static role fixture build failed")
			return
		}
		sessionLifecycleImage, sessionLifecycleBuildError = os.ReadFile(binary)
	})
	if sessionLifecycleBuildError != nil {
		t.Fatal("prepared static role fixture unavailable")
	}
	policy, profile := ownerStatusFixture(t)
	dir := t.TempDir()
	members := []map[string]string{}
	var options [4]protected.RoleOptions
	for i, role := range protocol.Roles() {
		if os.WriteFile(filepath.Join(dir, role), sessionLifecycleImage, 0500) != nil {
			t.Fatal("private fixture binary unavailable")
		}
		members = append(members, map[string]string{"id": role, "entrypoint": role, "binaryDigest": sessionLifecycleDigest(sessionLifecycleImage)})
		options[i] = protected.RoleOptions{ID: role, Args: []string{"fixture-child", "ignore-term"}, Env: map[string]string{"AGENTMUX_INSTANCE_ID": profile.InstanceID}}
	}
	authority := assembly.Authority{ID: "session_fixture_authority", OwnerHubID: policy.KernelScope.HubID, Revision: 1}
	raw, err := json.Marshal(map[string]any{"schemaVersion": "1.0.0", "releaseVersion": "1.0.0", "releaseManifestDigest": profile.ReleaseFingerprint, "releaseAuthorityRef": authority, "kernelApiMajor": 1, "plugins": members})
	if err != nil {
		t.Fatal("fixture release encoding failed")
	}
	claim := assembly.Trust{AssemblyDigest: sessionLifecycleDigest(raw), ReleaseManifestDigest: profile.ReleaseFingerprint, ReleaseVersion: "1.0.0", ReleaseAuthority: authority, KernelAPIMajor: 1}
	// The fixture enrollment key is supplied separately from the assembly. Real
	// signature verification creates the trust input; neither JSON nor binary
	// fields authorize themselves. This is not a production installer claim.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("fixture release enrollment unavailable")
	}
	claimBytes, err := json.Marshal(claim)
	if err != nil {
		t.Fatal("fixture signed claim unavailable")
	}
	signature := ed25519.Sign(private, claimBytes)
	if !ed25519.Verify(public, claimBytes, signature) {
		t.Fatal("real fixture release signature rejected")
	}
	changed := append(append([]byte{}, claimBytes...), byte(" "[0]))
	if ed25519.Verify(public, changed, signature) {
		t.Fatal("altered signed release claim accepted")
	}
	policy.KernelScope.AssemblyDigest = claim.AssemblyDigest
	owner, err := LoadOwnerStatus(policy)
	if err != nil {
		t.Fatal("real private owner enrollment rejected")
	}
	prepared, err := protected.Prepare(context.Background(), raw, dir, claim, protected.Limits{})
	if err != nil {
		t.Fatal("actual sealed fixture preparation failed")
	}
	t.Cleanup(func() {
		if prepared.Close() != nil {
			t.Error("owned prepared descriptor cleanup failed")
		}
	})
	group, err := prepared.Start(context.Background(), options, protected.Deadlines{StartTimeout: 3 * time.Second, StopGrace: 50 * time.Millisecond, ReapTimeout: 2 * time.Second})
	if group != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if group.Stop(ctx) != nil {
				t.Error("actual owned fixture cleanup failed")
			}
			select {
			case <-group.Done():
			default:
				t.Error("fixture children not reaped")
			}
		})
	}
	if err != nil {
		t.Fatal("actual four-process supervisor start failed")
	}
	end := time.Now().Add(3 * time.Second)
	for {
		states := group.Status()
		ready := len(states) == 4
		seen := map[int]bool{}
		for _, state := range states {
			if state.Exited || state.PID <= 0 || seen[state.PID] {
				ready = false
			}
			seen[state.PID] = true
			output, truncated := group.Output(state.Role)
			var message struct {
				Role string `json:"role"`
				PID  int    `json:"pid"`
			}
			line := bytes.SplitN(output, []byte("\n"), 2)[0]
			if truncated || json.Unmarshal(line, &message) != nil || message.Role != state.Role || message.PID != state.PID {
				ready = false
			}
		}
		if ready {
			break
		}
		if time.Now().After(end) {
			for _, state := range group.Status() {
				output, truncated := group.Output(state.Role)
				var message struct {
					Role string `json:"role"`
					PID  int    `json:"pid"`
				}
				valid := json.Unmarshal(bytes.SplitN(output, []byte("\n"), 2)[0], &message) == nil
				t.Logf("Safe fixture startup: role=%s exited=%t exitCode=%d outputTruncated=%t outputBytes=%d jsonValid=%t roleMatches=%t pidMatches=%t", state.Role, state.Exited, state.ExitCode, truncated, len(output), valid, message.Role == state.Role, message.PID == state.PID)
			}
			t.Fatal("four distinct real fixture children did not report startup")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// This cached status frame is deliberately synthetic. Real process handles,
	// signatures and lifecycle facts are exercised; no live NATS status is claimed.
	input := ownerObservationFixture(policy, profile, "started")
	return &Session{Status: input.status, group: group, startupAttemptID: input.attemptID, observedAt: input.receivedAt}, owner, group
}

func sessionLifecycleFailed(t *testing.T, out StartupStatusObservation, code string) {
	t.Helper()
	if out.Disposition != "failed" || out.Instance.Readiness != "not_ready" || out.Instance.RunningVersion != nil {
		t.Fatal("known owned lifecycle fact did not override cached success")
	}
	found := false
	for _, err := range out.Errors {
		if err.Code == code {
			found = true
		}
	}
	if !found {
		t.Fatal("known owned lifecycle error was lost")
	}
	for _, service := range out.Instance.Services {
		for _, role := range protocol.Roles() {
			if service.ServiceID == role && (service.Availability != "unavailable" || service.Readiness != "unknown" || service.UnavailableReason == nil || *service.UnavailableReason != "probe_failed" || service.ObservedAt != nil || service.SourceRevision != nil) {
				t.Fatal("exited owned role retained ready claims or invalid contract reason")
			}
		}
	}
	if out.Persistence.Readiness == "ready" || out.Work.Active != nil || out.Hubs.InventoryState != "unavailable" {
		t.Fatal("lifecycle reporting invented other readiness or business state")
	}
}

func writeSessionLifecycleOutput(t *testing.T, name string, out StartupStatusObservation) {
	t.Helper()
	if dir := os.Getenv("AGENTMUX_TEST_LIFECYCLE_OUTPUT"); dir != "" {
		if !filepath.IsAbs(dir) {
			t.Fatal("fixture output must be external absolute path")
		}
		if os.WriteFile(filepath.Join(dir, name+".json"), mustStatusJSON(out), 0600) != nil {
			t.Fatal("safe lifecycle fixture output unavailable")
		}
	}
}

func TestSessionLifecycleActualSingleChildExit(t *testing.T) {
	session, owner, group := sessionLifecycleFixture(t)
	before, err := session.OwnerObservation(owner)
	if err != nil || before.Disposition != "started" {
		t.Fatal("valid synthetic cached frame rejected before actual exit")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if group.StopRole(ctx, "internal-communication") != nil {
		t.Fatal("owned single-child stop failed")
	}
	exited := 0
	for _, state := range group.Status() {
		if state.Exited {
			exited++
			if state.Role != "internal-communication" {
				t.Fatal("unselected child exited")
			}
		}
	}
	if exited != 1 {
		t.Fatal("actual selected child not reaped")
	}
	select {
	case <-group.Done():
		t.Fatal("all-group completion fabricated after one child exit")
	default:
	}
	out, err := session.OwnerObservation(owner)
	if err != nil {
		t.Fatal("local owner observation unavailable")
	}
	sessionLifecycleFailed(t, out, "owned_runtime_exited")
	writeSessionLifecycleOutput(t, "single-child-exit", out)
}

func TestSessionLifecycleActualRetirementAndReusedSeparation(t *testing.T) {
	session, owner, group := sessionLifecycleFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if session.Close(ctx) != nil {
		t.Fatal("actual owned Session close failed")
	}
	select {
	case <-group.Done():
	default:
		t.Fatal("actual whole-group reaping incomplete")
	}
	for _, state := range group.Status() {
		if !state.Exited {
			t.Fatal("retired group retains live child")
		}
	}
	if session.group != nil || session.retiredGroup != group {
		t.Fatal("Session lost actual retired ownership")
	}
	out, err := session.OwnerObservation(owner)
	if err != nil {
		t.Fatal("retired owner observation unavailable")
	}
	sessionLifecycleFailed(t, out, "owned_runtime_exited")
	writeSessionLifecycleOutput(t, "whole-group-retirement", out)
	// A warm cached observation without any owned group cannot infer the other
	// owner's shutdown. Its unchanged snapshot is still subject to freshness.
	reused := &Session{Status: session.Status, startupAttemptID: session.startupAttemptID, observedAt: session.observedAt}
	reused.Status.Disposition = "reused"
	warm, err := reused.OwnerObservation(owner)
	if err != nil || warm.Disposition != "reused" {
		t.Fatal("non-owned reuse was confused with retired owned group")
	}
	writeSessionLifecycleOutput(t, "non-owned-reuse", warm)
}

func TestSessionLifecycleActualFailedStopRetainsCleanup(t *testing.T) {
	session, owner, _ := sessionLifecycleFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if session.Close(ctx) == nil || session.cleanupFailure == nil {
		t.Fatal("actual failed owned Stop was not retained")
	}
	out, err := session.OwnerObservation(owner)
	if err != nil {
		t.Fatal("cleanup-failed observation unavailable")
	}
	sessionLifecycleFailed(t, out, "owned_cleanup_incomplete")
	writeSessionLifecycleOutput(t, "actual-stop-cleanup-failure", out)
	cleanup, finish := context.WithTimeout(context.Background(), 3*time.Second)
	defer finish()
	if session.Close(cleanup) == nil || session.CleanupError() == nil {
		t.Fatal("later reaping erased historical cleanup failure")
	}
}

func TestSessionLifecycleConcurrentCloseAndObservation(t *testing.T) {
	session, owner, group := sessionLifecycleFixture(t)
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan StartupStatusObservation, 16)
	errorsSeen := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			out, err := session.OwnerObservation(owner)
			if err != nil {
				errorsSeen <- err
			} else {
				results <- out
			}
		}()
	}
	closed := make(chan error, 1)
	go func() {
		<-start
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		closed <- session.Close(ctx)
	}()
	close(start)
	wg.Wait()
	close(results)
	close(errorsSeen)
	if err := <-closed; err != nil {
		t.Fatal("concurrent actual owned Close failed")
	}
	for range errorsSeen {
		t.Fatal("concurrent owner observation failed")
	}
	for out := range results {
		if out.Disposition != "started" && out.Disposition != "failed" {
			t.Fatal("concurrent snapshot produced mixed lifecycle disposition")
		}
		if out.Disposition == "failed" {
			sessionLifecycleFailed(t, out, "owned_runtime_exited")
		}
	}
	select {
	case <-group.Done():
	default:
		t.Fatal("concurrent Close did not reap actual owned children")
	}
	out, err := session.OwnerObservation(owner)
	if err != nil {
		t.Fatal("post-close observation failed")
	}
	sessionLifecycleFailed(t, out, "owned_runtime_exited")
	writeSessionLifecycleOutput(t, "post-concurrent-close", out)
}
