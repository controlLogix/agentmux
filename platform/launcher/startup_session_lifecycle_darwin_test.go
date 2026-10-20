//go:build darwin && cgo && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

// The fixture's cached status frame is deliberately synthetic. These controls
// exercise real owned process lifecycle facts; they do not claim live NATS status.
func sessionLifecycleFailed(t *testing.T, out StartupStatusObservation, code string, exitedRoles ...string) {
	t.Helper()
	if out.Disposition != "failed" || out.Instance.Readiness != "not_ready" {
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
	if len(exitedRoles) == 4 && out.Instance.RunningVersion != nil {
		t.Fatal("completed group retained a current running version")
	}
	for _, service := range out.Instance.Services {
		for _, role := range exitedRoles {
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
	sessionLifecycleFailed(t, out, "owned_runtime_exited", "internal-communication")
	for _, service := range out.Instance.Services {
		for _, role := range protocol.Roles() {
			if role != "internal-communication" && service.ServiceID == role && service.Readiness != "ready" {
				t.Fatal("one exited role erased a fresh independently observed sibling")
			}
		}
	}
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
	sessionLifecycleFailed(t, out, "owned_runtime_exited", "boot", "kernel-lifecycle", "internal-communication", "exported-status")
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
			sessionLifecycleFailed(t, out, "owned_runtime_exited", "boot", "kernel-lifecycle", "internal-communication", "exported-status")
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
	sessionLifecycleFailed(t, out, "owned_runtime_exited", "boot", "kernel-lifecycle", "internal-communication", "exported-status")
	writeSessionLifecycleOutput(t, "post-concurrent-close", out)
}
