//go:build linux

package launcher

import (
	"context"
	"errors"
	protected "github.com/controlLogix/agentmux/platform/runtime"
	"strings"
	"testing"
	"time"
)

func TestBootstrapHistoryPreEntryActualFailureChronology(t *testing.T) {
	op, f, _, _, _ := pendingOperationFixture(t)
	actual := errors.New("actual_pre_entry_failure")
	if op.complete(nil, actual) != nil {
		t.Fatal("actual completion unavailable")
	}
	binding := protected.BootstrapReceiptBinding{Scope: op.scope, EnrollmentDigest: historyDigest(mustStatusJSON(f.enrollment.Owner)), ColdInvocationID: op.attemptID, RuntimeDigest: "sha256:" + strings.Repeat("d", 64)}
	store, err := openBootstrapHistory(op.startup, op, binding)
	if store != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if store.Close(ctx) != nil {
				t.Error("exact store cleanup failed")
			}
		})
	}
	if err != nil {
		t.Fatal("private history construction failed")
	}
	if store.RecordTerminal(op.startup) != nil {
		t.Fatal("real pre-entry completion chronology refused")
	}
	if store.state.expected.LatestAttempt.Terminal.Outcome != "failed" {
		t.Fatal("actual failure not recorded")
	}
}

func TestBootstrapHistoryFailureFinalizationUsesJoinedEnvelope(t *testing.T) {
	op, f, _, cancelStartup, _ := pendingOperationFixture(t)
	binding := protected.BootstrapReceiptBinding{Scope: op.scope, EnrollmentDigest: historyDigest(mustStatusJSON(f.enrollment.Owner)), ColdInvocationID: op.attemptID, RuntimeDigest: "sha256:" + strings.Repeat("d", 64)}
	op.server.history = newOwnerBridgeHistoryState(binding)
	returned := make(chan struct{})
	op.server.history.returned = returned
	cause := errors.New("actual_failed_bootstrap")
	if op.complete(nil, cause) != nil {
		t.Fatal("actual failure unavailable")
	}
	cancelStartup()
	op.server.recordBootstrapHistoryTerminal(op.startup, op, nil, cause)
	if !op.server.history.snapshot.Load().pendingFinalization {
		t.Fatal("expired actual failure dropped")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if op.server.CloseBootstrapHistory(ctx) == nil {
		t.Fatal("pending cleanup accepted before worker joined")
	}
	close(returned)
	op.server.finalizeBootstrapHistory(ctx, op)
	snap := op.server.history.snapshot.Load()
	if snap.pendingFinalization || !snap.retired || snap.store == nil || snap.store.state.expected == nil {
		t.Fatal("joined final publication or retirement missing")
	}
	if snap.store.state.expected.LatestAttempt.Terminal.Outcome != "failed" {
		t.Fatal("actual terminal failure not recorded")
	}
	if snap.store.Close(ctx) != nil {
		t.Fatal("exact cleanup unresolved")
	}
}
func TestBootstrapHistoryRetireActiveThenExpiredContext(t *testing.T) {
	store, op, f, lease, _ := historyFixture(t)
	store.state.mu.Lock()
	retired, err := store.retirePublication()
	store.state.mu.Unlock()
	if retired || err == nil {
		t.Fatal("active publisher retired")
	}
	expired, cancel := context.WithCancel(op.startup)
	cancel()
	if store.Begin(expired) == nil {
		t.Fatal("expired publication accepted")
	}
	retired, err = store.retirePublication()
	if !retired || err != nil {
		t.Fatal("quiescent expired ownership not retired")
	}
	if lease.Close() != nil {
		t.Fatal("original actual lease close failed")
	}
	ctx, cancelNext := context.WithTimeout(context.Background(), time.Second)
	defer cancelNext()
	next, err := AcquireBootstrapLock(ctx, f.profile.ProfileDirectory, f.profile.InstanceID, "owner-status-service")
	if err != nil {
		t.Fatal("retired duplicate blocked genuine new lease")
	}
	if next.Close() != nil {
		t.Fatal("new actual lease close failed")
	}
	if store.Close(ctx) != nil {
		t.Fatal("retained root cleanup failed")
	}
}

func TestBootstrapHistoryActiveWarningHasNoCleanupCapability(t *testing.T) {
	store, op, _, _, binding := historyFixture(t)
	file, err := store.createStage(op.startup, ".bootstrap-history-warning-control")
	if err != nil {
		t.Fatal("actual stage unavailable")
	}
	if file.Close() != nil || store.root.Chmod(".bootstrap-history-warning-control", 0644) != nil {
		t.Fatal("actual close/mode refusal setup failed")
	}
	retained := store.cleanupStage(op.startup)
	var cleanup *historyStageCleanupError
	if !errors.As(retained, &cleanup) {
		t.Fatal("actual cleanup owner absent")
	}
	state := newOwnerBridgeHistoryState(binding)
	state.returned = make(chan struct{})
	state.snapshot.Store(&ownerBridgeHistorySnapshot{store: store, warning: retained})
	op.server.history = state
	warning := op.server.BootstrapHistoryWarning(op.startup)
	var capability interface{ Close(context.Context) error }
	exposed := errors.As(warning, &capability)
	activeRefused := op.server.CloseBootstrapHistory(op.startup) != nil
	if store.root.Chmod(".bootstrap-history-warning-control", 0600) != nil {
		t.Fatal("actual stage restore failed")
	}
	if store.Close(op.startup) != nil {
		t.Fatal("exact cleanup failed")
	}
	if warning == nil || exposed || !activeRefused {
		t.Fatal("active public warning exposed cleanup capability")
	}
}

func TestBootstrapHistoryRefusedWritersPreserveSnapshot(t *testing.T) {
	store, op, _, _, binding := historyFixture(t)
	state := newOwnerBridgeHistoryState(binding)
	state.returned = make(chan struct{})
	retained := errors.New("private_original_warning")
	original := &ownerBridgeHistorySnapshot{store: store, warning: retained, retired: true}
	state.snapshot.Store(original)
	op.server.history = state
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	op.server.finalizeBootstrapHistory(ctx, op)
	prejoinUnchanged := state.snapshot.Load() == original
	// Closing returned represents the joined producer for this component seam.
	close(state.returned)
	state.snapshot.Store(original)
	state.cleanupGate.Lock()
	short, stop := context.WithTimeout(ctx, 20*time.Millisecond)
	done := make(chan error, 2)
	go func() { op.server.finalizeBootstrapHistory(short, op); done <- nil }()
	go func() { done <- op.server.CloseBootstrapHistory(short) }()
	first, second := <-done, <-done
	stop()
	gateUnchanged := state.snapshot.Load() == original
	state.cleanupGate.Unlock()
	if store.Close(ctx) != nil {
		t.Fatal("exact retained store cleanup failed")
	}
	if !prejoinUnchanged || !gateUnchanged || (first == nil && second == nil) {
		t.Fatal("refused producer changed immutable snapshot or dropped refusal")
	}
}
func TestBootstrapHistoryPublicWarningHasNoUnwrapMethods(t *testing.T) {
	store, op, _, _, binding := historyFixture(t)
	state := newOwnerBridgeHistoryState(binding)
	state.returned = make(chan struct{})
	state.snapshot.Store(&ownerBridgeHistorySnapshot{store: store, warning: errors.New("private-warning")})
	op.server.history = state
	warning := op.server.BootstrapHistoryWarning(op.startup)
	_, single := warning.(interface{ Unwrap() error })
	_, multiple := warning.(interface{ Unwrap() []error })
	if warning == nil || single || multiple {
		t.Fatal("public warning exposes ancestry method")
	}
}
