//go:build linux || darwin

package launcher

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestOwnerObservationDefaultCapOnHeldSessionLock(t *testing.T) {
	policy, profile := ownerStatusFixture(t)
	owner, err := LoadOwnerStatus(policy)
	if err != nil {
		t.Fatal("private owner fixture rejected")
	}
	input := ownerObservationFixture(policy, profile, "reused")
	session := &Session{Status: input.status, startupAttemptID: input.attemptID, observedAt: input.receivedAt}
	session.mu.Lock()
	done := make(chan error, 1)
	go func() { _, err := session.OwnerObservation(owner); done <- err }()
	// The caller goroutine is always joined after releasing the test-held lock.
	// This cannot leave a production lock waiter running after the test returns.
	timer := time.NewTimer(5*time.Second + 250*time.Millisecond)
	defer timer.Stop()
	select {
	case err := <-done:
		session.mu.Unlock()
		if err == nil || err.Error() != "owner_status_deadline" {
			t.Fatal("default cap did not return a safe deadline error")
		}
	case <-timer.C:
		session.mu.Unlock()
		<-done
		t.Fatal("default observation exceeded its five-second lock wait cap")
	}
}

func deadlineSessionFixture(t *testing.T) (*Session, *OwnerStatus) {
	t.Helper()
	policy, p := ownerStatusFixture(t)
	owner, err := LoadOwnerStatus(policy)
	if err != nil {
		t.Fatal("private owner fixture rejected")
	}
	input := ownerObservationFixture(policy, p, "reused")
	return &Session{Status: input.status, startupAttemptID: input.attemptID, observedAt: input.receivedAt}, owner
}

func TestOwnerObservationCallerBoundsOnBothLocks(t *testing.T) {
	for _, lockName := range []string{"session", "owner"} {
		for _, mode := range []string{"deadline", "cancel"} {
			t.Run(lockName+"-"+mode, func(t *testing.T) {
				session, owner := deadlineSessionFixture(t)
				lock := &session.mu
				if lockName == "owner" {
					lock = &owner.mu
				}
				lock.Lock()
				defer lock.Unlock()
				ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
				defer cancel()
				expected := "owner_status_deadline"
				var callbackDone chan struct{}
				if mode == "cancel" {
					cancel()
					ctx, cancel = context.WithCancel(context.Background())
					defer cancel()
					expected = "owner_status_cancelled"
					callbackDone = make(chan struct{})
					time.AfterFunc(20*time.Millisecond, func() { cancel(); close(callbackDone) })
					defer func() { <-callbackDone }()
				}
				start := time.Now()
				out, err := session.OwnerObservationContext(ctx, owner)
				if err == nil || err.Error() != expected || out.ObservationID != "" {
					t.Fatal("blocked observation ignored caller bound or exposed a late result")
				}
				if time.Since(start) > time.Second {
					t.Fatal("caller bound used the five-second default instead")
				}
				if lock.TryLock() {
					lock.Unlock()
					t.Fatal("cancelled observation changed the held lock")
				}
			})
		}
	}
}

func TestOwnerObservationOneBudgetAcrossSequentialLocks(t *testing.T) {
	session, owner := deadlineSessionFixture(t)
	session.mu.Lock()
	owner.mu.Lock()
	defer owner.mu.Unlock()
	released := make(chan struct{})
	time.AfterFunc(25*time.Millisecond, func() { session.mu.Unlock(); close(released) })
	defer func() { <-released }()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	start := time.Now()
	if out, err := session.OwnerObservationContext(ctx, owner); err == nil || err.Error() != "owner_status_deadline" || out.ObservationID != "" {
		t.Fatal("sequential locks reset the caller budget")
	}
	if time.Since(start) > time.Second {
		t.Fatal("second lock consumed a new default budget")
	}
}

func TestOwnerObservationContextPreservesIdentityFreshnessAndSnapshot(t *testing.T) {
	session, owner := deadlineSessionFixture(t)
	if _, err := session.OwnerObservationContext(nil, owner); err == nil || err.Error() != "owner_status_context_invalid" {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, err := session.OwnerObservationContext(ctx, owner); err == nil || out.ObservationID != "" {
		t.Fatal("already canceled caller produced a status")
	}
	if _, err := session.OwnerObservationContext(context.Background(), nil); err == nil {
		t.Fatal("missing owner accepted by context entry")
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	first, err := session.OwnerObservationContext(ctx, owner)
	if err != nil || first.Disposition != "reused" || first.Persistence.Readiness != "unknown" || first.Work.Active != nil || first.Hubs.InventoryState != "unavailable" {
		t.Fatal("context entry changed owner or unsupported-state semantics")
	}
	// Returned role observations cannot mutate the retained Session frame.
	first.Instance.Services[0].Readiness = "unknown"
	if session.Status.Kernel.Members[0].State != "ready" {
		t.Fatal("output mutated retained member snapshot")
	}
	session.mu.Lock()
	session.observedAt = time.Now().Add(-4 * time.Second)
	session.mu.Unlock()
	stale, err := session.OwnerObservationContext(ctx, owner)
	if err != nil || stale.Disposition != "failed" || len(stale.Errors) == 0 || stale.Errors[0].Code != "observation_unavailable" {
		t.Fatal("context entry refreshed an old receipt")
	}
}

func TestObservationLockCancellationLeavesNoWaiter(t *testing.T) {
	var lock sync.Mutex
	lock.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := lockOwnerObservation(ctx, &lock); err == nil {
		lock.Unlock()
		t.Fatal("held lock acquired despite deadline")
	}
	lock.Unlock()
	if !lock.TryLock() {
		t.Fatal("deadline left a hidden lock waiter")
	}
	lock.Unlock()
}
