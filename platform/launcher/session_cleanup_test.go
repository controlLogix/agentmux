//go:build linux

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func cleanupOwnershipFixture(t *testing.T) (*Session, *BootstrapLock, <-chan struct{}) {
	t.Helper()
	session, _, group := sessionLifecycleFixture(t)
	dir := privateLockDirectory(t)
	boot, err := AcquireBootstrapLock(boundedLockContext(t), dir, "cleanup_instance", "bootstrap")
	if err != nil {
		t.Fatal("actual bootstrap lease unavailable")
	}
	service, err := AcquireBootstrapLock(boundedLockContext(t), dir, "cleanup_instance", "service")
	if err != nil {
		boot.Close()
		t.Fatal("actual service lease unavailable")
	}
	session.lock = boot
	session.cleanupState = newSessionCleanupState(boot.file)
	session.cleanupState.recordGroup(group)
	joined := make(chan struct{})
	// This is the existing production Session reaper structure, not a separate
	// retained-error watcher or substitute for a real Group completion.
	go func() {
		defer close(joined)
		<-group.Done()
		session.mu.Lock()
		defer session.mu.Unlock()
		session.retiredGroup = group
		session.group = nil
		session.lock.Close()
		session.lock = nil
		session.cleanupState.notify()
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		group.Stop(ctx)
		select {
		case <-joined:
		case <-ctx.Done():
			t.Error("actual reaper not joined")
		}
		service.Close()
	})
	return session, service, joined
}

func TestRuntimeCleanupRetainsExactSessionLeaseAndHonorsCancellation(t *testing.T) {
	session, service, _ := cleanupOwnershipFixture(t)
	session.mu.Lock()
	cause := errors.New("private_original_failure")
	failure, transferred := closeOwnedSession(session, service, cause, 250*time.Millisecond)
	session.mu.Unlock()
	var retained *RuntimeCleanupError
	if !transferred || !errors.As(failure, &retained) || retained.owner.session != session || retained.owner.lease != service {
		t.Fatal("failed shutdown lost exact ownership")
	}
	if !errors.Is(failure, cause) {
		t.Fatal("original cause was lost")
	}
	if service.file == nil {
		t.Fatal("live runtime lost service lease")
	}
	serviceDirectory := filepath.Dir(service.file.Name())
	contenderCtx, contenderCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	contender, contenderErr := AcquireBootstrapLock(contenderCtx, serviceDirectory, "cleanup_instance", "service")
	contenderCancel()
	if contender != nil {
		contender.Close()
		t.Fatal("retained service lease allowed takeover")
	}
	if !errors.Is(contenderErr, context.DeadlineExceeded) {
		t.Fatal("actual retained lease control failed")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(retained.Close(canceled), context.Canceled) {
		t.Fatal("earlier cancellation was ignored")
	}
	if service.file == nil {
		t.Fatal("canceled retry released service lease")
	}
	ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	if retained.Close(ctx) != nil || retained.Close(ctx) != nil {
		t.Fatal("exact owned retry or idempotence failed")
	}
	if service.file != nil {
		t.Fatal("joined runtime retained service lease")
	}
	acquired, acquireErr := AcquireBootstrapLock(ctx, serviceDirectory, "cleanup_instance", "service")
	if acquireErr != nil || acquired == nil {
		t.Fatal("joined cleanup did not release actual OS lease")
	}
	acquired.Close()
}

func TestRuntimeCleanupExistingReaperReleasesIgnoredError(t *testing.T) {
	session, service, joined := cleanupOwnershipFixture(t)
	serviceDirectory := filepath.Dir(service.file.Name())
	session.mu.Lock()
	_, transferred := closeOwnedSession(session, service, nil, 30*time.Millisecond)
	session.mu.Unlock()
	if !transferred {
		t.Fatal("actual pending ownership was not retained")
	}
	// Ignore the returned error. Only the pre-existing actual Session reaper is
	// responsible for release; no polling or new cleanup waiter is created.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if session.cleanupState.group.Stop(ctx) != nil {
		t.Fatal("actual group stop failed")
	}
	select {
	case <-joined:
	case <-ctx.Done():
		t.Fatal("existing reaper did not release ownership")
	}
	if service.file != nil {
		t.Fatal("ignored error orphaned the service lease")
	}
	acquired, acquireErr := AcquireBootstrapLock(ctx, serviceDirectory, "cleanup_instance", "service")
	if acquireErr != nil || acquired == nil {
		t.Fatal("existing reaper did not release actual OS lease")
	}
	acquired.Close()
}

func TestRuntimeCleanupHistoricalAndClosedFileHaveNoRetryAuthority(t *testing.T) {
	for _, closedFile := range []bool{false, true} {
		session := &Session{cleanupFailure: bootstrapError("owned_cleanup_incomplete")}
		service, err := AcquireBootstrapLock(boundedLockContext(t), privateLockDirectory(t), "cleanup_instance", "service")
		if err != nil {
			t.Fatal(err)
		}
		defer service.Close()
		if closedFile {
			lease, err := AcquireBootstrapLock(boundedLockContext(t), privateLockDirectory(t), "cleanup_instance", "bootstrap")
			if err != nil {
				t.Fatal(err)
			}
			session.lock = lease
			session.cleanupState = newSessionCleanupState(lease.file)
			if lease.file.Close() != nil {
				t.Fatal("closed descriptor control failed")
			}
		}
		failure, transferred := closeOwnedSession(session, service, nil, time.Second)
		var retained *RuntimeCleanupError
		if failure == nil || transferred || errors.As(failure, &retained) {
			t.Fatal("historical failure manufactured retained authority")
		}
		if service.file == nil {
			t.Fatal("factory consumed caller-owned service lease without transfer")
		}
	}
}

func TestRuntimeCleanupFormattingAndJSONNeverExposeOwnedState(t *testing.T) {
	value := RuntimeCleanupError{owner: &sessionCleanupOwner{session: &Session{startupAttemptID: "private_attempt"}}, cause: errors.New("private_password /private/path")}
	for _, input := range []any{value, &value} {
		for _, format := range []string{"%s", "%v", "%+v", "%#v", "%q"} {
			if fmt.Sprintf(format, input) != "owner_bridge_runtime_cleanup_failed" {
				t.Fatal("private state entered formatted output")
			}
		}
		raw, err := json.Marshal(input)
		if err != nil || string(raw) != `"owner_bridge_runtime_cleanup_failed"` {
			t.Fatal("private state entered JSON")
		}
	}
	if strings.Contains(value.Error(), "private_") {
		t.Fatal("private cause entered Error")
	}
}

func TestSessionCloseHonorsHeldLockDeadline(t *testing.T) {
	session := &Session{}
	session.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := session.Close(ctx)
	session.mu.Unlock()
	if err == nil || time.Since(start) > 150*time.Millisecond {
		t.Fatal("Session.Close ignored held-lock deadline")
	}
}
