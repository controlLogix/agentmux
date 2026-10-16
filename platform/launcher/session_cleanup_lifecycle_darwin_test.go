//go:build darwin && cgo && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"errors"
	"path/filepath"
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
		if boot.Close() != nil {
			t.Error("bootstrap lease close after service admission failure failed")
		}
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
		if session.lock.Close() != nil {
			t.Error("actual bootstrap lease close failed")
		}
		session.lock = nil
		session.cleanupState.notify()
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if group.Stop(ctx) != nil {
			t.Error("actual owned group cleanup failed")
		}
		select {
		case <-joined:
		case <-ctx.Done():
			t.Error("actual reaper not joined; exact service lease retained")
			return
		}
		if service.Close() != nil {
			t.Error("actual service lease close failed")
		}
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
