//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

func sessionCleanupCauseFixture(t *testing.T) (*Session, *BootstrapLock) {
	t.Helper()
	directory := privateLockDirectory(t)
	boot, err := AcquireBootstrapLock(boundedLockContext(t), directory, "cleanup_causes", "bootstrap")
	if err != nil {
		t.Fatal("actual bootstrap lease unavailable")
	}
	t.Cleanup(func() { boot.Close() })
	service, err := AcquireBootstrapLock(boundedLockContext(t), directory, "cleanup_causes", "service")
	if err != nil {
		t.Fatal("actual service lease unavailable")
	}
	t.Cleanup(func() { service.Close() })
	session := &Session{lock: boot, cleanupState: newSessionCleanupState(boot.file)}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		session.Close(ctx)
	})
	return session, service
}

func assertSessionCleanupCausePrivate(t *testing.T, failure error, pending bool) {
	t.Helper()
	if failure == nil || !errors.Is(failure, errRuntimeCleanup) {
		t.Fatal("cleanup failure or category was discarded")
	}
	var retained *RuntimeCleanupError
	if errors.As(failure, &retained) != pending {
		t.Fatal("cleanup error reported the wrong pending authority")
	}
	for _, format := range []string{"%s", "%v", "%+v", "%#v", "%q"} {
		if fmt.Sprintf(format, failure) != "owner_bridge_runtime_cleanup_failed" {
			t.Fatal("private cleanup details entered formatted output")
		}
	}
	raw, err := json.Marshal(failure)
	if err != nil || string(raw) != `"owner_bridge_runtime_cleanup_failed"` {
		t.Fatal("private cleanup details entered JSON")
	}
}

func sessionCleanupPathCauses(failure error) []*os.PathError {
	var found []*os.PathError
	var visit func(error)
	visit = func(err error) {
		if path, ok := err.(*os.PathError); ok {
			found = append(found, path)
		}
		switch wrapped := err.(type) {
		case interface{ Unwrap() []error }:
			for _, cause := range wrapped.Unwrap() {
				visit(cause)
			}
		case interface{ Unwrap() error }:
			visit(wrapped.Unwrap())
		}
	}
	visit(failure)
	return found
}

func TestSessionCleanupCausesConsumedBootstrapRetainsPrimaryWithoutAuthority(t *testing.T) {
	session, service := sessionCleanupCauseFixture(t)
	file := session.lock.file
	if err := file.Close(); err != nil {
		t.Fatal("owned bootstrap descriptor fault setup failed")
	}
	primary := &os.PathError{Op: "start", Path: "/private/session-primary", Err: context.Canceled}
	failure, transferred := closeOwnedSessionContext(context.Background(), session, service, primary, time.Second)
	assertSessionCleanupCausePrivate(t, failure, false)
	if transferred || !errors.Is(failure, primary) || !errors.Is(failure, context.Canceled) || !errors.Is(failure, os.ErrClosed) {
		t.Fatal("consumed bootstrap lost a cause or manufactured transfer")
	}
	var first *os.PathError
	if !errors.As(failure, &first) || first != primary {
		t.Fatal("primary typed cause lost precedence")
	}
	var closeCause *os.PathError
	for _, path := range sessionCleanupPathCauses(failure) {
		if path.Op == "close" && path.Path == file.Name() {
			closeCause = path
		}
	}
	if closeCause == nil || session.lock.file != nil || session.cleanupState.pending() || session.cleanupState.retained != nil {
		t.Fatal("actual close cause or consumed ownership differs")
	}
	again, transferredAgain := closeOwnedSession(session, service, primary, time.Second)
	assertSessionCleanupCausePrivate(t, again, false)
	if transferredAgain || !errors.Is(again, closeCause) || service.file == nil {
		t.Fatal("historical failure disappeared or consumed the caller service lease")
	}
	if _, err := service.file.Stat(); err != nil {
		t.Fatal("nontransferred service lease was closed")
	}
}

func TestSessionCleanupCausesRetryRetainsActualCloseAndReleaseFailures(t *testing.T) {
	session, service := sessionCleanupCauseFixture(t)
	bootFile, serviceFile := session.lock.file, service.file
	for _, file := range []*os.File{bootFile, serviceFile} {
		if err := file.Close(); err != nil {
			t.Fatal("owned descriptor fault setup failed")
		}
	}
	// Construct the existing private owner state around actual acquired leases.
	// This control does not claim a running Group or a real pending transfer.
	owner := &sessionCleanupOwner{session: session, lease: service, budget: time.Second}
	session.cleanupState.retained = owner
	primary := &os.PathError{Op: "start", Path: "/private/retry-primary", Err: context.Canceled}
	retained := &RuntimeCleanupError{owner: owner, cause: primary}
	failure := retained.Close(context.Background())
	assertSessionCleanupCausePrivate(t, failure, false)
	if !errors.Is(failure, primary) || !errors.Is(failure, os.ErrClosed) {
		t.Fatal("retry lost original or actual close failure")
	}
	seen := map[string]*os.PathError{}
	for _, path := range sessionCleanupPathCauses(failure) {
		if path.Op == "close" {
			seen[path.Path] = path
		}
	}
	if seen[bootFile.Name()] == nil || seen[serviceFile.Name()] == nil || owner.releaseError == nil {
		t.Fatal("actual session or service release cause was discarded")
	}
	if session.lock.file != nil || service.file != nil || session.cleanupState.pending() {
		t.Fatal("consumed files acquired pending authority")
	}
	for range 2 {
		again := retained.Close(context.Background())
		assertSessionCleanupCausePrivate(t, again, false)
		for _, cause := range []*os.PathError{seen[bootFile.Name()], seen[serviceFile.Name()]} {
			if !errors.Is(again, cause) {
				t.Fatal("repeated cleanup erased an actual historical failure")
			}
		}
	}
	if owner.release() != owner.releaseError {
		t.Fatal("consumed service release was retried")
	}
	factoryFailure, transferred := closeOwnedSession(session, service, primary, time.Second)
	assertSessionCleanupCausePrivate(t, factoryFailure, false)
	if transferred || !errors.Is(factoryFailure, seen[serviceFile.Name()]) {
		t.Fatal("nontransfer path lost the retained release failure")
	}
}

func TestSessionCleanupCausesPendingAdmissionAndExactOwner(t *testing.T) {
	session, service := sessionCleanupCauseFixture(t)
	primary := &os.PathError{Op: "start", Path: "/private/pending-primary", Err: context.Canceled}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Keep an actual bootstrap lease open while Session.Close cannot acquire its lock.
	session.mu.Lock()
	failure, transferred := closeOwnedSessionContext(ctx, session, service, primary, time.Second)
	session.mu.Unlock()
	assertSessionCleanupCausePrivate(t, failure, true)
	var retained *RuntimeCleanupError
	if !transferred || !errors.As(failure, &retained) || retained.owner.session != session || retained.owner.lease != service {
		t.Fatal("pending cleanup lost the exact owner")
	}
	if !errors.Is(failure, primary) || !errors.Is(failure, context.Canceled) {
		t.Fatal("pending cleanup lost primary or cancellation")
	}
	other, err := AcquireBootstrapLock(boundedLockContext(t), privateLockDirectory(t), "cleanup_causes", "service")
	if err != nil {
		t.Fatal("other actual service lease unavailable")
	}
	t.Cleanup(func() { other.Close() })
	for _, lease := range []*BootstrapLock{nil, {}, other} {
		session.mu.Lock()
		refused, adopted := closeOwnedSessionContext(ctx, session, lease, primary, time.Second)
		session.mu.Unlock()
		assertSessionCleanupCausePrivate(t, refused, false)
		if adopted || !errors.Is(refused, primary) || !errors.Is(refused, context.Canceled) || session.cleanupState.retained != retained.owner {
			t.Fatal("failed lease admission lost causes or replaced the exact owner")
		}
	}
	if _, err := other.file.Stat(); err != nil {
		t.Fatal("rejected service lease was consumed")
	}
	retained.owner.retryMu.Lock()
	retryFailure := retained.Close(ctx)
	retained.owner.retryMu.Unlock()
	assertSessionCleanupCausePrivate(t, retryFailure, true)
	var retry *RuntimeCleanupError
	if !errors.As(retryFailure, &retry) || retry.owner != retained.owner || !errors.Is(retryFailure, context.Canceled) || !errors.Is(retryFailure, primary) {
		t.Fatal("canceled retry lost its owner or causes")
	}
	nilContextFailure := retained.Close(nil)
	assertSessionCleanupCausePrivate(t, nilContextFailure, true)
	if !errors.Is(nilContextFailure, primary) || service.file == nil {
		t.Fatal("invalid context discarded primary or released pending lease")
	}
	if retained.Close(context.Background()) != nil || retained.Close(context.Background()) != nil {
		t.Fatal("successful exact cleanup or repeated cleanup failed")
	}
	if service.file != nil || session.cleanupState.pending() {
		t.Fatal("successful cleanup retained pending resources")
	}
}

func TestSessionCleanupCausesClosedServiceAdmissionRetainsStatCause(t *testing.T) {
	session, service := sessionCleanupCauseFixture(t)
	file := service.file
	if err := file.Close(); err != nil {
		t.Fatal("owned service descriptor fault setup failed")
	}
	primary := errors.New("private_admission_primary")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	session.mu.Lock()
	failure, transferred := closeOwnedSessionContext(ctx, session, service, primary, time.Second)
	session.mu.Unlock()
	assertSessionCleanupCausePrivate(t, failure, false)
	if transferred || !errors.Is(failure, primary) || !errors.Is(failure, os.ErrClosed) || !errors.Is(failure, context.Canceled) {
		t.Fatal("admission discarded a primary, cleanup, or actual stat cause")
	}
	var actual *os.PathError
	if !errors.As(failure, &actual) || actual.Op != "stat" || actual.Path != file.Name() || session.cleanupState.retained != nil {
		t.Fatal("actual admission cause or authority differs")
	}
}

func TestSessionCleanupCausesInvalidInputPrecedenceAndOwnerlessFailure(t *testing.T) {
	primary := &os.PathError{Op: "start", Path: "/private/admission-precedence", Err: context.Canceled}
	if failure, transferred := closeOwnedSessionContext(nil, nil, nil, primary, 0); failure != primary || transferred {
		t.Fatal("absent session changed primary precedence")
	}
	for _, budget := range []time.Duration{0, 21 * time.Second, time.Second} {
		failure, transferred := closeOwnedSessionContext(nil, &Session{}, nil, primary, budget)
		assertSessionCleanupCausePrivate(t, failure, false)
		var actual *os.PathError
		if transferred || !errors.Is(failure, primary) || !errors.As(failure, &actual) || actual != primary {
			t.Fatal("invalid admission lost primary precedence")
		}
	}
	var absent *RuntimeCleanupError
	if absent.Close(nil) != nil {
		t.Fatal("nil cleanup receiver reported a failure")
	}
	ownerless := &RuntimeCleanupError{cause: primary}
	failure := ownerless.Close(context.Background())
	assertSessionCleanupCausePrivate(t, failure, false)
	if !errors.Is(failure, primary) {
		t.Fatal("ownerless historical failure became success")
	}
}

func TestSessionCleanupCausesObservedContextOnly(t *testing.T) {
	for _, kind := range []string{"cancel", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			session, service := sessionCleanupCauseFixture(t)
			primary := errors.New("private_observed_context_primary")
			var ctx context.Context
			var cancel context.CancelFunc
			want, other := context.Canceled, context.DeadlineExceeded
			if kind == "cancel" {
				ctx, cancel = context.WithCancel(context.Background())
				cancel()
			} else {
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				want, other = context.DeadlineExceeded, context.Canceled
			}
			defer cancel()
			if !errors.Is(ctx.Err(), want) {
				t.Fatal("context fault setup did not produce its actual cause")
			}
			session.mu.Lock()
			failure, transferred := closeOwnedSessionContext(ctx, session, service, primary, time.Second)
			session.mu.Unlock()
			assertSessionCleanupCausePrivate(t, failure, true)
			if !transferred || !errors.Is(failure, primary) || !errors.Is(failure, want) || errors.Is(failure, other) {
				t.Fatal("cleanup lost the observed context cause or manufactured another")
			}
			var retained *RuntimeCleanupError
			if !errors.As(failure, &retained) || retained.owner.session != session || retained.owner.lease != service {
				t.Fatal("observed context failure changed the pending owner")
			}
			if retained.Close(context.Background()) != nil || retained.Close(context.Background()) != nil {
				t.Fatal("recoverable context failure prevented successful exact cleanup")
			}
		})
	}
	t.Run("healthy", func(t *testing.T) {
		for _, primary := range []error{nil, errors.New("private_healthy_context_primary")} {
			session, service := sessionCleanupCauseFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			failure, transferred := closeOwnedSessionContext(ctx, session, service, primary, time.Second)
			if transferred || failure != primary || errors.Is(failure, context.Canceled) || errors.Is(failure, context.DeadlineExceeded) || ctx.Err() != nil {
				cancel()
				t.Fatal("successful cleanup manufactured a context failure or changed primary precedence")
			}
			cancel()
			if service.file == nil || session.cleanupState.pending() {
				t.Fatal("successful nontransfer cleanup changed service ownership")
			}
		}
	})
	t.Run("healthy_actual_close_failure", func(t *testing.T) {
		session, service := sessionCleanupCauseFixture(t)
		if err := session.lock.file.Close(); err != nil {
			t.Fatal("owned descriptor fault setup failed")
		}
		primary := errors.New("private_healthy_close_primary")
		failure, transferred := closeOwnedSessionContext(context.Background(), session, service, primary, time.Second)
		assertSessionCleanupCausePrivate(t, failure, false)
		if transferred || !errors.Is(failure, primary) || !errors.Is(failure, os.ErrClosed) || errors.Is(failure, context.Canceled) || errors.Is(failure, context.DeadlineExceeded) {
			t.Fatal("actual close failure lost its cause or acquired cleanup cancellation")
		}
	})
}
