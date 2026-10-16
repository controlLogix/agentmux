//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	protected "github.com/controlLogix/agentmux/platform/runtime"
)

var errRuntimeCleanup = errors.New("owner_bridge_runtime_cleanup_failed")

// Historical failures retain causes without granting session cleanup authority.
type runtimeCleanupCause struct{ cause error }

func (runtimeCleanupCause) Error() string                    { return "owner_bridge_runtime_cleanup_failed" }
func (e runtimeCleanupCause) Format(state fmt.State, _ rune) { fmt.Fprint(state, e.Error()) }
func (e runtimeCleanupCause) MarshalJSON() ([]byte, error)   { return json.Marshal(e.Error()) }
func (e runtimeCleanupCause) Unwrap() error                  { return errors.Join(e.cause, errRuntimeCleanup) }

func runtimeCleanupFailure(owner *sessionCleanupOwner, causes ...error) error {
	cause := errors.Join(causes...)
	if owner != nil && owner.session != nil && owner.session.cleanupState.pending() {
		return &RuntimeCleanupError{owner: owner, cause: cause}
	}
	return &runtimeCleanupCause{cause: cause}
}

// RuntimeCleanupError retains only the exact session and service lease that
// still need cleanup. Human-readable and JSON output never includes either.
type RuntimeCleanupError struct {
	owner *sessionCleanupOwner
	cause error
}

func (RuntimeCleanupError) Error() string                    { return "owner_bridge_runtime_cleanup_failed" }
func (e RuntimeCleanupError) Format(state fmt.State, _ rune) { fmt.Fprint(state, e.Error()) }
func (e RuntimeCleanupError) MarshalJSON() ([]byte, error)   { return json.Marshal(e.Error()) }
func (e RuntimeCleanupError) Unwrap() error                  { return errors.Join(e.cause, errRuntimeCleanup) }
func (e *RuntimeCleanupError) Close(parent context.Context) error {
	if e == nil {
		return nil
	}
	if e.owner == nil || e.owner.session == nil {
		return runtimeCleanupFailure(nil, e.cause)
	}
	if parent == nil {
		return runtimeCleanupFailure(e.owner, e.cause, errors.New("runtime_cleanup_context_invalid"))
	}
	ctx, cancel := context.WithTimeout(parent, e.owner.budget)
	defer cancel()
	if err := lockOwnerObservation(ctx, &e.owner.retryMu); err != nil {
		return runtimeCleanupFailure(e.owner, e.cause, err, ctx.Err())
	}
	defer e.owner.retryMu.Unlock()
	if err := ctx.Err(); err != nil {
		return runtimeCleanupFailure(e.owner, e.cause, err)
	}
	cleanupErr := e.owner.session.Close(ctx)
	if e.owner.session.cleanupState.pending() {
		return runtimeCleanupFailure(e.owner, e.cause, cleanupErr, ctx.Err())
	}
	e.owner.session.cleanupState.notify()
	releaseErr := e.owner.release()
	if cleanupErr != nil || releaseErr != nil {
		return runtimeCleanupFailure(nil, e.cause, cleanupErr, releaseErr)
	}
	return nil
}

type sessionCleanupOwner struct {
	session      *Session
	lease        *BootstrapLock
	budget       time.Duration
	retryMu      sync.Mutex
	releaseOnce  sync.Once
	releaseError error
}

func (o *sessionCleanupOwner) release() error {
	o.releaseOnce.Do(func() {
		if err := o.lease.Close(); err != nil {
			o.releaseError = runtimeCleanupFailure(nil, err)
		}
	})
	return o.releaseError
}

// closeOwnedSession transfers the service lease only while the actual session
// still owns an unfinished group or open bootstrap lease. Historical failures
// remain errors but cannot manufacture cleanup authority.
func closeOwnedSession(session *Session, lease *BootstrapLock, cause error, budget time.Duration) (error, bool) {
	return closeOwnedSessionContext(context.Background(), session, lease, cause, budget)
}

// The caller supplies its existing shared cleanup envelope.
func closeOwnedSessionContext(parent context.Context, session *Session, lease *BootstrapLock, cause error, budget time.Duration) (error, bool) {
	if session == nil {
		return cause, false
	}
	if budget <= 0 || budget > 20*time.Second {
		return runtimeCleanupFailure(nil, cause, errors.New("runtime_cleanup_budget_invalid")), false
	}
	if parent == nil {
		return runtimeCleanupFailure(nil, cause, errors.New("runtime_cleanup_context_invalid")), false
	}
	ctx, cancel := context.WithTimeout(parent, budget)
	cleanupErr := session.Close(ctx)
	if contextErr := ctx.Err(); contextErr != nil {
		cleanupErr = errors.Join(cleanupErr, contextErr)
	}
	cancel()
	state := session.cleanupState
	if !state.pending() {
		state.notify()
		var releaseErr error
		if state != nil {
			state.mu.Lock()
			owner := state.retained
			state.mu.Unlock()
			if owner != nil {
				releaseErr = owner.release()
			}
		}
		if cleanupErr != nil || releaseErr != nil {
			return runtimeCleanupFailure(nil, cause, cleanupErr, releaseErr), false
		}
		return cause, false
	}
	if lease == nil || lease.file == nil {
		return runtimeCleanupFailure(nil, cause, cleanupErr, errors.New("runtime_cleanup_lease_missing")), false
	}
	if _, err := lease.file.Stat(); err != nil {
		return runtimeCleanupFailure(nil, cause, cleanupErr, err), false
	}
	state.mu.Lock()
	owner := state.retained
	if owner == nil {
		owner = &sessionCleanupOwner{session: session, lease: lease, budget: budget}
		state.retained = owner
	} else if owner.lease != lease {
		state.mu.Unlock()
		return runtimeCleanupFailure(nil, cause, cleanupErr, errors.New("runtime_cleanup_owner_mismatch")), false
	}
	state.mu.Unlock()
	// The existing reaper can complete between the pending check and transfer.
	// This direct recheck releases the same lease; it creates no waiter.
	state.notify()
	if !state.pending() {
		return runtimeCleanupFailure(nil, cause, cleanupErr, owner.release()), true
	}
	return runtimeCleanupFailure(owner, cause, cleanupErr), true
}

// References are recorded only at actual Session construction and Group
// assignment. File inspection and lease closure never hold this small mutex.
type sessionCleanupState struct {
	mu        sync.Mutex
	group     *protected.Group
	leaseFile *os.File
	retained  *sessionCleanupOwner
	done      chan struct{}
	notified  bool
}

func newSessionCleanupState(file *os.File) *sessionCleanupState {
	return &sessionCleanupState{leaseFile: file, done: make(chan struct{})}
}
func (s *sessionCleanupState) recordGroup(group *protected.Group) {
	s.mu.Lock()
	s.group = group
	s.mu.Unlock()
}
func (s *sessionCleanupState) pending() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	group, file := s.group, s.leaseFile
	s.mu.Unlock()
	if group != nil {
		select {
		case <-group.Done():
		default:
			return true
		}
	}
	if file != nil {
		_, err := file.Stat()
		return !errors.Is(err, os.ErrClosed)
	}
	return false
}
func (s *sessionCleanupState) notify() {
	if s == nil || s.pending() {
		return
	}
	s.mu.Lock()
	owner := s.retained
	var done chan struct{}
	if !s.notified {
		s.notified = true
		done = s.done
	}
	s.mu.Unlock()
	if owner != nil {
		owner.release()
	}
	if done != nil {
		close(done)
	}
}
