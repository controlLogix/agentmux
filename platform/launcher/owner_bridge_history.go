//go:build linux || darwin

package launcher

import (
	"context"
	"errors"
	protected "github.com/controlLogix/agentmux/platform/runtime"
	"sync"
	"sync/atomic"
	"time"
)

// The Run worker is the only publication producer. Readers see immutable
// snapshots; the actual root/stage owner is never replaced by a warning string.
type ownerBridgeHistorySnapshot struct {
	store               *bootstrapHistoryStore
	warning             error
	attempted           bool
	admitted            bool
	retired             bool
	pendingFinalization bool
}
type ownerBridgeHistoryState struct {
	binding     protected.BootstrapReceiptBinding
	returned    chan struct{} // Set by Run before its sole worker is started.
	snapshot    atomic.Pointer[ownerBridgeHistorySnapshot]
	cleanupGate sync.Mutex
}

func newOwnerBridgeHistoryState(binding protected.BootstrapReceiptBinding) *ownerBridgeHistoryState {
	state := &ownerBridgeHistoryState{binding: binding}
	state.snapshot.Store(&ownerBridgeHistorySnapshot{})
	return state
}

// Writes occur only in the sole publication producer, then under cleanupGate
// after the returned channel closes. Readers never mutate the snapshot.
func (state *ownerBridgeHistoryState) warn(cause error) {
	if cause == nil {
		return
	}
	next := *state.snapshot.Load()
	next.warning = errors.Join(next.warning, cause)
	state.snapshot.Store(&next)
}

// Called only by the publication producer before returned closes.
func (state *ownerBridgeHistoryState) publishSnapshot(next ownerBridgeHistorySnapshot) {
	state.snapshot.Store(&next)
}

type ownerBridgeCleanupEnvelope struct {
	once   sync.Once
	budget time.Duration
	ctx    context.Context
	cancel context.CancelFunc
}

func newOwnerBridgeCleanupEnvelope(budget time.Duration) *ownerBridgeCleanupEnvelope {
	return &ownerBridgeCleanupEnvelope{budget: budget}
}
func (e *ownerBridgeCleanupEnvelope) context() context.Context {
	e.once.Do(func() { e.ctx, e.cancel = context.WithTimeout(context.Background(), e.budget) })
	return e.ctx
}
func (e *ownerBridgeCleanupEnvelope) close() {
	if e.cancel != nil {
		e.cancel()
	}
}

func (server *OwnerBridgeServer) beginBootstrapHistory(ctx context.Context, op *bootstrapOperation) {
	state := server.history
	if state == nil {
		return
	}
	next := *state.snapshot.Load()
	if next.attempted {
		return
	}
	next.attempted = true
	// Store ownership is retained as soon as construction returns, even on error.
	store, err := openBootstrapHistory(ctx, op, state.binding)
	next.store = store
	next.admitted = err == nil
	next.warning = errors.Join(next.warning, err)
	state.publishSnapshot(next)
	if next.admitted {
		state.warn(store.Begin(ctx))
	}
}
func (server *OwnerBridgeServer) recordBootstrapHistoryTerminal(startup context.Context, op *bootstrapOperation, actualSession *Session, actualFailure error) {
	if server.history == nil {
		return
	}
	state := server.history
	next := *state.snapshot.Load()
	if !next.attempted && startup.Err() == nil {
		next.attempted = true
		var err error
		next.store, err = openBootstrapHistory(startup, op, state.binding)
		next.admitted = err == nil
		next.warning = errors.Join(next.warning, err)
		state.publishSnapshot(next)
	}
	var publicationErr error
	if next.store != nil && next.admitted && startup.Err() == nil {
		publicationErr = next.store.RecordTerminal(startup)
	} else {
		publicationErr = historyError("context_invalid", startup.Err())
	}
	state.warn(publicationErr)
	if actualFailure != nil && publicationErr != nil {
		next = *state.snapshot.Load()
		next.pendingFinalization = true
		state.publishSnapshot(next)
		return
	}
	// Optional failed publication never starts teardown for a healthy runtime.
	if next.store != nil {
		retired, err := next.store.retirePublication()
		next = *state.snapshot.Load()
		next.retired = retired
		next.warning = errors.Join(next.warning, err)
		state.publishSnapshot(next)
	}
	_ = actualSession // Session cleanup remains exclusively owned by Run.
}

// Run invokes this only after both the actual operation and worker are joined.
// History receives one capped portion of the existing core cleanup envelope.
func (server *OwnerBridgeServer) finalizeBootstrapHistory(ctx context.Context, op *bootstrapOperation) error {
	if server.history == nil {
		return nil
	}
	state := server.history
	select {
	case <-state.returned:
	default:
		return historyError("state_invalid", nil)
	}
	bounded, cancel := context.WithTimeout(ctx, bootstrapHistoryIOBudget)
	defer cancel()
	if err := lockHistory(bounded, &state.cleanupGate); err != nil {
		return err
	}
	defer state.cleanupGate.Unlock()
	next := *state.snapshot.Load()
	if next.pendingFinalization {
		if next.store == nil {
			var err error
			next.store, err = openBootstrapHistory(bounded, op, state.binding)
			next.admitted = err == nil
			next.warning = errors.Join(next.warning, err)
			state.publishSnapshot(next)
		}
		if next.store != nil && next.admitted {
			state.warn(next.store.RecordTerminal(bounded))
		}
	}
	next = *state.snapshot.Load()
	if next.store == nil {
		return nil
	}
	// Even exhausted IO cannot authorize more publication. Retirement closes only
	// our consumed duplicate and retains exact staging/root cleanup ownership.
	retired, err := next.store.retirePublication()
	next = *state.snapshot.Load()
	next.retired = retired
	next.pendingFinalization = !retired
	next.warning = errors.Join(next.warning, err)
	state.publishSnapshot(next)
	if retired {
		closeErr := next.store.Close(bounded)
		state.warn(closeErr)
		return closeErr
	}
	return err
}

// CloseBootstrapHistory retries only retained unpublished stage cleanup after
// the actual publication worker has returned. No lease is acquired or adopted.
func (server *OwnerBridgeServer) CloseBootstrapHistory(ctx context.Context) error {
	if server == nil || server.history == nil {
		return nil
	}
	state := server.history
	if state.returned == nil {
		return historyError("state_invalid", nil)
	}
	select {
	case <-state.returned:
	default:
		return historyError("state_invalid", nil)
	}
	snap := state.snapshot.Load()
	if snap.store == nil {
		return nil
	}
	if !snap.retired || snap.pendingFinalization {
		return historyError("state_invalid", nil)
	}
	bounded, cancel, err := historyIOContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if err = lockHistory(bounded, &state.cleanupGate); err != nil {
		return err
	}
	defer state.cleanupGate.Unlock()
	err = snap.store.Close(bounded)
	state.warn(err)
	return err
}
func (server *OwnerBridgeServer) BootstrapHistoryWarning(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("bootstrap_history_context_invalid")
	}
	if server == nil || server.history == nil {
		return nil
	}
	if server.history.snapshot.Load().warning != nil {
		return errors.New("bootstrap_history_publication_failed")
	}
	return nil
}
