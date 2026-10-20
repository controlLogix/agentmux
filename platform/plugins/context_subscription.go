package plugins

import (
	"bytes"
	"context"
	"errors"
	"time"
)

// Next returns the original signed event, not an unauthenticated payload. Close
// cancels pending receives. Done closes only after all original resources join.
// Open's context bounds admission; the returned lease lives until Close.
// Close must start shutdown even if its wait times out; Done must be non-nil
// and eventually close after the original resources join. A broken owner stays
// reserved rather than being replaced or closed concurrently.
type ContextSubscriptionLease interface {
	Next(context.Context) ([]byte, error)
	Close(context.Context) error
	Done() <-chan struct{}
}

// Event admission verifies source signature, digest, audience, current grants,
// and the approved subscription filter before returning a safe domain payload.
// An identifier, matching correlation, or valid JSON never establishes trust.
type ContextSubscriptionAuthority interface {
	AdmitDomainEvent(context.Context, OwnerReference, ContextOperationAdmission, ContextApprovedEnvelope, []byte) ([]byte, error)
}

const contextSubscriptionLimit = 64

type contextSubscription struct {
	handle            string
	operation         *contextOperation
	approved          ContextApprovedEnvelope
	lease             ContextSubscriptionLease
	ownerDone         <-chan struct{}
	ctx               context.Context
	cancel            context.CancelFunc
	joined            chan struct{}
	receive           chan struct{}
	closeRun          chan struct{}
	closeErr          error
	permanentCloseErr error
	cleanupJoined     chan struct{}
	closeSucceeded    bool
}

func (l *contextLease) subscriptionBinding(call ContextDomainCall) bool {
	for _, binding := range l.admission.DomainBindings {
		if binding.ID != call.BindingID || binding.ContractID != call.ContractID || binding.Action != "subscribe" {
			continue
		}
		for _, declared := range l.binding.Package.Manifest().RequestedCapabilities {
			if declared.Action == binding.Action && declared.ResourceClass == binding.ResourceClass {
				return true
			}
		}
	}
	return false
}

func (l *contextLease) subscribeDomain(ctx context.Context, op *contextOperation, call ContextDomainCall) ([]byte, string) {
	if op == nil || !l.subscriptionBinding(call) || l.ports.Subscribe == nil || nilContextDependency(l.ports.SubscriptionAuthority) {
		return nil, "context_domain_unavailable"
	}
	nonce, err := randomControlID()
	if err != nil {
		return nil, "context_service_unavailable"
	}
	lifetime, cancel := context.WithCancel(op.ctx)
	sub := &contextSubscription{handle: "subscription_" + nonce, operation: op, ctx: lifetime, cancel: cancel, joined: make(chan struct{}), receive: make(chan struct{}, 1), cleanupJoined: make(chan struct{})}
	l.mu.Lock()
	if l.closing || op.ctx.Err() != nil || len(l.subscriptions) >= contextSubscriptionLimit {
		l.mu.Unlock()
		cancel()
		return nil, "context_capacity_exceeded"
	}
	if l.subscriptions == nil {
		l.subscriptions = map[string]*contextSubscription{}
	}
	l.subscriptions[sub.handle] = sub
	l.mu.Unlock()
	// Reservation precedes every external call and stays owned even when Open
	// returns a lease after its admission deadline.
	discard := func() { cancel(); l.mu.Lock(); delete(l.subscriptions, sub.handle); l.mu.Unlock(); close(sub.joined) }
	if l.ports.Authority.Recheck(ctx, l.binding.Owner, cloneInstanceAdmission(l.admission), operationAdmissionPointer(op.admission)) != nil || ctx.Err() != nil {
		discard()
		return nil, "context_authority_unavailable"
	}
	approved, err := l.ports.Authority.PrepareDomainCall(ctx, l.binding.Owner, cloneOperationAdmission(op.admission), call)
	if err != nil || approved.BindingID != call.BindingID || !contextApprovedFor(approved.Envelope, op.admission.Operation, call) {
		discard()
		return nil, "context_domain_unavailable"
	}
	if ctx.Err() != nil || lifetime.Err() != nil {
		discard()
		return nil, "context_operation_canceled"
	}
	sub.approved = approved.Clone()
	lease, openErr := l.ports.Subscribe(ctx, approved.Clone())
	if nilContextDependency(lease) {
		discard()
		return nil, "context_domain_unavailable"
	}
	ownerDone := lease.Done()
	l.mu.Lock()
	sub.lease = lease
	sub.ownerDone = ownerDone
	l.mu.Unlock()
	// The service caller already owns a worker, so this Add cannot race a zero
	// worker count during Close. This worker owns the original lease until Done.
	l.workers.Add(1)
	go func() {
		defer l.workers.Done()
		<-sub.ctx.Done()
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		_ = l.closeSubscription(cleanup, sub)
		stop()
		select {
		case <-sub.cleanupJoined:
		case <-sub.ownerDone:
			// A timed-out caller may outlive a successful background join.
			// Confirm that same owner's final Close result once, without a loop.
			final, end := context.WithTimeout(context.Background(), time.Second)
			_ = l.closeSubscription(final, sub)
			end()
		}
		// A failed attempt retains the same owner. Explicit context cleanup can
		// retry before waiting for this worker, without replacing the allocation.
		<-sub.cleanupJoined
		l.mu.Lock()
		delete(l.subscriptions, sub.handle)
		l.mu.Unlock()
		close(sub.joined)
	}()
	if openErr != nil || sub.ownerDone == nil || ctx.Err() != nil || lifetime.Err() != nil {
		cancel()
		return nil, "context_domain_unavailable"
	}
	return contextJSON(map[string]string{"subscriptionHandle": sub.handle}), "ok"
}

func (l *contextLease) ownedSubscription(op *contextOperation, handle string) *contextSubscription {
	l.mu.Lock()
	defer l.mu.Unlock()
	sub := l.subscriptions[handle]
	if sub == nil || sub.operation != op || op == nil || sub.lease == nil {
		return nil
	}
	return sub
}

func (l *contextLease) nextDomainEvent(ctx context.Context, op *contextOperation, handle string) ([]byte, string) {
	sub := l.ownedSubscription(op, handle)
	if sub == nil || sub.ctx.Err() != nil {
		return nil, "context_domain_unavailable"
	}
	select {
	case sub.receive <- struct{}{}:
		defer func() { <-sub.receive }()
	default:
		return nil, "context_capacity_exceeded"
	}
	call, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(sub.ctx, cancel)
	defer stop()
	defer cancel()
	if l.ports.Authority.Recheck(call, l.binding.Owner, cloneInstanceAdmission(l.admission), operationAdmissionPointer(op.admission)) != nil || call.Err() != nil {
		return nil, "context_authority_unavailable"
	}
	disclosed := false
	defer func() {
		if !disclosed {
			sub.cancel()
		}
	}()
	raw, err := sub.lease.Next(call)
	if err != nil || strictDocument(raw) != nil {
		return nil, "context_domain_unavailable"
	}
	if call.Err() != nil {
		return nil, "context_operation_canceled"
	}
	payload, err := l.ports.SubscriptionAuthority.AdmitDomainEvent(call, l.binding.Owner, cloneOperationAdmission(op.admission), sub.approved.Clone(), bytes.Clone(raw))
	if err != nil || strictDocument(payload) != nil {
		return nil, "context_authority_unavailable"
	}
	if l.ports.Authority.Recheck(call, l.binding.Owner, cloneInstanceAdmission(l.admission), operationAdmissionPointer(op.admission)) != nil {
		return nil, "context_authority_unavailable"
	}
	if call.Err() != nil || completed(l.done) {
		return nil, "context_operation_canceled"
	}
	disclosed = true
	return bytes.Clone(payload), "ok"
}

func (l *contextLease) unsubscribeDomain(ctx context.Context, op *contextOperation, handle string) ([]byte, string) {
	sub := l.ownedSubscription(op, handle)
	if sub == nil {
		return nil, "context_domain_unavailable"
	}
	sub.cancel()
	if l.closeSubscription(ctx, sub) != nil {
		return nil, "context_operation_canceled"
	}
	select {
	case <-sub.joined:
		return []byte("null"), "ok"
	case <-ctx.Done():
		return nil, "context_operation_canceled"
	}
}

// closeSubscription serializes attempts on one original lease. A timeout or
// negative join can recover on a later explicit Close. Opaque consumed cleanup
// failures remain owned and are never cleared by retrying another resource.
func (l *contextLease) closeSubscription(ctx context.Context, sub *contextSubscription) error {
	if ctx == nil {
		return pluginError("context_cleanup_incomplete")
	}
	l.mu.Lock()
	if sub.permanentCloseErr != nil {
		err := sub.permanentCloseErr
		l.mu.Unlock()
		return err
	}
	if sub.closeSucceeded {
		l.mu.Unlock()
		return nil
	}
	if sub.closeRun == nil || completed(sub.closeRun) {
		sub.closeRun = make(chan struct{})
		run := sub.closeRun
		go func() {
			err := sub.lease.Close(ctx)
			if err == nil && !completed(sub.ownerDone) {
				err = pluginError("context_cleanup_incomplete")
			}
			l.mu.Lock()
			sub.closeErr = err
			var admission *AdmissionCleanupFailure
			if errors.As(err, &admission) {
				sub.permanentCloseErr = err
			}
			joined := err == nil
			if joined {
				sub.closeSucceeded = true
			}
			l.mu.Unlock()
			close(run)
			if joined {
				close(sub.cleanupJoined)
			}
		}()
	}
	run := sub.closeRun
	l.mu.Unlock()
	select {
	case <-run:
	case <-ctx.Done():
		return pluginError("context_cleanup_incomplete")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return sub.closeErr
}

func (l *contextLease) closeOwnedSubscriptions(ctx context.Context) error {
	l.mu.Lock()
	owned := make([]*contextSubscription, 0, len(l.subscriptions))
	for _, sub := range l.subscriptions {
		if sub.lease != nil {
			owned = append(owned, sub)
		}
	}
	l.mu.Unlock()
	for _, sub := range owned {
		sub.cancel()
	}
	for _, sub := range owned {
		if err := l.closeSubscription(ctx, sub); err != nil {
			return err
		}
	}
	return nil
}

func (l *contextLease) joinOperationSubscriptions(op *contextOperation) {
	l.mu.Lock()
	var owned []*contextSubscription
	for _, sub := range l.subscriptions {
		if sub.operation == op {
			owned = append(owned, sub)
		}
	}
	l.mu.Unlock()
	for _, sub := range owned {
		sub.cancel()
	}
	for _, sub := range owned {
		<-sub.joined
	}
}
