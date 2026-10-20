package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Exercise the actual context worker, native lease, driver Stop and composition
// Close. Broker/process IO and current authority transport are controlled; this
// is an offline cleanup/disclosure regression, not a live enrollment claim.
func nativeSubscriptionContextFixture(t *testing.T, mode string) (*contextLease, *contextOperation, *nativeSubscriptionTestTransport, *NativeConfigurationSubscriptions, string, chan struct{}, *nativeContextLifecycle) {
	t.Helper()
	host, transport, approved := nativeRemoteSubscriptionFixture(t, mode)
	authority := transport.authority.authority
	authority.mu.Lock()
	delete(authority.instances, transport.authority.binding.Owner)
	authority.mu.Unlock()
	var nativeCalls sync.Mutex
	originalExchange := authority.client.options.Exchange
	authority.client.options.Exchange = nativeAuthorityTestExchange(func(ctx context.Context, reply string, raw []byte) ([]byte, error) {
		nativeCalls.Lock()
		defer nativeCalls.Unlock()
		return originalExchange.Exchange(ctx, reply, raw)
	})
	lifetime := make(chan struct{})
	lifecycle := newNativeContextLifecycle(transport.authority.binding.Owner)
	lifecycle.markReady()
	fixture := newContextTestFixture(t, func(binding *ContextBinding, ports *ContextPorts) {
		*binding = cloneContextBinding(transport.authority.binding)
		binding.LifetimeDone = lifetime
		binding.Lifecycle = lifecycle
		ports.Authority = authority
		ports.SubscriptionAuthority = authority
		ports.Subscribe = func(ctx context.Context, current ContextApprovedEnvelope) (ContextSubscriptionLease, error) {
			transport.mu.Lock()
			transport.approved = current.Clone()
			transport.mu.Unlock()
			return host.Subscribe(ctx, current)
		}
	})
	l := fixture.lease
	opCtx, cancel := context.WithCancel(l.ctx)
	op := &contextOperation{ctx: opCtx, cancel: cancel, admission: cloneOperationAdmission(approved.subscription.operation)}
	t.Cleanup(cancel)
	var requestID string
	json.Unmarshal(fieldsForClaim(approved.Envelope, "correlationId"), &requestID)
	call := ContextDomainCall{RequestID: requestID, BindingID: approved.BindingID, ContractID: "configuration-change-subscribe", Payload: append([]byte(nil), fieldsForClaim(approved.Envelope, "payload")...)}
	raw, code := l.subscribeDomain(context.Background(), op, call)
	handle := subscriptionHandle(t, raw, code)
	t.Cleanup(func() { transport.mu.Lock(); transport.mode = ""; transport.mu.Unlock() })
	return l, op, transport, host, handle, lifetime, lifecycle
}

func TestNativeSubscriptionCompositionCloseRetriesOriginalContextAndDriver(t *testing.T) {
	l, op, transport, host, handle, lifetime, lifecycle := nativeSubscriptionContextFixture(t, "close-unjoined")
	original := l.ownedSubscription(op, handle).lease
	directory := privateTestDirectory(t)
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	if err := root.Mkdir("stage", 0700); err != nil {
		t.Fatal(err)
	}
	info, err := root.Lstat("stage")
	if err != nil {
		t.Fatal(err)
	}
	processDone := make(chan struct{})
	close(processDone)
	driver := &NativeDriver{root: root, owners: map[string]*nativeInstance{}}
	instance := &nativeInstance{driver: driver, owner: l.binding.Owner, drain: time.Second, stage: "stage", stageInfo: info, done: processDone, processDone: processDone, lifetimeDone: lifetime, lifecycle: lifecycle, stopToken: make(chan struct{}, 1), contextLease: l, contextDone: l.Done()}
	instance.stopToken <- struct{}{}
	driver.owners[instance.owner.InstanceID] = instance
	composition := &NativeContextComposition{driver: driver, subscriptionOwner: host, serviceClosed: map[*NativeAuthorityNATSExchange]bool{}}
	first, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	err = composition.Close(first)
	cancel()
	if err == nil || instance.cleaned || driver.owners[instance.owner.InstanceID] != instance || completed(original.Done()) {
		t.Fatal("unjoined original owner or stage was released")
	}
	if _, err := root.Lstat("stage"); err != nil {
		t.Fatal("unjoined stage was removed")
	}
	l.mu.Lock()
	sticky := l.failure
	l.mu.Unlock()
	if sticky != nil {
		t.Fatal("first transient join refusal became permanent context failure")
	}
	transport.mu.Lock()
	transport.mode = ""
	transport.mu.Unlock()
	retry, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	if err := composition.Close(retry); err != nil {
		t.Fatal("actual composition cleanup could not retry original context owner", err)
	}
	if !instance.cleaned || !completed(original.Done()) || !completed(l.joined) || len(driver.owners) != 0 || !composition.closed {
		t.Fatal("original context/driver/composition did not join")
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.closeClaims) < 2 {
		t.Fatal("production cleanup order never retried original allocation")
	}
	for _, claim := range transport.closeClaims {
		if claim.OpenRequestID != transport.open.OpenRequestID {
			t.Fatal("cleanup retried a replacement allocation")
		}
	}
}

func TestNativeSubscriptionContextJoinsBackgroundCloseAfterCallerTimeout(t *testing.T) {
	l, op, transport, _, handle, _, _ := nativeSubscriptionContextFixture(t, "blocked-close")
	t.Cleanup(func() { close(transport.closeRelease) })
	sub := l.ownedSubscription(op, handle)
	request, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, code := l.unsubscribeDomain(request, op, handle)
	cancel()
	if code == "ok" {
		t.Fatal("blocked close reported joined")
	}
	<-transport.closeEntered
	l.mu.Lock()
	run := sub.closeRun
	l.mu.Unlock()
	select {
	case <-run:
	case <-time.After(2 * time.Second):
		t.Fatal("first close attempt did not settle")
	}
	transport.closeRelease <- struct{}{}
	select {
	case <-sub.joined:
	case <-time.After(2 * time.Second):
		t.Fatal("original background join could not release context reservation")
	}
	l.mu.Lock()
	failure := l.failure
	l.mu.Unlock()
	if failure != nil || !completed(sub.ownerDone) {
		t.Fatal("recovered background close became a permanent failure")
	}
}

func TestNativeSubscriptionWithheldEventClosesOriginalAndPreventsContinuation(t *testing.T) {
	for _, gate := range []string{"outer-admission", "final-recheck", "canceled-delivery"} {
		t.Run(gate, func(t *testing.T) {
			l, op, transport, _, handle, _, _ := nativeSubscriptionContextFixture(t, "")
			originalSubscription := l.ownedSubscription(op, handle)
			original := originalSubscription.lease.(*nativeRemoteSubscription)
			prior := transport.authority.mutate
			var eventCalls, afterSecond atomic.Int32
			var recoverAuthority atomic.Bool
			request, cancel := context.WithCancel(context.Background())
			defer cancel()
			transport.authority.mutate = func(claims map[string]any) {
				prior(claims)
				if recoverAuthority.Load() {
					return
				}
				if claims["method"] == "admit-domain-event" && eventCalls.Add(1) == 2 {
					if gate == "outer-admission" {
						claims["outcome"] = "denied"
						claims["result"] = nil
					}
					if gate == "canceled-delivery" {
						cancel()
					}
				}
				if gate == "final-recheck" && claims["method"] == "recheck" && eventCalls.Load() >= 2 {
					if fields, ok := claims["result"].(map[string]any); ok && fields["operationAuthorityRef"] != nil && afterSecond.Add(1) == 2 {
						claims["outcome"] = "denied"
						claims["result"] = nil
					}
				}
			}
			if data, code := l.nextDomainEvent(request, op, handle); code == "ok" || data != nil {
				t.Fatal("withheld event escaped final disclosure gate")
			}
			if eventCalls.Load() != 2 {
				t.Fatal("regression did not reach outer event admission")
			}
			recoverAuthority.Store(true)
			beforeNext := transport.nextCalls.Load()
			if data, code := l.nextDomainEvent(context.Background(), op, handle); code != "context_domain_unavailable" || data != nil {
				t.Fatal("withheld cursor silently continued after authority recovered")
			}
			if originalSubscription.ctx.Err() == nil || transport.nextCalls.Load() != beforeNext {
				t.Fatal("withheld original lease was left reusable")
			}
			cleanup, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err := l.Close(cleanup); err != nil || !completed(original.Done()) {
				t.Fatal("withheld original lease did not join", err)
			}
		})
	}
}

type permanentSubscriptionClose struct {
	err   error
	calls int
	done  chan struct{}
}

func (*permanentSubscriptionClose) Next(context.Context) ([]byte, error) {
	return nil, errors.New("unavailable")
}
func (s *permanentSubscriptionClose) Done() <-chan struct{}       { return s.done }
func (s *permanentSubscriptionClose) Close(context.Context) error { s.calls++; return s.err }
func TestContextSubscriptionCleanupPreservesOpaquePermanentFailure(t *testing.T) {
	consumed := &nativeAdmissionTestCloser{}
	failure := closeAdmission(consumed, errors.New("private original cleanup"))
	done := make(chan struct{})
	close(done)
	original := &permanentSubscriptionClose{err: failure, done: done}
	sub := &contextSubscription{lease: original, ownerDone: done, cleanupJoined: make(chan struct{})}
	l := &contextLease{}
	for range 2 {
		if !errors.Is(l.closeSubscription(context.Background(), sub), failure) {
			t.Fatal("permanent failure was cleared")
		}
	}
	if original.calls != 1 || consumed.calls != 1 || completed(sub.cleanupJoined) || sub.permanentCloseErr == nil {
		t.Fatal("opaque original cleanup owner was retried or released")
	}
}
