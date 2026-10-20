package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This fixture checks the host's authority boundary, not enrollment or signing.
type subscriptionTestAuthority struct {
	calls atomic.Int32
	deny  atomic.Bool
}

func (a *subscriptionTestAuthority) AdmitDomainEvent(_ context.Context, _ OwnerReference, _ ContextOperationAdmission, approved ContextApprovedEnvelope, event []byte) ([]byte, error) {
	a.calls.Add(1)
	if a.deny.Load() || approved.BindingID != "events" || !bytes.Equal(event, []byte(`{"signed":"fixture"}`)) {
		return nil, errors.New("private event refusal")
	}
	return []byte(`{"accepted":true}`), nil
}

type subscriptionTestLease struct {
	done    chan struct{}
	closed  chan struct{}
	release chan struct{}
	once    sync.Once
	calls   atomic.Int32
	next    func(context.Context) ([]byte, error)
}

func (s *subscriptionTestLease) Next(ctx context.Context) ([]byte, error) {
	s.calls.Add(1)
	if s.next != nil {
		return s.next(ctx)
	}
	return []byte(`{"signed":"fixture"}`), nil
}
func (s *subscriptionTestLease) Close(context.Context) error {
	s.once.Do(func() { close(s.closed); <-s.release; close(s.done) })
	return nil
}
func (s *subscriptionTestLease) Done() <-chan struct{} { return s.done }
func newSubscriptionTestLease() *subscriptionTestLease {
	return &subscriptionTestLease{done: make(chan struct{}), closed: make(chan struct{}), release: make(chan struct{})}
}
func subscriptionHarness(t *testing.T) (*contextLease, *contextOperation, *subscriptionTestLease, *subscriptionTestAuthority, ContextDomainCall) {
	t.Helper()
	manifest := fixtureManifest("subscription_package")
	manifest.RequestedCapabilities = []Capability{{Action: "subscribe", ResourceClass: "status"}}
	pkg := fixturePackage(t, manifest, map[string][]byte{"schemas/config.json": []byte(`{"type":"object"}`)})
	ctx, cancel := context.WithCancel(context.Background())
	var envelope struct {
		Operation json.RawMessage `json:"operation"`
	}
	if err := json.Unmarshal(contextTestEnvelope("a"), &envelope); err != nil {
		t.Fatal(err)
	}
	op := &contextOperation{ctx: ctx, cancel: cancel, admission: ContextOperationAdmission{Operation: envelope.Operation}}
	lease := newSubscriptionTestLease()
	authority := &subscriptionTestAuthority{}
	l := &contextLease{binding: ContextBinding{Package: pkg}, done: make(chan struct{}), ctx: ctx, cancel: cancel, admission: ContextInstanceAdmission{DomainBindings: []ContextDomainBinding{{ID: "events", ContractID: "status-events", Action: "subscribe", ResourceClass: "status"}}}}
	l.ports = ContextPorts{Authority: &contextTestAuthority{}, SubscriptionAuthority: authority, Subscribe: func(context.Context, ContextApprovedEnvelope) (ContextSubscriptionLease, error) { return lease, nil }}
	t.Cleanup(func() {
		cancel()
		select {
		case <-lease.release:
		default:
			close(lease.release)
		}
		l.joinOperationSubscriptions(op)
		l.workers.Wait()
	})
	return l, op, lease, authority, ContextDomainCall{RequestID: contextTestNonce("request"), BindingID: "events", ContractID: "status-events", Payload: []byte(`{"filter":"status"}`)}
}
func subscriptionHandle(t *testing.T, raw []byte, code string) string {
	t.Helper()
	if code != "ok" {
		t.Fatal(code)
	}
	var result struct {
		Handle string `json:"subscriptionHandle"`
	}
	if json.Unmarshal(raw, &result) != nil || result.Handle == "" {
		t.Fatal("subscription handle missing")
	}
	return result.Handle
}
func TestContextSubscriptionEventAuthorityAndOperationOwnership(t *testing.T) {
	l, op, lease, authority, call := subscriptionHarness(t)
	raw, code := l.subscribeDomain(context.Background(), op, call)
	handle := subscriptionHandle(t, raw, code)
	other := &contextOperation{ctx: op.ctx}
	if _, code = l.nextDomainEvent(context.Background(), other, handle); code != "context_domain_unavailable" || lease.calls.Load() != 0 {
		t.Fatal("another operation accessed subscription")
	}
	raw, code = l.nextDomainEvent(context.Background(), op, handle)
	if code != "ok" || !bytes.Equal(raw, []byte(`{"accepted":true}`)) || authority.calls.Load() != 1 {
		t.Fatal("event did not pass event authority")
	}
	authority.deny.Store(true)
	if raw, code = l.nextDomainEvent(context.Background(), op, handle); code != "context_authority_unavailable" || len(raw) != 0 {
		t.Fatal("denied event escaped")
	}
}
func TestContextSubscriptionBindingAndCapacityBeforeOpen(t *testing.T) {
	l, op, _, _, call := subscriptionHarness(t)
	var opens atomic.Int32
	l.ports.Subscribe = func(context.Context, ContextApprovedEnvelope) (ContextSubscriptionLease, error) {
		opens.Add(1)
		return nil, errors.New("private open failure")
	}
	wrong := call
	wrong.ContractID = "other-events"
	if _, code := l.subscribeDomain(context.Background(), op, wrong); code != "context_domain_unavailable" {
		t.Fatal(code)
	}
	l.subscriptions = map[string]*contextSubscription{}
	for i := 0; i < contextSubscriptionLimit; i++ {
		l.subscriptions[contextTestNonce("subscription")] = &contextSubscription{operation: &contextOperation{}}
	}
	if _, code := l.subscribeDomain(context.Background(), op, call); code != "context_capacity_exceeded" {
		t.Fatal(code)
	}
	if opens.Load() != 0 {
		t.Fatal("invalid binding or exhausted capacity opened subscription")
	}
}
func TestContextSubscriptionCloseKeepsOriginalReservationUntilJoin(t *testing.T) {
	l, op, lease, _, call := subscriptionHarness(t)
	raw, code := l.subscribeDomain(context.Background(), op, call)
	handle := subscriptionHandle(t, raw, code)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, code = l.unsubscribeDomain(ctx, op, handle); code != "context_operation_canceled" {
		t.Fatal(code)
	}
	select {
	case <-lease.closed:
	case <-time.After(time.Second):
		t.Fatal("close did not start")
	}
	l.mu.Lock()
	retained := l.subscriptions[handle] != nil
	l.mu.Unlock()
	if !retained {
		t.Fatal("unjoined original subscription released capacity")
	}
	joined := make(chan struct{})
	go func() { l.joinOperationSubscriptions(op); close(joined) }()
	select {
	case <-joined:
		t.Fatal("operation released unjoined resource")
	default:
	}
	close(lease.release)
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("original owner did not join")
	}
	l.mu.Lock()
	retained = l.subscriptions[handle] != nil
	l.mu.Unlock()
	if retained {
		t.Fatal("joined subscription retained reservation")
	}
}
func TestContextSubscriptionLateOpenRetainsAndClosesLease(t *testing.T) {
	l, op, lease, _, call := subscriptionHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	l.ports.Subscribe = func(context.Context, ContextApprovedEnvelope) (ContextSubscriptionLease, error) {
		cancel()
		return lease, errors.New("private late open failure")
	}
	if _, code := l.subscribeDomain(ctx, op, call); code != "context_domain_unavailable" {
		t.Fatal(code)
	}
	select {
	case <-lease.closed:
	case <-time.After(time.Second):
		t.Fatal("late lease was not closed")
	}
	l.mu.Lock()
	count := len(l.subscriptions)
	l.mu.Unlock()
	if count != 1 {
		t.Fatal("late unjoined lease was discarded")
	}
	close(lease.release)
	l.joinOperationSubscriptions(op)
}

func TestContextSubscriptionReceiveBoundAndCancellation(t *testing.T) {
	l, op, lease, _, call := subscriptionHarness(t)
	entered := make(chan struct{})
	lease.next = func(ctx context.Context) ([]byte, error) { close(entered); <-ctx.Done(); return nil, ctx.Err() }
	raw, code := l.subscribeDomain(context.Background(), op, call)
	handle := subscriptionHandle(t, raw, code)
	result := make(chan string, 1)
	go func() { _, code := l.nextDomainEvent(context.Background(), op, handle); result <- code }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("receive did not start")
	}
	if _, code = l.nextDomainEvent(context.Background(), op, handle); code != "context_capacity_exceeded" {
		t.Fatal(code)
	}
	op.cancel()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("operation cancellation did not release receive")
	}
}

// The memory owner and event admission are fixtures only. They exercise host
// calls and cleanup without claiming enrolled ingress or signature verification.
type contextMemorySubscription struct {
	events    chan []byte
	canceled  chan struct{}
	done      chan struct{}
	once      sync.Once
	mu        sync.Mutex
	closing   bool
	receivers sync.WaitGroup
}

func newContextMemorySubscription() *contextMemorySubscription {
	return &contextMemorySubscription{events: make(chan []byte, 16), canceled: make(chan struct{}), done: make(chan struct{})}
}
func (s *contextMemorySubscription) Next(ctx context.Context) ([]byte, error) {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return nil, context.Canceled
	}
	s.receivers.Add(1)
	s.mu.Unlock()
	defer s.receivers.Done()
	select {
	case raw := <-s.events:
		return bytes.Clone(raw), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.canceled:
		return nil, context.Canceled
	}
}
func (s *contextMemorySubscription) Close(context.Context) error {
	s.once.Do(func() {
		s.mu.Lock()
		s.closing = true
		close(s.canceled)
		s.mu.Unlock()
		s.receivers.Wait()
		close(s.done)
	})
	return nil
}
func (s *contextMemorySubscription) Done() <-chan struct{} { return s.done }
func (a *contextTestAuthority) AdmitDomainEvent(_ context.Context, _ OwnerReference, _ ContextOperationAdmission, approved ContextApprovedEnvelope, event []byte) ([]byte, error) {
	var value struct {
		BindingID string          `json:"bindingId"`
		Payload   json.RawMessage `json:"payload"`
	}
	if a.deny.Load() || a.denyDomain.Load() || strictDocument(event) != nil || json.Unmarshal(event, &value) != nil || value.BindingID != approved.BindingID || strictDocument(value.Payload) != nil {
		return nil, errors.New("private fixture event refusal")
	}
	return bytes.Clone(value.Payload), nil
}
