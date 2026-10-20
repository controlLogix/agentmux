package plugins

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"
)

type contextBoundsAuthority struct {
	ContextAuthority
	admit   func(context.Context, OwnerReference, []byte) (ContextOperationAdmission, error)
	check   func(context.Context, OwnerReference, ContextInstanceAdmission, *ContextOperationAdmission) error
	prepare func(context.Context, OwnerReference, ContextOperationAdmission, ContextDomainCall) (ContextApprovedEnvelope, error)
}

func (a contextBoundsAuthority) AdmitOperation(ctx context.Context, owner OwnerReference, raw []byte) (ContextOperationAdmission, error) {
	if a.admit != nil {
		return a.admit(ctx, owner, raw)
	}
	return a.ContextAuthority.AdmitOperation(ctx, owner, raw)
}
func (a contextBoundsAuthority) Recheck(ctx context.Context, owner OwnerReference, instance ContextInstanceAdmission, op *ContextOperationAdmission) error {
	if a.check != nil {
		return a.check(ctx, owner, instance, op)
	}
	return a.ContextAuthority.Recheck(ctx, owner, instance, op)
}
func (a contextBoundsAuthority) PrepareDomainCall(ctx context.Context, owner OwnerReference, op ContextOperationAdmission, call ContextDomainCall) (ContextApprovedEnvelope, error) {
	if a.prepare != nil {
		return a.prepare(ctx, owner, op, call)
	}
	return a.ContextAuthority.PrepareDomainCall(ctx, owner, op, call)
}

func TestContextAdmissionConsumesSignedDeadline(t *testing.T) {
	var advance atomic.Bool
	f := newContextTestFixture(t, func(_ *ContextBinding, ports *ContextPorts) {
		ports.Now = func() time.Time {
			if advance.Load() {
				return time.Now().Add(2 * time.Minute)
			}
			return time.Now()
		}
		ports.Authority = contextBoundsAuthority{ContextAuthority: ports.Authority, check: func(_ context.Context, _ OwnerReference, _ ContextInstanceAdmission, op *ContextOperationAdmission) error {
			if op != nil {
				advance.Store(true)
			}
			return nil
		}}
	})
	_, err := f.lease.Dispatch(context.Background(), contextTestEnvelope("a"))
	if err == nil || err.Error() != "context_operation_stale" {
		t.Fatalf("expired admission: %v", err)
	}
	if len(f.connection.invokes) != 0 {
		t.Fatal("expired operation reached child")
	}
}

func TestContextAdmissionHasPermitAndBudget(t *testing.T) {
	var calls atomic.Int32
	f := newContextTestFixture(t, func(_ *ContextBinding, ports *ContextPorts) {
		ports.Authority = contextBoundsAuthority{ContextAuthority: ports.Authority, admit: func(ctx context.Context, _ OwnerReference, _ []byte) (ContextOperationAdmission, error) {
			calls.Add(1)
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > contextCallBudget {
				t.Error("admission lacks short budget")
			}
			return ContextOperationAdmission{}, pluginError("fixture_refused")
		}}
	})
	for range contextOperationLimit {
		f.lease.admissions <- struct{}{}
	}
	_, err := f.lease.Dispatch(context.Background(), contextTestEnvelope("a"))
	if err == nil || err.Error() != "context_capacity_exceeded" || calls.Load() != 0 {
		t.Fatal("full admission called authority")
	}
	for range contextOperationLimit {
		<-f.lease.admissions
	}
	_, _ = f.lease.Dispatch(context.Background(), contextTestEnvelope("a"))
	if calls.Load() != 1 {
		t.Fatal("available admission did not call authority")
	}
}

func TestContextDomainBindingRefusedBeforeAuthority(t *testing.T) {
	var checks atomic.Int32
	f := newContextTestFixture(t, func(_ *ContextBinding, ports *ContextPorts) {
		ports.Authority = contextBoundsAuthority{ContextAuthority: ports.Authority, check: func(context.Context, OwnerReference, ContextInstanceAdmission, *ContextOperationAdmission) error {
			checks.Add(1)
			return nil
		}}
	})
	handle, result := f.dispatch(t, context.Background(), "a")
	before := checks.Load()
	for _, params := range []map[string]any{
		{"bindingId": "missing", "contractId": "status-query", "payload": nil},
		{"bindingId": "owner", "contractId": "missing", "payload": nil},
	} {
		if f.call(t, "domainGateway", "request", &handle, params).Code != "context_domain_unavailable" {
			t.Fatal("unknown domain accepted")
		}
	}
	if checks.Load() != before {
		t.Fatal("unknown domain reached authority")
	}
	f.complete(handle)
	if contextTestResult(t, result).err != nil {
		t.Fatal("operation failed")
	}
}

func TestContextCanceledDomainApprovalCannotCallOwner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := newContextTestFixture(t, func(_ *ContextBinding, ports *ContextPorts) {
		original := ports.Authority
		ports.Authority = contextBoundsAuthority{ContextAuthority: original, prepare: func(ctx context.Context, owner OwnerReference, op ContextOperationAdmission, call ContextDomainCall) (ContextApprovedEnvelope, error) {
			approved, err := original.PrepareDomainCall(ctx, owner, op, call)
			cancel()
			return approved, err
		}}
	})
	handle, result := f.dispatch(t, ctx, "a")
	if f.call(t, "domainGateway", "request", &handle, map[string]any{"bindingId": "owner", "contractId": "status-query", "payload": nil}).Code != "context_operation_canceled" {
		t.Fatal("canceled approval accepted")
	}
	if contextTestResult(t, result).err == nil {
		t.Fatal("canceled operation accepted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.domains != 0 {
		t.Fatal("canceled approval called owner")
	}
}

func TestContextDomainAdmissionRequiresManifestCapability(t *testing.T) {
	f := newContextTestFixture(t, nil)
	for _, field := range []string{"action", "resource"} {
		admission := cloneInstanceAdmission(f.lease.admission)
		if field == "action" {
			admission.DomainBindings[0].Action = "delete"
		} else {
			admission.DomainBindings[0].ResourceClass = "other"
		}
		if _, _, _, err := contextDescriptor("context_hub", f.lease.binding, admission, time.Now()); err == nil {
			t.Fatal("undeclared domain capability accepted")
		}
	}
}

func TestContextDistinctPayloadNumbersStayDistinct(t *testing.T) {
	if sameContextJSON([]byte(`{"value":1.00000000000000001}`), []byte(`{"value":1.00000000000000002}`)) {
		t.Fatal("distinct payload numbers collapsed")
	}
	if !sameContextJSON([]byte(`{"value":1}`), []byte(`{ "value": 1 }`)) {
		t.Fatal("equivalent formatting refused")
	}
}

func TestContextUnjoinedLeaseRefusesDuplicateOwner(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	f := newContextTestFixture(t, func(_ *ContextBinding, ports *ContextPorts) {
		ports.Log = func(context.Context, ContextLogRecord) error { close(entered); <-release; return nil }
	})
	defer close(release)
	var request contextServiceRequest
	if err := json.Unmarshal(f.request("logger", "record-instance", nil, map[string]any{"eventCode": "operation_started"}), &request); err != nil {
		t.Fatal(err)
	}
	f.connection.requests <- contextJSON(request)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("log owner not entered")
	}
	f.lease.Invalidate()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.lease.Close(ctx); err == nil {
		t.Fatal("unjoined lease closed")
	}
	if _, err := f.provider.Open(context.Background(), f.lease.binding); err == nil || err.Error() != "context_instance_owned" {
		t.Fatalf("unjoined owner replaced: %v", err)
	}
}

func TestContextActorTagsAreCopiedAndCannotBeSuppliedByChild(t *testing.T) {
	f := newContextTestFixture(t, nil)
	handle, result := f.dispatch(t, context.Background(), "a")
	f.lease.mu.Lock()
	op := f.lease.operations[handle]
	f.lease.mu.Unlock()
	tags := f.lease.tags(op)
	contextTestActorTags(t, tags, "a")
	tags.AuthenticatedIdentityRef.ID = "changed"
	tags.EffectiveActorRef.ID = "changed"
	tags.DelegationRef.ID = "changed"
	contextTestActorTags(t, f.lease.tags(op), "a")
	for _, field := range []string{"authenticatedIdentityRef", "effectiveActorRef", "delegationRef"} {
		if f.call(t, "logger", "record", &handle, map[string]any{"eventCode": "operation_started", field: ContextReference{"forged", "context_hub", 1}}).Outcome != "rejected" {
			t.Fatal("child supplied attribution reference")
		}
	}
	withoutDelegation := &contextOperation{claims: op.claims}
	withoutDelegation.claims.DelegationRef = nil
	if f.lease.tags(withoutDelegation).DelegationRef != nil {
		t.Fatal("missing delegation replaced with ambient reference")
	}
	instance := f.lease.tags(nil)
	if instance.AuthenticatedIdentityRef != nil || instance.EffectiveActorRef != nil || instance.DelegationRef != nil {
		t.Fatal("instance log invented caller attribution")
	}
	f.complete(handle)
	if contextTestResult(t, result).err != nil {
		t.Fatal("operation failed")
	}
}

func TestContextCompletionJoinsAdmissionBeforeUsers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	canceled, finished := make(chan struct{}), make(chan struct{})
	op := &contextOperation{handle: "operation", ctx: ctx, cancel: func() { cancel(); close(canceled) }, spans: map[string]string{}}
	l := &contextLease{operations: map[string]*contextOperation{"operation": op}}
	l.mu.Lock()
	go func() { l.finishOperation(op); close(finished) }()
	// Model a service that has passed its context check while holding the
	// admission lock, but has not added its user yet.
	select {
	case <-canceled:
		l.mu.Unlock()
		<-finished
		t.Fatal("completion crossed active admission")
	case <-time.After(20 * time.Millisecond):
	}
	op.users.Add(1)
	l.mu.Unlock()
	<-canceled
	select {
	case <-finished:
		t.Fatal("completion missed admitted service")
	default:
	}
	op.users.Done()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("completion did not join service")
	}
}

func TestContextDirectDispatchRequiresReadyHealthyOwner(t *testing.T) {
	f := newContextTestFixture(t, nil)
	source := f.lease.binding.Lifecycle.(*nativeContextLifecycle)
	if source.ReportHealth("unhealthy") != nil {
		t.Fatal("health report failed")
	}
	if _, err := f.lease.Dispatch(context.Background(), contextTestEnvelope("a")); err == nil {
		t.Fatal("unhealthy lease admitted call")
	}
	if source.ReportHealth("healthy") != nil {
		t.Fatal("health recovery failed")
	}
	handle, result := f.dispatch(t, context.Background(), "a")
	source.beginDrain()
	if _, err := f.lease.Dispatch(context.Background(), contextTestEnvelope("b")); err == nil {
		t.Fatal("draining lease admitted call")
	}
	if f.call(t, "logger", "record", &handle, map[string]any{"eventCode": "operation_started"}).Code != "ok" {
		t.Fatal("drain canceled admitted operation")
	}
	f.complete(handle)
	if contextTestResult(t, result).err != nil {
		t.Fatal("drained operation could not finish")
	}
}
