package plugins

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This transport and authority exercise the host boundary offline. They do not
// qualify enrolled human identity, signatures, grants or a real remote owner.
type contextTestConnection struct {
	transport                                    ContextTransport
	requests, results, replies, invokes, cancels chan []byte
	done                                         chan struct{}
	once                                         sync.Once
	closed                                       atomic.Int32
}

func newContextTestConnection(transport ContextTransport) *contextTestConnection {
	return &contextTestConnection{transport: transport, requests: make(chan []byte, 128), results: make(chan []byte, 128),
		replies: make(chan []byte, 128), invokes: make(chan []byte, 128), cancels: make(chan []byte, 128), done: make(chan struct{})}
}
func (c *contextTestConnection) Publish(ctx context.Context, subject string, raw []byte) error {
	var out chan []byte
	switch subject {
	case c.transport.ReplySubject:
		out = c.replies
	case c.transport.InvokeSubject:
		out = c.invokes
	case c.transport.CancelSubject:
		out = c.cancels
	default:
		return errors.New("private-transport-detail")
	}
	select {
	case <-c.done:
		return errors.New("private-transport-detail")
	case <-ctx.Done():
		return ctx.Err()
	case out <- bytes.Clone(raw):
		return nil
	}
}
func (c *contextTestConnection) Receive(ctx context.Context, result bool) ([]byte, error) {
	input := c.requests
	if result {
		input = c.results
	}
	select {
	case <-c.done:
		return nil, errors.New("private-transport-detail")
	case <-ctx.Done():
		return nil, ctx.Err()
	case raw := <-input:
		return raw, nil
	}
}
func (c *contextTestConnection) Close()                { c.closed.Add(1); c.once.Do(func() { close(c.done) }) }
func (c *contextTestConnection) Done() <-chan struct{} { return c.done }

type contextTestAuthority struct {
	deny       atomic.Bool
	denyDomain atomic.Bool
	instance   ContextInstanceAdmission
}

func (a *contextTestAuthority) BindInstance(context.Context, ContextBinding) (ContextInstanceAdmission, error) {
	if a.deny.Load() {
		return ContextInstanceAdmission{}, errors.New("private-authority-detail")
	}
	return cloneInstanceAdmission(a.instance), nil
}
func (a *contextTestAuthority) AdmitOperation(_ context.Context, _ OwnerReference, raw []byte) (ContextOperationAdmission, error) {
	if a.deny.Load() {
		return ContextOperationAdmission{}, errors.New("private-authority-detail")
	}
	var envelope struct {
		Operation json.RawMessage `json:"operation"`
	}
	var claims contextOperationClaims
	if json.Unmarshal(raw, &envelope) != nil || json.Unmarshal(envelope.Operation, &claims) != nil ||
		claims.Scope.ProjectID == nil || (claims.Caller.PrincipalID != "caller_a" && claims.Caller.PrincipalID != "caller_b") ||
		*claims.Scope.ProjectID != "project_"+strings.TrimPrefix(claims.Caller.PrincipalID, "caller_") {
		return ContextOperationAdmission{}, errors.New("private-authority-detail")
	}
	return ContextOperationAdmission{Operation: bytes.Clone(envelope.Operation), AuthorityRef: ContextReference{"operation_authority", "context_hub", 1}}, nil
}
func (a *contextTestAuthority) Recheck(context.Context, OwnerReference, ContextInstanceAdmission, *ContextOperationAdmission) error {
	if a.deny.Load() {
		return errors.New("private-authority-detail")
	}
	return nil
}
func (a *contextTestAuthority) PrepareDomainCall(_ context.Context, _ OwnerReference, op ContextOperationAdmission, call ContextDomainCall) (ContextApprovedEnvelope, error) {
	if a.denyDomain.Load() {
		return ContextApprovedEnvelope{}, errors.New("private-authority-detail")
	}
	var operation map[string]any
	_ = json.Unmarshal(op.Operation, &operation)
	operation["causationId"] = operation["operationId"]
	operation["operationId"], _ = ContextDownstreamOperationID(operation["operationId"].(string), call.RequestID)
	return ContextApprovedEnvelope{BindingID: call.BindingID, Envelope: contextJSON(map[string]any{"contractId": call.ContractID,
		"operation": operation, "payload": json.RawMessage(call.Payload)})}, nil
}

type contextTestFixture struct {
	lease      *contextLease
	provider   *contextProvider
	authority  *contextTestAuthority
	connection *contextTestConnection
	lifetime   chan struct{}
	mu         sync.Mutex
	logs       []ContextLogRecord
	traces     []ContextTraceRecord
	metrics    []ContextMetricRecord
	domains    int
}

func newContextTestFixture(t *testing.T, change func(*ContextBinding, *ContextPorts)) *contextTestFixture {
	t.Helper()
	f := &contextTestFixture{lifetime: make(chan struct{})}
	manifest := fixtureManifest("context_package")
	manifest.RequestedCapabilities = []Capability{{Action: "inspect", ResourceClass: "status", Required: false}}
	pkg := fixturePackage(t, manifest, map[string][]byte{"schemas/config.json": []byte(`{"type":"object"}`)})
	configuration, err := PrepareConfiguration(pkg, nil, []byte("{\n \"private\":\"configuration-secret\"\n}"))
	if err != nil {
		t.Fatal(err)
	}
	binding := ContextBinding{Owner: OwnerReference{Pin: pkg.Pin(), InstanceID: "context_instance", Epoch: strings.Repeat("a", 64), Generation: 1}, Package: pkg, Configuration: configuration, LifetimeDone: f.lifetime}
	lifecycle := newNativeContextLifecycle(binding.Owner)
	lifecycle.markReady()
	binding.Lifecycle = lifecycle
	ref := ContextReference{"context_scope", "context_hub", 1}
	f.authority = &contextTestAuthority{instance: ContextInstanceAdmission{ScopeRef: ref, ConfigurationRevision: 7, SecretReferences: []ContextReference{},
		DomainBindings: []ContextDomainBinding{{ID: "owner", ContractID: "status-query", Action: "inspect", ResourceClass: "status"}}}}
	f.authority.instance.EffectiveGrant = contextJSON(map[string]any{"grantId": "context_grant", "issuerHubId": "context_hub", "subjectInstanceId": binding.Owner.InstanceID,
		"scope": map[string]any{"organizationId": "context_org", "projectId": nil, "workspaceId": nil}, "actions": []string{"inspect"}, "resourceIds": []string{"fixture_resource"},
		"issuedAt": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), "expiresAt": time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "policyRef": ref, "parentGrantRef": ref, "revision": 1})
	ports := ContextPorts{Authority: f.authority, Configuration: newContextMemoryConfigurationOwner(), Now: time.Now, EventCodes: []string{"operation_started"}, SpanCodes: []string{"domain_request"}, MetricCodes: []string{"calls"}}
	ports.SubscriptionAuthority = f.authority
	ports.Subscribe = func(_ context.Context, approved ContextApprovedEnvelope) (ContextSubscriptionLease, error) {
		lease := newContextMemorySubscription()
		lease.events <- contextJSON(map[string]any{"bindingId": approved.BindingID, "payload": map[string]any{"event": "status_changed"}})
		return lease, nil
	}
	ports.Log = func(_ context.Context, record ContextLogRecord) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.logs = append(f.logs, record)
		return nil
	}
	ports.Trace = func(_ context.Context, record ContextTraceRecord) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.traces = append(f.traces, record)
		return nil
	}
	ports.Metric = func(_ context.Context, record ContextMetricRecord) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.metrics = append(f.metrics, record)
		return nil
	}
	ports.Domain = func(_ context.Context, approved ContextApprovedEnvelope) ([]byte, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.domains++
		return []byte(`{"accepted":true}`), nil
	}
	if change != nil {
		change(&binding, &ports)
	}
	f.provider = &contextProvider{options: NATSContextOptions{HubID: "context_hub", ServerURL: "tls://context.invalid:4222"}, ports: ports,
		clients: map[string]lifecycleCredential{binding.Owner.InstanceID: {public: "fixture-public", raw: []byte("credential-secret")}}, ca: []byte("ca-fixture")}
	f.provider.connect = func(_ context.Context, transport ContextTransport) (contextConnection, error) {
		f.connection = newContextTestConnection(transport)
		return f.connection, nil
	}
	startup, cancel := context.WithTimeout(context.Background(), time.Second)
	lease, err := f.provider.Open(startup, binding)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	f.lease = lease.(*contextLease)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := f.lease.Close(ctx); err != nil {
			t.Errorf("context cleanup: %v", err)
		}
	})
	return f
}
func contextTestRead(t *testing.T, ch <-chan []byte) []byte {
	t.Helper()
	select {
	case raw := <-ch:
		return raw
	case <-time.After(2 * time.Second):
		t.Fatal("context response deadline")
		return nil
	}
}
func contextTestNonce(prefix string) string {
	nonce, _ := randomControlID()
	return prefix + "_" + nonce
}
func contextTestEnvelope(name string) []byte {
	ref := ContextReference{"operation_reference", "context_hub", 1}
	op := map[string]any{"schemaVersion": "1.0.0", "operationId": "operation_" + name, "payloadDigest": "sha256:" + strings.Repeat("b", 64), "expectedVersion": 1,
		"caller": map[string]any{"principalId": "caller_" + name, "kind": "service", "authenticatedIdentityRef": ContextReference{"identity_" + name, "context_hub", 1}}, "effectiveActorRef": ContextReference{"actor_" + name, "context_hub", 1},
		"scope": map[string]any{"organizationId": "context_org", "projectId": "project_" + name, "workspaceId": nil}, "taskId": nil, "runId": nil, "attemptId": nil,
		"delegationRef": ContextReference{"delegation_" + name, "context_hub", 1}, "grantRef": ref, "approvalRefs": []any{}, "traceId": "trace_" + name, "causationId": "cause_" + name,
		"deadline": time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano), "cancellationRef": ref}
	return contextJSON(map[string]any{"operation": op, "payload": map[string]any{"private": "payload-secret"}})
}

type contextDispatchResult struct {
	raw []byte
	err error
}

func (f *contextTestFixture) dispatch(t *testing.T, ctx context.Context, name string) (string, <-chan contextDispatchResult) {
	t.Helper()
	result := make(chan contextDispatchResult, 1)
	go func() {
		raw, err := f.lease.Dispatch(ctx, contextTestEnvelope(name))
		result <- contextDispatchResult{raw, err}
	}()
	var invoke struct {
		OperationHandle string `json:"operationHandle"`
	}
	if json.Unmarshal(contextTestRead(t, f.connection.invokes), &invoke) != nil || invoke.OperationHandle == "" {
		t.Fatal("invocation missing")
	}
	return invoke.OperationHandle, result
}
func (f *contextTestFixture) request(service, method string, operation *string, parameters any) []byte {
	return contextJSON(contextServiceRequest{SchemaVersion: "1.0.0", Kind: "plugin-context-request", RequestID: contextTestNonce("request"), Owner: f.lease.Owner(),
		HandleID: f.lease.handles[service], Service: service, Method: method, OperationHandle: operation, Parameters: contextJSON(parameters)})
}
func (f *contextTestFixture) call(t *testing.T, service, method string, operation *string, parameters any) contextServiceReply {
	t.Helper()
	return f.rawCall(t, f.request(service, method, operation, parameters))
}
func (f *contextTestFixture) rawCall(t *testing.T, raw []byte) contextServiceReply {
	t.Helper()
	f.connection.requests <- raw
	var reply contextServiceReply
	if decodeContextJSON("plugin-context-reply", contextTestRead(t, f.connection.replies), &reply) != nil {
		t.Fatal("invalid context reply")
	}
	return reply
}
func (f *contextTestFixture) complete(handle string) {
	f.connection.results <- contextJSON(contextOperationResult{SchemaVersion: "1.0.0", Kind: "plugin-operation-result", Owner: f.lease.Owner(), OperationHandle: handle, Outcome: "completed", Value: []byte(`{"done":true}`)})
}
func contextTestResult(t *testing.T, ch <-chan contextDispatchResult) contextDispatchResult {
	t.Helper()
	select {
	case result := <-ch:
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("dispatch deadline")
		return contextDispatchResult{}
	}
}

func TestContextAdmissionSnapshotsAndMissingOwners(t *testing.T) {
	f := newContextTestFixture(t, nil)
	if completed(f.lease.Done()) {
		t.Fatal("startup cancellation ended lease")
	}
	if _, err := f.provider.Open(context.Background(), f.lease.binding); err == nil {
		t.Fatal("duplicate context owner accepted")
	}
	before := f.lease.Descriptor()
	for _, raw := range [][]byte{f.lease.Descriptor(), f.lease.Bootstrap().Descriptor(), f.lease.Bootstrap().Credentials(), f.lease.Bootstrap().CA()} {
		raw[0] = 'x'
	}
	if !bytes.Equal(before, f.lease.Descriptor()) || string(f.lease.Bootstrap().Credentials()) != "credential-secret" {
		t.Fatal("mutable bootstrap snapshot")
	}
	for _, value := range []any{f.lease, f.lease.Bootstrap(), f.lease.binding, f.authority.instance, ContextOperationAdmission{Operation: []byte("payload-secret")}} {
		encoded, _ := json.Marshal(value)
		text := fmt.Sprintf("%v %+v %#v %s %q", value, value, value, value, value) + string(encoded)
		if strings.Contains(text, "credential-secret") || strings.Contains(text, "configuration-secret") || strings.Contains(text, "payload-secret") {
			t.Fatal("private context exposed")
		}
	}
	for _, missing := range []string{"authority", "log", "trace", "metric", "domain", "subscription", "event-authority", "configuration", "clock"} {
		ports := f.provider.ports
		switch missing {
		case "authority":
			ports.Authority = nil
		case "log":
			ports.Log = nil
		case "trace":
			ports.Trace = nil
		case "metric":
			ports.Metric = nil
		case "domain":
			ports.Domain = nil
		case "subscription":
			ports.Subscribe = nil
		case "event-authority":
			ports.SubscriptionAuthority = nil
		case "configuration":
			ports.Configuration = nil
		case "clock":
			ports.Now = nil
		}
		if _, err := NewNATSContextProvider(context.Background(), NATSContextOptions{}, ports); err == nil {
			t.Fatal("missing owner accepted")
		}
	}
}

func TestContextSevenServicesKeepConcurrentCallersSeparate(t *testing.T) {
	f := newContextTestFixture(t, nil)
	a, ar := f.dispatch(t, context.Background(), "a")
	b, br := f.dispatch(t, context.Background(), "b")
	for _, handle := range []string{a, b} {
		for _, entry := range []struct {
			service, method string
			parameters      any
		}{
			{"logger", "record", map[string]any{"eventCode": "operation_started"}},
			{"metrics", "add", map[string]any{"metricCode": "calls", "value": 1}},
			{"clock", "wait", map[string]any{"durationMs": 1}},
			{"domainGateway", "request", map[string]any{"bindingId": "owner", "contractId": "status-query", "payload": map[string]any{"private": "domain-secret"}}},
		} {
			if reply := f.call(t, entry.service, entry.method, &handle, entry.parameters); reply.Code != "ok" {
				t.Fatalf("%s failed: %s", entry.service, reply.Code)
			}
		}
		configuration := f.call(t, "config", "read", &handle, map[string]any{})
		var config struct {
			Bytes    string `json:"configurationBytes"`
			Revision uint64 `json:"configurationRevision"`
		}
		_ = json.Unmarshal(configuration.Value, &config)
		raw, err := base64.StdEncoding.DecodeString(config.Bytes)
		if configuration.Code != "ok" || err != nil || !bytes.Equal(raw, f.lease.binding.Configuration.Bytes()) || config.Revision != 7 {
			t.Fatal("configuration changed")
		}
		span := f.call(t, "tracing", "start", &handle, map[string]any{"spanCode": "domain_request"})
		var started struct {
			Handle string `json:"spanHandle"`
		}
		_ = json.Unmarshal(span.Value, &started)
		if span.Code != "ok" || started.Handle == "" {
			t.Fatal("trace not started")
		}
		if reply := f.call(t, "tracing", "finish", &handle, map[string]any{"spanHandle": started.Handle, "outcomeCode": "completed"}); reply.Code != "ok" {
			t.Fatal("trace not finished")
		}
	}
	for _, entry := range []struct{ service, method string }{{"clock", "now"}, {"lifecycle", "status"}} {
		if f.call(t, entry.service, entry.method, nil, map[string]any{}).Code != "ok" {
			t.Fatal("instance service unavailable")
		}
	}
	f.complete(a)
	f.complete(b)
	if contextTestResult(t, ar).err != nil || contextTestResult(t, br).err != nil {
		t.Fatal("operation did not complete")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.logs) != 2 || len(f.metrics) != 2 || len(f.traces) != 4 || f.domains != 2 {
		t.Fatal("missing service owner call")
	}
	for _, tags := range []ContextTags{f.logs[0].Tags, f.logs[1].Tags, f.metrics[0].Tags, f.metrics[1].Tags, f.traces[0].Tags, f.traces[2].Tags} {
		suffix := strings.TrimPrefix(tags.PrincipalID, "caller_")
		if tags.ProjectID == nil || *tags.ProjectID != "project_"+suffix || tags.TraceID != "trace_"+suffix || tags.Owner != f.lease.Owner() {
			t.Fatal("caller or identity tags mixed")
		}
		contextTestActorTags(t, tags, suffix)
	}
	diagnostics := fmt.Sprintf("%v %v %v", f.logs, f.metrics, f.traces)
	for _, secret := range []string{"payload-secret", "configuration-secret", "credential-secret", "domain-secret"} {
		if strings.Contains(diagnostics, secret) {
			t.Fatal("secret in diagnostics")
		}
	}
}

func contextTestActorTags(t *testing.T, tags ContextTags, suffix string) {
	t.Helper()
	for name, ref := range map[string]*ContextReference{"identity": tags.AuthenticatedIdentityRef, "actor": tags.EffectiveActorRef, "delegation": tags.DelegationRef} {
		if ref == nil || *ref != (ContextReference{name + "_" + suffix, "context_hub", 1}) {
			t.Fatal("signed attribution reference missing or mixed")
		}
	}
}

func TestContextForgedIdentityHandlesAndStaleOperationsFail(t *testing.T) {
	f := newContextTestFixture(t, nil)
	handle, result := f.dispatch(t, context.Background(), "a")
	for _, change := range []func(map[string]any){
		func(v map[string]any) { v["caller"] = "caller_b" },
		func(v map[string]any) { v["parameters"].(map[string]any)["projectId"] = "project_b" },
		func(v map[string]any) { v["owner"].(map[string]any)["generation"] = 2 },
		func(v map[string]any) { v["handleId"] = contextTestNonce("service") },
		func(v map[string]any) { v["operationHandle"] = contextTestNonce("operation") },
		func(v map[string]any) { v["parameters"].(map[string]any)["eventCode"] = "private_secret" },
	} {
		var request map[string]any
		_ = json.Unmarshal(f.request("logger", "record", &handle, map[string]any{"eventCode": "operation_started"}), &request)
		change(request)
		if reply := f.rawCall(t, contextJSON(request)); reply.Outcome != "rejected" {
			t.Fatal("forged request accepted")
		}
	}
	f.complete(handle)
	if contextTestResult(t, result).err != nil {
		t.Fatal("completion failed")
	}
	if f.call(t, "logger", "record", &handle, map[string]any{"eventCode": "operation_started"}).Code != "context_operation_stale" {
		t.Fatal("finished operation accepted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.logs) != 0 {
		t.Fatal("forged identity reached log owner")
	}
}

func TestContextCancellationReleasesWaitAndFinishesSpan(t *testing.T) {
	f := newContextTestFixture(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	handle, result := f.dispatch(t, ctx, "a")
	if f.call(t, "tracing", "start", &handle, map[string]any{"spanCode": "domain_request"}).Code != "ok" {
		t.Fatal("trace start failed")
	}
	f.connection.requests <- f.request("clock", "wait", &handle, map[string]any{"durationMs": 180000})
	cancel()
	if got := contextTestResult(t, result); got.err == nil || got.err.Error() != "context_operation_canceled" {
		t.Fatal("cancellation outcome lost")
	}
	contextTestRead(t, f.connection.cancels)
	var reply contextServiceReply
	_ = json.Unmarshal(contextTestRead(t, f.connection.replies), &reply)
	if reply.Code != "context_operation_canceled" && reply.Code != "context_operation_stale" {
		t.Fatal("wait remained active")
	}
	f.lease.mu.Lock()
	count := len(f.lease.operations)
	f.lease.mu.Unlock()
	if count != 0 {
		t.Fatal("operation resource retained")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.traces) != 2 || f.traces[1].OutcomeCode != "canceled" {
		t.Fatal("span resource retained")
	}
}

func TestContextRevokedAuthorityAndAbsentDownstreamCannotPublish(t *testing.T) {
	f := newContextTestFixture(t, nil)
	handle, result := f.dispatch(t, context.Background(), "a")
	f.authority.denyDomain.Store(true)
	if f.call(t, "domainGateway", "request", &handle, map[string]any{"bindingId": "owner", "contractId": "status-query", "payload": map[string]any{}}).Code != "context_domain_unavailable" {
		t.Fatal("absent downstream authority accepted")
	}
	f.authority.deny.Store(true)
	if f.call(t, "logger", "record", &handle, map[string]any{"eventCode": "operation_started"}).Code != "context_authority_unavailable" {
		t.Fatal("revoked operation accepted")
	}
	f.complete(handle)
	if contextTestResult(t, result).err == nil {
		t.Fatal("revoked result accepted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.domains != 0 || len(f.logs) != 0 {
		t.Fatal("refused authority caused an owner effect")
	}
}

func TestContextParentLossAndTransportLossInvalidateLease(t *testing.T) {
	for _, reason := range []string{"parent", "transport"} {
		t.Run(reason, func(t *testing.T) {
			parentLifetime := make(chan struct{})
			f := newContextTestFixture(t, func(binding *ContextBinding, _ *ContextPorts) {
				parent := binding.Owner
				parent.InstanceID = "parent_instance"
				binding.Parent = &parent
				binding.ParentLifetime = parentLifetime
			})
			if reason == "parent" {
				close(parentLifetime)
			} else {
				f.connection.once.Do(func() { close(f.connection.done) })
			}
			select {
			case <-f.lease.Done():
			case <-time.After(time.Second):
				t.Fatal("lost context stayed available")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := f.lease.Close(ctx); err != nil {
				t.Fatal(err)
			}
			if f.connection.closed.Load() != 1 {
				t.Fatal("original transport not joined once")
			}
		})
	}
}

func TestContextCloseRetainsUnjoinedOwnerCall(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	f := newContextTestFixture(t, func(_ *ContextBinding, ports *ContextPorts) {
		ports.Log = func(context.Context, ContextLogRecord) error { close(entered); <-release; return nil }
	})
	f.connection.requests <- f.request("logger", "record-instance", nil, map[string]any{"eventCode": "operation_started"})
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("owner call not entered")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	err := f.lease.Close(ctx)
	cancel()
	if err == nil || err.Error() != "context_cleanup_incomplete" || completed(f.lease.joined) {
		t.Fatal("unjoined owner reported success")
	}
	close(release)
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := f.lease.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestContextSchemasMatchPublishedContracts(t *testing.T) {
	for _, name := range []string{"plugin-context", "operation-context", "plugin-context-request", "plugin-context-reply", "plugin-context-operation"} {
		published, err := os.ReadFile(filepath.Join("..", "..", "contracts", "v1", "schemas", name+".schema.json"))
		if err != nil {
			t.Fatal(err)
		}
		embedded, err := contextResources.ReadFile("schemas/" + name + ".schema.json")
		if err != nil || !bytes.Equal(published, embedded) {
			t.Fatal("context schema copies differ")
		}
	}
}

func TestContextCredentialsKeepExactPermissionBoundary(t *testing.T) {
	options := NATSContextOptions{HubID: "context_hub"}
	transport := contextSubjects(options, "context_instance")
	publish := []string{transport.RequestSubject, transport.ResultSubject}
	subscribe := []string{transport.ReplySubject, transport.InvokeSubject, transport.CancelSubject}
	raw, account := signedLifecycleFixture(t, func(_ map[string]any, claims map[string]any) {
		nats := claims["nats"].(map[string]any)
		nats["pub"] = map[string]any{"allow": publish}
		nats["sub"] = map[string]any{"allow": subscribe}
	}, false)
	path := filepath.Join(privateTestDirectory(t), "context.creds")
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("credential fixture write")
	}
	if _, err := readContextCredential(path, account, publish, subscribe); err != nil {
		t.Fatal(err)
	}
	if _, err := readLifecycleCredential(path, account, []string{"amx.control"}, []string{"amx.event"}); err == nil {
		t.Fatal("context credential widened lifecycle profile")
	}
	if _, err := readContextCredential(path, account, []string{"amx.>"}, subscribe); err == nil {
		t.Fatal("wildcard context permission accepted")
	}
}
