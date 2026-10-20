package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type capabilityHandleFixture struct {
	operationLifetime context.Context
	handles           *CapabilityHandles
	authority         *contextTestAuthority
	binding           ContextBinding
	instance          ContextInstanceAdmission
	operation         ContextOperationAdmission
	ports             CapabilityHandlePorts
	lifetime          chan struct{}
	mu                sync.Mutex
	calls             []ContextApprovedEnvelope
}

// This fixture checks typed clients offline. It is not an enrolled authority,
// remote durable owner, real secret store or NATS isolation qualification.
func newCapabilityHandleFixture(t *testing.T, change func(*capabilityHandleFixture)) *capabilityHandleFixture {
	t.Helper()
	f := &capabilityHandleFixture{lifetime: make(chan struct{}), operationLifetime: context.Background()}
	manifest := fixtureManifest("handles_package")
	var routes []ContextDomainBinding
	actions := []string{}
	for contract, spec := range capabilityHandleOperations {
		manifest.RequestedCapabilities = append(manifest.RequestedCapabilities, Capability{Action: spec.action, ResourceClass: spec.class})
		routes = append(routes, ContextDomainBinding{ID: strings.ReplaceAll(contract, "-", "_"), ContractID: contract, Action: spec.action, ResourceClass: spec.class})
		found := false
		for _, a := range actions {
			if a == spec.action {
				found = true
			}
		}
		if !found {
			actions = append(actions, spec.action)
		}
	}
	pkg := fixturePackage(t, manifest, map[string][]byte{"schemas/config.json": []byte(`{"type":"object"}`)})
	f.binding = ContextBinding{Owner: OwnerReference{Pin: pkg.Pin(), InstanceID: "handle_instance", Epoch: strings.Repeat("a", 64), Generation: 1}, Package: pkg, LifetimeDone: f.lifetime}
	ref := ContextReference{"reference", "context_hub", 1}
	f.instance = ContextInstanceAdmission{SecretReferences: []ContextReference{capabilityTestResource()}, DomainBindings: routes, ScopeRef: ref, EffectiveGrant: contextJSON(map[string]any{
		"subjectInstanceId": "handle_instance", "scope": map[string]any{"organizationId": "context_org", "projectId": "project_a", "workspaceId": nil}, "actions": actions, "resourceIds": []string{"record"}, "issuedAt": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano), "expiresAt": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)})}
	f.authority = &contextTestAuthority{}
	var envelope struct {
		Operation json.RawMessage `json:"operation"`
	}
	if json.Unmarshal(contextTestEnvelope("a"), &envelope) != nil {
		t.Fatal("operation fixture")
	}
	f.operation = ContextOperationAdmission{Operation: envelope.Operation, AuthorityRef: ref}
	f.ports = CapabilityHandlePorts{Authority: capabilityStableAuthority{f.authority}, Now: time.Now}
	f.ports.Domain = func(_ context.Context, approved ContextApprovedEnvelope) ([]byte, error) {
		f.mu.Lock()
		f.calls = append(f.calls, approved)
		f.mu.Unlock()
		var message struct {
			ContractID string `json:"contractId"`
			Payload    struct {
				Resource ContextReference `json:"resourceRef"`
			} `json:"payload"`
		}
		if json.Unmarshal(approved.Envelope, &message) != nil {
			return nil, errors.New("private-body")
		}
		switch message.ContractID {
		case "capability-storage-read", "capability-artifact-read", "capability-workspace-read":
			return contextJSON(map[string]any{"resourceRef": message.Payload.Resource, "data": []byte("private-content")}), nil
		default:
			outcome := "accepted"
			switch message.ContractID {
			case "capability-storage-write":
				outcome = "applied"
				receipt := ref
				receipt.OwnerHubID = message.Payload.Resource.OwnerHubID
				observed := message.Payload.Resource
				observed.Revision++
				return contextJSON(map[string]any{"receiptRef": receipt, "resourceRef": observed, "outcome": outcome}), nil
			case "capability-process-cancel", "capability-decision-request":
				outcome = "pending"
			case "capability-policy-evaluate":
				outcome = "allow"
			}
			return contextJSON(map[string]any{"receiptRef": ref, "outcome": outcome}), nil
		}
	}
	if change != nil {
		change(f)
	}
	h, err := OpenCapabilityHandles(f.operationLifetime, f.binding, f.instance, f.operation, f.ports)
	if err != nil {
		t.Fatal(err)
	}
	f.handles = h
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := h.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return f
}
func capabilityTestResource() ContextReference { return ContextReference{"record", "resource_hub", 2} }

func TestCapabilityHandlesSevenTypedServices(t *testing.T) {
	f := newCapabilityHandleFixture(t, nil)
	h := f.handles
	ctx := context.Background()
	r := capabilityTestResource()
	checks := []func() error{
		func() error {
			v, e := h.Storage.Read(ctx, r)
			if e == nil && !bytes.Equal(v.Bytes(), []byte("private-content")) {
				t.Fatal("record changed")
			}
			return e
		},
		func() error {
			_, e := h.Storage.CompareAndSwap(ctx, capabilityPrepared(t, h.Storage.PrepareCompareAndSwap, ctx, r, []byte(`{"storedId":"original","unknownField":42}`)), r, []byte(`{"storedId":"original","unknownField":42}`))
			return e
		},
		func() error { _, e := h.Artifact.Read(ctx, r, checksum([]byte("private-content"))); return e },
		func() error {
			_, e := h.Secret.Use(ctx, capabilityPreparedRefs(t, h.Secret.PrepareUse, ctx, r, r, r), r, r, r)
			return e
		},
		func() error { _, e := h.Workspace.ReadFile(ctx, r, "src/file.txt"); return e },
		func() error {
			_, e := h.Process.Start(ctx, capabilityPreparedPair(t, h.Process.PrepareStart, ctx, r, r), r, r)
			return e
		},
		func() error {
			v, e := h.Process.Cancel(ctx, capabilityPreparedPair(t, h.Process.PrepareCancel, ctx, r, r), r, r)
			if e == nil && v.Outcome() != "pending" {
				t.Fatal("cancel reported stopped")
			}
			return e
		},
		func() error {
			_, e := h.Policy.Evaluate(ctx, r, CapabilityAccess{"read", "storage", "record"})
			return e
		},
		func() error {
			_, e := h.Decision.Request(ctx, capabilityPreparedPair(t, h.Decision.PrepareRequest, ctx, r, r), r, r)
			return e
		},
	}
	for i, check := range checks {
		if e := check(); e != nil {
			t.Fatalf("typed operation %d: %v", i, e)
		}
	}
	if len(f.calls) != 9 {
		t.Fatal("missing remote operation")
	}
	for _, call := range f.calls {
		var env struct {
			Contract string `json:"contractId"`
			Payload  struct {
				Resource ContextReference `json:"resourceRef"`
				Input    json.RawMessage  `json:"input"`
			} `json:"payload"`
		}
		if json.Unmarshal(call.Envelope, &env) != nil || env.Payload.Resource != r {
			t.Fatal("resource identity/revision changed")
		}
		if env.Contract == "capability-storage-write" && !bytes.Contains(env.Payload.Input, []byte(`"unknownField":42`)) {
			t.Fatal("record field dropped")
		}
	}
}

func TestCapabilityHandlesRefuseRevokedAndUndeclaredCalls(t *testing.T) {
	f := newCapabilityHandleFixture(t, nil)
	r := capabilityTestResource()
	f.authority.deny.Store(true)
	if _, err := f.handles.Storage.Read(context.Background(), r); err == nil {
		t.Fatal("revoked authority admitted")
	}
	f.authority.deny.Store(false)
	r.ID = "ungranted"
	if _, err := f.handles.Storage.Read(context.Background(), r); err == nil {
		t.Fatal("ungranted resource admitted")
	}
	if len(f.calls) != 0 {
		t.Fatal("refused request reached owner")
	}
	f.handles.session.mu.Lock()
	delete(f.handles.session.routes, "capability-storage-write")
	f.handles.session.mu.Unlock()
	if _, err := f.handles.Storage.CompareAndSwap(context.Background(), capabilityTestMutation(t, f.handles), capabilityTestResource(), []byte(`{}`)); err == nil {
		t.Fatal("undeclared method admitted")
	}
}

func TestCapabilityHandlesSecretReplyAndDiagnostics(t *testing.T) {
	f := newCapabilityHandleFixture(t, func(f *capabilityHandleFixture) {
		f.ports.Domain = func(context.Context, ContextApprovedEnvelope) ([]byte, error) {
			return []byte(`{"receiptRef":{"id":"receipt","ownerHubId":"hub","revision":1},"outcome":"accepted","secret":"private-secret"}`), nil
		}
	})
	r := capabilityTestResource()
	mutation := capabilityPreparedRefs(t, f.handles.Secret.PrepareUse, context.Background(), r, r, r)
	receipt, err := f.handles.Secret.Use(context.Background(), mutation, r, r, r)
	if err == nil || strings.Contains(err.Error(), "private-secret") || receipt.Outcome() != "" {
		t.Fatal("secret response escaped")
	}
	for _, v := range []any{f.handles, f.handles.Secret, CapabilityContent{[]byte("private-secret")}, CapabilityReceipt{reference: ContextReference{ID: "private-secret"}}} {
		raw, e := json.Marshal(v)
		if e != nil || strings.Contains(string(raw), "private-secret") || strings.Contains(fmt.Sprintf("%+v %#v", v, v), "private-secret") {
			t.Fatal("diagnostic leaked private data")
		}
	}
}

func TestCapabilityHandlesWorkspacePathsAndArtifactDigest(t *testing.T) {
	f := newCapabilityHandleFixture(t, nil)
	r := capabilityTestResource()
	for _, p := range []string{"", "/etc/passwd", "../secret", "a/../../secret", "a/../file", "a\\file", "a\x00file", "."} {
		if _, e := f.handles.Workspace.ReadFile(context.Background(), r, p); e == nil {
			t.Fatal("unsafe workspace path")
		}
	}
	for _, digest := range []string{"sha256:" + strings.Repeat("a", 1024), "sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("g", 64)} {
		if _, err := f.handles.Artifact.Read(context.Background(), r, digest); err == nil {
			t.Fatal("invalid digest accepted")
		}
	}
	if len(f.calls) != 0 {
		t.Fatal("unsafe path reached owner")
	}
	if _, e := f.handles.Artifact.Read(context.Background(), r, checksum([]byte("different"))); e == nil {
		t.Fatal("artifact digest mismatch accepted")
	}
}

func TestCapabilityHandlesCloseJoinsOriginalCall(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	f := newCapabilityHandleFixture(t, func(f *capabilityHandleFixture) {
		f.ports.Domain = func(context.Context, ContextApprovedEnvelope) ([]byte, error) {
			close(entered)
			<-release
			return []byte(`{}`), nil
		}
	})
	result := make(chan error, 1)
	go func() { _, e := f.handles.Storage.Read(context.Background(), capabilityTestResource()); result <- e }()
	select {
	case <-entered:
	case err := <-result:
		t.Fatalf("call failed before owner: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if e := f.handles.Close(canceled); e == nil || e.Error() != "capability_cleanup_incomplete" {
		t.Fatal("cleanup abandoned an owned call")
	}
	if _, e := f.handles.Storage.Read(context.Background(), capabilityTestResource()); e == nil {
		t.Fatal("closed handle accepted use")
	}
	close(release)
	if e := <-result; e == nil {
		t.Fatal("canceled call reported success")
	}
	if e := f.handles.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
}

func TestCapabilityHandlesLifetimeAndInputCopies(t *testing.T) {
	f := newCapabilityHandleFixture(t, nil)
	f.instance.EffectiveGrant[0] = 'x'
	f.operation.Operation[0] = 'x'
	f.instance.DomainBindings[0].ID = "changed"
	if _, e := f.handles.Storage.Read(context.Background(), capabilityTestResource()); e != nil {
		t.Fatal("caller mutated owned snapshots")
	}
	close(f.lifetime)
	if _, e := f.handles.Storage.Read(context.Background(), capabilityTestResource()); e == nil {
		t.Fatal("expired owner accepted use")
	}
}

func TestCapabilityHandlesOpenRejectsScopeAndRouteForgery(t *testing.T) {
	f := newCapabilityHandleFixture(t, nil)
	for _, change := range []func(*ContextBinding, *ContextInstanceAdmission, *ContextOperationAdmission){
		func(b *ContextBinding, i *ContextInstanceAdmission, o *ContextOperationAdmission) {
			b.LifetimeDone = nil
		},
		func(b *ContextBinding, i *ContextInstanceAdmission, o *ContextOperationAdmission) {
			i.DomainBindings[0].Action = "other"
		},
		func(b *ContextBinding, i *ContextInstanceAdmission, o *ContextOperationAdmission) {
			o.Operation = bytes.ReplaceAll(o.Operation, []byte("project_a"), []byte("project_b"))
		},
		func(b *ContextBinding, i *ContextInstanceAdmission, o *ContextOperationAdmission) {
			i.DomainBindings = nil
		},
	} {
		b, i, o := f.binding, cloneInstanceAdmission(f.instance), cloneOperationAdmission(f.operation)
		change(&b, &i, &o)
		h, e := OpenCapabilityHandles(context.Background(), b, i, o, f.ports)
		if e == nil {
			_ = h.Close(context.Background())
			t.Fatal("invalid binding admitted")
		}
	}
}

func TestCapabilityHandlesOperationCancellation(t *testing.T) {
	operation, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := newCapabilityHandleFixture(t, func(f *capabilityHandleFixture) { f.operationLifetime = operation })
	cancel()
	if _, err := f.handles.Storage.Read(context.Background(), capabilityTestResource()); err == nil {
		t.Fatal("canceled operation admitted new use")
	}
	if len(f.calls) != 0 {
		t.Fatal("canceled operation reached owner")
	}
	if err := f.handles.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCapabilityHandlesOperationCancellationJoinsCall(t *testing.T) {
	operation, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, canceled := make(chan struct{}), make(chan struct{})
	f := newCapabilityHandleFixture(t, func(f *capabilityHandleFixture) {
		f.operationLifetime = operation
		f.ports.Domain = func(ctx context.Context, _ ContextApprovedEnvelope) ([]byte, error) {
			close(entered)
			<-ctx.Done()
			close(canceled)
			return nil, errors.New("private-cancellation")
		}
	})
	result := make(chan error, 1)
	go func() {
		_, err := f.handles.Storage.Read(context.Background(), capabilityTestResource())
		result <- err
	}()
	select {
	case <-entered:
	case err := <-result:
		t.Fatalf("call failed before owner: %v", err)
	}
	cancel()
	if err := f.handles.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	default:
		t.Fatal("close did not join original canceled call")
	}
	if err := <-result; err == nil {
		t.Fatal("canceled call reported success")
	}
}

func TestCapabilityHandlesSecretRequiresExactAdmittedReference(t *testing.T) {
	f := newCapabilityHandleFixture(t, nil)
	r := capabilityTestResource()
	changed := r
	changed.Revision++
	if _, err := f.handles.Secret.Use(context.Background(), capabilityTestMutation(t, f.handles), changed, r, r); err == nil {
		t.Fatal("unadmitted secret revision accepted")
	}
	changed = r
	changed.OwnerHubID = "other_hub"
	if _, err := f.handles.Secret.Use(context.Background(), capabilityTestMutation(t, f.handles), changed, r, r); err == nil {
		t.Fatal("unadmitted secret owner accepted")
	}
	if len(f.calls) != 0 {
		t.Fatal("unadmitted secret reference reached owner")
	}
}

// Only the per-attempt identity/digest binding is exercised here. Production
// signing and canonical payload digests remain with the enrolled authority.
type capabilityStableAuthority struct{ *contextTestAuthority }

func (a capabilityStableAuthority) PrepareDomainCall(ctx context.Context, owner OwnerReference, op ContextOperationAdmission, call ContextDomainCall) (ContextApprovedEnvelope, error) {
	approved, err := a.contextTestAuthority.PrepareDomainCall(ctx, owner, op, call)
	if err != nil {
		return approved, err
	}
	var envelope map[string]any
	_ = json.Unmarshal(approved.Envelope, &envelope)
	operation := envelope["operation"].(map[string]any)
	operation["payloadDigest"] = checksum(call.Payload)
	approved.Envelope = contextJSON(envelope)
	return approved, nil
}
func capabilityTestMutation(t *testing.T, h *CapabilityHandles) *CapabilityMutation {
	t.Helper()
	mutation, err := h.NewMutation()
	if err != nil {
		t.Fatal(err)
	}
	return mutation
}

func capabilityPrepared(t *testing.T, prepare func(context.Context, ContextReference, []byte) (*CapabilityMutation, error), ctx context.Context, r ContextReference, value []byte) *CapabilityMutation {
	t.Helper()
	m, err := prepare(ctx, r, value)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func capabilityPreparedPair(t *testing.T, prepare func(context.Context, ContextReference, ContextReference) (*CapabilityMutation, error), ctx context.Context, a, b ContextReference) *CapabilityMutation {
	t.Helper()
	m, err := prepare(ctx, a, b)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func capabilityPreparedRefs(t *testing.T, prepare func(context.Context, ContextReference, ContextReference, ContextReference) (*CapabilityMutation, error), ctx context.Context, a, b, c ContextReference) *CapabilityMutation {
	t.Helper()
	m, err := prepare(ctx, a, b, c)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// Use the native authority and gateway together so private preparation must
// survive the typed handle's call boundary. Transport remains offline.
func TestCapabilityHandlesNativeGatewayPreservesPreparation(t *testing.T) {
	f := newNativeCapabilityFixture(t)
	a := f.authority
	state, err := a.authority.instance(a.binding.Owner)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := a.authority.AdmitOperation(context.Background(), a.binding.Owner, bytes.Clone(a.original))
	if err != nil {
		t.Fatal(err)
	}
	handles, err := OpenCapabilityHandles(context.Background(), a.binding, cloneInstanceAdmission(state.facts.admission), operation,
		CapabilityHandlePorts{Authority: a.authority, Domain: f.gateway.Domain, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := handles.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	content, err := handles.Storage.Read(context.Background(), ContextReference{"fixture_resource", "context_hub", 1})
	if err != nil {
		t.Fatal(err)
	}
	if string(content.Bytes()) != "private owner content" {
		t.Fatal("authenticated owner content missing")
	}
}
