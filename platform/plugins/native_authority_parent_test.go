package plugins

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type nativeParentFixture struct {
	root                      *nativeAuthorityFixture
	child                     ContextBinding
	rootFacts, childFacts     map[string]any
	revokeParent              atomic.Bool
	advanceChild              atomic.Bool
	sequence                  atomic.Uint64
	advanceMethod             string
	parentChecks, childChecks atomic.Int32
}

// This signed protocol fixture exercises the Go consumer, not production
// private-parent enrollment or the Python provider's outstanding integration.
func newNativeParentFixture(t *testing.T, childClasses ...string) *nativeParentFixture {
	t.Helper()
	f := &nativeParentFixture{root: newNativeAuthorityFixture(t)}
	f.sequence.Store(3)
	clone := func(v map[string]any) map[string]any {
		var result map[string]any
		_ = json.Unmarshal(contextJSON(v), &result)
		return result
	}
	f.rootFacts = clone(f.root.facts)
	manifest := fixtureManifest("native_private_child")
	manifest.InstallationModes = []string{"private-child"}
	resourceClass := "storage"
	if len(childClasses) > 0 {
		resourceClass = childClasses[0]
	}
	manifest.RequestedCapabilities = []Capability{{Action: "read", ResourceClass: resourceClass, Required: true}}
	pkg := fixturePackage(t, manifest, map[string][]byte{"schemas/config.json": []byte(`{"type":"object"}`)})
	configuration, err := PrepareConfiguration(pkg, nil, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	lifetime := make(chan struct{})
	t.Cleanup(func() { close(lifetime) })
	f.child = ContextBinding{Owner: OwnerReference{Pin: pkg.Pin(), InstanceID: "native_child", Epoch: strings.Repeat("c", 64), Generation: 1}, Parent: copyParent(&f.root.binding.Owner), ParentLifetime: f.root.binding.LifetimeDone, LifetimeDone: lifetime, Package: pkg, Configuration: configuration}
	f.childFacts = clone(f.rootFacts)
	parent := clone(f.rootFacts["grant"].(map[string]any))
	grant := f.childFacts["grant"].(map[string]any)
	grant["grantId"] = "child_grant"
	grant["subjectInstanceId"] = f.child.Owner.InstanceID
	grant["parentGrantRef"] = map[string]any{"id": parent["grantId"], "ownerHubId": parent["issuerHubId"], "revision": parent["revision"]}
	f.childFacts["policy"].(map[string]any)["subjectInstanceId"] = f.child.Owner.InstanceID
	f.childFacts["parentGrant"] = parent
	f.childFacts["parentAccess"] = []any{map[string]any{"action": "read", "resourceClass": resourceClass, "resourceId": "fixture_resource"}}
	if resourceClass != "storage" {
		f.childFacts["policy"].(map[string]any)["decisions"].([]any)[0].(map[string]any)["access"].(map[string]any)["resourceClass"] = resourceClass
		f.childFacts["domainBindings"] = []any{}
	}
	a := f.root.authority
	a.destinations[f.child.Owner.InstanceID] = "storage-owner"
	original := a.client.options.Exchange
	a.client.options.Exchange = nativeAuthorityTestExchange(func(ctx context.Context, reply string, raw []byte) ([]byte, error) {
		var request struct {
			Owner  OwnerReference `json:"owner"`
			Method string         `json:"method"`
		}
		if json.Unmarshal(fieldsForClaim(raw, "claims"), &request) != nil {
			t.Fatal("signed native request invalid")
		}
		child := request.Owner == f.child.Owner
		if child {
			f.root.facts = f.childFacts
			f.childChecks.Add(1)
		} else {
			f.root.facts = f.rootFacts
			f.parentChecks.Add(1)
		}
		f.root.mutate = func(claims map[string]any) {
			claims["authoritySequence"] = f.sequence.Load()
			if !child && f.revokeParent.Load() {
				claims["outcome"] = "denied"
				claims["result"] = nil
			}
			if child && (f.advanceChild.Load() || request.Method == f.advanceMethod) {
				claims["authoritySequence"] = f.sequence.Load() + 1
			}
		}
		return original.Exchange(ctx, reply, raw)
	})
	return f
}
func (f *nativeParentFixture) bindRoot(t *testing.T) {
	t.Helper()
	if _, err := f.root.authority.BindInstance(context.Background(), f.root.binding); err != nil {
		t.Fatal("parent admission failed", err)
	}
}
func TestNativeAuthorityPrivateChildUsesCurrentGoParent(t *testing.T) {
	f := newNativeParentFixture(t)
	f.bindRoot(t)
	admission, err := f.root.authority.BindInstance(context.Background(), f.child)
	if err != nil {
		t.Fatal("matching private child refused", err)
	}
	before := f.parentChecks.Load()
	if err := f.root.authority.Recheck(context.Background(), f.child.Owner, admission, nil); err != nil {
		t.Fatal("current child recheck failed", err)
	}
	if f.parentChecks.Load() != before+1 {
		t.Fatal("child recheck reused older parent authority")
	}
	f.revokeParent.Store(true)
	beforeChild := f.childChecks.Load()
	if f.root.authority.Recheck(context.Background(), f.child.Owner, admission, nil) == nil {
		t.Fatal("revoked parent retained delegated child access")
	}
	if f.childChecks.Load() != beforeChild {
		t.Fatal("revoked parent reached child authority lookup")
	}
}
func TestNativeAuthorityPrivateChildRefusesParentSubstitution(t *testing.T) {
	for _, name := range []string{"unbound", "generation", "epoch", "lifetime", "grant", "access", "newer-child"} {
		t.Run(name, func(t *testing.T) {
			f := newNativeParentFixture(t)
			if name != "unbound" {
				f.bindRoot(t)
			}
			switch name {
			case "generation":
				f.child.Parent.Generation++
			case "epoch":
				f.child.Parent.Epoch = strings.Repeat("f", 64)
			case "lifetime":
				other := make(chan struct{})
				defer close(other)
				f.child.ParentLifetime = other
			case "grant":
				f.childFacts["parentGrant"].(map[string]any)["policyRef"] = ContextReference{ID: "other_policy", OwnerHubID: "context_hub", Revision: 1}
			case "access":
				f.childFacts["parentAccess"] = append(f.childFacts["parentAccess"].([]any), map[string]any{"action": "read", "resourceClass": "task", "resourceId": "fixture_resource"})
			case "newer-child":
				f.advanceChild.Store(true)
			}
			if _, err := f.root.authority.BindInstance(context.Background(), f.child); err == nil {
				t.Fatal("substituted or stale parent binding was accepted")
			}
		})
	}
}

func TestNativeAuthorityPrivateChildAcceptsFreshSharedRevision(t *testing.T) {
	f := newNativeParentFixture(t)
	f.bindRoot(t)
	f.sequence.Store(4)
	admission, err := f.root.authority.BindInstance(context.Background(), f.child)
	if err != nil {
		t.Fatal("fresh shared parent and child revision refused", err)
	}
	if err := f.root.authority.Recheck(context.Background(), f.child.Owner, admission, nil); err != nil {
		t.Fatal("fresh private authority was not reusable through a new check", err)
	}
}
func TestNativeAuthorityPrivateOperationKeepsParentSequence(t *testing.T) {
	for _, method := range []string{"current", "admit-operation", "prepare-domain-call"} {
		t.Run(method, func(t *testing.T) {
			f := newNativeParentFixture(t)
			f.bindRoot(t)
			if _, err := f.root.authority.BindInstance(context.Background(), f.child); err != nil {
				t.Fatal(err)
			}
			var source map[string]any
			_ = json.Unmarshal(fieldsForClaim(contextTestEnvelope("a"), "operation"), &source)
			source["deadline"] = nativeAuthorityStamp(time.Now().Add(time.Minute))
			payload := map[string]any{"resourceRef": ContextReference{ID: "fixture_resource", OwnerHubID: "context_hub", Revision: 1}, "input": map[string]any{}}
			original := f.root.envelope(t, source, payload, "capability-storage-read")
			if method == "admit-operation" {
				f.advanceMethod = method
			}
			operation, err := f.root.authority.AdmitOperation(context.Background(), f.child.Owner, original)
			if method == "admit-operation" {
				if err == nil {
					t.Fatal("private operation crossed a newer child snapshot without a fresh parent")
				}
				return
			}
			if err != nil {
				t.Fatal("current private operation refused", err)
			}
			if method == "prepare-domain-call" {
				f.advanceMethod = method
			}
			_, err = f.root.authority.PrepareDomainCall(context.Background(), f.child.Owner, operation, ContextDomainCall{RequestID: "request_" + strings.Repeat("e", 64), BindingID: "owner", ContractID: "capability-storage-read", Payload: contextJSON(payload)})
			if (err != nil) != (method == "prepare-domain-call") {
				t.Fatal("private downstream signing did not preserve its checked parent revision", err)
			}
		})
	}
}

func TestNativeAuthorityPrivateChildCannotReplaceParentDeclarations(t *testing.T) {
	f := newNativeParentFixture(t, "task")
	f.bindRoot(t)
	// The remote tuples fit the broad grant's action/resource IDs and the child
	// policy. Only the parent's actual Go evaluation removes this resource class.
	if _, err := decodeNativeAuthorityFacts(contextJSON(f.childFacts), f.child, time.Now()); err != nil {
		t.Fatal("control facts did not reach the parent-declaration boundary", err)
	}
	if _, err := f.root.authority.BindInstance(context.Background(), f.child); err == nil {
		t.Fatal("child gained a resource class absent from its parent's declarations")
	}
}
