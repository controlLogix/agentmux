package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestCapabilityMutationLostReplyReconcileAndRetry(t *testing.T) {
	cases := []struct {
		name    string
		invoke  func(*CapabilityHandles, *CapabilityMutation, ContextReference) (CapabilityReceipt, error)
		outcome string
	}{
		{"storage", func(h *CapabilityHandles, m *CapabilityMutation, r ContextReference) (CapabilityReceipt, error) {
			return h.Storage.CompareAndSwap(context.Background(), m, r, []byte(`{"storedId":"original","data":"private-marker"}`))
		}, "applied"},
		{"secret", func(h *CapabilityHandles, m *CapabilityMutation, r ContextReference) (CapabilityReceipt, error) {
			return h.Secret.Use(context.Background(), m, r, r, r)
		}, "accepted"},
		{"start", func(h *CapabilityHandles, m *CapabilityMutation, r ContextReference) (CapabilityReceipt, error) {
			return h.Process.Start(context.Background(), m, r, r)
		}, "accepted"},
		{"cancel", func(h *CapabilityHandles, m *CapabilityMutation, r ContextReference) (CapabilityReceipt, error) {
			return h.Process.Cancel(context.Background(), m, r, r)
		}, "pending"},
		{"decision", func(h *CapabilityHandles, m *CapabilityMutation, r ContextReference) (CapabilityReceipt, error) {
			return h.Decision.Request(context.Background(), m, r, r)
		}, "pending"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var originalID, originalDigest string
			var originalResource ContextReference
			effects, attempts, queries := 0, 0, 0
			ref := ContextReference{"retained_record", "resource_hub", 7}
			f := newCapabilityHandleFixture(t, func(f *capabilityHandleFixture) {
				f.ports.Domain = func(_ context.Context, approved ContextApprovedEnvelope) ([]byte, error) {
					var env struct {
						Contract  string `json:"contractId"`
						Operation struct {
							ID     string `json:"operationId"`
							Digest string `json:"payloadDigest"`
						} `json:"operation"`
						Payload struct {
							Resource ContextReference `json:"resourceRef"`
							Input    struct {
								OperationID string `json:"operationId"`
								Digest      string `json:"payloadDigest"`
							} `json:"input"`
						} `json:"payload"`
					}
					if json.Unmarshal(approved.Envelope, &env) != nil {
						t.Fatal("bad fixture request")
					}
					if env.Contract == "capability-outcome-query" {
						queries++
						if env.Payload.Resource != originalResource || env.Payload.Input.OperationID != originalID || env.Payload.Input.Digest != originalDigest {
							t.Fatal("query did not preserve original aggregate/operation/digest")
						}
						reply := map[string]any{"operationId": originalID, "payloadDigest": originalDigest, "recordRef": ref, "outcome": "committed"}
						if test.name == "storage" {
							observed := originalResource
							observed.Revision++
							reply["contractId"], reply["resourceRef"] = "capability-storage-write", observed
						}
						return contextJSON(reply), nil
					}
					attempts++
					if effects == 0 {
						originalID, originalDigest, originalResource = env.Operation.ID, env.Operation.Digest, env.Payload.Resource
						effects++
						return nil, errors.New("private-lost-reply")
					}
					if env.Operation.ID != originalID || env.Operation.Digest != originalDigest || env.Payload.Resource != originalResource {
						t.Fatal("retry changed original effect identity")
					}
					// Models the OwnerLedger outcome replay contract, not a live durable owner.
					reply := map[string]any{"receiptRef": ref, "outcome": test.outcome}
					if env.Contract == "capability-storage-write" {
						observed := originalResource
						observed.Revision++
						reply["resourceRef"] = observed
					}
					return contextJSON(reply), nil
				}
			})
			r := capabilityTestResource()
			var mutation *CapabilityMutation
			switch test.name {
			case "storage":
				mutation = capabilityPrepared(t, f.handles.Storage.PrepareCompareAndSwap, context.Background(), r, []byte(`{"storedId":"original","data":"private-marker"}`))
			case "secret":
				mutation = capabilityPreparedRefs(t, f.handles.Secret.PrepareUse, context.Background(), r, r, r)
			case "start":
				mutation = capabilityPreparedPair(t, f.handles.Process.PrepareStart, context.Background(), r, r)
			case "cancel":
				mutation = capabilityPreparedPair(t, f.handles.Process.PrepareCancel, context.Background(), r, r)
			case "decision":
				mutation = capabilityPreparedPair(t, f.handles.Decision.PrepareRequest, context.Background(), r, r)
			}
			raw, err := mutation.RecoveryBytes()
			if err != nil {
				t.Fatal(err)
			}
			if effects != 0 || attempts != 0 {
				t.Fatal("prepare dispatched effect")
			}
			if _, err := test.invoke(f.handles, mutation, capabilityTestResource()); err == nil || err.Error() != "capability_outcome_unavailable" {
				t.Fatal("lost reply became success")
			}
			token, err := mutation.Reconciliation()
			if err != nil || token.OperationID() != originalID || token.PayloadDigest() != originalDigest {
				t.Fatal("uncertain call lost its reconciliation identity")
			}
			restored, err := RestoreCapabilityMutation(raw)
			if err != nil {
				t.Fatal(err)
			}
			result, err := f.handles.Reconcile(context.Background(), restored)
			if err != nil || result.Outcome() != "committed" {
				t.Fatalf("reconciliation failed: %v", err)
			}
			if receipt, err := test.invoke(f.handles, restored, capabilityTestResource()); err != nil || receipt.Outcome() != test.outcome {
				t.Fatalf("same-identity retry failed: %v", err)
			}
			if effects != 1 || attempts != 2 || queries != 1 {
				t.Fatal("client duplicated an effect or silently retried")
			}
			for _, value := range []any{mutation, token, result} {
				raw, _ := json.Marshal(value)
				if strings.Contains(string(raw), originalID) || strings.Contains(fmt.Sprintf("%+v %#v", value, value), "private-marker") {
					t.Fatal("recovery details leaked through ordinary diagnostics")
				}
			}
		})
	}
}

func TestCapabilityMutationRefusesChangedIntent(t *testing.T) {
	f := newCapabilityHandleFixture(t, nil)
	r := capabilityTestResource()
	mutation := capabilityPrepared(t, f.handles.Storage.PrepareCompareAndSwap, context.Background(), r, []byte(`{"v":1}`))
	if _, err := f.handles.Storage.CompareAndSwap(context.Background(), mutation, r, []byte(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	for _, invoke := range []func() error{
		func() error {
			_, e := f.handles.Storage.CompareAndSwap(context.Background(), mutation, r, []byte(`{"v":2}`))
			return e
		},
		func() error {
			changed := r
			changed.Revision++
			_, e := f.handles.Storage.CompareAndSwap(context.Background(), mutation, changed, []byte(`{"v":1}`))
			return e
		},
		func() error { _, e := f.handles.Process.Start(context.Background(), mutation, r, r); return e },
	} {
		if err := invoke(); err == nil || err.Error() != "capability_mutation_changed" {
			t.Fatal("changed intent reused mutation identity")
		}
	}
	if len(f.calls) != 1 {
		t.Fatal("changed mutation reached owner")
	}
	if _, err := f.handles.Process.Start(context.Background(), nil, r, r); err == nil || err.Error() != "capability_mutation_required" {
		t.Fatal("mutation silently allocated identity")
	}
}

func TestCapabilityMutationRejectsChangedAuthorityIdentityOrDigest(t *testing.T) {
	f := newCapabilityHandleFixture(t, nil)
	r := capabilityTestResource()
	m := capabilityPreparedPair(t, f.handles.Process.PrepareStart, context.Background(), r, r)
	if _, err := f.handles.Process.Start(context.Background(), m, r, r); err != nil {
		t.Fatal(err)
	}
	f.handles.session.ports.Authority = capabilityMutationChangedAuthority{ContextAuthority: f.ports.Authority}
	if _, err := f.handles.Process.Start(context.Background(), m, r, r); err == nil {
		t.Fatal("changed signed digest accepted")
	}
	if len(f.calls) != 1 {
		t.Fatal("changed digest reached owner")
	}
}

type capabilityMutationChangedAuthority struct{ ContextAuthority }

func (a capabilityMutationChangedAuthority) PrepareDomainCall(ctx context.Context, owner OwnerReference, op ContextOperationAdmission, call ContextDomainCall) (ContextApprovedEnvelope, error) {
	approved, err := a.ContextAuthority.PrepareDomainCall(ctx, owner, op, call)
	if err != nil {
		return approved, err
	}
	var env map[string]any
	_ = json.Unmarshal(approved.Envelope, &env)
	env["operation"].(map[string]any)["payloadDigest"] = "sha256:" + strings.Repeat("f", 64)
	approved.Envelope = contextJSON(env)
	return approved, nil
}

func TestCapabilityMutationRestoreAndQueryRefusals(t *testing.T) {
	f := newCapabilityHandleFixture(t, nil)
	m := capabilityTestMutation(t, f.handles)
	if _, err := m.Reconciliation(); err == nil {
		t.Fatal("unprepared mutation has an owner outcome")
	}
	raw, err := m.RecoveryBytes()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreCapabilityMutation(raw)
	if err != nil || restored == nil {
		t.Fatal("new invocation cannot be retained")
	}
	for _, invalid := range [][]byte{[]byte(`{}`), []byte(`{"requestId":"*"}`), []byte(`{"requestId":"request_` + strings.Repeat("a", 64) + `","unknown":true}`)} {
		if _, err := RestoreCapabilityMutation(invalid); err == nil {
			t.Fatal("invalid recovery state accepted")
		}
	}
	r := capabilityTestResource()
	if _, err := f.handles.Process.Start(context.Background(), m, r, r); err == nil || err.Error() != "capability_mutation_not_prepared" {
		t.Fatal("unprepared effect dispatched")
	}
	if len(f.calls) != 0 {
		t.Fatal("unprepared effect reached owner")
	}
	m = capabilityPreparedPair(t, f.handles.Process.PrepareStart, context.Background(), r, r)
	if _, err := f.handles.Process.Start(context.Background(), m, r, r); err != nil {
		t.Fatal(err)
	}
	f.handles.session.ports.Domain = func(context.Context, ContextApprovedEnvelope) ([]byte, error) {
		return []byte(`{"operationId":"other","payloadDigest":"sha256:` + strings.Repeat("a", 64) + `","recordRef":null,"outcome":"absent"}`), nil
	}
	if _, err := f.handles.Reconcile(context.Background(), m); err == nil {
		t.Fatal("unrelated owner outcome accepted")
	}
}

func TestCapabilityMutationOutcomeRequiresExplicitRecord(t *testing.T) {
	f := newCapabilityHandleFixture(t, nil)
	r := capabilityTestResource()
	m := capabilityPreparedPair(t, f.handles.Process.PrepareStart, context.Background(), r, r)
	token, err := m.Reconciliation()
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"missing", "null", "extra"} {
		f.handles.session.ports.Domain = func(context.Context, ContextApprovedEnvelope) ([]byte, error) {
			reply := map[string]any{"operationId": token.OperationID(), "payloadDigest": token.PayloadDigest(), "outcome": "absent"}
			if variant == "null" {
				reply["recordRef"] = nil
			}
			if variant == "extra" {
				reply["outcome"] = "committed"
				reply["recordRef"] = map[string]any{"id": "record", "ownerHubId": "resource_hub", "revision": 3, "secret": "private"}
			}
			return contextJSON(reply), nil
		}
		result, err := f.handles.Reconcile(context.Background(), m)
		if variant == "null" {
			if err != nil || result.Outcome() != "absent" {
				t.Fatal("explicit absence refused")
			}
		} else if err == nil {
			t.Fatal("invalid outcome reference accepted")
		}
	}
}
