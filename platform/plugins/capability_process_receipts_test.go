package plugins

import (
	"context"
	"testing"
)

// These tests exercise the typed caller's reply boundary. The existing offline
// fixture does not establish native transport or execution qualification.
func TestProcessClosedReceipts(t *testing.T) {
	for _, action := range []string{"start", "cancel"} {
		t.Run(action, func(t *testing.T) {
			allowed := []string{"accepted", "rejected", "uncertain"}
			if action == "cancel" {
				allowed = []string{"pending", "stopped", "rejected", "uncertain"}
			}
			type replyCase struct {
				name, outcome string
				change        func(map[string]any)
				valid         bool
			}
			cases := []replyCase{}
			for _, outcome := range allowed {
				cases = append(cases, replyCase{outcome, outcome, nil, true})
			}
			cases = append(cases,
				replyCase{"execution_field", allowed[0], func(reply map[string]any) { reply["executionPhase"] = "running" }, false},
				replyCase{"invalid_reference", allowed[0], func(reply map[string]any) { reply["receiptRef"] = ContextReference{"*", "resource_hub", 1} }, false},
				replyCase{"extra_reference_field", allowed[0], func(reply map[string]any) {
					reply["receiptRef"] = map[string]any{"id": "run", "ownerHubId": "resource_hub", "revision": 1, "containerId": "private"}
				}, false},
				replyCase{"running", "running", nil, false},
			)
			for _, test := range cases {
				t.Run(test.name, func(t *testing.T) {
					f := newCapabilityHandleFixture(t, nil)
					r := capabilityTestResource()
					prepare := f.handles.Process.PrepareStart
					invoke := f.handles.Process.Start
					if action == "cancel" {
						prepare, invoke = f.handles.Process.PrepareCancel, f.handles.Process.Cancel
					}
					mutation := capabilityPreparedPair(t, prepare, context.Background(), r, r)
					f.handles.session.ports.Domain = func(context.Context, ContextApprovedEnvelope) ([]byte, error) {
						reply := map[string]any{"receiptRef": r, "outcome": test.outcome}
						if test.change != nil {
							test.change(reply)
						}
						return contextJSON(reply), nil
					}
					receipt, err := invoke(context.Background(), mutation, r, r)
					if !test.valid {
						if err == nil || err.Error() != "capability_reply_invalid" {
							t.Fatalf("invalid Process reply accepted: %v", err)
						}
						return
					}
					if err != nil || receipt.Reference() != r || receipt.Outcome() != test.outcome {
						t.Fatalf("supported Process reply refused: %v", err)
					}
					if _, ok := receipt.ResourceReference(); ok {
						t.Fatal("Process receipt acquired a storage result")
					}
				})
			}
		})
	}
}

func TestProcessClosedReconciliation(t *testing.T) {
	for _, action := range []string{"start", "cancel"} {
		t.Run(action, func(t *testing.T) {
			for _, variant := range []string{"committed", "rejected", "absent", "contract", "resource", "storage_reply", "running"} {
				t.Run(variant, func(t *testing.T) {
					f := newCapabilityHandleFixture(t, nil)
					r := capabilityTestResource()
					prepare := f.handles.Process.PrepareStart
					if action == "cancel" {
						prepare = f.handles.Process.PrepareCancel
					}
					mutation := capabilityPreparedPair(t, prepare, context.Background(), r, r)
					raw, err := mutation.RecoveryBytes()
					if err != nil {
						t.Fatal(err)
					}
					restored, err := RestoreCapabilityMutation(raw)
					if err != nil {
						t.Fatal(err)
					}
					token, err := restored.Reconciliation()
					if err != nil {
						t.Fatal(err)
					}
					outcome := "committed"
					if variant == "rejected" || variant == "absent" || variant == "running" {
						outcome = variant
					}
					f.handles.session.ports.Domain = func(context.Context, ContextApprovedEnvelope) ([]byte, error) {
						reply := map[string]any{"operationId": token.OperationID(), "payloadDigest": token.PayloadDigest(), "recordRef": r, "outcome": outcome}
						if variant == "absent" {
							reply["recordRef"] = nil
						}
						if variant == "contract" || variant == "storage_reply" {
							reply["contractId"] = "capability-storage-write"
						}
						if variant == "resource" || variant == "storage_reply" {
							reply["resourceRef"] = r
						}
						return contextJSON(reply), nil
					}
					result, err := f.handles.Reconcile(context.Background(), restored)
					valid := variant == "committed" || variant == "rejected" || variant == "absent"
					if !valid {
						if err == nil || err.Error() != "capability_reply_invalid" {
							t.Fatalf("invalid Process recovery accepted: %v", err)
						}
						return
					}
					if err != nil || result.Outcome() != outcome {
						t.Fatalf("supported Process recovery refused: %v", err)
					}
					ref, ok := result.Record()
					if (variant == "absent" && ok) || (variant != "absent" && (!ok || ref != r)) {
						t.Fatal("Process recovery changed the original record")
					}
					if _, ok := result.ResourceReference(); ok {
						t.Fatal("Process recovery acquired a storage result")
					}
				})
			}
		})
	}
}
