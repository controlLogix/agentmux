package plugins

import (
	"context"
	"testing"
)

func TestCapabilityStorageResultSeparatesResourceAndReceipt(t *testing.T) {
	for _, outcome := range []string{"applied", "conflict", "rejected", "uncertain"} {
		t.Run(outcome, func(t *testing.T) {
			resource := capabilityTestResource()
			observed := resource
			observed.Revision = 99
			receipt := ContextReference{"actual_receipt", resource.OwnerHubID, 7}
			f := newCapabilityHandleFixture(t, func(f *capabilityHandleFixture) {
				f.ports.Domain = func(context.Context, ContextApprovedEnvelope) ([]byte, error) {
					var result any = observed
					if outcome == "uncertain" {
						result = nil
					}
					return contextJSON(map[string]any{"receiptRef": receipt, "resourceRef": result, "outcome": outcome}), nil
				}
			})
			value := []byte(`{"value":"original"}`)
			mutation := capabilityPrepared(t, f.handles.Storage.PrepareCompareAndSwap, context.Background(), resource, value)
			result, err := f.handles.Storage.CompareAndSwap(context.Background(), mutation, resource, value)
			if err != nil || result.Reference() != receipt || result.Outcome() != outcome {
				t.Fatal("storage result refused", err)
			}
			got, present := result.ResourceReference()
			if outcome == "uncertain" {
				if present || got != (ContextReference{}) {
					t.Fatal("uncertain result invented a resource revision")
				}
			} else if !present || got != observed {
				t.Fatal("resource version was inferred from receipt version")
			}
		})
	}
}

func TestCapabilityStorageResultRefusesMissingOrSubstitutedResource(t *testing.T) {
	for _, variant := range []string{"missing-applied", "missing-uncertain", "null-applied", "nonnull-uncertain", "wrong-id", "wrong-hub", "unknown-field", "missing-receipt-revision", "null-receipt-revision"} {
		t.Run(variant, func(t *testing.T) {
			resource := capabilityTestResource()
			f := newCapabilityHandleFixture(t, func(f *capabilityHandleFixture) {
				f.ports.Domain = func(context.Context, ContextApprovedEnvelope) ([]byte, error) {
					observed := resource
					observed.Revision++
					reply := map[string]any{"receiptRef": ContextReference{"receipt", resource.OwnerHubID, 8}, "resourceRef": observed, "outcome": "applied"}
					switch variant {
					case "missing-applied":
						delete(reply, "resourceRef")
					case "missing-uncertain":
						delete(reply, "resourceRef")
						reply["outcome"] = "uncertain"
					case "null-applied":
						reply["resourceRef"] = nil
					case "nonnull-uncertain":
						reply["outcome"] = "uncertain"
					case "wrong-id":
						observed.ID = "other"
						reply["resourceRef"] = observed
					case "wrong-hub":
						observed.OwnerHubID = "other"
						reply["resourceRef"] = observed
					case "unknown-field":
						reply["unregistered"] = "private"
					case "missing-receipt-revision":
						reply["receiptRef"] = map[string]any{"id": "receipt", "ownerHubId": resource.OwnerHubID}
					case "null-receipt-revision":
						reply["receiptRef"] = map[string]any{"id": "receipt", "ownerHubId": resource.OwnerHubID, "revision": nil}
					}
					return contextJSON(reply), nil
				}
			})
			value := []byte(`{"value":"original"}`)
			mutation := capabilityPrepared(t, f.handles.Storage.PrepareCompareAndSwap, context.Background(), resource, value)
			if _, err := f.handles.Storage.CompareAndSwap(context.Background(), mutation, resource, value); err == nil {
				t.Fatal("invalid storage result accepted")
			}
		})
	}
}

func TestCapabilityNonStorageReceiptHasNoResourceReference(t *testing.T) {
	f := newCapabilityHandleFixture(t, nil)
	resource := capabilityTestResource()
	mutation := capabilityPreparedRefs(t, f.handles.Secret.PrepareUse, context.Background(), resource, resource, resource)
	receipt, err := f.handles.Secret.Use(context.Background(), mutation, resource, resource, resource)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := receipt.ResourceReference(); present {
		t.Fatal("non-storage receipt acquired a resource result")
	}
}

func TestCapabilityStorageRecoveryPreservesOriginalResultReference(t *testing.T) {
	for _, outcome := range []string{"committed", "rejected", "absent"} {
		t.Run(outcome, func(t *testing.T) {
			resource := capabilityTestResource()
			observed := resource
			observed.Revision = 9
			var token CapabilityReconciliation
			f := newCapabilityHandleFixture(t, func(f *capabilityHandleFixture) {
				f.ports.Domain = func(context.Context, ContextApprovedEnvelope) ([]byte, error) {
					var record any = ContextReference{"original_receipt", resource.OwnerHubID, 7}
					var result any = observed
					if outcome == "absent" {
						record, result = nil, nil
					}
					return contextJSON(map[string]any{"operationId": token.OperationID(), "payloadDigest": token.PayloadDigest(), "recordRef": record, "outcome": outcome, "contractId": "capability-storage-write", "resourceRef": result}), nil
				}
			})
			mutation := capabilityPrepared(t, f.handles.Storage.PrepareCompareAndSwap, context.Background(), resource, []byte(`{"v":1}`))
			var err error
			token, err = mutation.Reconciliation()
			if err != nil {
				t.Fatal(err)
			}
			result, err := f.handles.Reconcile(context.Background(), mutation)
			if err != nil || result.Outcome() != outcome {
				t.Fatal("storage recovery refused", err)
			}
			got, present := result.ResourceReference()
			if outcome == "absent" {
				if present {
					t.Fatal("absent operation invented result reference")
				}
			} else if !present || got != observed {
				t.Fatal("recovery inferred resource version from receipt version")
			}
		})
	}
}

func TestCapabilityStorageRecoveryRefusesSubstitutedOrMissingResults(t *testing.T) {
	for _, variant := range []string{"missing-result", "null-result", "wrong-resource", "wrong-hub", "wrong-contract", "missing-contract", "missing-receipt-revision", "null-receipt-revision", "wrong-receipt-hub", "absent-with-result"} {
		t.Run(variant, func(t *testing.T) {
			resource := capabilityTestResource()
			var token CapabilityReconciliation
			f := newCapabilityHandleFixture(t, func(f *capabilityHandleFixture) {
				f.ports.Domain = func(context.Context, ContextApprovedEnvelope) ([]byte, error) {
					result := resource
					result.Revision = 9
					reply := map[string]any{"operationId": token.OperationID(), "payloadDigest": token.PayloadDigest(), "recordRef": ContextReference{"receipt", resource.OwnerHubID, 7}, "outcome": "committed", "contractId": "capability-storage-write", "resourceRef": result}
					switch variant {
					case "missing-result":
						delete(reply, "resourceRef")
					case "null-result":
						reply["resourceRef"] = nil
					case "wrong-resource":
						result.ID = "other"
						reply["resourceRef"] = result
					case "wrong-hub":
						result.OwnerHubID = "other"
						reply["resourceRef"] = result
					case "wrong-contract":
						reply["contractId"] = "capability-secret-use"
					case "missing-contract":
						delete(reply, "contractId")
						delete(reply, "resourceRef")
					case "missing-receipt-revision":
						reply["recordRef"] = map[string]any{"id": "receipt", "ownerHubId": resource.OwnerHubID}
					case "null-receipt-revision":
						reply["recordRef"] = map[string]any{"id": "receipt", "ownerHubId": resource.OwnerHubID, "revision": nil}
					case "wrong-receipt-hub":
						reply["recordRef"] = ContextReference{"receipt", "other", 7}
					case "absent-with-result":
						reply["outcome"] = "absent"
						reply["recordRef"] = nil
					}
					return contextJSON(reply), nil
				}
			})
			mutation := capabilityPrepared(t, f.handles.Storage.PrepareCompareAndSwap, context.Background(), resource, []byte(`{"v":1}`))
			token, _ = mutation.Reconciliation()
			if _, err := f.handles.Reconcile(context.Background(), mutation); err == nil {
				t.Fatal("invalid storage recovery result accepted")
			}
		})
	}
}

func TestCapabilityRecoveryRequiresOriginalDeclaredRoute(t *testing.T) {
	f := newCapabilityHandleFixture(t, nil)
	resource := capabilityTestResource()
	mutation := capabilityPrepared(t, f.handles.Storage.PrepareCompareAndSwap, context.Background(), resource, []byte(`{"v":1}`))
	f.handles.session.mu.Lock()
	delete(f.handles.session.routes, "capability-storage-write")
	f.handles.session.mu.Unlock()
	if _, err := f.handles.Reconcile(context.Background(), mutation); err == nil || err.Error() != "capability_access_refused" {
		t.Fatal("recovery bypassed original capability declaration", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) != 0 {
		t.Fatal("undeclared original capability reached domain owner")
	}
}
