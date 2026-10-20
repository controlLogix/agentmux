package plugins

import (
	"encoding/json"
	"strings"
	"testing"
)

func contextProvenanceFixture(t *testing.T) ([]byte, map[string]json.RawMessage, ContextDomainCall) {
	t.Helper()
	var envelope struct {
		Operation json.RawMessage `json:"operation"`
	}
	if err := json.Unmarshal(contextTestEnvelope("a"), &envelope); err != nil {
		t.Fatal(err)
	}
	var original map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Operation, &original); err != nil {
		t.Fatal(err)
	}
	original["deadline"] = contextJSON("2030-01-01T00:00:00.000000Z")
	original["taskId"] = contextJSON("task_original")
	original["runId"] = contextJSON("run_original")
	original["attemptId"] = contextJSON("attempt_original")
	original["delegationRef"] = contextJSON(ContextReference{ID: "delegation_original", OwnerHubID: "context_hub", Revision: 1})
	raw := contextJSON(original)
	if validateContextJSON("operation-context", raw) != nil {
		t.Fatal("invalid original operation fixture")
	}
	call := ContextDomainCall{RequestID: "request_" + strings.Repeat("a", 64), BindingID: "owner", ContractID: "status-query", Payload: []byte(`{"query":"status"}`)}
	target := make(map[string]json.RawMessage, len(original))
	for key, value := range original {
		target[key] = append(json.RawMessage(nil), value...)
	}
	id, err := ContextDownstreamOperationID("operation_a", call.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	target["operationId"] = contextJSON(id)
	target["causationId"] = contextJSON("operation_a")
	return raw, target, call
}

func contextProvenanceEnvelope(target map[string]json.RawMessage, call ContextDomainCall) []byte {
	return contextJSON(map[string]any{"contractId": call.ContractID, "payload": json.RawMessage(call.Payload), "operation": target})
}

func TestContextProvenanceRejectsChangedInheritedFields(t *testing.T) {
	for _, field := range []string{"caller", "scope", "traceId", "effectiveActorRef", "taskId", "runId", "attemptId", "delegationRef", "cancellationRef", "causationId", "operationId", "deadline"} {
		t.Run(field, func(t *testing.T) {
			original, target, call := contextProvenanceFixture(t)
			if !contextApprovedFor(contextProvenanceEnvelope(target, call), original, call) {
				t.Fatal("valid downstream fixture refused")
			}
			switch field {
			case "caller":
				var caller map[string]json.RawMessage
				if err := json.Unmarshal(target[field], &caller); err != nil {
					t.Fatal(err)
				}
				caller["principalId"] = contextJSON("other_principal")
				target[field] = contextJSON(caller)
			case "scope":
				var scope map[string]json.RawMessage
				if err := json.Unmarshal(target[field], &scope); err != nil {
					t.Fatal(err)
				}
				scope["projectId"] = contextJSON("other_project")
				target[field] = contextJSON(scope)
			case "effectiveActorRef", "delegationRef", "cancellationRef":
				target[field] = contextJSON(ContextReference{ID: "other_reference", OwnerHubID: "context_hub", Revision: 2})
			case "deadline":
				target[field] = contextJSON("2030-01-01T00:00:00.000001Z")
			default:
				target[field] = contextJSON("other_value")
			}
			if validateContextJSON("operation-context", contextJSON(target)) != nil {
				t.Fatal("mutation must remain a valid operation shape")
			}
			if contextApprovedFor(contextProvenanceEnvelope(target, call), original, call) {
				t.Fatal("changed inherited claim accepted")
			}
		})
	}
}

func TestContextProvenanceAllowsNarrowerDeadlineAndDestinationClaims(t *testing.T) {
	original, target, call := contextProvenanceFixture(t)
	target["deadline"] = contextJSON("2029-12-31T23:59:59.999999Z")
	target["expectedVersion"] = contextJSON(29)
	target["payloadDigest"] = contextJSON("sha256:" + strings.Repeat("d", 64))
	target["grantRef"] = contextJSON(ContextReference{ID: "destination_grant", OwnerHubID: "destination_hub", Revision: 3})
	target["approvalRefs"] = contextJSON([]ContextReference{{ID: "destination_approval", OwnerHubID: "destination_hub", Revision: 2}})
	if !contextApprovedFor(contextProvenanceEnvelope(target, call), original, call) {
		t.Fatal("destination claims or narrower deadline refused")
	}
	// This shape/lineage check does not verify the digest, grant or approval.
	// The destination authority and receiving owner still own those checks.
}

func TestContextProvenanceBindsContractPayloadAndRequest(t *testing.T) {
	original, target, call := contextProvenanceFixture(t)
	raw := contextProvenanceEnvelope(target, call)
	for _, field := range []string{"contract", "payload", "request"} {
		changed := call
		switch field {
		case "contract":
			changed.ContractID = "another-contract"
		case "payload":
			changed.Payload = []byte(`{"query":"private"}`)
		case "request":
			changed.RequestID = "request_" + strings.Repeat("b", 64)
		}
		if contextApprovedFor(raw, original, changed) {
			t.Fatalf("changed %s accepted", field)
		}
	}
}

func TestContextProvenanceDownstreamIDIsStableForOriginalAndRequest(t *testing.T) {
	request := "request_" + strings.Repeat("a", 64)
	first, err := ContextDownstreamOperationID("operation_a", request)
	if err != nil || !registryIdentifier.MatchString(first) {
		t.Fatal("invalid derived operation ID")
	}
	repeated, err := ContextDownstreamOperationID("operation_a", request)
	if err != nil || repeated != first {
		t.Fatal("retry changed downstream operation ID")
	}
	otherParent, err := ContextDownstreamOperationID("operation_b", request)
	if err != nil || otherParent == first {
		t.Fatal("different original operation reused ID")
	}
	otherRequest, err := ContextDownstreamOperationID("operation_a", "request_"+strings.Repeat("b", 64))
	if err != nil || otherRequest == first {
		t.Fatal("different service request reused ID")
	}
	for _, input := range [][2]string{{"", request}, {"operation_a", ""}, {"operation_a", "request_invalid"}, {"operation_a\x00other", request}} {
		if id, err := ContextDownstreamOperationID(input[0], input[1]); err == nil || id != "" {
			t.Fatal("invalid lineage ID accepted")
		}
	}
}
