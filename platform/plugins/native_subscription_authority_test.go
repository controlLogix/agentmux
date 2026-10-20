package plugins

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNativeActivationDeclarationPassesOnlySelectedEventSources(t *testing.T) {
	f, _, _, _ := nativeSubscriptionAuthorityFixture(t)
	declaration := NativeActivationDeclaration{RecordRef: ContextReference{"native_record", "context_hub", 1}, IdentityRef: ContextReference{"plugin_identity", "context_hub", 1}, Pin: f.binding.Owner.Pin, ManifestDigest: f.binding.Package.manifest.Checksum(), ConfigurationChecksum: f.binding.Configuration.Checksum(), Facts: contextJSON(f.facts), ConfigurationEventSources: f.binding.ConfigurationEventSources}
	retained := cloneNativeActivationDeclaration(declaration)
	wanted := contextJSON(retained.ConfigurationEventSources)
	declaration.ConfigurationEventSources[0].SourceDigest = nativeAuthorityDigest([]byte("replacement"))
	raw, err := nativeActivationRecord(f.binding, retained, ContextReference{"host_identity", "context_hub", 1})
	if err != nil || !nativeCapabilityEqual(fieldsForClaim(raw, "configurationEventSources"), wanted) {
		t.Fatal("activation lost or changed its admitted source pins", err)
	}
}

func nativeSubscriptionAuthorityFixture(t *testing.T) (*nativeAuthorityFixture, ContextOperationAdmission, ContextDomainCall, []byte) {
	t.Helper()
	f := newNativeAuthorityFixture(t)
	manifest := f.binding.Package.Manifest()
	manifest.RequestedCapabilities = append(manifest.RequestedCapabilities, Capability{Action: "subscribe", ResourceClass: "configuration", Required: true})
	pkg := fixturePackage(t, manifest, map[string][]byte{"schemas/config.json": []byte(`{"type":"object"}`)})
	configuration, err := PrepareConfiguration(pkg, nil, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	f.binding.Package, f.binding.Configuration = pkg, configuration
	f.binding.Owner.Pin = pkg.Pin()
	grant := f.facts["grant"].(map[string]any)
	grant["actions"] = []string{"read", "subscribe"}
	policy := f.facts["policy"].(map[string]any)
	policy["decisions"] = append(policy["decisions"].([]any), map[string]any{"access": map[string]string{"action": "subscribe", "resourceClass": "configuration", "resourceId": "fixture_resource"}, "outcome": "allow"})
	f.facts["domainBindings"] = append(f.facts["domainBindings"].([]any), map[string]any{"id": "configuration_events", "contractId": "configuration-change-subscribe", "action": "subscribe", "resourceClass": "configuration", "resourceIds": []string{"fixture_resource"}})
	created := nativeAuthorityStamp(time.Now().Add(-time.Hour))
	digest := nativeAuthorityDigest([]byte("selected-source"))
	f.binding.ConfigurationEventSources = []NativeConfigurationEventSource{{ConfigurationRef: ContextReference{"fixture_resource", "context_hub", 6}, SchemaRef: configuration.SchemaRef(), SourceDigest: digest, StreamCreated: created}}
	if _, err := f.authority.BindInstance(context.Background(), f.binding); err != nil {
		t.Fatal(err)
	}
	var operation map[string]any
	json.Unmarshal(fieldsForClaim(contextTestEnvelope("storage"), "operation"), &operation)
	operation["deadline"] = nativeAuthorityStamp(time.Now().Add(30 * time.Second))
	original := f.envelope(t, operation, map[string]any{"resourceRef": ContextReference{"fixture_resource", "context_hub", 1}}, "capability-storage-read")
	admission, err := f.authority.AdmitOperation(context.Background(), f.binding.Owner, original)
	if err != nil {
		t.Fatal(err)
	}
	filter := nativeConfigurationSubscription{ResourceRef: ContextReference{"fixture_resource", "context_hub", 6}, EventContractID: "configuration-change", Cursor: NativeConfigurationEventCursor{SourceDigest: digest, StreamCreated: created, Sequence: 6}}
	filter.Filter.Owner = f.binding.Owner
	filter.Filter.SchemaRef = configuration.SchemaRef()
	filter.FilterDigest = nativeAuthorityDigestMustCanonical(contextJSON(map[string]any{"resourceRef": filter.ResourceRef, "eventContractId": filter.EventContractID, "filter": filter.Filter}))
	call := ContextDomainCall{RequestID: "request_" + strings.Repeat("b", 64), BindingID: "configuration_events", ContractID: "configuration-change-subscribe", Payload: contextJSON(filter)}
	eventOperation := map[string]any{}
	json.Unmarshal(admission.Operation, &eventOperation)
	eventOperation["operationId"] = "configuration_event_" + strings.Repeat("c", 64)
	event := nativeSubscriptionTestEnvelope(t, f, eventOperation, map[string]any{"configurationRef": ContextReference{"fixture_resource", "context_hub", 7}, "owner": f.binding.Owner, "schemaRef": configuration.SchemaRef(), "configurationChecksum": configuration.Checksum()}, "configuration-change", "event")
	return f, admission, call, event
}
func nativeSubscriptionTestEnvelope(t *testing.T, f *nativeAuthorityFixture, operation map[string]any, payload any, contract, kind string, correlation ...string) []byte {
	t.Helper()
	var envelope map[string]any
	json.Unmarshal(f.envelope(t, operation, payload, contract), &envelope)
	envelope["kind"] = kind
	envelope["destinationServiceId"] = "configuration-owner"
	claims := envelope["ingressAttestation"].(map[string]any)["claims"].(map[string]any)
	claims["kind"] = kind
	if len(correlation) > 0 {
		envelope["correlationId"] = correlation[0]
		claims["correlationId"] = correlation[0]
	}
	claims["audience"].(map[string]any)["serviceId"] = "configuration-owner"
	signed, err := nativeAuthoritySign(contextJSON(claims), f.response)
	if err != nil {
		t.Fatal(err)
	}
	envelope["ingressAttestation"] = json.RawMessage(signed)
	return contextJSON(envelope)
}
func nativeSubscriptionTestReplies(t *testing.T, f *nativeAuthorityFixture, operation ContextOperationAdmission, call ContextDomainCall, event []byte, change string) {
	t.Helper()
	f.mutate = func(claims map[string]any) {
		switch claims["method"] {
		case "prepare-subscription-call":
			var op map[string]any
			json.Unmarshal(operation.Operation, &op)
			source := op["operationId"].(string)
			id, err := ContextDownstreamOperationID(source, call.RequestID)
			if err != nil {
				t.Fatal(err)
			}
			op["operationId"], op["causationId"] = id, source
			op["deadline"] = claims["validUntil"]
			if change == "extended-deadline" {
				op["deadline"] = nativeAuthorityStamp(time.Now().Add(30 * time.Second))
			}
			var payload any
			json.Unmarshal(call.Payload, &payload)
			prepared := nativeSubscriptionTestEnvelope(t, f, op, payload, call.ContractID, "command", call.RequestID)
			claims["result"] = map[string]any{"bindingId": call.BindingID, "envelopeBytes": base64.StdEncoding.EncodeToString(prepared)}
		case "admit-domain-event":
			payload := fieldsForClaim(event, "payload")
			if change == "changed-payload" {
				payload = []byte(`{"different":true}`)
			}
			claims["result"] = map[string]any{"payloadBytes": base64.StdEncoding.EncodeToString(payload)}
		}
	}
}
func TestNativeSubscriptionAuthorityPreparesAndAdmitsOriginalEvent(t *testing.T) {
	f, operation, call, event := nativeSubscriptionAuthorityFixture(t)
	nativeSubscriptionTestReplies(t, f, operation, call, event, "")
	approved, err := f.authority.PrepareDomainCall(context.Background(), f.binding.Owner, operation, call)
	if err != nil || approved.subscription == nil || approved.delivery != nil {
		t.Fatal("signed subscription preparation failed", err)
	}
	payload, err := f.authority.AdmitDomainEvent(context.Background(), f.binding.Owner, operation, approved.Clone(), event)
	if err != nil || !nativeCapabilityEqual(payload, fieldsForClaim(event, "payload")) {
		t.Fatal("original signed event admission failed", err)
	}
	for _, field := range []string{"streamCreated", "sourceDigest", "sequence"} {
		var changed map[string]any
		json.Unmarshal(call.Payload, &changed)
		cursor := changed["cursor"].(map[string]any)
		switch field {
		case "streamCreated":
			cursor[field] = nativeAuthorityStamp(time.Now().Add(-2 * time.Hour))
		case "sourceDigest":
			cursor[field] = nativeAuthorityDigest([]byte("unselected-source"))
		case "sequence":
			cursor[field] = uint64(5)
		}
		tampered := call
		tampered.Payload = contextJSON(changed)
		if _, err := f.authority.PrepareDomainCall(context.Background(), f.binding.Owner, operation, tampered); err == nil {
			t.Fatal("invalid source-bound cursor admitted", field)
		}
	}
}
func TestNativeSubscriptionAuthorityRejectsEnvelopeOperationAndEventChanges(t *testing.T) {
	for _, change := range []string{"envelope", "binding", "operation", "old-revision", "owner", "schema", "changed-payload", "extended-deadline"} {
		t.Run(change, func(t *testing.T) {
			f, operation, call, event := nativeSubscriptionAuthorityFixture(t)
			nativeSubscriptionTestReplies(t, f, operation, call, event, change)
			approved, err := f.authority.PrepareDomainCall(context.Background(), f.binding.Owner, operation, call)
			if change == "extended-deadline" {
				if err == nil {
					t.Fatal("subscription exceeded signed admission deadline")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "envelope":
				approved.Envelope = append([]byte(" "), approved.Envelope...)
			case "binding":
				approved.BindingID = "another_binding"
			case "operation":
				operation.Operation = bytes.ReplaceAll(operation.Operation, []byte(`"fixture_op"`), []byte(`"another_operation"`))
				operation.AuthorityRef.Revision++
			case "old-revision", "owner", "schema":
				var body map[string]any
				json.Unmarshal(event, &body)
				payload := body["payload"].(map[string]any)
				if change == "old-revision" {
					payload["configurationRef"].(map[string]any)["revision"] = float64(6)
				}
				if change == "owner" {
					payload["owner"].(map[string]any)["generation"] = float64(2)
				}
				if change == "schema" {
					payload["schemaRef"] = "another.json"
				}
				event = contextJSON(body)
			}
			if _, err := f.authority.AdmitDomainEvent(context.Background(), f.binding.Owner, operation, approved, event); err == nil {
				t.Fatal("changed subscription event admitted")
			}
		})
	}
}
