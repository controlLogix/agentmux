package plugins

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"time"
)

// NativeConfigurationEventSource is an explicit enrolled source pin. A selected
// revision is a floor; later verified events may advance beyond it.
type NativeConfigurationEventSource struct {
	ConfigurationRef ContextReference `json:"configurationRef"`
	SchemaRef        string           `json:"schemaRef"`
	SourceDigest     string           `json:"sourceDigest"`
	StreamCreated    string           `json:"streamCreated"`
}
type NativeConfigurationEventCursor struct {
	SourceDigest  string `json:"sourceDigest"`
	StreamCreated string `json:"streamCreated"`
	Sequence      uint64 `json:"sequence"`
}
type nativeConfigurationSubscription struct {
	ResourceRef     ContextReference `json:"resourceRef"`
	EventContractID string           `json:"eventContractId"`
	Filter          struct {
		Owner     OwnerReference `json:"owner"`
		SchemaRef string         `json:"schemaRef"`
	} `json:"filter"`
	FilterDigest string                         `json:"filterDigest"`
	Cursor       NativeConfigurationEventCursor `json:"cursor"`
}
type nativeSubscriptionApproval struct {
	authority      *NativeContextAuthority
	owner          OwnerReference
	operation      ContextOperationAdmission
	envelopeDigest string
	bindingID      string
	filter         nativeConfigurationSubscription
}

func nativeSubscriptionEnvelopeDeadline(raw []byte) (time.Time, error) {
	var deadline, expires string
	if json.Unmarshal(fieldsForClaim(fieldsForClaim(raw, "operation"), "deadline"), &deadline) != nil || json.Unmarshal(fieldsForClaim(fieldsForClaim(fieldsForClaim(raw, "ingressAttestation"), "claims"), "expiresAt"), &expires) != nil {
		return time.Time{}, pluginError("context_subscription_unavailable")
	}
	end, e1 := nativeAuthorityTime(deadline)
	attestationEnd, e2 := nativeAuthorityTime(expires)
	if e1 != nil || e2 != nil {
		return time.Time{}, pluginError("context_subscription_unavailable")
	}
	return minTime(end, attestationEnd), nil
}

func nativeSubscriptionFilter(raw []byte, binding ContextBinding) (nativeConfigurationSubscription, error) {
	var filter nativeConfigurationSubscription
	fail := pluginError("context_subscription_unavailable")
	// The hub comes from the authority, so the caller checks it separately.
	if nativeAuthoritySchema("configuration-change-subscribe", raw) != nil || json.Unmarshal(raw, &filter) != nil || filter.Filter.Owner != binding.Owner || filter.Filter.SchemaRef != binding.Package.Manifest().ConfigurationSchemaRef || filter.Cursor.Sequence < filter.ResourceRef.Revision {
		return filter, fail
	}
	created, err := nativeAuthorityTime(filter.Cursor.StreamCreated)
	if err != nil || created.After(time.Now()) {
		return filter, fail
	}
	selected := map[string]any{"resourceRef": filter.ResourceRef, "eventContractId": filter.EventContractID, "filter": filter.Filter}
	if filter.FilterDigest != nativeAuthorityDigestMustCanonical(contextJSON(selected)) {
		return filter, fail
	}
	matched := 0
	for _, source := range binding.ConfigurationEventSources {
		if source.ConfigurationRef.ID != filter.ResourceRef.ID || source.ConfigurationRef.OwnerHubID != filter.ResourceRef.OwnerHubID {
			continue
		}
		if source.SchemaRef != filter.Filter.SchemaRef || source.SourceDigest != filter.Cursor.SourceDigest || source.StreamCreated != filter.Cursor.StreamCreated || filter.ResourceRef.Revision < source.ConfigurationRef.Revision {
			return filter, fail
		}
		matched++
	}
	if matched != 1 {
		return filter, fail
	}
	return filter, nil
}

func (a *NativeContextAuthority) prepareSubscriptionCall(ctx context.Context, owner OwnerReference, operation ContextOperationAdmission, call ContextDomainCall) (ContextApprovedEnvelope, error) {
	fail := func() (ContextApprovedEnvelope, error) {
		return ContextApprovedEnvelope{}, pluginError("context_subscription_unavailable")
	}
	state, err := a.instance(owner)
	if err != nil || nativeAuthorityOriginal(operation) != nil || call.ContractID != "configuration-change-subscribe" {
		return fail()
	}
	bound := false
	for _, binding := range state.facts.admission.DomainBindings {
		if binding.ID == call.BindingID && binding.ContractID == call.ContractID && binding.Action == "subscribe" && binding.ResourceClass == "configuration" {
			bound = true
		}
	}
	filter, err := nativeSubscriptionFilter(call.Payload, state.binding)
	if err != nil || !bound || filter.ResourceRef.OwnerHubID != a.client.options.HubID {
		return fail()
	}
	work, cancel, err := nativeAuthorityOperationContext(ctx, operation.Operation)
	if err != nil {
		return fail()
	}
	defer cancel()
	checked, err := a.recheckWithSequence(work, owner, state.facts.admission, &operation)
	if err != nil {
		return fail()
	}
	raw, until, sequence, err := a.client.callWithSequence(work, owner, "prepare-subscription-call", map[string]any{"operation": json.RawMessage(operation.Operation), "operationAuthorityRef": operation.AuthorityRef, "originalEnvelopeBytes": base64.StdEncoding.EncodeToString(operation.originalEnvelope), "bindingId": call.BindingID, "contractId": call.ContractID, "serviceRequestId": call.RequestID, "payload": json.RawMessage(call.Payload)})
	if err != nil || state.binding.Parent != nil && checked != sequence {
		return fail()
	}
	fields, err := nativeAuthorityObject(raw, "bindingId", "envelopeBytes")
	if err != nil {
		return fail()
	}
	var bindingID, encoded string
	if json.Unmarshal(fields["bindingId"], &bindingID) != nil || bindingID != call.BindingID || json.Unmarshal(fields["envelopeBytes"], &encoded) != nil {
		return fail()
	}
	envelope, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(envelope) != encoded || len(envelope) > nativeAuthorityLimit || nativeAuthoritySchema("envelope", envelope) != nil || !contextApprovedFor(envelope, operation.Operation, call) || string(fieldsForClaim(envelope, "destinationServiceId")) != `"configuration-owner"` || !nativeCapabilityEqual(fieldsForClaim(envelope, "destinationHubId"), contextJSON(a.client.options.HubID)) || !nativeAuthorityLive(state.binding) || work.Err() != nil || !a.client.now().Before(until) {
		return fail()
	}
	deadline, err := nativeSubscriptionEnvelopeDeadline(envelope)
	if err != nil || deadline.After(until) || !a.client.now().Before(deadline) {
		return fail()
	}
	return ContextApprovedEnvelope{BindingID: bindingID, Envelope: bytes.Clone(envelope), subscription: &nativeSubscriptionApproval{authority: a, owner: owner, operation: cloneOperationAdmission(operation), envelopeDigest: nativeAuthorityDigest(envelope), bindingID: bindingID, filter: filter}}, nil
}

func (a *NativeContextAuthority) AdmitDomainEvent(ctx context.Context, owner OwnerReference, operation ContextOperationAdmission, approved ContextApprovedEnvelope, event []byte) ([]byte, error) {
	fail := func() ([]byte, error) { return nil, pluginError("context_subscription_unavailable") }
	proof := approved.subscription
	if proof == nil || proof.authority != a || proof.owner != owner || proof.bindingID != approved.BindingID || proof.envelopeDigest != nativeAuthorityDigest(approved.Envelope) || nativeAuthorityOriginal(operation) != nil || !nativeCapabilityEqual(operation.Operation, proof.operation.Operation) || operation.AuthorityRef != proof.operation.AuthorityRef || !bytes.Equal(operation.originalEnvelope, proof.operation.originalEnvelope) || len(event) > nativeAuthorityLimit || nativeAuthoritySchema("envelope", event) != nil || string(fieldsForClaim(event, "kind")) != `"event"` || string(fieldsForClaim(event, "contractId")) != `"configuration-change"` || string(fieldsForClaim(event, "destinationServiceId")) != `"configuration-owner"` || !nativeCapabilityEqual(fieldsForClaim(event, "destinationHubId"), contextJSON(a.client.options.HubID)) {
		return fail()
	}
	if !nativeCapabilityEqual(fieldsForClaim(event, "sourceHubId"), contextJSON(a.client.options.HubID)) {
		return fail()
	}
	payload := fieldsForClaim(event, "payload")
	if nativeAuthoritySchema("configuration-change", payload) != nil {
		return fail()
	}
	var changed struct {
		ConfigurationRef ContextReference `json:"configurationRef"`
		Owner            OwnerReference   `json:"owner"`
		SchemaRef        string           `json:"schemaRef"`
	}
	if json.Unmarshal(payload, &changed) != nil || changed.ConfigurationRef.ID != proof.filter.ResourceRef.ID || changed.ConfigurationRef.OwnerHubID != proof.filter.ResourceRef.OwnerHubID || changed.ConfigurationRef.Revision <= proof.filter.Cursor.Sequence || changed.Owner != proof.filter.Filter.Owner || changed.SchemaRef != proof.filter.Filter.SchemaRef {
		return fail()
	}
	state, err := a.instance(owner)
	if err != nil {
		return fail()
	}
	work, cancel, err := nativeAuthorityOperationContext(ctx, operation.Operation)
	if err != nil {
		return fail()
	}
	defer cancel()
	if _, err := a.recheckWithSequence(work, owner, state.facts.admission, &operation); err != nil {
		return fail()
	}
	raw, until, sequence, err := a.client.callWithSequence(work, owner, "admit-domain-event", map[string]any{"operation": json.RawMessage(operation.Operation), "operationAuthorityRef": operation.AuthorityRef, "originalEnvelopeBytes": base64.StdEncoding.EncodeToString(operation.originalEnvelope), "subscriptionEnvelopeBytes": base64.StdEncoding.EncodeToString(approved.Envelope), "eventEnvelopeBytes": base64.StdEncoding.EncodeToString(event)})
	if err != nil {
		return fail()
	}
	fields, err := nativeAuthorityObject(raw, "payloadBytes")
	if err != nil {
		return fail()
	}
	var encoded string
	if json.Unmarshal(fields["payloadBytes"], &encoded) != nil {
		return fail()
	}
	data, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(data) != encoded || len(data) > nativeAuthorityLimit || !nativeCapabilityEqual(data, payload) {
		return fail()
	}
	end, err := nativeSubscriptionEnvelopeDeadline(event)
	if err != nil || until.After(end) {
		return fail()
	}
	final, err := a.recheckWithSequence(work, owner, state.facts.admission, &operation)
	if err != nil || final != sequence || !nativeAuthorityLive(state.binding) || work.Err() != nil || !a.client.now().Before(until) {
		return fail()
	}
	return bytes.Clone(data), nil
}
