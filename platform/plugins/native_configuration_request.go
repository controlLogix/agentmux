package plugins

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
)

// NativeConfigurationRequestPreparer must return an ordinary configuration
// envelope with current host authorization and ingress attestation. It cannot
// derive those from configuration bytes, a plugin label or display metadata.
type NativeConfigurationRequestPreparer interface {
	PrepareConfigurationRequest(context.Context, OwnerReference, ContextReference, string, uint64, ContextReference) ([]byte, error)
}

func (a *NativeContextAuthority) PrepareConfigurationRequest(ctx context.Context, owner OwnerReference, reference ContextReference, contract string, afterRevision uint64, cancellationRef ContextReference) ([]byte, error) {
	fail := func() ([]byte, error) { return nil, pluginError("context_configuration_unavailable") }
	if !contextReferenceValid(cancellationRef) || cancellationRef.OwnerHubID != a.client.options.HubID || cancellationRef.Revision == 0 || ctx == nil || ctx.Err() != nil || !contextReferenceValid(reference) || reference.OwnerHubID != a.client.options.HubID || afterRevision > maxGeneration || (contract == "configuration-read" && afterRevision != 0) || (contract != "configuration-read" && contract != "configuration-watch") {
		return fail()
	}
	state, err := a.instance(owner)
	if err != nil {
		return fail()
	}
	checked, err := a.recheckWithSequence(ctx, owner, state.facts.admission, nil)
	if err != nil {
		return fail()
	}
	input := map[string]any{"configurationRef": reference, "contractId": contract, "cancellationRef": cancellationRef}
	if contract == "configuration-watch" {
		input["afterRevision"] = afterRevision
	}
	result, until, sequence, err := a.client.callWithSequence(ctx, owner, "prepare-configuration-request", input)
	if err != nil || (state.binding.Parent != nil && checked != sequence) {
		return fail()
	}
	fields, err := nativeAuthorityObject(result, "envelopeBytes")
	if err != nil {
		return fail()
	}
	var encoded string
	if json.Unmarshal(fields["envelopeBytes"], &encoded) != nil {
		return fail()
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) > nativeAuthorityLimit || base64.StdEncoding.EncodeToString(raw) != encoded || nativeAuthoritySchema("envelope", raw) != nil {
		return fail()
	}
	if !nativeCapabilityEqual(fieldsForClaim(fieldsForClaim(raw, "operation"), "scope"), fieldsForClaim(state.facts.admission.EffectiveGrant, "scope")) {
		return fail()
	}
	cancelRaw, err := json.Marshal(cancellationRef)
	if err != nil || !nativeCapabilityEqual(fieldsForClaim(fieldsForClaim(raw, "operation"), "cancellationRef"), cancelRaw) {
		return fail()
	}
	payload := fieldsForClaim(raw, "payload")
	expected := map[string]any{"configurationRef": reference, "owner": owner}
	if contract == "configuration-watch" {
		expected["afterRevision"] = afterRevision
	}
	expectedRaw, err := json.Marshal(expected)
	if err != nil || !nativeCapabilityEqual(payload, expectedRaw) {
		return fail()
	}
	var envelope struct {
		ContractID           string `json:"contractId"`
		DestinationHubID     string `json:"destinationHubId"`
		DestinationServiceID string `json:"destinationServiceId"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.ContractID != contract || envelope.DestinationHubID != a.client.options.HubID || envelope.DestinationServiceID != "configuration-owner" {
		return fail()
	}
	binding := NativeConfigurationBinding{ConfigurationRef: reference, Service: NativeConfigurationServiceBinding{HubID: a.client.options.HubID}}
	deadline, err := nativeConfigurationRequest(raw, owner, binding)
	if err != nil || deadline.After(until) {
		return fail()
	}
	final, err := a.recheckWithSequence(ctx, owner, state.facts.admission, nil)
	if err != nil || final != sequence || !nativeAuthorityLive(state.binding) || !a.client.now().Before(until) || ctx.Err() != nil {
		return fail()
	}
	return bytes.Clone(raw), nil
}
