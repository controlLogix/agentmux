package plugins

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
)

// prepareConfigurationInitialization requests an ordinary configuration-set
// envelope after native activation. It does not reuse read/watch authorization.
func (a *NativeContextAuthority) prepareConfigurationInitialization(ctx context.Context, binding ContextBinding, reference ContextReference, facts []byte, cancellationRef ContextReference) ([]byte, error) {
	fail := func() ([]byte, error) { return nil, pluginError("context_configuration_unavailable") }
	if a == nil || a.client == nil || ctx == nil || ctx.Err() != nil || !nativeAuthorityLive(binding) || !contextReferenceValid(reference) || reference.OwnerHubID != a.client.options.HubID || !contextReferenceValid(cancellationRef) || cancellationRef.OwnerHubID != a.client.options.HubID || !binding.Configuration.BelongsTo(binding.Package) {
		return fail()
	}
	admission, err := decodeNativeAuthorityFacts(facts, binding, a.client.now())
	if err != nil || reference.Revision >= maxGeneration || admission.admission.ConfigurationRevision != reference.Revision+1 {
		return fail()
	}
	payload := map[string]any{"configurationRef": reference, "owner": binding.Owner, "schemaRef": binding.Configuration.SchemaRef(), "configurationBytes": base64.StdEncoding.EncodeToString(binding.Configuration.Bytes()), "secretReferences": append([]ContextReference{}, admission.admission.SecretReferences...)}
	result, until, _, err := a.client.callWithSequence(ctx, binding.Owner, "prepare-configuration-initialization", map[string]any{"payload": payload, "cancellationRef": cancellationRef})
	if err != nil {
		return nil, managerFailure(err, "context_configuration_unavailable")
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
	if err != nil || len(raw) > nativeAuthorityLimit || base64.StdEncoding.EncodeToString(raw) != encoded || nativeAuthoritySchema("envelope", raw) != nil || string(fieldsForClaim(raw, "contractId")) != `"configuration-set"` || string(fieldsForClaim(raw, "destinationServiceId")) != `"configuration-owner"` || !nativeCapabilityEqual(fieldsForClaim(raw, "destinationHubId"), contextJSON(a.client.options.HubID)) || !nativeCapabilityEqual(fieldsForClaim(raw, "payload"), contextJSON(payload)) {
		return fail()
	}
	operation := fieldsForClaim(raw, "operation")
	if !nativeCapabilityEqual(fieldsForClaim(operation, "scope"), fieldsForClaim(admission.admission.EffectiveGrant, "scope")) || !nativeCapabilityEqual(fieldsForClaim(operation, "cancellationRef"), contextJSON(cancellationRef)) || !nativeCapabilityEqual(fieldsForClaim(operation, "expectedVersion"), contextJSON(reference.Revision)) {
		return fail()
	}
	deadline, err := nativeConfigurationRequest(raw, binding.Owner, NativeConfigurationBinding{ConfigurationRef: reference, Service: NativeConfigurationServiceBinding{HubID: a.client.options.HubID}})
	if err != nil || deadline.After(until) || !nativeAuthorityLive(binding) || ctx.Err() != nil || !a.client.now().Before(until) {
		return fail()
	}
	return bytes.Clone(raw), nil
}

func (p *nativeRegisteredContextProvider) initializeConfiguration(ctx context.Context, binding ContextBinding, declaration NativeActivationDeclaration) error {
	p.activationMu.Lock()
	input, ok := p.configurations[binding.Owner.InstanceID]
	p.activationMu.Unlock()
	if !ok || nilContextDependency(input.Exchange) {
		return pluginError("context_configuration_unavailable")
	}
	nonce, err := randomControlID()
	if err != nil {
		return pluginError("context_configuration_unavailable")
	}
	cancellationRef := ContextReference{"configuration_" + nonce, p.profile.HubID, 1}
	raw, err := p.authority.prepareConfigurationInitialization(ctx, binding, input.Binding.ConfigurationRef, declaration.Facts, cancellationRef)
	if err != nil {
		return err
	}
	reply, err := input.Exchange.ExchangeConfiguration(ctx, input.ReplyPrefix+"."+nonce, raw)
	if err != nil {
		return managerFailure(err, "context_configuration_unavailable")
	}
	snapshot, _, err := verifyNativeConfigurationResponse(ctx, reply, raw, binding, input.Binding, p.activationKeys)
	if err != nil {
		return err
	}
	if snapshot.Configuration.Checksum() != binding.Configuration.Checksum() || snapshot.Revision != input.Binding.ConfigurationRef.Revision+1 || !nativeAuthorityLive(binding) || ctx.Err() != nil {
		return pluginError("context_configuration_unavailable")
	}
	// Only a verified committed reply advances the next activation's CAS input.
	// Keep every grant, policy and secret reference unchanged. The current
	// instance still admits the committed revision; only its successor uses +1.
	fields, err := nativeAuthorityObject(declaration.Facts, "grant", "policy", "parentGrant", "parentAccess", "scopeRef", "configurationRevision", "secretReferences", "domainBindings")
	if err != nil {
		return pluginError("context_configuration_unavailable")
	}
	if snapshot.Revision < maxGeneration {
		fields["configurationRevision"] = contextJSON(snapshot.Revision + 1)
		declaration.Facts, err = json.Marshal(fields)
		if err != nil {
			return pluginError("context_configuration_unavailable")
		}
	}
	p.activationMu.Lock()
	defer p.activationMu.Unlock()
	if p.configurationOwner == nil {
		return pluginError("context_configuration_unavailable")
	}
	p.configurationOwner.mu.Lock()
	defer p.configurationOwner.mu.Unlock()
	current, exists := p.configurations[binding.Owner.InstanceID]
	ownerInput, ownerExists := p.configurationOwner.bindings[binding.Owner.InstanceID]
	if !exists || !ownerExists || current.Binding.ConfigurationRef != input.Binding.ConfigurationRef || ownerInput.Binding.ConfigurationRef != input.Binding.ConfigurationRef || p.configurationOwner.closing || ctx.Err() != nil || !nativeAuthorityLive(binding) {
		return pluginError("context_configuration_unavailable")
	}
	current.Binding.ConfigurationRef.Revision = snapshot.Revision
	ownerInput.Binding.ConfigurationRef.Revision = snapshot.Revision
	p.configurations[binding.Owner.InstanceID] = current
	p.configurationOwner.bindings[binding.Owner.InstanceID] = ownerInput
	_, identityCanAdvance := p.declarations[binding.Owner.InstanceID]
	if identityCanAdvance && snapshot.Revision < maxGeneration {
		p.declarations[binding.Owner.InstanceID] = cloneNativeActivationDeclaration(declaration)
	} else {
		delete(p.declarations, binding.Owner.InstanceID)
	}
	return nil
}
