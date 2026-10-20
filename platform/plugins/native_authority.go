package plugins

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// NativeContextAuthority consumes signed current facts. The host must supply
// enrolled trust and an owned transport; this constructor does not enroll keys.
// Destinations are host-registered service IDs by instance, never child input.
type NativeContextAuthority struct {
	client       *nativeAuthorityClient
	destinations map[string]string
	mu           sync.Mutex
	instances    map[OwnerReference]*nativeAuthorityInstance
}

func (NativeContextAuthority) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private native context authority]")
}
func (NativeContextAuthority) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-native-context-authority"}`), nil
}

type nativeAuthorityInstance struct {
	binding ContextBinding
	facts   nativeAuthorityFacts
	ready   bool
}

func NewNativeContextAuthority(options NativeAuthorityClientOptions, destinations map[string]string) (*NativeContextAuthority, error) {
	client, err := newNativeAuthorityClient(options)
	if err != nil {
		return nil, err
	}
	if len(destinations) == 0 || len(destinations) > contextOperationLimit {
		return nil, pluginError("context_authority_configuration_invalid")
	}
	owned := map[string]string{}
	for instance, service := range destinations {
		if !registryIdentifier.MatchString(instance) || !registryIdentifier.MatchString(service) {
			return nil, pluginError("context_authority_configuration_invalid")
		}
		owned[instance] = service
	}
	return &NativeContextAuthority{client: client, destinations: owned, instances: map[OwnerReference]*nativeAuthorityInstance{}}, nil
}
func nativeAuthorityLive(binding ContextBinding) bool {
	return binding.LifetimeDone != nil && !completed(binding.LifetimeDone) && (binding.Parent == nil || (binding.ParentLifetime != nil && !completed(binding.ParentLifetime)))
}
func (a *NativeContextAuthority) instance(owner OwnerReference) (*nativeAuthorityInstance, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	state := a.instances[owner]
	if state == nil || !state.ready || !nativeAuthorityLive(state.binding) {
		return nil, pluginError("context_owner_stale")
	}
	return state, nil // Immutable after ready, with original lifetime channels.
}
func (a *NativeContextAuthority) BindInstance(ctx context.Context, binding ContextBinding) (result ContextInstanceAdmission, err error) {
	if ctx == nil || ctx.Err() != nil || !contextOwnerValid(binding.Owner) || binding.Owner.Pin != binding.Package.Pin() || binding.Configuration.Pin() != binding.Owner.Pin || !nativeAuthorityLive(binding) || a.destinations[binding.Owner.InstanceID] == "" {
		return result, pluginError("context_owner_stale")
	}
	retained := cloneContextBinding(binding)
	retained.Configuration = ValidatedConfiguration{}
	retained.Package = AdmittedPackage{manifest: binding.Package.manifest, pin: binding.Package.Pin()}
	retained.Lifecycle = nil
	state := &nativeAuthorityInstance{binding: retained}
	a.mu.Lock()
	for owner, old := range a.instances {
		if !nativeAuthorityLive(old.binding) {
			delete(a.instances, owner)
		}
	}
	for owner := range a.instances {
		if owner.InstanceID == binding.Owner.InstanceID {
			a.mu.Unlock()
			return result, pluginError("context_owner_stale")
		}
	}
	if len(a.instances) >= contextOperationLimit {
		a.mu.Unlock()
		return result, pluginError("context_authority_unavailable")
	}
	a.instances[binding.Owner] = state
	a.mu.Unlock()
	defer func() {
		if err != nil {
			a.mu.Lock()
			if a.instances[binding.Owner] == state {
				delete(a.instances, binding.Owner)
			}
			a.mu.Unlock()
		}
	}()
	relationship := "independent"
	if binding.Parent != nil {
		relationship = "private"
	}
	parent, parentSequence, err := a.currentParent(ctx, binding)
	if err != nil {
		return result, err
	}
	raw, validUntil, sequence, err := a.client.callWithSequence(ctx, binding.Owner, "bind-instance", map[string]any{"manifestDigest": binding.Package.manifest.Checksum(), "relationship": relationship, "parentOwner": binding.Parent, "configurationChecksum": binding.Configuration.Checksum()})
	if err != nil {
		return result, err
	}
	if !nativeAuthorityParentSequence(parent, parentSequence, sequence) || !nativeAuthorityParentMatches(raw, parent) {
		return result, pluginError("context_authority_unavailable")
	}
	facts, err := decodeNativeAuthorityFacts(raw, binding, a.client.now())
	if err != nil {
		return result, err
	}
	if !nativeAuthorityLive(binding) || ctx.Err() != nil || !a.client.now().Before(validUntil) {
		return result, pluginError("context_owner_stale")
	}
	a.mu.Lock()
	state.facts = facts
	state.ready = true
	a.mu.Unlock()
	return cloneInstanceAdmission(facts.admission), nil
}
func nativeAuthorityOperationContext(ctx context.Context, operation []byte) (context.Context, context.CancelFunc, error) {
	if ctx == nil || nativeAuthoritySchema("operation", operation) != nil {
		return nil, nil, pluginError("context_authority_unavailable")
	}
	var claims struct {
		Deadline string `json:"deadline"`
	}
	_ = json.Unmarshal(operation, &claims)
	deadline, err := nativeAuthorityTime(claims.Deadline)
	if err != nil || !time.Now().Before(deadline) {
		return nil, nil, pluginError("context_authority_unavailable")
	}
	work, cancel := context.WithDeadline(ctx, deadline)
	return work, cancel, nil
}
func nativeAuthorityOriginal(operation ContextOperationAdmission) error {
	if len(operation.originalEnvelope) == 0 || strictDocument(operation.originalEnvelope) != nil || !contextReferenceValid(operation.AuthorityRef) {
		return pluginError("context_authority_unavailable")
	}
	original := fieldsForClaim(operation.originalEnvelope, "operation")
	left, e1 := nativeAuthorityCanonical(original)
	right, e2 := nativeAuthorityCanonical(operation.Operation)
	if e1 != nil || e2 != nil || !bytes.Equal(left, right) {
		return pluginError("context_authority_unavailable")
	}
	return nil
}
func (a *NativeContextAuthority) AdmitOperation(ctx context.Context, owner OwnerReference, original []byte) (ContextOperationAdmission, error) {
	fail := func() (ContextOperationAdmission, error) {
		return ContextOperationAdmission{}, pluginError("context_authority_unavailable")
	}
	state, err := a.instance(owner)
	if err != nil || len(original) > nativeAuthorityLimit || nativeAuthoritySchema("envelope", original) != nil {
		return fail()
	}
	original = bytes.Clone(original)
	operation := fieldsForClaim(original, "operation")
	work, cancel, err := nativeAuthorityOperationContext(ctx, operation)
	if err != nil {
		return fail()
	}
	defer cancel()
	checkedSequence, err := a.recheckWithSequence(work, owner, state.facts.admission, nil)
	if err != nil {
		return fail()
	}
	raw, validUntil, sequence, err := a.client.callWithSequence(work, owner, "admit-operation", map[string]any{"envelopeBytes": base64.StdEncoding.EncodeToString(original), "audience": map[string]string{"hubId": a.client.options.HubID, "serviceId": a.destinations[owner.InstanceID]}})
	if err != nil || (state.binding.Parent != nil && checkedSequence != sequence) {
		return fail()
	}
	var admitted struct {
		Operation    json.RawMessage  `json:"operation"`
		AuthorityRef ContextReference `json:"authorityRef"`
	}
	if json.Unmarshal(raw, &admitted) != nil {
		return fail()
	}
	result := ContextOperationAdmission{Operation: bytes.Clone(admitted.Operation), AuthorityRef: admitted.AuthorityRef, originalEnvelope: original}
	if !nativeCapabilityEqual(fieldsForClaim(result.Operation, "scope"), fieldsForClaim(state.facts.admission.EffectiveGrant, "scope")) || result.AuthorityRef.ID != a.client.options.AuthorityID || result.AuthorityRef.OwnerHubID != a.client.options.HubID || nativeAuthorityOriginal(result) != nil || !nativeAuthorityLive(state.binding) || work.Err() != nil || !a.client.now().Before(validUntil) {
		return fail()
	}
	return result, nil
}
func (a *NativeContextAuthority) Recheck(ctx context.Context, owner OwnerReference, instance ContextInstanceAdmission, operation *ContextOperationAdmission) error {
	_, err := a.recheckWithSequence(ctx, owner, instance, operation)
	return err
}
func (a *NativeContextAuthority) recheckWithSequence(ctx context.Context, owner OwnerReference, instance ContextInstanceAdmission, operation *ContextOperationAdmission) (uint64, error) {
	if ctx == nil || ctx.Err() != nil {
		return 0, pluginError("context_authority_unavailable")
	}
	state, err := a.instance(owner)
	if err != nil {
		return 0, err
	}
	if !sameNativeAdmission(instance, state.facts.admission) {
		return 0, pluginError("context_authority_unavailable")
	}
	input := map[string]any{"instanceFactsDigest": state.facts.digest, "operation": nil, "operationAuthorityRef": nil, "originalEnvelopeBytes": nil}
	if operation != nil {
		if nativeAuthorityOriginal(*operation) != nil {
			return 0, pluginError("context_authority_unavailable")
		}
		work, cancel, err := nativeAuthorityOperationContext(ctx, operation.Operation)
		if err != nil {
			return 0, err
		}
		defer cancel()
		ctx = work
		input["operation"] = json.RawMessage(operation.Operation)
		input["operationAuthorityRef"] = operation.AuthorityRef
		input["originalEnvelopeBytes"] = base64.StdEncoding.EncodeToString(operation.originalEnvelope)
	}
	parent, parentSequence, err := a.currentParent(ctx, state.binding)
	if err != nil {
		return 0, err
	}
	raw, validUntil, sequence, err := a.client.callWithSequence(ctx, owner, "recheck", input)
	if err != nil {
		return 0, err
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	ref := fields["operationAuthorityRef"]
	delete(fields, "operationAuthorityRef")
	if operation == nil {
		if !bytes.Equal(ref, []byte("null")) {
			return 0, pluginError("context_authority_unavailable")
		}
	} else {
		current, e := nativeAuthorityReference(ref)
		if e != nil || current.ID != operation.AuthorityRef.ID || current.OwnerHubID != operation.AuthorityRef.OwnerHubID || current.Revision < operation.AuthorityRef.Revision {
			return 0, pluginError("context_authority_unavailable")
		}
	}
	factsRaw, _ := json.Marshal(fields)
	facts, err := decodeNativeAuthorityFacts(factsRaw, state.binding, a.client.now())
	// A changed grant/policy/config binding requires fresh instance admission.
	// Retained facts are comparison input, never a successful authorization cache.
	if err != nil || !nativeAuthorityParentSequence(parent, parentSequence, sequence) || !nativeAuthorityParentMatches(factsRaw, parent) || facts.digest != state.facts.digest || !nativeAuthorityLive(state.binding) || ctx.Err() != nil || !a.client.now().Before(validUntil) {
		return 0, pluginError("context_authority_unavailable")
	}
	if sequence < a.client.sequence.Load() {
		return 0, pluginError("context_authority_unavailable")
	}
	return sequence, nil
}
func sameNativeAdmission(a, b ContextInstanceAdmission) bool {
	// Admissions have deliberately redacted MarshalJSON methods.
	return sameContextJSON(a.EffectiveGrant, b.EffectiveGrant) && a.ScopeRef == b.ScopeRef && a.ConfigurationRevision == b.ConfigurationRevision &&
		bytes.Equal(contextJSON(a.SecretReferences), contextJSON(b.SecretReferences)) && bytes.Equal(contextJSON(a.DomainBindings), contextJSON(b.DomainBindings))
}
func (a *NativeContextAuthority) PrepareDomainCall(ctx context.Context, owner OwnerReference, operation ContextOperationAdmission, call ContextDomainCall) (ContextApprovedEnvelope, error) {
	if call.ContractID == "configuration-change-subscribe" {
		return a.prepareSubscriptionCall(ctx, owner, operation, call)
	}
	fail := func() (ContextApprovedEnvelope, error) {
		return ContextApprovedEnvelope{}, pluginError("context_authority_unavailable")
	}
	state, err := a.instance(owner)
	if err != nil || nativeAuthorityOriginal(operation) != nil {
		return fail()
	}
	bound := false
	for _, d := range state.facts.admission.DomainBindings {
		if d.ID == call.BindingID && d.ContractID == call.ContractID {
			bound = true
		}
	}
	if !bound {
		return fail()
	}
	// Allocate the delivery inbox before asking the authority to prepare the
	// downstream command. It stays private until the host signs its wrapper.
	deliveryNonce, err := randomControlID()
	if err != nil {
		return fail()
	}
	work, cancel, err := nativeAuthorityOperationContext(ctx, operation.Operation)
	if err != nil {
		return fail()
	}
	defer cancel()
	checkedSequence, err := a.recheckWithSequence(work, owner, state.facts.admission, &operation)
	if err != nil {
		return fail()
	}
	raw, validUntil, sequence, err := a.client.callWithSequence(work, owner, "prepare-domain-call", map[string]any{"operation": json.RawMessage(operation.Operation), "operationAuthorityRef": operation.AuthorityRef, "bindingId": call.BindingID, "contractId": call.ContractID, "serviceRequestId": call.RequestID, "serviceReplySubject": a.client.replySubject(deliveryNonce), "payload": json.RawMessage(call.Payload), "originalEnvelopeBytes": base64.StdEncoding.EncodeToString(operation.originalEnvelope)})
	if err != nil || (state.binding.Parent != nil && checkedSequence != sequence) {
		return fail()
	}
	var result struct {
		BindingID           string `json:"bindingId"`
		EnvelopeBytes       string `json:"envelopeBytes"`
		ServiceRequestBytes string `json:"serviceRequestBytes"`
	}
	if json.Unmarshal(raw, &result) != nil || result.BindingID != call.BindingID {
		return fail()
	}
	envelope, err := base64.StdEncoding.Strict().DecodeString(result.EnvelopeBytes)
	if err != nil || base64.StdEncoding.EncodeToString(envelope) != result.EnvelopeBytes || nativeAuthoritySchema("envelope", envelope) != nil || !contextApprovedFor(envelope, operation.Operation, call) || !nativeAuthorityLive(state.binding) || work.Err() != nil || !a.client.now().Before(validUntil) {
		return fail()
	}
	serviceRequest, err := base64.StdEncoding.Strict().DecodeString(result.ServiceRequestBytes)
	if err != nil || base64.StdEncoding.EncodeToString(serviceRequest) != result.ServiceRequestBytes || nativeCapabilitySchema("capability-service-request", serviceRequest) != nil {
		return fail()
	}
	return ContextApprovedEnvelope{BindingID: result.BindingID, Envelope: envelope,
		delivery: &nativeCapabilityDelivery{authority: a, owner: owner, operation: cloneOperationAdmission(operation), replySubject: a.client.replySubject(deliveryNonce), requestID: call.RequestID, envelopeDigest: nativeAuthorityDigest(envelope), serviceRequest: serviceRequest}}, nil
}

var _ ContextAuthority = (*NativeContextAuthority)(nil)
