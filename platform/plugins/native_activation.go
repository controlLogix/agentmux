package plugins

import (
	"bytes"
	"context"
	"encoding/json"
)

// ActivateInstance sends a complete host-admitted record through the enrolled
// authority channel. The record and expectedVersion must come from protected
// admission and a current identity read; this method does not create grants.
// Success does not replace BindInstance or establish plugin readiness.
func (a *NativeContextAuthority) ActivateInstance(ctx context.Context, binding ContextBinding, record []byte, previousRef *ContextReference, expectedVersion uint64) (ContextReference, error) {
	record = bytes.Clone(record)
	binding = cloneContextBinding(binding)
	if previousRef != nil {
		previous := *previousRef
		previousRef = &previous
	}
	fail := func() (ContextReference, error) {
		return ContextReference{}, pluginError("context_activation_unavailable")
	}
	if a == nil || a.client == nil || ctx == nil || ctx.Err() != nil || expectedVersion == 0 || expectedVersion > maxGeneration || !contextOwnerValid(binding.Owner) || binding.Owner.Pin != binding.Package.Pin() || !binding.Configuration.BelongsTo(binding.Package) || !nativeAuthorityLive(binding) || nilContextDependency(binding.Lifecycle) || binding.Lifecycle.Snapshot().Owner != binding.Owner || binding.Lifecycle.DrainDone() == nil || completed(binding.Lifecycle.DrainDone()) || nativeAuthoritySchema("identity-native-instance", record) != nil {
		return fail()
	}
	names := []string{"ref", "status", "owner", "identityRef", "hostIdentityRef", "manifestDigest", "relationship", "parentOwner", "configurationChecksum", "facts"}
	if len(fieldsForClaim(record, "configurationEventSources")) != 0 {
		names = append(names, "configurationEventSources")
	}
	if len(fieldsForClaim(record, "privateStorageResources")) != 0 {
		names = append(names, "privateStorageResources")
	}
	fields, err := nativeAuthorityObject(record, names...)
	if err != nil {
		return fail()
	}
	var row struct {
		Ref                   ContextReference `json:"ref"`
		Status                string           `json:"status"`
		Owner                 OwnerReference   `json:"owner"`
		ManifestDigest        string           `json:"manifestDigest"`
		Relationship          string           `json:"relationship"`
		ParentOwner           *OwnerReference  `json:"parentOwner"`
		ConfigurationChecksum string           `json:"configurationChecksum"`
	}
	if json.Unmarshal(record, &row) != nil || row.Status != "active" || row.Owner != binding.Owner || row.Ref.OwnerHubID != a.client.options.HubID || row.ManifestDigest != binding.Package.manifest.Checksum() || row.ConfigurationChecksum != binding.Configuration.Checksum() {
		return fail()
	}
	if previousRef == nil {
		if row.Ref.Revision != 1 {
			return fail()
		}
	} else if !contextReferenceValid(*previousRef) || previousRef.Revision >= maxGeneration || previousRef.ID != row.Ref.ID || previousRef.OwnerHubID != row.Ref.OwnerHubID || row.Ref.Revision != previousRef.Revision+1 {
		return fail()
	}
	if binding.Parent == nil {
		if row.Relationship != "independent" || row.ParentOwner != nil || binding.ParentLifetime != nil {
			return fail()
		}
	} else if row.Relationship != "private" || row.ParentOwner == nil || *row.ParentOwner != *binding.Parent || !contextOwnerValid(*binding.Parent) || binding.Parent.Epoch != binding.Owner.Epoch || binding.Parent.InstanceID == binding.Owner.InstanceID {
		return fail()
	}
	if _, err := decodeNativeAuthorityFacts(fields["facts"], binding, a.client.now()); err != nil {
		return fail()
	}
	if _, _, err := a.currentParent(ctx, binding); err != nil {
		return fail()
	}
	nonce, err := randomControlID()
	if err != nil {
		return fail()
	}
	input := map[string]any{"record": json.RawMessage(record), "previousRef": previousRef, "cancellationRef": ContextReference{ID: "activation_" + nonce, OwnerHubID: a.client.options.HubID, Revision: 1}, "expectedVersion": expectedVersion}
	raw, until, sequence, err := a.client.callWithSequence(ctx, binding.Owner, "activate-instance", input)
	if err != nil {
		return ContextReference{}, managerFailure(err, "context_activation_unavailable")
	}
	result, err := nativeAuthorityObject(raw, "enrollmentRef", "facts")
	if err != nil {
		return fail()
	}
	var committed ContextReference
	if json.Unmarshal(result["enrollmentRef"], &committed) != nil || committed != row.Ref || !nativeCapabilityEqual(result["facts"], fields["facts"]) {
		return fail()
	}
	if _, err := nativeAuthorityObject(result["enrollmentRef"], "id", "ownerHubId", "revision"); err != nil {
		return fail()
	}
	// Activation changes the aggregate. Recheck the original parent against the
	// committed sequence instead of retaining the pre-commit sequence.
	parent, parentSequence, err := a.currentParent(ctx, binding)
	if err != nil || !nativeAuthorityParentSequence(parent, parentSequence, sequence) || !nativeAuthorityParentMatches(result["facts"], parent) || !nativeAuthorityLive(binding) || completed(binding.Lifecycle.DrainDone()) || ctx.Err() != nil || !a.client.now().Before(until) {
		return fail()
	}
	return committed, nil
}
