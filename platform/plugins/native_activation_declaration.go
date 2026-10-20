package plugins

import (
	"bytes"
	"context"
	"encoding/json"
)

// Production construction supplies only NativeEnrolledKeys. This private
// boundary lets offline tests exercise the provider without a live broker.
type nativeActivationKeySource interface {
	NativeConfigurationKeySource
	currentWithSequence(context.Context) ([]byte, uint64, error)
	activationHostIdentity() ContextReference
}

func (k *NativeEnrolledKeys) activationHostIdentity() ContextReference {
	return k.options.HostIdentityRef
}

// NativeActivationDeclaration is an owner-private enrollment input, not an
// authority record. Only the allocated ContextBinding supplies the live owner.
type NativePrivateStorageResource struct {
	ResourceID    string          `json:"resourceId"`
	Scope         json.RawMessage `json:"scope"`
	BindingDigest string          `json:"bindingDigest"`
}

type NativeActivationDeclaration struct {
	PrivateStorageResources   []NativePrivateStorageResource   `json:"privateStorageResources,omitempty"`
	RecordRef                 ContextReference                 `json:"recordRef"`
	PreviousRef               *ContextReference                `json:"previousRef"`
	IdentityRef               ContextReference                 `json:"identityRef"`
	Pin                       PackagePin                       `json:"pin"`
	ManifestDigest            string                           `json:"manifestDigest"`
	ConfigurationChecksum     string                           `json:"configurationChecksum"`
	Facts                     json.RawMessage                  `json:"facts"`
	ConfigurationEventSources []NativeConfigurationEventSource `json:"configurationEventSources,omitempty"`
}

func cloneNativeActivationDeclaration(d NativeActivationDeclaration) NativeActivationDeclaration {
	d.Facts = bytes.Clone(d.Facts)
	if d.PrivateStorageResources != nil {
		d.PrivateStorageResources = append([]NativePrivateStorageResource{}, d.PrivateStorageResources...)
		for i := range d.PrivateStorageResources {
			d.PrivateStorageResources[i].Scope = bytes.Clone(d.PrivateStorageResources[i].Scope)
		}
	}
	d.ConfigurationEventSources = append([]NativeConfigurationEventSource(nil), d.ConfigurationEventSources...)
	if d.PreviousRef != nil {
		previous := *d.PreviousRef
		d.PreviousRef = &previous
	}
	return d
}

func nativeActivationRecord(binding ContextBinding, declaration NativeActivationDeclaration, host ContextReference) ([]byte, error) {
	fail := pluginError("context_activation_unavailable")
	if !contextOwnerValid(binding.Owner) || !contextReferenceValid(host) || declaration.Pin != binding.Owner.Pin || declaration.Pin != binding.Package.Pin() || !binding.Configuration.BelongsTo(binding.Package) || declaration.ManifestDigest != binding.Package.manifest.Checksum() || declaration.ConfigurationChecksum != binding.Configuration.Checksum() || !contextReferenceValid(declaration.RecordRef) || declaration.RecordRef.OwnerHubID != host.OwnerHubID || !contextReferenceValid(declaration.IdentityRef) || declaration.IdentityRef.OwnerHubID != host.OwnerHubID {
		return nil, fail
	}
	if declaration.PreviousRef == nil {
		if declaration.RecordRef.Revision != 1 {
			return nil, fail
		}
	} else if !contextReferenceValid(*declaration.PreviousRef) || declaration.PreviousRef.Revision >= maxGeneration || declaration.RecordRef.ID != declaration.PreviousRef.ID || declaration.RecordRef.OwnerHubID != declaration.PreviousRef.OwnerHubID || declaration.RecordRef.Revision != declaration.PreviousRef.Revision+1 {
		return nil, fail
	}
	relationship := "independent"
	if binding.Parent != nil {
		relationship = "private"
	}
	row := map[string]any{"ref": declaration.RecordRef, "status": "active", "owner": binding.Owner, "identityRef": declaration.IdentityRef, "hostIdentityRef": host, "manifestDigest": declaration.ManifestDigest, "configurationChecksum": declaration.ConfigurationChecksum, "relationship": relationship, "parentOwner": binding.Parent, "facts": declaration.Facts}
	if declaration.ConfigurationEventSources != nil {
		row["configurationEventSources"] = declaration.ConfigurationEventSources
	}
	if declaration.PrivateStorageResources != nil {
		row["privateStorageResources"] = declaration.PrivateStorageResources
	}
	raw, err := json.Marshal(row)
	if err != nil || nativeAuthoritySchema("identity-native-instance", raw) != nil {
		return nil, fail
	}
	return raw, nil
}

func (p *nativeRegisteredContextProvider) activate(ctx context.Context, binding ContextBinding) error {
	if ctx == nil || ctx.Err() != nil || p.activationKeys == nil || p.authority == nil {
		return pluginError("context_activation_unavailable")
	}
	work, cancel := context.WithTimeout(ctx, contextCallBudget)
	defer cancel()
	p.activationMu.Lock()
	declaration, exists := p.declarations[binding.Owner.InstanceID]
	if !exists || p.activating[binding.Owner.InstanceID] || p.activationFailed[binding.Owner.InstanceID] {
		p.activationMu.Unlock()
		return pluginError("context_activation_unavailable")
	}
	p.activating[binding.Owner.InstanceID] = true
	configuration, hasConfiguration := p.configurations[binding.Owner.InstanceID]
	p.activationMu.Unlock()
	succeeded := false
	defer func() {
		p.activationMu.Lock()
		delete(p.activating, binding.Owner.InstanceID)
		if !succeeded {
			p.activationFailed[binding.Owner.InstanceID] = true
		}
		p.activationMu.Unlock()
	}()
	// Reject a known stale configuration declaration before committing identity.
	admission, err := decodeNativeAuthorityFacts(declaration.Facts, binding, p.authority.client.now())
	if err != nil || !hasConfiguration || configuration.Binding.ConfigurationRef.Revision >= maxGeneration || admission.admission.ConfigurationRevision != configuration.Binding.ConfigurationRef.Revision+1 {
		return pluginError("context_configuration_unavailable")
	}
	raw, err := nativeActivationRecord(binding, declaration, p.activationKeys.activationHostIdentity())
	if err != nil {
		return err
	}
	_, expectedVersion, err := p.activationKeys.currentWithSequence(work)
	if err != nil {
		return managerFailure(err, "context_activation_unavailable")
	}
	committed, err := p.authority.ActivateInstance(work, binding, raw, declaration.PreviousRef, expectedVersion)
	if err != nil {
		return err
	}
	p.activationMu.Lock()
	if committed.Revision < maxGeneration {
		declaration.PreviousRef = &committed
		declaration.RecordRef = committed
		declaration.RecordRef.Revision++
		p.declarations[binding.Owner.InstanceID] = declaration
	} else {
		delete(p.declarations, binding.Owner.InstanceID)
	}
	p.activationMu.Unlock()
	if err := p.initializeConfiguration(work, binding, declaration); err != nil {
		return err
	}
	succeeded = true
	return nil
}
