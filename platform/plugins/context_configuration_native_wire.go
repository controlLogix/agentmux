package plugins

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

// NativeConfigurationServiceBinding is an independently enrolled signer
// association for configuration-owner. It is not a capability route or grant.
type NativeConfigurationServiceBinding struct {
	ProfileID, HubID, ServiceInstanceID string
	ServiceIdentityRef, SigningKeyRef   ContextReference
}

// NativeConfigurationKeySource resolves the current independently enrolled
// configuration service signer. A reply never selects its own trust source.
type NativeConfigurationKeySource interface {
	CurrentConfigurationKey(context.Context, NativeConfigurationServiceBinding) (NativeAuthorityKey, error)
}

type NativeConfigurationBinding struct {
	ConfigurationRef ContextReference
	Service          NativeConfigurationServiceBinding
	AuthorityRef     ContextReference
	Resources        []SchemaResource
}

type nativeConfigurationState struct {
	Format                string             `json:"format"`
	Owner                 OwnerReference     `json:"owner"`
	SchemaRef             string             `json:"schemaRef"`
	ConfigurationBytes    string             `json:"configurationBytes"`
	SecretReferences      []ContextReference `json:"secretReferences"`
	ConfigurationChecksum string             `json:"configurationChecksum"`
	Revision              uint64             `json:"revision"`
}
type nativeConfigurationReply struct {
	Claims struct {
		Purpose          string                   `json:"purpose"`
		RequestDigest    string                   `json:"requestDigest"`
		ConfigurationRef ContextReference         `json:"configurationRef"`
		Owner            OwnerReference           `json:"owner"`
		AuthorityRef     ContextReference         `json:"authorityRef"`
		SigningKeyRef    ContextReference         `json:"signingKeyRef"`
		IssuedAt         string                   `json:"issuedAt"`
		ValidUntil       string                   `json:"validUntil"`
		State            nativeConfigurationState `json:"state"`
	} `json:"claims"`
	Signature string `json:"signature"`
}

func nativeConfigurationRequest(raw []byte, owner OwnerReference, binding NativeConfigurationBinding) (time.Time, error) {
	fail := pluginError("context_configuration_unavailable")
	if nativeAuthoritySchema("envelope", raw) != nil {
		return time.Time{}, fail
	}
	var request struct {
		ContractID           string `json:"contractId"`
		DestinationHubID     string `json:"destinationHubId"`
		DestinationServiceID string `json:"destinationServiceId"`
		Operation            struct {
			Deadline string `json:"deadline"`
		} `json:"operation"`
		IngressAttestation struct {
			Claims struct {
				ExpiresAt string `json:"expiresAt"`
			} `json:"claims"`
		} `json:"ingressAttestation"`
		Payload struct {
			ConfigurationRef ContextReference `json:"configurationRef"`
			Owner            OwnerReference   `json:"owner"`
			AfterRevision    uint64           `json:"afterRevision,omitempty"`
		} `json:"payload"`
	}
	if json.Unmarshal(raw, &request) != nil || request.DestinationHubID != binding.Service.HubID || request.DestinationServiceID != "configuration-owner" || request.Payload.Owner != owner || request.Payload.ConfigurationRef != binding.ConfigurationRef {
		return time.Time{}, fail
	}
	payload := fieldsForClaim(raw, "payload")
	if nativeAuthoritySchema("reference", fieldsForClaim(payload, "configurationRef")) != nil || nativeAuthoritySchema("owner", fieldsForClaim(payload, "owner")) != nil {
		return time.Time{}, fail
	}
	switch request.ContractID {
	case "configuration-read":
		if _, err := nativeAuthorityObject(payload, "configurationRef", "owner"); err != nil {
			return time.Time{}, fail
		}
	case "configuration-watch":
		if _, err := nativeAuthorityObject(payload, "configurationRef", "owner", "afterRevision"); err != nil {
			return time.Time{}, fail
		}
	case "configuration-set":
		if _, err := nativeAuthorityObject(payload, "configurationRef", "owner", "schemaRef", "configurationBytes", "secretReferences"); err != nil {
			return time.Time{}, fail
		}
	default:
		return time.Time{}, fail
	}
	deadline, e1 := nativeAuthorityTime(request.Operation.Deadline)
	expiry, e2 := nativeAuthorityTime(request.IngressAttestation.Claims.ExpiresAt)
	if e1 != nil || e2 != nil {
		return time.Time{}, fail
	}
	return minTime(deadline, expiry), nil
}

func verifyNativeConfigurationResponse(ctx context.Context, raw, request []byte, contextBinding ContextBinding, binding NativeConfigurationBinding, keys NativeConfigurationKeySource) (ContextConfigurationSnapshot, time.Time, error) {
	fail := func() (ContextConfigurationSnapshot, time.Time, error) {
		return ContextConfigurationSnapshot{}, time.Time{}, pluginError("context_configuration_unavailable")
	}
	deadline, err := nativeConfigurationRequest(request, contextBinding.Owner, binding)
	if err != nil || ctx == nil || ctx.Err() != nil || nilContextDependency(keys) {
		return fail()
	}
	if _, err = nativeAuthorityObject(raw, "claims", "signature"); err != nil {
		return fail()
	}
	claims := fieldsForClaim(raw, "claims")
	if _, err = nativeAuthorityObject(claims, "purpose", "requestDigest", "configurationRef", "owner", "authorityRef", "signingKeyRef", "issuedAt", "validUntil", "state"); err != nil {
		return fail()
	}
	state := fieldsForClaim(claims, "state")
	if _, err = nativeAuthorityObject(state, "format", "owner", "schemaRef", "configurationBytes", "secretReferences", "configurationChecksum", "revision"); err != nil {
		return fail()
	}
	var reply nativeConfigurationReply
	if protocol.DecodeClosedJSON(raw, &reply, nativeAuthorityLimit) != nil {
		return fail()
	}
	canonical, err := nativeAuthorityCanonical(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		return fail()
	}
	c, s := reply.Claims, reply.Claims.State
	if string(fieldsForClaim(request, "contractId")) == `"configuration-set"` {
		payload := fieldsForClaim(request, "payload")
		if binding.ConfigurationRef.Revision >= maxGeneration || s.Revision != binding.ConfigurationRef.Revision+1 || !nativeCapabilityEqual(fieldsForClaim(payload, "schemaRef"), contextJSON(s.SchemaRef)) || !nativeCapabilityEqual(fieldsForClaim(payload, "configurationBytes"), contextJSON(s.ConfigurationBytes)) || !nativeCapabilityEqual(fieldsForClaim(payload, "secretReferences"), contextJSON(s.SecretReferences)) {
			return fail()
		}
	}
	if c.Purpose != "agentmux-configuration-response-v1" || c.RequestDigest != nativeAuthorityDigestMustCanonical(request) || c.Owner != contextBinding.Owner || s.Owner != c.Owner || s.Format != "amx-configuration-v1" || s.Revision == 0 || s.Revision > maxGeneration || s.SchemaRef != contextBinding.Package.Manifest().ConfigurationSchemaRef || s.SecretReferences == nil || len(s.SecretReferences) > 64 || c.ConfigurationRef.ID != binding.ConfigurationRef.ID || c.ConfigurationRef.OwnerHubID != binding.ConfigurationRef.OwnerHubID || c.ConfigurationRef.Revision != s.Revision || s.Revision < binding.ConfigurationRef.Revision || c.SigningKeyRef != binding.Service.SigningKeyRef || !contextReferenceValid(c.AuthorityRef) || c.AuthorityRef.ID != binding.AuthorityRef.ID || c.AuthorityRef.OwnerHubID != binding.AuthorityRef.OwnerHubID || c.AuthorityRef.Revision < binding.AuthorityRef.Revision {
		return fail()
	}
	for _, name := range []string{"configurationRef", "authorityRef", "signingKeyRef"} {
		if _, err = nativeAuthorityObject(fieldsForClaim(claims, name), "id", "ownerHubId", "revision"); err != nil {
			return fail()
		}
	}
	for _, ownerRaw := range [][]byte{fieldsForClaim(claims, "owner"), fieldsForClaim(state, "owner")} {
		if nativeAuthoritySchema("owner", ownerRaw) != nil {
			return fail()
		}
	}
	var rawReferences []json.RawMessage
	if json.Unmarshal(fieldsForClaim(state, "secretReferences"), &rawReferences) != nil {
		return fail()
	}
	for _, reference := range rawReferences {
		if nativeAuthoritySchema("reference", reference) != nil {
			return fail()
		}
	}
	if string(fieldsForClaim(request, "contractId")) == `"configuration-watch"` {
		var after uint64
		rawAfter := fieldsForClaim(fieldsForClaim(request, "payload"), "afterRevision")
		if string(rawAfter) == "null" || json.Unmarshal(rawAfter, &after) != nil || after > maxGeneration || s.Revision <= after {
			return fail()
		}
	}
	seen := map[ContextReference]bool{}
	for _, ref := range s.SecretReferences {
		if !contextReferenceValid(ref) || seen[ref] {
			return fail()
		}
		seen[ref] = true
	}
	issued, e1 := nativeAuthorityTime(c.IssuedAt)
	until, e2 := nativeAuthorityTime(c.ValidUntil)
	now := time.Now()
	if e1 != nil || e2 != nil || issued.After(now) || !now.Before(until) || until.After(deadline) {
		return fail()
	}
	data, e1 := base64.StdEncoding.Strict().DecodeString(s.ConfigurationBytes)
	signature, e2 := base64.RawURLEncoding.Strict().DecodeString(reply.Signature)
	if e1 != nil || e2 != nil || len(data) == 0 || len(data) > 16384 || base64.StdEncoding.EncodeToString(data) != s.ConfigurationBytes || checksum(data) != s.ConfigurationChecksum || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != reply.Signature {
		return fail()
	}
	key, err := keys.CurrentConfigurationKey(ctx, binding.Service)
	signed, canonicalErr := nativeAuthorityCanonical(claims)
	if err != nil || canonicalErr != nil || len(key.PublicKey) != ed25519.PublicKeySize || key.NotBefore.After(now) || issued.Before(key.NotBefore) || !now.Before(key.ExpiresAt) || until.After(key.ExpiresAt) || key.AuthoritySequence > c.AuthorityRef.Revision || !ed25519.Verify(key.PublicKey, signed, signature) {
		return fail()
	}
	configuration, err := PrepareConfiguration(contextBinding.Package, binding.Resources, data)
	if err != nil {
		return ContextConfigurationSnapshot{}, time.Time{}, managerFailure(err, "context_configuration_unavailable")
	}
	// Repeat the fresh key read after validation work, before releasing values.
	key, err = keys.CurrentConfigurationKey(ctx, binding.Service)
	now = time.Now()
	if err != nil || ctx.Err() != nil || len(key.PublicKey) != ed25519.PublicKeySize || key.NotBefore.After(now) || issued.Before(key.NotBefore) || !now.Before(key.ExpiresAt) || !now.Before(until) || until.After(key.ExpiresAt) || key.AuthoritySequence > c.AuthorityRef.Revision || !ed25519.Verify(key.PublicKey, signed, signature) {
		return fail()
	}
	return ContextConfigurationSnapshot{Configuration: configuration, Revision: s.Revision, SecretReferences: append([]ContextReference{}, s.SecretReferences...)}, until, nil
}
