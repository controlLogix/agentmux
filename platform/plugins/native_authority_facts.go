package plugins

import (
	"bytes"
	"encoding/json"
	"slices"
	"time"
)

type nativeAuthorityFacts struct {
	admission ContextInstanceAdmission
	access    []CapabilityAccess
	digest    string
	resources map[string][]string
}

func nativeAuthorityReference(raw []byte) (ContextReference, error) {
	var r ContextReference
	if nativeAuthoritySchema("reference", raw) != nil || json.Unmarshal(raw, &r) != nil {
		return r, pluginError("context_authority_wire_invalid")
	}
	return r, nil
}
func nativeAuthorityGrant(raw []byte) (CapabilityGrant, error) {
	fail := func() (CapabilityGrant, error) {
		return CapabilityGrant{}, pluginError("context_authority_wire_invalid")
	}
	if nativeAuthoritySchema("grant", raw) != nil {
		return fail()
	}
	var g struct {
		GrantID           string            `json:"grantId"`
		IssuerHubID       string            `json:"issuerHubId"`
		Revision          uint64            `json:"revision"`
		SubjectInstanceID string            `json:"subjectInstanceId"`
		Scope             CapabilityScope   `json:"scope"`
		Actions           []string          `json:"actions"`
		ResourceIDs       []string          `json:"resourceIds"`
		IssuedAt          string            `json:"issuedAt"`
		ExpiresAt         string            `json:"expiresAt"`
		PolicyRef         ContextReference  `json:"policyRef"`
		ParentGrantRef    *ContextReference `json:"parentGrantRef"`
	}
	if json.Unmarshal(raw, &g) != nil {
		return fail()
	}
	start, e1 := nativeAuthorityTime(g.IssuedAt)
	end, e2 := nativeAuthorityTime(g.ExpiresAt)
	if e1 != nil || e2 != nil {
		return fail()
	}
	return CapabilityGrant{Reference: ContextReference{ID: g.GrantID, OwnerHubID: g.IssuerHubID, Revision: g.Revision}, SubjectInstanceID: g.SubjectInstanceID, Scope: g.Scope, Actions: g.Actions, ResourceIDs: g.ResourceIDs, IssuedAt: start, ExpiresAt: end, PolicyRef: g.PolicyRef, ParentGrantRef: g.ParentGrantRef}, nil
}
func nativeAuthorityAccess(raw []byte) (CapabilityAccess, error) {
	var a CapabilityAccess
	if _, e := nativeAuthorityObject(raw, "action", "resourceClass", "resourceId"); e != nil {
		return a, e
	}
	if json.Unmarshal(raw, &a) != nil || !capabilityAccessValid(a) {
		return a, pluginError("context_authority_wire_invalid")
	}
	return a, nil
}
func nativeAuthorityAccessList(raw []byte) ([]CapabilityAccess, error) {
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil || items == nil || len(items) > capabilityLimit {
		return nil, pluginError("context_authority_wire_invalid")
	}
	out := make([]CapabilityAccess, 0, len(items))
	seen := map[CapabilityAccess]bool{}
	for _, item := range items {
		a, e := nativeAuthorityAccess(item)
		if e != nil || seen[a] {
			return nil, pluginError("context_authority_wire_invalid")
		}
		seen[a] = true
		out = append(out, a)
	}
	return out, nil
}
func nativeAuthorityPolicy(raw []byte) (CapabilityPolicy, error) {
	fail := func() (CapabilityPolicy, error) {
		return CapabilityPolicy{}, pluginError("context_authority_wire_invalid")
	}
	f, e := nativeAuthorityObject(raw, "reference", "subjectInstanceId", "scope", "issuedAt", "expiresAt", "decisions")
	if e != nil {
		return fail()
	}
	var p CapabilityPolicy
	var issued, expires string
	p.Reference, e = nativeAuthorityReference(f["reference"])
	if e != nil || nativeAuthoritySchema("scope", f["scope"]) != nil {
		return fail()
	}
	if json.Unmarshal(f["subjectInstanceId"], &p.SubjectInstanceID) != nil || json.Unmarshal(f["scope"], &p.Scope) != nil || json.Unmarshal(f["issuedAt"], &issued) != nil || json.Unmarshal(f["expiresAt"], &expires) != nil {
		return fail()
	}
	p.IssuedAt, e = nativeAuthorityTime(issued)
	if e != nil {
		return fail()
	}
	p.ExpiresAt, e = nativeAuthorityTime(expires)
	if e != nil {
		return fail()
	}
	var decisions []json.RawMessage
	if json.Unmarshal(f["decisions"], &decisions) != nil || decisions == nil || len(decisions) > capabilityLimit {
		return fail()
	}
	seen := map[CapabilityAccess]bool{}
	for _, raw := range decisions {
		fields, e := nativeAuthorityObject(raw, "access", "outcome")
		if e != nil {
			return fail()
		}
		access, e := nativeAuthorityAccess(fields["access"])
		if e != nil || seen[access] {
			return fail()
		}
		seen[access] = true
		var outcome string
		if json.Unmarshal(fields["outcome"], &outcome) != nil {
			return fail()
		}
		p.Decisions = append(p.Decisions, CapabilityPolicyDecision{Access: access, Outcome: outcome})
	}
	return p, nil
}
func decodeNativeAuthorityFacts(raw []byte, binding ContextBinding, now time.Time) (nativeAuthorityFacts, error) {
	fail := func() (nativeAuthorityFacts, error) {
		return nativeAuthorityFacts{}, pluginError("context_authority_unavailable")
	}
	if nativeAuthoritySchema("facts", raw) != nil {
		return fail()
	}
	f, e := nativeAuthorityObject(raw, "grant", "policy", "parentGrant", "parentAccess", "scopeRef", "configurationRevision", "secretReferences", "domainBindings")
	if e != nil {
		return fail()
	}
	grant, e := nativeAuthorityGrant(f["grant"])
	if e != nil {
		return fail()
	}
	policy, e := nativeAuthorityPolicy(f["policy"])
	if e != nil {
		return fail()
	}
	input := CapabilityEvaluation{Manifest: binding.Package.manifest, Relationship: "independent", InstanceID: binding.Owner.InstanceID, Grant: grant, Policy: policy, Now: now}
	input.ParentAccess, e = nativeAuthorityAccessList(f["parentAccess"])
	if e != nil {
		return fail()
	}
	if !bytes.Equal(f["parentGrant"], []byte("null")) {
		parent, e := nativeAuthorityGrant(f["parentGrant"])
		if e != nil {
			return fail()
		}
		input.Parent = &parent
	}
	if binding.Parent != nil {
		input.Relationship = "private"
		input.ParentInstanceID = binding.Parent.InstanceID
	}
	intersection, e := EvaluateCapabilityGrant(input)
	if e != nil {
		return fail()
	}
	admission := ContextInstanceAdmission{EffectiveGrant: bytes.Clone(f["grant"]), DomainBindings: []ContextDomainBinding{}, SecretReferences: []ContextReference{}}
	admission.ScopeRef, e = nativeAuthorityReference(f["scopeRef"])
	if e != nil {
		return fail()
	}
	if json.Unmarshal(f["configurationRevision"], &admission.ConfigurationRevision) != nil || admission.ConfigurationRevision > maxGeneration {
		return fail()
	}
	var secrets, domains []json.RawMessage
	if json.Unmarshal(f["secretReferences"], &secrets) != nil || secrets == nil || len(secrets) > 64 || json.Unmarshal(f["domainBindings"], &domains) != nil || domains == nil || len(domains) > 64 {
		return fail()
	}
	seenRefs := map[ContextReference]bool{}
	for _, r := range secrets {
		ref, e := nativeAuthorityReference(r)
		if e != nil || seenRefs[ref] {
			return fail()
		}
		seenRefs[ref] = true
		admission.SecretReferences = append(admission.SecretReferences, ref)
	}
	seen := map[string]bool{}
	resources := map[string][]string{}
	for _, d := range domains {
		if _, e := nativeAuthorityObject(d, "id", "contractId", "action", "resourceClass", "resourceIds"); e != nil {
			return fail()
		}
		var domain struct {
			ID            string   `json:"id"`
			ContractID    string   `json:"contractId"`
			Action        string   `json:"action"`
			ResourceClass string   `json:"resourceClass"`
			ResourceIDs   []string `json:"resourceIds"`
		}
		if json.Unmarshal(d, &domain) != nil || seen[domain.ID] || !registryIdentifier.MatchString(domain.ID) || !registryIdentifier.MatchString(domain.ContractID) || !capabilityIdentifiers(domain.ResourceIDs, false) {
			return fail()
		}
		seen[domain.ID] = true
		for _, resource := range domain.ResourceIDs {
			if !slices.Contains(intersection.Access(), CapabilityAccess{Action: domain.Action, ResourceClass: domain.ResourceClass, ResourceID: resource}) {
				return fail()
			}
		}
		admission.DomainBindings = append(admission.DomainBindings, ContextDomainBinding{ID: domain.ID, ContractID: domain.ContractID, Action: domain.Action, ResourceClass: domain.ResourceClass})
		resources[domain.ID] = append([]string{}, domain.ResourceIDs...)
	}
	canonical, e := nativeAuthorityCanonical(raw)
	if e != nil {
		return fail()
	}
	return nativeAuthorityFacts{admission: admission, access: intersection.Access(), digest: nativeAuthorityDigest(canonical), resources: resources}, nil
}
