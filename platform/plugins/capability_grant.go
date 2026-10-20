package plugins

import (
	"fmt"
	"io"
	"slices"
	"time"
)

// CapabilityScope uses exact equality. Empty project/workspace fields represent
// absent dimensions, not permission to access every project or workspace.
type CapabilityScope struct {
	OrganizationID string
	ProjectID      string
	WorkspaceID    string
}

// CapabilityGrant is an authority owner's resolved grant, not proof that the
// issuer, subject or revision is trusted or current. It follows common v1 grant
// semantics; parsing and authentication remain with the authority owner.
type CapabilityGrant struct {
	Reference         ContextReference
	SubjectInstanceID string
	Scope             CapabilityScope
	Actions           []string
	ResourceIDs       []string
	IssuedAt          time.Time
	ExpiresAt         time.Time
	PolicyRef         ContextReference
	ParentGrantRef    *ContextReference
}

// CapabilityAccess keeps the action, resource class and exact resource together.
// Resource classes must come from the resource owner, never a child's label.
type CapabilityAccess struct {
	Action        string
	ResourceClass string
	ResourceID    string
}

// CapabilityPolicyDecision is a resolved owner decision for one exact access.
// Outcome is allow, deny, or approval_required. The owner may supply allow only
// after checking all applicable policy, membership and approval requirements.
type CapabilityPolicyDecision struct {
	Access  CapabilityAccess
	Outcome string
}

type CapabilityPolicy struct {
	Reference         ContextReference
	SubjectInstanceID string
	Scope             CapabilityScope
	IssuedAt          time.Time
	ExpiresAt         time.Time
	Decisions         []CapabilityPolicyDecision
}

type CapabilityEvaluation struct {
	Manifest ValidatedManifest
	// Relationship is independent or private. Independent references use their
	// own independent evaluation and never inherit the referring parent's grant.
	Relationship     string
	InstanceID       string
	ParentInstanceID string
	Grant            CapabilityGrant
	Parent           *CapabilityGrant
	// ParentAccess is the current effective tuple set for the exact Parent grant.
	// It must be resolved by the authority owner; nil means no delegated access.
	ParentAccess []CapabilityAccess
	Policy       CapabilityPolicy
	Now          time.Time
}

// CapabilityIntersection is a calculation, not a credential, enrollment record
// or authorization cache. The authority owner must obtain current inputs and
// evaluate again at each use, then preserve signed audience/payload binding and
// have the destination owner check current authority before an effect.
type CapabilityIntersection struct {
	access    []CapabilityAccess
	expiresAt time.Time
}

func (c CapabilityIntersection) Access() []CapabilityAccess { return slices.Clone(c.access) }
func (c CapabilityIntersection) ExpiresAt() time.Time       { return c.expiresAt }
func (CapabilityIntersection) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[capability intersection]")
}
func (CapabilityIntersection) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"capability-intersection"}`), nil
}
func (CapabilityEvaluation) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[capability evaluation]")
}
func (CapabilityEvaluation) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"capability-evaluation"}`), nil
}
func (CapabilityGrant) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[resolved capability grant]")
}
func (CapabilityGrant) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"resolved-capability-grant"}`), nil
}
func (CapabilityPolicy) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[resolved capability policy]")
}
func (CapabilityPolicy) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"resolved-capability-policy"}`), nil
}

const capabilityLimit = 256

// EvaluateCapabilityGrant calculates declarations intersected with the grant,
// parent delegation and policy. A wider private grant is refused, not repaired.
// No remote effects, credentials, service handles or grant records are created.
// Inputs must be owned snapshots and must not be mutated during this call.
func EvaluateCapabilityGrant(in CapabilityEvaluation) (CapabilityIntersection, error) {
	fail := func(code string) (CapabilityIntersection, error) { return CapabilityIntersection{}, pluginError(code) }
	if len(in.Manifest.raw) == 0 || !registryIdentifier.MatchString(in.InstanceID) || in.Now.IsZero() ||
		!capabilityGrantValid(in.Grant, in.Now) || in.Grant.SubjectInstanceID != in.InstanceID {
		return fail("capability_grant_invalid")
	}
	manifest := in.Manifest.manifest
	switch in.Relationship {
	case "independent":
		if in.Parent != nil || len(in.ParentAccess) != 0 || in.ParentInstanceID != "" || in.Grant.ParentGrantRef != nil || !slices.Contains(manifest.InstallationModes, "independent") {
			return fail("capability_parent_invalid")
		}
	case "private":
		if in.Parent == nil || !registryIdentifier.MatchString(in.ParentInstanceID) || in.ParentInstanceID == in.InstanceID ||
			!slices.Contains(manifest.InstallationModes, "private-child") || !capabilityGrantValid(*in.Parent, in.Now) ||
			in.Parent.SubjectInstanceID != in.ParentInstanceID || in.Grant.ParentGrantRef == nil || *in.Grant.ParentGrantRef != in.Parent.Reference ||
			in.Grant.Reference.OwnerHubID != in.Parent.Reference.OwnerHubID || in.Grant.Reference.ID == in.Parent.Reference.ID {
			return fail("capability_parent_invalid")
		}
		if len(in.ParentAccess) > capabilityLimit {
			return fail("capability_parent_invalid")
		}
		for _, access := range in.ParentAccess {
			if !capabilityAccessValid(access) || !slices.Contains(in.Parent.Actions, access.Action) || !slices.Contains(in.Parent.ResourceIDs, access.ResourceID) {
				return fail("capability_parent_invalid")
			}
		}
		parent := in.Parent
		if in.Grant.Scope != parent.Scope || !capabilitySubset(in.Grant.Actions, parent.Actions) || !capabilitySubset(in.Grant.ResourceIDs, parent.ResourceIDs) ||
			in.Grant.IssuedAt.Before(parent.IssuedAt) || in.Grant.ExpiresAt.After(parent.ExpiresAt) {
			return fail("capability_grant_widened")
		}
	default:
		return fail("capability_parent_invalid")
	}
	policy := in.Policy
	if !contextReferenceValid(policy.Reference) || policy.Reference != in.Grant.PolicyRef || policy.SubjectInstanceID != in.InstanceID ||
		policy.Scope != in.Grant.Scope || !capabilityTimeValid(policy.IssuedAt, policy.ExpiresAt, in.Now) || len(policy.Decisions) > capabilityLimit {
		return fail("capability_policy_unavailable")
	}
	// Denial takes precedence over allow. An unresolved approval also prevents
	// access even if another entry allows the same tuple.
	decisions := make(map[CapabilityAccess]string, len(policy.Decisions))
	for _, decision := range policy.Decisions {
		access := decision.Access
		if !capabilityAccessValid(access) {
			return fail("capability_policy_unavailable")
		}
		if decision.Outcome != "allow" && decision.Outcome != "deny" && decision.Outcome != "approval_required" {
			return fail("capability_policy_unavailable")
		}
		previous := decisions[access]
		if previous == "deny" || (previous == "approval_required" && decision.Outcome == "allow") {
			continue
		}
		decisions[access] = decision.Outcome
	}
	result := CapabilityIntersection{expiresAt: in.Grant.ExpiresAt, access: []CapabilityAccess{}}
	if policy.ExpiresAt.Before(result.expiresAt) {
		result.expiresAt = policy.ExpiresAt
	}
	if len(manifest.RequestedCapabilities) > capabilityLimit {
		return fail("capability_declarations_invalid")
	}
	seen := map[CapabilityAccess]bool{}
	for _, declaration := range manifest.RequestedCapabilities {
		available := false
		for _, decision := range policy.Decisions {
			access := decision.Access
			if decisions[access] != "allow" || declaration.Action != access.Action || declaration.ResourceClass != access.ResourceClass ||
				!slices.Contains(in.Grant.Actions, access.Action) || !slices.Contains(in.Grant.ResourceIDs, access.ResourceID) {
				continue
			}
			if in.Relationship == "private" && !slices.Contains(in.ParentAccess, access) {
				continue
			}
			available = true
			if !seen[access] {
				result.access = append(result.access, access)
				seen[access] = true
			}
		}
		if declaration.Required && !available {
			return fail("capability_required_unavailable")
		}
	}
	return result, nil
}

func capabilityGrantValid(grant CapabilityGrant, now time.Time) bool {
	return contextReferenceValid(grant.Reference) && registryIdentifier.MatchString(grant.SubjectInstanceID) &&
		capabilityScopeValid(grant.Scope) && capabilityIdentifiers(grant.Actions, false) && capabilityIdentifiers(grant.ResourceIDs, true) &&
		capabilityTimeValid(grant.IssuedAt, grant.ExpiresAt, now) && contextReferenceValid(grant.PolicyRef) &&
		(grant.ParentGrantRef == nil || contextReferenceValid(*grant.ParentGrantRef))
}
func capabilityTimeValid(issued, expires, now time.Time) bool {
	return !issued.IsZero() && !expires.IsZero() && !issued.After(now) && issued.Before(expires) && now.Before(expires)
}
func capabilityScopeValid(scope CapabilityScope) bool {
	return registryIdentifier.MatchString(scope.OrganizationID) && (scope.ProjectID == "" || registryIdentifier.MatchString(scope.ProjectID)) &&
		(scope.WorkspaceID == "" || registryIdentifier.MatchString(scope.WorkspaceID))
}
func capabilityIdentifiers(values []string, empty bool) bool {
	if len(values) > capabilityLimit || (!empty && len(values) == 0) {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !registryIdentifier.MatchString(value) || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}
func capabilitySubset(child, parent []string) bool {
	for _, value := range child {
		if !slices.Contains(parent, value) {
			return false
		}
	}
	return true
}

func capabilityAccessValid(access CapabilityAccess) bool {
	return registryIdentifier.MatchString(access.Action) && registryIdentifier.MatchString(access.ResourceClass) && registryIdentifier.MatchString(access.ResourceID)
}
