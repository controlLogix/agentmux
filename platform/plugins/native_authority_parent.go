package plugins

import (
	"context"
	"slices"
)

// The parent state is the Go host's original evaluated admission. Remote parent
// tuples must agree with it; the child cannot replace the parent's declarations.
func (a *NativeContextAuthority) currentParent(ctx context.Context, binding ContextBinding) (*nativeAuthorityInstance, uint64, error) {
	if binding.Parent == nil {
		return nil, 0, nil
	}
	parent, err := a.instance(*binding.Parent)
	if err != nil || binding.ParentLifetime != parent.binding.LifetimeDone {
		return nil, 0, pluginError("context_authority_unavailable")
	}
	sequence, err := a.recheckWithSequence(ctx, *binding.Parent, parent.facts.admission, nil)
	if err != nil || !nativeAuthorityLive(parent.binding) {
		return nil, 0, pluginError("context_authority_unavailable")
	}
	return parent, sequence, nil
}
func nativeAuthorityParentMatches(raw []byte, parent *nativeAuthorityInstance) bool {
	if parent == nil {
		return true
	}
	if !nativeAuthorityLive(parent.binding) || !nativeCapabilityEqual(fieldsForClaim(raw, "parentGrant"), parent.facts.admission.EffectiveGrant) {
		return false
	}
	access, err := nativeAuthorityAccessList(fieldsForClaim(raw, "parentAccess"))
	if err != nil || len(access) != len(parent.facts.access) {
		return false
	}
	for _, entry := range access {
		if !slices.Contains(parent.facts.access, entry) {
			return false
		}
	}
	return true
}

// The parent and child share one identity aggregate. A newer child snapshot
// requires a fresh parent check, rather than trusting older delegated access.
func nativeAuthorityParentSequence(parent *nativeAuthorityInstance, parentSequence, childSequence uint64) bool {
	return parent == nil || parentSequence == childSequence
}
