package plugins

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func capabilityFixture(t *testing.T, private bool) CapabilityEvaluation {
	t.Helper()
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	manifest := fixtureManifest("capability_package")
	manifest.InstallationModes = []string{"independent", "private-child"}
	manifest.RequestedCapabilities = []Capability{{Action: "read", ResourceClass: "storage", Required: true}}
	validated, err := ValidateManifest(manifestBytes(t, manifest))
	if err != nil {
		t.Fatal(err)
	}
	scope := CapabilityScope{OrganizationID: "org", ProjectID: "project", WorkspaceID: "workspace"}
	policyRef := ContextReference{ID: "policy", OwnerHubID: "hub", Revision: 2}
	grant := CapabilityGrant{Reference: ContextReference{ID: "child_grant", OwnerHubID: "hub", Revision: 3}, SubjectInstanceID: "child", Scope: scope,
		Actions: []string{"read"}, ResourceIDs: []string{"record"}, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), PolicyRef: policyRef}
	access := CapabilityAccess{Action: "read", ResourceClass: "storage", ResourceID: "record"}
	in := CapabilityEvaluation{Manifest: validated, Relationship: "independent", InstanceID: "child", Grant: grant, Now: now,
		Policy: CapabilityPolicy{Reference: policyRef, SubjectInstanceID: "child", Scope: scope, IssuedAt: grant.IssuedAt, ExpiresAt: grant.ExpiresAt, Decisions: []CapabilityPolicyDecision{{Access: access, Outcome: "allow"}}}}
	if private {
		parent := grant
		parent.Reference.ID, parent.SubjectInstanceID = "parent_grant", "parent"
		parent.Actions, parent.ResourceIDs = []string{"read", "write"}, []string{"record", "other"}
		in.Relationship, in.ParentInstanceID, in.Parent, in.Grant.ParentGrantRef = "private", "parent", &parent, &parent.Reference
		in.ParentAccess = []CapabilityAccess{access}
	}
	return in
}

func TestCapabilityGrantIntersection(t *testing.T) {
	for _, private := range []bool{false, true} {
		in := capabilityFixture(t, private)
		result, err := EvaluateCapabilityGrant(in)
		if err != nil || !slices.Equal(result.Access(), []CapabilityAccess{{Action: "read", ResourceClass: "storage", ResourceID: "record"}}) {
			t.Fatalf("valid access refused: %v", err)
		}
		copy := result.Access()
		copy[0].ResourceID = "changed"
		in.Policy.Decisions[0].Access.ResourceID = "changed"
		in.Grant.ResourceIDs[0] = "changed"
		if result.Access()[0].ResourceID != "record" {
			t.Fatal("result retained mutable input or output")
		}
	}
}

func TestCapabilityGrantRefusesWideningAndStaleAuthority(t *testing.T) {
	cases := map[string]func(*CapabilityEvaluation){
		"malformed-grant-ref":        func(in *CapabilityEvaluation) { in.Grant.Reference.ID = "*" },
		"invalid-grant-revision":     func(in *CapabilityEvaluation) { in.Grant.Reference.Revision = maxGeneration + 1 },
		"invalid-policy-revision":    func(in *CapabilityEvaluation) { in.Policy.Reference.Revision = maxGeneration + 1 },
		"invalid-parent-tuple":       func(in *CapabilityEvaluation) { in.ParentAccess[0].ResourceID = "*" },
		"parent-tuple-outside-grant": func(in *CapabilityEvaluation) { in.ParentAccess[0].ResourceID = "extra" },
		"parent-ref-missing":         func(in *CapabilityEvaluation) { in.Grant.ParentGrantRef = nil },
		"organization":               func(in *CapabilityEvaluation) { in.Grant.Scope.OrganizationID = "other" },
		"project":                    func(in *CapabilityEvaluation) { in.Grant.Scope.ProjectID = "other" },
		"absent-project":             func(in *CapabilityEvaluation) { in.Grant.Scope.ProjectID = "" },
		"workspace":                  func(in *CapabilityEvaluation) { in.Grant.Scope.WorkspaceID = "other" },
		"absent-workspace":           func(in *CapabilityEvaluation) { in.Grant.Scope.WorkspaceID = "" },
		"action":                     func(in *CapabilityEvaluation) { in.Grant.Actions = append(in.Grant.Actions, "delete") },
		"resource":                   func(in *CapabilityEvaluation) { in.Grant.ResourceIDs = append(in.Grant.ResourceIDs, "extra") },
		"early-issue":                func(in *CapabilityEvaluation) { in.Grant.IssuedAt = in.Parent.IssuedAt.Add(-time.Second) },
		"late-expiry":                func(in *CapabilityEvaluation) { in.Grant.ExpiresAt = in.Parent.ExpiresAt.Add(time.Second) },
		"parent-revision": func(in *CapabilityEvaluation) {
			r := *in.Grant.ParentGrantRef
			r.Revision++
			in.Grant.ParentGrantRef = &r
		},
		"parent-issuer":      func(in *CapabilityEvaluation) { in.Grant.Reference.OwnerHubID = "other" },
		"parent-missing":     func(in *CapabilityEvaluation) { in.Parent = nil },
		"parent-instance":    func(in *CapabilityEvaluation) { in.ParentInstanceID = "other" },
		"child-instance":     func(in *CapabilityEvaluation) { in.InstanceID = "other" },
		"grant-expired":      func(in *CapabilityEvaluation) { in.Grant.ExpiresAt = in.Now },
		"parent-expired":     func(in *CapabilityEvaluation) { in.Parent.ExpiresAt = in.Now },
		"future-grant":       func(in *CapabilityEvaluation) { in.Grant.IssuedAt = in.Now.Add(time.Second) },
		"policy-expired":     func(in *CapabilityEvaluation) { in.Policy.ExpiresAt = in.Now },
		"policy-revision":    func(in *CapabilityEvaluation) { in.Policy.Reference.Revision++ },
		"policy-instance":    func(in *CapabilityEvaluation) { in.Policy.SubjectInstanceID = "other" },
		"policy-scope":       func(in *CapabilityEvaluation) { in.Policy.Scope.ProjectID = "other" },
		"unknown-policy":     func(in *CapabilityEvaluation) { in.Policy.Decisions[0].Outcome = "unknown" },
		"no-policy":          func(in *CapabilityEvaluation) { in.Policy = CapabilityPolicy{} },
		"no-manifest":        func(in *CapabilityEvaluation) { in.Manifest = ValidatedManifest{} },
		"no-relationship":    func(in *CapabilityEvaluation) { in.Relationship = "" },
		"no-clock":           func(in *CapabilityEvaluation) { in.Now = time.Time{} },
		"too-many-resources": func(in *CapabilityEvaluation) { in.Grant.ResourceIDs = make([]string, capabilityLimit+1) },
		"too-many-policy-decisions": func(in *CapabilityEvaluation) {
			in.Policy.Decisions = make([]CapabilityPolicyDecision, capabilityLimit+1)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			in := capabilityFixture(t, true)
			change(&in)
			result, err := EvaluateCapabilityGrant(in)
			if err == nil || len(result.Access()) != 0 || !result.ExpiresAt().IsZero() {
				t.Fatal("invalid authority returned access")
			}
		})
	}
}

func TestCapabilityGrantDenyAndApprovalPrecedence(t *testing.T) {
	for _, outcome := range []string{"deny", "approval_required"} {
		for _, first := range []bool{false, true} {
			in := capabilityFixture(t, false)
			refusal := in.Policy.Decisions[0]
			refusal.Outcome = outcome
			if first {
				in.Policy.Decisions = append([]CapabilityPolicyDecision{refusal}, in.Policy.Decisions...)
			} else {
				in.Policy.Decisions = append(in.Policy.Decisions, refusal)
			}
			if _, err := EvaluateCapabilityGrant(in); err == nil {
				t.Fatal("required access bypassed refusal")
			}
		}
	}
}

func TestCapabilityGrantDoesNotInventAccess(t *testing.T) {
	cases := map[string]func(*CapabilityEvaluation){
		"empty-resources":        func(in *CapabilityEvaluation) { in.Grant.ResourceIDs = nil },
		"wrong-class":            func(in *CapabilityEvaluation) { in.Policy.Decisions[0].Access.ResourceClass = "secret" },
		"wrong-action":           func(in *CapabilityEvaluation) { in.Policy.Decisions[0].Access.Action = "write" },
		"wrong-resource":         func(in *CapabilityEvaluation) { in.Policy.Decisions[0].Access.ResourceID = "other" },
		"missing-policy":         func(in *CapabilityEvaluation) { in.Policy.Decisions = nil },
		"missing-parent-access":  func(in *CapabilityEvaluation) { in.ParentAccess = nil },
		"different-parent-class": func(in *CapabilityEvaluation) { in.ParentAccess[0].ResourceClass = "secret" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			in := capabilityFixture(t, true)
			change(&in)
			if _, err := EvaluateCapabilityGrant(in); err == nil {
				t.Fatal("invented required access")
			}
		})
	}
	in := capabilityFixture(t, false)
	m := in.Manifest.Manifest()
	m.RequestedCapabilities[0].Required = false
	in.Manifest, _ = ValidateManifest(manifestBytes(t, m))
	in.Grant.ResourceIDs = nil
	result, err := EvaluateCapabilityGrant(in)
	if err != nil || len(result.Access()) != 0 {
		t.Fatal("empty optional intersection must grant nothing")
	}
}

func TestCapabilityGrantPreservesTuplesAndLifetime(t *testing.T) {
	in := capabilityFixture(t, false)
	m := in.Manifest.Manifest()
	m.RequestedCapabilities = append(m.RequestedCapabilities, Capability{Action: "write", ResourceClass: "artifact"})
	in.Manifest, _ = ValidateManifest(manifestBytes(t, m))
	in.Grant.Actions = append(in.Grant.Actions, "write")
	in.Grant.ResourceIDs = append(in.Grant.ResourceIDs, "artifact_id")
	in.Policy.Decisions = append(in.Policy.Decisions, CapabilityPolicyDecision{Access: CapabilityAccess{Action: "write", ResourceClass: "artifact", ResourceID: "artifact_id"}, Outcome: "allow"})
	in.Policy.ExpiresAt = in.Now.Add(time.Minute)
	result, err := EvaluateCapabilityGrant(in)
	if err != nil || len(result.Access()) != 2 || !result.ExpiresAt().Equal(in.Policy.ExpiresAt) {
		t.Fatal("intersection or lifetime changed")
	}
	for _, a := range result.Access() {
		if a.Action == "write" && a.ResourceID == "record" {
			t.Fatal("permissions combined across tuples")
		}
	}
}

func TestCapabilityGrantIndependentHasNoParentAuthority(t *testing.T) {
	in := capabilityFixture(t, true)
	in.Relationship = "independent"
	if _, err := EvaluateCapabilityGrant(in); err == nil {
		t.Fatal("independent instance inherited parent authority")
	}
	in = capabilityFixture(t, false)
	in.Grant.Scope.ProjectID = ""
	in.Policy.Scope.ProjectID = ""
	if _, err := EvaluateCapabilityGrant(in); err != nil {
		t.Fatal("matching absent scope dimensions refused")
	}
}

func TestCapabilityGrantSafeDiagnostics(t *testing.T) {
	in := capabilityFixture(t, false)
	in.Policy.Decisions[0].Outcome = "secret-private-marker"
	_, err := EvaluateCapabilityGrant(in)
	if err == nil || err.Error() != "capability_policy_unavailable" {
		t.Fatal("unsafe diagnostic")
	}
	for _, value := range []any{in, in.Grant, in.Policy, CapabilityIntersection{access: []CapabilityAccess{{ResourceID: "secret-private-marker"}}}} {
		raw, e := json.Marshal(value)
		if e != nil || strings.Contains(string(raw), "secret-private-marker") || strings.Contains(fmt.Sprintf("%+v %#v", value, value), "secret-private-marker") {
			t.Fatal("private evaluation data leaked")
		}
	}
}

func TestCapabilityGrantOptionalDenialPreservesRequiredAccess(t *testing.T) {
	in := capabilityFixture(t, false)
	manifest := in.Manifest.Manifest()
	manifest.RequestedCapabilities = append(manifest.RequestedCapabilities, Capability{Action: "read", ResourceClass: "secret"})
	var err error
	in.Manifest, err = ValidateManifest(manifestBytes(t, manifest))
	if err != nil {
		t.Fatal(err)
	}
	in.Policy.Decisions = append(in.Policy.Decisions, CapabilityPolicyDecision{Access: CapabilityAccess{Action: "read", ResourceClass: "secret", ResourceID: "record"}, Outcome: "deny"})
	result, err := EvaluateCapabilityGrant(in)
	if err != nil || len(result.Access()) != 1 || result.Access()[0].ResourceClass != "storage" {
		t.Fatal("optional denial changed required storage access")
	}
}
