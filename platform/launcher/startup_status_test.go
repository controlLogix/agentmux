//go:build linux || darwin

package launcher

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

func ownerStatusFixture(t *testing.T) (OwnerPolicy, Profile) {
	t.Helper()
	policy, p := profileFixture(t)
	p.OrganizationID = "fixture_org"
	project := "fixture_project"
	p.ProjectID = project
	scope := protocol.Scope{HubID: "fixture_hub", InstanceID: p.InstanceID, ProfileID: p.ProfileID, AssemblyDigest: "sha256:" + strings.Repeat("b", 64), ReleaseManifestDigest: p.ReleaseFingerprint, ReleaseVersion: "1.0.0"}
	e := OwnerEnrollment{SchemaVersion: "1.0.0", OwnerUID: policy.OwnerUID, PrincipalID: "fixture_owner", Identity: OwnerIdentityReference{ID: "fixture_owner_record", OwnerHubID: scope.HubID, Revision: 1}, Scope: OwnerScope{OrganizationID: p.OrganizationID, ProjectID: &project}, InstanceID: p.InstanceID, ProfileID: p.ProfileID, ReleaseFingerprint: p.ReleaseFingerprint}
	ownerPolicy := OwnerPolicy{Profile: policy, Enrollment: e, KernelScope: scope, ServerName: "fixture_server", Domain: "fixture_domain", PublicEndpoint: p.NATSEndpoint, PublicContextName: p.Docker.Context}
	if err := EnrollProfile(policy, p); err != nil {
		t.Fatal("explicit fixture profile enrollment failed")
	}
	writeOwnerFixture(t, policy.Directory, mustStatusJSON(e))
	return ownerPolicy, p
}
func writeOwnerFixture(t *testing.T, dir string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "status-owner.json"), raw, 0600); err != nil {
		t.Fatal("private owner fixture write failed")
	}
}
func ownerObservationFixture(policy OwnerPolicy, p Profile, disposition string) ownerStatusObservation {
	now := time.Now().UTC()
	members := []protocol.Member{}
	for _, role := range protocol.Roles() {
		members = append(members, protocol.Member{Role: role, State: "ready", Incarnation: strings.Repeat("a", 32), Revision: 1, ObservedAt: now.Format(time.RFC3339Nano)})
	}
	snapshot := protocol.Snapshot{SchemaVersion: protocol.Version, Kind: "kernel-info", Scope: policy.KernelScope, Role: "exported-status", Incarnation: strings.Repeat("a", 32), Revision: 1, ObservedAt: now.Format(time.RFC3339Nano), ValidUntil: now.Add(3 * time.Second).Format(time.RFC3339Nano), KernelReadiness: "ready", Members: members}
	persistence := deployment.Observation{ServerName: policy.ServerName, ServerVersion: "2.15.0", Domain: policy.Domain, Stream: deployment.HealthStream(policy.KernelScope.HubID), BrokerVerified: true, PersistenceEvidence: deployment.PersistenceRecordSeen, RecordSequence: 1, RecordObservedAt: now.Add(-time.Hour).Format(time.RFC3339Nano), RecordDigest: "sha256:" + strings.Repeat("c", 64)}
	return ownerStatusObservation{status: BootstrapStatus{Disposition: disposition, Profile: (LoadedProfile{p}).Summary(), Kernel: snapshot, Persistence: persistence}, receivedAt: now, attemptID: "attempt_fixture"}
}

func TestOwnerStatusActualEnrollmentAndSameStartReuseSemantics(t *testing.T) {
	policy, p := ownerStatusFixture(t)
	owner, err := LoadOwnerStatus(policy)
	if err != nil {
		t.Fatal("actual private owner enrollment rejected")
	}
	results := []StartupStatusObservation{}
	for _, disposition := range []string{"started", "reused"} {
		result, err := owner.mapObservation(ownerObservationFixture(policy, p, disposition))
		if err != nil || result.Disposition != disposition || result.Instance.Readiness != "degraded" || result.Persistence.Availability != "available" || result.Persistence.Readiness != "unknown" {
			t.Fatal("read-only evidence became write or application readiness")
		}
		if result.Caller.PrincipalID != policy.Enrollment.PrincipalID || !reflect.DeepEqual(result.Caller.Scope, policy.Enrollment.Scope) || result.Caller.Identity != policy.Enrollment.Identity {
			t.Fatal("authenticated enrollment identity changed")
		}
		if result.Work.State != "unavailable" || result.Work.Active != nil || result.Work.Projects != nil || result.Work.Reserved != nil || result.Work.SourceCursor != nil || result.Work.ObservedAt != nil || result.Hubs.InventoryState != "unavailable" || len(result.Hubs.Entries) != 0 {
			t.Fatal("unsupported inventory was reported as observed empty or zero")
		}
		if result.Persistence.StoragePressure.PercentUsed != nil || result.Persistence.ReplicationHealth.Replicas != nil {
			t.Fatal("unsupported pressure or replication invented")
		}
		if len(result.Errors) != 1 || result.Errors[0].Code != "write_readiness_unobserved" {
			t.Fatal("pending cold write proof not explicit")
		}
		if _, err := time.Parse("2006-01-02T15:04:05.999999Z", result.ObservedAt); err != nil {
			t.Fatal("output timestamp format invalid")
		}
		for _, service := range result.Instance.Services {
			if service.ObservedAt != nil {
				parts := strings.Split(strings.TrimSuffix(*service.ObservedAt, "Z"), ".")
				if !strings.HasSuffix(*service.ObservedAt, "Z") || len(parts) > 1 && len(parts[1]) > 6 {
					t.Fatal("service timestamp exceeds six fractional digits")
				}
			}
		}
		public := mustStatusJSON(result)
		for _, private := range []string{policy.Profile.Directory, p.CredentialRef, p.Docker.Executable, p.Docker.Endpoint, p.Docker.EngineID, "fixture-private-password"} {
			if bytes.Contains(public, []byte(private)) {
				t.Fatal("private machine or credential data disclosed")
			}
		}
		results = append(results, result)
	}
	if results[1].SourceRevision != results[0].SourceRevision+1 || results[1].ObservationID == results[0].ObservationID {
		t.Fatal("observation cursor did not advance")
	}
	// Compare the stable field semantics, excluding actual observation metadata.
	left, right := results[0], results[1]
	left.ObservationID, right.ObservationID = "", ""
	left.ObservedAt, right.ObservedAt = "", ""
	left.SourceRevision, right.SourceRevision = 0, 0
	left.Disposition, right.Disposition = "", ""
	left.Persistence.ObservedAt, right.Persistence.ObservedAt = nil, nil
	for i := range left.Instance.Services {
		left.Instance.Services[i].ObservedAt = nil
		right.Instance.Services[i].ObservedAt = nil
	}
	if !reflect.DeepEqual(left, right) {
		t.Fatal("start and reuse field semantics differ")
	}
	// Mutable caller policy pointers cannot change the retained enrolled scope.
	*policy.Enrollment.Scope.ProjectID = "other_project"
	if *owner.policy.Enrollment.Scope.ProjectID != "fixture_project" {
		t.Fatal("caller pointer changed retained owner authority")
	}
}

func TestOwnerStatusEnrollmentDenialsOnRealFiles(t *testing.T) {
	for _, kind := range []string{"missing-owner", "owner-uid-policy", "scope-policy", "release-policy", "scope-file", "identity-file", "revision-file", "top-alias", "nested-alias", "duplicate", "missing-null-field", "unknown-field", "mode", "symlink", "hardlink", "oversize", "profile-scope", "profile-endpoint"} {
		t.Run(kind, func(t *testing.T) {
			policy, p := ownerStatusFixture(t)
			path := filepath.Join(policy.Profile.Directory, "status-owner.json")
			raw := mustStatusJSON(policy.Enrollment)
			expected := "owner_status_enrollment_invalid"
			var editErr error
			switch kind {
			case "missing-owner":
				editErr = os.Remove(path)
				expected = "owner_status_owner_unconfigured"
			case "owner-uid-policy":
				policy.Profile.OwnerUID++
				policy.Enrollment.OwnerUID++
				expected = "owner_status_owner_forbidden"
			case "scope-policy":
				policy.Enrollment.Scope.OrganizationID = "other_org"
			case "release-policy":
				policy.Profile.InstalledReleaseFingerprint = "sha256:" + strings.Repeat("d", 64)
				expected = "owner_status_policy_invalid"
			case "scope-file":
				e := policy.Enrollment
				e.Scope.OrganizationID = "other_org"
				raw = mustStatusJSON(e)
			case "identity-file":
				e := policy.Enrollment
				e.Identity.ID = "other_owner"
				raw = mustStatusJSON(e)
			case "revision-file":
				e := policy.Enrollment
				e.Identity.Revision++
				raw = mustStatusJSON(e)
			case "top-alias":
				raw = bytes.Replace(raw, []byte(`"principalId":`), []byte(`"PrincipalId":`), 1)
			case "nested-alias":
				raw = bytes.Replace(raw, []byte(`"organizationId":`), []byte(`"OrganizationId":`), 1)
			case "duplicate":
				raw = append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"principalId":"fixture_owner"}`)...)
			case "missing-null-field":
				raw = bytes.Replace(raw, []byte(`,"workspaceId":null`), nil, 1)
			case "unknown-field":
				raw = append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"authority":"invented"}`)...)
			case "mode":
				editErr = os.Chmod(path, 0644)
			case "symlink":
				if editErr = os.Rename(path, path+".real"); editErr == nil {
					editErr = os.Symlink(path+".real", path)
				}
			case "hardlink":
				editErr = os.Link(path, path+".link")
			case "oversize":
				raw = append(raw, bytes.Repeat([]byte(" "), protocol.MaxPayload)...)
			case "profile-scope":
				p.OrganizationID = "other_org"
				editErr = os.WriteFile(filepath.Join(policy.Profile.Directory, "profile.json"), mustStatusJSON(p), 0600)
				expected = "owner_status_profile_binding_invalid"
			case "profile-endpoint":
				policy.PublicEndpoint = "nats://127.0.0.1:4223"
				expected = "owner_status_profile_binding_invalid"
			}
			if editErr != nil {
				t.Fatal("real denial fixture setup failed")
			}
			if !reflect.DeepEqual(raw, mustStatusJSON(policy.Enrollment)) && kind != "scope-policy" {
				writeOwnerFixture(t, policy.Profile.Directory, raw)
			}
			if owner, err := LoadOwnerStatus(policy); owner != nil || err == nil || err.Error() != expected {
				t.Fatalf("owner denial did not return expected safe code %s", expected)
			}
		})
	}
}

func TestOwnerStatusFreshnessBindingsAndRevocation(t *testing.T) {
	for _, kind := range []string{"receipt-stale", "receipt-future", "attempt-missing", "profile", "release", "kernel-stale", "kernel-not-ready", "persistence-identity", "persistence-configuration-only", "record-invalid", "owner-revoked", "profile-changed"} {
		t.Run(kind, func(t *testing.T) {
			policy, p := ownerStatusFixture(t)
			owner, err := LoadOwnerStatus(policy)
			if err != nil {
				t.Fatal("owner fixture admission failed")
			}
			input := ownerObservationFixture(policy, p, "reused")
			switch kind {
			case "receipt-stale":
				input.receivedAt = input.receivedAt.Add(-4 * time.Second)
			case "receipt-future":
				input.receivedAt = input.receivedAt.Add(time.Second)
			case "attempt-missing":
				input.attemptID = ""
			case "profile":
				input.status.Profile.InstanceID = "other_instance"
			case "release":
				input.status.Kernel.Scope.ReleaseManifestDigest = "sha256:" + strings.Repeat("d", 64)
			case "kernel-stale":
				input.status.Kernel.ObservedAt = time.Now().Add(-4 * time.Second).UTC().Format(time.RFC3339Nano)
			case "kernel-not-ready":
				input.status.Kernel.KernelReadiness = "not_ready"
			case "persistence-identity":
				input.status.Persistence.ServerName = "RAW_UPPERCASE_SERVER_ID"
			case "persistence-configuration-only":
				input.status.Persistence.PersistenceEvidence = deployment.PersistenceConfigSeen
			case "record-invalid":
				input.status.Persistence.RecordObservedAt = "invalid"
			case "owner-revoked":
				if os.Chmod(filepath.Join(policy.Profile.Directory, "status-owner.json"), 0644) != nil {
					t.Fatal("revocation fixture failed")
				}
			case "profile-changed":
				p.DisplayName = "Changed profile"
				if os.WriteFile(filepath.Join(policy.Profile.Directory, "profile.json"), mustStatusJSON(p), 0600) != nil {
					t.Fatal("profile change fixture failed")
				}
			}
			out, err := owner.mapObservation(input)
			if kind == "owner-revoked" || kind == "profile-changed" {
				if err == nil {
					t.Fatal("retained handle ignored revocation or profile change")
				}
				return
			}
			if err != nil {
				t.Fatal("bound observation should return safe failed status")
			}
			if strings.HasPrefix(kind, "persistence-") || kind == "record-invalid" {
				if out.Persistence.Availability != "unavailable" || out.Persistence.ServerID != nil || out.Persistence.DomainID != nil || out.Persistence.Readiness != "unknown" {
					t.Fatal("unverified persistence identity or write claim disclosed")
				}
			} else if out.Disposition != "failed" || out.Instance.Readiness == "ready" || len(out.Errors) == 0 {
				t.Fatal("stale or wrong-scope runtime became current success")
			}
		})
	}
}

func TestOwnerStatusGeneratedContractExamples(t *testing.T) {
	policy, p := ownerStatusFixture(t)
	owner, err := LoadOwnerStatus(policy)
	if err != nil {
		t.Fatal("owner fixture admission failed")
	}
	cases := map[string]StartupStatusObservation{}
	for _, name := range []string{"started", "reused", "failed-stale", "failed-scope", "read-only-no-record"} {
		input := ownerObservationFixture(policy, p, "reused")
		if name == "started" {
			input.status.Disposition = "started"
		}
		if name == "failed-stale" {
			input.receivedAt = time.Now().Add(-4 * time.Second)
		}
		if name == "failed-scope" {
			input.status.Kernel.Scope.HubID = "other_hub"
		}
		if name == "read-only-no-record" {
			input.status.Persistence.PersistenceEvidence = deployment.PersistenceUnknown
		}
		out, err := owner.mapObservation(input)
		if err != nil {
			t.Fatal("fixture status generation failed")
		}
		cases[name] = out
	}
	if os.Remove(filepath.Join(policy.Profile.Directory, "profile.json")) != nil {
		t.Fatal("missing profile fixture failed")
	}
	missing, err := LoadOwnerStatus(policy)
	if err != nil {
		t.Fatal("authenticated owner without runtime profile rejected")
	}
	out, err := missing.mapObservation(ownerStatusObservation{})
	if err != nil || out.Disposition != "unconfigured" || out.Instance.InstanceID != nil {
		t.Fatal("unconfigured owner status fabricated runtime identity")
	}
	cases["unconfigured"] = out
	if output := os.Getenv("AGENTMUX_TEST_STATUS_OUTPUT"); output != "" {
		if !filepath.IsAbs(output) {
			t.Fatal("fixture output must be an absolute external path")
		}
		raw, err := json.MarshalIndent(cases, "", "  ")
		if err != nil || os.WriteFile(output, raw, 0600) != nil {
			t.Fatal("generated fixture output unavailable")
		}
	}
}
