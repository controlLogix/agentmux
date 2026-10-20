//go:build linux || darwin

package launcher

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

type OwnerIdentityReference struct {
	ID         string `json:"id"`
	OwnerHubID string `json:"ownerHubId"`
	Revision   uint64 `json:"revision"`
}

type OwnerScope struct {
	OrganizationID string  `json:"organizationId"`
	ProjectID      *string `json:"projectId"`
	WorkspaceID    *string `json:"workspaceId"`
}

// OwnerEnrollment records an explicitly enrolled local owner. Its organization
// scope does not grant remote, federation or business permissions.
type OwnerEnrollment struct {
	SchemaVersion      string                 `json:"schemaVersion"`
	OwnerUID           uint32                 `json:"ownerUid"`
	PrincipalID        string                 `json:"principalId"`
	Identity           OwnerIdentityReference `json:"authenticatedIdentityRef"`
	Scope              OwnerScope             `json:"scope"`
	InstanceID         string                 `json:"instanceId"`
	ProfileID          string                 `json:"profileId"`
	ReleaseFingerprint string                 `json:"releaseFingerprint"`
}

// OwnerPolicy is supplied by the installed, explicitly enrolled host, never by
// a status request. The expected identity must come from that enrollment, not
// from the status-owner.json record it is used to check. OS identity and private
// file ownership authenticate this local process only; same-UID code is trusted.
type OwnerPolicy struct {
	Profile                           ProfilePolicy
	Enrollment                        OwnerEnrollment
	KernelScope                       protocol.Scope
	ServerName, Domain                string
	PublicEndpoint, PublicContextName string
}

type OwnerStatus struct {
	mu       sync.Mutex
	policy   OwnerPolicy
	profile  *Profile
	revision uint64
}

type StartupStatusCaller struct {
	PrincipalID string                 `json:"principalId"`
	Kind        string                 `json:"kind"`
	Identity    OwnerIdentityReference `json:"authenticatedIdentityRef"`
	Scope       OwnerScope             `json:"scope"`
}
type StartupStatusError struct {
	Component string `json:"component"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}
type StartupStatusService struct {
	ServiceID         string  `json:"serviceId"`
	Availability      string  `json:"availability"`
	UnavailableReason *string `json:"unavailableReason"`
	Readiness         string  `json:"readiness"`
	ObservedAt        *string `json:"observedAt"`
	SourceRevision    *uint64 `json:"sourceRevision"`
}
type StartupStatusInstance struct {
	InstanceID         *string                `json:"instanceId"`
	DisplayName        *string                `json:"displayName"`
	ProfileID          *string                `json:"profileId"`
	InstalledVersion   *string                `json:"installedVersion"`
	RunningVersion     *string                `json:"runningVersion"`
	Mode               string                 `json:"mode"`
	ComposeProject     *string                `json:"composeProject"`
	ContextDisplayName *string                `json:"contextDisplayName"`
	ContextFingerprint *string                `json:"contextFingerprint"`
	Endpoint           *string                `json:"endpoint"`
	Dashboard          *string                `json:"dashboard"`
	Readiness          string                 `json:"readiness"`
	Services           []StartupStatusService `json:"services"`
}
type StartupStoragePressure struct {
	State       string   `json:"state"`
	PercentUsed *float64 `json:"percentUsed"`
}
type StartupReplicationHealth struct {
	State    string  `json:"state"`
	Replicas *uint64 `json:"replicas"`
}
type StartupStatusPersistence struct {
	Availability      string                   `json:"availability"`
	Backend           *string                  `json:"backend"`
	Profile           *string                  `json:"profile"`
	ServerID          *string                  `json:"serverId"`
	DomainID          *string                  `json:"domainId"`
	Readiness         string                   `json:"readiness"`
	StoragePressure   StartupStoragePressure   `json:"storagePressure"`
	ReplicationHealth StartupReplicationHealth `json:"replicationHealth"`
	ObservedAt        *string                  `json:"observedAt"`
}
type StartupStatusWork struct {
	State        string  `json:"state"`
	Active       *uint64 `json:"active"`
	Projects     *uint64 `json:"projects"`
	Reserved     *uint64 `json:"reserved"`
	SourceCursor *uint64 `json:"sourceCursor"`
	ObservedAt   *string `json:"observedAt"`
}

// No hub entry constructor exists in this bounded adapter. Inventory belongs
// to its future authenticated owner; an empty unavailable list is not known empty.
type StartupStatusHubs struct {
	InventoryState string     `json:"inventoryState"`
	Entries        []struct{} `json:"entries"`
}
type StartupStatusObservation struct {
	SchemaVersion    string                   `json:"schemaVersion"`
	ObservationID    string                   `json:"observationId"`
	ObservedAt       string                   `json:"observedAt"`
	SourceRevision   uint64                   `json:"sourceRevision"`
	StartupAttemptID *string                  `json:"startupAttemptId"`
	Disposition      string                   `json:"disposition"`
	Caller           StartupStatusCaller      `json:"caller"`
	Errors           []StartupStatusError     `json:"errors"`
	Instance         StartupStatusInstance    `json:"instance"`
	Persistence      StartupStatusPersistence `json:"persistence"`
	Work             StartupStatusWork        `json:"work"`
	Hubs             StartupStatusHubs        `json:"hubs"`
}

// The bootstrap owner must supply these private observations under its Session
// lock, including the actual attempt and receipt time. They are not request data.
// A completed probe is copied from the owning Session, never from request data.
// The separate write-proof qualifier must check its actual binding and age.
type ownerStatusObservation struct {
	status      BootstrapStatus
	receivedAt  time.Time
	attemptID   string
	healthProof *completedHealthProbe
}

func ownerStatusError(code string) error { return errors.New("owner_status_" + code) }
func statusText(s string, limit int) bool {
	if !utf8.ValidString(s) || len(s) == 0 || len(s) > limit {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func optionalStatusID(p *string) bool { return p == nil || kernelStatusID.MatchString(*p) }
func copyOwnerScope(s OwnerScope) OwnerScope {
	if s.ProjectID != nil {
		v := *s.ProjectID
		s.ProjectID = &v
	}
	if s.WorkspaceID != nil {
		v := *s.WorkspaceID
		s.WorkspaceID = &v
	}
	return s
}

// LoadOwnerStatus never enrolls an identity or creates a profile. A missing
// owner record returns owner_status_owner_unconfigured, not an L04 envelope
// with invented caller fields. A missing runtime profile can be reported only
// after a real local owner enrollment has been authenticated.
func LoadOwnerStatus(policy OwnerPolicy) (*OwnerStatus, error) {
	e := policy.Enrollment
	s := policy.KernelScope
	if uint32(os.Geteuid()) != policy.Profile.OwnerUID || e.OwnerUID != policy.Profile.OwnerUID {
		return nil, ownerStatusError("owner_forbidden")
	}
	if e.SchemaVersion != "1.0.0" || !kernelStatusID.MatchString(e.PrincipalID) || !kernelStatusID.MatchString(e.Identity.ID) || e.Identity.Revision == 0 || e.Identity.Revision > protocol.MaxRevision || e.Identity.OwnerHubID != s.HubID || !kernelStatusID.MatchString(e.Scope.OrganizationID) || !optionalStatusID(e.Scope.ProjectID) || !optionalStatusID(e.Scope.WorkspaceID) || !profileID.MatchString(e.ProfileID) || !profileInstanceID.MatchString(e.InstanceID) || e.ProfileID != s.ProfileID || e.InstanceID != s.InstanceID || e.ReleaseFingerprint != policy.Profile.InstalledReleaseFingerprint || e.ReleaseFingerprint != s.ReleaseManifestDigest || !kernelStatusID.MatchString(s.HubID) || !kernelStatusDigest.MatchString(s.AssemblyDigest) || !kernelStatusDigest.MatchString(s.ReleaseManifestDigest) || !kernelStatusVersion.MatchString(s.ReleaseVersion) || !kernelStatusID.MatchString(policy.ServerName) || !kernelStatusID.MatchString(policy.Domain) || !statusText(policy.PublicContextName, 160) {
		return nil, ownerStatusError("policy_invalid")
	}
	root, err := openProfileDirectory(policy.Profile)
	if err != nil {
		return nil, ownerStatusError("owner_forbidden")
	}
	defer root.Close()
	if _, err := root.Lstat("status-owner.json"); os.IsNotExist(err) {
		return nil, ownerStatusError("owner_unconfigured")
	} else if err != nil {
		return nil, ownerStatusError("enrollment_invalid")
	}
	raw, err := hostPrivateRead(root, "status-owner.json", policy.Profile.OwnerUID, protocol.MaxPayload)
	if err != nil {
		return nil, ownerStatusError("enrollment_invalid")
	}
	var actual OwnerEnrollment
	fields, fieldsErr := releaseFields(raw, "schemaVersion", "ownerUid", "principalId", "authenticatedIdentityRef", "scope", "instanceId", "profileId", "releaseFingerprint")
	if fieldsErr != nil {
		return nil, ownerStatusError("enrollment_invalid")
	}
	_, scopeErr := releaseFields(fields["scope"], "organizationId", "projectId", "workspaceId")
	_, identityErr := releaseFields(fields["authenticatedIdentityRef"], "id", "ownerHubId", "revision")
	if scopeErr != nil || identityErr != nil || protocol.StrictJSON(raw, &actual) != nil || !reflect.DeepEqual(actual, e) {
		return nil, ownerStatusError("enrollment_invalid")
	}
	policy.Enrollment.Scope = copyOwnerScope(e.Scope)
	policy.Profile.WorkspaceRoots = append([]string(nil), policy.Profile.WorkspaceRoots...)
	owner := &OwnerStatus{policy: policy}
	if _, err := root.Lstat("profile.json"); os.IsNotExist(err) {
		return owner, nil
	} else if err != nil {
		return nil, ownerStatusError("profile_invalid")
	}
	loaded, err := LoadProfile(policy.Profile)
	if err != nil {
		return nil, ownerStatusError("profile_invalid")
	}
	p := loaded.Declaration()
	if p.Mode != "local" || p.ProfileID != e.ProfileID || p.InstanceID != e.InstanceID || p.NATSEndpoint != policy.PublicEndpoint || p.OrganizationID != "" && p.OrganizationID != e.Scope.OrganizationID || p.ProjectID != "" && (e.Scope.ProjectID == nil || p.ProjectID != *e.Scope.ProjectID) || p.Docker == nil || p.Docker.Context != policy.PublicContextName {
		return nil, ownerStatusError("profile_binding_invalid")
	}
	owner.profile = &p
	return owner, nil
}

func statusTimestamp(t time.Time) string {
	return t.UTC().Truncate(time.Microsecond).Format("2006-01-02T15:04:05.999999Z")
}
func statusString(v string) *string   { return &v }
func statusRevision(v uint64) *uint64 { return &v }
func unknownStatusService(id, reason string) StartupStatusService {
	return StartupStatusService{ServiceID: id, Availability: "unavailable", UnavailableReason: statusString(reason), Readiness: "unknown"}
}

// mapStartingContext reports only an actual admitted, still-running bootstrap
// call held by the enrolled service owner. Its attempt is not a request ID.
func (owner *OwnerStatus) mapStartingContext(ctx context.Context, operation *bootstrapOperation) (StartupStatusObservation, error) {
	if ctx == nil {
		return StartupStatusObservation{}, ownerStatusError("context_invalid")
	}
	ctx, cancel := context.WithTimeout(ctx, ownerObservationLimit)
	defer cancel()
	if err := operation.pending(owner); err != nil {
		return StartupStatusObservation{}, err
	}
	if err := lockOwnerObservation(ctx, &owner.mu); err != nil {
		return StartupStatusObservation{}, err
	}
	defer owner.mu.Unlock()
	out, err := owner.newObservationLocked()
	if err != nil {
		return StartupStatusObservation{}, err
	}
	if ctx.Err() != nil {
		return StartupStatusObservation{}, observationContextError(ctx)
	}
	// Enrollment checks may take time. Completion or cancellation during those
	// checks invalidates this result instead of creating a late pending reply.
	if err := operation.pending(owner); err != nil {
		return StartupStatusObservation{}, err
	}
	if ctx.Err() != nil {
		return StartupStatusObservation{}, observationContextError(ctx)
	}
	out.Disposition = "starting"
	out.StartupAttemptID = statusString(operation.attemptID)
	out.Instance.Readiness = "not_ready"
	for _, role := range protocol.Roles() {
		out.Instance.Services = append(out.Instance.Services, unknownStatusService(role, "unknown"))
	}
	out.Instance.Services = append(out.Instance.Services, unknownStatusService("work", "not_implemented"), unknownStatusService("hub_federation", "not_implemented"))
	return out, nil
}

func (owner *OwnerStatus) mapObservation(input ownerStatusObservation) (StartupStatusObservation, error) {
	return owner.mapObservationContext(context.Background(), input)
}

func (owner *OwnerStatus) mapObservationContext(ctx context.Context, input ownerStatusObservation) (StartupStatusObservation, error) {
	if ctx == nil {
		return StartupStatusObservation{}, ownerStatusError("context_invalid")
	}
	ctx, cancel := context.WithTimeout(ctx, ownerObservationLimit)
	defer cancel()
	if owner == nil {
		return StartupStatusObservation{}, ownerStatusError("owner_unconfigured")
	}
	if err := lockOwnerObservation(ctx, &owner.mu); err != nil {
		return StartupStatusObservation{}, err
	}
	defer owner.mu.Unlock()
	out, err := owner.mapObservationLocked(input)
	if ctx.Err() != nil {
		return StartupStatusObservation{}, observationContextError(ctx)
	}
	return out, err
}

// The caller holds owner.mu. File checks stay synchronous; the context-aware
// caller rejects a result that completes after its deadline. No syscall or
// cleanup goroutine is left running in the background.
func (owner *OwnerStatus) newObservationLocked() (StartupStatusObservation, error) {
	if uint32(os.Geteuid()) != owner.policy.Profile.OwnerUID {
		return StartupStatusObservation{}, ownerStatusError("owner_forbidden")
	}
	current, err := LoadOwnerStatus(owner.policy)
	if err != nil {
		return StartupStatusObservation{}, err
	}
	if !reflect.DeepEqual(current.profile, owner.profile) {
		return StartupStatusObservation{}, ownerStatusError("profile_changed")
	}
	if owner.revision >= protocol.MaxRevision {
		return StartupStatusObservation{}, ownerStatusError("revision_exhausted")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return StartupStatusObservation{}, ownerStatusError("observation_failed")
	}
	now := time.Now().UTC()
	owner.revision++
	e := owner.policy.Enrollment
	out := StartupStatusObservation{SchemaVersion: "1.0.0", ObservationID: "observation_" + hex.EncodeToString(nonce[:]), ObservedAt: statusTimestamp(now), SourceRevision: owner.revision, Disposition: "unconfigured", Caller: StartupStatusCaller{PrincipalID: e.PrincipalID, Kind: "human", Identity: e.Identity, Scope: copyOwnerScope(e.Scope)}, Errors: []StartupStatusError{}, Instance: StartupStatusInstance{Mode: "unknown", Readiness: "unknown", Services: []StartupStatusService{}}, Persistence: StartupStatusPersistence{Availability: "unavailable", Readiness: "unknown", StoragePressure: StartupStoragePressure{State: "unknown"}, ReplicationHealth: StartupReplicationHealth{State: "unknown"}}, Work: StartupStatusWork{State: "unavailable"}, Hubs: StartupStatusHubs{InventoryState: "unavailable", Entries: []struct{}{}}}
	addError := func(component, code, message string, retry bool) {
		out.Errors = append(out.Errors, StartupStatusError{component, code, message, retry})
	}
	if owner.profile == nil {
		addError("startup", "profile_unconfigured", "The local runtime profile is not configured.", false)
		return out, nil
	}
	p := *owner.profile
	out.Instance = StartupStatusInstance{InstanceID: statusString(p.InstanceID), DisplayName: statusString(p.DisplayName), ProfileID: statusString(p.ProfileID), InstalledVersion: statusString(owner.policy.KernelScope.ReleaseVersion), Mode: "local", ComposeProject: statusString(p.ComposeProject), ContextDisplayName: statusString(owner.policy.PublicContextName), Endpoint: statusString(owner.policy.PublicEndpoint), Readiness: "unknown", Services: []StartupStatusService{}}
	selection := struct{ Context, Endpoint, EngineID string }{p.Docker.Context, p.Docker.Endpoint, p.Docker.EngineID}
	encoded, _ := json.Marshal(selection)
	fingerprint := sha256.Sum256(encoded)
	out.Instance.ContextFingerprint = statusString("sha256:" + hex.EncodeToString(fingerprint[:]))
	out.Disposition = "failed"
	return out, nil
}

func (owner *OwnerStatus) mapObservationLocked(input ownerStatusObservation) (StartupStatusObservation, error) {
	out, err := owner.newObservationLocked()
	if err != nil || owner.profile == nil {
		return out, err
	}
	now := time.Now().UTC()
	p := *owner.profile
	addError := func(component, code, message string, retry bool) {
		out.Errors = append(out.Errors, StartupStatusError{component, code, message, retry})
	}
	if !kernelStatusID.MatchString(input.attemptID) || input.receivedAt.IsZero() || input.receivedAt.After(now) || now.Sub(input.receivedAt) > 3*time.Second {
		addError("startup", "observation_unavailable", "A current startup observation is unavailable.", true)
		return out, nil
	}
	out.StartupAttemptID = statusString(input.attemptID)
	if input.status.Profile != (LoadedProfile{p}).Summary() {
		addError("instance", "profile_mismatch", "The runtime observation does not match the enrolled profile.", false)
		return out, nil
	}
	persist := input.status.Persistence
	recordAt, recordTimeErr := time.Parse(time.RFC3339Nano, persist.RecordObservedAt)
	if persist.BrokerVerified && persist.ServerName == owner.policy.ServerName && persist.Domain == owner.policy.Domain && persist.ServerVersion == "2.15.0" && persist.Stream == deployment.HealthStream(owner.policy.KernelScope.HubID) && persist.PersistenceEvidence == deployment.PersistenceRecordSeen && persist.RecordSequence > 0 && kernelStatusDigest.MatchString(persist.RecordDigest) && recordTimeErr == nil && !recordAt.After(now) {
		out.Persistence.Availability = "available"
		out.Persistence.Backend = statusString("nats_jetstream")
		out.Persistence.Profile = statusString(p.ProfileID)
		out.Persistence.ServerID = statusString(persist.ServerName)
		out.Persistence.DomainID = statusString(persist.Domain)
		out.Persistence.ObservedAt = statusString(statusTimestamp(input.receivedAt))
	}
	k := input.status.Kernel
	if _, err := protocol.DecodeSnapshot(mustStatusJSON(k), owner.policy.KernelScope, now, 3*time.Second); err != nil {
		addError("instance", "kernel_observation_invalid", "A current protected runtime observation is unavailable.", true)
		return out, nil
	}
	out.Instance.RunningVersion = statusString(k.Scope.ReleaseVersion)
	for _, member := range k.Members {
		service := unknownStatusService(member.Role, "unknown")
		if member.State != "unknown" && member.State != "stale" {
			at, err := time.Parse(time.RFC3339Nano, member.ObservedAt)
			if err == nil && !at.After(now) && now.Sub(at) <= 3*time.Second {
				readiness := "not_ready"
				if member.State == "ready" {
					readiness = "ready"
				} else if member.State == "degraded" {
					readiness = "degraded"
				}
				service = StartupStatusService{ServiceID: member.Role, Availability: "available", Readiness: readiness, ObservedAt: statusString(statusTimestamp(at)), SourceRevision: statusRevision(member.Revision)}
			}
		}
		out.Instance.Services = append(out.Instance.Services, service)
	}
	writeReady := false
	// Write readiness still requires a valid scoped kernel frame and this
	// session's qualified cold-start proof; a stored record alone is read-only.
	if input.status.Disposition == "started" && input.healthProof != nil {
		writeReady = qualifyWriteProof(owner.policy, input, &out, now)
	}
	out.Instance.Services = append(out.Instance.Services, unknownStatusService("work", "not_implemented"), unknownStatusService("hub_federation", "not_implemented"))
	if (input.status.Disposition == "started" || input.status.Disposition == "reused") && (k.KernelReadiness == "ready" || k.KernelReadiness == "degraded") {
		out.Disposition = input.status.Disposition
		// Protected-role and write-probe observations do not prove the surrounding
		// business services. Overall readiness stays degraded until those exist.
		out.Instance.Readiness = "degraded"
		if !writeReady {
			addError("persistence", "write_readiness_unobserved", "Current persistence write readiness has not been observed.", true)
		}
	} else {
		addError("instance", "runtime_not_ready", "The protected runtime is not ready.", true)
	}
	return out, nil
}

func mustStatusJSON(value any) []byte { raw, _ := json.Marshal(value); return raw }
