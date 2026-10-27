//go:build linux || darwin

package launcher

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

// OwnerProfilePreparationRequest supplies approved declarations. Display context
// never supplies an identity, authorization projectId, release pin or Docker default.
// Repositories share these explicit profile and instance IDs.
type OwnerProfilePreparationRequest struct {
	CoreHub                                        *CoreHubSelection
	Owner                                          OwnerEnrollment
	Context                                        CentralProfileContext
	ClientInstallationID                           string
	ApprovedWorkspaceRoots                         []string
	Release                                        ReleasePolicy
	RuntimeExecutablePath, RuntimeExecutableDigest string
	Docker                                         ProfileDocker
	HostPort                                       int
	ComposeProject, ServerName, Domain             string
	MaxMemoryBytes, MaxFileBytes                   int64
	StartupTimeout, ProbeTimeout                   time.Duration
	Deadlines                                      protected.Deadlines
}

func (OwnerProfilePreparationRequest) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "[private owner profile preparation request]")
}
func (OwnerProfilePreparationRequest) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-owner-profile-preparation-request"}`), nil
}

type ownerProfileAccount struct {
	home, name string
	uid        uint32
}
type ownerProfileDependencies struct {
	account func() (ownerProfileAccount, error)
	central centralProfileDependencies
	// Tests inject a failed durability boundary; production always uses File.Sync.
	syncDirectory func(*ownerProfilePreparationDirectory) error
	openDirectory func(int, string) (int, error)
}

func ownerProfileProduction() ownerProfileDependencies {
	return ownerProfileDependencies{account: func() (ownerProfileAccount, error) {
		home, uid, err := centralProfileAccount()
		if err != nil {
			return ownerProfileAccount{}, err
		}
		account, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
		if err != nil || account.HomeDir != home || account.Uid != strconv.FormatUint(uint64(uid), 10) {
			return ownerProfileAccount{}, centralProfileError("account_unavailable")
		}
		name := strings.TrimSpace(strings.SplitN(account.Name, ",", 2)[0])
		if name == "" {
			name = account.Username
		}
		return ownerProfileAccount{home, name, uid}, nil
	}, central: centralProfileProduction(), syncDirectory: func(d *ownerProfilePreparationDirectory) error { return d.entry.file.Sync() }, openDirectory: openOwnerProfileChild}
}

// OwnerProfilePreparation retains every original filesystem and image owner.
// A non-nil result accompanying an error must be retained through recovery and
// closed by its caller. Close releases handles; it never deletes partial setup.
// Recovery after process exit requires an explicit RecoverOwnerProfile call.
type OwnerProfilePreparation struct {
	mu                        sync.Mutex
	files                     *CentralProfileResolution
	registration              *CentralProfileResolution
	deps                      ownerProfileDependencies
	account                   ownerProfileAccount
	request                   OwnerProfilePreparationRequest
	mutated, prepared, closed bool
	closeErr                  error
	retainedFailure           error
	stages                    []ownerProfilePreparationStage
}

func (*OwnerProfilePreparation) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "[private owner profile preparation]")
}
func (*OwnerProfilePreparation) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-owner-profile-preparation"}`), nil
}

// PrepareOwnerProfile creates one new central profile. It does not alter an
// existing profile, repository reference or client setting, pull an image, or
// start a broker. Registration confirms declarations, not application readiness.
func PrepareOwnerProfile(ctx context.Context, request OwnerProfilePreparationRequest) (*OwnerProfilePreparation, error) {
	return prepareOwnerProfile(ctx, request, ownerProfileProduction())
}

// RecoverOwnerProfile validates retained preparation against the approved
// request. It never replaces files or generates credentials. Missing credential
// material and ambiguous partial publications require inspection.
func RecoverOwnerProfile(ctx context.Context, request OwnerProfilePreparationRequest) (*OwnerProfilePreparation, error) {
	return prepareOwnerProfileMode(ctx, request, ownerProfileProduction(), true)
}

func ownerProfileDisplayName(name string, c CentralProfileContext) (string, error) {
	if !c.valid() || !statusText(name, 128) || strings.TrimSpace(name) != name {
		return "", centralProfileError("display_context_invalid")
	}
	parts := []string{name}
	if c.Project != nil {
		parts = append(parts, *c.Project)
	}
	if c.Environment != nil {
		parts = append(parts, *c.Environment)
	}
	label := strings.Join(parts, " - ")
	if !statusText(label, 128) || strings.ContainsAny(label, "\u2028\u2029") {
		return "", centralProfileError("display_context_invalid")
	}
	return label, nil
}

func prepareOwnerProfile(parent context.Context, request OwnerProfilePreparationRequest, deps ownerProfileDependencies) (*OwnerProfilePreparation, error) {
	return prepareOwnerProfileMode(parent, request, deps, false)
}

func prepareOwnerProfileMode(parent context.Context, request OwnerProfilePreparationRequest, deps ownerProfileDependencies, recover bool) (*OwnerProfilePreparation, error) {
	if parent == nil || parent.Err() != nil || !request.Context.valid() || !centralRootsValid(request.ApprovedWorkspaceRoots) || !protected.ValidClientInstallationID(request.ClientInstallationID) || !releaseHostPath(request.RuntimeExecutablePath, request.Release.PackageDirectory) {
		return nil, centralProfileError("preparation_invalid")
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	account, err := deps.account()
	if err != nil {
		return nil, centralProfileError("account_unavailable")
	}
	label, err := ownerProfileDisplayName(account.name, request.Context)
	if err != nil {
		return nil, err
	}
	if request.CoreHub != nil {
		core := *request.CoreHub
		if !centralSelectionPath(core.Selection, request.ApprovedWorkspaceRoots) || !digest.MatchString(core.SHA256) {
			return nil, centralProfileError("core_selection_invalid")
		}
		request.CoreHub = &core
	}
	request.Context = request.Context.clone()
	request.Owner.Scope = copyOwnerScope(request.Owner.Scope)
	request.ApprovedWorkspaceRoots = append([]string(nil), request.ApprovedWorkspaceRoots...)
	request.Release.PublicKey = append([]byte(nil), request.Release.PublicKey...)
	directory := filepath.Join(account.home, "Library", "Application Support", "Agentmux", "profiles", request.Owner.ProfileID)
	if !filepath.IsAbs(account.home) || filepath.Clean(account.home) != account.home || !profileID.MatchString(request.Owner.ProfileID) || !profileInstanceID.MatchString(request.Owner.InstanceID) || request.Owner.OwnerUID != account.uid || request.Owner.ReleaseFingerprint != request.Release.ReleaseManifestDigest || request.Docker.Backend != NativeUnix || !ownerProfileOutsideRoots(directory, request.ApprovedWorkspaceRoots) {
		return nil, centralProfileError("preparation_invalid")
	}
	release, err := LoadInstalledRelease(request.Release)
	if err != nil {
		return nil, centralProfileError("release_invalid")
	}
	var artifacts []ownerProfileArtifact
	if !recover {
		artifacts, err = ownerProfileArtifacts(ctx, request, account, directory, label, release)
		if err != nil {
			return nil, err
		}
	}
	r := &OwnerProfilePreparation{files: &CentralProfileResolution{uid: account.uid, home: account.home, store: filepath.Dir(directory), directory: directory}, deps: deps, account: account, request: request}
	fail := func(err error) (*OwnerProfilePreparation, error) {
		// Some admission checks return only a closed error category. Preserve
		// an observed interruption as well, without replacing that failure.
		err = errors.Join(err, ctx.Err())
		if recover || r.mutated || r.retainedFailure != nil {
			return r, &centralProfileFailure{code: "preparation_recovery_required", cause: errors.Join(err, r.retainedFailure)}
		}
		if closeErr := r.Close(); closeErr != nil {
			return r, &centralProfileFailure{code: "cleanup_pending", cause: errors.Join(err, closeErr)}
		}
		return nil, err
	}
	if request.CoreHub != nil {
		core := request.CoreHub
		parent, err := r.files.openDirectory(ctx, filepath.Dir(core.Selection), true)
		if err != nil {
			return fail(err)
		}
		raw, err := r.files.readFile(ctx, parent, filepath.Base(core.Selection), account.uid, 0600, 1024*1024)
		if err != nil {
			return fail(err)
		}
		if centralDigest(raw) != core.SHA256 {
			return fail(centralProfileError("core_selection_changed"))
		}
		// The original descriptor stays in the existing input checks through
		// publication and registration. Application enrollment is checked at use.
	}
	// Admit installed code before creating credentials on disk. No executable runs.
	r.files.client, err = deps.central.client(ctx, request.ClientInstallationID)
	if err != nil {
		r.retainedFailure = err
		return fail(&centralProfileFailure{code: "client_unqualified", cause: err})
	}
	r.files.image, err = deps.central.image(ctx, protected.StableFrontendPath, request.RuntimeExecutableDigest)
	if err != nil {
		r.retainedFailure = err
		return fail(&centralProfileFailure{code: "executable_unqualified", cause: err})
	}
	frontend, err := deps.central.clientDigest(ctx, request.ClientInstallationID, r.files)
	if err != nil || frontend != request.RuntimeExecutableDigest {
		r.retainedFailure = err
		return fail(&centralProfileFailure{code: "client_binding_invalid", cause: err})
	}
	r.files.hostImage, err = deps.central.hostImage(ctx, request.RuntimeExecutablePath, request.RuntimeExecutableDigest)
	if err != nil {
		r.retainedFailure = err
		return fail(&centralProfileFailure{code: "executable_unqualified", cause: err})
	}
	if r.files.hostImage == nil {
		return fail(centralProfileError("executable_unqualified"))
	}
	for _, root := range request.ApprovedWorkspaceRoots {
		if _, err := r.files.openDirectory(ctx, root, false); err != nil {
			return fail(err)
		}
	}
	if err := r.recheckInputs(ctx); err != nil {
		return fail(err)
	}
	var dir *ownerProfilePreparationDirectory
	var retained map[string][]byte
	if recover {
		dir, retained, err = r.openRecoveryDirectory(ctx)
		if err == nil {
			artifacts, err = ownerProfileArtifactsFromRetained(ctx, request, account, directory, label, release, retained)
		}
	} else {
		dir, err = r.createDirectory(ctx)
	}
	if err != nil {
		return fail(err)
	}
	// Compare every existing artifact before publishing any missing file.
	for _, artifact := range artifacts {
		if raw, exists := retained[artifact.name]; exists && centralDigest(raw) != centralDigest(artifact.raw) {
			return fail(centralProfileError("recovery_request_mismatch"))
		}
	}
	for _, artifact := range artifacts {
		if _, exists := retained[artifact.name]; exists {
			continue
		}
		if err := r.publish(ctx, dir, artifact.name, artifact.raw); err != nil {
			return fail(err)
		}
	}
	if err := r.recheckInputs(ctx); err != nil {
		return fail(err)
	}
	if _, err := LoadEnrolledHostPolicy(HostPolicySelection{Path: filepath.Join(directory, "host-policy.json"), OwnerUID: account.uid, WorkspaceRoots: request.ApprovedWorkspaceRoots}); err != nil {
		return fail(centralProfileError("prepared_host_invalid"))
	}
	if _, registered := retained[centralProfileRegistrationName]; registered {
		r.registration, err = resolveCentralProfile(ctx, request.Owner.ProfileID, request.ApprovedWorkspaceRoots[0], deps.central)
		if err == nil && (r.registration.record.ClientInstallationID != request.ClientInstallationID || !reflect.DeepEqual(r.registration.record.CentralProfileContext, request.Context) || !reflect.DeepEqual(r.registration.selected.Workspaces, request.ApprovedWorkspaceRoots)) {
			err = centralProfileError("recovery_registration_mismatch")
		}
	} else {
		r.registration, err = registerCentralProfile(ctx, CentralProfileRegistrationRequest{ProfileID: request.Owner.ProfileID, ClientInstallationID: request.ClientInstallationID, ApprovedWorkspaceRoots: request.ApprovedWorkspaceRoots, Context: request.Context}, deps.central)
	}
	if err != nil {
		return fail(err)
	}
	if err := r.recheckInputs(ctx); err != nil {
		return fail(err)
	}
	r.prepared = true
	return r, nil
}

func (r *OwnerProfilePreparation) recheckInputs(ctx context.Context) error {
	return r.recheck(ctx, true)
}

// recheckPublication runs around each created directory and published file.
// It rechecks everything except the installed client tree, whose readmission
// walks every packaged file (about 0.1 s for a 2,000-file client). Repeating
// that around each file exhausted the preparation deadline. recheckInputs
// still rechecks the client tree before the directory is created, after all
// files are published and after registration, so a change is refused before
// success.
func (r *OwnerProfilePreparation) recheckPublication(ctx context.Context) error {
	return r.recheck(ctx, false)
}

func (r *OwnerProfilePreparation) recheck(ctx context.Context, clientTree bool) error {
	if err := ctx.Err(); err != nil {
		return &centralProfileFailure{code: "preparation_interrupted", cause: err}
	}
	a, err := r.deps.account()
	if err != nil {
		r.retainedFailure = errors.Join(r.retainedFailure, err)
		return &centralProfileFailure{code: "preparation_changed", cause: err}
	}
	if err := ctx.Err(); err != nil {
		return &centralProfileFailure{code: "preparation_interrupted", cause: err}
	}
	if a != r.account || r.files.client == nil || r.files.image == nil || r.files.hostImage == nil {
		return centralProfileError("preparation_changed")
	}
	checks := []func(context.Context) error{r.files.recheckFiles, r.files.image.Recheck, r.files.hostImage.Recheck}
	if clientTree {
		checks = append(checks, r.files.client.Recheck)
	}
	for _, check := range checks {
		if err := check(ctx); err != nil {
			r.retainedFailure = errors.Join(r.retainedFailure, err)
			return &centralProfileFailure{code: "preparation_changed", cause: errors.Join(err, ctx.Err())}
		}
	}
	return nil
}

// Selection is available only after complete host readback and registration.
func (r *OwnerProfilePreparation) Selection(ctx context.Context) (CentralProfileSelection, error) {
	if r == nil || ctx == nil {
		return CentralProfileSelection{}, centralProfileError("closed")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || !r.prepared || r.closeErr != nil {
		return CentralProfileSelection{}, centralProfileError("preparation_incomplete")
	}
	if err := r.recheckInputs(ctx); err != nil {
		return CentralProfileSelection{}, err
	}
	return r.registration.Selection(ctx)
}

func (r *OwnerProfilePreparation) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.closeErr
	}
	r.closed = true
	var failures []error
	if r.retainedFailure != nil {
		failures = append(failures, r.retainedFailure)
	}
	if r.registration != nil {
		if err := r.registration.Close(); err != nil {
			failures = append(failures, err)
		}
	}
	if r.files != nil {
		if err := r.files.Close(); err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) > 0 {
		r.closeErr = &centralProfileFailure{code: "cleanup_pending", cause: errors.Join(failures...)}
	}
	return r.closeErr
}

type ownerProfileArtifact struct {
	name string
	raw  []byte
}

func ownerProfileArtifacts(ctx context.Context, q OwnerProfilePreparationRequest, a ownerProfileAccount, directory, label string, release InstalledRelease) ([]ownerProfileArtifact, error) {
	return ownerProfileArtifactsFromRetained(ctx, q, a, directory, label, release, nil)
}

func ownerProfileArtifactsFromRetained(ctx context.Context, q OwnerProfilePreparationRequest, a ownerProfileAccount, directory, label string, release InstalledRelease, retained map[string][]byte) ([]ownerProfileArtifact, error) {
	empty := func() ([]ownerProfileArtifact, error) { return nil, centralProfileError("preparation_invalid") }
	e := q.Owner
	if e.SchemaVersion != protocol.Version || !kernelStatusID.MatchString(e.PrincipalID) || !kernelStatusID.MatchString(e.Identity.ID) || !kernelStatusID.MatchString(e.Identity.OwnerHubID) || e.Identity.Revision == 0 || e.Identity.Revision > protocol.MaxRevision || !kernelStatusID.MatchString(e.Scope.OrganizationID) || !optionalStatusID(e.Scope.ProjectID) || !optionalStatusID(e.Scope.WorkspaceID) || !kernelStatusID.MatchString(q.ServerName) || !kernelStatusID.MatchString(q.Domain) || q.HostPort < 1 || q.HostPort > 65535 || !canonicalHostFilePath(q.RuntimeExecutablePath) || !digest.MatchString(q.RuntimeExecutableDigest) || q.Docker.ComposeVersion != release.BrokerPins().ComposeVersion {
		return empty()
	}
	limits := hostPolicyLimits{q.StartupTimeout.Milliseconds(), q.ProbeTimeout.Milliseconds(), q.Deadlines.StartTimeout.Milliseconds(), q.Deadlines.StopGrace.Milliseconds(), q.Deadlines.ReapTimeout.Milliseconds()}
	if limits.StartupMilliseconds < 1 || limits.StartupMilliseconds > 60000 || limits.ProbeMilliseconds < 1 || limits.ProbeMilliseconds > 5000 || limits.RoleStartMilliseconds < 1 || limits.RoleStartMilliseconds > 30000 || limits.StopGraceMilliseconds < 1 || limits.StopGraceMilliseconds > 10000 || limits.ReapMilliseconds < 1 || limits.ReapMilliseconds > 10000 {
		return empty()
	}
	var material *deployment.LocalTLSMaterial
	var secrets map[string]string
	var err error
	if retained == nil {
		material, err = deployment.EnrollLocalTLS(ctx, e.ProfileID)
	} else {
		material, secrets, err = ownerProfileRetainedSecrets(e.ProfileID, retained)
	}
	if err != nil {
		return empty()
	}
	scope := protocol.Scope{HubID: e.Identity.OwnerHubID, InstanceID: e.InstanceID, ProfileID: e.ProfileID, AssemblyDigest: release.Trust().AssemblyDigest, ReleaseManifestDigest: q.Release.ReleaseManifestDigest, ReleaseVersion: q.Release.ReleaseVersion}
	profile := Profile{SchemaVersion: protocol.Version, ProfileID: e.ProfileID, InstanceID: e.InstanceID, OwnerUID: a.uid, DisplayName: label, ProfileDirectory: directory, Mode: "local", ReleaseFingerprint: q.Release.ReleaseManifestDigest, NATSEndpoint: "tls://127.0.0.1:" + strconv.Itoa(q.HostPort), ServerTrustRef: localServerTrustFile, ComposeProject: q.ComposeProject, Docker: &q.Docker}
	trust, err := json.Marshal(protocol.ServerTrustRecord{SchemaVersion: protocol.Version, Endpoint: profile.NATSEndpoint, ServerName: material.ServerName(), RootsPEM: string(material.RootsPEM()), LeafCertificateSHA256: material.LeafCertificateSHA256(), Scope: scope})
	if err != nil {
		return empty()
	}
	profile.ServerTrustDigest = centralDigest(trust)
	secret := func(name string) (string, error) {
		if retained != nil {
			value, ok := secrets[name]
			if !ok || !kernelStatusPassword.MatchString(value) {
				return "", centralProfileError("recovery_credentials_incomplete")
			}
			return value, nil
		}
		var raw [32]byte
		_, err := rand.Read(raw[:])
		return hex.EncodeToString(raw[:]), err
	}
	credentials := communication.Credentials{}
	roles := protocol.Roles()
	for _, role := range append([]string{communication.Administrator, communication.OrdinaryPlugin}, roles[:]...) {
		value, err := secret(role)
		if err != nil {
			return empty()
		}
		credentials[role] = value
	}
	health, err := secret(deployment.HealthUser)
	if err != nil {
		return empty()
	}
	server, err := secret(deployment.OwnerBridgeServerUser)
	if err != nil {
		return empty()
	}
	client, err := secret(deployment.OwnerBridgeClientUser)
	if err != nil {
		return empty()
	}
	bridge := deployment.OwnerBridgeSettings{Scope: scope, ServerPassword: server, ClientPassword: client}
	metadata := hostRuntimeMetadata{protocol.Version, scope.HubID, q.ServerName, q.Domain, "/data/store", q.MaxMemoryBytes, q.MaxFileBytes}
	broker, err := deployment.BuildSecureLocalConfigWithOwnerBridge(deployment.StorageProfile{HubID: scope.HubID, ServerName: q.ServerName, Domain: q.Domain, StoreDirectory: metadata.StoreDirectory, MaxMemoryBytes: q.MaxMemoryBytes, MaxFileBytes: q.MaxFileBytes, Listener: communication.Listener{Mode: communication.ContainerInternal, Port: 4222}}, credentials, health, bridge, material)
	if err != nil {
		return empty()
	}
	compose, err := deployment.RenderSecureCompose(deployment.ComposeSpec{Project: q.ComposeProject, InstanceID: e.InstanceID, ProfileID: e.ProfileID, ReleaseDigest: profile.ReleaseFingerprint, Image: release.BrokerPins().Image, HostPort: q.HostPort, BrokerConfig: broker}, material)
	if err != nil {
		return empty()
	}
	profile.ConfigDigest = centralDigest(compose)
	if validateProfile(profile, ProfilePolicy{Directory: directory, OwnerUID: a.uid, WorkspaceRoots: q.ApprovedWorkspaceRoots, InstalledReleaseFingerprint: profile.ReleaseFingerprint}) != nil {
		return empty()
	}
	p := q.Release
	host := hostPolicyRecord{SchemaVersion: protocol.Version, OwnerUID: a.uid, ProfileDirectory: directory, ProfileID: e.ProfileID, InstanceID: e.InstanceID, Owner: e, ServerName: q.ServerName, Domain: q.Domain, PublicEndpoint: profile.NATSEndpoint, PublicContextName: q.Docker.Context, RuntimeExecutable: hostPolicyExecutable{q.RuntimeExecutablePath, q.RuntimeExecutableDigest}, Limits: limits, Release: hostPolicyRelease{p.PackageDirectory, hex.EncodeToString(p.PublicKey), p.ReleaseManifestDigest, p.ReleaseAuthority, p.ReleaseVersion, p.KernelAPIMajor}, OwnerBridge: &OwnerBridgeCredentialRefs{Server: "owner-host.json", Client: "owner-client.json"}}
	selection := centralProfileSelectionFile{CoreHub: q.CoreHub, SchemaVersion: protocol.Version, HostPolicy: filepath.Join(directory, "host-policy.json"), Workspaces: q.ApprovedWorkspaceRoots, InstanceID: e.InstanceID, ProfileID: e.ProfileID, HubID: scope.HubID}
	artifacts := []ownerProfileArtifact{{localServerTrustFile, trust}, {localServerCertificateFile, material.ServerCertificatePEM()}, {localServerKeyFile, material.ServerKeyPEM()}, {"broker.json", broker}}
	add := func(name string, value any) bool {
		raw, err := json.Marshal(value)
		if err != nil {
			return false
		}
		artifacts = append(artifacts, ownerProfileArtifact{name, raw})
		return true
	}
	if !add("runtime.json", metadata) || !add("status-owner.json", e) || !add("owner-host.json", OwnerBridgeCredential{protocol.Version, deployment.OwnerBridgeServerUser, scope, e, server}) || !add("owner-client.json", OwnerBridgeCredential{protocol.Version, deployment.OwnerBridgeClientUser, scope, e, client}) {
		return empty()
	}
	for _, role := range roles {
		if !add(role+".json", protocol.Credentials{SchemaVersion: protocol.Version, Role: role, Username: role, Password: credentials[role], NATSURL: profile.NATSEndpoint, Scope: scope}) {
			return empty()
		}
	}
	if !add("host-policy.json", host) || !add("client-selection.json", selection) || !add("profile.json", profile) {
		return empty()
	}
	return artifacts, nil
}
