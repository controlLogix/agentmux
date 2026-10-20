//go:build linux || darwin

package launcher

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/controlLogix/agentmux/platform/internal/wirejson"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/privatefs"
	protected "github.com/controlLogix/agentmux/platform/runtime"
	"golang.org/x/sys/unix"
)

const centralProfileRegistrationName = "registration.json"

// CentralProfileContext contains display/context metadata only. Project is not
// an authorization projectId. Nil values are omitted, never guessed on migration.
type CentralProfileContext struct {
	Environment *string `json:"environment,omitempty"`
	Project     *string `json:"project,omitempty"`
}

func (c CentralProfileContext) clone() CentralProfileContext {
	if c.Environment != nil {
		v := *c.Environment
		c.Environment = &v
	}
	if c.Project != nil {
		v := *c.Project
		c.Project = &v
	}
	return c
}
func (c CentralProfileContext) valid() bool {
	if c.Environment == nil && c.Project == nil {
		return false
	}
	for _, value := range []*string{c.Environment, c.Project} {
		if value == nil {
			continue
		}
		if *value == "" || strings.TrimSpace(*value) != *value || len(*value) > 128 || !utf8.ValidString(*value) {
			return false
		}
		for _, r := range *value {
			if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
				return false
			}
		}
	}
	return true
}

// CentralProfileRegistrationRequest requires existing admitted files at their canonical location.
// This operation publishes only registration.json; it creates no directories,
// profile, credentials, client selection, workspace membership or broker state.
type CentralProfileRegistrationRequest struct {
	ProfileID              string
	ClientInstallationID   string
	ApprovedWorkspaceRoots []string
	Context                CentralProfileContext
}
type centralProfileRegistration struct {
	SchemaVersion         string `json:"schemaVersion"`
	OwnerUID              uint32 `json:"ownerUid"`
	ProfileID             string `json:"profileId"`
	InstanceID            string `json:"instanceId"`
	ClientInstallationID  string `json:"clientInstallationId"`
	ProfileSHA256         string `json:"profileSha256"`
	HostPolicySHA256      string `json:"hostPolicySha256"`
	ClientSelectionSHA256 string `json:"clientSelectionSha256"`
	CentralProfileContext
}

// CentralProfileSelection is an explicit private disclosure to the installed CLI. Callers
// retain the resolution through startup/exec and close it on every return path.
type CentralProfileSelection struct {
	ProfileID, InstanceID, HubID, ClientInstallationID, ClientSelectionPath string
	Context                                                                 CentralProfileContext
}

func (CentralProfileSelection) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "[private central profile selection]")
}
func (CentralProfileSelection) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-central-profile-selection"}`), nil
}

type centralClientOwner interface {
	Recheck(context.Context) error
	Close() error
	ExecRegistered(context.Context, string, string, *os.File, string) error
}
type centralCoreClientOwner interface {
	ExecRegisteredCore(context.Context, string, *os.File, string, string, []string) error
}

type centralImageOwner interface {
	Recheck(context.Context) error
	Close() error
}
type centralProfileDependencies struct {
	account      func() (string, uint32, error)
	host         func(HostPolicySelection) (*EnrolledHostPolicy, error)
	client       func(context.Context, string) (centralClientOwner, error)
	clientDigest func(context.Context, string, *CentralProfileResolution) (string, error)
	image        func(context.Context, string, string) (centralImageOwner, error)
	hostImage    func(context.Context, string, string) (centralImageOwner, error)
}

func centralProfileProduction() centralProfileDependencies {
	return centralProfileDependencies{
		account: centralProfileAccount, host: LoadEnrolledHostPolicy,
		client: func(ctx context.Context, id string) (centralClientOwner, error) {
			return protected.PrepareInstalledClient(ctx, id)
		},
		clientDigest: func(ctx context.Context, id string, r *CentralProfileResolution) (string, error) {
			directory, err := r.openDirectory(ctx, filepath.Join(protected.InstalledClientBase, id), false)
			if err != nil {
				return "", err
			}
			raw, err := r.readFile(ctx, directory, "client-manifest.json", 0, 0444, protected.ClientManifestLimit)
			if err != nil {
				return "", centralProfileErrorWithCause("client_binding_invalid", err)
			}
			if centralDigest(raw) != "sha256:"+id {
				return "", centralProfileError("client_binding_invalid")
			}
			manifest, err := protected.DecodeClientManifest(raw)
			if err != nil {
				return "", centralProfileErrorWithCause("client_binding_invalid", err)
			}
			if err := r.client.Recheck(ctx); err != nil {
				return "", centralProfileErrorWithCause("client_binding_invalid", err)
			}
			return manifest.FrontendDigest, nil
		},
		image: func(ctx context.Context, path, digest string) (centralImageOwner, error) {
			return protected.PrepareProtectedInstalledFrontend(ctx, path, digest, 128*1024*1024)
		},
		hostImage: func(ctx context.Context, path, digest string) (centralImageOwner, error) {
			return protected.PrepareProtectedInstalledHost(ctx, path, digest, 128*1024*1024)
		},
	}
}
func centralProfileAccount() (string, uint32, error) {
	if goruntime.GOOS != "darwin" || goruntime.GOARCH != "arm64" {
		return "", 0, protected.ErrPlatformUnqualified
	}
	if os.Getuid() != os.Geteuid() || os.Geteuid() == 0 {
		return "", 0, centralProfileError("owner_invalid")
	}
	uid := uint32(os.Geteuid())
	account, err := user.LookupId(strconv.Itoa(int(uid)))
	if err != nil || account.Uid != strconv.Itoa(int(uid)) || !filepath.IsAbs(account.HomeDir) || filepath.Clean(account.HomeDir) != account.HomeDir {
		return "", 0, centralProfileError("account_unavailable")
	}
	return account.HomeDir, uid, nil
}

type centralProfileFailure struct {
	code  string
	cause error
}

func (e *centralProfileFailure) Error() string                { return "central_profile_" + e.code }
func (e *centralProfileFailure) Format(s fmt.State, _ rune)   { fmt.Fprint(s, e.Error()) }
func (e *centralProfileFailure) MarshalJSON() ([]byte, error) { return json.Marshal(e.Error()) }
func (e *centralProfileFailure) Unwrap() error                { return e.cause }
func centralProfileError(code string) error                   { return &centralProfileFailure{code: code} }

func centralProfileErrorWithCause(code string, cause error) error {
	return &centralProfileFailure{code: code, cause: cause}
}

// Admission errors can own resources even when their admission result is nil.
// Their concrete cleanup state is opaque here. Retain them without retrying or
// assuming that closing our other descriptors resolves that nested ownership.
func (r *CentralProfileResolution) retainAdmissionFailure(code string, cause error) error {
	failure := centralProfileErrorWithCause(code, cause)
	r.admissionErr = failure
	r.useErr = failure
	return failure
}

// Resolution owns original filesystem and installed-image admissions. A failed
// Close remains a failed owner; it must never be replaced by another lookup.
type CentralProfileResolution struct {
	mu                                 sync.Mutex
	uid                                uint32
	home, store, directory, repository string
	dependencies                       centralProfileDependencies
	files                              []*centralProfileFile
	stages                             []*os.File
	directoryFile                      *centralProfileFile
	registrationFile                   *centralProfileFile
	client                             centralClientOwner
	image                              centralImageOwner
	hostImage                          centralImageOwner
	record                             centralProfileRegistration
	selected                           centralProfileSelectionFile
	publicationRetained                bool
	useErr                             error
	admissionErr                       error
	closed                             bool
	cleanupErr                         error
}

func (*CentralProfileResolution) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "[private central profile resolution]")
}
func (*CentralProfileResolution) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-central-profile-resolution"}`), nil
}

// RegisterCentralProfile creates registration.json only after the existing
// profile, host policy and installed client pass admission. An error may return
// an owner when admission cleanup or publication is uncertain; callers must retain
// that owner and failure. Publication uncertainty blocks all use until close.
func RegisterCentralProfile(ctx context.Context, request CentralProfileRegistrationRequest) (*CentralProfileResolution, error) {
	return registerCentralProfile(ctx, request, centralProfileProduction())
}

// ResolveCentralProfile accepts an already approved repository root. It checks
// existing membership without adding a workspace or modifying profile files.
// Callers retain the returned owner through use and close it on every return.
func ResolveCentralProfile(ctx context.Context, id, approvedRepositoryRoot string) (*CentralProfileResolution, error) {
	return resolveCentralProfile(ctx, id, approvedRepositoryRoot, centralProfileProduction())
}

func centralProfileOpen(ctx context.Context, id string, deps centralProfileDependencies) (*CentralProfileResolution, error) {
	if ctx == nil || ctx.Err() != nil || !profileID.MatchString(id) {
		return nil, centralProfileError("reference_invalid")
	}
	home, uid, err := deps.account()
	if err != nil || uid != uint32(os.Geteuid()) || !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return nil, centralProfileError("account_unavailable")
	}
	store := filepath.Join(home, "Library", "Application Support", "Agentmux", "profiles")
	r := &CentralProfileResolution{uid: uid, home: home, store: store, directory: filepath.Join(store, id), dependencies: deps}
	r.directoryFile, err = r.openDirectory(ctx, r.directory, true)
	if err != nil {
		return centralProfileAbort(r, err)
	}
	return r, nil
}
func centralProfileAbort(r *CentralProfileResolution, err error) (*CentralProfileResolution, error) {
	if r == nil {
		return nil, err
	}
	// A published registration or an uncertain stage remains owned by the
	// caller. Keep original handles open and block use; do not hide the result
	// behind successful descriptor cleanup. Close is explicit after handoff.
	if r.publicationRetained {
		r.useErr = &centralProfileFailure{code: "publication_uncertain", cause: err}
		return r, r.useErr
	}
	if r.admissionErr != nil {
		return r, err
	}
	if closeErr := r.Close(); closeErr != nil {
		return r, &centralProfileFailure{code: "cleanup_pending", cause: errors.Join(err, closeErr)}
	}
	return nil, err
}
func registerCentralProfile(parent context.Context, request CentralProfileRegistrationRequest, deps centralProfileDependencies) (*CentralProfileResolution, error) {
	if parent == nil || !request.Context.valid() || !protected.ValidClientInstallationID(request.ClientInstallationID) {
		return nil, centralProfileError("registration_invalid")
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	r, err := centralProfileOpen(ctx, request.ProfileID, deps)
	if err != nil {
		return r, err
	}
	r.record = centralProfileRegistration{SchemaVersion: "1.0.0", OwnerUID: r.uid, ProfileID: request.ProfileID, ClientInstallationID: request.ClientInstallationID, CentralProfileContext: request.Context.clone()}
	if err = r.admit(ctx, request.ApprovedWorkspaceRoots, true); err != nil {
		return centralProfileAbort(r, err)
	}
	if err = r.recheck(ctx); err != nil {
		return centralProfileAbort(r, err)
	}
	raw, err := json.Marshal(r.record)
	if err != nil {
		return centralProfileAbort(r, centralProfileError("registration_invalid"))
	}
	if err = r.publishRegistration(ctx, raw); err != nil {
		return centralProfileAbort(r, err)
	}
	if _, err = r.readFile(ctx, r.directoryFile, centralProfileRegistrationName, r.uid, 0600, 16384); err != nil {
		return centralProfileAbort(r, centralProfileError("publication_uncertain"))
	}
	if err = r.recheck(ctx); err != nil {
		return centralProfileAbort(r, centralProfileError("publication_uncertain"))
	}
	return r, nil
}
func resolveCentralProfile(parent context.Context, id, repository string, deps centralProfileDependencies) (*CentralProfileResolution, error) {
	if parent == nil || !canonicalProfilePath(repository) {
		return nil, centralProfileError("repository_invalid")
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	r, err := centralProfileOpen(ctx, id, deps)
	if err != nil {
		return r, err
	}
	r.repository = repository
	raw, err := r.readFile(ctx, r.directoryFile, centralProfileRegistrationName, r.uid, 0600, 16384)
	if err != nil {
		return centralProfileAbort(r, centralProfileError("registration_required"))
	}
	if err = decodeCentralRegistration(raw, &r.record); err != nil || r.record.ProfileID != id || r.record.OwnerUID != r.uid {
		return centralProfileAbort(r, centralProfileError("registration_invalid"))
	}
	if err = r.admit(ctx, nil, false); err != nil {
		return centralProfileAbort(r, err)
	}
	if !containsCentralRoot(r.selected.Workspaces, repository) {
		return centralProfileAbort(r, centralProfileError("repository_not_registered"))
	}
	if _, err = r.openDirectory(ctx, repository, false); err != nil {
		return centralProfileAbort(r, err)
	}
	if err = r.recheck(ctx); err != nil {
		return centralProfileAbort(r, err)
	}
	return r, nil
}
func (r *CentralProfileResolution) Recheck(parent context.Context) error {
	if r == nil || parent == nil {
		return centralProfileError("closed")
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.recheck(ctx)
}
func (r *CentralProfileResolution) recheck(ctx context.Context) error {
	if r.useErr != nil {
		return r.useErr
	}
	if r.closed || r.cleanupErr != nil || ctx.Err() != nil {
		return centralProfileError("closed")
	}
	home, uid, err := r.dependencies.account()
	if err != nil {
		return r.retainAdmissionFailure("changed", err)
	}
	if uid != r.uid || home != r.home || r.recheckFiles(ctx) != nil {
		return centralProfileError("changed")
	}
	host, err := r.dependencies.host(HostPolicySelection{Path: filepath.Join(r.directory, "host-policy.json"), OwnerUID: r.uid, WorkspaceRoots: append([]string(nil), r.selected.Workspaces...)})
	if err != nil {
		return r.retainAdmissionFailure("binding_changed", err)
	}
	if host == nil || host.record.ProfileID != r.record.ProfileID || host.record.InstanceID != r.record.InstanceID || host.record.ProfileDirectory != r.directory {
		return centralProfileError("binding_changed")
	}
	if !releaseHostPath(host.record.RuntimeExecutable.Path, host.record.Release.PackageDirectory) {
		return centralProfileError("release_binding_invalid")
	}
	profile, err := LoadProfile(host.policy.Profile)
	if err != nil {
		return r.retainAdmissionFailure("binding_changed", err)
	}
	if profile.profile.ProfileID != r.record.ProfileID || profile.profile.InstanceID != r.record.InstanceID {
		return centralProfileError("binding_changed")
	}
	if err := r.client.Recheck(ctx); err != nil {
		return r.retainAdmissionFailure("binding_changed", err)
	}
	if err := r.image.Recheck(ctx); err != nil {
		return r.retainAdmissionFailure("binding_changed", err)
	}
	if err := r.hostImage.Recheck(ctx); err != nil {
		return r.retainAdmissionFailure("binding_changed", err)
	}
	if err := r.recheckFiles(ctx); err != nil {
		return err
	}

	return nil
}
func (r *CentralProfileResolution) Selection(ctx context.Context) (CentralProfileSelection, error) {
	if err := r.Recheck(ctx); err != nil {
		return CentralProfileSelection{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return CentralProfileSelection{}, centralProfileError("closed")
	}
	return CentralProfileSelection{r.record.ProfileID, r.record.InstanceID, r.selected.HubID, r.record.ClientInstallationID, filepath.Join(r.directory, "client-selection.json"), r.record.CentralProfileContext.clone()}, nil
}

// ExecClient keeps the registration admission and the installed client owner
// through the final full recheck and private descriptor handoff. It never
// reopens registration.json or falls back to metadata-free execution.
func (r *CentralProfileResolution) ExecClient(parent context.Context, operation string) error {
	if r == nil || parent == nil {
		return centralProfileError("closed")
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.recheck(ctx); err != nil {
		return err
	}
	if r.registrationFile == nil || r.registrationFile.file == nil || !digest.MatchString(r.registrationFile.digest) {
		return centralProfileError("registration_required")
	}
	return r.client.ExecRegistered(ctx, operation, filepath.Join(r.directory, "client-selection.json"), r.registrationFile.file, r.registrationFile.digest)
}

// ExecCoreClient carries the admitted repository and original registration through exec.
func (r *CentralProfileResolution) ExecCoreClient(parent context.Context, arguments []string) error {
	if r == nil || parent == nil || len(arguments) == 0 {
		return centralProfileError("selection_invalid")
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.recheck(ctx); err != nil {
		return err
	}
	owner, ok := r.client.(centralCoreClientOwner)
	if !ok || r.selected.CoreHub == nil || r.repository == "" || r.registrationFile == nil || r.registrationFile.file == nil {
		return centralProfileError("application_setup_required")
	}
	return owner.ExecRegisteredCore(ctx, filepath.Join(r.directory, "client-selection.json"),
		r.registrationFile.file, r.registrationFile.digest, r.repository, arguments)
}

func (r *CentralProfileResolution) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.cleanupErr
	}
	r.closed = true
	var failures []error
	if r.cleanupErr != nil {
		failures = append(failures, r.cleanupErr)
	}
	if r.admissionErr != nil {
		failures = append(failures, r.admissionErr)
	}
	if r.image != nil {
		if err := r.image.Close(); err != nil {
			failures = append(failures, err)
		}
	}
	if r.hostImage != nil {
		if err := r.hostImage.Close(); err != nil {
			failures = append(failures, err)
		}
	}
	if r.client != nil {
		if err := r.client.Close(); err != nil {
			failures = append(failures, err)
		}
	}
	for _, staged := range r.stages {
		if err := staged.Close(); err != nil {
			failures = append(failures, err)
		}
	}
	for i := len(r.files) - 1; i >= 0; i-- {
		if err := r.files[i].file.Close(); err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) > 0 {
		r.cleanupErr = &centralProfileFailure{code: "cleanup_pending", cause: errors.Join(failures...)}
	}
	return r.cleanupErr
}

func decodeCentralRegistration(raw []byte, out *centralProfileRegistration) error {
	if wirejson.Validate(raw, 16384) != nil {
		return centralProfileError("registration_invalid")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return centralProfileError("registration_invalid")
	}
	allowed := map[string]bool{}
	for _, key := range []string{"schemaVersion", "ownerUid", "profileId", "instanceId", "clientInstallationId", "profileSha256", "hostPolicySha256", "clientSelectionSha256", "environment", "project"} {
		allowed[key] = true
	}
	for key, value := range fields {
		if !allowed[key] || string(value) == "null" {
			return centralProfileError("registration_invalid")
		}
	}
	for _, key := range []string{"schemaVersion", "ownerUid", "profileId", "instanceId", "clientInstallationId", "profileSha256", "hostPolicySha256", "clientSelectionSha256"} {
		if _, ok := fields[key]; !ok {
			return centralProfileError("registration_invalid")
		}
	}
	if json.Unmarshal(raw, out) != nil || out.SchemaVersion != "1.0.0" || !profileID.MatchString(out.ProfileID) || !profileInstanceID.MatchString(out.InstanceID) || !protected.ValidClientInstallationID(out.ClientInstallationID) || !out.CentralProfileContext.valid() || !digest.MatchString(out.ProfileSHA256) || !digest.MatchString(out.HostPolicySHA256) || !digest.MatchString(out.ClientSelectionSHA256) {
		return centralProfileError("registration_invalid")
	}
	return nil
}

// CoreHubSelection pins an explicitly prepared core route. It grants no application authority.
type CoreHubSelection struct {
	Selection string `json:"selection"`
	SHA256    string `json:"sha256"`
}

type centralProfileSelectionFile struct {
	CoreHub       *CoreHubSelection `json:"coreHub,omitempty"`
	SchemaVersion string            `json:"schemaVersion"`
	HostPolicy    string            `json:"hostPolicy"`
	Workspaces    []string          `json:"workspaces"`
	InstanceID    string            `json:"instanceId"`
	ProfileID     string            `json:"profileId"`
	HubID         string            `json:"hubId"`
	Application   *struct {
		ClientKey    string   `json:"clientKey"`
		Connection   string   `json:"connection"`
		Repositories []string `json:"repositories,omitempty"`
	} `json:"application,omitempty"`
	ApplicationAttestor *struct {
		Selection string `json:"selection"`
		SHA256    string `json:"sha256"`
	} `json:"applicationAttestor,omitempty"`
	ApplicationServices *struct {
		InstallationID string `json:"installationId"`
		Selection      string `json:"selection"`
		SHA256         string `json:"sha256"`
	} `json:"applicationServices,omitempty"`
}

func containsCentralRoot(roots []string, path string) bool {
	for _, root := range roots {
		if root == path {
			return true
		}
	}
	return false
}
func centralRootsValid(roots []string) bool {
	if len(roots) == 0 || len(roots) > 16 {
		return false
	}
	seen := map[string]bool{}
	for _, root := range roots {
		if !canonicalProfilePath(root) || seen[root] {
			return false
		}
		seen[root] = true
	}
	return true
}
func centralRepositoryName(name string) bool {
	if len(name) == 0 || len(name) > 32 {
		return false
	}
	for _, value := range []byte(name) {
		if (value < 'a' || value > 'z') && (value < '0' || value > '9') && value != '_' {
			return false
		}
	}
	return true
}
func (r *CentralProfileResolution) admit(ctx context.Context, approved []string, register bool) error {
	bodies := map[string][]byte{}
	for _, name := range []string{"profile.json", "host-policy.json", "client-selection.json"} {
		raw, err := r.readFile(ctx, r.directoryFile, name, r.uid, 0600, 65536)
		if err != nil {
			return err
		}
		bodies[name] = raw
	}
	if !register && (centralDigest(bodies["profile.json"]) != r.record.ProfileSHA256 || centralDigest(bodies["host-policy.json"]) != r.record.HostPolicySHA256 || centralDigest(bodies["client-selection.json"]) != r.record.ClientSelectionSHA256) {
		return centralProfileError("binding_changed")
	}
	raw := bodies["client-selection.json"]
	if wirejson.Validate(raw, 16384) != nil || protocol.DecodeClosedJSON(raw, &r.selected, 16384) != nil || r.selected.SchemaVersion != "1.0.0" || r.selected.ProfileID != r.record.ProfileID || r.selected.HostPolicy != filepath.Join(r.directory, "host-policy.json") || !centralRootsValid(r.selected.Workspaces) || !profileInstanceID.MatchString(r.selected.InstanceID) || !profileToken.MatchString(r.selected.HubID) {
		return centralProfileError("selection_invalid")
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	for _, key := range []string{"schemaVersion", "hostPolicy", "workspaces", "instanceId", "profileId", "hubId"} {
		if v, ok := fields[key]; !ok || string(v) == "null" {
			return centralProfileError("selection_invalid")
		}
	}
	for _, key := range []string{"application", "applicationAttestor", "applicationServices", "coreHub"} {
		if v, ok := fields[key]; ok && string(v) == "null" {
			return centralProfileError("selection_invalid")
		}
	}
	if r.selected.Application != nil {
		app := r.selected.Application
		if !centralSelectionPath(app.ClientKey, r.selected.Workspaces) || !centralSelectionPath(app.Connection, r.selected.Workspaces) {
			return centralProfileError("selection_invalid")
		}
		if app.Repositories != nil {
			seen := map[string]bool{}
			for _, repository := range app.Repositories {
				if !centralRepositoryName(repository) || seen[repository] {
					return centralProfileError("selection_invalid")
				}
				seen[repository] = true
			}
			if len(seen) == 0 {
				return centralProfileError("selection_invalid")
			}
		}
	}
	if r.selected.CoreHub != nil {
		core := r.selected.CoreHub
		if !centralSelectionPath(core.Selection, r.selected.Workspaces) || !digest.MatchString(core.SHA256) {
			return centralProfileError("selection_invalid")
		}
	}
	if r.selected.ApplicationAttestor != nil {
		app := r.selected.ApplicationAttestor
		if !centralSelectionPath(app.Selection, r.selected.Workspaces) || !digest.MatchString(app.SHA256) {
			return centralProfileError("selection_invalid")
		}
	}
	if r.selected.ApplicationServices != nil {
		services := r.selected.ApplicationServices
		if r.selected.ApplicationAttestor == nil || !protected.ValidClientInstallationID(services.InstallationID) || !centralSelectionPath(services.Selection, r.selected.Workspaces) || !digest.MatchString(services.SHA256) {
			return centralProfileError("selection_invalid")
		}
	}
	if register && (!centralRootsValid(approved) || !reflect.DeepEqual(approved, r.selected.Workspaces)) {
		return centralProfileError("workspace_mismatch")
	}
	if !register && !containsCentralRoot(r.selected.Workspaces, r.repository) {
		return centralProfileError("repository_not_registered")
	}
	host, err := r.dependencies.host(HostPolicySelection{Path: r.selected.HostPolicy, OwnerUID: r.uid, WorkspaceRoots: append([]string(nil), r.selected.Workspaces...)})
	if err != nil {
		return r.retainAdmissionFailure("host_policy_invalid", err)
	}
	if host == nil {
		return centralProfileError("host_policy_invalid")
	}
	if !releaseHostPath(host.record.RuntimeExecutable.Path, host.record.Release.PackageDirectory) {
		return centralProfileError("release_binding_invalid")
	}
	profile, err := LoadProfile(host.policy.Profile)
	if err != nil {
		return r.retainAdmissionFailure("profile_binding_invalid", err)
	}
	if profile.profile.ProfileID != r.record.ProfileID || profile.profile.InstanceID != r.selected.InstanceID || profile.profile.ProfileDirectory != r.directory || host.record.ProfileID != r.record.ProfileID || host.record.InstanceID != r.selected.InstanceID || host.record.ProfileDirectory != r.directory || host.record.Owner.Identity.OwnerHubID != r.selected.HubID {
		return centralProfileError("profile_binding_invalid")
	}
	if register {
		r.record.InstanceID = r.selected.InstanceID
		r.record.ProfileSHA256 = centralDigest(bodies["profile.json"])
		r.record.HostPolicySHA256 = centralDigest(bodies["host-policy.json"])
		r.record.ClientSelectionSHA256 = centralDigest(raw)
	} else if r.record.InstanceID != r.selected.InstanceID {
		return centralProfileError("profile_binding_invalid")
	}
	r.client, err = r.dependencies.client(ctx, r.record.ClientInstallationID)
	if err != nil {
		return r.retainAdmissionFailure("client_binding_invalid", err)
	}
	if r.client == nil {
		return centralProfileError("client_binding_invalid")
	}
	rawDigest, err := r.dependencies.clientDigest(ctx, r.record.ClientInstallationID, r)
	if err != nil {
		return r.retainAdmissionFailure("client_binding_invalid", err)
	}
	if rawDigest != host.record.RuntimeExecutable.Digest {
		return centralProfileError("client_binding_invalid")
	}

	// The installed client invokes the fixed frontend, which then starts the
	// separately admitted runtime in this profile's immutable release directory.
	r.image, err = r.dependencies.image(ctx, protected.StableFrontendPath, rawDigest)
	if err != nil {
		return r.retainAdmissionFailure("release_binding_invalid", err)
	}
	if r.image == nil {
		return centralProfileError("release_binding_invalid")
	}
	r.hostImage, err = r.dependencies.hostImage(ctx, host.record.RuntimeExecutable.Path, host.record.RuntimeExecutable.Digest)
	if err != nil {
		return r.retainAdmissionFailure("release_binding_invalid", err)
	}
	if r.hostImage == nil {
		return centralProfileError("release_binding_invalid")
	}
	return nil
}

func releaseHostPath(path, releaseDirectory string) bool {
	return filepath.IsAbs(releaseDirectory) && filepath.Clean(releaseDirectory) == releaseDirectory &&
		path == filepath.Join(releaseDirectory, "agentmux-runtime")
}

// Publish without replacing any existing registration. Stage cleanup finishes
// while the original directory descriptor is still owned by the resolution.
func (r *CentralProfileResolution) publishRegistration(ctx context.Context, raw []byte) (result error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return centralProfileError("publication_failed")
	}
	stage := ".registration-" + hex.EncodeToString(nonce[:])
	dirfd := int(r.directoryFile.file.Fd())
	fd, err := unix.Openat(dirfd, stage, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return centralProfileError("publication_failed")
	}
	staged := os.NewFile(uintptr(fd), "central-profile-registration-stage")
	r.stages = append(r.stages, staged)
	cleanupAttempted := false
	defer func() {
		if !cleanupAttempted {
			if err := unlinkCentralProfileStage(r.directoryFile.file, stage, staged); err != nil {
				result = centralProfileError("publication_uncertain")
				r.publicationRetained = true
			}
		}
	}()
	if _, err := staged.Write(raw); err != nil {
		return centralProfileError("publication_failed")
	}
	if staged.Sync() != nil || r.recheck(ctx) != nil {
		return centralProfileError("publication_failed")
	}
	info, err := staged.Stat()
	named, namedErr := os.Lstat(filepath.Join(r.directory, stage))
	if err != nil || namedErr != nil || !centralFileMode(info, r.uid, 0600) || privatefs.CheckDescriptor(staged, privatefs.PrivateObject) != nil || !hostReadMetadataEqual(info, named) {
		return centralProfileError("publication_failed")
	}
	if unix.Linkat(dirfd, stage, dirfd, centralProfileRegistrationName, 0) != nil {
		return centralProfileError("already_registered")
	}
	r.publicationRetained = true
	cleanupAttempted = true
	if unlinkCentralProfileStage(r.directoryFile.file, stage, staged) != nil {
		return centralProfileError("publication_uncertain")
	}
	final, err := staged.Stat()
	named, namedErr = os.Lstat(filepath.Join(r.directory, centralProfileRegistrationName))
	if err != nil || namedErr != nil || !centralFileMode(final, r.uid, 0600) || !os.SameFile(info, final) || !hostReadMetadataEqual(final, named) {
		return centralProfileError("publication_uncertain")
	}
	if r.directoryFile.file.Sync() != nil {
		return centralProfileError("publication_uncertain")
	}
	return nil
}

func centralSelectionPath(path string, workspaces []string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !canonicalProfilePath(filepath.Dir(path)) {
		return false
	}
	for _, root := range workspaces {
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return false
		}
	}
	return true
}
