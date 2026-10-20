//go:build linux || darwin

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/controlLogix/agentmux/platform/internal/wirejson"
	"github.com/controlLogix/agentmux/platform/kernel/assembly"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/launcher"
	"github.com/controlLogix/agentmux/platform/privatefs"
	protected "github.com/controlLogix/agentmux/platform/runtime"
	"golang.org/x/sys/unix"
)

const ownerPreparationRequestLimit = 64 * 1024
const ownerPreparationCommandLimit = 10 * time.Second

var ownerPreparationDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type ownerPreparationArguments struct {
	path, digest string
	apply        bool
}
type ownerPreparationApplyFlag struct{ present bool }

func (*ownerPreparationApplyFlag) String() string   { return "false" }
func (*ownerPreparationApplyFlag) IsBoolFlag() bool { return true }
func (f *ownerPreparationApplyFlag) Set(value string) error {
	if f.present || value != "true" {
		return errors.New("owner_profile_preparation_arguments_invalid")
	}
	f.present = true
	return nil
}

func parseOwnerProfilePreparation(args []string) (ownerPreparationArguments, error) {
	invalid := func() (ownerPreparationArguments, error) {
		return ownerPreparationArguments{}, errors.New("owner_profile_preparation_arguments_invalid")
	}
	if len(args) < 3 || len(args) > 6 || (args[0] != "prepare-owner-profile" && args[0] != "recover-owner-profile") {
		return invalid()
	}
	for _, arg := range args {
		if len(arg) > 4096 || !utf8.ValidString(arg) || strings.IndexFunc(arg, unicode.IsControl) >= 0 {
			return invalid()
		}
	}
	var result ownerPreparationArguments
	path, digest := singleApplicationFlag{value: &result.path}, singleApplicationFlag{value: &result.digest}
	apply := ownerPreparationApplyFlag{}
	flags := flag.NewFlagSet("prepare-owner-profile", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Var(&path, "request", "Explicit private owner preparation request")
	flags.Var(&digest, "request-sha256", "Independently approved request digest")
	flags.Var(&apply, "apply", "Apply the explicitly requested profile action")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || !path.present || !digest.present || !filepath.IsAbs(result.path) || filepath.Clean(result.path) != result.path || !ownerPreparationDigest.MatchString(result.digest) {
		return invalid()
	}
	result.apply = apply.present
	return result, nil
}

// The wire format contains declarations and a release public key, never broker
// passwords, private keys or client login material. The digest is approved
// independently of this file; a hash does not authenticate its business owner.
type ownerPreparationDocument struct {
	CoreHub                *launcher.CoreHubSelection     `json:"coreHub,omitempty"`
	SchemaVersion          string                         `json:"schemaVersion"`
	Owner                  launcher.OwnerEnrollment       `json:"owner"`
	Context                launcher.CentralProfileContext `json:"context"`
	ClientInstallationID   string                         `json:"clientInstallationId"`
	ApprovedWorkspaceRoots []string                       `json:"approvedWorkspaceRoots"`
	Release                struct {
		PackageDirectory      string             `json:"packageDirectory"`
		PublicKeyHex          string             `json:"publicKeyHex"`
		ReleaseManifestDigest string             `json:"releaseManifestDigest"`
		ReleaseAuthority      assembly.Authority `json:"releaseAuthority"`
		ReleaseVersion        string             `json:"releaseVersion"`
		KernelAPIMajor        int                `json:"kernelApiMajor"`
	} `json:"release"`
	RuntimeExecutable struct {
		Path   string `json:"path"`
		Digest string `json:"digest"`
	} `json:"runtimeExecutable"`
	Docker         launcher.ProfileDocker `json:"docker"`
	HostPort       int                    `json:"hostPort"`
	ComposeProject string                 `json:"composeProject"`
	ServerName     string                 `json:"serverName"`
	Domain         string                 `json:"domain"`
	MaxMemoryBytes int64                  `json:"maxMemoryBytes"`
	MaxFileBytes   int64                  `json:"maxFileBytes"`
	Limits         struct {
		StartupMilliseconds   int64 `json:"startupMilliseconds"`
		ProbeMilliseconds     int64 `json:"probeMilliseconds"`
		RoleStartMilliseconds int64 `json:"roleStartMilliseconds"`
		StopGraceMilliseconds int64 `json:"stopGraceMilliseconds"`
		ReapMilliseconds      int64 `json:"reapMilliseconds"`
	} `json:"limits"`
}

func ownerPreparationFields(raw []byte, required, optional, nullable []string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, errors.New("owner_profile_preparation_request_invalid")
	}
	allowed, nulls := map[string]bool{}, map[string]bool{}
	for _, key := range append(append([]string(nil), required...), optional...) {
		allowed[key] = true
	}
	for _, key := range nullable {
		nulls[key] = true
	}
	for key, value := range fields {
		if !allowed[key] || (string(value) == "null" && !nulls[key]) {
			return nil, errors.New("owner_profile_preparation_request_invalid")
		}
	}
	for _, key := range required {
		if _, ok := fields[key]; !ok {
			return nil, errors.New("owner_profile_preparation_request_invalid")
		}
	}
	return fields, nil
}

func decodeOwnerPreparationRequest(raw []byte) (launcher.OwnerProfilePreparationRequest, error) {
	invalid := func() (launcher.OwnerProfilePreparationRequest, error) {
		return launcher.OwnerProfilePreparationRequest{}, errors.New("owner_profile_preparation_request_invalid")
	}
	if wirejson.Validate(raw, ownerPreparationRequestLimit) != nil {
		return invalid()
	}
	f, err := ownerPreparationFields(raw, []string{"schemaVersion", "owner", "context", "clientInstallationId", "approvedWorkspaceRoots", "release", "runtimeExecutable", "docker", "hostPort", "composeProject", "serverName", "domain", "maxMemoryBytes", "maxFileBytes", "limits"}, []string{"coreHub"}, nil)
	if err != nil {
		return invalid()
	}
	owner, err := ownerPreparationFields(f["owner"], []string{"schemaVersion", "ownerUid", "principalId", "authenticatedIdentityRef", "scope", "instanceId", "profileId", "releaseFingerprint"}, nil, nil)
	if err != nil {
		return invalid()
	}
	release, err := ownerPreparationFields(f["release"], []string{"packageDirectory", "publicKeyHex", "releaseManifestDigest", "releaseAuthority", "releaseVersion", "kernelApiMajor"}, nil, nil)
	if err != nil {
		return invalid()
	}
	for _, check := range []struct {
		raw                          []byte
		required, optional, nullable []string
	}{
		{f["context"], nil, []string{"environment", "project"}, nil},
		{owner["authenticatedIdentityRef"], []string{"id", "ownerHubId", "revision"}, nil, nil},
		{owner["scope"], []string{"organizationId", "projectId", "workspaceId"}, nil, []string{"projectId", "workspaceId"}},
		{release["releaseAuthority"], []string{"id", "ownerHubId", "revision"}, nil, nil},
		{f["runtimeExecutable"], []string{"path", "digest"}, nil, nil},
		{f["docker"], []string{"backend", "executable", "context", "endpoint", "engineId", "clientVersion", "serverVersion", "composeVersion"}, nil, nil},
		{f["limits"], []string{"startupMilliseconds", "probeMilliseconds", "roleStartMilliseconds", "stopGraceMilliseconds", "reapMilliseconds"}, nil, nil},
	} {
		if _, err := ownerPreparationFields(check.raw, check.required, check.optional, check.nullable); err != nil {
			return invalid()
		}
	}
	if core, present := f["coreHub"]; present {
		if _, err := ownerPreparationFields(core, []string{"selection", "sha256"}, nil, nil); err != nil {
			return invalid()
		}
	}
	var d ownerPreparationDocument
	if protocol.DecodeClosedJSON(raw, &d, ownerPreparationRequestLimit) != nil || d.SchemaVersion != protocol.Version || d.Owner.SchemaVersion != protocol.Version || d.Owner.OwnerUID != uint32(os.Geteuid()) || !centralRegistrationProfileID.MatchString(d.Owner.ProfileID) || !regexp.MustCompile(`^instance_[0-9a-f]{32}$`).MatchString(d.Owner.InstanceID) || !protected.ValidClientInstallationID(d.ClientInstallationID) || !ownerPreparationDigest.MatchString(d.Owner.ReleaseFingerprint) || d.Owner.ReleaseFingerprint != d.Release.ReleaseManifestDigest || !ownerPreparationDigest.MatchString(d.RuntimeExecutable.Digest) || d.Docker.Backend != launcher.NativeUnix || d.HostPort < 1 || d.HostPort > 65535 || d.MaxMemoryBytes <= 0 || d.MaxFileBytes <= 0 || len(d.ApprovedWorkspaceRoots) < 1 || len(d.ApprovedWorkspaceRoots) > 16 {
		return invalid()
	}
	if d.CoreHub != nil && (!ownerPreparationCanonicalPath(d.CoreHub.Selection) || !ownerPreparationDigest.MatchString(d.CoreHub.SHA256)) {
		return invalid()
	}
	if d.Context.Environment == nil && d.Context.Project == nil {
		return invalid()
	}
	for _, v := range []*string{d.Context.Environment, d.Context.Project} {
		if v != nil && (*v == "" || len(*v) > 128 || strings.TrimSpace(*v) != *v || strings.IndexFunc(*v, func(r rune) bool { return unicode.IsControl(r) || r == '\u2028' || r == '\u2029' }) >= 0) {
			return invalid()
		}
	}
	seen := map[string]bool{}
	for _, path := range d.ApprovedWorkspaceRoots {
		if !ownerPreparationCanonicalPath(path) || seen[path] {
			return invalid()
		}
		seen[path] = true
	}
	for _, path := range []string{d.Release.PackageDirectory, d.RuntimeExecutable.Path, d.Docker.Executable} {
		if !ownerPreparationCanonicalPath(path) {
			return invalid()
		}
	}
	if d.RuntimeExecutable.Path != filepath.Join(d.Release.PackageDirectory, "agentmux-runtime") {
		return invalid()
	}
	key, err := hex.DecodeString(d.Release.PublicKeyHex)
	if err != nil || len(key) != ed25519.PublicKeySize || hex.EncodeToString(key) != d.Release.PublicKeyHex {
		return invalid()
	}
	l := d.Limits
	if l.StartupMilliseconds < 1 || l.StartupMilliseconds > 60000 || l.ProbeMilliseconds < 1 || l.ProbeMilliseconds > 5000 || l.RoleStartMilliseconds < 1 || l.RoleStartMilliseconds > 30000 || l.StopGraceMilliseconds < 1 || l.StopGraceMilliseconds > 10000 || l.ReapMilliseconds < 1 || l.ReapMilliseconds > 10000 {
		return invalid()
	}
	return launcher.OwnerProfilePreparationRequest{CoreHub: d.CoreHub, Owner: d.Owner, Context: d.Context, ClientInstallationID: d.ClientInstallationID, ApprovedWorkspaceRoots: d.ApprovedWorkspaceRoots, Release: launcher.ReleasePolicy{PackageDirectory: d.Release.PackageDirectory, PublicKey: key, ReleaseManifestDigest: d.Release.ReleaseManifestDigest, ReleaseAuthority: d.Release.ReleaseAuthority, ReleaseVersion: d.Release.ReleaseVersion, KernelAPIMajor: d.Release.KernelAPIMajor}, RuntimeExecutablePath: d.RuntimeExecutable.Path, RuntimeExecutableDigest: d.RuntimeExecutable.Digest, Docker: d.Docker, HostPort: d.HostPort, ComposeProject: d.ComposeProject, ServerName: d.ServerName, Domain: d.Domain, MaxMemoryBytes: d.MaxMemoryBytes, MaxFileBytes: d.MaxFileBytes, StartupTimeout: time.Duration(l.StartupMilliseconds) * time.Millisecond, ProbeTimeout: time.Duration(l.ProbeMilliseconds) * time.Millisecond, Deadlines: protected.Deadlines{StartTimeout: time.Duration(l.RoleStartMilliseconds) * time.Millisecond, StopGrace: time.Duration(l.StopGraceMilliseconds) * time.Millisecond, ReapTimeout: time.Duration(l.ReapMilliseconds) * time.Millisecond}}, nil
}

func ownerPreparationCanonicalPath(path string) bool {
	return len(path) <= 4096 && filepath.IsAbs(path) && filepath.Clean(path) == path && strings.IndexFunc(path, unicode.IsControl) < 0
}

type ownerPreparationRequestEntry struct {
	file      *os.File
	path      string
	info      os.FileInfo
	directory bool
}
type ownerPreparationRequestOwner struct {
	entries  []ownerPreparationRequestEntry
	digest   string
	closed   bool
	closeErr error
}

func (r *ownerPreparationRequestOwner) Close() error {
	if r.closed {
		return r.closeErr
	}
	r.closed = true
	for i := len(r.entries) - 1; i >= 0; i-- {
		if r.entries[i].file.Close() != nil {
			r.closeErr = errors.New("owner_profile_preparation_request_cleanup_pending")
		}
	}
	return r.closeErr
}

func ownerPreparationSame(a, b os.FileInfo, directory bool) bool {
	if a == nil || b == nil || !os.SameFile(a, b) || a.Mode() != b.Mode() {
		return false
	}
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	if !xok || !yok || x.Uid != y.Uid || x.Gid != y.Gid {
		return false
	}
	if directory {
		return true
	}
	if x.Nlink != y.Nlink || a.Size() != b.Size() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	xv, yv := reflect.ValueOf(x).Elem(), reflect.ValueOf(y).Elem()
	for _, field := range []string{"Ctim", "Ctimespec"} {
		a, b := xv.FieldByName(field), yv.FieldByName(field)
		if a.IsValid() && b.IsValid() && a.CanInterface() && b.CanInterface() {
			return reflect.DeepEqual(a.Interface(), b.Interface())
		}
	}
	return false
}

func (r *ownerPreparationRequestOwner) Recheck(ctx context.Context) error {
	invalid := errors.New("owner_profile_preparation_request_changed")
	if r == nil || r.closed || ctx == nil || ctx.Err() != nil || len(r.entries) == 0 {
		return invalid
	}
	for _, entry := range r.entries {
		held, err := entry.file.Stat()
		named, namedErr := os.Lstat(entry.path)
		kind := privatefs.PrivateObject
		if entry.directory {
			kind = privatefs.PublicAncestor
		}
		if err != nil || namedErr != nil || !ownerPreparationSame(entry.info, held, entry.directory) || !ownerPreparationSame(entry.info, named, entry.directory) || privatefs.CheckDescriptor(entry.file, kind) != nil || ctx.Err() != nil {
			return invalid
		}
	}
	entry := r.entries[len(r.entries)-1]
	raw, err := io.ReadAll(io.NewSectionReader(entry.file, 0, ownerPreparationRequestLimit+1))
	final, statErr := entry.file.Stat()
	named, namedErr := os.Lstat(entry.path)
	if err != nil || statErr != nil || namedErr != nil || ownerPreparationSHA(raw) != r.digest || !ownerPreparationSame(entry.info, final, false) || !ownerPreparationSame(entry.info, named, false) || ctx.Err() != nil {
		return invalid
	}
	return nil
}

func ownerPreparationSHA(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func openOwnerPreparationRequest(ctx context.Context, args ownerPreparationArguments) (*ownerPreparationRequestOwner, []byte, error) {
	r := &ownerPreparationRequestOwner{digest: args.digest}
	fail := func() (*ownerPreparationRequestOwner, []byte, error) {
		if r.Close() != nil {
			return r, nil, r.closeErr
		}
		return nil, nil, errors.New("owner_profile_preparation_request_refused")
	}
	parent, current := unix.AT_FDCWD, "/"
	parts := strings.Split(strings.TrimPrefix(args.path, "/"), "/")
	if len(parts) > 128 {
		return fail()
	}
	for i := -1; i < len(parts); i++ {
		if ctx.Err() != nil {
			return fail()
		}
		name := "/"
		if i >= 0 {
			name = parts[i]
			current = filepath.Join(current, name)
		}
		directory := i < len(parts)-1
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
		if directory {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(parent, name, flags, 0)
		if err != nil {
			return fail()
		}
		file := os.NewFile(uintptr(fd), "owner-preparation-request")
		r.entries = append(r.entries, ownerPreparationRequestEntry{file: file, path: current, directory: directory})
		info, err := file.Stat()
		if err != nil {
			return fail()
		}
		r.entries[len(r.entries)-1].info = info
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fail()
		}
		kind := privatefs.PrivateObject
		if directory {
			kind = privatefs.PublicAncestor
			if !info.IsDir() || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || (info.Mode().Perm()&0022 != 0 && !(stat.Uid == 0 && info.Mode()&os.ModeSticky != 0)) {
				return fail()
			}
		} else if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || info.Size() < 1 || info.Size() > ownerPreparationRequestLimit {
			return fail()
		}
		if privatefs.CheckDescriptor(file, kind) != nil {
			return fail()
		}
		parent = fd
	}
	entry := r.entries[len(r.entries)-1]
	raw, err := io.ReadAll(io.NewSectionReader(entry.file, 0, ownerPreparationRequestLimit+1))
	if err != nil || ownerPreparationSHA(raw) != args.digest || r.Recheck(ctx) != nil {
		return fail()
	}
	return r, raw, nil
}

type ownerPreparationCommandOwner interface{ Close() error }
type ownerPreparationCommandPrepare func(context.Context, launcher.OwnerProfilePreparationRequest) (ownerPreparationCommandOwner, error)
type ownerPreparationCommandOwners struct {
	request     *ownerPreparationRequestOwner
	preparation ownerPreparationCommandOwner
	closed      bool
	closeErr    error
}

func (o *ownerPreparationCommandOwners) Close() error {
	if o.closed {
		return o.closeErr
	}
	o.closed = true
	var failures []error
	if o.preparation != nil {
		if err := o.preparation.Close(); err != nil {
			failures = append(failures, err)
		}
	}
	if o.request != nil {
		if err := o.request.Close(); err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) > 0 {
		o.closeErr = &ownerPreparationCommandFailure{owner: o, cause: errors.Join(failures...), outcome: "review_required"}
	}
	return o.closeErr
}

type ownerPreparationCommandFailure struct {
	owner         *ownerPreparationCommandOwners
	cause         error
	outcome       string
	resultEmitted bool
}

func (e *ownerPreparationCommandFailure) Error() string {
	return "owner_profile_preparation_" + e.outcome
}
func (e *ownerPreparationCommandFailure) Unwrap() error              { return e.cause }
func (e *ownerPreparationCommandFailure) Format(s fmt.State, _ rune) { fmt.Fprint(s, e.Error()) }
func (e *ownerPreparationCommandFailure) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.Error())
}

type ownerPreparationCommandResult struct {
	SchemaVersion string `json:"schemaVersion"`
	Kind          string `json:"kind"`
	Outcome       string `json:"outcome"`
	Action        string `json:"action"`
	Message       string `json:"message"`
}

func ownerPreparationResult(outcome string) ownerPreparationCommandResult {
	r := ownerPreparationCommandResult{protocol.Version, "owner-profile-preparation-result", outcome, "check_approved_request", "Preparation was refused. Check the approved private request and installed prerequisites."}
	switch outcome {
	case "request_checked":
		r.Action = "review_then_apply"
		r.Message = "The private request format and pinned bytes were checked. Apply requires admission of the declared owner setup, release and installed code."
	case "prepared":
		r.Action = "select_registered_profile"
		r.Message = "Owner profile preparation and registration are complete. Startup and application readiness were not checked."
	case "review_required":
		r.Action = "inspect_partial_preparation_before_retry"
		r.Message = "Preparation or cleanup is uncertain. Keep the original recovery owner and inspect partial setup before retrying. Process exit does not complete recovery."
	}
	return r
}

func ownerPreparationFailureResult(outcome string, failure error) ownerPreparationCommandResult {
	r := ownerPreparationResult(outcome)
	if errors.Is(failure, context.DeadlineExceeded) {
		r.Message = "The preparation deadline expired. " + r.Message
	} else if errors.Is(failure, context.Canceled) {
		r.Message = "Preparation was canceled. " + r.Message
	}
	return r
}

func runOwnerProfilePreparation(ctx context.Context, args []string, output io.Writer) error {
	return runOwnerProfilePreparationWith(ctx, args, output, func(ctx context.Context, request launcher.OwnerProfilePreparationRequest) (ownerPreparationCommandOwner, error) {
		prepare := launcher.PrepareOwnerProfile
		if len(args) > 0 && args[0] == "recover-owner-profile" {
			prepare = launcher.RecoverOwnerProfile
		}
		owner, err := prepare(ctx, request)
		if owner == nil {
			return nil, err
		}
		return owner, err
	})
}

func runOwnerProfilePreparationWith(parent context.Context, args []string, output io.Writer, prepare ownerPreparationCommandPrepare) error {
	if parent == nil || parent.Err() != nil || output == nil || prepare == nil {
		return errors.New("request_context_invalid")
	}
	total, cancel := context.WithTimeout(parent, ownerPreparationCommandLimit)
	defer cancel()
	arguments, err := parseOwnerProfilePreparation(args)
	if err != nil {
		return err
	}
	work, cancelWork := frontendWorkContext(total)
	defer cancelWork()
	held, raw, failure := openOwnerPreparationRequest(work, arguments)
	owners := &ownerPreparationCommandOwners{request: held}
	outcome := "refused"
	if failure == nil {
		var request launcher.OwnerProfilePreparationRequest
		request, failure = decodeOwnerPreparationRequest(raw)
		if failure == nil && held.Recheck(work) != nil {
			failure = errors.New("owner_profile_preparation_request_changed")
		}
		if failure == nil && arguments.apply {
			owners.preparation, failure = prepare(work, request)
			if failure == nil && owners.preparation == nil {
				failure = errors.New("owner_profile_preparation_owner_missing")
			}
			if failure == nil && held.Recheck(work) != nil {
				failure = errors.New("owner_profile_preparation_request_changed")
			}
			if failure == nil {
				outcome = "prepared"
			}
		} else if failure == nil {
			outcome = "request_checked"
		}
	}
	if failure != nil && (owners.preparation != nil || (held != nil && held.closeErr != nil)) {
		outcome = "review_required"
	} else if closeErr := owners.Close(); closeErr != nil {
		failure = closeErr
		outcome = "review_required"
	}
	if err := writePreparationJSON(total, output, ownerPreparationFailureResult(outcome, failure)); err != nil {
		if owners.preparation != nil {
			outcome = "review_required"
		} else if outcome == "request_checked" {
			outcome = "refused"
		}
		return &ownerPreparationCommandFailure{owner: owners, cause: errors.Join(failure, err), outcome: outcome}
	}
	if failure != nil {
		return &ownerPreparationCommandFailure{owner: owners, cause: failure, outcome: outcome, resultEmitted: true}
	}
	return nil
}

func ownerProfilePreparationDiagnostic(err error) (ownerPreparationCommandResult, bool) {
	failure, ok := err.(*ownerPreparationCommandFailure)
	if !ok {
		return ownerPreparationCommandResult{}, false
	}
	return ownerPreparationFailureResult(failure.outcome, failure.cause), true
}

func writeOwnerProfilePreparationDiagnostic(ctx context.Context, output io.Writer, failure error) error {
	// The runner may have already emitted the complete terminal result. Failed
	// or partial stdout writes still need the normal stderr fallback.
	if recorded, ok := failure.(*ownerPreparationCommandFailure); ok && recorded.resultEmitted {
		return nil
	}
	if result, ok := ownerProfilePreparationDiagnostic(failure); ok {
		return writePreparationJSON(ctx, output, result)
	}
	return writePreparationJSON(ctx, output, launcher.ProjectRequestDiagnostic(failure))
}
