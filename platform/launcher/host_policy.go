//go:build linux || darwin

package launcher

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"strings"
	"syscall"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/assembly"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/privatefs"
	protected "github.com/controlLogix/agentmux/platform/runtime"
	"golang.org/x/sys/unix"
)

// Selection comes from an explicit installed-launcher invocation. Workspace
// roots and the current OS owner are not read from the policy being checked.
type HostPolicySelection struct {
	Path           string
	OwnerUID       uint32
	WorkspaceRoots []string
}

type hostPolicyRelease struct {
	PackageDirectory      string             `json:"packageDirectory"`
	PublicKeyHex          string             `json:"publicKeyHex"`
	ReleaseManifestDigest string             `json:"releaseManifestDigest"`
	ReleaseAuthority      assembly.Authority `json:"releaseAuthority"`
	ReleaseVersion        string             `json:"releaseVersion"`
	KernelAPIMajor        int                `json:"kernelApiMajor"`
}
type hostPolicyExecutable struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}
type hostPolicyLimits struct {
	StartupMilliseconds   int64 `json:"startupMilliseconds"`
	ProbeMilliseconds     int64 `json:"probeMilliseconds"`
	RoleStartMilliseconds int64 `json:"roleStartMilliseconds"`
	StopGraceMilliseconds int64 `json:"stopGraceMilliseconds"`
	ReapMilliseconds      int64 `json:"reapMilliseconds"`
}
type hostPolicyRecord struct {
	SchemaVersion     string                     `json:"schemaVersion"`
	OwnerUID          uint32                     `json:"ownerUid"`
	ProfileDirectory  string                     `json:"profileDirectory"`
	ProfileID         string                     `json:"profileId"`
	InstanceID        string                     `json:"instanceId"`
	Release           hostPolicyRelease          `json:"release"`
	RuntimeExecutable hostPolicyExecutable       `json:"runtimeExecutable"`
	Owner             OwnerEnrollment            `json:"owner"`
	ServerName        string                     `json:"serverName"`
	Domain            string                     `json:"domain"`
	PublicEndpoint    string                     `json:"publicEndpoint"`
	PublicContextName string                     `json:"publicContextName"`
	Limits            hostPolicyLimits           `json:"limits"`
	OwnerBridge       *OwnerBridgeCredentialRefs `json:"ownerBridge"`
}

// EnrolledHostPolicy retains external declarations, not startup observations.
// No method enrolls identities, installs files or discovers workspace settings.
type EnrolledHostPolicy struct {
	selection HostPolicySelection
	record    hostPolicyRecord
	policy    HostPolicy
}

func hostPolicyError(code string) error { return &hostPolicyFailure{code: code} }

func canonicalHostFilePath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !canonicalProfilePath(filepath.Dir(path)) {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}

// A policy root precedes release declarations, so it cannot use the profile
// opener that requires an already trusted release fingerprint.
func openPrivateHostRoot(directory string, uid uint32, workspaces []string) (*os.Root, error) {
	if uid != uint32(os.Geteuid()) || !canonicalProfilePath(directory) || len(workspaces) == 0 {
		return nil, hostPolicyError("private_root_invalid")
	}
	for _, workspace := range workspaces {
		resolved, e := filepath.EvalSymlinks(workspace)
		if e != nil {
			return nil, hostPolicyError("workspace_invalid")
		}
		rel, e := filepath.Rel(resolved, directory)
		if e != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return nil, hostPolicyError("inside_workspace")
		}
	}
	before, e := os.Lstat(directory)
	if e != nil || !privateProfileInfo(before, uid, true) {
		return nil, hostPolicyError("private_root_invalid")
	}
	ancestors, e := trustedHostAncestors(directory, uid)
	if e != nil {
		return nil, e
	}
	root, e := os.OpenRoot(directory)
	if e != nil {
		return nil, hostPolicyError("private_root_unavailable")
	}
	after, e := root.Stat(".")
	if e != nil || !os.SameFile(before, after) || !privateProfileInfo(after, uid, true) || checkPrivateProfileRoot(root) != nil {
		root.Close()
		return nil, hostPolicyError("private_root_changed")
	}
	current, e := trustedHostAncestors(directory, uid)
	if e != nil || len(current) != len(ancestors) {
		root.Close()
		return nil, hostPolicyError("ancestor_changed")
	}
	for i := range ancestors {
		if !os.SameFile(ancestors[i], current[i]) {
			root.Close()
			return nil, hostPolicyError("ancestor_changed")
		}
	}
	return root, nil
}

// A private leaf cannot protect a path whose enclosing directory another OS
// user may replace. Root-owned sticky temporary directories remain valid.
func trustedHostAncestors(directory string, uid uint32) ([]os.FileInfo, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, hostPolicyError("ancestor_invalid")
	}
	parts := strings.Split(strings.TrimPrefix(directory, "/"), "/")
	if directory == "/" {
		parts = nil
	}
	if len(parts) > 128 {
		return nil, hostPolicyError("ancestor_invalid")
	}
	var entries []os.FileInfo
	var handles []*os.File
	defer func() {
		for _, file := range handles {
			file.Close()
		}
	}()
	parent := unix.AT_FDCWD
	for i := -1; i < len(parts); i++ {
		name := "/"
		if i >= 0 {
			name = parts[i]
		}
		fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, hostPolicyError("ancestor_invalid")
		}
		file := os.NewFile(uintptr(fd), "trusted-profile-ancestor")
		handles = append(handles, file)
		info, err := file.Stat()
		if err != nil || !info.IsDir() {
			return nil, hostPolicyError("ancestor_invalid")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != 0 && stat.Uid != uid) || (info.Mode().Perm()&0022 != 0 && !(stat.Uid == 0 && info.Mode()&os.ModeSticky != 0)) {
			return nil, hostPolicyError("ancestor_untrusted")
		}
		kind := privatefs.PublicAncestor
		if i == len(parts)-1 {
			kind = privatefs.PrivateObject
		}
		if privatefs.CheckDescriptor(file, kind) != nil {
			return nil, hostPolicyError("ancestor_access_denied")
		}
		entries = append(entries, info)
		parent = fd
	}
	return entries, nil
}

func LoadEnrolledHostPolicy(s HostPolicySelection) (*EnrolledHostPolicy, error) {
	if uint32(os.Geteuid()) != s.OwnerUID || !canonicalHostFilePath(s.Path) || len(s.WorkspaceRoots) == 0 || len(s.WorkspaceRoots) > 16 {
		return nil, hostPolicyError("selection_invalid")
	}
	seen := map[string]bool{}
	for _, root := range s.WorkspaceRoots {
		info, e := os.Stat(root)
		if e != nil || !info.IsDir() || !canonicalProfilePath(root) || seen[root] {
			return nil, hostPolicyError("workspace_invalid")
		}
		seen[root] = true
	}
	root, e := openPrivateHostRoot(filepath.Dir(s.Path), s.OwnerUID, s.WorkspaceRoots)
	if e != nil {
		return nil, hostPolicyError("private_policy_root_invalid")
	}
	defer root.Close()
	raw, e := hostPrivateRead(root, filepath.Base(s.Path), s.OwnerUID, 64*1024)
	if e != nil || !releaseEscapesValid(raw) {
		return nil, hostPolicyError("private_policy_invalid")
	}
	fields, e := releaseFields(raw, "schemaVersion", "ownerUid", "profileDirectory", "profileId", "instanceId", "release", "runtimeExecutable", "owner", "serverName", "domain", "publicEndpoint", "publicContextName", "limits", "ownerBridge")
	if e != nil {
		return nil, hostPolicyError("fields_invalid")
	}
	checks := []struct {
		raw  []byte
		keys []string
	}{
		{fields["release"], []string{"packageDirectory", "publicKeyHex", "releaseManifestDigest", "releaseAuthority", "releaseVersion", "kernelApiMajor"}},
		{fields["runtimeExecutable"], []string{"path", "digest"}},
		{fields["limits"], []string{"startupMilliseconds", "probeMilliseconds", "roleStartMilliseconds", "stopGraceMilliseconds", "reapMilliseconds"}},
		{fields["owner"], []string{"schemaVersion", "ownerUid", "principalId", "authenticatedIdentityRef", "scope", "instanceId", "profileId", "releaseFingerprint"}},
	}
	for _, check := range checks {
		if _, e := releaseFields(check.raw, check.keys...); e != nil {
			return nil, hostPolicyError("fields_invalid")
		}
	}
	var record hostPolicyRecord
	if protocol.DecodeClosedJSON(raw, &record, 64*1024) != nil {
		return nil, hostPolicyError("decode_invalid")
	}
	if record.OwnerBridge != nil {
		if _, e := releaseFields(fields["ownerBridge"], "server", "client"); e != nil {
			return nil, hostPolicyError("fields_invalid")
		}
	}
	releaseParts, _ := releaseFields(fields["release"], "packageDirectory", "publicKeyHex", "releaseManifestDigest", "releaseAuthority", "releaseVersion", "kernelApiMajor")
	ownerParts, _ := releaseFields(fields["owner"], "schemaVersion", "ownerUid", "principalId", "authenticatedIdentityRef", "scope", "instanceId", "profileId", "releaseFingerprint")
	for _, check := range []struct {
		raw  []byte
		keys []string
	}{
		{releaseParts["releaseAuthority"], []string{"id", "ownerHubId", "revision"}},
		{ownerParts["authenticatedIdentityRef"], []string{"id", "ownerHubId", "revision"}},
		{ownerParts["scope"], []string{"organizationId", "projectId", "workspaceId"}},
	} {
		if _, e := releaseFields(check.raw, check.keys...); e != nil {
			return nil, hostPolicyError("fields_invalid")
		}
	}
	public, e := hex.DecodeString(record.Release.PublicKeyHex)
	l := record.Limits
	if e != nil || len(public) != ed25519.PublicKeySize || hex.EncodeToString(public) != record.Release.PublicKeyHex || record.SchemaVersion != "1.0.0" || record.OwnerUID != s.OwnerUID || !profileID.MatchString(record.ProfileID) || !profileInstanceID.MatchString(record.InstanceID) || record.Owner.ProfileID != record.ProfileID || record.Owner.InstanceID != record.InstanceID || record.Owner.OwnerUID != s.OwnerUID || record.Owner.ReleaseFingerprint != record.Release.ReleaseManifestDigest || !digest.MatchString(record.RuntimeExecutable.Digest) || !canonicalHostFilePath(record.RuntimeExecutable.Path) || !canonicalProfilePath(record.Release.PackageDirectory) || l.StartupMilliseconds < 1 || l.StartupMilliseconds > 60000 || l.ProbeMilliseconds < 1 || l.ProbeMilliseconds > 5000 || l.RoleStartMilliseconds < 1 || l.RoleStartMilliseconds > 30000 || l.StopGraceMilliseconds < 1 || l.StopGraceMilliseconds > 10000 || l.ReapMilliseconds < 1 || l.ReapMilliseconds > 10000 {
		return nil, hostPolicyError("declarations_invalid")
	}
	profilePolicy := ProfilePolicy{Directory: record.ProfileDirectory, OwnerUID: s.OwnerUID, WorkspaceRoots: append([]string(nil), s.WorkspaceRoots...), InstalledReleaseFingerprint: record.Release.ReleaseManifestDigest}
	policy := HostPolicy{Profile: profilePolicy, ExternalRelease: ReleasePolicy{PackageDirectory: record.Release.PackageDirectory, PublicKey: append(ed25519.PublicKey(nil), public...), ReleaseManifestDigest: record.Release.ReleaseManifestDigest, ReleaseAuthority: record.Release.ReleaseAuthority, ReleaseVersion: record.Release.ReleaseVersion, KernelAPIMajor: record.Release.KernelAPIMajor}, StartupTimeout: time.Duration(l.StartupMilliseconds) * time.Millisecond, ProbeTimeout: time.Duration(l.ProbeMilliseconds) * time.Millisecond, Deadlines: protected.Deadlines{StartTimeout: time.Duration(l.RoleStartMilliseconds) * time.Millisecond, StopGrace: time.Duration(l.StopGraceMilliseconds) * time.Millisecond, ReapTimeout: time.Duration(l.ReapMilliseconds) * time.Millisecond}}
	h := &EnrolledHostPolicy{selection: HostPolicySelection{Path: s.Path, OwnerUID: s.OwnerUID, WorkspaceRoots: append([]string(nil), s.WorkspaceRoots...)}, record: record, policy: policy}
	if _, _, e := h.Load(); e != nil {
		return nil, e
	}
	return h, nil
}

// Load validates the external release and actual private factory/role files.
// Returned BootstrapConfig contains secrets for trusted local bootstrap only.
func (h *EnrolledHostPolicy) Load() (BootstrapConfig, *OwnerStatus, error) {
	if h == nil {
		return BootstrapConfig{}, nil, hostPolicyError("unconfigured")
	}
	p, e := LoadProfile(h.policy.Profile)
	if e != nil {
		return BootstrapConfig{}, nil, hostPolicyError("profile_invalid")
	}
	declaration := p.Declaration()
	if declaration.ProfileID != h.record.ProfileID || declaration.InstanceID != h.record.InstanceID || declaration.NATSEndpoint != h.record.PublicEndpoint || declaration.Docker == nil || declaration.Docker.Context != h.record.PublicContextName {
		return BootstrapConfig{}, nil, hostPolicyError("profile_binding_invalid")
	}
	policy := h.policy
	if h.record.OwnerBridge != nil {
		settings, err := h.loadBridgeSettings()
		if err != nil {
			return BootstrapConfig{}, nil, err
		}
		policy.OwnerBridge = &settings
	}
	c, e := LoadBootstrapConfig(policy)
	if e != nil {
		return BootstrapConfig{}, nil, hostPolicyError("bootstrap_config_invalid")
	}
	if c.Health.ServerName != h.record.ServerName || c.Health.Domain != h.record.Domain || c.Kernel.Scope.HubID != h.record.Owner.Identity.OwnerHubID {
		return BootstrapConfig{}, nil, hostPolicyError("owner_binding_invalid")
	}
	owner, e := LoadOwnerStatus(OwnerPolicy{Profile: h.policy.Profile, Enrollment: h.record.Owner, KernelScope: c.Kernel.Scope, ServerName: h.record.ServerName, Domain: h.record.Domain, PublicEndpoint: h.record.PublicEndpoint, PublicContextName: h.record.PublicContextName})
	if e != nil {
		return BootstrapConfig{}, nil, hostPolicyError("owner_enrollment_invalid")
	}
	return c, owner, nil
}

func (h *EnrolledHostPolicy) Invocation() protected.HostInvocation {
	if h == nil {
		return protected.HostInvocation{}
	}
	return protected.HostInvocation{PolicyPath: h.selection.Path, WorkspaceRoots: append([]string(nil), h.selection.WorkspaceRoots...)}
}

func (h *EnrolledHostPolicy) PrepareHost(ctx context.Context) (*protected.InstalledHostImage, error) {
	if h == nil || ctx == nil || ctx.Err() != nil {
		return nil, hostPolicyError("context_invalid")
	}
	if goruntime.GOOS == "darwin" {
		image, err := protected.PrepareProtectedInstalledHost(ctx, h.record.RuntimeExecutable.Path, h.record.RuntimeExecutable.Digest, 128*1024*1024)
		if err != nil {
			return nil, &hostPolicyFailure{code: "executable_unqualified", cause: err}
		}
		return image, nil
	}
	root, e := openPrivateHostRoot(filepath.Dir(h.record.RuntimeExecutable.Path), h.selection.OwnerUID, h.selection.WorkspaceRoots)
	if e != nil {
		return nil, hostPolicyError("executable_root_invalid")
	}
	defer root.Close()
	name := filepath.Base(h.record.RuntimeExecutable.Path)
	before, e := root.Lstat(name)
	if e != nil || !privateProfileInfo(before, h.selection.OwnerUID, false) {
		return nil, hostPolicyError("executable_invalid")
	}
	file, e := assembly.OpenMember(root, name)
	if e != nil {
		return nil, hostPolicyError("executable_invalid")
	}
	defer file.Close()
	actual, e := file.Stat()
	if e != nil || !os.SameFile(before, actual) || !privateProfileInfo(actual, h.selection.OwnerUID, false) || privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil {
		return nil, hostPolicyError("executable_changed")
	}
	image, e := protected.PrepareInstalledHost(ctx, file, h.record.RuntimeExecutable.Digest, 128*1024*1024)
	if e != nil {
		return nil, hostPolicyError("executable_unqualified")
	}
	return image, nil
}

// loadBridgeSettings reads both private credential declarations before validating
// the broker factory. Neither credential can choose a different enrolled owner.
func (h *EnrolledHostPolicy) loadBridgeSettings() (deployment.OwnerBridgeSettings, error) {
	empty := deployment.OwnerBridgeSettings{}
	refs := h.record.OwnerBridge
	if refs == nil || refs.Server == refs.Client {
		return empty, hostPolicyError("bridge_unconfigured")
	}
	root, err := openProfileDirectory(h.policy.Profile)
	if err != nil {
		return empty, hostPolicyError("bridge_private_root_invalid")
	}
	defer root.Close()
	var settings deployment.OwnerBridgeSettings
	for _, item := range []struct{ name, role string }{{refs.Server, deployment.OwnerBridgeServerUser}, {refs.Client, deployment.OwnerBridgeClientUser}} {
		if !filepath.IsLocal(item.name) || filepath.Clean(item.name) != item.name || item.name == "." {
			return empty, hostPolicyError("bridge_reference_invalid")
		}
		raw, err := hostPrivateRead(root, item.name, h.selection.OwnerUID, protocol.MaxPayload)
		if err != nil || !releaseEscapesValid(raw) {
			return empty, hostPolicyError("bridge_credential_invalid")
		}
		fields, err := releaseFields(raw, "schemaVersion", "role", "scope", "owner", "password")
		if err != nil {
			return empty, hostPolicyError("bridge_fields_invalid")
		}
		scope, err := releaseFields(fields["scope"], "hubId", "instanceId", "profileId", "assemblyDigest", "releaseManifestDigest", "releaseVersion")
		if err != nil || scope == nil {
			return empty, hostPolicyError("bridge_fields_invalid")
		}
		owner, err := releaseFields(fields["owner"], "schemaVersion", "ownerUid", "principalId", "authenticatedIdentityRef", "scope", "instanceId", "profileId", "releaseFingerprint")
		if err != nil {
			return empty, hostPolicyError("bridge_fields_invalid")
		}
		if _, err = releaseFields(owner["authenticatedIdentityRef"], "id", "ownerHubId", "revision"); err != nil {
			return empty, hostPolicyError("bridge_fields_invalid")
		}
		if _, err = releaseFields(owner["scope"], "organizationId", "projectId", "workspaceId"); err != nil {
			return empty, hostPolicyError("bridge_fields_invalid")
		}
		var credential OwnerBridgeCredential
		if protocol.DecodeClosedJSON(raw, &credential, protocol.MaxPayload) != nil || credential.SchemaVersion != protocol.Version || credential.Role != item.role || !reflect.DeepEqual(credential.Owner, h.record.Owner) || !kernelStatusPassword.MatchString(credential.Password) || credential.Scope.HubID != h.record.Owner.Identity.OwnerHubID || credential.Scope.InstanceID != h.record.InstanceID || credential.Scope.ProfileID != h.record.ProfileID || credential.Scope.ReleaseManifestDigest != h.record.Release.ReleaseManifestDigest || credential.Scope.ReleaseVersion != h.record.Release.ReleaseVersion {
			return empty, hostPolicyError("bridge_binding_invalid")
		}
		if item.role == deployment.OwnerBridgeServerUser {
			settings.Scope = credential.Scope
			settings.ServerPassword = credential.Password
		} else {
			if credential.Scope != settings.Scope {
				return empty, hostPolicyError("bridge_binding_invalid")
			}
			settings.ClientPassword = credential.Password
		}
	}
	if _, err := deployment.OwnerBridgeSubjects(settings.Scope); err != nil {
		return empty, hostPolicyError("bridge_binding_invalid")
	}
	return settings, nil
}

func (h *EnrolledHostPolicy) BridgeClient() (*OwnerBridgeClient, error) {
	if h == nil || h.record.OwnerBridge == nil {
		return nil, hostPolicyError("bridge_unconfigured")
	}
	c, _, err := h.Load()
	if err != nil {
		return nil, err
	}
	return LoadOwnerBridgeClient(c, OwnerBridgeEnrollment{Owner: h.record.Owner, Credentials: *h.record.OwnerBridge})
}
func (h *EnrolledHostPolicy) BridgeServer() (*OwnerBridgeServer, time.Duration, error) {
	if h == nil || h.record.OwnerBridge == nil {
		return nil, 0, hostPolicyError("bridge_unconfigured")
	}
	c, owner, err := h.Load()
	if err != nil {
		return nil, 0, err
	}
	server, err := LoadOwnerBridgeServer(c, owner, OwnerBridgeEnrollment{Owner: h.record.Owner, Credentials: *h.record.OwnerBridge})
	return server, c.StartupTimeout, err
}

type EnsureInvocation struct {
	host *EnrolledHostPolicy
	id   string
}

func hostInvocationID(prefix string) (string, error) {
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return "", hostPolicyError("invocation_failed")
	}
	return prefix + hex.EncodeToString(nonce[:]), nil
}

// BeginEnsure identifies this real invocation, independently of runtime ownership.
func (h *EnrolledHostPolicy) BeginEnsure() (*EnsureInvocation, error) {
	if h == nil {
		return nil, hostPolicyError("unconfigured")
	}
	id, e := hostInvocationID("attempt_")
	if e != nil {
		return nil, e
	}
	return &EnsureInvocation{host: h, id: id}, nil
}
func (i *EnsureInvocation) ID() string {
	if i == nil {
		return ""
	}
	return i.id
}
func (i *EnsureInvocation) Observe(ctx context.Context) (StartupStatusObservation, error) {
	return i.Request(ctx, "ensure")
}

// Probe asks only whether this initial ensure has an authenticated response.
// A native no-responders hint grants no runtime ownership or readiness.
func (i *EnsureInvocation) Probe(ctx context.Context) (StartupStatusObservation, error) {
	if i == nil || ctx == nil || ctx.Err() != nil {
		return StartupStatusObservation{}, hostPolicyError("context_invalid")
	}
	client, err := i.host.BridgeClient()
	if err != nil {
		return StartupStatusObservation{}, err
	}
	return client.probe(ctx, i.id)
}
func (i *EnsureInvocation) Request(ctx context.Context, operation string) (StartupStatusObservation, error) {
	if i == nil || ctx == nil || ctx.Err() != nil {
		return StartupStatusObservation{}, hostPolicyError("context_invalid")
	}
	client, err := i.host.BridgeClient()
	if err != nil {
		return StartupStatusObservation{}, err
	}
	return client.Request(ctx, operation, i.id)
}
func (h *EnrolledHostPolicy) ObserveStatus(ctx context.Context) (StartupStatusObservation, error) {
	invocation, err := h.BeginEnsure()
	if err != nil {
		return StartupStatusObservation{}, err
	}
	return invocation.Request(ctx, "status")
}
