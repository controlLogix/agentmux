//go:build linux || darwin

package launcher

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/controlLogix/agentmux/platform/kernel/assembly"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/privatefs"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
)

const profileLimit = 64 * 1024

// ProfilePolicy comes from the installed launcher, not the profile being read.
type ProfilePolicy struct {
	Directory                   string
	WorkspaceRoots              []string
	OwnerUID                    uint32
	InstalledReleaseFingerprint string
}

type ProfileDocker struct {
	Backend        DockerBackend `json:"backend"`
	Executable     string        `json:"executable"`
	Context        string        `json:"context"`
	Endpoint       string        `json:"endpoint"`
	EngineID       string        `json:"engineId"`
	ClientVersion  string        `json:"clientVersion"`
	ServerVersion  string        `json:"serverVersion"`
	ComposeVersion string        `json:"composeVersion"`
}

// Profile contains declarations only. Loading it does not contact a service.
type Profile struct {
	SchemaVersion      string         `json:"schemaVersion"`
	ProfileID          string         `json:"profileId"`
	DisplayName        string         `json:"displayName"`
	InstanceID         string         `json:"instanceId"`
	OwnerUID           uint32         `json:"ownerUid"`
	ProfileDirectory   string         `json:"profileDirectory"`
	Mode               string         `json:"mode"`
	ReleaseFingerprint string         `json:"releaseFingerprint"`
	ConfigDigest       string         `json:"configDigest"`
	NATSEndpoint       string         `json:"natsEndpoint"`
	ServerTrustRef     string         `json:"serverTrustRef,omitempty"`
	ServerTrustDigest  string         `json:"serverTrustDigest,omitempty"`
	CredentialRef      string         `json:"credentialRef,omitempty"`
	OrganizationID     string         `json:"organizationId,omitempty"`
	ProjectID          string         `json:"projectId,omitempty"`
	ComposeProject     string         `json:"composeProject,omitempty"`
	Docker             *ProfileDocker `json:"docker,omitempty"`
}

type LoadedProfile struct{ profile Profile }
type ProfileSummary struct{ ProfileID, InstanceID, DisplayName, Mode, ComposeProject, ReleaseFingerprint string }

func (p LoadedProfile) Summary() ProfileSummary {
	v := p.profile
	return ProfileSummary{v.ProfileID, v.InstanceID, v.DisplayName, v.Mode, v.ComposeProject, v.ReleaseFingerprint}
}

// Declaration returns a copy for trusted launcher code, not public presentation.
func (p LoadedProfile) Declaration() Profile {
	v := p.profile
	if v.Docker != nil {
		d := *v.Docker
		v.Docker = &d
	}
	return v
}

func (p LoadedProfile) LocalDocker() (ProfileDocker, bool) {
	if p.profile.Mode != "local" || p.profile.Docker == nil {
		return ProfileDocker{}, false
	}
	return *p.profile.Docker, true
}

var profileID = regexp.MustCompile(`^profile_[0-9a-f]{32}$`)
var profileInstanceID = regexp.MustCompile(`^instance_[0-9a-f]{32}$`)
var profileToken = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,95}$`)
var profileHostLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func profileError(code string) error { return errors.New("profile_" + code) }

func privateProfileInfo(info os.FileInfo, uid uint32, directory bool) bool {
	owner, ok := info.Sys().(*syscall.Stat_t)
	return ok && owner.Uid == uid && info.Mode().Perm()&0077 == 0 && info.Mode()&os.ModeSymlink == 0 && ((directory && info.IsDir()) || (!directory && info.Mode().IsRegular() && owner.Nlink == 1))
}

func canonicalProfilePath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return false
		}
		if filepath.Dir(current) == current {
			return true
		}
	}
}

func openProfileDirectory(policy ProfilePolicy) (*os.Root, error) {
	if policy.OwnerUID != uint32(os.Geteuid()) || !digest.MatchString(policy.InstalledReleaseFingerprint) || !canonicalProfilePath(policy.Directory) || len(policy.WorkspaceRoots) == 0 {
		return nil, profileError("invalid_policy")
	}
	for _, workspace := range policy.WorkspaceRoots {
		resolved, err := filepath.EvalSymlinks(workspace)
		if err != nil || !filepath.IsAbs(workspace) {
			return nil, profileError("invalid_workspace")
		}
		rel, err := filepath.Rel(resolved, policy.Directory)
		if err != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return nil, profileError("inside_workspace")
		}
	}
	info, err := os.Lstat(policy.Directory)
	if err != nil || !privateProfileInfo(info, policy.OwnerUID, true) {
		return nil, profileError("directory_not_private")
	}
	ancestors, err := trustedHostAncestors(policy.Directory, policy.OwnerUID)
	if err != nil {
		return nil, profileError("untrusted_ancestor")
	}
	root, err := os.OpenRoot(policy.Directory)
	if err != nil {
		return nil, profileError("directory_open_failed")
	}
	current, err := root.Stat(".")
	if err != nil || !os.SameFile(info, current) || !privateProfileInfo(current, policy.OwnerUID, true) || checkPrivateProfileRoot(root) != nil {
		root.Close()
		return nil, profileError("directory_changed")
	}
	checked, err := trustedHostAncestors(policy.Directory, policy.OwnerUID)
	if err != nil || len(ancestors) != len(checked) {
		root.Close()
		return nil, profileError("ancestor_changed")
	}
	for i := range ancestors {
		if !os.SameFile(ancestors[i], checked[i]) {
			root.Close()
			return nil, profileError("ancestor_changed")
		}
	}
	return root, nil
}

func validateProfile(p Profile, policy ProfilePolicy) error {
	if p.SchemaVersion != "1.0.0" || !profileID.MatchString(p.ProfileID) || !profileInstanceID.MatchString(p.InstanceID) || p.OwnerUID != policy.OwnerUID || p.ProfileDirectory != policy.Directory {
		return profileError("identity_mismatch")
	}
	if p.DisplayName == "" || len(p.DisplayName) > 128 || !utf8.ValidString(p.DisplayName) {
		return profileError("invalid_display_name")
	}
	for _, r := range p.DisplayName {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return profileError("invalid_display_name")
		}
	}
	if p.ReleaseFingerprint != policy.InstalledReleaseFingerprint || !digest.MatchString(p.ConfigDigest) {
		return profileError("release_or_config_mismatch")
	}
	if p.ServerTrustRef != "" || p.ServerTrustDigest != "" {
		if p.Mode != "local" || p.ServerTrustRef != "nats-server-trust.json" || !digest.MatchString(p.ServerTrustDigest) || !strings.HasPrefix(p.NATSEndpoint, "tls://") {
			return profileError("invalid_server_trust")
		}
	}
	for _, token := range []string{p.CredentialRef, p.OrganizationID, p.ProjectID} {
		if token != "" && !profileToken.MatchString(token) {
			return profileError("invalid_scope")
		}
	}
	u, err := url.Parse(p.NATSEndpoint)
	if err != nil || (u.Scheme != "nats" && u.Scheme != "tls") || u.User != nil || u.Path != "" || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Host == "" || strings.ContainsAny(p.NATSEndpoint, "?#\r\n\x00") {
		return profileError("invalid_nats_endpoint")
	}
	host, port, err := net.SplitHostPort(u.Host)
	number, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || host == "" || portErr != nil || number == 0 || strings.ContainsAny(host, "% \\\t") {
		return profileError("invalid_nats_endpoint")
	}
	if net.ParseIP(host) == nil {
		if len(host) > 253 {
			return profileError("invalid_nats_endpoint")
		}
		for _, label := range strings.Split(host, ".") {
			if !profileHostLabel.MatchString(label) {
				return profileError("invalid_nats_endpoint")
			}
		}
	}
	if p.Mode == "remote" {
		if p.Docker != nil || p.ComposeProject != "" || u.Scheme != "tls" {
			return profileError("remote_local_selection")
		}
		return nil
	}
	if p.Mode != "local" || p.Docker == nil || !slug.MatchString(p.ComposeProject) {
		return profileError("invalid_mode")
	}
	d := p.Docker
	if !filepath.IsAbs(d.Executable) || filepath.Clean(d.Executable) != d.Executable || strings.ContainsAny(d.Executable, "\x00\r\n") || !slug.MatchString(d.Context) || d.EngineID == "" || len(d.EngineID) > 256 || strings.ContainsAny(d.EngineID, "\x00\r\n") || !version.MatchString(d.ClientVersion) || !version.MatchString(d.ServerVersion) || !version.MatchString(d.ComposeVersion) {
		return profileError("invalid_docker_selection")
	}
	local := d.Backend == WindowsInterop && pipe.MatchString(d.Endpoint)
	if d.Backend == NativeUnix && strings.HasPrefix(d.Endpoint, "unix:///") {
		path := strings.TrimPrefix(d.Endpoint, "unix://")
		local = filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "%?#\x00\r\n")
	}
	if !local {
		return profileError("nonlocal_docker_endpoint")
	}
	if host != "127.0.0.1" && host != "::1" {
		return profileError("nonlocal_nats_endpoint")
	}
	return nil
}

// checkProfileJSON rejects duplicate keys at every depth before decoding fields.
func checkProfileJSON(raw []byte) error {
	if len(raw) == 0 || len(raw) > profileLimit || !utf8.Valid(raw) {
		return profileError("invalid_json")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 16 {
			return profileError("invalid_json")
		}
		t, err := d.Token()
		if err != nil || t == nil {
			return profileError("invalid_json")
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					if err != nil {
						return profileError("invalid_json")
					}
					name, ok := key.(string)
					if !ok || seen[name] {
						return profileError("duplicate_key")
					}
					seen[name] = true
					if err := value(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err := value(depth + 1); err != nil {
						return err
					}
				}
			default:
				return profileError("invalid_json")
			}
			if _, err := d.Token(); err != nil {
				return profileError("invalid_json")
			}
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return profileError("invalid_json")
	}
	return nil
}

// LoadProfile never enrolls, writes a file, or selects another backend.
func LoadProfile(policy ProfilePolicy) (LoadedProfile, error) {
	return loadProfile(policy, assembly.OpenMember)
}

func loadProfile(policy ProfilePolicy, open func(*os.Root, string) (*os.File, error)) (LoadedProfile, error) {
	root, err := openProfileDirectory(policy)
	if err != nil {
		return LoadedProfile{}, err
	}
	defer root.Close()
	before, err := root.Lstat("profile.json")
	if err != nil || !privateProfileInfo(before, policy.OwnerUID, false) {
		return LoadedProfile{}, profileError("file_not_private")
	}
	f, err := open(root, "profile.json")
	if err != nil {
		return LoadedProfile{}, profileError("open_failed")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !hostReadMetadataEqual(before, opened) || !privateProfileInfo(opened, policy.OwnerUID, false) || privatefs.CheckDescriptor(f, privatefs.PrivateObject) != nil {
		return LoadedProfile{}, profileError("file_changed")
	}
	raw, err := io.ReadAll(io.LimitReader(f, profileLimit+1))
	if err != nil {
		return LoadedProfile{}, profileError("read_failed")
	}
	if err := checkProfileJSON(raw); err != nil {
		return LoadedProfile{}, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return LoadedProfile{}, profileError("invalid_fields")
	}
	for _, key := range []string{"schemaVersion", "profileId", "instanceId", "displayName", "ownerUid", "profileDirectory", "mode", "releaseFingerprint", "configDigest", "natsEndpoint"} {
		if _, ok := fields[key]; !ok {
			return LoadedProfile{}, profileError("missing_field")
		}
	}
	var p Profile
	if err := protocol.DecodeClosedJSON(raw, &p, profileLimit); err != nil {
		return LoadedProfile{}, profileError("invalid_fields")
	}
	if err := validateProfile(p, policy); err != nil {
		return LoadedProfile{}, err
	}
	after, err := root.Lstat("profile.json")
	final, finalErr := f.Stat()
	if err != nil || finalErr != nil || privatefs.CheckDescriptor(f, privatefs.PrivateObject) != nil || !hostReadMetadataEqual(opened, after) || !hostReadMetadataEqual(opened, final) || opened.Size() != int64(len(raw)) || !privateProfileInfo(after, policy.OwnerUID, false) || !privateProfileInfo(final, policy.OwnerUID, false) {
		return LoadedProfile{}, profileError("file_changed")
	}
	return LoadedProfile{p}, nil
}

// EnrollProfile publishes a complete file exclusively in an existing private
// directory. A failure never replaces an existing profile or user configuration.
// Release signature validation and key enrollment belong to the release owner.
func EnrollProfile(policy ProfilePolicy, p Profile) error {
	if err := validateProfile(p, policy); err != nil {
		return err
	}
	root, err := openProfileDirectory(policy)
	if err != nil {
		return err
	}
	defer root.Close()
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > profileLimit {
		return profileError("invalid_fields")
	}
	// The random name is confined to the opened directory; publication uses Link,
	// whose existing destination failure does not replace any file.
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return profileError("stage_failed")
	}
	name := ".enroll-" + hex.EncodeToString(nonce[:])
	f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return profileError("stage_failed")
	}
	defer f.Close()
	defer root.Remove(name)
	staged, err := root.Lstat(name)
	opened, statErr := f.Stat()
	if err != nil || statErr != nil || !os.SameFile(staged, opened) || !privateProfileInfo(opened, policy.OwnerUID, false) {
		return profileError("directory_changed")
	}
	if _, err = f.Write(append(raw, '\n')); err != nil {
		return profileError("stage_failed")
	}
	if err = f.Sync(); err != nil {
		return profileError("stage_failed")
	}
	current, err := root.Lstat(name)
	if err != nil || !os.SameFile(opened, current) || !privateProfileInfo(current, policy.OwnerUID, false) {
		return profileError("stage_changed")
	}
	if err = root.Link(name, "profile.json"); err != nil {
		return profileError("already_enrolled_or_publish_failed")
	}
	if err = root.Remove(name); err != nil {
		return profileError("published_cleanup_failed")
	}
	dir, err := root.Open(".")
	if err != nil {
		return profileError("published_sync_failed")
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return profileError("published_sync_failed")
	}
	return nil
}
