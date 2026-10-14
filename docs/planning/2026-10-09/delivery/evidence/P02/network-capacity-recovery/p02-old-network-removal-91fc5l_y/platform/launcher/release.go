//go:build linux || darwin

package launcher

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/controlLogix/agentmux/platform/kernel/assembly"
)

const (
	releaseMetadataLimit = 64 * 1024
	releaseMemberLimit   = assembly.MaxMemberBytes
	releaseTotalLimit    = assembly.MaxAssemblyBytes
)

// ReleasePolicy is separately enrolled host policy, never package-supplied data.
// The caller binds this public key to the expected authority, version and parent
// manifest digest. This loader does not enroll keys or manage identity/revocation.
type ReleasePolicy struct {
	PackageDirectory      string
	PublicKey             ed25519.PublicKey
	ReleaseManifestDigest string
	ReleaseAuthority      assembly.Authority
	ReleaseVersion        string
	KernelAPIMajor        int
}

type BrokerPins struct {
	Image          string `json:"image"`
	NATSVersion    string `json:"natsVersion"`
	ComposeVersion string `json:"composeVersion"`
}

type installedManifest struct {
	SchemaVersion    string             `json:"schemaVersion"`
	ReleaseVersion   string             `json:"releaseVersion"`
	KernelAPIMajor   int                `json:"kernelApiMajor"`
	ReleaseAuthority assembly.Authority `json:"releaseAuthorityRef"`
	Broker           BrokerPins         `json:"broker"`
}

type releaseAuthorization struct {
	SchemaVersion         string             `json:"schemaVersion"`
	ReleaseVersion        string             `json:"releaseVersion"`
	KernelAPIMajor        int                `json:"kernelApiMajor"`
	ReleaseAuthority      assembly.Authority `json:"releaseAuthorityRef"`
	AssemblyDigest        string             `json:"assemblyDigest"`
	ReleaseManifestDigest string             `json:"releaseManifestDigest"`
}

// InstalledRelease has private fields and only exposes copies. It observes and
// verifies a fixed package; runtime.Prepare must still bind immutable executable
// snapshots. A verified path alone is not a race-free execution handle.
type InstalledRelease struct {
	trust     assembly.Trust
	assembly  []byte
	directory string
	pins      BrokerPins
	verified  assembly.Verified
}

func (r InstalledRelease) Trust() assembly.Trust               { return r.trust }
func (r InstalledRelease) Assembly() []byte                    { return append([]byte(nil), r.assembly...) }
func (r InstalledRelease) PackageDirectory() string            { return r.directory }
func (r InstalledRelease) BrokerPins() BrokerPins              { return r.pins }
func (r InstalledRelease) VerifiedAssembly() assembly.Verified { return r.verified }

var releaseVersionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
var releaseIdentifier = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,95}$`)
var releaseHash = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var releaseImage = regexp.MustCompile(`^docker\.io/library/nats@sha256:[a-f0-9]{64}$`)

func releaseError(code string) error { return errors.New("release_" + code) }

func releaseDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func releaseAuthorityValid(a assembly.Authority) bool {
	return releaseIdentifier.MatchString(a.ID) && releaseIdentifier.MatchString(a.OwnerHubID) &&
		a.Revision >= 0 && a.Revision <= 9007199254740991
}

func releaseEscapesValid(raw []byte) bool {
	quoted := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			quoted = !quoted
			continue
		}
		if !quoted || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		value, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil || value >= 0xdc00 && value <= 0xdfff {
			return false
		}
		i += 4
		if value >= 0xd800 && value <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return !quoted
}

func releaseJSON(raw []byte) error {
	if len(raw) == 0 || len(raw) > releaseMetadataLimit || !utf8.Valid(raw) || !releaseEscapesValid(raw) {
		return releaseError("json_invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return releaseError("json_depth")
		}
		token, err := decoder.Token()
		if err != nil || token == nil {
			return releaseError("json_invalid")
		}
		if opening, ok := token.(json.Delim); ok {
			switch opening {
			case '{':
				seen := map[string]bool{}
				for decoder.More() {
					key, err := decoder.Token()
					name, ok := key.(string)
					if err != nil || !ok || seen[name] {
						return releaseError("json_duplicate_or_invalid_key")
					}
					seen[name] = true
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				for decoder.More() {
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
			default:
				return releaseError("json_invalid")
			}
			if _, err := decoder.Token(); err != nil {
				return releaseError("json_invalid")
			}
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return releaseError("json_trailing_data")
	}
	return nil
}

func releaseFields(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != len(keys) {
		return nil, releaseError("fields_invalid")
	}
	for _, key := range keys {
		if _, ok := fields[key]; !ok {
			return nil, releaseError("fields_invalid")
		}
	}
	return fields, nil
}

func decodeRelease(raw []byte, dst any, broker bool) error {
	if err := releaseJSON(raw); err != nil {
		return err
	}
	keys := []string{"schemaVersion", "releaseVersion", "kernelApiMajor", "releaseAuthorityRef"}
	if broker {
		keys = append(keys, "broker")
	} else {
		keys = append(keys, "assemblyDigest", "releaseManifestDigest")
	}
	fields, err := releaseFields(raw, keys...)
	if err != nil {
		return err
	}
	if _, err := releaseFields(fields["releaseAuthorityRef"], "id", "ownerHubId", "revision"); err != nil {
		return err
	}
	if broker {
		if _, err := releaseFields(fields["broker"], "image", "natsVersion", "composeVersion"); err != nil {
			return err
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(dst) != nil {
		return releaseError("field_types_invalid")
	}
	return nil
}

func releaseOpen(root *os.Root, name string) (*os.File, error) {
	// Use the common direct-directory-handle opener: os.Root.OpenFile alone can
	// resolve a symlink before applying flags. This opener refuses symlinks and
	// substituted special files without waiting on a FIFO.
	return assembly.OpenMember(root, name)
}

func releaseRead(root *os.Root, name string, limit int64) ([]byte, error) {
	return releaseReadOpened(root, name, limit, releaseOpen)
}

// The package-private opener seam allows a controlled filesystem race test,
// without replacing globals or weakening production opening flags.
func releaseReadOpened(root *os.Root, name string, limit int64, open func(*os.Root, string) (*os.File, error)) ([]byte, error) {
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > limit {
		return nil, releaseError("file_invalid_or_oversized")
	}
	file, err := open(root, name)
	if err != nil {
		return nil, releaseError("file_unavailable")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, releaseError("file_changed")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, releaseError("file_read_or_size_invalid")
	}
	after, err := root.Lstat(name)
	final, statErr := file.Stat()
	if err != nil || statErr != nil || !after.Mode().IsRegular() || !os.SameFile(opened, after) ||
		final.Size() != int64(len(raw)) || before.Size() != final.Size() {
		return nil, releaseError("file_changed")
	}
	return raw, nil
}

func preflightReleaseMembers(root *os.Root, raw []byte) error {
	if err := releaseJSON(raw); err != nil {
		return err
	}
	var manifest struct {
		Plugins []struct {
			Entrypoint string `json:"entrypoint"`
		} `json:"plugins"`
	}
	if json.Unmarshal(raw, &manifest) != nil || len(manifest.Plugins) != 4 {
		return releaseError("assembly_members_invalid")
	}
	var total int64
	for _, member := range manifest.Plugins {
		entry := member.Entrypoint
		if entry == "" || utf8.RuneCountInString(entry) > 4096 || strings.ContainsAny(entry, "\\:\x00") || path.IsAbs(entry) || path.Clean(entry) != entry {
			return releaseError("entrypoint_invalid")
		}
		parts := strings.Split(entry, "/")
		for index, part := range parts {
			if part == "." || part == ".." {
				return releaseError("entrypoint_invalid")
			}
			info, err := root.Lstat(filepath.FromSlash(strings.Join(parts[:index+1], "/")))
			if err != nil || info.Mode()&os.ModeSymlink != 0 || index < len(parts)-1 && !info.IsDir() {
				return releaseError("entrypoint_invalid")
			}
			if index == len(parts)-1 {
				if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > releaseMemberLimit {
					return releaseError("member_size_or_type_invalid")
				}
				total += info.Size()
				if total > releaseTotalLimit {
					return releaseError("member_total_size_invalid")
				}
			}
		}
	}
	return nil
}

// LoadInstalledRelease reads only the fixed installed package. The signed
// authorization binds the parent manifest and assembly separately, avoiding a
// parent/assembly hash cycle. It never trusts a package-selected public key or
// expected digest and returns no partially trusted result after a failure.
func LoadInstalledRelease(policy ReleasePolicy) (InstalledRelease, error) {
	if len(policy.PublicKey) != ed25519.PublicKeySize || !releaseHash.MatchString(policy.ReleaseManifestDigest) ||
		!releaseAuthorityValid(policy.ReleaseAuthority) || !releaseVersionPattern.MatchString(policy.ReleaseVersion) || policy.KernelAPIMajor != 1 {
		return InstalledRelease{}, releaseError("policy_invalid")
	}
	key := append(ed25519.PublicKey(nil), policy.PublicKey...)
	directory := policy.PackageDirectory
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return InstalledRelease{}, releaseError("directory_invalid")
	}
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil || canonical != directory {
		return InstalledRelease{}, releaseError("directory_not_canonical")
	}
	before, err := os.Lstat(directory)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return InstalledRelease{}, releaseError("directory_invalid")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return InstalledRelease{}, releaseError("directory_unavailable")
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		return InstalledRelease{}, releaseError("directory_changed")
	}
	authorization, err := releaseRead(root, "release-authorization.json", releaseMetadataLimit)
	if err != nil {
		return InstalledRelease{}, err
	}
	signature, err := releaseRead(root, "release-authorization.sig", ed25519.SignatureSize)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return InstalledRelease{}, releaseError("signature_file_invalid")
	}
	if !ed25519.Verify(key, authorization, signature) {
		return InstalledRelease{}, releaseError("signature_invalid")
	}
	var approval releaseAuthorization
	if err := decodeRelease(authorization, &approval, false); err != nil {
		return InstalledRelease{}, err
	}
	if approval.SchemaVersion != "1.0.0" || approval.ReleaseVersion != policy.ReleaseVersion ||
		approval.ReleaseAuthority != policy.ReleaseAuthority || approval.KernelAPIMajor != policy.KernelAPIMajor ||
		approval.ReleaseManifestDigest != policy.ReleaseManifestDigest || !releaseHash.MatchString(approval.AssemblyDigest) {
		return InstalledRelease{}, releaseError("authorization_policy_mismatch")
	}
	parent, err := releaseRead(root, "release-manifest.json", releaseMetadataLimit)
	if err != nil {
		return InstalledRelease{}, err
	}
	if releaseDigest(parent) != policy.ReleaseManifestDigest {
		return InstalledRelease{}, releaseError("manifest_digest_mismatch")
	}
	var manifest installedManifest
	if err := decodeRelease(parent, &manifest, true); err != nil {
		return InstalledRelease{}, err
	}
	if manifest.SchemaVersion != "1.0.0" || manifest.ReleaseVersion != approval.ReleaseVersion ||
		manifest.KernelAPIMajor != approval.KernelAPIMajor || manifest.ReleaseAuthority != approval.ReleaseAuthority ||
		!releaseImage.MatchString(manifest.Broker.Image) || manifest.Broker.NATSVersion != "2.15.0" || manifest.Broker.ComposeVersion != "5.5.1" {
		return InstalledRelease{}, releaseError("manifest_policy_or_pins_mismatch")
	}
	rawAssembly, err := releaseRead(root, "protected-assembly.json", releaseMetadataLimit)
	if err != nil {
		return InstalledRelease{}, err
	}
	if releaseDigest(rawAssembly) != approval.AssemblyDigest {
		return InstalledRelease{}, releaseError("assembly_digest_mismatch")
	}
	if err := preflightReleaseMembers(root, rawAssembly); err != nil {
		return InstalledRelease{}, err
	}
	trust := assembly.Trust{AssemblyDigest: approval.AssemblyDigest, ReleaseManifestDigest: approval.ReleaseManifestDigest,
		ReleaseVersion: approval.ReleaseVersion, ReleaseAuthority: approval.ReleaseAuthority, KernelAPIMajor: approval.KernelAPIMajor}
	verified, err := assembly.VerifyRoot(rawAssembly, directory, root, trust,
		assembly.Limits{MemberBytes: releaseMemberLimit, TotalBytes: releaseTotalLimit})
	if err != nil {
		return InstalledRelease{}, releaseError("assembly_verification_failed")
	}
	after, err := os.Lstat(directory)
	if err != nil || !after.IsDir() || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, after) {
		return InstalledRelease{}, releaseError("directory_changed")
	}
	return InstalledRelease{trust, append([]byte(nil), rawAssembly...), directory, manifest.Broker, verified}, nil
}
