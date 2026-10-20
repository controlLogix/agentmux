// Package installer installs an explicitly selected signed release. It never
// enrolls an identity, starts a runtime, or installs dependencies.
package installer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"debug/macho"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/assembly"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/launcher"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

const ProtectedReleaseBase = "/Library/Application Support/Agentmux/Protected/releases"
const metadataLimit = 64 * 1024
const runtimeLimit = 128 * 1024 * 1024

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Selection is trusted only after the caller supplies its independent digest.
// The runtime pin is separate: the existing release signature binds the parent
// manifest and four-role assembly, not the installed frontend executable.
type Selection struct {
	SchemaVersion string           `json:"schemaVersion"`
	Release       ReleaseSelection `json:"release"`
	Runtime       RuntimeSelection `json:"runtime"`
}

type ReleaseSelection struct {
	PackageDirectory      string             `json:"packageDirectory"`
	PublicKeyHex          string             `json:"publicKeyHex"`
	ReleaseManifestDigest string             `json:"releaseManifestDigest"`
	ReleaseAuthority      assembly.Authority `json:"releaseAuthority"`
	ReleaseVersion        string             `json:"releaseVersion"`
	KernelAPIMajor        int                `json:"kernelApiMajor"`
}

type RuntimeSelection struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

type Result struct {
	SchemaVersion  string `json:"schemaVersion"`
	Kind           string `json:"kind"`
	Outcome        string `json:"outcome"`
	InstallationID string `json:"installationId"`
	ReleaseVersion string `json:"releaseVersion"`
	Enrollment     string `json:"enrollment"`
	Readiness      string `json:"readiness"`
}

type payload struct {
	name string
	data []byte
	mode os.FileMode
}

// Package holds bounded, verified copies. Installation never reopens its source
// paths, and callers cannot replace the retained bytes or destination identity.
type Package struct {
	id, version string
	files       []payload
}

func (p *Package) Result(outcome string) Result {
	if p == nil {
		return Result{}
	}
	return Result{"1.0.0", "installation-result", outcome, p.id, p.version, "not_checked", "not_observed"}
}

// Failure retains concrete consumed-close owners and causes without granting a
// raw descriptor retry or authority to remove a partial installation.
type Failure struct {
	code         string
	cause        error
	installation string
	files        []*os.File
	owners       []any
}

func (e *Failure) Error() string                  { return "installer_" + e.code }
func (e *Failure) Format(state fmt.State, _ rune) { fmt.Fprint(state, e.Error()) }
func (e *Failure) MarshalJSON() ([]byte, error)   { return json.Marshal(e.Error()) }
func (e *Failure) Unwrap() error                  { return e.cause }
func (e *Failure) InstallationID() string         { return e.installation }

func refusal(code string, cause error) error { return &Failure{code: code, cause: cause} }

func hash(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func canonical(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && len(path) <= 4096 && !strings.ContainsAny(path, "\x00\r\n")
}

func ReadSelection(ctx context.Context, path, expectedDigest string, ownerUID uint32) (Selection, error) {
	var selected Selection
	if ctx == nil || !digestPattern.MatchString(expectedDigest) || !canonical(path) || ownerUID == 0 {
		return selected, refusal("selection_invalid", nil)
	}
	raw, err := readSelection(ctx, path, ownerUID)
	if err != nil {
		return selected, err
	}
	if hash(raw) != expectedDigest || protocol.DecodeClosedJSON(raw, &selected, metadataLimit) != nil || !selectionFields(raw) {
		return Selection{}, refusal("selection_invalid", nil)
	}
	return selected, nil
}

// Prepare verifies the selected release and snapshots only the fixed payload.
// Filesystem calls must return promptly on supported local storage; a deadline
// discards late results and never claims to preempt a blocked filesystem call.
func Prepare(parent context.Context, selected Selection) (*Package, error) {
	return prepare(parent, selected, nativeImage)
}

func prepare(parent context.Context, selected Selection, checkImage func([]byte) error) (*Package, error) {
	if parent == nil {
		return nil, refusal("context_invalid", nil)
	}
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()
	key, err := hex.DecodeString(selected.Release.PublicKeyHex)
	if err != nil || len(key) != ed25519.PublicKeySize || hex.EncodeToString(key) != selected.Release.PublicKeyHex || selected.SchemaVersion != "1.0.0" || !canonical(selected.Release.PackageDirectory) || !canonical(selected.Runtime.Path) || !digestPattern.MatchString(selected.Runtime.Digest) {
		return nil, refusal("selection_invalid", nil)
	}
	policy := launcher.ReleasePolicy{PackageDirectory: selected.Release.PackageDirectory, PublicKey: key, ReleaseManifestDigest: selected.Release.ReleaseManifestDigest, ReleaseAuthority: selected.Release.ReleaseAuthority, ReleaseVersion: selected.Release.ReleaseVersion, KernelAPIMajor: selected.Release.KernelAPIMajor}
	release, err := launcher.LoadInstalledRelease(policy)
	if err != nil {
		return nil, refusal("release_rejected", err)
	}
	p := &Package{version: selected.Release.ReleaseVersion}
	root, err := openSourceDirectory(ctx, policy.PackageDirectory)
	if err != nil {
		return nil, err
	}
	var failure error
	for _, name := range []string{"release-manifest.json", "release-authorization.json", "release-authorization.sig", "protected-assembly.json"} {
		raw, readErr := readBelow(ctx, root, name, metadataLimit)
		if readErr != nil {
			failure = readErr
			break
		}
		p.files = append(p.files, payload{name, raw, 0444})
	}
	if failure == nil {
		// Recheck the retained authorization and assembly after snapshotting;
		// the earlier path-based verification cannot authorize changed bytes.
		byName := map[string][]byte{}
		for _, file := range p.files {
			byName[file.name] = file.data
		}
		var approval struct {
			SchemaVersion         string             `json:"schemaVersion"`
			ReleaseVersion        string             `json:"releaseVersion"`
			KernelAPIMajor        int                `json:"kernelApiMajor"`
			ReleaseAuthority      assembly.Authority `json:"releaseAuthorityRef"`
			AssemblyDigest        string             `json:"assemblyDigest"`
			ReleaseManifestDigest string             `json:"releaseManifestDigest"`
		}
		approvalValid := authorizationFields(byName["release-authorization.json"]) && protocol.DecodeClosedJSON(byName["release-authorization.json"], &approval, metadataLimit) == nil && approval.SchemaVersion == "1.0.0" && approval.ReleaseVersion == policy.ReleaseVersion && approval.KernelAPIMajor == policy.KernelAPIMajor && approval.ReleaseAuthority == policy.ReleaseAuthority && approval.AssemblyDigest == release.Trust().AssemblyDigest && approval.ReleaseManifestDigest == policy.ReleaseManifestDigest
		if !approvalValid || !ed25519.Verify(key, byName["release-authorization.json"], byName["release-authorization.sig"]) || hash(byName["release-manifest.json"]) != policy.ReleaseManifestDigest || hash(byName["protected-assembly.json"]) != release.Trust().AssemblyDigest {
			failure = refusal("source_changed", nil)
		}
	}
	var total int64
	if failure == nil {
		for _, member := range release.VerifiedAssembly().Members() {
			rel, relErr := filepath.Rel(policy.PackageDirectory, member.Path)
			if relErr != nil || rel != filepath.Join("bin", member.ID) {
				failure = refusal("layout_unsupported", nil)
				break
			}
			raw, readErr := readBelow(ctx, root, rel, assembly.MaxMemberBytes)
			total += int64(len(raw))
			if readErr != nil || total > assembly.MaxAssemblyBytes || hash(raw) != member.BinaryDigest || checkImage(raw) != nil {
				failure = refusal("member_rejected", readErr)
				break
			}
			p.files = append(p.files, payload{rel, raw, 0555})
		}
	}
	failure = closeOwned(root, failure)
	if failure != nil {
		return nil, failure
	}
	raw, err := readAbsolute(ctx, selected.Runtime.Path, runtimeLimit)
	if err != nil || hash(raw) != selected.Runtime.Digest || checkImage(raw) != nil {
		return nil, refusal("runtime_rejected", err)
	}
	p.files = append(p.files, payload{"agentmux-runtime", raw, 0555})
	if err := ctx.Err(); err != nil {
		return nil, refusal("deadline", err)
	}
	identity := sha256.Sum256([]byte(policy.ReleaseManifestDigest + "\x00" + release.Trust().AssemblyDigest + "\x00" + selected.Runtime.Digest))
	p.id = hex.EncodeToString(identity[:])
	return p, nil
}

func nativeImage(data []byte) error {
	image, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return refusal("image_invalid", nil)
	}
	defer image.Close()
	if image.Type != macho.TypeExec || image.Cpu != macho.CpuArm64 {
		return refusal("image_invalid", nil)
	}
	return nil
}

// CheckEnrollment runs as the enrolled ordinary user after installation. It
// validates protected images and existing private enrollment without spawning
// processes, changing identity, or contacting Docker or a broker.
func CheckEnrollment(parent context.Context, selected launcher.HostPolicySelection) (result Result, failure error) {
	if parent == nil {
		return Result{}, refusal("context_invalid", nil)
	}
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		return Result{}, refusal("platform_unqualified", nil)
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	host, err := launcher.LoadEnrolledHostPolicy(selected)
	if err != nil {
		return Result{}, refusal("enrollment_rejected", err)
	}
	config, _, err := host.Load()
	if err != nil {
		return Result{}, refusal("enrollment_rejected", err)
	}
	if filepath.Dir(config.PackageDirectory) != ProtectedReleaseBase {
		return Result{}, refusal("enrollment_rejected", nil)
	}
	image, err := host.PrepareHost(ctx)
	if err != nil {
		return Result{}, refusal("installed_images_rejected", err)
	}
	defer func() {
		if err := image.Close(); err != nil {
			failure = &Failure{code: "cleanup_failed", cause: errors.Join(failure, err), owners: []any{image}}
		}
	}()
	roles, err := protected.Prepare(ctx, config.Assembly, config.PackageDirectory, config.ReleaseTrust, protected.Limits{})
	if roles != nil {
		defer func() {
			if err := roles.Close(); err != nil {
				failure = &Failure{code: "cleanup_failed", cause: errors.Join(failure, err), owners: []any{roles}}
			}
		}()
	}
	if err != nil {
		return Result{}, refusal("installed_images_rejected", err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, refusal("deadline", err)
	}
	return Result{"1.0.0", "installation-result", "enrollment_verified", filepath.Base(config.PackageDirectory), config.ReleaseTrust.ReleaseVersion, "verified", "not_observed"}, nil
}

func selectionFields(raw []byte) bool {
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil || !exactFields(top, "schemaVersion", "release", "runtime") {
		return false
	}
	var release, runtime, authority map[string]json.RawMessage
	return json.Unmarshal(top["release"], &release) == nil && exactFields(release, "packageDirectory", "publicKeyHex", "releaseManifestDigest", "releaseAuthority", "releaseVersion", "kernelApiMajor") && json.Unmarshal(release["releaseAuthority"], &authority) == nil && exactFields(authority, "id", "ownerHubId", "revision") && json.Unmarshal(top["runtime"], &runtime) == nil && exactFields(runtime, "path", "digest")
}

func authorizationFields(raw []byte) bool {
	var top, authority map[string]json.RawMessage
	return json.Unmarshal(raw, &top) == nil && exactFields(top, "schemaVersion", "releaseVersion", "kernelApiMajor", "releaseAuthorityRef", "assemblyDigest", "releaseManifestDigest") && json.Unmarshal(top["releaseAuthorityRef"], &authority) == nil && exactFields(authority, "id", "ownerHubId", "revision")
}

func exactFields(fields map[string]json.RawMessage, names ...string) bool {
	if len(fields) != len(names) {
		return false
	}
	for _, name := range names {
		raw, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return false
		}
	}
	return true
}
