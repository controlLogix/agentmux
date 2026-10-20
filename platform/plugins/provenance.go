package plugins

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode"
)

type PackagePin struct {
	PackageID          string `json:"packageId"`
	Version            string `json:"version"`
	ManifestChecksum   string `json:"manifestChecksum"`
	PackageChecksum    string `json:"packageChecksum"`
	ProvenanceChecksum string `json:"provenanceChecksum"`
}
type AdmissionLimits struct {
	MaxFileBytes  int64
	MaxTotalBytes int64
	MaxFiles      int
}
type PackageInput struct {
	Directory      string
	ManifestPath   string
	SourceID       string
	SourcePath     string
	Scope          string
	Source         []byte
	SourceChecksum string
	Limits         AdmissionLimits
}
type Provenance struct {
	SourceID string
	Path     string
	Scope    string
	Checksum string
	source   []byte
}

func (p Provenance) Source() []byte { return bytes.Clone(p.source) }
func (Provenance) String() string   { return "[plugin source provenance; not origin attestation]" }
func (Provenance) GoString() string { return "[plugin source provenance; not origin attestation]" }
func (Provenance) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[plugin source provenance; not origin attestation]")
}
func (Provenance) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"plugin-source-provenance"}`), nil
}

type packageFile struct {
	raw  []byte
	mode fs.FileMode
}
type AdmittedPackage struct {
	manifest   ValidatedManifest
	provenance Provenance
	files      map[string]packageFile
	pin        PackagePin
}

func (p AdmittedPackage) Manifest() Manifest { return p.manifest.Manifest() }
func (p AdmittedPackage) Pin() PackagePin    { return p.pin }
func (p AdmittedPackage) Provenance() Provenance {
	v := p.provenance
	v.source = bytes.Clone(v.source)
	return v
}
func cleanRef(ref string) bool {
	return ref != "." && fs.ValidPath(ref) && !strings.Contains(ref, "\\")
}
func (p AdmittedPackage) File(ref string) ([]byte, error) {
	if !cleanRef(ref) {
		return nil, pluginError("package_reference_invalid")
	}
	v, ok := p.files[ref]
	if !ok {
		return nil, pluginError("package_reference_unavailable")
	}
	return bytes.Clone(v.raw), nil
}
func (p AdmittedPackage) FilePaths() []string {
	paths := make([]string, 0, len(p.files))
	for ref := range p.files {
		paths = append(paths, ref)
	}
	sort.Strings(paths)
	return paths
}
func (p AdmittedPackage) FileMode(ref string) (fs.FileMode, error) {
	v, ok := p.files[ref]
	if !cleanRef(ref) || !ok {
		return 0, pluginError("package_reference_unavailable")
	}
	return v.mode, nil
}
func (AdmittedPackage) String() string   { return "[admitted ordinary package]" }
func (AdmittedPackage) GoString() string { return "[admitted ordinary package]" }
func (AdmittedPackage) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[admitted ordinary package]")
}
func (AdmittedPackage) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"admitted-ordinary-package"}`), nil
}
func metadataText(s string) bool {
	if s == "" || len(s) > 4096 {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
func sameFile(a, b fs.FileInfo) bool {
	return os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime() == b.ModTime()
}

// AdmitPackage holds each regular file while copying it. Source metadata is
// owner-supplied provenance, not a signature or permission to run the package.
func AdmitPackage(ctx context.Context, input PackageInput) (admitted AdmittedPackage, failure error) {
	fail := func(code string) (AdmittedPackage, error) { return AdmittedPackage{}, pluginError(code) }
	if ctx == nil {
		return fail("package_context_required")
	}
	if ctx.Err() != nil {
		return fail("package_admission_cancelled")
	}
	if !metadataText(input.SourceID) || !metadataText(input.SourcePath) || !filepath.IsAbs(input.SourcePath) || !metadataText(input.Scope) || len(input.Source) > manifestLimit || input.SourceChecksum != checksum(input.Source) {
		return fail("package_source_invalid")
	}
	if !filepath.IsAbs(input.Directory) || !cleanRef(input.ManifestPath) {
		return fail("package_root_invalid")
	}
	limits := input.Limits
	if limits.MaxFileBytes == 0 {
		limits.MaxFileBytes = 128 << 20
	}
	if limits.MaxTotalBytes == 0 {
		limits.MaxTotalBytes = 256 << 20
	}
	if limits.MaxFiles == 0 {
		limits.MaxFiles = 4096
	}
	if limits.MaxFileBytes < 1 || limits.MaxFileBytes > 1<<30 || limits.MaxTotalBytes < 1 || limits.MaxTotalBytes > 1<<30 || limits.MaxFiles < 1 || limits.MaxFiles > 16384 {
		return fail("package_limits_unsupported")
	}
	info, err := os.Lstat(input.Directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fail("package_root_invalid")
	}
	root, err := os.OpenRoot(input.Directory)
	if err != nil {
		return fail("package_root_unavailable")
	}
	// A completed descriptor-close failure remains owned and observable; a
	// second no-op close must not turn it into a successful admission.
	defer func() {
		if cleanup := closeAdmission(root, failure); cleanup != failure {
			admitted = AdmittedPackage{}
			failure = cleanup
		}
	}()
	held, err := root.Stat(".")
	if err != nil || !os.SameFile(info, held) {
		return fail("package_root_changed")
	}
	files := map[string]packageFile{}
	var total int64
	entries := 0
	var walk func(*os.Root, string, int) error
	walk = func(directory *os.Root, prefix string, depth int) (failure error) {
		if ctx.Err() != nil {
			return pluginError("package_admission_cancelled")
		}
		if depth > 64 {
			return pluginError("package_limits_exceeded")
		}
		beforeDir, err := directory.Stat(".")
		if err != nil {
			return pluginError("package_directory_unavailable")
		}
		listing, err := directory.Open(".")
		if err != nil {
			return pluginError("package_directory_unavailable")
		}
		var names []string
		for {
			batch, readErr := listing.ReadDir(128)
			for _, entry := range batch {
				entries++
				if entries > limits.MaxFiles {
					return closeAdmission(listing, pluginError("package_limits_exceeded"))
				}
				names = append(names, entry.Name())
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return closeAdmission(listing, pluginError("package_directory_unavailable"))
			}
			if ctx.Err() != nil {
				return closeAdmission(listing, pluginError("package_admission_cancelled"))
			}
		}
		if err := closeAdmission(listing, nil); err != nil {
			return err
		}
		sort.Strings(names)
		for _, name := range names {
			if ctx.Err() != nil {
				return pluginError("package_admission_cancelled")
			}
			ref := path.Join(prefix, name)
			if !cleanRef(ref) {
				return pluginError("package_reference_invalid")
			}
			before, err := directory.Lstat(name)
			if err != nil || before.Mode()&os.ModeSymlink != 0 {
				return pluginError("package_file_not_regular")
			}
			if before.IsDir() {
				child, err := directory.OpenRoot(name)
				if err != nil {
					return pluginError("package_directory_unavailable")
				}
				held, statErr := child.Stat(".")
				if statErr != nil || !sameFile(before, held) {
					return closeAdmission(child, pluginError("package_directory_changed"))
				}
				operation := walk(child, ref, depth+1)
				if closed := closeAdmission(child, operation); closed != nil {
					return closed
				}
				continue
			}
			if !before.Mode().IsRegular() {
				return pluginError("package_file_not_regular")
			}
			if before.Size() > limits.MaxFileBytes || before.Size() > limits.MaxTotalBytes-total {
				return pluginError("package_limits_exceeded")
			}
			file, err := directory.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
			if err != nil {
				return pluginError("package_file_unavailable")
			}
			current, err := file.Stat()
			if err != nil || !current.Mode().IsRegular() || !sameFile(before, current) {
				return closeAdmission(file, pluginError("package_file_changed"))
			}
			readBound := min(limits.MaxFileBytes, limits.MaxTotalBytes-total)
			raw, readErr := io.ReadAll(io.LimitReader(file, readBound+1))
			after, statErr := file.Stat()
			var operation error
			if readErr != nil || statErr != nil {
				operation = pluginError("package_file_read_failed")
			}
			if closed := closeAdmission(file, operation); closed != nil {
				return closed
			}
			if !sameFile(current, after) {
				return pluginError("package_file_changed")
			}
			if int64(len(raw)) > readBound {
				return pluginError("package_limits_exceeded")
			}
			total += int64(len(raw))
			files[ref] = packageFile{raw: raw, mode: current.Mode().Perm()}
		}
		afterDir, err := directory.Stat(".")
		if err != nil || !sameFile(beforeDir, afterDir) {
			return pluginError("package_directory_changed")
		}
		return nil
	}
	err = walk(root, "", 0)
	if err != nil {
		switch err.(type) {
		case *Error, *AdmissionCleanupFailure:
			return AdmittedPackage{}, err
		}
		return fail("package_file_unavailable")
	}
	manifestFile, ok := files[input.ManifestPath]
	if !ok {
		return fail("package_manifest_unavailable")
	}
	manifest, err := ValidateManifest(manifestFile.raw)
	if err != nil {
		return AdmittedPackage{}, err
	}
	keys := make([]string, 0, len(files))
	for key := range files {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	h := sha256.New()
	_, _ = io.WriteString(h, "agentmux-ordinary-package-tree-v1\x00")
	for _, key := range keys {
		v := files[key]
		_ = binary.Write(h, binary.BigEndian, uint64(len(key)))
		_, _ = io.WriteString(h, key)
		_ = binary.Write(h, binary.BigEndian, uint32(v.mode))
		_ = binary.Write(h, binary.BigEndian, uint64(len(v.raw)))
		_, _ = h.Write(v.raw)
	}
	p := AdmittedPackage{manifest: manifest, provenance: Provenance{SourceID: input.SourceID, Path: input.SourcePath, Scope: input.Scope, Checksum: input.SourceChecksum, source: bytes.Clone(input.Source)}, files: files}
	m := manifest.manifest
	provenanceHash := sha256.New()
	_, _ = io.WriteString(provenanceHash, "agentmux-ordinary-source-v1\x00")
	for _, value := range []string{input.SourceID, input.SourcePath, input.Scope, input.SourceChecksum} {
		_ = binary.Write(provenanceHash, binary.BigEndian, uint64(len(value)))
		_, _ = io.WriteString(provenanceHash, value)
	}
	p.pin = PackagePin{PackageID: m.PackageID, Version: m.Version, ManifestChecksum: manifest.Checksum(), PackageChecksum: "sha256:" + hex.EncodeToString(h.Sum(nil)), ProvenanceChecksum: "sha256:" + hex.EncodeToString(provenanceHash.Sum(nil))}
	if ctx.Err() != nil {
		return fail("package_admission_cancelled")
	}
	return p, nil
}

// ValidateActivationSupport is intentionally narrower than structural validity.
// Unsupported declarations are retained by admission and explicitly refused here.
func ValidateActivationSupport(p AdmittedPackage, mode string, host Platform) error {
	return validateActivationSupport(p, mode, host, false)
}

// ValidateContextActivationSupport checks declarations for a host that will
// separately admit every required capability through current native authority.
// It grants no capability and does not establish runtime readiness.
func ValidateContextActivationSupport(p AdmittedPackage, mode string, host Platform) error {
	return validateActivationSupport(p, mode, host, true)
}

func validateActivationSupport(p AdmittedPackage, mode string, host Platform, nativeContext bool) error {
	m := p.Manifest()
	if len(p.files) == 0 {
		return pluginError("package_not_admitted")
	}
	if m.PackageID == "boot" || m.PackageID == "kernel-lifecycle" || m.PackageID == "internal-communication" || m.PackageID == "exported-status" {
		return pluginError("protected_kernel_replacement")
	}
	if host != (Platform{OS: "darwin", Arch: "arm64"}) {
		return pluginError("package_platform_unsupported")
	}
	found := false
	for _, v := range m.Platforms {
		if v == host {
			found = true
		}
	}
	if !found {
		return pluginError("package_platform_incompatible")
	}
	found = false
	for _, v := range m.InstallationModes {
		if v == mode {
			found = true
		}
	}
	if !found {
		return pluginError("package_installation_mode_incompatible")
	}
	for _, capability := range m.RequestedCapabilities {
		if capability.Required && !nativeContext {
			return pluginError("package_capability_binding_unsupported")
		}
	}
	if len(m.Migrations) > 0 {
		return pluginError("package_migrations_unsupported")
	}
	if m.Runtime.Kind != "process" {
		return pluginError("package_runtime_unsupported")
	}
	if !cleanRef(m.Runtime.ExecutableRef) {
		return pluginError("package_executable_reference_invalid")
	}
	f, ok := p.files[path.Clean(m.Runtime.ExecutableRef)]
	if !ok || f.mode&0111 == 0 {
		return pluginError("package_executable_unavailable")
	}
	return nil
}
