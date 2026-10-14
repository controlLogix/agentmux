// Package assembly verifies a fixed protected release before a supervisor launches it.
package assembly

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	identifier = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,95}$`)
	version    = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	digest     = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	roles      = [4]string{"boot", "kernel-lifecycle", "internal-communication", "exported-status"}
)

// Authority identifies the externally enrolled release authority, not a key from the package.
type Authority struct {
	ID         string `json:"id"`
	OwnerHubID string `json:"ownerHubId"`
	Revision   int64  `json:"revision"`
}

// Trust must come from authenticated host release policy, separately from assembly JSON.
// AssemblyDigest binds the exact JSON bytes listed by that trusted release.
// ReleaseManifestDigest identifies the parent release manifest, not these JSON bytes.
type Trust struct {
	AssemblyDigest        string
	ReleaseManifestDigest string
	ReleaseVersion        string
	ReleaseAuthority      Authority
	KernelAPIMajor        int
}

type manifest struct {
	SchemaVersion         string    `json:"schemaVersion"`
	ReleaseVersion        string    `json:"releaseVersion"`
	ReleaseManifestDigest string    `json:"releaseManifestDigest"`
	ReleaseAuthority      Authority `json:"releaseAuthorityRef"`
	KernelAPIMajor        int       `json:"kernelApiMajor"`
	Plugins               []plugin  `json:"plugins"`
}

type plugin struct {
	ID           string `json:"id"`
	BinaryDigest string `json:"binaryDigest"`
	Entrypoint   string `json:"entrypoint"`
}

// Member describes a checked regular file. It is not a safe-to-execute handle.
type Member struct {
	ID           string
	Path         string
	BinaryDigest string
	Size         int64
}

// Verified can only be populated by Verify. Members returns a value copy.
// A supervisor must still secure the files against changes before execution.
type Verified struct {
	root    string
	trust   Trust
	members [4]Member
}

func (v Verified) PackageRoot() string { return v.root }
func (v Verified) Release() Trust      { return v.trust }
func (v Verified) Members() [4]Member  { return v.members }

// Verify checks the v1 protected-assembly shape and host-selected release policy.
// It reads files but never launches processes, contacts a broker or reads credentials.
// No partial result is returned if any member fails verification.
func Verify(raw []byte, packageDir string, trust Trust) (Verified, error) {
	if !digest.MatchString(trust.AssemblyDigest) || !digest.MatchString(trust.ReleaseManifestDigest) ||
		!version.MatchString(trust.ReleaseVersion) || !validAuthority(trust.ReleaseAuthority) || trust.KernelAPIMajor != 1 {
		return Verified{}, errors.New("trusted release policy is incomplete or incompatible")
	}
	if sum(raw) != trust.AssemblyDigest {
		return Verified{}, errors.New("assembly bytes do not match the trusted release")
	}
	if !utf8.Valid(raw) || !validEscapes(raw) {
		return Verified{}, errors.New("assembly contains invalid Unicode")
	}
	if err := uniqueKeys(raw); err != nil {
		return Verified{}, err
	}
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(raw, &shape); err != nil {
		return Verified{}, errors.New("assembly is not a JSON object")
	}
	if err := exactKeys(shape, "schemaVersion", "releaseVersion", "releaseManifestDigest", "releaseAuthorityRef", "kernelApiMajor", "plugins"); err != nil {
		return Verified{}, err
	}
	var authority map[string]json.RawMessage
	if err := json.Unmarshal(shape["releaseAuthorityRef"], &authority); err != nil {
		return Verified{}, errors.New("release authority is not an object")
	}
	if err := exactKeys(authority, "id", "ownerHubId", "revision"); err != nil {
		return Verified{}, err
	}
	for _, value := range authority {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return Verified{}, errors.New("release authority fields cannot be null")
		}
	}
	// JSON Schema integers include integer-valued decimal/exponent spellings.
	revision, err := integer(authority["revision"])
	if err != nil {
		return Verified{}, err
	}
	authority["revision"], _ = json.Marshal(revision)
	api, err := integer(shape["kernelApiMajor"])
	if err != nil {
		return Verified{}, err
	}
	shape["kernelApiMajor"], _ = json.Marshal(api)
	shape["releaseAuthorityRef"], _ = json.Marshal(authority)
	normalized, _ := json.Marshal(shape)
	var members []map[string]json.RawMessage
	if err := json.Unmarshal(shape["plugins"], &members); err != nil || len(members) != 4 {
		return Verified{}, errors.New("assembly must contain exactly four members")
	}
	for _, member := range members {
		if err := exactKeys(member, "id", "binaryDigest", "entrypoint"); err != nil {
			return Verified{}, err
		}
	}
	var m manifest
	decoder := json.NewDecoder(bytes.NewReader(normalized))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&m); err != nil {
		return Verified{}, errors.New("assembly fields have incompatible types")
	}
	if m.SchemaVersion != "1.0.0" || !version.MatchString(m.ReleaseVersion) || !validAuthority(m.ReleaseAuthority) || !digest.MatchString(m.ReleaseManifestDigest) || m.KernelAPIMajor != 1 {
		return Verified{}, errors.New("assembly version, API or authority shape is invalid")
	}
	if m.ReleaseVersion != trust.ReleaseVersion || m.ReleaseManifestDigest != trust.ReleaseManifestDigest || m.ReleaseAuthority != trust.ReleaseAuthority || m.KernelAPIMajor != trust.KernelAPIMajor {
		return Verified{}, errors.New("assembly does not match the trusted release policy")
	}
	byID := make(map[string]plugin, 4)
	for _, member := range m.Plugins {
		known := false
		for _, role := range roles {
			if role == member.ID {
				known = true
			}
		}
		if !known || !digest.MatchString(member.BinaryDigest) {
			return Verified{}, errors.New("assembly member identity or digest is invalid")
		}
		if _, exists := byID[member.ID]; exists {
			return Verified{}, errors.New("assembly member identity is repeated")
		}
		byID[member.ID] = member
	}
	if packageDir == "" {
		return Verified{}, errors.New("package directory must be selected explicitly")
	}
	absolute, err := filepath.Abs(packageDir)
	if err != nil {
		return Verified{}, errors.New("package directory is invalid")
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return Verified{}, errors.New("package directory is unavailable")
	}
	root, err := os.OpenRoot(canonical)
	if err != nil {
		return Verified{}, errors.New("package root cannot be opened")
	}
	defer root.Close()
	verified := Verified{root: canonical, trust: trust}
	for i, role := range roles {
		member := byID[role]
		file, err := checkFile(root, member.Entrypoint)
		if err != nil {
			return Verified{}, fmt.Errorf("member %s: %w", role, err)
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			file.Close()
			return Verified{}, fmt.Errorf("member %s: entrypoint is not a regular file", role)
		}
		h := sha256.New()
		_, hashErr := io.Copy(h, file)
		closeErr := file.Close()
		if hashErr != nil || closeErr != nil {
			return Verified{}, fmt.Errorf("member %s: binary could not be read", role)
		}
		if "sha256:"+hex.EncodeToString(h.Sum(nil)) != member.BinaryDigest {
			return Verified{}, fmt.Errorf("member %s: binary digest differs", role)
		}
		verified.members[i] = Member{ID: role, Path: filepath.Join(canonical, filepath.FromSlash(member.Entrypoint)), BinaryDigest: member.BinaryDigest, Size: info.Size()}
	}
	return verified, nil
}

func validAuthority(a Authority) bool {
	return identifier.MatchString(a.ID) && identifier.MatchString(a.OwnerHubID) && a.Revision >= 0 && a.Revision <= 9007199254740991
}

func sum(data []byte) string {
	hash := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(hash[:])
}

func exactKeys(object map[string]json.RawMessage, keys ...string) error {
	if len(object) != len(keys) {
		return errors.New("assembly has missing or unknown fields")
	}
	for _, key := range keys {
		if _, present := object[key]; !present {
			return errors.New("assembly has missing or unknown fields")
		}
	}
	return nil
}

func integer(raw json.RawMessage) (int64, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	token, err := d.Token()
	number, ok := token.(json.Number)
	if err != nil || !ok {
		return 0, errors.New("assembly integer field is invalid")
	}
	rat, valid := new(big.Rat).SetString(string(number))
	if !valid || !rat.IsInt() || !rat.Num().IsInt64() {
		return 0, errors.New("assembly integer field is invalid")
	}
	n := rat.Num().Int64()
	if n < 0 || n > 9007199254740991 {
		return 0, errors.New("assembly integer field exceeds the safe range")
	}
	return n, nil
}

func checkFile(root *os.Root, entry string) (*os.File, error) {
	if entry == "" || utf8.RuneCountInString(entry) > 4096 || strings.ContainsAny(entry, "\\:\x00") || path.IsAbs(entry) || path.Clean(entry) != entry {
		return nil, errors.New("entrypoint must be a contained relative path")
	}
	parts := strings.Split(entry, "/")
	for i, part := range parts {
		if part == "." || part == ".." {
			return nil, errors.New("entrypoint traversal is refused")
		}
		info, err := root.Lstat(filepath.FromSlash(strings.Join(parts[:i+1], "/")))
		if err != nil {
			return nil, errors.New("entrypoint is unavailable")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("entrypoint symlinks are refused")
		}
		if i < len(parts)-1 && !info.IsDir() {
			return nil, errors.New("entrypoint parent is not a directory")
		}
		if i == len(parts)-1 && !info.Mode().IsRegular() {
			return nil, errors.New("entrypoint is not a regular file")
		}
	}
	file, err := root.Open(filepath.FromSlash(entry))
	if err != nil {
		return nil, errors.New("entrypoint cannot be opened inside the package")
	}
	return file, nil
}

// encoding/json accepts duplicate names. Reject them before decoding trusted fields.
func uniqueKeys(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return errors.New("assembly JSON nesting is too deep")
		}
		token, err := d.Token()
		if err != nil {
			return errors.New("assembly JSON is invalid")
		}
		opening, composite := token.(json.Delim)
		if !composite {
			return nil
		}
		if opening == '{' {
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return errors.New("assembly JSON is invalid")
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("assembly JSON repeats a field")
				}
				seen[name] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		} else if opening == '[' {
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		} else {
			return errors.New("assembly JSON is invalid")
		}
		_, err = d.Token()
		return err
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("assembly JSON has trailing data")
	}
	return nil
}

// Reject lone escaped surrogates rather than letting encoding/json replace them.
func validEscapes(raw []byte) bool {
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
		var code uint16
		for j := 1; j <= 4; j++ {
			ch := raw[i+j]
			code <<= 4
			switch {
			case ch >= '0' && ch <= '9':
				code += uint16(ch - '0')
			case ch >= 'a' && ch <= 'f':
				code += uint16(ch - 'a' + 10)
			case ch >= 'A' && ch <= 'F':
				code += uint16(ch - 'A' + 10)
			default:
				return false
			}
		}
		i += 4
		if code >= 0xdc00 && code <= 0xdfff {
			return false
		}
		if code >= 0xd800 && code <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low := raw[i+3 : i+7]
			if !(low[0] == 'd' || low[0] == 'D') || !((low[1] >= 'c' && low[1] <= 'f') || (low[1] >= 'C' && low[1] <= 'F')) {
				return false
			}
			for _, ch := range low[2:] {
				if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
					return false
				}
			}
			i += 6
		}
	}
	return !quoted
}
