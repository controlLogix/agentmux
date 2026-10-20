package runtime

import (
	"bytes"
	"crypto/sha256"
	"debug/macho"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"strings"

	"github.com/controlLogix/agentmux/platform/internal/wirejson"
)

const (
	InstalledClientBase = "/Library/Application Support/Agentmux/Protected/clients"
	ClientPythonVersion = "3.14.4"
	ClientInterpreter   = "python/bin/python3.14"
	ClientBootstrap     = "bootstrap.py"
	ClientManifestLimit = 2 * 1024 * 1024
	ClientFileLimit     = 64 * 1024 * 1024
	ClientTotalLimit    = 256 * 1024 * 1024
	ClientMaxFiles      = 4096
)

var clientIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var clientDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var clientPathPattern = regexp.MustCompile(`^[A-Za-z0-9_.+/-]+$`)

type ClientFile struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
}

// ClientManifest describes an ordinary client package. It does not add a
// protected kernel role, enroll a user, or establish application readiness.
type ClientManifest struct {
	SchemaVersion            string       `json:"schemaVersion"`
	Kind                     string       `json:"kind"`
	FoundationInstallationID string       `json:"foundationInstallationId"`
	FrontendDigest           string       `json:"frontendDigest"`
	PythonVersion            string       `json:"pythonVersion"`
	Interpreter              string       `json:"interpreter"`
	Bootstrap                string       `json:"bootstrap"`
	Files                    []ClientFile `json:"files"`
}

func ClientDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ValidClientInstallationID(id string) bool { return clientIDPattern.MatchString(id) }

func validClientPath(name string) bool {
	return len(name) <= 512 && len(strings.Split(name, "/")) <= 24 && clientPathPattern.MatchString(name) && path.Clean(name) == name && name != "." && !strings.HasPrefix(name, "/") && !strings.HasPrefix(name, "../")
}

func clientFields(raw []byte, fields ...string) bool {
	var value map[string]json.RawMessage
	if json.Unmarshal(raw, &value) != nil || len(value) != len(fields) {
		return false
	}
	for _, field := range fields {
		item, ok := value[field]
		if !ok || bytes.Equal(bytes.TrimSpace(item), []byte("null")) {
			return false
		}
	}
	return true
}

// DecodeClientManifest checks the complete bounded roster before filesystem
// access. Its exact bytes are independently selected and identify installation.
func DecodeClientManifest(raw []byte) (ClientManifest, error) {
	var m ClientManifest
	bad := errors.New("installed_client_manifest_invalid")
	if wirejson.Validate(raw, ClientManifestLimit) != nil || json.Unmarshal(raw, &m) != nil || !clientFields(raw, "schemaVersion", "kind", "foundationInstallationId", "frontendDigest", "pythonVersion", "interpreter", "bootstrap", "files") || m.SchemaVersion != "1.0.0" || m.Kind != "ordinary-python-client" || !ValidClientInstallationID(m.FoundationInstallationID) || !clientDigestPattern.MatchString(m.FrontendDigest) || m.PythonVersion != ClientPythonVersion || m.Interpreter != ClientInterpreter || m.Bootstrap != ClientBootstrap || len(m.Files) < 4 || len(m.Files) > ClientMaxFiles {
		return ClientManifest{}, bad
	}
	var fields struct {
		Files []json.RawMessage `json:"files"`
	}
	if json.Unmarshal(raw, &fields) != nil {
		return ClientManifest{}, bad
	}
	var total int64
	previous := ""
	roster := make(map[string]ClientFile, len(m.Files))
	for i, file := range m.Files {
		if !clientFields(fields.Files[i], "path", "digest", "size", "mode") || !validClientPath(file.Path) || file.Path <= previous || !clientDigestPattern.MatchString(file.Digest) || file.Size < 0 || file.Size > ClientFileLimit || (file.Mode != 0444 && file.Mode != 0555) {
			return ClientManifest{}, bad
		}
		if file.Path != ClientBootstrap && file.Path != ClientInterpreter && !strings.HasPrefix(file.Path, "python/lib/") && !strings.HasPrefix(file.Path, "site-packages/") && !strings.HasPrefix(file.Path, "app/") {
			return ClientManifest{}, bad
		}
		if strings.Contains(file.Path, "/__pycache__/") || strings.HasSuffix(file.Path, ".pyc") || strings.HasSuffix(file.Path, "/pyvenv.cfg") {
			return ClientManifest{}, bad
		}
		total += file.Size
		if total > ClientTotalLimit {
			return ClientManifest{}, bad
		}
		roster[file.Path], previous = file, file.Path
	}
	for _, required := range []string{ClientBootstrap, ClientInterpreter, "python/lib/libpython3.14.dylib", "python/lib/python3.14/os.py", "app/hub/cli.py", "app/hub/client_launch_entrypoint.py", "app/hub/client_launch_coordinator.py", "app/sdk/python/agentmux_contracts/validation.py", "app/contracts/v1/schemas/startup-status-observation.schema.json", "app/client-requirements.lock"} {
		if _, ok := roster[required]; !ok {
			return ClientManifest{}, bad
		}
	}
	if roster[ClientInterpreter].Mode != 0555 {
		return ClientManifest{}, bad
	}
	for name := range roster {
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if _, exists := roster[parent]; exists {
				return ClientManifest{}, bad
			}
		}
	}
	return m, nil
}

// ClientNativeCandidate identifies bytes that must undergo Mach-O admission.
func ClientNativeCandidate(name string, data []byte) bool {
	if name == ClientInterpreter || strings.HasSuffix(name, ".dylib") || strings.HasSuffix(name, ".so") {
		return true
	}
	if len(data) < 4 {
		return false
	}
	magic := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	return magic == 0xcafebabe || magic == 0xbebafeca || magic == 0xfeedfacf || magic == 0xcffaedfe || magic == 0xfeedface || magic == 0xcefaedfe
}

func clientNativeImages(name string, data []byte) ([]*macho.File, error) {
	image, err := macho.NewFile(bytes.NewReader(data))
	if err == nil {
		if image.Cpu != macho.CpuArm64 || image.SubCpu != 0 || (name == ClientInterpreter && image.Type != macho.TypeExec) {
			return nil, errors.New("installed_client_native_architecture_invalid")
		}
		return []*macho.File{image}, nil
	}
	fat, err := macho.NewFatFile(bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("installed_client_native_image_invalid")
	}
	var images []*macho.File
	seen := map[uint32]bool{}
	for _, arch := range fat.Arches {
		if arch.Cpu != arch.File.Cpu || arch.SubCpu != arch.File.SubCpu {
			return nil, errors.New("installed_client_native_architecture_invalid")
		}
		if arch.Cpu != macho.CpuArm64 {
			continue
		}
		// The selected beta interpreter and native wheels use generic ARM64.
		// Refuse unqualified subtypes and ambiguous duplicate native slices.
		if arch.SubCpu != 0 || seen[arch.SubCpu] || (name == ClientInterpreter && arch.Type != macho.TypeExec) {
			return nil, errors.New("installed_client_native_architecture_invalid")
		}
		seen[arch.SubCpu] = true
		images = append(images, arch.File)
	}
	if len(images) == 0 {
		return nil, errors.New("installed_client_native_architecture_invalid")
	}
	return images, nil
}

func resolveClientLibrary(name, value string) (string, bool) {
	var base, suffix string
	if strings.HasPrefix(value, "@loader_path/") {
		base, suffix = path.Dir(name), strings.TrimPrefix(value, "@loader_path/")
	} else if strings.HasPrefix(value, "@executable_path/") {
		base, suffix = path.Dir(ClientInterpreter), strings.TrimPrefix(value, "@executable_path/")
	} else {
		return "", false
	}
	joined := path.Join(base, suffix)
	return joined, validClientPath(joined)
}

func clientImageRPaths(name string, image *macho.File) ([]string, error) {
	var result []string
	for _, load := range image.Loads {
		if item, ok := load.(*macho.Rpath); ok {
			resolved, safe := resolveClientLibrary(name, item.Path)
			if !safe {
				return nil, errors.New("installed_client_library_path_invalid")
			}
			result = append(result, resolved)
		}
	}
	return result, nil
}

// CheckClientNativePayload derives inherited library paths from the actual
// selected interpreter before validating extensions. It never invents an rpath.
func CheckClientNativePayload(files map[string][]byte, roster map[string]ClientFile) error {
	interpreter, ok := files[ClientInterpreter]
	if !ok {
		return errors.New("installed_client_interpreter_missing")
	}
	images, err := clientNativeImages(ClientInterpreter, interpreter)
	if err != nil {
		return err
	}
	// The production interpreter is one thin generic ARM64 executable. Wheels
	// may contain additional non-native slices, which are not executed here.
	if len(images) != 1 {
		return errors.New("installed_client_interpreter_invalid")
	}
	paths, err := clientImageRPaths(ClientInterpreter, images[0])
	if err != nil {
		return err
	}
	for name, raw := range files {
		if err := checkClientNativeFile(name, raw, roster, paths); err != nil {
			return err
		}
	}
	return nil
}

// CheckClientNativeFile validates one file without inherited search paths.
// Production package checks use CheckClientNativePayload for extension loads.
func CheckClientNativeFile(name string, data []byte, roster map[string]ClientFile) error {
	return checkClientNativeFile(name, data, roster, nil)
}

func checkClientNativeFile(name string, data []byte, roster map[string]ClientFile, inherited []string) error {
	if !ClientNativeCandidate(name, data) {
		return nil
	}
	images, err := clientNativeImages(name, data)
	if err != nil {
		return err
	}
	for _, image := range images {
		if err := checkClientNativeImage(name, image, roster, inherited); err != nil {
			return err
		}
	}
	return nil
}

func checkClientNativeImage(name string, image *macho.File, roster map[string]ClientFile, inherited []string) error {
	rpaths, err := clientImageRPaths(name, image)
	if err != nil {
		return err
	}
	rpaths = append(rpaths, inherited...)
	for _, load := range image.Loads {
		raw := load.Raw()
		if len(raw) < 8 {
			return errors.New("installed_client_native_image_invalid")
		}
		command := image.ByteOrder.Uint32(raw[:4])
		if command == 0x27 {
			return errors.New("installed_client_loader_environment_denied")
		}
		if command == 0xe {
			if len(raw) < 12 {
				return errors.New("installed_client_native_image_invalid")
			}
			offset := image.ByteOrder.Uint32(raw[8:12])
			if offset < 12 || offset >= uint32(len(raw)) || string(bytes.TrimRight(raw[offset:], "\x00")) != "/usr/lib/dyld" {
				return errors.New("installed_client_loader_invalid")
			}
		}
		if command != 0xc && command != 0x80000018 && command != 0x8000001f && command != 0x80000023 && command != 0x20 {
			continue
		}
		if len(raw) < 24 {
			return errors.New("installed_client_native_image_invalid")
		}
		offset := image.ByteOrder.Uint32(raw[8:12])
		if offset < 24 || offset >= uint32(len(raw)) {
			return errors.New("installed_client_native_image_invalid")
		}
		value := bytes.SplitN(raw[offset:], []byte{0}, 2)
		if len(value) != 2 {
			return errors.New("installed_client_native_image_invalid")
		}
		library := string(value[0])
		if path.Clean(library) == library && (strings.HasPrefix(library, "/usr/lib/") || strings.HasPrefix(library, "/System/Library/")) {
			continue
		}
		found := false
		if strings.HasPrefix(library, "@rpath/") {
			for _, rpath := range rpaths {
				if _, ok := roster[path.Join(rpath, strings.TrimPrefix(library, "@rpath/"))]; ok {
					found = true
				}
			}
		} else if resolved, ok := resolveClientLibrary(name, library); ok {
			_, found = roster[resolved]
		}
		if !found {
			return errors.New("installed_client_library_outside_package")
		}
	}
	return nil
}
