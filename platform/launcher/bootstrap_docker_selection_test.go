//go:build (linux || darwin) && agentmux_bootstrap_docker

package launcher

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"golang.org/x/sys/unix"
)

// Expected identities come from separately pinned CI enrollment, not discovery.
// This is fixture input, not a product enrollment or a native qualification result.
type bootstrapFixtureSelection struct {
	SchemaVersion string        `json:"schemaVersion"`
	Target        string        `json:"target"`
	GOOS          string        `json:"goos"`
	GOARCH        string        `json:"goarch"`
	WorkspaceRoot string        `json:"workspaceRoot"`
	Docker        ProfileDocker `json:"docker"`
	Image         string        `json:"image"`
	NATSVersion   string        `json:"natsVersion"`
	Compiler      string        `json:"compiler"`
	SDKRoot       string        `json:"sdkRoot"`
}

type bootstrapFixtureHost struct {
	GOOS, GOARCH string
	WSL          bool
}

func bootstrapSelectionError() error { return errors.New("fixture_selection_invalid_or_unpinned") }

func decodeBootstrapFixtureSelection(raw []byte, pin string, host bootstrapFixtureHost) (bootstrapFixtureSelection, error) {
	var selected bootstrapFixtureSelection
	sum := sha256.Sum256(raw)
	if !fullID.MatchString(pin) || hex.EncodeToString(sum[:]) != pin ||
		protocol.DecodeClosedJSON(raw, &selected, 16*1024) != nil {
		return bootstrapFixtureSelection{}, bootstrapSelectionError()
	}
	// Explicit fields also reject wrong-case aliases and omitted empty fields.
	fields, err := releaseFields(raw, "schemaVersion", "target", "goos", "goarch", "workspaceRoot", "docker", "image", "natsVersion", "compiler", "sdkRoot")
	if err != nil {
		return bootstrapFixtureSelection{}, bootstrapSelectionError()
	}
	if _, err := releaseFields(fields["docker"], "backend", "executable", "context", "endpoint", "engineId", "clientVersion", "serverVersion", "composeVersion"); err != nil {
		return bootstrapFixtureSelection{}, bootstrapSelectionError()
	}
	for key, value := range fields {
		if key != "docker" && (len(bytes.TrimSpace(value)) == 0 || bytes.TrimSpace(value)[0] != '"') {
			return bootstrapFixtureSelection{}, bootstrapSelectionError()
		}
	}
	if err := validateBootstrapFixtureSelection(selected, host); err != nil {
		return bootstrapFixtureSelection{}, err
	}
	return selected, nil
}

func bootstrapFixtureAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\x00\r\n")
}

func validateBootstrapFixtureSelection(s bootstrapFixtureSelection, host bootstrapFixtureHost) error {
	d := s.Docker
	if s.SchemaVersion != "1.0.0" || s.GOOS != host.GOOS || s.GOARCH != host.GOARCH ||
		(s.GOARCH != "amd64" && s.GOARCH != "arm64") || !bootstrapFixtureAbsolute(s.WorkspaceRoot) || s.WorkspaceRoot == "/" ||
		!bootstrapFixtureAbsolute(d.Executable) || !slug.MatchString(d.Context) || d.Context == "default" ||
		len(d.EngineID) == 0 || len(d.EngineID) > 128 || strings.ContainsAny(d.EngineID, "\x00\r\n\t ") ||
		!version.MatchString(d.ClientVersion) || !version.MatchString(d.ServerVersion) || !version.MatchString(d.ComposeVersion) ||
		!strings.HasPrefix(s.Image, "docker.io/library/nats@sha256:") || !digest.MatchString(strings.TrimPrefix(s.Image, "docker.io/library/nats@")) ||
		s.NATSVersion != "2.15.0" || d.ComposeVersion != "5.5.1" {
		return bootstrapSelectionError()
	}
	switch s.Target {
	case "wsl-windows-interop":
		// Keep the already qualified tuple literal. A new engine is not its successor.
		if host.GOOS != "linux" || host.GOARCH != "amd64" || !host.WSL || s != bootstrapLegacyWSLSelection() {
			return bootstrapSelectionError()
		}
	case "wsl-windows-current-qualification":
		// This separate reviewed fixture tuple never replaces the legacy selection.
		if host.GOOS != "linux" || host.GOARCH != "amd64" || !host.WSL || s != bootstrapCurrentWSLQualificationSelection() {
			return bootstrapSelectionError()
		}
	case "native-linux", "native-darwin":
		if host.WSL || s.Target != "native-"+host.GOOS || d.Backend != NativeUnix ||
			!strings.HasPrefix(d.Endpoint, "unix:///") || !bootstrapFixtureAbsolute(strings.TrimPrefix(d.Endpoint, "unix://")) ||
			strings.ContainsAny(d.Endpoint, "%?#") {
			return bootstrapSelectionError()
		}
		if host.GOOS == "linux" {
			if s.Compiler != "" || s.SDKRoot != "" {
				return bootstrapSelectionError()
			}
		} else if host.GOOS == "darwin" {
			if s.Compiler != "/usr/bin/clang" || !bootstrapFixtureAbsolute(s.SDKRoot) || !strings.HasSuffix(s.SDKRoot, ".sdk") || strings.ContainsAny(s.SDKRoot, "\"\\") {
				return bootstrapSelectionError()
			}
		} else {
			return bootstrapSelectionError()
		}
	default:
		return bootstrapSelectionError()
	}
	return nil
}

func bootstrapLegacyWSLSelection() bootstrapFixtureSelection {
	return bootstrapFixtureSelection{SchemaVersion: "1.0.0", Target: "wsl-windows-interop", GOOS: "linux", GOARCH: "amd64",
		WorkspaceRoot: "/mnt/c/Users/RyanHelms/GitHub/agentmux", Image: bootstrapFixtureImage, NATSVersion: "2.15.0",
		Docker: ProfileDocker{Backend: WindowsInterop, Executable: bootstrapFixtureDocker, Context: "desktop-linux",
			Endpoint: "npipe:////./pipe/dockerDesktopLinuxEngine", EngineID: bootstrapFixtureEngine,
			ClientVersion: "29.8.0", ServerVersion: "29.8.0", ComposeVersion: "5.5.1"}}
}

// This fixed current-daemon tuple is available only through an explicit pinned
// selection file. It creates fresh disposable fixtures, not an old-profile rebind.
func bootstrapCurrentWSLQualificationSelection() bootstrapFixtureSelection {
	return bootstrapFixtureSelection{SchemaVersion: "1.0.0", Target: "wsl-windows-current-qualification", GOOS: "linux", GOARCH: "amd64",
		WorkspaceRoot: "/mnt/c/Users/RyanHelms/GitHub/agentmux", Image: bootstrapFixtureImage, NATSVersion: "2.15.0",
		Docker: ProfileDocker{Backend: WindowsInterop, Executable: bootstrapFixtureDocker, Context: "desktop-linux",
			Endpoint: "npipe:////./pipe/dockerDesktopLinuxEngine", EngineID: "772de646-ba89-42ac-8675-45b2025fbdee",
			ClientVersion: "29.8.0", ServerVersion: "29.8.0", ComposeVersion: "5.5.1"}}
}

func bootstrapActualHost() bootstrapFixtureHost {
	host := bootstrapFixtureHost{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
	if host.GOOS == "linux" {
		raw, err := os.ReadFile("/proc/sys/kernel/osrelease")
		if err == nil {
			host.WSL = strings.Contains(strings.ToLower(string(raw)), "microsoft")
		}
	}
	return host
}

func loadBootstrapFixtureSelection(t *testing.T) (bootstrapFixtureSelection, string) {
	t.Helper()
	host := bootstrapActualHost()
	path, pin := os.Getenv("AMX_BOOTSTRAP_SELECTION_FILE"), os.Getenv("AMX_BOOTSTRAP_SELECTION_SHA256")
	if path == "" && pin == "" {
		legacy := bootstrapLegacyWSLSelection()
		if validateBootstrapFixtureSelection(legacy, host) != nil {
			t.Fatal("native fixture needs a selection file and its separately enrolled SHA-256")
		}
		return legacy, "qualified-wsl-literal"
	}
	if !bootstrapFixtureAbsolute(path) || !fullID.MatchString(pin) {
		t.Fatal("fixture selection file or separate SHA-256 missing")
	}
	selected, err := readBootstrapFixtureSelection(path, pin, host, bootstrapOpenSelection)
	if err != nil {
		t.Fatal("fixture selection does not match enrollment or actual host")
	}
	return selected, pin
}

func bootstrapOpenSelection(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, bootstrapSelectionError()
	}
	return os.NewFile(uintptr(fd), "fixture-selection"), nil
}

// The private opener seam reproduces substitutions without weakening the real
// no-follow, nonblocking descriptor open or changing any process-wide state.
func readBootstrapFixtureSelection(path, pin string, host bootstrapFixtureHost, open func(string) (*os.File, error)) (bootstrapFixtureSelection, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > 16*1024 {
		return bootstrapFixtureSelection{}, bootstrapSelectionError()
	}
	file, err := open(path)
	if err != nil {
		return bootstrapFixtureSelection{}, bootstrapSelectionError()
	}
	defer file.Close()
	held, err := file.Stat()
	if err != nil || !held.Mode().IsRegular() || !os.SameFile(before, held) {
		return bootstrapFixtureSelection{}, bootstrapSelectionError()
	}
	raw, err := io.ReadAll(io.LimitReader(file, 16*1024+1))
	if err != nil {
		return bootstrapFixtureSelection{}, bootstrapSelectionError()
	}
	return decodeBootstrapFixtureSelection(raw, pin, host)
}

func (s bootstrapFixtureSelection) dockerConfig() DockerConfig {
	d := s.Docker
	return DockerConfig{Executable: d.Executable, Context: d.Context, Endpoint: d.Endpoint, EngineID: d.EngineID,
		Versions: DockerVersions{d.ClientVersion, d.ServerVersion, d.ComposeVersion}, Backend: d.Backend, Timeout: 60 * time.Second}
}

type bootstrapKernelBuildPlan struct {
	Executable string
	Args       []string
	Env        []string
}

func bootstrapKernelBuild(s bootstrapFixtureSelection, host bootstrapFixtureHost, goroot, output string, inherited []string) (bootstrapKernelBuildPlan, error) {
	if validateBootstrapFixtureSelection(s, host) != nil || !bootstrapFixtureAbsolute(goroot) || !bootstrapFixtureAbsolute(output) {
		return bootstrapKernelBuildPlan{}, bootstrapSelectionError()
	}
	var env []string
	for _, item := range inherited {
		key, _, ok := strings.Cut(item, "=")
		if !ok || strings.HasPrefix(key, "CGO_") {
			continue
		}
		switch key {
		case "GOOS", "GOARCH", "GOAMD64", "GOARM64", "GOEXPERIMENT", "GOROOT", "GOTOOLCHAIN", "GOFLAGS", "GOENV", "GOWORK", "GO111MODULE", "GOPROXY", "GOSUMDB", "CC", "CXX", "SDKROOT", "MACOSX_DEPLOYMENT_TARGET":
			continue
		}
		env = append(env, item)
	}
	env = append(env, "GOOS="+s.GOOS, "GOARCH="+s.GOARCH, "GOROOT="+goroot, "GOTOOLCHAIN=local", "GOENV=off", "GOFLAGS=", "GOWORK=off", "GO111MODULE=on", "GOPROXY=off", "GOSUMDB=off")
	if s.GOOS == "darwin" {
		env = append(env, "CGO_ENABLED=1", "CC="+s.Compiler, "CXX=/usr/bin/clang++", "SDKROOT="+s.SDKRoot,
			`CGO_CFLAGS=-isysroot "`+s.SDKRoot+`"`, `CGO_LDFLAGS=-isysroot "`+s.SDKRoot+`"`)
	} else {
		env = append(env, "CGO_ENABLED=0")
	}
	return bootstrapKernelBuildPlan{Executable: filepath.Join(goroot, "bin", "go"),
		Args: []string{"build", "-trimpath", "-ldflags=-s -w", "-o", output, "./cmd/agentmux-kernel"}, Env: env}, nil
}

func bootstrapCopyRoleMembers(directory string, binary []byte) ([]any, error) {
	if !bootstrapFixtureAbsolute(directory) || len(binary) == 0 {
		return nil, bootstrapSelectionError()
	}
	var members []any
	for _, role := range protocol.Roles() {
		path := filepath.Join(directory, "bin", role)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
		if err != nil {
			return nil, errors.New("fixture_member_copy_failed")
		}
		_, writeErr := file.Write(binary)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			return nil, errors.New("fixture_member_copy_failed")
		}
		members = append(members, map[string]any{"id": role, "entrypoint": "bin/" + role, "binaryDigest": releaseDigest(binary)})
	}
	return members, nil
}

func bootstrapSelectedPort(t *testing.T, selected bootstrapFixtureSelection) int {
	t.Helper()
	if selected.Target == "wsl-windows-interop" || selected.Target == "wsl-windows-current-qualification" {
		return bootstrapWindowsPort(t)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("native loopback port selection failed")
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if listener.Close() != nil || port < 1 || port > 65535 {
		t.Fatal("native loopback port release failed")
	}
	// Selection is once only. The caller checks Docker and loopback conflicts;
	// a later bind collision remains a failure, never permission for takeover.
	return port
}

const bootstrapDarwinReleaseBase = "/Library/Application Support/Agentmux/Protected/releases"

type bootstrapProtectedCopy struct {
	Source, Destination, Mode string
}

func bootstrapDarwinCopies(stage, destination string) ([]bootstrapProtectedCopy, error) {
	if !bootstrapFixtureAbsolute(stage) || !bootstrapFixtureAbsolute(destination) ||
		filepath.Dir(destination) != bootstrapDarwinReleaseBase || !fullID.MatchString(filepath.Base(destination)) {
		return nil, bootstrapSelectionError()
	}
	var result []bootstrapProtectedCopy
	for _, name := range []string{"release-manifest.json", "protected-assembly.json", "release-authorization.json", "release-authorization.sig"} {
		result = append(result, bootstrapProtectedCopy{filepath.Join(stage, name), filepath.Join(destination, name), "0444"})
	}
	for _, role := range protocol.Roles() {
		result = append(result, bootstrapProtectedCopy{filepath.Join(stage, "bin", role), filepath.Join(destination, "bin", role), "0555"})
	}
	return result, nil
}
