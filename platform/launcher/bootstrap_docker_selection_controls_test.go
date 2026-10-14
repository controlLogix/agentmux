//go:build (linux || darwin) && agentmux_bootstrap_docker

package launcher

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"golang.org/x/sys/unix"
)

func bootstrapSelectionControl(goos, arch string) bootstrapFixtureSelection {
	s := bootstrapFixtureSelection{SchemaVersion: "1.0.0", Target: "native-" + goos, GOOS: goos, GOARCH: arch,
		WorkspaceRoot: "/review/source", Image: bootstrapFixtureImage, NATSVersion: "2.15.0",
		Docker: ProfileDocker{Backend: NativeUnix, Executable: "/review/tools/docker", Context: "enrolled-engine",
			Endpoint: "unix:///review/engine.sock", EngineID: "separately-enrolled-engine", ClientVersion: "29.8.0", ServerVersion: "29.8.0", ComposeVersion: "5.5.1"}}
	if goos == "darwin" {
		s.Compiler = "/usr/bin/clang"
		s.SDKRoot = "/Applications/Qualified Xcode/MacOSX.sdk"
	}
	return s
}

func bootstrapSelectionControlBytes(t *testing.T, s bootstrapFixtureSelection) ([]byte, string) {
	t.Helper()
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:])
}

func TestBootstrapSelectionNativeMatrixAndLegacyWSL(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, arch := range []string{"amd64", "arm64"} {
			t.Run(goos+"-"+arch, func(t *testing.T) {
				s := bootstrapSelectionControl(goos, arch)
				raw, pin := bootstrapSelectionControlBytes(t, s)
				actual, err := decodeBootstrapFixtureSelection(raw, pin, bootstrapFixtureHost{GOOS: goos, GOARCH: arch})
				if err != nil || actual != s || actual.dockerConfig().Backend != NativeUnix || actual.dockerConfig().EngineID != s.Docker.EngineID {
					t.Fatal("explicit native fixture matrix lost expected identity")
				}
			})
		}
	}
	legacy := bootstrapLegacyWSLSelection()
	raw, pin := bootstrapSelectionControlBytes(t, legacy)
	if got, err := decodeBootstrapFixtureSelection(raw, pin, bootstrapFixtureHost{"linux", "amd64", true}); err != nil || got != legacy {
		t.Fatal("qualified Windows interop constants changed")
	}
	for _, host := range []bootstrapFixtureHost{{"linux", "amd64", false}, {"linux", "arm64", true}, {"darwin", "amd64", false}} {
		if _, err := decodeBootstrapFixtureSelection(raw, pin, host); err == nil {
			t.Fatal("legacy WSL selection admitted on a different actual host")
		}
	}
}

func TestBootstrapSelectionRejectsUnpinnedOrAmbiguousInput(t *testing.T) {
	s := bootstrapSelectionControl("linux", "amd64")
	raw, pin := bootstrapSelectionControlBytes(t, s)
	host := bootstrapFixtureHost{"linux", "amd64", false}
	for name, bad := range map[string][]byte{
		"duplicate":         bytes.Replace(raw, []byte(`"goos":`), []byte(`"goos":"darwin","goos":`), 1),
		"wrong-case":        bytes.Replace(raw, []byte(`"goos":`), []byte(`"GOOS":`), 1),
		"omitted-empty":     bytes.Replace(raw, []byte(`,"compiler":""`), nil, 1),
		"null-empty":        bytes.Replace(raw, []byte(`"compiler":""`), []byte(`"compiler":null`), 1),
		"unknown":           bytes.Replace(raw, []byte(`"target":`), []byte(`"ambient":true,"target":`), 1),
		"duplicate-docker":  bytes.Replace(raw, []byte(`"engineId":`), []byte(`"engineId":"discovered","engineId":`), 1),
		"wrong-docker-case": bytes.Replace(raw, []byte(`"engineId":`), []byte(`"EngineID":`), 1),
		"missing-docker":    bytes.Replace(raw, []byte(`,"composeVersion":"5.5.1"`), nil, 1),
		"trailing":          append(append([]byte{}, raw...), []byte(` {}`)...),
		"oversized":         bytes.Repeat([]byte(" "), 16*1024+1),
	} {
		t.Run(name, func(t *testing.T) {
			sum := sha256.Sum256(bad)
			if _, err := decodeBootstrapFixtureSelection(bad, hex.EncodeToString(sum[:]), host); err == nil {
				t.Fatal("ambiguous enrollment accepted")
			}
		})
	}
	for _, badPin := range []string{"", "sha256:" + pin, strings.ToUpper(pin), strings.Repeat("0", 64)} {
		if _, err := decodeBootstrapFixtureSelection(raw, badPin, host); err == nil {
			t.Fatal("missing or mismatched independent pin accepted")
		}
	}
	changed := append(append([]byte{}, raw...), '\n')
	if _, err := decodeBootstrapFixtureSelection(changed, pin, host); err == nil {
		t.Fatal("changed enrollment bytes accepted under old pin")
	}
}

func TestBootstrapSelectionRejectsWrongHostAndAmbientTargets(t *testing.T) {
	base := bootstrapSelectionControl("linux", "amd64")
	changes := map[string]func(*bootstrapFixtureSelection){
		"cross-arch":          func(s *bootstrapFixtureSelection) { s.GOARCH = "arm64" },
		"cross-os":            func(s *bootstrapFixtureSelection) { s.GOOS = "darwin" },
		"unknown-target":      func(s *bootstrapFixtureSelection) { s.Target = "discover" },
		"wrong-target":        func(s *bootstrapFixtureSelection) { s.Target = "native-darwin" },
		"default-context":     func(s *bootstrapFixtureSelection) { s.Docker.Context = "default" },
		"missing-context":     func(s *bootstrapFixtureSelection) { s.Docker.Context = "" },
		"missing-engine":      func(s *bootstrapFixtureSelection) { s.Docker.EngineID = "" },
		"engine-newline":      func(s *bootstrapFixtureSelection) { s.Docker.EngineID = "engine\nprivate" },
		"remote-engine":       func(s *bootstrapFixtureSelection) { s.Docker.Endpoint = "tcp://127.0.0.1:2375" },
		"relative-socket":     func(s *bootstrapFixtureSelection) { s.Docker.Endpoint = "unix://relative.sock" },
		"socket-traversal":    func(s *bootstrapFixtureSelection) { s.Docker.Endpoint = "unix:///review/../engine.sock" },
		"interop-backend":     func(s *bootstrapFixtureSelection) { s.Docker.Backend = WindowsInterop },
		"relative-cli":        func(s *bootstrapFixtureSelection) { s.Docker.Executable = "docker" },
		"workspace-root":      func(s *bootstrapFixtureSelection) { s.WorkspaceRoot = "/" },
		"workspace-relative":  func(s *bootstrapFixtureSelection) { s.WorkspaceRoot = "source" },
		"unpinned-image":      func(s *bootstrapFixtureSelection) { s.Image = "nats:latest" },
		"unsupported-nats":    func(s *bootstrapFixtureSelection) { s.NATSVersion = "2.16.0" },
		"unsupported-compose": func(s *bootstrapFixtureSelection) { s.Docker.ComposeVersion = "5.6.0" },
		"version-missing":     func(s *bootstrapFixtureSelection) { s.Docker.ServerVersion = "" },
		"linux-compiler":      func(s *bootstrapFixtureSelection) { s.Compiler = "/usr/bin/clang" },
		"linux-sdk":           func(s *bootstrapFixtureSelection) { s.SDKRoot = "/review/sdk" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			s := base
			change(&s)
			raw, pin := bootstrapSelectionControlBytes(t, s)
			if _, err := decodeBootstrapFixtureSelection(raw, pin, bootstrapFixtureHost{"linux", "amd64", false}); err == nil {
				t.Fatal("unqualified selection accepted")
			}
		})
	}
	raw, pin := bootstrapSelectionControlBytes(t, base)
	if _, err := decodeBootstrapFixtureSelection(raw, pin, bootstrapFixtureHost{"linux", "amd64", true}); err == nil {
		t.Fatal("WSL presented as native Linux")
	}
	for _, arch := range []string{"amd64", "arm64"} {
		s := bootstrapSelectionControl("darwin", arch)
		for _, compiler := range []string{"", "clang", "/review/clang"} {
			s.Compiler = compiler
			if validateBootstrapFixtureSelection(s, bootstrapFixtureHost{"darwin", arch, false}) == nil {
				t.Fatal("unselected Apple compiler accepted")
			}
		}
		s.Compiler = "/usr/bin/clang"
		for _, sdk := range []string{"", "sdk", "/review/sdk", "/review/\"bad.sdk"} {
			s.SDKRoot = sdk
			if validateBootstrapFixtureSelection(s, bootstrapFixtureHost{"darwin", arch, false}) == nil {
				t.Fatal("missing or unsafe Apple SDK accepted")
			}
		}
	}
}

func TestBootstrapSelectionBuildCommandsStayNative(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, arch := range []string{"amd64", "arm64"} {
			t.Run(goos+"-"+arch, func(t *testing.T) {
				s := bootstrapSelectionControl(goos, arch)
				inherited := []string{"HOME=/review/home", "PATH=/review/tools", "GOOS=windows", "GOARCH=386", "CGO_ENABLED=0", "CGO_CFLAGS=-Dwrong", "GOFLAGS=-buildmode=plugin", "CC=hostile", "SDKROOT=/wrong", "GOTOOLCHAIN=auto", "GOPROXY=https://remote", "GOSUMDB=sum.golang.org", "GO111MODULE=off"}
				plan, err := bootstrapKernelBuild(s, bootstrapFixtureHost{goos, arch, false}, "/review/go", "/review/out/kernel", inherited)
				if err != nil || plan.Executable != "/review/go/bin/go" || !reflect.DeepEqual(plan.Args, []string{"build", "-trimpath", "-ldflags=-s -w", "-o", "/review/out/kernel", "./cmd/agentmux-kernel"}) {
					t.Fatal("literal native build arguments differ")
				}
				env := map[string]string{}
				for _, item := range plan.Env {
					key, value, _ := strings.Cut(item, "=")
					if _, exists := env[key]; exists {
						t.Fatal("ambiguous duplicate build environment")
					}
					env[key] = value
				}
				if env["GOOS"] != goos || env["GOARCH"] != arch || env["GOTOOLCHAIN"] != "local" || env["GOENV"] != "off" || env["GOFLAGS"] != "" || env["GOPROXY"] != "off" || env["GOSUMDB"] != "off" || env["GO111MODULE"] != "on" || env["HOME"] != "/review/home" {
					t.Fatal("build authority came from inherited host overrides")
				}
				if goos == "darwin" {
					if env["CGO_ENABLED"] != "1" || env["CC"] != "/usr/bin/clang" || env["SDKROOT"] != s.SDKRoot || env["CGO_CFLAGS"] != `-isysroot "`+s.SDKRoot+`"` || env["CGO_LDFLAGS"] != env["CGO_CFLAGS"] {
						t.Fatal("native Apple CGO and SDK binding lost")
					}
				} else if env["CGO_ENABLED"] != "0" || env["CC"] != "" || env["SDKROOT"] != "" || env["CGO_CFLAGS"] != "" {
					t.Fatal("Linux static build inherited CGO settings")
				}
			})
		}
	}
	if _, err := bootstrapKernelBuild(bootstrapSelectionControl("linux", "arm64"), bootstrapFixtureHost{"linux", "amd64", false}, "/review/go", "/review/out/kernel", nil); err == nil {
		t.Fatal("cross-build could be presented as a native fixture")
	}
}

func TestBootstrapSelectionCopiesAndSignsExactRoles(t *testing.T) {
	release := signedReleaseFixture(t)
	stage, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Mkdir(filepath.Join(stage, "bin"), 0700) != nil {
		t.Fatal("copy fixture setup failed")
	}
	binary := []byte("test-only member bytes; no executable qualification")
	members, err := bootstrapCopyRoleMembers(stage, binary)
	if err != nil || len(members) != 4 {
		t.Fatal("four fixed role copies failed")
	}
	release.policy.PackageDirectory = stage
	release.assembly["plugins"] = members
	release.refresh(t)
	verified, err := LoadInstalledRelease(release.policy)
	if err != nil || len(verified.VerifiedAssembly().Members()) != 4 {
		t.Fatal("new role digests were not signed and verified")
	}
	for _, role := range protocol.Roles() {
		path := filepath.Join(stage, "bin", role)
		raw, err := os.ReadFile(path)
		info, statErr := os.Lstat(path)
		if err != nil || statErr != nil || !bytes.Equal(raw, binary) || info.Mode().Perm() != 0700 {
			t.Fatal("fixed role bytes or private mode differ")
		}
	}
	if _, err := bootstrapCopyRoleMembers(stage, []byte("replacement")); err == nil {
		t.Fatal("copy overwrote an existing role")
	}
	if _, err := bootstrapCopyRoleMembers(stage, nil); err == nil {
		t.Fatal("empty role image admitted")
	}
	for _, role := range protocol.Roles() {
		raw, _ := os.ReadFile(filepath.Join(stage, "bin", role))
		if !bytes.Equal(raw, binary) {
			t.Fatal("collision changed an existing image")
		}
	}
}

func TestBootstrapSelectionProtectedCopyPlanAndLeases(t *testing.T) {
	destination := bootstrapDarwinReleaseBase + "/" + strings.Repeat("a", 64)
	copies, err := bootstrapDarwinCopies("/review/stage", destination)
	if err != nil || len(copies) != 8 {
		t.Fatal("protected copy plan failed")
	}
	for index, copy := range copies {
		if !strings.HasPrefix(copy.Source, "/review/stage/") || !strings.HasPrefix(copy.Destination, destination+"/") {
			t.Fatal("copy escaped the fixed source or destination")
		}
		if index < 4 && copy.Mode != "0444" || index >= 4 && copy.Mode != "0555" {
			t.Fatal("protected copy mode changed")
		}
	}
	for _, bad := range []string{"/tmp/" + strings.Repeat("a", 64), bootstrapDarwinReleaseBase + "/short", destination + "/../" + strings.Repeat("b", 64)} {
		if _, err := bootstrapDarwinCopies("/review/stage", bad); err == nil {
			t.Fatal("unprotected installation target accepted")
		}
	}
	for index, identity := range bootstrapFixtureRoleLeaseIDs("enrolled-native-engine") {
		if identity != "enrolled-native-engine:runtime:"+protocol.Roles()[index] {
			t.Fatal("cleanup lease fell back to WSL engine")
		}
	}
}

func TestBootstrapSelectionDescriptorRejectsActualSubstitutions(t *testing.T) {
	selected := bootstrapSelectionControl("linux", "amd64")
	raw, pin := bootstrapSelectionControlBytes(t, selected)
	host := bootstrapFixtureHost{"linux", "amd64", false}
	for _, kind := range []string{"regular", "symlink", "fifo", "directory", "changed-file"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "selection.json")
			if os.WriteFile(path, raw, 0600) != nil {
				t.Fatal("descriptor fixture write failed")
			}
			open := func(name string) (*os.File, error) {
				if kind != "regular" {
					if os.Rename(path, path+"-original") != nil {
						t.Fatal("substitution setup failed")
					}
					switch kind {
					case "symlink":
						if os.Symlink(path+"-original", path) != nil {
							t.Fatal("symlink substitution failed")
						}
					case "fifo":
						if unix.Mkfifo(path, 0600) != nil {
							t.Fatal("FIFO substitution failed")
						}
					case "directory":
						if os.Mkdir(path, 0700) != nil {
							t.Fatal("directory substitution failed")
						}
					case "changed-file":
						if os.WriteFile(path, raw, 0600) != nil {
							t.Fatal("inode substitution failed")
						}
					}
				}
				return bootstrapOpenSelection(name)
			}
			started := time.Now()
			actual, err := readBootstrapFixtureSelection(path, pin, host, open)
			if kind == "regular" {
				if err != nil || actual != selected {
					t.Fatal("held regular-file enrollment refused")
				}
			} else if err == nil || actual != (bootstrapFixtureSelection{}) {
				t.Fatal("substituted descriptor admitted")
			}
			if time.Since(started) > time.Second {
				t.Fatal("special-file refusal was not prompt")
			}
		})
	}
}
