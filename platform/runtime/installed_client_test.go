//go:build linux || darwin

package runtime

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/controlLogix/agentmux/platform/privatefs"
)

func TestInstalledRegisteredCoreRejectsInvalidArgumentsBeforeAdmission(t *testing.T) {
	original, err := os.CreateTemp(t.TempDir(), "registration")
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	var admission *InstalledClientAdmission
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, arguments := range [][]string{{"start"}, {"kill", "falcon-worker-one", "--operation-id", "original-stop"}, {"post", "--", "literal $(body); 'quotes'"}, {strings.Repeat("a", 65536)}, make([]string, 128)} {
		if err := admission.ExecRegisteredCore(context.Background(), "/private/selected.json", original, digest, "/approved/repo 'literal' $(name)", arguments); err == nil || err.Error() != "installed_client_recheck_invalid" {
			t.Fatal("valid core form bypassed retained admission or changed literal inputs", err)
		}
	}
	for _, mode := range []string{"selection", "repository", "registration", "digest", "empty", "too-many", "too-long", "nul"} {
		t.Run(mode, func(t *testing.T) {
			selection, repository, selectedDigest, file := "/private/selected.json", "/approved/repo", digest, original
			arguments := []string{"agents"}
			switch mode {
			case "selection":
				selection = "relative"
			case "repository":
				repository = "/approved/../other"
			case "registration":
				file = nil
			case "digest":
				selectedDigest = "sha256:invalid"
			case "empty":
				arguments = nil
			case "too-many":
				arguments = make([]string, 129)
			case "too-long":
				arguments = []string{strings.Repeat("a", 65537)}
			case "nul":
				arguments = []string{"agents\x00ignored"}
			}
			if err := admission.ExecRegisteredCore(context.Background(), selection, file, selectedDigest, repository, arguments); err == nil || err.Error() != "installed_client_command_invalid" {
				t.Fatal("invalid core command reached admission", err)
			}
			if _, err := original.Stat(); err != nil {
				t.Fatal("refusal consumed borrowed registration", err)
			}
		})
	}
}

type coreRefusalBackend struct {
	checks, closes int
	failure        error
}

func (b *coreRefusalBackend) recheck(context.Context) error { b.checks++; return b.failure }
func (b *coreRefusalBackend) close() error                  { b.closes++; return nil }

func TestInstalledRegisteredCoreRetainsBorrowedRegistrationOnRecheckFailure(t *testing.T) {
	original, err := os.CreateTemp(t.TempDir(), "registration")
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	failure := errors.New("retained client changed")
	backend := &coreRefusalBackend{failure: failure}
	frontend := &frontendTestValidation{}
	admission := &InstalledClientAdmission{backend: backend, frontend: &InstalledFrontendImage{image: frontend}}
	err = admission.ExecRegisteredCore(context.Background(), "/private/selected.json", original,
		"sha256:"+strings.Repeat("a", 64), "/approved/repo", []string{"spawn", "falcon", "worker", "one"})
	if !errors.Is(err, failure) || backend.checks != 1 || frontend.calls != 0 || backend.closes != 0 {
		t.Fatal("recheck refusal lost original owner or reached exec", err)
	}
	if _, err := original.Stat(); err != nil {
		t.Fatal("borrowed registration closed on refusal", err)
	}
	if err := admission.Close(); err != nil {
		t.Fatal(err)
	}
	if err := admission.Close(); err != nil || backend.closes != 1 || frontend.closes != 1 {
		t.Fatal("admission cleanup replayed", err)
	}
	if _, err := original.Stat(); err != nil {
		t.Fatal("admission cleanup consumed caller registration", err)
	}
}

func TestInstalledClientEnvironmentPreservesOnlyExactRestriction(t *testing.T) {
	for name, value := range map[string]string{
		"PATH": "/untrusted/bin", "HOME": "/untrusted/home", "LANG": "untrusted",
		"LC_CTYPE": "untrusted", "AGENTMUX_BIN": "/untrusted/harness",
		"AGENTMUX_HUB": "/untrusted/hub", "AGENTMUX_TOKEN": "untrusted-token",
		"PYTHONPATH": "/untrusted/python", "BASH_ENV": "/untrusted/shell",
	} {
		t.Setenv(name, value)
	}
	for _, value := range []string{"", "0", "true", " 1", "1 ", "1\n", "1"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("AGENTMUX_NO_BYPASS", value)
			for _, home := range []string{"", "/Users/admitted user"} {
				want := []string{"PATH=/usr/bin:/bin", "LANG=en_US.UTF-8", "LC_CTYPE=UTF-8"}
				if home != "" {
					want = append(want, "HOME="+home)
				}
				if value == "1" {
					want = append(want, "AGENTMUX_NO_BYPASS=1")
				}
				if got := installedClientEnvironment(home); !slices.Equal(got, want) {
					t.Fatalf("installed environment differed: got %q, want %q", got, want)
				}
			}
		})
	}
	t.Setenv("AGENTMUX_NO_BYPASS", "1")
	if err := os.Unsetenv("AGENTMUX_NO_BYPASS"); err != nil {
		t.Fatal(err)
	}
	if got := installedClientEnvironment(""); !slices.Equal(got,
		[]string{"PATH=/usr/bin:/bin", "LANG=en_US.UTF-8", "LC_CTYPE=UTF-8"}) {
		t.Fatal("absent restriction changed the closed environment", got)
	}
}

func TestInstalledClientDesktopRequiresRetainedAdmission(t *testing.T) {
	var admission *InstalledClientAdmission
	for _, operation := range []string{"mcp", "startup", "launch-claude-desktop"} {
		if err := admission.Exec(context.Background(), operation, "/private/selected.json"); err == nil || err.Error() != "installed_client_recheck_invalid" {
			t.Fatal("client command bypassed retained admission", err)
		}
	}
	if err := admission.Exec(context.Background(), "launch-claude-desktop", "/private/../unselected.json"); err == nil || err.Error() != "installed_client_selection_invalid" {
		t.Fatal("Desktop route accepted a noncanonical selection", err)
	}
	for _, operation := range []string{"launch-app", "application-services"} {
		if err := admission.Exec(context.Background(), operation, "/private/selected.json"); err == nil || err.Error() != "installed_client_command_invalid" {
			t.Fatal("unsupported public application command accepted", err)
		}
	}
}

func TestInstalledClientProfileOperationsRequireRetainedAdmission(t *testing.T) {
	var admission *InstalledClientAdmission
	for _, operation := range []string{"startup", "startup-json", "startup-worker", "startup-worker-json", "mcp", "mcp-worker", "dashboard", "claude-code-hook", "claude-code-hook-worker"} {
		t.Run(operation, func(t *testing.T) {
			if err := admission.Exec(context.Background(), operation, "/private/a 'literal' $(selection).json"); err == nil || err.Error() != "installed_client_recheck_invalid" {
				t.Fatal("profile operation bypassed retained admission", err)
			}
			for _, selection := range []string{"relative", "/private/../selection.json", "/private/selection.json\n"} {
				if err := admission.Exec(context.Background(), operation, selection); err == nil || err.Error() != "installed_client_selection_invalid" {
					t.Fatal("profile operation accepted an invalid selection", err)
				}
			}
		})
	}
	for _, operation := range []string{"", "mcp-json", "mcp-worker-json", "startup-json-worker", "startup --managed-worker", "startup-worker --output json", "application-services", "client-setup", "launch-app", "repository-client", "registered-client"} {
		if err := admission.Exec(context.Background(), operation, "/private/selected.json"); err == nil || err.Error() != "installed_client_command_invalid" {
			t.Fatal("unsupported profile operation accepted", err)
		}
	}
}

func TestInstalledClientRepositoryOperationsRequireRetainedAdmission(t *testing.T) {
	var admission *InstalledClientAdmission
	for _, operation := range []string{"startup", "startup-json", "startup-worker", "startup-worker-json", "mcp", "mcp-worker"} {
		t.Run(operation, func(t *testing.T) {
			for _, repository := range []string{"/private/a 'literal' $(repository)", "/private/répertoire", strings.Repeat("/r", 127)} {
				if err := admission.ExecRepository(context.Background(), operation, repository); err == nil || err.Error() != "installed_client_recheck_invalid" {
					t.Fatal("repository operation bypassed retained admission", err)
				}
			}
			for _, repository := range []string{"relative", "/", "//private/repository", "/private/../repository", "/private/repository\n", "/private/repository\t", "/private/repository\x7f", "/private/repository\u0085", "/private/repository\u009f", "/private/\xff", "/" + strings.Repeat("r", 4096), "/" + strings.Repeat("é", 2048), strings.Repeat("/r", 128)} {
				if err := admission.ExecRepository(context.Background(), operation, repository); err == nil || err.Error() != "installed_client_repository_invalid" {
					t.Fatal("repository operation accepted an invalid root", err)
				}
			}
		})
	}
	for _, operation := range []string{"", "mcp-json", "mcp-worker-json", "startup-json-worker", "startup --managed-worker", "dashboard", "application-services", "client-setup", "launch-claude-desktop", "repository-client", "registered-client", "claude-code-hook", "claude-code-hook-worker"} {
		if err := admission.ExecRepository(context.Background(), operation, "/private/repository"); err == nil || err.Error() != "installed_client_command_invalid" {
			t.Fatal("unsupported repository operation accepted", err)
		}
	}
}

func TestInstalledClientSetupHomeIgnoresCallerEnvironment(t *testing.T) {
	if os.Geteuid() == 0 {
		if _, err := installedClientAccountHome(); err == nil {
			t.Fatal("administrator accepted as ordinary setup user")
		}
		return
	}
	account, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		t.Fatal("native account unavailable", err)
	}
	t.Setenv("HOME", "/private/unselected-home")
	home, err := installedClientAccountHome()
	if err != nil || home != account.HomeDir || home == os.Getenv("HOME") {
		t.Fatal("ambient HOME redirected native setup", err)
	}
}

func TestClaudeHookSettingsPathPreservesSelectedNamespace(t *testing.T) {
	for _, item := range []struct {
		override string
		present  bool
		want     string
	}{
		{"", false, "/Users/example/.claude/settings.json"},
		{"/private/Claude 'literal' $(path)", true, "/private/Claude 'literal' $(path)/settings.json"},
	} {
		got, err := claudeHookSettingsPath("/Users/example", item.override, item.present)
		if err != nil || got != item.want {
			t.Fatal("selected Claude namespace changed", err)
		}
	}
	for _, invalid := range []string{"", "/", "relative", "//private/claude", "/private/../claude", "/private/claude\n", "/private/claude\t", "/private/\xff", "/" + strings.Repeat("a", 4090)} {
		if _, err := claudeHookSettingsPath("/Users/example", invalid, true); err == nil {
			t.Fatal("invalid override fell back to the default namespace")
		}
	}
}

func installedClientFixture(t *testing.T) (string, string) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	names := []string{ClientBootstrap, ClientInterpreter, "python/lib/libpython3.14.dylib", "python/lib/python3.14/os.py", "app/hub/cli.py", "app/hub/client_launch_entrypoint.py", "app/hub/client_launch_coordinator.py", "app/sdk/python/agentmux_contracts/validation.py", "app/contracts/v1/schemas/startup-status-observation.schema.json", "app/client-requirements.lock", "app/hub/__init__.py"}
	sort.Strings(names)
	m := ClientManifest{SchemaVersion: "1.0.0", Kind: "ordinary-python-client", FoundationInstallationID: strings.Repeat("a", 64), FrontendDigest: "sha256:" + strings.Repeat("b", 64), PythonVersion: ClientPythonVersion, Interpreter: ClientInterpreter, Bootstrap: ClientBootstrap}
	for _, name := range names {
		raw := []byte("selected " + name)
		if name == "app/hub/__init__.py" {
			raw = nil
		}
		mode := uint32(0444)
		if name == ClientInterpreter {
			mode = 0555
		}
		m.Files = append(m.Files, ClientFile{name, ClientDigest(raw), int64(len(raw)), mode})
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.TrimPrefix(ClientDigest(raw), "sha256:")
	root := filepath.Join(base, id)
	for _, file := range m.Files {
		name := filepath.Join(root, file.Path)
		data := []byte("selected " + file.Path)
		if file.Size == 0 {
			data = nil
		}
		if os.MkdirAll(filepath.Dir(name), 0755) != nil || os.WriteFile(name, data, os.FileMode(file.Mode)) != nil {
			t.Fatal("client fixture unavailable")
		}
	}
	if os.WriteFile(filepath.Join(root, "client-manifest.json"), raw, 0444) != nil {
		t.Fatal("manifest unavailable")
	}
	return root, id
}

func privateClientTree(t *testing.T, root, id string) *clientTreeAdmission {
	t.Helper()
	a, err := admitClientTree(context.Background(), root, id, uint32(os.Geteuid()), func(*os.File, privatefs.AccessKind) error { return nil }, func(string, []byte, map[string]ClientFile) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if a.close() != nil {
			t.Error("client admission cleanup failed")
		}
	})
	return a
}

func TestInstalledClientRetainsAdmissionAndRejectsMutation(t *testing.T) {
	for _, fault := range []string{"content", "same-content-replacement", "extra", "symlink", "mode", "hardlink", "missing"} {
		t.Run(fault, func(t *testing.T) {
			root, id := installedClientFixture(t)
			a := privateClientTree(t, root, id)
			if err := a.recheck(context.Background()); err != nil {
				t.Fatal("unchanged admission rejected", err)
			}
			name := filepath.Join(root, "app/hub/cli.py")
			switch fault {
			case "content":
				os.Chmod(name, 0600)
				os.WriteFile(name, []byte("changed"), 0600)
				os.Chmod(name, 0444)
			case "same-content-replacement":
				raw, _ := os.ReadFile(name)
				os.Remove(name)
				os.WriteFile(name, raw, 0444)
			case "extra":
				os.WriteFile(filepath.Join(root, "foreign.py"), nil, 0444)
			case "symlink":
				os.Remove(name)
				os.Symlink("/etc/passwd", name)
			case "mode":
				os.Chmod(name, 0666)
			case "hardlink":
				os.Link(name, filepath.Join(filepath.Dir(root), "alias"))
			case "missing":
				os.Remove(name)
			}
			if err := a.recheck(context.Background()); err == nil {
				t.Fatal("changed installed client admitted")
			}
		})
	}
}

func TestInstalledClientNativeACLFailureAndCancellationRefuse(t *testing.T) {
	root, id := installedClientFixture(t)
	check := func(*os.File, privatefs.AccessKind) error { return privatefs.ErrAccessDenied }
	if a, err := admitClientTree(context.Background(), root, id, uint32(os.Geteuid()), check, CheckClientNativeFile); err == nil || a != nil {
		t.Fatal("native permission failure admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if a, err := admitClientTree(ctx, root, id, uint32(os.Geteuid()), check, CheckClientNativeFile); err == nil || a != nil {
		t.Fatal("cancelled admission accepted")
	}
}

func TestInstalledClientCloseKeepsConsumedHandleFailure(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "admission")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	tree := &clientTreeAdmission{parents: []*os.File{file}}
	owner := &InstalledClientAdmission{backend: tree}
	first := owner.Close()
	if first == nil || len(tree.uncertainCloses) != 1 || len(tree.parents) != 0 {
		t.Fatal("consumed descriptor failure lost its owner")
	}
	if second := owner.Close(); second != first || len(tree.uncertainCloses) != 1 {
		t.Fatal("close retried a consumed descriptor or lost uncertainty")
	}
	if failure, ok := first.(*clientFailure); !ok || failure.owner == nil {
		t.Fatal("cleanup diagnostic lost its concrete owner")
	}
}

func TestInstalledClientManifestIdentityIncludesFoundationAndFrontend(t *testing.T) {
	root, id := installedClientFixture(t)
	raw, err := os.ReadFile(filepath.Join(root, "client-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"foundationInstallationId", "frontendDigest"} {
		var m map[string]any
		json.Unmarshal(raw, &m)
		m[field] = strings.Replace(m[field].(string), "a", "c", 1)
		if field == "frontendDigest" {
			m[field] = "sha256:" + strings.Repeat("c", 64)
		}
		changed, _ := json.Marshal(m)
		if ClientDigest(changed) == "sha256:"+id {
			t.Fatal("foundation/frontend not bound to client identity")
		}
	}
}

func TestClientNativeDependencyCannotEscapePackage(t *testing.T) {
	makeImage := func(library string) []byte {
		name := append([]byte(library), 0)
		commandSize := (24 + len(name) + 7) &^ 7
		raw := make([]byte, 32+commandSize)
		for i, value := range []uint32{0xfeedfacf, 0x100000c, 0, 2, 1, uint32(commandSize), 0, 0} {
			binary.LittleEndian.PutUint32(raw[i*4:], value)
		}
		binary.LittleEndian.PutUint32(raw[32:], 0xc)
		binary.LittleEndian.PutUint32(raw[36:], uint32(commandSize))
		binary.LittleEndian.PutUint32(raw[40:], 24)
		copy(raw[56:], name)
		return raw
	}
	roster := map[string]ClientFile{"python/lib/bundled.dylib": {Path: "python/lib/bundled.dylib"}}
	for _, library := range []string{"/opt/homebrew/lib/external.dylib", "@rpath/missing.dylib", "@rpath/bundled.dylib", "@loader_path/../../../outside.dylib"} {
		if CheckClientNativeFile(ClientInterpreter, makeImage(library), roster) == nil {
			t.Fatal("external native library admitted", library)
		}
	}
	for _, library := range []string{"/usr/lib/libSystem.B.dylib", "@loader_path/../lib/bundled.dylib"} {
		if err := CheckClientNativeFile(ClientInterpreter, makeImage(library), roster); err != nil {
			t.Fatal("selected library refused", err)
		}
	}
}

func clientNativeTestImage(library, rpath string, subtype uint32) []byte {
	name := append([]byte(library), 0)
	commandSize := (24 + len(name) + 7) &^ 7
	rpathSize := 0
	commands := uint32(1)
	if rpath != "" {
		rpathSize = (12 + len(rpath) + 1 + 7) &^ 7
		commands++
	}
	raw := make([]byte, 32+commandSize+rpathSize)
	for i, value := range []uint32{0xfeedfacf, 0x100000c, subtype, 2, commands, uint32(commandSize + rpathSize), 0, 0} {
		binary.LittleEndian.PutUint32(raw[i*4:], value)
	}
	binary.LittleEndian.PutUint32(raw[32:], 0xc)
	binary.LittleEndian.PutUint32(raw[36:], uint32(commandSize))
	binary.LittleEndian.PutUint32(raw[40:], 24)
	copy(raw[56:], name)
	if rpath != "" {
		offset := 32 + commandSize
		binary.LittleEndian.PutUint32(raw[offset:], 0x8000001c)
		binary.LittleEndian.PutUint32(raw[offset+4:], uint32(rpathSize))
		binary.LittleEndian.PutUint32(raw[offset+8:], 12)
		copy(raw[offset+12:], rpath)
	}
	return raw
}

func TestClientNativeFatImageRejectsHiddenGenericArm64Slice(t *testing.T) {
	for _, subtype := range []uint32{99, 0} {
		safe := clientNativeTestImage("/usr/lib/libSystem.B.dylib", "", subtype)
		dangerous := clientNativeTestImage("/opt/homebrew/unselected.dylib", "", 0)
		fat := make([]byte, 48+len(safe)+len(dangerous))
		binary.BigEndian.PutUint32(fat, 0xcafebabe)
		binary.BigEndian.PutUint32(fat[4:], 2)
		for index, slice := range [][]byte{safe, dangerous} {
			header := 8 + index*20
			offset := 48
			if index == 1 {
				offset += len(safe)
			}
			binary.BigEndian.PutUint32(fat[header:], 0x100000c)
			binary.BigEndian.PutUint32(fat[header+4:], binary.LittleEndian.Uint32(slice[8:]))
			binary.BigEndian.PutUint32(fat[header+8:], uint32(offset))
			binary.BigEndian.PutUint32(fat[header+12:], uint32(len(slice)))
			copy(fat[offset:], slice)
		}
		if CheckClientNativeFile(ClientInterpreter, fat, nil) == nil {
			t.Fatal("hidden native fat slice admitted")
		}
	}
}

func TestClientNativePayloadUsesActualInterpreterRPath(t *testing.T) {
	roster := map[string]ClientFile{"python/lib/libpython3.14.dylib": {Path: "python/lib/libpython3.14.dylib"}, "python/lib/extension-library.dylib": {Path: "python/lib/extension-library.dylib"}}
	for _, rpath := range []string{"", "@executable_path/../lib"} {
		files := map[string][]byte{
			ClientInterpreter:            clientNativeTestImage("@rpath/libpython3.14.dylib", rpath, 0),
			"site-packages/extension.so": clientNativeTestImage("@rpath/extension-library.dylib", "", 0),
		}
		err := CheckClientNativePayload(files, roster)
		if (err == nil) != (rpath != "") {
			t.Fatal("native payload used invented interpreter rpath", err)
		}
	}
}
