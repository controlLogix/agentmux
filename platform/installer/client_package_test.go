//go:build linux || darwin

package installer

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	protected "github.com/controlLogix/agentmux/platform/runtime"
)

func clientFixture(t *testing.T) ClientSelection {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	names := []string{protected.ClientBootstrap, protected.ClientInterpreter, "python/lib/libpython3.14.dylib", "python/lib/python3.14/os.py", "app/hub/cli.py", "app/hub/client_launch_entrypoint.py", "app/hub/client_launch_coordinator.py", "app/sdk/python/agentmux_contracts/validation.py", "app/contracts/v1/schemas/startup-status-observation.schema.json", "app/client-requirements.lock", "app/hub/__init__.py"}
	sort.Strings(names)
	m := protected.ClientManifest{SchemaVersion: "1.0.0", Kind: "ordinary-python-client", FoundationInstallationID: strings.Repeat("a", 64), FrontendDigest: "sha256:" + strings.Repeat("b", 64), PythonVersion: protected.ClientPythonVersion, Interpreter: protected.ClientInterpreter, Bootstrap: protected.ClientBootstrap}
	for _, name := range names {
		data := []byte("selected " + name)
		if name == "app/hub/__init__.py" {
			data = nil
		}
		mode := uint32(0444)
		if name == protected.ClientInterpreter {
			mode = 0555
		}
		path := filepath.Join(root, name)
		if os.MkdirAll(filepath.Dir(path), 0755) != nil || os.WriteFile(path, data, os.FileMode(mode)) != nil {
			t.Fatal("client fixture unavailable")
		}
		m.Files = append(m.Files, protected.ClientFile{Path: name, Digest: hash(data), Size: int64(len(data)), Mode: mode})
	}
	raw, err := json.Marshal(m)
	if err != nil || os.WriteFile(filepath.Join(root, "client-manifest.json"), raw, 0444) != nil {
		t.Fatal("client manifest unavailable")
	}
	return ClientSelection{"1.0.0", root, hash(raw)}
}

func prepareClientFixture(t *testing.T, selected ClientSelection) *ClientPackage {
	t.Helper()
	p, err := prepareClient(context.Background(), selected, func(string, []byte, map[string]protected.ClientFile) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestClientPackageRetainsCompleteBytesAndRefusesConflict(t *testing.T) {
	selected := clientFixture(t)
	p := prepareClientFixture(t, selected)
	path := filepath.Join(selected.PackageDirectory, "app/hub/cli.py")
	if os.Chmod(path, 0600) != nil || os.WriteFile(path, []byte("changed source"), 0600) != nil {
		t.Fatal("mutation failed")
	}
	base, policy := privateDestination(t)
	first, err := installClientAt(context.Background(), base, p, policy)
	if err != nil || first.Outcome != "installed" || first.Readiness != "not_observed" || first.Enrollment != "not_checked" {
		t.Fatal("client copy failed", err)
	}
	raw, err := os.ReadFile(filepath.Join(base.Name(), p.id, "app/hub/cli.py"))
	if err != nil || string(raw) != "selected app/hub/cli.py" {
		t.Fatal("changed source was reopened")
	}
	second, err := installClientAt(context.Background(), base, p, policy)
	if err != nil || second.Outcome != "reused" {
		t.Fatal("exact reuse failed", err)
	}
	if os.WriteFile(filepath.Join(base.Name(), p.id, "foreign"), []byte("retain"), 0600) != nil {
		t.Fatal("foreign file unavailable")
	}
	if _, err := installClientAt(context.Background(), base, p, policy); err == nil {
		t.Fatal("extra installed file admitted")
	}
	if raw, err := os.ReadFile(filepath.Join(base.Name(), p.id, "foreign")); err != nil || string(raw) != "retain" {
		t.Fatal("conflict modified foreign file")
	}
}

func TestClientPackageRejectsChangedMissingExtraLinksAndWrongPython(t *testing.T) {
	for _, fault := range []string{"changed", "missing", "extra", "symlink", "hardlink", "python", "mode", "native", "duplicate", "missing-size"} {
		t.Run(fault, func(t *testing.T) {
			selected := clientFixture(t)
			path := filepath.Join(selected.PackageDirectory, "app/hub/cli.py")
			manifest := filepath.Join(selected.PackageDirectory, "client-manifest.json")
			switch fault {
			case "changed":
				os.Chmod(path, 0600)
				os.WriteFile(path, []byte("wrong"), 0600)
			case "missing":
				os.Remove(path)
			case "extra":
				os.WriteFile(filepath.Join(selected.PackageDirectory, "app/foreign.py"), []byte("wrong"), 0600)
			case "symlink":
				os.Rename(path, path+".real")
				os.Symlink(path+".real", path)
			case "hardlink":
				os.Link(path, path+".alias")
			case "python", "mode", "duplicate", "missing-size":
				raw, _ := os.ReadFile(manifest)
				switch fault {
				case "python":
					raw = []byte(strings.Replace(string(raw), `"pythonVersion":"3.14.4"`, `"pythonVersion":"3.14.8"`, 1))
				case "mode":
					raw = []byte(strings.Replace(string(raw), `"mode":292`, `"mode":438`, 1))
				case "duplicate":
					raw = append([]byte(`{"kind":"ordinary-python-client",`), raw[1:]...)
				case "missing-size":
					raw = []byte(strings.Replace(string(raw), `,"size":0`, "", 1))
				}
				os.Chmod(manifest, 0600)
				os.WriteFile(manifest, raw, 0600)
				selected.ManifestDigest = hash(raw)
			}
			check := func(string, []byte, map[string]protected.ClientFile) error { return nil }
			if fault == "native" {
				check = protected.CheckClientNativeFile
			}
			if p, err := prepareClient(context.Background(), selected, check); err == nil || p != nil {
				t.Fatal("invalid client source admitted")
			}
		})
	}
}

func TestClientSelectionNeedsIndependentDigestAndClosedFields(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("selection belongs to an ordinary user")
	}
	selected := clientFixture(t)
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(directory, 0700)
	raw, _ := json.Marshal(selected)
	path := filepath.Join(directory, "selection.json")
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("selection unavailable")
	}
	if _, err := ReadClientSelection(context.Background(), path, hash(raw), uint32(os.Geteuid())); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadClientSelection(context.Background(), path, "sha256:"+strings.Repeat("f", 64), uint32(os.Geteuid())); err == nil {
		t.Fatal("wrong independent selection pin admitted")
	}
	raw = append([]byte(`{"extra":true,`), raw[1:]...)
	os.WriteFile(path, raw, 0600)
	if _, err := ReadClientSelection(context.Background(), path, hash(raw), uint32(os.Geteuid())); err == nil {
		t.Fatal("unknown selection field admitted")
	}
}
