package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func fixturePackage(t *testing.T, m Manifest, extra map[string][]byte) AdmittedPackage {
	t.Helper()
	dir := t.TempDir()
	raw := manifestBytes(t, m)
	files := map[string][]byte{"manifest.json": raw, "bin/run": []byte("native fixture bytes"), "schemas/config.json": []byte(`{"type":"object"}`)}
	for k, v := range extra {
		files[k] = v
	}
	for k, v := range files {
		if e := os.MkdirAll(filepath.Dir(filepath.Join(dir, k)), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(filepath.Join(dir, k), v, 0700); e != nil {
			t.Fatal(e)
		}
	}
	source := []byte("original private-marker source")
	p, err := AdmitPackage(context.Background(), PackageInput{Directory: dir, ManifestPath: "manifest.json", SourceID: "fixture", SourcePath: filepath.Join(dir, "original.md"), Scope: "repo", Source: source, SourceChecksum: checksum(source)})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestPackageSnapshotsIdentityAndSource(t *testing.T) {
	p := fixturePackage(t, fixtureManifest("example"), nil)
	source := p.Provenance()
	if source.Checksum == p.Pin().ManifestChecksum || !bytes.Equal(source.Source(), []byte("original private-marker source")) {
		t.Fatal("source conflated")
	}
	raw, _ := p.File("bin/run")
	raw[0] = 'x'
	again, _ := p.File("bin/run")
	if bytes.Equal(raw, again) {
		t.Fatal("mutable snapshot")
	}
	if _, e := p.File("../manifest.json"); e == nil {
		t.Fatal("escape allowed")
	}
	for _, v := range []any{p, p.Provenance()} {
		encoded, _ := json.Marshal(v)
		if strings.Contains(fmt.Sprintf("%v %+v %#v", v, v, v)+string(encoded), "private-marker") {
			t.Fatal("source exposed")
		}
	}
	if e := ValidateActivationSupport(p, "independent", Platform{OS: "darwin", Arch: "arm64"}); e != nil {
		t.Fatal(e)
	}
}
func TestPackageRefusesUnsafeSourcesAndFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo", "source", "limit", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			raw := manifestBytes(t, fixtureManifest("example"))
			_ = os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0600)
			input := PackageInput{Directory: dir, ManifestPath: "manifest.json", SourceID: "fixture", SourcePath: filepath.Join(dir, "original.md"), Scope: "repo", Source: raw, SourceChecksum: checksum(raw)}
			ctx := context.Background()
			switch kind {
			case "symlink":
				_ = os.Symlink("manifest.json", filepath.Join(dir, "link"))
			case "fifo":
				if e := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0600); e != nil {
					t.Fatal(e)
				}
			case "source":
				input.SourceChecksum = checksum([]byte("wrong"))
			case "limit":
				input.Limits = AdmissionLimits{MaxFileBytes: 1}
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, e := AdmitPackage(ctx, input); e == nil {
				t.Fatal("unsafe admission")
			}
		})
	}
}
func TestUnsupportedDeclarationsRetainedThenRefused(t *testing.T) {
	for _, kind := range []string{"migrations", "runtime", "platform", "kernel", "capability"} {
		t.Run(kind, func(t *testing.T) {
			m := fixtureManifest("example")
			switch kind {
			case "migrations":
				m.Migrations = []Migration{{Domain: "work", FromSchema: "1.0.0", ToSchema: "2.0.0", ContractRef: "migrate.json"}}
			case "runtime":
				m.Runtime.Kind = "container"
			case "platform":
				m.Platforms = []Platform{{OS: "linux", Arch: "arm64"}}
			case "kernel":
				m.PackageID = "kernel-lifecycle"
			case "capability":
				m.RequestedCapabilities = []Capability{{Action: "task-read", ResourceClass: "task", Required: true}}
			}
			p := fixturePackage(t, m, nil)
			if ValidateActivationSupport(p, "independent", Platform{OS: "darwin", Arch: "arm64"}) == nil {
				t.Fatal("unsupported declaration ignored")
			}
		})
	}
}

func TestSourceMetadataAndPackageContentHaveSeparatePins(t *testing.T) {
	p := fixturePackage(t, fixtureManifest("example"), nil)
	provenance := p.Provenance()
	input := PackageInput{Directory: filepath.Dir(provenance.Path), ManifestPath: "manifest.json", SourceID: provenance.SourceID, SourcePath: provenance.Path, Scope: provenance.Scope, Source: provenance.Source(), SourceChecksum: provenance.Checksum}
	unchanged, err := AdmitPackage(context.Background(), input)
	if err != nil || unchanged.Pin() != p.Pin() {
		t.Fatal("same admission changed identity")
	}
	for _, mutate := range []func(*PackageInput){func(i *PackageInput) { i.Scope = "global" }, func(i *PackageInput) { i.SourcePath = filepath.Join(i.Directory, "other-source.md") }, func(i *PackageInput) { i.SourceID = "different-source" }, func(i *PackageInput) { i.Source = []byte("different original"); i.SourceChecksum = checksum(i.Source) }} {
		other := input
		mutate(&other)
		changed, err := AdmitPackage(context.Background(), other)
		if err != nil || changed.Pin().ProvenanceChecksum == p.Pin().ProvenanceChecksum || changed.Pin().PackageChecksum != p.Pin().PackageChecksum {
			t.Fatal("provenance/content identity conflated")
		}
	}
	paths := p.FilePaths()
	paths[0] = "changed"
	if p.FilePaths()[0] == "changed" {
		t.Fatal("mutable path list")
	}
	if err := os.WriteFile(filepath.Join(input.Directory, "schemas/config.json"), []byte(`{"type":"string"}`), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := AdmitPackage(context.Background(), input)
	if err != nil || changed.Pin().PackageChecksum == p.Pin().PackageChecksum || changed.Pin().ManifestChecksum != p.Pin().ManifestChecksum {
		t.Fatal("referenced schema not content-bound")
	}
	original, _ := p.File("schemas/config.json")
	if string(original) != `{"type":"object"}` {
		t.Fatal("original bytes reread")
	}
}

func TestAdmissionCompletedCloseFailureIsRetainedAndPrivate(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "private-marker")
	if err != nil {
		t.Fatal("fixture unavailable")
	}
	if file.Close() != nil {
		t.Fatal("fixture close failed")
	}
	operation := pluginError("package_file_changed")
	closed := closeAdmission(file, operation)
	failure, ok := closed.(*AdmissionCleanupFailure)
	if !ok || failure.owner != file || failure.operation != operation || failure.cause == nil {
		t.Fatal("exact close owner/cause lost")
	}
	raw, _ := json.Marshal(failure)
	if strings.Contains(fmt.Sprintf("%+v %#v", failure, failure)+string(raw), "private-marker") {
		t.Fatal("close cause leaked")
	}
}

func TestPackageDirectoryAndTotalBounds(t *testing.T) {
	dir := t.TempDir()
	raw := manifestBytes(t, fixtureManifest("example"))
	if os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0600) != nil {
		t.Fatal("fixture unavailable")
	}
	input := PackageInput{Directory: dir, ManifestPath: "manifest.json", SourceID: "fixture", SourcePath: filepath.Join(dir, "source.md"), Scope: "repo", Source: raw, SourceChecksum: checksum(raw)}
	for _, name := range []string{"empty-one", "empty-two", "empty-three"} {
		if os.Mkdir(filepath.Join(dir, name), 0700) != nil {
			t.Fatal("fixture unavailable")
		}
	}
	input.Limits = AdmissionLimits{MaxFiles: 2}
	if _, err := AdmitPackage(context.Background(), input); err == nil {
		t.Fatal("directory entries escaped admission bound")
	}
	input.Limits = AdmissionLimits{MaxTotalBytes: 1}
	if _, err := AdmitPackage(context.Background(), input); err == nil {
		t.Fatal("total bytes escaped admission bound")
	}
	input.Limits = AdmissionLimits{MaxFiles: 20000}
	if _, err := AdmitPackage(context.Background(), input); err == nil {
		t.Fatal("unsupported limits accepted")
	}
}
