//go:build linux || darwin

package installer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/controlLogix/agentmux/platform/kernel/assembly"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

func fixtureSelection(t *testing.T) Selection {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(root, 0700) != nil || os.Mkdir(filepath.Join(root, "bin"), 0700) != nil {
		t.Fatal("private package fixture unavailable")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("disposable release key unavailable")
	}
	authority := assembly.Authority{ID: "fixture_authority", OwnerHubID: "fixture_hub", Revision: 1}
	write := func(name string, data []byte, mode os.FileMode) {
		t.Helper()
		if os.WriteFile(filepath.Join(root, name), data, mode) != nil {
			t.Fatal("package fixture write failed")
		}
	}
	encode := func(value any) []byte {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	manifest := encode(map[string]any{"schemaVersion": "1.0.0", "releaseVersion": "1.0.0", "kernelApiMajor": 1, "releaseAuthorityRef": authority, "broker": map[string]string{"image": "docker.io/library/nats@sha256:" + strings.Repeat("a", 64), "natsVersion": "2.15.0", "composeVersion": "5.5.1"}})
	members := []map[string]string{}
	for _, role := range protocol.Roles() {
		data := []byte("disposable member " + role)
		name := "bin/" + role
		write(name, data, 0500)
		members = append(members, map[string]string{"id": role, "entrypoint": name, "binaryDigest": hash(data)})
	}
	assembly := encode(map[string]any{"schemaVersion": "1.0.0", "releaseVersion": "1.0.0", "kernelApiMajor": 1, "releaseAuthorityRef": authority, "releaseManifestDigest": hash(manifest), "plugins": members})
	approval := encode(map[string]any{"schemaVersion": "1.0.0", "releaseVersion": "1.0.0", "kernelApiMajor": 1, "releaseAuthorityRef": authority, "releaseManifestDigest": hash(manifest), "assemblyDigest": hash(assembly)})
	write("release-manifest.json", manifest, 0400)
	write("protected-assembly.json", assembly, 0400)
	write("release-authorization.json", approval, 0400)
	write("release-authorization.sig", ed25519.Sign(private, approval), 0400)
	runtime := []byte("disposable runtime")
	write("frontend-source", runtime, 0500)
	return Selection{SchemaVersion: "1.0.0", Release: ReleaseSelection{PackageDirectory: root, PublicKeyHex: hex.EncodeToString(public), ReleaseManifestDigest: hash(manifest), ReleaseAuthority: authority, ReleaseVersion: "1.0.0", KernelAPIMajor: 1}, Runtime: RuntimeSelection{Path: filepath.Join(root, "frontend-source"), Digest: hash(runtime)}}
}

// Signature/copy tests deliberately admit tiny private image bytes. Production
// always checks native ARM64 Mach-O and protects root-owned destination paths.
func prepareFixture(t *testing.T, selected Selection) *Package {
	t.Helper()
	p, err := prepare(context.Background(), selected, func([]byte) error { return nil })
	if err != nil {
		t.Fatal("signed package fixture rejected", err)
	}
	return p
}

func privateDestination(t *testing.T) (*os.File, destinationPolicy) {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if file.Close() != nil {
			t.Error("private destination close failed")
		}
	})
	owner := uint32(os.Geteuid())
	policy := destinationPolicy{
		directory: func(file *os.File) error {
			info, err := file.Stat()
			if err != nil || !info.IsDir() {
				return refusal("destination_untrusted", err)
			}
			stat := info.Sys().(*syscall.Stat_t)
			if stat.Uid != owner || info.Mode().Perm()&0022 != 0 {
				return refusal("destination_untrusted", nil)
			}
			return nil
		},
		file: func(file *os.File, mode os.FileMode) error {
			info, err := file.Stat()
			if err != nil || !info.Mode().IsRegular() {
				return refusal("destination_untrusted", err)
			}
			stat := info.Sys().(*syscall.Stat_t)
			if stat.Uid != owner || stat.Nlink != 1 || info.Mode().Perm() != mode {
				return refusal("destination_untrusted", nil)
			}
			return nil
		},
	}
	return file, policy
}

func TestPrepareSignedPackageRejectsChangedTrustMembersAndRuntime(t *testing.T) {
	for _, fault := range []string{"key", "authority", "member", "runtime", "symlink", "hardlink", "native-image"} {
		t.Run(fault, func(t *testing.T) {
			selected := fixtureSelection(t)
			switch fault {
			case "key":
				selected.Release.PublicKeyHex = strings.Repeat("a", 64)
			case "authority":
				selected.Release.ReleaseAuthority.Revision++
			case "member":
				path := filepath.Join(selected.Release.PackageDirectory, "bin/boot")
				if os.Chmod(path, 0700) != nil || os.WriteFile(path, []byte("changed"), 0500) != nil {
					t.Fatal("member mutation unavailable")
				}
			case "runtime":
				selected.Runtime.Digest = "sha256:" + strings.Repeat("f", 64)
			case "symlink":
				path := selected.Runtime.Path
				if os.Rename(path, path+".real") != nil || os.Symlink(path+".real", path) != nil {
					t.Fatal("link fixture unavailable")
				}
			case "hardlink":
				if os.Link(selected.Runtime.Path, selected.Runtime.Path+".alias") != nil {
					t.Fatal("link fixture unavailable")
				}
			}
			check := func([]byte) error { return nil }
			if fault == "native-image" {
				check = nativeImage
			}
			if p, err := prepare(context.Background(), selected, check); err == nil || p != nil {
				t.Fatal("changed or invalid package admitted")
			}
		})
	}
}

func TestVerifiedCopiesDoNotReopenMutableSourcesAndReuseExactly(t *testing.T) {
	selected := fixtureSelection(t)
	p := prepareFixture(t, selected)
	if os.Chmod(selected.Runtime.Path, 0700) != nil || os.WriteFile(selected.Runtime.Path, []byte("changed after verification"), 0500) != nil {
		t.Fatal("source mutation unavailable")
	}
	base, policy := privateDestination(t)
	first, err := installAt(context.Background(), base, p, policy)
	if err != nil || first.Outcome != "installed" || first.Enrollment != "not_checked" || first.Readiness != "not_observed" {
		t.Fatal("private copy did not complete", err)
	}
	path := filepath.Join(base.Name(), p.id, "agentmux-runtime")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	copied, err := os.ReadFile(path)
	if err != nil || hash(copied) != selected.Runtime.Digest {
		t.Fatal("installation reopened a changed source")
	}
	second, err := installAt(context.Background(), base, p, policy)
	after, statErr := os.Stat(path)
	if err != nil || statErr != nil || second.Outcome != "reused" || !os.SameFile(before, after) {
		t.Fatal("exact reuse rewrote an installed member", err)
	}
	if _, err := os.Stat(filepath.Join(base.Name(), p.id, "frontend-source")); !os.IsNotExist(err) {
		t.Fatal("source-only file escaped the allowlist")
	}
}

func TestInstallerRefusesForeignReplacementAndUnexpectedFiles(t *testing.T) {
	for _, fault := range []string{"symlink", "changed", "extra", "hardlink"} {
		t.Run(fault, func(t *testing.T) {
			p := prepareFixture(t, fixtureSelection(t))
			base, policy := privateDestination(t)
			victim := filepath.Join(base.Name(), "unrelated")
			if os.Mkdir(victim, 0700) != nil || os.WriteFile(filepath.Join(victim, "keep"), []byte("unchanged"), 0600) != nil {
				t.Fatal("unrelated fixture unavailable")
			}
			if fault == "symlink" {
				if os.Symlink(victim, filepath.Join(base.Name(), p.id)) != nil {
					t.Fatal("link fixture unavailable")
				}
			} else {
				if _, err := installAt(context.Background(), base, p, policy); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(base.Name(), p.id, "release-manifest.json")
				switch fault {
				case "changed":
					if os.Chmod(path, 0600) != nil || os.WriteFile(path, []byte("foreign"), 0600) != nil || os.Chmod(path, 0444) != nil {
						t.Fatal("replacement fixture unavailable")
					}
				case "extra":
					if os.WriteFile(filepath.Join(base.Name(), p.id, "extra"), []byte("keep"), 0600) != nil {
						t.Fatal("extra file unavailable")
					}
				case "hardlink":
					if os.Link(path, filepath.Join(victim, "alias")) != nil {
						t.Fatal("hardlink unavailable")
					}
				}
			}
			if _, err := installAt(context.Background(), base, p, policy); err == nil {
				t.Fatal("foreign or changed destination was accepted")
			}
			raw, err := os.ReadFile(filepath.Join(victim, "keep"))
			if err != nil || string(raw) != "unchanged" {
				t.Fatal("refusal changed an unrelated resource")
			}
		})
	}
}

func TestInterruptedCopyKeepsPartialUnselectedAndDiagnosticsPrivate(t *testing.T) {
	p := prepareFixture(t, fixtureSelection(t))
	base, policy := privateDestination(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	original := policy.file
	policy.file = func(file *os.File, mode os.FileMode) error { cancel(); return original(file, mode) }
	result, err := installAt(ctx, base, p, policy)
	if err == nil || result.Kind != "" {
		t.Fatal("interrupted copy reported success")
	}
	path := filepath.Join(base.Name(), p.id, "release-manifest.json")
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatal("partial created file was deleted")
	}
	var failure *Failure
	if !errors.As(err, &failure) || failure.InstallationID() != p.id {
		t.Fatal("partial installation identity lost")
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, err), base.Name()) {
			t.Fatal("private destination leaked in error formatting")
		}
	}
	encoded, _ := json.Marshal(Diagnose(err))
	if strings.Contains(string(encoded), base.Name()) || !strings.Contains(string(encoded), p.id) {
		t.Fatal("diagnostic lost exact public identity or disclosed private paths")
	}
	policy.file = original
	if _, err := installAt(context.Background(), base, p, policy); err == nil {
		t.Fatal("partial destination was silently overwritten")
	}
}

func TestConcurrentCopiesNeverOverwriteOneAnother(t *testing.T) {
	p := prepareFixture(t, fixtureSelection(t))
	base, policy := privateDestination(t)
	var workers sync.WaitGroup
	results := make(chan Result, 2)
	for i := 0; i < 2; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			result, _ := installAt(context.Background(), base, p, policy)
			results <- result
		}()
	}
	workers.Wait()
	close(results)
	installed := 0
	for result := range results {
		if result.Outcome == "installed" {
			installed++
		}
	}
	if installed != 1 {
		t.Fatal("concurrent callers did not retain one installer")
	}
	if result, err := installAt(context.Background(), base, p, policy); err != nil || result.Outcome != "reused" {
		t.Fatal("concurrent copy left an incompatible destination", err)
	}
}

func TestSelectionRequiresIndependentPinPrivateFilesAndClosedFields(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("private selection belongs to an ordinary enrolled user")
	}
	for _, fault := range []string{"valid", "pin", "public-file", "public-parent", "missing-revision", "unknown", "duplicate", "symlink"} {
		t.Run(fault, func(t *testing.T) {
			selected := fixtureSelection(t)
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil || os.Chmod(directory, 0700) != nil {
				t.Fatal("private selection directory unavailable")
			}
			raw, _ := json.Marshal(selected)
			switch fault {
			case "missing-revision":
				raw = []byte(strings.Replace(string(raw), `,"revision":1`, "", 1))
			case "unknown":
				raw = append([]byte(`{"unknown":true,`), raw[1:]...)
			case "duplicate":
				raw = append([]byte(`{"schemaVersion":"1.0.0",`), raw[1:]...)
			}
			path := filepath.Join(directory, "selection.json")
			if os.WriteFile(path, raw, 0600) != nil {
				t.Fatal("selection write failed")
			}
			pin := hash(raw)
			switch fault {
			case "pin":
				pin = "sha256:" + strings.Repeat("f", 64)
			case "public-file":
				os.Chmod(path, 0644)
			case "public-parent":
				os.Chmod(directory, 0755)
			case "symlink":
				os.Rename(path, path+".real")
				os.Symlink(path+".real", path)
			}
			_, err = ReadSelection(context.Background(), path, pin, uint32(os.Geteuid()))
			if (err == nil) != (fault == "valid") {
				t.Fatal("selection admission did not match explicit trust and private fields", fault, err)
			}
		})
	}
}

func TestPublicInstallerDoesNotElevateOrInstallOnUnsupportedHost(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("administrator refusal requires an ordinary user")
	}
	if result, err := Install(context.Background(), prepareFixture(t, fixtureSelection(t))); err == nil || result.Kind != "" {
		t.Fatal("ordinary process performed protected installation")
	}
}

func TestNativeImageAdmissionUsesActualMachOAndRejectsText(t *testing.T) {
	if nativeImage([]byte("not an executable")) == nil {
		t.Fatal("text admitted as a native image")
	}
	path, err := os.Executable()
	if err != nil {
		t.Fatal("current native executable unavailable")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("native executable read failed")
	}
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && nativeImage(raw) != nil {
		t.Fatal("actual native ARM64 Mach-O rejected")
	}
}

func TestAuthorizationFieldsRequireAuthorityRevision(t *testing.T) {
	raw := []byte(`{"schemaVersion":"1.0.0","releaseVersion":"1.0.0","kernelApiMajor":1,"releaseAuthorityRef":{"id":"authority","ownerHubId":"hub","revision":0},"assemblyDigest":"sha256:a","releaseManifestDigest":"sha256:b"}`)
	if !authorizationFields(raw) {
		t.Fatal("complete authorization shape refused")
	}
	for _, changed := range []string{strings.Replace(string(raw), `,"revision":0`, "", 1), strings.Replace(string(raw), `"revision":0`, `"revision":null`, 1)} {
		if authorizationFields([]byte(changed)) {
			t.Fatal("missing or null authority revision accepted")
		}
	}
}
