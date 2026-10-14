//go:build linux || darwin

package launcher

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/assembly"
)

type releaseTestFixture struct {
	policy        ReleasePolicy
	private       ed25519.PrivateKey // Ephemeral test memory only; never written or logged.
	manifest      installedManifest
	authorization releaseAuthorization
	assembly      map[string]any
}

func signedReleaseFixture(t *testing.T) *releaseTestFixture {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("fixture directory unavailable")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("fixture signing key unavailable")
	}
	authority := assembly.Authority{ID: "release_authority", OwnerHubID: "fixture_hub", Revision: 2}
	f := &releaseTestFixture{policy: ReleasePolicy{PackageDirectory: directory, PublicKey: public,
		ReleaseAuthority: authority, ReleaseVersion: "1.2.3", KernelAPIMajor: 1}, private: private,
		manifest: installedManifest{SchemaVersion: "1.0.0", ReleaseVersion: "1.2.3", KernelAPIMajor: 1,
			ReleaseAuthority: authority, Broker: BrokerPins{Image: "docker.io/library/nats@sha256:" + strings.Repeat("a", 64),
				NATSVersion: "2.15.0", ComposeVersion: "5.5.1"}}}
	if os.Mkdir(filepath.Join(directory, "bin"), 0700) != nil {
		t.Fatal("fixture binary directory unavailable")
	}
	var members []any
	for _, role := range []string{"boot", "kernel-lifecycle", "internal-communication", "exported-status"} {
		data := []byte("synthetic contained binary for " + role)
		if os.WriteFile(filepath.Join(directory, "bin", role), data, 0700) != nil {
			t.Fatal("fixture binary write failed")
		}
		members = append(members, map[string]any{"id": role, "entrypoint": "bin/" + role, "binaryDigest": releaseDigest(data)})
	}
	f.assembly = map[string]any{"schemaVersion": "1.0.0", "releaseVersion": "1.2.3", "kernelApiMajor": 1,
		"releaseAuthorityRef": authority, "plugins": members}
	f.refresh(t)
	return f
}

func releaseTestWrite(t *testing.T, directory, name string, raw []byte) {
	t.Helper()
	if os.WriteFile(filepath.Join(directory, name), raw, 0600) != nil {
		t.Fatal("controlled release fixture write failed")
	}
}

func (f *releaseTestFixture) signAuthorization(t *testing.T, raw []byte) {
	t.Helper()
	releaseTestWrite(t, f.policy.PackageDirectory, "release-authorization.json", raw)
	releaseTestWrite(t, f.policy.PackageDirectory, "release-authorization.sig", ed25519.Sign(f.private, raw))
}

func (f *releaseTestFixture) refresh(t *testing.T) {
	t.Helper()
	parent, err := json.Marshal(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	f.policy.ReleaseManifestDigest = releaseDigest(parent)
	f.assembly["releaseManifestDigest"] = f.policy.ReleaseManifestDigest
	rawAssembly, err := json.Marshal(f.assembly)
	if err != nil {
		t.Fatal(err)
	}
	f.authorization = releaseAuthorization{SchemaVersion: "1.0.0", ReleaseVersion: f.policy.ReleaseVersion,
		KernelAPIMajor: 1, ReleaseAuthority: f.policy.ReleaseAuthority,
		AssemblyDigest: releaseDigest(rawAssembly), ReleaseManifestDigest: f.policy.ReleaseManifestDigest}
	approval, err := json.Marshal(f.authorization)
	if err != nil {
		t.Fatal(err)
	}
	releaseTestWrite(t, f.policy.PackageDirectory, "release-manifest.json", parent)
	releaseTestWrite(t, f.policy.PackageDirectory, "protected-assembly.json", rawAssembly)
	f.signAuthorization(t, approval)
}

func releaseMustRefuse(t *testing.T, policy ReleasePolicy) {
	t.Helper()
	result, err := LoadInstalledRelease(policy)
	if err == nil {
		t.Fatal("invalid installed release accepted")
	}
	if !reflect.DeepEqual(result.Trust(), assembly.Trust{}) || len(result.Assembly()) != 0 || result.PackageDirectory() != "" ||
		result.BrokerPins() != (BrokerPins{}) || result.VerifiedAssembly().PackageRoot() != "" {
		t.Fatal("verification failure exposed partially trusted release data")
	}
	if !strings.HasPrefix(err.Error(), "release_") || strings.Contains(err.Error(), policy.PackageDirectory) {
		t.Fatal("verification returned unsafe underlying error text")
	}
}

func TestInstalledReleaseRealSignatureAndCopyBoundaries(t *testing.T) {
	f := signedReleaseFixture(t)
	before := make(map[string]string)
	if err := filepath.WalkDir(f.policy.PackageDirectory, func(p string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			before[p] = releaseDigest(data)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	result, err := LoadInstalledRelease(f.policy)
	if err != nil {
		t.Fatal(err)
	}
	if result.Trust().ReleaseManifestDigest != f.policy.ReleaseManifestDigest ||
		result.Trust().AssemblyDigest != f.authorization.AssemblyDigest || result.Trust().ReleaseAuthority != f.policy.ReleaseAuthority ||
		result.PackageDirectory() != f.policy.PackageDirectory || result.BrokerPins() != f.manifest.Broker {
		t.Fatal("signed installed release bindings were lost")
	}
	for index, member := range result.VerifiedAssembly().Members() {
		if member.ID != []string{"boot", "kernel-lifecycle", "internal-communication", "exported-status"}[index] {
			t.Fatal("verified package lost fixed role membership")
		}
	}
	copy := result.Assembly()
	copy[0] ^= 1
	if bytes.Equal(copy, result.Assembly()) {
		t.Fatal("caller mutated private verified assembly bytes")
	}
	for p, expected := range before {
		actual, err := os.ReadFile(p)
		if err != nil || releaseDigest(actual) != expected {
			t.Fatal("verification changed installed package files")
		}
	}
}

func TestInstalledReleaseSeparatePolicyIsRequired(t *testing.T) {
	for _, kind := range []string{"key", "key-size", "digest", "authority", "revision", "version", "api", "relative", "unclean", "missing-root"} {
		t.Run(kind, func(t *testing.T) {
			f := signedReleaseFixture(t)
			p := f.policy
			switch kind {
			case "key":
				public, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				p.PublicKey = public
			case "key-size":
				p.PublicKey = p.PublicKey[:31]
			case "digest":
				p.ReleaseManifestDigest = "sha256:" + strings.Repeat("b", 64)
			case "authority":
				p.ReleaseAuthority.ID = "other_authority"
			case "revision":
				p.ReleaseAuthority.Revision++
			case "version":
				p.ReleaseVersion = "1.2.4"
			case "api":
				p.KernelAPIMajor = 2
			case "relative":
				p.PackageDirectory = "relative"
			case "unclean":
				p.PackageDirectory += "/../" + filepath.Base(p.PackageDirectory)
			case "missing-root":
				p.PackageDirectory += "-absent"
			}
			releaseMustRefuse(t, p)
		})
	}
}

func TestInstalledReleaseTamperingAndExactSignatureBytes(t *testing.T) {
	for _, file := range []string{"release-manifest.json", "release-authorization.json", "release-authorization.sig", "protected-assembly.json", "bin/boot"} {
		t.Run(file, func(t *testing.T) {
			f := signedReleaseFixture(t)
			name := filepath.Join(f.policy.PackageDirectory, file)
			raw, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			raw[0] ^= 1
			releaseTestWrite(t, f.policy.PackageDirectory, file, raw)
			releaseMustRefuse(t, f.policy)
		})
	}
	for _, size := range []int{0, 63, 65} {
		t.Run("signature-length-"+strconvForReleaseTest(size), func(t *testing.T) {
			f := signedReleaseFixture(t)
			releaseTestWrite(t, f.policy.PackageDirectory, "release-authorization.sig", make([]byte, size))
			releaseMustRefuse(t, f.policy)
		})
	}
	t.Run("unsigned whitespace", func(t *testing.T) {
		f := signedReleaseFixture(t)
		raw, _ := os.ReadFile(filepath.Join(f.policy.PackageDirectory, "release-authorization.json"))
		releaseTestWrite(t, f.policy.PackageDirectory, "release-authorization.json", append(raw, '\n'))
		releaseMustRefuse(t, f.policy)
	})
}

func strconvForReleaseTest(value int) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

func TestInstalledReleaseAuthenticallySignedMalformedAuthorizationIsRefused(t *testing.T) {
	for _, kind := range []string{"duplicate", "escaped-duplicate", "nested-duplicate", "unknown", "missing", "null", "invalid-utf8", "surrogate", "trailing", "wrong-assembly", "wrong-parent", "wrong-authority", "wrong-version", "wrong-api", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			f := signedReleaseFixture(t)
			raw, _ := json.Marshal(f.authorization)
			switch kind {
			case "duplicate":
				raw = append([]byte(`{"schemaVersion":"1.0.0",`), raw[1:]...)
			case "escaped-duplicate":
				raw = append([]byte(`{"schema\u0056ersion":"1.0.0",`), raw[1:]...)
			case "nested-duplicate":
				raw = bytes.Replace(raw, []byte(`"id":"release_authority"`), []byte(`"id":"release_authority","id":"release_authority"`), 1)
			case "unknown":
				raw = append([]byte(`{"publicKey":"package-must-not-select-a-key",`), raw[1:]...)
			case "missing":
				raw = bytes.Replace(raw, []byte(`"schemaVersion":"1.0.0",`), nil, 1)
			case "null":
				raw = bytes.Replace(raw, []byte(`"revision":2`), []byte(`"revision":null`), 1)
			case "invalid-utf8":
				raw = append(raw, 0xff)
			case "surrogate":
				raw = bytes.Replace(raw, []byte(`"release_authority"`), []byte(`"\ud800"`), 1)
			case "trailing":
				raw = append(raw, []byte(`{}`)...)
			case "wrong-assembly":
				f.authorization.AssemblyDigest = "sha256:" + strings.Repeat("c", 64)
				raw, _ = json.Marshal(f.authorization)
			case "wrong-parent":
				f.authorization.ReleaseManifestDigest = "sha256:" + strings.Repeat("d", 64)
				raw, _ = json.Marshal(f.authorization)
			case "wrong-authority":
				f.authorization.ReleaseAuthority.ID = "other_authority"
				raw, _ = json.Marshal(f.authorization)
			case "wrong-version":
				f.authorization.ReleaseVersion = "1.2.4"
				raw, _ = json.Marshal(f.authorization)
			case "wrong-api":
				f.authorization.KernelAPIMajor = 2
				raw, _ = json.Marshal(f.authorization)
			case "oversized":
				raw = append(raw, bytes.Repeat([]byte(" "), releaseMetadataLimit)...)
			}
			f.signAuthorization(t, raw)
			releaseMustRefuse(t, f.policy)
		})
	}
}

func TestInstalledReleaseSignedManifestPinsAndShapeAreClosed(t *testing.T) {
	for _, kind := range []string{"image-source", "image-tag", "nats", "compose", "authority", "version", "api", "unknown", "duplicate", "missing", "null", "invalid-utf8", "surrogate"} {
		t.Run(kind, func(t *testing.T) {
			f := signedReleaseFixture(t)
			switch kind {
			case "image-source":
				f.manifest.Broker.Image = "unapproved/nats@sha256:" + strings.Repeat("a", 64)
			case "image-tag":
				f.manifest.Broker.Image = "docker.io/library/nats:latest"
			case "nats":
				f.manifest.Broker.NATSVersion = "2.14.0"
			case "compose":
				f.manifest.Broker.ComposeVersion = "5.5.2"
			case "authority":
				f.manifest.ReleaseAuthority.ID = "other_authority"
			case "version":
				f.manifest.ReleaseVersion = "1.2.4"
			case "api":
				f.manifest.KernelAPIMajor = 2
			}
			parent, _ := json.Marshal(f.manifest)
			switch kind {
			case "unknown":
				parent = append([]byte(`{"assemblyDigest":"hash-cycle-is-forbidden",`), parent[1:]...)
			case "duplicate":
				parent = bytes.Replace(parent, []byte(`"natsVersion":"2.15.0"`), []byte(`"natsVersion":"2.15.0","natsVersion":"2.15.0"`), 1)
			case "missing":
				parent = bytes.Replace(parent, []byte(`"schemaVersion":"1.0.0",`), nil, 1)
			case "null":
				parent = bytes.Replace(parent, []byte(`"revision":2`), []byte(`"revision":null`), 1)
			case "invalid-utf8":
				parent = append(parent, 0xff)
			case "surrogate":
				parent = bytes.Replace(parent, []byte(`"release_authority"`), []byte(`"\udc00"`), 1)
			}
			f.policy.ReleaseManifestDigest = releaseDigest(parent)
			f.assembly["releaseManifestDigest"] = f.policy.ReleaseManifestDigest
			assemblyBytes, _ := json.Marshal(f.assembly)
			f.authorization.ReleaseManifestDigest = f.policy.ReleaseManifestDigest
			f.authorization.AssemblyDigest = releaseDigest(assemblyBytes)
			approval, _ := json.Marshal(f.authorization)
			releaseTestWrite(t, f.policy.PackageDirectory, "release-manifest.json", parent)
			releaseTestWrite(t, f.policy.PackageDirectory, "protected-assembly.json", assemblyBytes)
			f.signAuthorization(t, approval)
			releaseMustRefuse(t, f.policy)
		})
	}
}

func TestInstalledReleaseContainedFilesAndFixedMembers(t *testing.T) {
	for _, kind := range []string{"metadata-symlink", "root-symlink", "directory-file", "missing-file", "member-symlink", "traversal", "absolute", "backslash", "three-roles", "role-replacement", "duplicate-role", "member-oversized", "total-oversized"} {
		t.Run(kind, func(t *testing.T) {
			f := signedReleaseFixture(t)
			switch kind {
			case "metadata-symlink":
				file := filepath.Join(f.policy.PackageDirectory, "release-authorization.json")
				outside := filepath.Join(t.TempDir(), "outside.json")
				raw, _ := os.ReadFile(file)
				releaseTestWrite(t, filepath.Dir(outside), filepath.Base(outside), raw)
				if os.Remove(file) != nil || os.Symlink(outside, file) != nil {
					t.Fatal("controlled metadata symlink unavailable")
				}
			case "root-symlink":
				link := filepath.Join(t.TempDir(), "installed-link")
				if os.Symlink(f.policy.PackageDirectory, link) != nil {
					t.Fatal("controlled root symlink unavailable")
				}
				f.policy.PackageDirectory = link
			case "directory-file":
				name := filepath.Join(f.policy.PackageDirectory, "release-authorization.sig")
				if os.Remove(name) != nil || os.Mkdir(name, 0700) != nil {
					t.Fatal("controlled nonregular file unavailable")
				}
			case "missing-file":
				if os.Remove(filepath.Join(f.policy.PackageDirectory, "release-authorization.sig")) != nil {
					t.Fatal("controlled missing file unavailable")
				}
			case "member-symlink":
				name := filepath.Join(f.policy.PackageDirectory, "bin", "boot")
				if os.Remove(name) != nil || os.Symlink("kernel-lifecycle", name) != nil {
					t.Fatal("controlled member symlink unavailable")
				}
			default:
				members := f.assembly["plugins"].([]any)
				first := members[0].(map[string]any)
				switch kind {
				case "traversal":
					first["entrypoint"] = "../outside"
				case "absolute":
					first["entrypoint"] = "/outside"
				case "backslash":
					first["entrypoint"] = `bin\boot`
				case "three-roles":
					f.assembly["plugins"] = members[:3]
				case "role-replacement":
					first["id"] = "ordinary-plugin"
				case "duplicate-role":
					first["id"] = "kernel-lifecycle"
				case "member-oversized", "total-oversized":
					for index, role := range []string{"boot", "kernel-lifecycle", "internal-communication", "exported-status"} {
						size := int64(releaseMemberLimit + 1)
						if kind == "total-oversized" {
							if index > 2 {
								break
							}
							size = releaseTotalLimit/3 + 1
						} else if index > 0 {
							break
						}
						file, err := os.OpenFile(filepath.Join(f.policy.PackageDirectory, "bin", role), os.O_WRONLY, 0700)
						if err != nil || file.Truncate(size) != nil {
							t.Fatal("controlled sparse size fixture unavailable")
						}
						file.Close()
					}
				}
				f.refresh(t)
			}
			releaseMustRefuse(t, f.policy)
		})
	}
}

func TestReleaseNonblockingRaceChild(t *testing.T) {
	if os.Getenv("AMX_RELEASE_OPEN_RACE_CHILD") != "1" {
		return
	}
	directory := os.Getenv("AMX_RELEASE_OPEN_RACE_DIR")
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal("controlled race root unavailable")
	}
	defer root.Close()
	if os.WriteFile(filepath.Join(directory, "regular-target"), []byte("original"), 0600) != nil {
		t.Fatal("controlled regular symlink target unavailable")
	}
	for _, kind := range []string{"fifo", "symlink"} {
		name := "metadata-" + kind
		if os.WriteFile(filepath.Join(directory, name), []byte("original"), 0600) != nil {
			t.Fatal("controlled regular file unavailable")
		}
		opener := func(root *os.Root, selected string) (*os.File, error) {
			// releaseReadOpened already checked the original regular file. Change
			// its directory entry at the exact boundary before the production open.
			if root.Remove(selected) != nil {
				t.Fatal("controlled replacement failed")
			}
			if kind == "fifo" {
				if syscall.Mkfifo(filepath.Join(directory, selected), 0600) != nil {
					t.Fatal("controlled FIFO unavailable")
				}
			} else if os.Symlink("regular-target", filepath.Join(directory, selected)) != nil {
				t.Fatal("controlled symlink unavailable")
			}
			return releaseOpen(root, selected)
		}
		if _, err := releaseReadOpened(root, name, 64, opener); err == nil {
			t.Fatal("substituted special file was accepted")
		}
	}
}

func TestInstalledReleaseSubstitutedSpecialFileCannotBlockOpen(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestReleaseNonblockingRaceChild$")
	cmd.Env = append(os.Environ(), "AMX_RELEASE_OPEN_RACE_CHILD=1", "AMX_RELEASE_OPEN_RACE_DIR="+t.TempDir())
	if err := cmd.Run(); err != nil || ctx.Err() != nil {
		t.Fatal("substituted FIFO/symlink blocked or escaped owned bounded test process")
	}
}
