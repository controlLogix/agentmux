package assembly

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T) (string, manifest, Trust) {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	m := manifest{SchemaVersion: "1.0.0", ReleaseVersion: "1.2.3", ReleaseManifestDigest: "sha256:" + strings.Repeat("a", 64), ReleaseAuthority: Authority{ID: "release_authority", OwnerHubID: "fixture_hub", Revision: 2}, KernelAPIMajor: 1}
	for _, role := range roles {
		data := []byte("synthetic binary for " + role)
		if err := os.WriteFile(filepath.Join(root, "bin", role), data, 0700); err != nil {
			t.Fatal(err)
		}
		m.Plugins = append(m.Plugins, plugin{ID: role, Entrypoint: "bin/" + role, BinaryDigest: sum(data)})
	}
	trust := Trust{ReleaseVersion: m.ReleaseVersion, ReleaseManifestDigest: m.ReleaseManifestDigest, ReleaseAuthority: m.ReleaseAuthority, KernelAPIMajor: 1}
	return root, m, trust
}

func encode(t *testing.T, m manifest, trust Trust) ([]byte, Trust) {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	trust.AssemblyDigest = sum(raw)
	return raw, trust
}

func refused(t *testing.T, raw []byte, root string, trust Trust) {
	t.Helper()
	v, err := Verify(raw, root, trust)
	if err == nil {
		t.Fatal("invalid assembly accepted")
	}
	if v.PackageRoot() != "" || v.Members() != ([4]Member{}) {
		t.Fatal("failure exposed partially verified members")
	}
}

func TestVerifyFixedAssembly(t *testing.T) {
	root, m, trust := fixture(t)
	m.Plugins[0], m.Plugins[3] = m.Plugins[3], m.Plugins[0]
	raw, trust := encode(t, m, trust)
	v, err := Verify(raw, root, trust)
	if err != nil {
		t.Fatal(err)
	}
	for i, member := range v.Members() {
		if member.ID != roles[i] || !filepath.IsAbs(member.Path) || member.Size == 0 {
			t.Fatalf("unexpected verified member: %+v", member)
		}
	}
	copy := v.Members()
	copy[0].Path = "outside"
	if v.Members()[0].Path == "outside" {
		t.Fatal("caller changed verified member list")
	}
	if v.Release() != trust {
		t.Fatal("trusted release identity lost")
	}
}

func TestShapeAndTrustedPolicy(t *testing.T) {
	cases := []struct {
		name   string
		change func(*manifest)
	}{
		{"missing-member", func(m *manifest) { m.Plugins = m.Plugins[:3] }},
		{"extra-member", func(m *manifest) { m.Plugins = append(m.Plugins, m.Plugins[0]) }},
		{"duplicate-role-with-different-fields", func(m *manifest) { m.Plugins[1].ID = "boot" }},
		{"ordinary-role", func(m *manifest) { m.Plugins[0].ID = "application" }},
		{"wrong-schema", func(m *manifest) { m.SchemaVersion = "2.0.0" }},
		{"wrong-api", func(m *manifest) { m.KernelAPIMajor = 2 }},
		{"wrong-release", func(m *manifest) { m.ReleaseVersion = "1.2.4" }},
		{"invalid-version", func(m *manifest) { m.ReleaseVersion = "01.2.3" }},
		{"wrong-release-digest", func(m *manifest) { m.ReleaseManifestDigest = "sha256:" + strings.Repeat("b", 64) }},
		{"invalid-binary-digest", func(m *manifest) { m.Plugins[0].BinaryDigest = "sha256:" + strings.Repeat("A", 64) }},
		{"wrong-authority", func(m *manifest) { m.ReleaseAuthority.ID = "attacker" }},
		{"wrong-authority-owner", func(m *manifest) { m.ReleaseAuthority.OwnerHubID = "foreign_hub" }},
		{"wrong-authority-revision", func(m *manifest) { m.ReleaseAuthority.Revision = 3 }},
		{"invalid-authority-token", func(m *manifest) { m.ReleaseAuthority.ID = "*" }},
		{"negative-authority-revision", func(m *manifest) { m.ReleaseAuthority.Revision = -1 }},
		{"unsafe-authority-revision", func(m *manifest) { m.ReleaseAuthority.Revision = 9007199254740992 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, m, trust := fixture(t)
			tc.change(&m)
			raw, trust := encode(t, m, trust)
			refused(t, raw, root, trust)
		})
	}
}

func TestAssemblyBytesRequireSeparateTrust(t *testing.T) {
	root, m, trust := fixture(t)
	raw, trust := encode(t, m, trust)
	changed := append(append([]byte{}, raw...), byte(' '))
	refused(t, changed, root, trust)
	m.Plugins[0].BinaryDigest = sum([]byte("tampered"))
	altered, _ := encode(t, m, trust)
	if err := os.WriteFile(filepath.Join(root, "bin", "boot"), []byte("tampered"), 0700); err != nil {
		t.Fatal(err)
	}
	refused(t, altered, root, trust)
	refused(t, raw, root, Trust{})
}

func TestBinaryDigestAndMissingFile(t *testing.T) {
	for _, action := range []string{"tamper", "missing", "directory"} {
		t.Run(action, func(t *testing.T) {
			root, m, trust := fixture(t)
			raw, trust := encode(t, m, trust)
			file := filepath.Join(root, "bin", "exported-status")
			if action == "tamper" {
				if err := os.WriteFile(file, []byte("modified bytes"), 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				if action == "directory" {
					if err := os.Mkdir(file, 0700); err != nil {
						t.Fatal(err)
					}
				}
			}
			refused(t, raw, root, trust)
		})
	}
}

func TestContainedPaths(t *testing.T) {
	for _, entry := range []string{"", ".", "..", "../outside", "/bin/sh", "bin/../bin/boot", "bin//boot", "bin/boot/", `bin\boot`, `C:\outside`, "bin/boot\x00", "bin/" + strings.Repeat("x", 4097)} {
		t.Run(entry, func(t *testing.T) {
			root, m, trust := fixture(t)
			m.Plugins[0].Entrypoint = entry
			raw, trust := encode(t, m, trust)
			refused(t, raw, root, trust)
		})
	}
}

func TestSymlinksRefusedInsideAndOutsidePackage(t *testing.T) {
	for _, kind := range []string{"inside-file", "outside-file", "inside-directory", "outside-directory"} {
		t.Run(kind, func(t *testing.T) {
			root, m, trust := fixture(t)
			target := filepath.Join(root, "bin", "boot")
			entry := "linked"
			if strings.HasPrefix(kind, "outside") {
				outside := t.TempDir()
				if err := os.WriteFile(filepath.Join(outside, "boot"), []byte("synthetic binary for boot"), 0700); err != nil {
					t.Fatal(err)
				}
				target = filepath.Join(outside, "boot")
			}
			if strings.HasSuffix(kind, "directory") {
				target = filepath.Dir(target)
				entry = "linked/boot"
			}
			if err := os.Symlink(target, filepath.Join(root, "linked")); err != nil {
				t.Fatal(err)
			}
			m.Plugins[0].Entrypoint = entry
			raw, trust := encode(t, m, trust)
			refused(t, raw, root, trust)
		})
	}
}

func TestClosedRequiredFieldsAndDuplicateJSON(t *testing.T) {
	root, m, trust := fixture(t)
	raw, trust := encode(t, m, trust)
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"schemaVersion", "releaseVersion", "releaseManifestDigest", "releaseAuthorityRef", "kernelApiMajor", "plugins"} {
		t.Run("missing-"+key, func(t *testing.T) {
			var fresh map[string]any
			json.Unmarshal(raw, &fresh)
			delete(fresh, key)
			value, _ := json.Marshal(fresh)
			policy := trust
			policy.AssemblyDigest = sum(value)
			refused(t, value, root, policy)
		})
	}
	for _, change := range []string{"unknown", "authority-null-revision", "authority-missing-revision", "member-unknown"} {
		t.Run(change, func(t *testing.T) {
			var fresh map[string]any
			json.Unmarshal(raw, &fresh)
			switch change {
			case "unknown":
				fresh["other"] = true
			case "authority-null-revision":
				fresh["releaseAuthorityRef"].(map[string]any)["revision"] = nil
			case "authority-missing-revision":
				delete(fresh["releaseAuthorityRef"].(map[string]any), "revision")
			case "member-unknown":
				fresh["plugins"].([]any)[0].(map[string]any)["other"] = true
			}
			value, _ := json.Marshal(fresh)
			policy := trust
			policy.AssemblyDigest = sum(value)
			refused(t, value, root, policy)
		})
	}
	for _, value := range [][]byte{append(append([]byte{}, raw...), []byte(` {}`)...), []byte(strings.Replace(string(raw), `"kernelApiMajor":1`, `"kernelApiMajor":1,"kernelApiMajor":1`, 1)), []byte(strings.Replace(string(raw), `"revision":2`, `"revision":2,"revi\u0073ion":2`, 1)), []byte(strings.Replace(string(raw), `"entrypoint":"bin/boot"`, `"entrypoint":"bin/\ud800"`, 1)), append([]byte{0xff}, raw...)} {
		policy := trust
		policy.AssemblyDigest = sum(value)
		refused(t, value, root, policy)
	}
}

func TestMissingPackage(t *testing.T) {
	root, m, trust := fixture(t)
	raw, trust := encode(t, m, trust)
	refused(t, raw, filepath.Join(root, "missing"), trust)
	refused(t, raw, "", trust)
}

func TestUnicodeEntrypoint(t *testing.T) {
	root, m, trust := fixture(t)
	name := "bin/\U0001f600"
	if err := os.Rename(filepath.Join(root, "bin", "boot"), filepath.Join(root, filepath.FromSlash(name))); err != nil {
		t.Fatal(err)
	}
	m.Plugins[0].Entrypoint = name
	raw, trust := encode(t, m, trust)
	if _, err := Verify(raw, root, trust); err != nil {
		t.Fatal(err)
	}
	escaped := []byte(strings.Replace(string(raw), "\U0001f600", `\ud83d\ude00`, 1))
	trust.AssemblyDigest = sum(escaped)
	if _, err := Verify(escaped, root, trust); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaIntegerSpellings(t *testing.T) {
	root, m, trust := fixture(t)
	raw, trust := encode(t, m, trust)
	for _, spelling := range []string{"2.0", "2e0", "0.2e1"} {
		t.Run(spelling, func(t *testing.T) {
			value := []byte(strings.Replace(strings.Replace(string(raw), `"revision":2`, `"revision":`+spelling, 1), `"kernelApiMajor":1`, `"kernelApiMajor":1.0`, 1))
			policy := trust
			policy.AssemblyDigest = sum(value)
			if _, err := Verify(value, root, policy); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, spelling := range []string{"2.1", "true", "\"2\"", "9007199254740991.1"} {
		value := []byte(strings.Replace(string(raw), `"revision":2`, `"revision":`+spelling, 1))
		policy := trust
		policy.AssemblyDigest = sum(value)
		refused(t, value, root, policy)
	}
}
