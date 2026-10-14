//go:build linux || darwin

package launcher

import (
	"encoding/json"
	"github.com/controlLogix/agentmux/platform/kernel/assembly"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func profileFixture(t *testing.T) (ProfilePolicy, Profile) {
	t.Helper()
	base := t.TempDir()
	dir := filepath.Join(base, "profiles")
	workspace := filepath.Join(base, "workspace")
	for _, path := range []string{dir, workspace} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	// macOS temporary roots may have a symlink prefix. The policy is canonical.
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err = filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := "sha256:" + strings.Repeat("a", 64)
	policy := ProfilePolicy{Directory: dir, WorkspaceRoots: []string{workspace}, OwnerUID: uint32(os.Geteuid()), InstalledReleaseFingerprint: fingerprint}
	p := Profile{SchemaVersion: "1.0.0", ProfileID: "profile_" + strings.Repeat("a", 32), InstanceID: "instance_" + strings.Repeat("b", 32), DisplayName: "Private test hub", OwnerUID: policy.OwnerUID, ProfileDirectory: dir, Mode: "local", ReleaseFingerprint: fingerprint, ConfigDigest: "sha256:" + strings.Repeat("b", 64), NATSEndpoint: "nats://127.0.0.1:4222", CredentialRef: "credential_test", ComposeProject: "agentmux_test", Docker: &ProfileDocker{Backend: NativeUnix, Executable: "/usr/bin/docker", Context: "test", Endpoint: "unix:///private/docker.sock", EngineID: "engine-test", ClientVersion: "29.1.0", ServerVersion: "29.1.0", ComposeVersion: "2.40.0"}}
	return policy, p
}

func TestProfileEnrollmentAndReadOnlyLoad(t *testing.T) {
	policy, p := profileFixture(t)
	if _, err := LoadProfile(policy); err == nil {
		t.Fatal("missing file loaded")
	}
	entries, _ := os.ReadDir(policy.Directory)
	if len(entries) != 0 {
		t.Fatal("load enrolled")
	}
	if err := EnrollProfile(policy, p); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(policy.Directory, "profile.json")
	before, _ := os.ReadFile(path)
	loaded, err := LoadProfile(policy)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Summary().ProfileID != p.ProfileID {
		t.Fatal("identity changed")
	}
	public, _ := json.Marshal(loaded.Summary())
	for _, secret := range []string{policy.Directory, p.CredentialRef, p.Docker.Endpoint, p.Docker.Executable} {
		if strings.Contains(string(public), secret) {
			t.Fatal("private declaration exposed")
		}
	}
	copy := loaded.Declaration()
	copy.Docker.Context = "changed"
	declared, ok := loaded.LocalDocker()
	if !ok || declared.Context != "test" {
		t.Fatal("mutable declaration")
	}
	p.DisplayName = "Replacement"
	if err := EnrollProfile(policy, p); err == nil {
		t.Fatal("overwrite accepted")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("existing bytes changed")
	}
	entries, _ = os.ReadDir(policy.Directory)
	if len(entries) != 1 {
		t.Fatal("staging file retained")
	}
}

func TestProfileRejectsWritableAncestorBeforeRead(t *testing.T) {
	policy, p := profileFixture(t)
	if err := EnrollProfile(policy, p); err != nil {
		t.Fatal(err)
	}
	ancestor := filepath.Dir(policy.Directory)
	info, err := os.Stat(ancestor)
	if err != nil {
		t.Fatal("ancestor control unavailable")
	}
	if os.Chmod(ancestor, 0777) != nil {
		t.Fatal("writable ancestor control failed")
	}
	defer os.Chmod(ancestor, info.Mode().Perm())
	if _, err := LoadProfile(policy); err == nil {
		t.Fatal("private profile below writable ancestor was accepted")
	}
}

func TestProfileRejectsSameSizeRewriteAfterOpen(t *testing.T) {
	for _, restore := range []bool{false, true} {
		t.Run(map[bool]string{false: "rewrite", true: "restore-mtime"}[restore], func(t *testing.T) {
			policy, p := profileFixture(t)
			if EnrollProfile(policy, p) != nil {
				t.Fatal("profile rewrite control enrollment failed")
			}
			path := filepath.Join(policy.Directory, "profile.json")
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal("profile rewrite metadata unavailable")
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal("profile rewrite contents unavailable")
			}
			changed := strings.Replace(string(raw), "Private test hub", "Changed test hub", 1)
			if len(changed) != len(raw) {
				t.Fatal("profile control did not preserve file size")
			}
			open := func(root *os.Root, name string) (*os.File, error) {
				file, err := assembly.OpenMember(root, name)
				if err != nil {
					return nil, err
				}
				time.Sleep(time.Millisecond)
				if os.WriteFile(path, []byte(changed), 0600) != nil {
					file.Close()
					t.Fatal("profile rewrite control failed")
				}
				if restore && os.Chtimes(path, before.ModTime(), before.ModTime()) != nil {
					file.Close()
					t.Fatal("profile mtime restore failed")
				}
				return file, nil
			}
			if _, err := loadProfile(policy, open); err == nil {
				t.Fatal("changed private profile was accepted")
			}
		})
	}
}

func TestProfileServerTrustDeclarations(t *testing.T) {
	for _, mode := range []string{"valid", "missing-reference", "missing-digest", "wrong-reference", "invalid-digest", "plaintext", "remote"} {
		t.Run(mode, func(t *testing.T) {
			policy, p := profileFixture(t)
			p.NATSEndpoint = "tls://127.0.0.1:4222"
			p.ServerTrustRef = "nats-server-trust.json"
			p.ServerTrustDigest = "sha256:" + strings.Repeat("c", 64)
			switch mode {
			case "missing-reference":
				p.ServerTrustRef = ""
			case "missing-digest":
				p.ServerTrustDigest = ""
			case "wrong-reference":
				p.ServerTrustRef = "alternative.json"
			case "invalid-digest":
				p.ServerTrustDigest = "invalid"
			case "plaintext":
				p.NATSEndpoint = "nats://127.0.0.1:4222"
			case "remote":
				p.Mode = "remote"
				p.Docker = nil
				p.ComposeProject = ""
			}
			err := EnrollProfile(policy, p)
			if mode == "valid" {
				if err != nil {
					t.Fatal("valid local trust declaration rejected")
				}
				if loaded, err := LoadProfile(policy); err != nil || loaded.Declaration().ServerTrustDigest != p.ServerTrustDigest {
					t.Fatal("enrolled local trust declaration changed")
				}
			} else if err == nil {
				t.Fatal("invalid local trust declaration accepted")
			}
		})
	}
}

func TestProfileConcurrentExclusiveEnrollment(t *testing.T) {
	policy, p := profileFixture(t)
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- EnrollProfile(policy, p) }()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("successful enrollments: %d", success)
	}
	if _, err := LoadProfile(policy); err != nil {
		t.Fatal(err)
	}
}

func TestProfileInvalidDeclarationsBeforeSideEffects(t *testing.T) {
	cases := map[string]func(*Profile){
		"identity":    func(p *Profile) { p.InstanceID = "123" },
		"display":     func(p *Profile) { p.DisplayName = "bad\x1b[31m" },
		"release":     func(p *Profile) { p.ReleaseFingerprint = "sha256:" + strings.Repeat("c", 64) },
		"owner":       func(p *Profile) { p.OwnerUID++ },
		"path":        func(p *Profile) { p.ProfileDirectory += "/other" },
		"userinfo":    func(p *Profile) { p.NATSEndpoint = "tls://user:secret@example.test:4222" },
		"port":        func(p *Profile) { p.NATSEndpoint = "nats://127.0.0.1:99999" },
		"query":       func(p *Profile) { p.NATSEndpoint += "?token=secret" },
		"empty-query": func(p *Profile) { p.NATSEndpoint += "?" },
		"hostname": func(p *Profile) {
			p.Mode = "remote"
			p.Docker = nil
			p.ComposeProject = ""
			p.NATSEndpoint = "tls://-invalid.test:4222"
		},
		"nonloopback":   func(p *Profile) { p.NATSEndpoint = "nats://example.test:4222" },
		"docker-remote": func(p *Profile) { p.Docker.Endpoint = "ssh://example.test" },
		"version":       func(p *Profile) { p.Docker.ClientVersion = "latest" },
		"remote-docker": func(p *Profile) { p.Mode = "remote"; p.NATSEndpoint = "tls://example.test:4222" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			policy, p := profileFixture(t)
			change(&p)
			if err := EnrollProfile(policy, p); err == nil {
				t.Fatal("invalid enrollment")
			}
			entries, _ := os.ReadDir(policy.Directory)
			if len(entries) != 0 {
				t.Fatal("failure changed files")
			}
		})
	}
}

func TestProfileRemoteDeclarationDoesNotSelectDocker(t *testing.T) {
	policy, p := profileFixture(t)
	p.Mode = "remote"
	p.Docker = nil
	p.ComposeProject = ""
	p.NATSEndpoint = "tls://example.test:4222"
	t.Setenv("DOCKER_HOST", "ssh://do-not-contact.test")
	if err := EnrollProfile(policy, p); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadProfile(policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded.LocalDocker(); ok {
		t.Fatal("remote selected Docker")
	}
	p.NATSEndpoint = "nats://example.test:4222"
	if validateProfile(p, policy) == nil {
		t.Fatal("plaintext remote accepted")
	}
}

func TestProfileStrictJSONAndTrust(t *testing.T) {
	for _, name := range []string{"duplicate", "escaped-duplicate", "nested-duplicate", "unknown", "missing", "null", "oversize", "trailing", "untrusted-installed"} {
		t.Run(name, func(t *testing.T) {
			policy, p := profileFixture(t)
			raw, _ := json.Marshal(p)
			switch name {
			case "duplicate":
				raw = append([]byte(`{"mode":"remote",`), raw[1:]...)
			case "escaped-duplicate":
				raw = append([]byte(`{"\u006dode":"remote",`), raw[1:]...)
			case "nested-duplicate":
				raw = []byte(strings.Replace(string(raw), `"context":"test"`, `"context":"test","context":"other"`, 1))
			case "unknown":
				raw = append([]byte(`{"surprise":true,`), raw[1:]...)
			case "missing":
				var fields map[string]any
				json.Unmarshal(raw, &fields)
				delete(fields, "ownerUid")
				raw, _ = json.Marshal(fields)
			case "null":
				raw = []byte(strings.Replace(string(raw), `"displayName":"Private test hub"`, `"displayName":null`, 1))
			case "oversize":
				raw = append(raw, []byte(strings.Repeat(" ", profileLimit))...)
			case "trailing":
				raw = append(raw, []byte(` {}`)...)
			case "untrusted-installed":
				policy.InstalledReleaseFingerprint = "sha256:" + strings.Repeat("c", 64)
			}
			path := filepath.Join(policy.Directory, "profile.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadProfile(policy); err == nil {
				t.Fatal("invalid profile loaded")
			}
			after, _ := os.ReadFile(path)
			if string(after) != string(raw) {
				t.Fatal("load modified bytes")
			}
		})
	}
}

func TestProfileFilesystemRefusals(t *testing.T) {
	for _, name := range []string{"workspace", "directory-mode", "file-mode", "file-symlink", "directory-symlink", "hardlink", "wrong-policy-owner", "missing-directory"} {
		t.Run(name, func(t *testing.T) {
			policy, p := profileFixture(t)
			if err := EnrollProfile(policy, p); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(policy.Directory, "profile.json")
			switch name {
			case "workspace":
				policy.WorkspaceRoots = []string{filepath.Dir(policy.Directory)}
			case "directory-mode":
				os.Chmod(policy.Directory, 0755)
			case "file-mode":
				os.Chmod(path, 0644)
			case "file-symlink":
				os.Rename(path, path+".real")
				os.Symlink(path+".real", path)
			case "directory-symlink":
				alias := policy.Directory + "-alias"
				os.Symlink(policy.Directory, alias)
				policy.Directory = alias
			case "hardlink":
				if err := os.Link(path, path+".link"); err != nil {
					t.Fatal(err)
				}
			case "wrong-policy-owner":
				policy.OwnerUID++
			case "missing-directory":
				policy.Directory += "/missing"
			}
			if _, err := LoadProfile(policy); err == nil {
				t.Fatal("unsafe profile loaded")
			}
		})
	}
}
