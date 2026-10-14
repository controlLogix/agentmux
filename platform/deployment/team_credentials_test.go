//go:build linux || darwin

package deployment

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestTeamPrivateCredentialResolverBindingsAndFileAdmission(t *testing.T) {
	for _, mode := range []string{"valid", "reference", "scope", "symlink", "hardlink", "permissions", "fifo", "oversize", "mixed-auth", "field-alias"} {
		t.Run(mode, func(t *testing.T) {
			p := teamTestPolicy(t)
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal("canonical private fixture directory unavailable")
			}
			if os.Chmod(dir, 0700) != nil {
				t.Fatal("private fixture directory permissions unavailable")
			}
			workspace, err := filepath.Abs(".")
			if err != nil {
				t.Fatal("fixture workspace unavailable")
			}
			policy := TeamPrivateCredentialPolicy{Directory: dir, OwnerUID: uint32(os.Geteuid()), WorkspaceRoots: []string{workspace}, Reference: p.CredentialRef, Scope: p.Scope}
			resolver, err := NewPrivateTeamCredentialResolver(policy)
			if err != nil {
				t.Fatal("explicit private policy rejected")
			}
			doc := teamCredentialDocument{SchemaVersion: "1.0.0", Reference: p.CredentialRef, Scope: p.Scope, Username: "fixture_user", Password: strings.Repeat("c", 48)}
			if mode == "scope" {
				doc.Scope.ProjectID = "other_project"
			}
			if mode == "mixed-auth" {
				doc.DecoratedCredentials = "not-a-basic-credential"
			}
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal("private fixture encoding failed")
			}
			if mode == "field-alias" {
				raw = []byte(strings.Replace(string(raw), "\"password\"", "\"Password\"", 1))
			}
			if mode == "oversize" {
				raw = []byte(strings.Repeat("x", 64*1024+1))
			}
			path := filepath.Join(dir, p.CredentialRef.ID+".json")
			if mode == "fifo" {
				if unix.Mkfifo(path, 0600) != nil {
					t.Fatal("owned FIFO fixture creation failed")
				}
			} else if mode == "symlink" {
				target := filepath.Join(dir, "actual.json")
				if os.WriteFile(target, raw, 0600) != nil || os.Symlink(target, path) != nil {
					t.Fatal("owned symlink fixture creation failed")
				}
			} else {
				if os.WriteFile(path, raw, 0600) != nil {
					t.Fatal("private fixture write failed")
				}
				if mode == "hardlink" && os.Link(path, filepath.Join(dir, "alias.json")) != nil {
					t.Fatal("owned hard-link fixture creation failed")
				}
				if mode == "permissions" && os.Chmod(path, 0644) != nil {
					t.Fatal("owned permissions fixture creation failed")
				}
			}
			ref := p.CredentialRef
			if mode == "reference" {
				ref.ID = "wrong_reference"
			}
			credential, err := resolver.Resolve(context.Background(), ref)
			if mode == "valid" {
				if err != nil || credential.reference != p.CredentialRef || credential.scope != p.Scope || credential.username != "fixture_user" {
					t.Fatalf("valid private credential binding failed: %v", err)
				}
			} else if err == nil {
				t.Fatal("invalid private credential file was admitted")
			}
		})
	}
}

func TestTeamPrivateResolverRefusesWorkspaceAndDirectoryAlias(t *testing.T) {
	p := teamTestPolicy(t)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("canonical private fixture unavailable")
	}
	policy := TeamPrivateCredentialPolicy{Directory: dir, OwnerUID: uint32(os.Geteuid()), WorkspaceRoots: []string{dir}, Reference: p.CredentialRef, Scope: p.Scope}
	if _, err := NewPrivateTeamCredentialResolver(policy); err == nil {
		t.Fatal("workspace-owned authentication was admitted")
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if os.Symlink(dir, alias) != nil {
		t.Fatal("owned directory-alias fixture unavailable")
	}
	policy.Directory = alias
	if _, err := NewPrivateTeamCredentialResolver(policy); err == nil {
		t.Fatal("directory alias was admitted")
	}
}

func TestTeamPrivateReadRejectsWritableAncestorAndSameSizeRewrite(t *testing.T) {
	for _, mode := range []string{"writable-ancestor", "same-size-rewrite"} {
		t.Run(mode, func(t *testing.T) {
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal("canonical controlled fixture unavailable")
			}
			if os.Chmod(base, 0700) != nil {
				t.Fatal("controlled ancestor permissions unavailable")
			}
			directory := filepath.Join(base, "private")
			if os.Mkdir(directory, 0700) != nil {
				t.Fatal("controlled private directory unavailable")
			}
			path := filepath.Join(directory, "fixture.json")
			original := []byte(`{"value":"original"}`)
			changed := []byte(`{"value":"modified"}`)
			if len(original) != len(changed) || os.WriteFile(path, original, 0600) != nil {
				t.Fatal("equal-size private fixture unavailable")
			}
			var hook func()
			hookCalled := false
			expected := "team_private_directory_invalid"
			if mode == "writable-ancestor" {
				if os.Chmod(base, 0777) != nil {
					t.Fatal("controlled writable ancestor unavailable")
				}
			} else {
				expected = "team_private_file_changed"
				hook = func() {
					hookCalled = true
					if os.WriteFile(path, changed, 0600) != nil {
						t.Fatal("controlled in-place rewrite failed")
					}
				}
			}
			if raw, err := teamReadPrivateChecked(directory, "fixture.json", uint32(os.Geteuid()), hook); err == nil || err.Error() != expected || raw != nil || (mode == "same-size-rewrite" && !hookCalled) {
				t.Fatal("untrusted ancestry or same-size change was admitted")
			}
		})
	}
}
