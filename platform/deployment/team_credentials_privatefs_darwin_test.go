//go:build darwin && cgo

package deployment

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Native ACL tests change only freshly created objects in the current owner's
// home directory. They neither use sudo nor change an existing installation.
func teamPrivateACL(t *testing.T, path string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/chmod", append(args, path)...)
	cmd.WaitDelay = time.Second
	if cmd.Run() != nil {
		t.Fatal("owned native ACL operation failed")
	}
}

func TestDarwinTeamPrivateCredentialRejectsACLGrants(t *testing.T) {
	for _, object := range []string{"credential-read", "private-directory-read", "ancestor-write", "deny-only", "directory-grant-during-read", "ancestor-grant-during-read"} {
		t.Run(object, func(t *testing.T) {
			home, err := os.UserHomeDir()
			if err != nil {
				t.Fatal("owned home unavailable")
			}
			home, err = filepath.EvalSymlinks(home)
			if err != nil {
				t.Fatal("canonical owned home unavailable")
			}
			base, err := os.MkdirTemp(home, "agentmux-team-privatefs-")
			if err != nil {
				t.Fatal("fresh owned ACL fixture unavailable")
			}
			t.Cleanup(func() {
				if os.RemoveAll(base) != nil {
					t.Error("owned ACL fixture cleanup failed")
				}
			})
			ancestor, directory := filepath.Join(base, "ancestor"), filepath.Join(base, "ancestor", "private")
			if os.Mkdir(ancestor, 0700) != nil || os.Mkdir(directory, 0700) != nil {
				t.Fatal("private fixture directories unavailable")
			}
			path := filepath.Join(directory, "credential.json")
			original := []byte(`{"fixture":"public synthetic bytes"}`)
			if os.WriteFile(path, original, 0600) != nil {
				t.Fatal("synthetic private credential unavailable")
			}
			for _, target := range []string{base, ancestor, directory, path} {
				teamPrivateACL(t, target, "-N")
			}
			if raw, err := teamReadPrivate(directory, "credential.json", uint32(os.Geteuid())); err != nil || string(raw) != string(original) {
				t.Fatal("actual native private fixture refused before ACL control")
			}
			if object == "directory-grant-during-read" || object == "ancestor-grant-during-read" {
				target, grant := directory, "everyone allow read"
				if object == "ancestor-grant-during-read" {
					target, grant = ancestor, "everyone allow write"
				}
				called := false
				raw, err := teamReadPrivateChecked(directory, "credential.json", uint32(os.Geteuid()), func() { called = true; teamPrivateACL(t, target, "+a", grant) })
				if !called || err == nil || err.Error() != "team_private_directory_invalid" || raw != nil {
					t.Fatal("private directory acquired granting ACL during credential read")
				}
				teamPrivateACL(t, target, "-N")
				return
			}
			target, grant := path, "everyone allow read"
			switch object {
			case "private-directory-read":
				target = directory
			case "ancestor-write":
				target = ancestor
				grant = "everyone allow write"
			case "deny-only":
				grant = "everyone deny write"
			}
			teamPrivateACL(t, target, "+a", grant)
			raw, readErr := teamReadPrivate(directory, "credential.json", uint32(os.Geteuid()))
			if object == "deny-only" {
				if readErr != nil || string(raw) != string(original) {
					t.Fatal("DENY-only private ACL refused")
				}
			} else if readErr == nil || raw != nil {
				t.Fatal("team credential admitted granting native ACL")
			}
			teamPrivateACL(t, target, "-N")
		})
	}
}
