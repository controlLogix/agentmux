//go:build linux || darwin

package installer

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLauncherRetainedBytesAndExactReuse(t *testing.T) {
	selected := fixtureSelection(t)
	p := prepareFixture(t, selected)
	if err := os.Chmod(selected.Runtime.Path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(selected.Runtime.Path, []byte("changed source"), 0500); err != nil {
		t.Fatal(err)
	}
	base, policy := privateDestination(t)
	first, err := installLauncherAt(context.Background(), base, p, "", policy)
	if err != nil || first.Outcome != "installed" || first.Digest != selected.Runtime.Digest || first.Enrollment != "unchanged" || first.Readiness != "not_observed" {
		t.Fatalf("installation result: %+v, %v", first, err)
	}
	path := filepath.Join(base.Name(), launcherName)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || hash(raw) != selected.Runtime.Digest {
		t.Fatal("retained runtime bytes changed", err)
	}
	second, err := installLauncherAt(context.Background(), base, p, "", policy)
	after, statErr := os.Stat(path)
	if err != nil || statErr != nil || second.Outcome != "reused" || !os.SameFile(before, after) {
		t.Fatal("reuse changed installed inode", err, statErr)
	}
}

func TestLauncherExplicitUpdatePreservesOpenImageAndUnrelatedFiles(t *testing.T) {
	selected := fixtureSelection(t)
	old := prepareFixture(t, selected)
	base, policy := privateDestination(t)
	if _, err := installAt(context.Background(), base, old, policy); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(base.Name(), "unrelated")
	if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := installLauncherAt(context.Background(), base, old, "", policy); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base.Name(), launcherName)
	held, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	oldInfo, err := held.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(selected.Runtime.Path, 0700); err != nil {
		t.Fatal(err)
	}
	newBytes := []byte("replacement runtime")
	if err := os.WriteFile(selected.Runtime.Path, newBytes, 0500); err != nil {
		t.Fatal(err)
	}
	oldDigest := selected.Runtime.Digest
	selected.Runtime.Digest = hash(newBytes)
	next := prepareFixture(t, selected)
	result, err := installLauncherAt(context.Background(), base, next, oldDigest, policy)
	if err != nil || result.Outcome != "updated" || result.Digest != selected.Runtime.Digest {
		t.Fatal("explicit update failed", err)
	}
	oldBytes, err := io.ReadAll(held)
	if err != nil || hash(oldBytes) != oldDigest {
		t.Fatal("original open image changed", err)
	}
	current, err := os.ReadFile(path)
	if err != nil || string(current) != string(newBytes) {
		t.Fatal("new launcher bytes missing", err)
	}
	newInfo, err := os.Stat(path)
	if err != nil || os.SameFile(oldInfo, newInfo) {
		t.Fatal("update did not replace inode", err)
	}
	kept, err := os.ReadFile(sentinel)
	if err != nil || string(kept) != "keep" {
		t.Fatal("unrelated file changed", err)
	}
	release, err := os.Open(filepath.Join(base.Name(), old.id))
	if err != nil {
		t.Fatal(err)
	}
	defer release.Close()
	if err := verifyDestination(context.Background(), release, old, policy); err != nil {
		t.Fatal("old release changed", err)
	}
}

func TestLauncherRefusesUnselectedReplacement(t *testing.T) {
	for _, scenario := range []string{"stale", "malformed", "expected_but_missing", "different_without_expected", "matching_new_stale_expected"} {
		t.Run(scenario, func(t *testing.T) {
			selected := fixtureSelection(t)
			p := prepareFixture(t, selected)
			base, policy := privateDestination(t)
			path := filepath.Join(base.Name(), launcherName)
			expected := "sha256:" + strings.Repeat("f", 64)
			original := []byte("different installed image")
			if scenario == "matching_new_stale_expected" {
				original = []byte("disposable runtime")
			}
			if scenario != "expected_but_missing" {
				if err := os.WriteFile(path, original, 0555); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "malformed" {
				expected = "invalid"
			}
			if scenario == "different_without_expected" {
				expected = ""
			}
			if _, err := installLauncherAt(context.Background(), base, p, expected, policy); err == nil {
				t.Fatal("unselected replacement accepted")
			}
			raw, err := os.ReadFile(path)
			if scenario == "expected_but_missing" {
				if !os.IsNotExist(err) {
					t.Fatal("missing launcher created", err)
				}
			} else if err != nil || string(raw) != string(original) {
				t.Fatal("refusal changed original", err)
			}
		})
	}
}

func TestLauncherRefusesUntrustedDestination(t *testing.T) {
	for _, fault := range []string{"symlink", "hardlink", "mode", "directory"} {
		t.Run(fault, func(t *testing.T) {
			p := prepareFixture(t, fixtureSelection(t))
			base, policy := privateDestination(t)
			path := filepath.Join(base.Name(), launcherName)
			sentinel := filepath.Join(base.Name(), "keep")
			if err := os.WriteFile(sentinel, []byte("unchanged"), 0555); err != nil {
				t.Fatal(err)
			}
			var err error
			switch fault {
			case "symlink":
				err = os.Symlink(sentinel, path)
			case "hardlink":
				err = os.Link(sentinel, path)
			case "mode":
				err = os.WriteFile(path, []byte("unchanged"), 0755)
			case "directory":
				err = os.Mkdir(path, 0755)
			}
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := installLauncherAt(context.Background(), base, p, hash([]byte("unchanged")), policy); err == nil {
				t.Fatal("untrusted target accepted")
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("refusal replaced target", err)
			}
			raw, err := os.ReadFile(sentinel)
			if err != nil || string(raw) != "unchanged" {
				t.Fatal("unrelated target changed", err)
			}
		})
	}
}

func TestLauncherDeadlineAndHeldLockDoNotPublish(t *testing.T) {
	for _, reason := range []string{"deadline", "lock"} {
		t.Run(reason, func(t *testing.T) {
			p := prepareFixture(t, fixtureSelection(t))
			base, policy := privateDestination(t)
			ctx := context.Background()
			if reason == "deadline" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Unix(1, 0))
				defer cancel()
			} else {
				other, err := os.Open(base.Name())
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close()
				if err := unix.Flock(int(other.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
					t.Fatal(err)
				}
				defer unix.Flock(int(other.Fd()), unix.LOCK_UN)
			}
			result, err := installLauncherAt(ctx, base, p, "", policy)
			want := "installer_deadline"
			if reason == "lock" {
				want = "installer_launcher_busy"
			}
			if err == nil || err.Error() != want || result != (LauncherResult{}) {
				t.Fatal("unavailable installation did not retain its exact refusal", err)
			}
			entries, err := os.ReadDir(base.Name())
			if err != nil || len(entries) != 0 {
				t.Fatal("refusal created entries", err)
			}
		})
	}
}
