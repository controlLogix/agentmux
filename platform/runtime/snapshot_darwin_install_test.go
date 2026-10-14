//go:build darwin && cgo && agentmux_darwin_install

package runtime

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// This selection performs privileged fixture setup only when separately
// authorized. Execution and mutation attempts remain in the ordinary process.
// Installed versions are retained; this test never recursively deletes them.
func TestDarwinProtectedInstalledExecutable(t *testing.T) {
	if os.Getenv("AMX_DARWIN_INSTALL_AUTHORIZED") != "1" {
		t.Fatal("native protected-install fixture authorization is required")
	}
	if os.Geteuid() == 0 {
		t.Fatal("the native runtime and adversary must not run as root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	want := "sha256:" + hex.EncodeToString(hash[:])
	var version [32]byte
	if _, err = rand.Read(version[:]); err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(darwinReleaseBase, hex.EncodeToString(version[:]))
	path := filepath.Join(rootPath, "role")
	privileged := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "/usr/bin/sudo", append([]string{"-n"}, args...)...)
		cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
		cmd.WaitDelay = time.Second
		if err := cmd.Run(); err != nil {
			t.Fatal("bounded privileged fixture setup failed")
		}
	}
	// Verify each controlling directory before creating its exact next child.
	// No privileged mkdir/install follows an unchecked writable/symlink ancestor.
	for _, directory := range []string{"/Library/Application Support", "/Library/Application Support/Agentmux", "/Library/Application Support/Agentmux/Protected", darwinReleaseBase} {
		assertDarwinFixtureDirectory(t, filepath.Dir(directory))
		if _, err := os.Lstat(directory); os.IsNotExist(err) {
			privileged("/bin/mkdir", directory)
		} else if err != nil {
			t.Fatal("fixture ancestor unavailable")
		}
		assertDarwinFixtureDirectory(t, directory)
	}
	privileged("/bin/mkdir", rootPath)
	assertDarwinFixtureDirectory(t, rootPath)
	privileged("/usr/bin/install", "-o", "root", "-g", "wheel", "-m", "0555", self, path)
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	image, err := prepareExecutable(ctx, root, "role", want, int64(len(data)+1))
	if err != nil {
		t.Fatal(err)
	}
	defer image.close()
	admitted := image.(*protectedDarwinExecutable)
	if err := admitted.validateForStart(ctx); err != nil {
		t.Fatal(err)
	}
	for _, attempt := range []struct {
		name string
		run  func() error
	}{
		{"overwrite", func() error {
			f, err := os.OpenFile(path, os.O_WRONLY, 0)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = f.WriteAt([]byte{0}, 0)
			return err
		}},
		{"truncate", func() error { return os.Truncate(path, 0) }},
		{"chmod", func() error { return os.Chmod(path, 0777) }},
		{"unlink", func() error { return os.Remove(path) }},
		{"rename", func() error { return os.Rename(path, path+"-replaced") }},
		{"replacement", func() error { return os.WriteFile(filepath.Join(rootPath, "replacement"), []byte("changed"), 0555) }},
		{"symlink", func() error { return os.Symlink(self, filepath.Join(rootPath, "alias")) }},
	} {
		t.Run(attempt.name, func(t *testing.T) {
			if attempt.run() == nil {
				t.Fatal("ordinary process changed the protected installation")
			}
		})
	}
	// A writable control proves these mutation tests are not inert.
	control := filepath.Join(t.TempDir(), "control")
	if err := os.WriteFile(control, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(control, 1); err != nil {
		t.Fatal("writable negative control failed")
	}
	if err := os.Chmod(control, 0700); err != nil {
		t.Fatal("writable negative control failed")
	}
	if err := os.Rename(control, control+"-new"); err != nil {
		t.Fatal("writable negative control failed")
	}
	if err := os.Remove(control + "-new"); err != nil {
		t.Fatal("writable negative control failed")
	}
	// Some hosts permit creation of a read-only hard-link alias. Such an alias
	// must make admission fail, regardless of whether its creation was denied.
	alias := filepath.Join(t.TempDir(), "hard-alias")
	if err := os.Link(path, alias); err == nil {
		if admitted.validateForStart(ctx) == nil {
			t.Fatal("hard-link alias was accepted")
		}
		if err := os.Remove(alias); err != nil {
			t.Fatal(err)
		}
	}
	if err := admitted.validateForStart(ctx); err != nil {
		t.Fatal(err)
	}
	cmd := image.command([]string{"darwin-fd-research-child"})
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.WaitDelay = time.Second
	// CommandContext is used for this isolated direct execution probe only.
	bounded := exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)
	bounded.Env = cmd.Env
	bounded.Dir = cmd.Dir
	bounded.WaitDelay = cmd.WaitDelay
	output, err := bounded.Output()
	if err != nil || strings.TrimSpace(string(output)) != "darwin-descriptor-child" {
		t.Fatal("actual installed Mach-O did not execute its expected marker")
	}
	if _, err := prepareExecutable(ctx, root, "role", "sha256:"+strings.Repeat("0", 64), int64(len(data)+1)); err == nil {
		t.Fatal("wrong external digest accepted")
	}
	// Real ACL modification is an authorized fixture negative, not an updater.
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	privileged("/bin/chmod", "+a", "user:"+current.Username+" allow add_file,delete_child", rootPath)
	if admitted.validateForStart(ctx) == nil {
		t.Fatal("write-granting ancestor ACL accepted")
	}
	privileged("/bin/chmod", "-N", rootPath)
	if err := admitted.validateForStart(ctx); err != nil {
		t.Fatal(err)
	}
	privileged("/bin/chmod", "+a", "user:"+current.Username+" allow write", path)
	if admitted.validateForStart(ctx) == nil {
		t.Fatal("write-granting executable ACL accepted")
	}
	privileged("/bin/chmod", "-N", path)
	privileged("/bin/ln", "-s", path, filepath.Join(rootPath, "soft-alias"))
	if _, err := prepareExecutable(ctx, root, "soft-alias", want, int64(len(data)+1)); err == nil {
		t.Fatal("symbolic link accepted")
	}
	privileged("/bin/ln", path, filepath.Join(rootPath, "hard-alias"))
	if _, err := prepareExecutable(ctx, root, "hard-alias", want, int64(len(data)+1)); err == nil {
		t.Fatal("hard link accepted")
	}
	privileged("/bin/rm", filepath.Join(rootPath, "hard-alias"))
	privileged("/bin/chmod", "0777", path)
	if admitted.validateForStart(ctx) == nil {
		t.Fatal("writable executable accepted")
	}
	privileged("/bin/chmod", "0555", path)
	privileged("/usr/sbin/chown", current.Uid, path)
	if admitted.validateForStart(ctx) == nil {
		t.Fatal("wrong executable owner accepted")
	}
	privileged("/usr/sbin/chown", "root:wheel", path)
	roles := [4]string{"boot", "kernel-lifecycle", "internal-communication", "exported-status"}
	// Exercise actual four-child ownership and reap through the real supervisor.
	// These are fixture markers, not the full NATS-connected kernel actors.
	positive := &Prepared{roles: roles}
	defer positive.Close()
	var positiveOptions [4]RoleOptions
	for i, role := range roles {
		positive.images[i], err = prepareExecutable(ctx, root, "role", want, int64(len(data)+1))
		if err != nil {
			t.Fatal(err)
		}
		positiveOptions[i] = RoleOptions{ID: role, Args: []string{"darwin-fd-research-child"}}
	}
	actual, err := positive.Start(ctx, positiveOptions, Deadlines{StartTimeout: 5 * time.Second, StopGrace: time.Second, ReapTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if actual.Stop(stopCtx) != nil {
			t.Error("owned fixture stop failed")
		}
	}()
	select {
	case <-actual.Done():
	case <-ctx.Done():
		t.Fatal("actual four fixture children were not reaped")
	}
	if actual.CleanupError() != nil {
		t.Fatal("actual fixture cleanup failed")
	}
	statuses := actual.Status()
	if len(statuses) != 4 {
		t.Fatal("actual supervisor did not start four distinct roles")
	}
	seen := map[int]bool{}
	for _, status := range statuses {
		if status.PID <= 0 || seen[status.PID] || !status.Exited || status.ExitCode != 0 {
			t.Fatal("actual role ownership or exit evidence differs")
		}
		seen[status.PID] = true
		output, truncated := actual.Output(status.Role)
		if truncated || !strings.Contains(string(output), "darwin-descriptor-child") {
			t.Fatal("actual role marker missing")
		}
	}
	prepared := &Prepared{roles: roles}
	defer prepared.Close()
	var options [4]RoleOptions
	for i, role := range roles {
		prepared.images[i], err = prepareExecutable(ctx, root, "role", want, int64(len(data)+1))
		if err != nil {
			t.Fatal(err)
		}
		options[i] = RoleOptions{ID: role, Args: []string{"darwin-fd-research-child"}}
	}
	// Even privileged path replacement is detected before spawn. The ordinary
	// user cannot perform this operation; root/updater integrity remains trusted.
	privileged("/bin/mv", path, path+"-original")
	privileged("/usr/bin/install", "-o", "root", "-g", "wheel", "-m", "0555", self, path)
	if err := admitted.validateForStart(ctx); err == nil {
		t.Fatal("changed executable inode accepted")
	}
	group, startErr := prepared.Start(ctx, options, Deadlines{StartTimeout: 5 * time.Second, StopGrace: time.Second, ReapTimeout: time.Second})
	if startErr == nil || !strings.Contains(startErr.Error(), "protected_path_changed") || group == nil || len(group.Status()) != 0 {
		t.Fatal("actual supervisor did not reject changed path before the first spawn")
	}
	select {
	case <-group.Done():
	case <-ctx.Done():
		t.Fatal("rejected startup cleanup did not complete")
	}
	if err := group.CleanupError(); err != nil {
		t.Fatal("rejected startup retained a cleanup failure")
	}
	t.Logf("native fixture only: uid=%d; root-owned installed version retained; no production signing or Compose qualification", os.Geteuid())
}

func assertDarwinFixtureDirectory(t *testing.T, path string) {
	t.Helper()
	parent := unix.AT_FDCWD
	parts := append([]string{"/"}, strings.Split(strings.TrimPrefix(path, "/"), "/")...)
	var files []*os.File
	defer func() {
		for _, file := range files {
			file.Close()
		}
	}()
	for _, part := range parts {
		fd, err := unix.Openat(parent, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal("privileged fixture refused unsafe ancestor")
		}
		files = append(files, os.NewFile(uintptr(fd), "fixture-ancestor"))
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil || stat.Uid != 0 || stat.Mode&0022 != 0 || stat.Mode&06000 != 0 || !darwinDescriptorPolicy(fd) {
			t.Fatal("privileged fixture refused unprotected ancestor")
		}
		parent = fd
	}
}

func TestDarwinProtectedPathPolicy(t *testing.T) {
	for _, path := range []string{"/tmp/" + strings.Repeat("a", 64), darwinReleaseBase + "/short", darwinReleaseBase + "/" + strings.Repeat("A", 64), darwinReleaseBase + "/" + strings.Repeat("a", 64) + "/../" + strings.Repeat("a", 64)} {
		if darwinReleaseRoot(path) {
			t.Fatal("unsafe release root accepted")
		}
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	_, err = prepareExecutable(context.Background(), root, "unused", "unused", 1)
	if !errors.Is(err, ErrPlatformUnqualified) {
		t.Fatal("user-owned fallback became available")
	}
}
