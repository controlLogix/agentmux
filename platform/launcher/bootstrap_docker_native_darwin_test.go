//go:build darwin && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"debug/macho"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/privatefs"
	"golang.org/x/sys/unix"
)

func bootstrapCheckNativeKernel(t *testing.T, path, arch string) {
	t.Helper()
	executable, err := macho.Open(path)
	if err != nil {
		t.Fatal("actual kernel is not a native Mach-O executable")
	}
	defer executable.Close()
	want := macho.CpuAmd64
	if arch == "arm64" {
		want = macho.CpuArm64
	}
	if executable.Type != macho.TypeExec || executable.Cpu != want {
		t.Fatal("actual kernel Mach-O target does not match the native host")
	}
	// The production image loader independently checks its allowed system dylibs
	// and protected descriptors before any role spawn. No alternate runtime here.
}

// Keep fixture setup separate from unprivileged runtime execution. The existing
// protected backend requires root-owned fixed-path releases. This helper has no
// discovery, shell, recursive operations or replacement of installed versions.
func bootstrapPrepareNativeRelease(t *testing.T, release *releaseTestFixture) {
	t.Helper()
	if os.Getenv("AMX_DARWIN_INSTALL_AUTHORIZED") != "1" || os.Geteuid() == 0 {
		t.Fatal("protected fixture setup needs separate authorization and an unprivileged test process")
	}
	stage := release.policy.PackageDirectory
	destination := filepath.Join(bootstrapDarwinReleaseBase, bootstrapFixtureRandom(t, 32))
	copies, err := bootstrapDarwinCopies(stage, destination)
	if err != nil {
		t.Fatal("protected fixture copy plan refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	privileged := func(args ...string) {
		t.Helper()
		command := exec.CommandContext(ctx, "/usr/bin/sudo", append([]string{"-n"}, args...)...)
		command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
		command.WaitDelay = time.Second
		if command.Run() != nil {
			t.Fatal("bounded protected fixture setup failed; installed version retained")
		}
	}
	for _, directory := range []string{"/Library/Application Support", "/Library/Application Support/Agentmux", "/Library/Application Support/Agentmux/Protected", bootstrapDarwinReleaseBase} {
		bootstrapAssertDarwinDirectory(t, filepath.Dir(directory))
		if _, err := os.Lstat(directory); os.IsNotExist(err) {
			privileged("/bin/mkdir", "-m", "0755", directory)
		} else if err != nil {
			t.Fatal("protected fixture ancestor unavailable")
		}
		bootstrapAssertDarwinDirectory(t, directory)
	}
	// mkdir must fail on a collision, even if the colliding version looks safe.
	privileged("/bin/mkdir", "-m", "0755", destination)
	bootstrapAssertDarwinDirectory(t, destination)
	privileged("/bin/mkdir", "-m", "0755", filepath.Join(destination, "bin"))
	bootstrapAssertDarwinDirectory(t, filepath.Join(destination, "bin"))
	for _, member := range copies {
		bootstrapAssertDarwinDirectory(t, filepath.Dir(member.Destination))
		if _, err := os.Lstat(member.Destination); !os.IsNotExist(err) {
			t.Fatal("protected fixture member already exists or is unverifiable")
		}
		privileged("/usr/bin/install", "-o", "root", "-g", "wheel", "-m", member.Mode, member.Source, member.Destination)
	}
	// Reverify signatures and member digests from installed bytes, not the stage.
	policy := release.policy
	policy.PackageDirectory = destination
	if _, err := LoadInstalledRelease(policy); err != nil {
		t.Fatal("protected installed fixture signature or member digest differs")
	}
	release.policy = policy
}

func bootstrapAssertDarwinDirectory(t *testing.T, path string) {
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
			t.Fatal("protected fixture refused unsafe ancestor")
		}
		file := os.NewFile(uintptr(fd), "fixture-ancestor")
		files = append(files, file)
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil || stat.Uid != 0 || stat.Mode&0022 != 0 || stat.Mode&06000 != 0 ||
			privatefs.CheckDescriptor(file, privatefs.PublicAncestor) != nil {
			t.Fatal("protected fixture refused writable or unprotected ancestor")
		}
		parent = fd
	}
}
