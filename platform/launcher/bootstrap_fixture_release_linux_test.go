//go:build linux && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func bootstrapPrepareFixtureRelease(t *testing.T, selected bootstrapFixtureSelection, directory string) bootstrapFixtureRelease {
	t.Helper()
	packageDirectory := filepath.Join(directory, "release")
	for _, path := range []string{packageDirectory, filepath.Join(packageDirectory, "bin")} {
		if os.Mkdir(path, 0700) != nil {
			t.Fatal("private fixture member directory unavailable")
		}
	}
	// Reuse the existing signature fixture, replacing every synthetic member with
	// the actual native kernel binary before signing its new source-bound hashes.
	release := signedReleaseFixture(t)
	release.policy.PackageDirectory = packageDirectory
	release.manifest.Broker.Image = selected.Image
	release.manifest.Broker.NATSVersion = selected.NATSVersion
	release.manifest.Broker.ComposeVersion = selected.Docker.ComposeVersion
	binary := filepath.Join(packageDirectory, "bin", "kernel-build")
	buildCtx, buildCancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer buildCancel()
	plan, err := bootstrapKernelBuild(selected, bootstrapActualHost(), runtime.GOROOT(), binary, os.Environ())
	if err != nil {
		t.Fatal("native kernel build selection refused")
	}
	build := exec.CommandContext(buildCtx, plan.Executable, plan.Args...)
	build.Dir = ".."
	build.WaitDelay = 2 * time.Second
	build.Env = plan.Env
	if build.Run() != nil {
		t.Fatal("actual native kernel build failed")
	}
	bootstrapCheckNativeKernel(t, binary, selected.GOARCH)
	binaryBytes, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal("actual native kernel bytes unavailable")
	}
	members, err := bootstrapCopyRoleMembers(packageDirectory, binaryBytes)
	if err != nil {
		t.Fatal("actual kernel member write failed")
	}
	if os.Remove(binary) != nil {
		t.Fatal("fixture build intermediate cleanup failed")
	}
	release.assembly["plugins"] = members
	release.refresh(t)
	bootstrapPrepareNativeRelease(t, release)
	return bootstrapFixtureRelease{policy: release.policy, assemblyDigest: release.authorization.AssemblyDigest, kernelDigest: releaseDigest(binaryBytes)}
}
