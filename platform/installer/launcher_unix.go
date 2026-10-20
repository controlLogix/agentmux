//go:build linux || darwin

package installer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"time"

	protected "github.com/controlLogix/agentmux/platform/runtime"
	"golang.org/x/sys/unix"
)

// StableLauncherPath contains the same frontend as a verified release. Its
// enrolled policy still selects the host; installing it never changes enrollment.
const StableLauncherPath = protected.StableFrontendPath

const launcherName = "agentmux-runtime"

type LauncherResult struct {
	SchemaVersion  string `json:"schemaVersion"`
	Kind           string `json:"kind"`
	Outcome        string `json:"outcome"`
	Path           string `json:"path"`
	Digest         string `json:"digest"`
	InstallationID string `json:"installationId"`
	Enrollment     string `json:"enrollment"`
	Readiness      string `json:"readiness"`
}

// InstallLauncher explicitly publishes a stable frontend from an already
// installed, verified package. Replacement requires the current executable's
// independently selected digest. It never elevates or starts a process.
func InstallLauncher(parent context.Context, p *Package, expectedCurrent string) (result LauncherResult, failure error) {
	if parent == nil {
		return result, refusal("context_invalid", nil)
	}
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		return result, refusal("platform_unqualified", nil)
	}
	if os.Geteuid() != 0 {
		return result, refusal("administrator_required", nil)
	}
	if !validPackage(p) || (expectedCurrent != "" && !digestPattern.MatchString(expectedCurrent)) {
		return result, refusal("selection_invalid", nil)
	}
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()
	// This operation cannot implicitly install or select a release.
	release, err := openDirectory(ctx, filepath.Join(ProtectedReleaseBase, p.id), protectedDirectory)
	if err != nil {
		return result, err
	}
	err = closeOwned(release, verifyDestination(ctx, release, p, destinationPolicy{protectedDirectory, protectedFile}))
	if err != nil {
		return result, err
	}
	base, err := openDirectory(ctx, filepath.Dir(StableLauncherPath), protectedDirectory)
	if err != nil {
		return result, err
	}
	defer func() {
		failure = closeOwned(base, failure)
		if failure != nil {
			result = LauncherResult{}
		}
	}()
	return installLauncherAt(ctx, base, p, expectedCurrent, destinationPolicy{protectedDirectory, protectedFile})
}

// All writers in this installer lock the retained directory before comparing or
// publishing. The trusted administrator remains responsible for external writes.
func installLauncherAt(ctx context.Context, base *os.File, p *Package, expectedCurrent string, policy destinationPolicy) (result LauncherResult, failure error) {
	if ctx == nil || base == nil || !validPackage(p) || policy.directory == nil || policy.file == nil || (expectedCurrent != "" && !digestPattern.MatchString(expectedCurrent)) {
		return result, refusal("selection_invalid", nil)
	}
	if err := ctx.Err(); err != nil {
		return result, refusal("deadline", err)
	}
	if err := policy.directory(base); err != nil {
		return result, err
	}
	if err := unix.Flock(int(base.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return result, refusal("launcher_busy", err)
	}
	defer func() {
		if err := unix.Flock(int(base.Fd()), unix.LOCK_UN); err != nil {
			failure = refusal("launcher_cleanup_failed", errors.Join(failure, err))
			result = LauncherResult{}
		}
	}()
	var body payload
	for _, candidate := range p.files {
		if candidate.name == launcherName {
			body = candidate
		}
	}
	current, currentDigest, err := readLauncher(ctx, base, launcherName, policy)
	if err != nil {
		return result, err
	}
	if current != nil {
		defer func() {
			failure = closeOwned(current, failure)
			if failure != nil {
				result = LauncherResult{}
			}
		}()
	}
	if expectedCurrent != "" && currentDigest != expectedCurrent {
		return result, refusal("launcher_conflict", nil)
	}
	if currentDigest == hash(body.data) {
		return launcherResult(p, "reused", currentDigest), nil
	}
	if current != nil && expectedCurrent == "" {
		return result, refusal("launcher_conflict", nil)
	}
	if current == nil && expectedCurrent != "" {
		return result, refusal("launcher_conflict", nil)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return result, refusal("launcher_copy_failed", err)
	}
	stage := ".agentmux-runtime-" + hex.EncodeToString(nonce[:])
	// On an uncertain failure retain this exact staging entry for administrator
	// inspection. Never remove another path or restore an old version by guessing.
	if err := writeNew(ctx, base, stage, body, policy); err != nil {
		return result, refusal("launcher_incomplete", err)
	}
	staged, stagedDigest, err := readLauncher(ctx, base, stage, policy)
	if err != nil {
		return result, refusal("launcher_incomplete", err)
	}
	if staged == nil {
		return result, refusal("launcher_incomplete", nil)
	}
	defer func() {
		failure = closeOwned(staged, failure)
		if failure != nil {
			result = LauncherResult{}
		}
	}()
	if stagedDigest != hash(body.data) {
		return result, refusal("launcher_incomplete", nil)
	}
	// Recheck both names through the held parent before the single publication.
	if err := sameLauncher(ctx, base, launcherName, current, currentDigest, policy); err != nil {
		return result, refusal("launcher_incomplete", err)
	}
	if err := sameLauncher(ctx, base, stage, staged, stagedDigest, policy); err != nil {
		return result, refusal("launcher_incomplete", err)
	}
	if err := ctx.Err(); err != nil {
		return result, refusal("deadline", err)
	}
	if err := unix.Renameat(int(base.Fd()), stage, int(base.Fd()), launcherName); err != nil {
		return result, refusal("launcher_incomplete", err)
	}
	if err := base.Sync(); err != nil {
		return result, refusal("launcher_incomplete", err)
	}
	if err := sameLauncher(ctx, base, launcherName, staged, stagedDigest, policy); err != nil {
		return result, refusal("launcher_incomplete", err)
	}
	if err := ctx.Err(); err != nil {
		return result, refusal("launcher_incomplete", err)
	}
	outcome := "installed"
	if current != nil {
		outcome = "updated"
	}
	return launcherResult(p, outcome, stagedDigest), nil
}

func launcherResult(p *Package, outcome, digest string) LauncherResult {
	return LauncherResult{"1.0.0", "launcher-installation-result", outcome, StableLauncherPath, digest, p.id, "unchanged", "not_observed"}
}

func readLauncher(ctx context.Context, base *os.File, name string, policy destinationPolicy) (*os.File, string, error) {
	fd, err := unix.Openat(int(base.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err == unix.ENOENT {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", refusal("launcher_conflict", err)
	}
	file := os.NewFile(uintptr(fd), "installer-launcher")
	if err := policy.file(file, 0555); err != nil {
		return nil, "", closeOwned(file, err)
	}
	raw, err := readHeld(ctx, file, runtimeLimit)
	if err != nil {
		return nil, "", closeOwned(file, err)
	}
	return file, hash(raw), nil
}

func sameLauncher(ctx context.Context, base *os.File, name string, original *os.File, expected string, policy destinationPolicy) (failure error) {
	current, digest, err := readLauncher(ctx, base, name, policy)
	if err != nil {
		return err
	}
	if current != nil {
		defer func() { failure = closeOwned(current, failure) }()
	}
	if current == nil && original == nil {
		return nil
	}
	if current == nil || original == nil || digest != expected {
		return refusal("launcher_conflict", nil)
	}
	before, err := original.Stat()
	if err != nil {
		return refusal("launcher_conflict", err)
	}
	after, err := current.Stat()
	if err != nil || !os.SameFile(before, after) {
		return refusal("launcher_conflict", err)
	}
	return nil
}
