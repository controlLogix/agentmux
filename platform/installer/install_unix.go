//go:build linux || darwin

package installer

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/controlLogix/agentmux/platform/privatefs"
	"golang.org/x/sys/unix"
)

type destinationPolicy struct {
	directory func(*os.File) error
	file      func(*os.File, os.FileMode) error
}

func protectedDirectory(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return refusal("destination_untrusted", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != 0 || info.Mode().Perm() != 0755 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 || privatefs.CheckDescriptor(file, privatefs.PublicAncestor) != nil {
		return refusal("destination_untrusted", nil)
	}
	return nil
}

func protectedFile(file *os.File, mode os.FileMode) error {
	info, err := file.Stat()
	if err != nil {
		return refusal("destination_untrusted", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != 0 || stat.Nlink != 1 || info.Mode().Perm() != mode || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 || privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil {
		return refusal("destination_untrusted", nil)
	}
	return nil
}

// Install is the explicit administrator operation. It never elevates itself,
// starts a child process, changes an existing release, or selects a profile.
func Install(parent context.Context, p *Package) (Result, error) {
	if parent == nil {
		return Result{}, refusal("context_invalid", nil)
	}
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		return Result{}, refusal("platform_unqualified", nil)
	}
	if os.Geteuid() != 0 {
		return Result{}, refusal("administrator_required", nil)
	}
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()
	if !validPackage(p) {
		return Result{}, refusal("package_invalid", nil)
	}
	base, err := openProtectedBase(ctx)
	if err != nil {
		return Result{}, err
	}
	result, failure := installAt(ctx, base, p, destinationPolicy{protectedDirectory, protectedFile})
	failure = closeOwned(base, failure)
	if failure != nil {
		return Result{}, bindInstallation(failure, p.id)
	}
	return result, nil
}

func validPackage(p *Package) bool {
	if p == nil || len(p.id) != 64 || len(p.files) != 9 {
		return false
	}
	allowed := map[string]os.FileMode{"release-manifest.json": 0444, "release-authorization.json": 0444, "release-authorization.sig": 0444, "protected-assembly.json": 0444, "agentmux-runtime": 0555,
		"bin/boot": 0555, "bin/kernel-lifecycle": 0555, "bin/internal-communication": 0555, "bin/exported-status": 0555}
	for _, file := range p.files {
		mode, ok := allowed[file.name]
		if !ok || file.mode != mode || len(file.data) == 0 {
			return false
		}
		delete(allowed, file.name)
	}
	return len(allowed) == 0 && digestPattern.MatchString("sha256:"+p.id)
}

func bindInstallation(cause error, id string) error {
	return &Failure{code: "installation_incomplete", installation: id, cause: cause}
}

func openProtectedBase(ctx context.Context) (*os.File, error) {
	parts := strings.Split(strings.TrimPrefix(ProtectedReleaseBase, "/"), "/")
	parent := unix.AT_FDCWD
	var held *os.File
	for i := -1; i < len(parts); i++ {
		if err := ctx.Err(); err != nil {
			return nil, closeOwned(held, refusal("deadline", err))
		}
		name := "/"
		if i >= 0 {
			name = parts[i]
		}
		created := false
		fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err == unix.ENOENT && i >= 2 {
			// Only the three fixed product directories may be created. Existing
			// system ancestors must already be trusted and are never repaired.
			if createErr := unix.Mkdirat(parent, name, 0755); createErr == nil {
				created = true
			} else if createErr != unix.EEXIST {
				return nil, closeOwned(held, refusal("destination_unavailable", createErr))
			}
			fd, err = unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		}
		if err != nil {
			return nil, closeOwned(held, refusal("destination_unavailable", err))
		}
		current := os.NewFile(uintptr(fd), "installer-protected-directory")
		if created {
			if err := current.Chmod(0755); err != nil {
				return nil, closeOwned(current, closeOwned(held, refusal("copy_failed", err)))
			}
		}
		if err := protectedDirectory(current); err != nil {
			return nil, closeOwned(current, closeOwned(held, err))
		}
		if err := closeOwned(held, nil); err != nil {
			return nil, closeOwned(current, err)
		}
		held, parent = current, fd
	}
	return held, nil
}

// installAt is the same fixed copy path used by Install. Focused tests provide a
// private directory policy here; that does not qualify protected installation.
func installAt(ctx context.Context, base *os.File, p *Package, policy destinationPolicy) (result Result, failure error) {
	if ctx == nil || base == nil || !validPackage(p) || policy.directory == nil || policy.file == nil {
		return Result{}, refusal("package_invalid", nil)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, refusal("deadline", err)
	}
	if err := policy.directory(base); err != nil {
		return Result{}, err
	}
	created := false
	if err := unix.Mkdirat(int(base.Fd()), p.id, 0755); err == nil {
		created = true
	} else if err != unix.EEXIST {
		return Result{}, refusal("destination_unavailable", err)
	}
	fd, err := unix.Openat(int(base.Fd()), p.id, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return Result{}, bindInstallation(refusal("destination_conflict", err), p.id)
	}
	root := os.NewFile(uintptr(fd), "installer-new-release")
	defer func() {
		failure = closeOwned(root, failure)
		if failure != nil {
			result = Result{}
			failure = bindInstallation(failure, p.id)
		}
	}()
	if created {
		if err := root.Chmod(0755); err != nil {
			return Result{}, refusal("copy_failed", err)
		}
	}
	if err := policy.directory(root); err != nil {
		return Result{}, err
	}
	if created {
		if err := unix.Mkdirat(fd, "bin", 0755); err != nil {
			return Result{}, refusal("copy_failed", err)
		}
		binFD, err := unix.Openat(fd, "bin", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return Result{}, refusal("copy_failed", err)
		}
		bin := os.NewFile(uintptr(binFD), "installer-new-members")
		if err := bin.Chmod(0755); err != nil {
			return Result{}, closeOwned(bin, refusal("copy_failed", err))
		}
		if err := policy.directory(bin); err != nil {
			return Result{}, closeOwned(bin, err)
		}
		for _, file := range p.files {
			parent, name := root, file.name
			if strings.HasPrefix(name, "bin/") {
				parent, name = bin, strings.TrimPrefix(name, "bin/")
			}
			if err := writeNew(ctx, parent, name, file, policy); err != nil {
				return Result{}, closeOwned(bin, err)
			}
		}
		failure = closeOwned(bin, bin.Sync())
		if failure != nil {
			return Result{}, failure
		}
		if err := root.Sync(); err != nil {
			return Result{}, refusal("sync_failed", err)
		}
		if err := base.Sync(); err != nil {
			return Result{}, refusal("sync_failed", err)
		}
	}
	if err := verifyDestination(ctx, root, p, policy); err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, refusal("deadline", err)
	}
	outcome := "reused"
	if created {
		outcome = "installed"
	}
	return p.Result(outcome), nil
}

func writeNew(ctx context.Context, parent *os.File, name string, body payload, policy destinationPolicy) error {
	if err := ctx.Err(); err != nil {
		return refusal("deadline", err)
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return refusal("copy_failed", err)
	}
	file := os.NewFile(uintptr(fd), "installer-new-file")
	var failure error
	for offset := 0; offset < len(body.data); {
		if err := ctx.Err(); err != nil {
			failure = refusal("deadline", err)
			break
		}
		end := offset + 64*1024
		if end > len(body.data) {
			end = len(body.data)
		}
		n, err := file.Write(body.data[offset:end])
		offset += n
		if err != nil || n == 0 {
			failure = refusal("copy_failed", err)
			break
		}
	}
	if failure == nil {
		if err := file.Chmod(body.mode); err != nil {
			failure = refusal("copy_failed", err)
		}
	}
	if failure == nil {
		if err := policy.file(file, body.mode); err != nil {
			failure = err
		}
	}
	if failure == nil {
		if err := file.Sync(); err != nil {
			failure = refusal("sync_failed", err)
		}
	}
	return closeOwned(file, failure)
}

func verifyDestination(ctx context.Context, root *os.File, p *Package, policy destinationPolicy) error {
	if err := policy.directory(root); err != nil {
		return err
	}
	entries, err := root.ReadDir(7)
	if err != nil && err != io.EOF {
		return refusal("destination_conflict", err)
	}
	if len(entries) != 6 {
		return refusal("destination_conflict", nil)
	}
	allowed := map[string]bool{"bin": true, "release-manifest.json": true, "release-authorization.json": true, "release-authorization.sig": true, "protected-assembly.json": true, "agentmux-runtime": true}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			return refusal("destination_conflict", nil)
		}
		delete(allowed, entry.Name())
	}
	fd, err := unix.Openat(int(root.Fd()), "bin", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return refusal("destination_conflict", err)
	}
	bin := os.NewFile(uintptr(fd), "installer-verified-members")
	failure := policy.directory(bin)
	if failure == nil {
		members, err := bin.ReadDir(5)
		if (err != nil && err != io.EOF) || len(members) != 4 {
			failure = refusal("destination_conflict", err)
		}
	}
	if failure == nil {
		for _, expected := range p.files {
			parent, name := root, expected.name
			if strings.HasPrefix(name, "bin/") {
				parent, name = bin, strings.TrimPrefix(name, "bin/")
			}
			fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if err != nil {
				failure = refusal("destination_conflict", err)
				break
			}
			file := os.NewFile(uintptr(fd), "installer-verified-file")
			failure = policy.file(file, expected.mode)
			if failure == nil {
				raw, err := readHeld(ctx, file, int64(len(expected.data)))
				if err != nil || hash(raw) != hash(expected.data) {
					failure = refusal("destination_conflict", err)
				}
			}
			failure = closeOwned(file, failure)
			if failure != nil {
				break
			}
		}
	}
	return closeOwned(bin, failure)
}

// Diagnostic is safe to print. Private paths, file handles and underlying errors
// remain on Failure and never enter this fixed public representation.
type Diagnostic struct {
	SchemaVersion  string `json:"schemaVersion"`
	Kind           string `json:"kind"`
	Code           string `json:"code"`
	Action         string `json:"action"`
	InstallationID string `json:"installationId,omitempty"`
}

func Diagnose(err error) Diagnostic {
	out := Diagnostic{SchemaVersion: "1.0.0", Kind: "installation-diagnostic", Code: "installation_failed", Action: "Check the explicitly selected installation and trusted release policy."}
	var failure *Failure
	if !errors.As(err, &failure) {
		return out
	}
	switch failure.code {
	case "administrator_required":
		out.Code, out.Action = failure.code, "Ask the installation administrator to invoke this install operation explicitly; the installer does not elevate itself."
	case "platform_unqualified":
		out.Code, out.Action = failure.code, "Use the native macOS ARM64 installation target."
	case "installation_incomplete":
		out.Code, out.Action = failure.code, "Keep this installation unselected. Have the administrator inspect the exact installation before retrying; do not replace another release or delete data."
		out.InstallationID = failure.installation
	case "enrollment_rejected", "installed_images_rejected":
		out.Code, out.Action = failure.code, "Check the existing explicit user enrollment and installed release paths; do not create another identity or bypass trust."
	case "cleanup_failed":
		out.Code, out.Action = failure.code, "Keep the concrete cleanup failure and have the installation administrator inspect it; do not retry consumed descriptors."
	case "selection_invalid", "release_rejected", "source_changed", "member_rejected", "runtime_rejected", "layout_unsupported":
		out.Code, out.Action = failure.code, "Verify the selected package, separately enrolled release authority and runtime digest before installing."
	case "client_manifest_rejected", "client_file_rejected", "client_native_rejected", "client_foundation_rejected":
		out.Code, out.Action = failure.code, "Verify the independently selected client package, complete file roster, bundled Python libraries and matching protected foundation."
	case "launcher_busy":
		out.Code, out.Action = failure.code, "Another launcher installation owns the destination. Wait for that operation to finish before inspecting and retrying."
	case "launcher_conflict":
		out.Code, out.Action = failure.code, "Inspect the installed launcher. Replacement requires its exact current digest; do not overwrite an unknown file or bypass permissions."
	case "launcher_incomplete", "launcher_cleanup_failed", "launcher_copy_failed":
		out.Code, out.Action = failure.code, "Launcher publication may be incomplete. Have the administrator inspect the stable launcher and retained staging files before retrying; do not infer rollback or delete unrelated entries."
	case "deadline":
		out.Code, out.Action = failure.code, "The operation exceeded its budget. Inspect the selected installation before retrying."
	}
	return out
}
