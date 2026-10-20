//go:build darwin && cgo

package runtime

import (
	"context"
	"crypto/sha256"
	"debug/macho"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"

	"golang.org/x/sys/unix"
)

const darwinReleaseBase = "/Library/Application Support/Agentmux/Protected/releases"

type protectedDarwinExecutable struct {
	frontend   bool
	path       string
	want       string
	max        int64
	files      []*os.File
	identities []unix.Stat_t
}

func (e *protectedDarwinExecutable) command(args []string) *exec.Cmd {
	return exec.Command(e.path, args...)
}

func (e *protectedDarwinExecutable) close() error {
	var failures []error
	for _, file := range e.files {
		failures = append(failures, file.Close())
	}
	e.files = nil
	return errors.Join(failures...)
}

// The supervisor calls this immediately before creating each child. Root and
// the privileged updater remain trusted and must never replace active versions.
func (e *protectedDarwinExecutable) validateForStart(ctx context.Context) (failure error) {
	if len(e.files) == 0 || len(e.files) != len(e.identities) {
		return errors.New("protected_descriptor_closed")
	}
	var fresh *protectedDarwinExecutable
	var err error
	if e.frontend {
		fresh, err = openDarwinStableFrontend(ctx, e.path, e.want, e.max)
	} else {
		fresh, err = openDarwinProtected(ctx, e.path, e.want, e.max)
	}
	if err != nil {
		return err
	}
	defer func() {
		if cleanup := fresh.close(); cleanup != nil {
			failure = retainStartupCleanupCause(failure, cleanup)
		}
	}()
	if len(fresh.identities) != len(e.identities) {
		return errors.New("protected_path_changed")
	}
	for i, old := range e.identities {
		current := fresh.identities[i]
		if current.Dev != old.Dev || current.Ino != old.Ino {
			return errors.New("protected_path_changed")
		}
		var held unix.Stat_t
		if unix.Fstat(int(e.files[i].Fd()), &held) != nil || held.Dev != old.Dev || held.Ino != old.Ino {
			return errors.New("protected_descriptor_changed")
		}
	}
	return nil
}

func prepareExecutable(ctx context.Context, root *os.Root, entry, want string, max int64) (executable, error) {
	// Preserve the historical refusal for ordinary user-owned staging trees.
	if root == nil || !darwinReleaseRoot(root.Name()) {
		return nil, ErrPlatformUnqualified
	}
	if !filepath.IsLocal(entry) || filepath.Clean(entry) != entry {
		return nil, errors.New("protected_member_path_invalid")
	}
	return openDarwinProtected(ctx, filepath.Join(root.Name(), entry), want, max)
}

func darwinReleaseRoot(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) != darwinReleaseBase {
		return false
	}
	name := filepath.Base(path)
	if len(name) != 64 || strings.ToLower(name) != name {
		return false
	}
	_, err := hex.DecodeString(name)
	return err == nil
}

func openDarwinProtected(ctx context.Context, path, want string, max int64) (*protectedDarwinExecutable, error) {
	return openDarwinProtectedPath(ctx, path, want, max, false)
}

// Only the fixed frontend entrypoint uses this purpose. Release and member
// callers retain their existing path admission and cannot select this mode.
func openDarwinStableFrontend(ctx context.Context, path, want string, max int64) (*protectedDarwinExecutable, error) {
	if path != StableFrontendPath || max < 1 || max > 128*1024*1024 {
		return nil, errors.New("protected_frontend_path_invalid")
	}
	return openDarwinProtectedPath(ctx, path, want, max, true)
}

func openDarwinProtectedPath(ctx context.Context, path, want string, max int64, frontend bool) (image *protectedDarwinExecutable, failure error) {
	if ctx == nil || max < 1 || max > 1024*1024*1024 || !strings.HasPrefix(want, "sha256:") || len(want) != 71 {
		return nil, errors.New("protected_image_options_invalid")
	}
	if os.Geteuid() == 0 {
		return nil, errors.New("protected_runtime_must_be_unprivileged")
	}
	allowed := strings.HasPrefix(path, darwinReleaseBase+"/")
	if frontend {
		allowed = path == StableFrontendPath
	}
	if filepath.Clean(path) != path || !allowed || len(path) > 1023 {
		return nil, errors.New("protected_member_path_invalid")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) > 64 {
		return nil, errors.New("protected_member_path_invalid")
	}
	e := &protectedDarwinExecutable{path: path, want: want, max: max, frontend: frontend}
	failed := true
	defer func() {
		if failed {
			if cleanup := e.close(); cleanup != nil {
				failure = retainStartupCleanupCause(failure, cleanup)
			}
		}
	}()
	parent := unix.AT_FDCWD
	for i := -1; i < len(parts); i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := "/"
		if i >= 0 {
			name = parts[i]
		}
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
		final := i == len(parts)-1
		if !final {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(parent, name, flags, 0)
		if err != nil {
			return nil, errors.New("protected_path_unavailable")
		}
		file := os.NewFile(uintptr(fd), "protected-installation")
		e.files = append(e.files, file)
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil || stat.Uid != 0 || stat.Mode&0022 != 0 || stat.Mode&06000 != 0 || !darwinDescriptorPolicy(fd) {
			return nil, errors.New("protected_path_policy_failed")
		}
		if final {
			if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Mode&0111 != 0111 || stat.Size < 1 || stat.Size > max {
				return nil, errors.New("protected_image_policy_failed")
			}
		} else if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			return nil, errors.New("protected_path_policy_failed")
		}
		e.identities = append(e.identities, stat)
		parent = fd
	}
	file := e.files[len(e.files)-1]
	if err := darwinImage(ctx, file, want, max); err != nil {
		return nil, err
	}
	failed = false
	return e, nil
}

func darwinImage(ctx context.Context, file *os.File, want string, max int64) error {
	info, err := file.Stat()
	if err != nil || info.Size() < 1 || info.Size() > max {
		return errors.New("protected_image_size_invalid")
	}
	h := sha256.New()
	reader := io.NewSectionReader(file, 0, info.Size())
	buffer := make([]byte, 64*1024)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := reader.Read(buffer)
		if n > 0 {
			h.Write(buffer[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("protected_image_read_failed")
		}
	}
	if "sha256:"+hex.EncodeToString(h.Sum(nil)) != want {
		return errors.New("protected_image_digest_mismatch")
	}
	image, err := macho.NewFile(io.NewSectionReader(file, 0, info.Size()))
	if err != nil {
		return errors.New("protected_macho_invalid")
	}
	defer image.Close()
	if image.Type != macho.TypeExec || (goruntime.GOARCH == "arm64" && image.Cpu != macho.CpuArm64) || (goruntime.GOARCH == "amd64" && image.Cpu != macho.CpuAmd64) {
		return errors.New("protected_macho_architecture_invalid")
	}
	if err := validateDarwinEntrypoint(image, uint64(info.Size())); err != nil {
		return err
	}
	loader, library := false, false
	seenLibraries := map[string]bool{}
	for _, load := range image.Loads {
		raw := load.Raw()
		if len(raw) < 8 {
			return errors.New("protected_macho_load_invalid")
		}
		command := image.ByteOrder.Uint32(raw[:4])
		switch command {
		case 0xe, 0xc: // LC_LOAD_DYLINKER and LC_LOAD_DYLIB only.
			if len(raw) < 12 {
				return errors.New("protected_macho_load_invalid")
			}
			offset := image.ByteOrder.Uint32(raw[8:12])
			if offset < 12 || offset >= uint32(len(raw)) {
				return errors.New("protected_macho_load_invalid")
			}
			name := raw[offset:]
			end := -1
			for i, b := range name {
				if b == 0 {
					end = i
					break
				}
			}
			if end < 0 {
				return errors.New("protected_macho_load_invalid")
			}
			if command == 0xe && string(name[:end]) == "/usr/lib/dyld" && !loader {
				loader = true
			} else if command == 0xc && approvedDarwinSystemLibrary(string(name[:end])) && !seenLibraries[string(name[:end])] {
				seenLibraries[string(name[:end])] = true
				if string(name[:end]) == "/usr/lib/libSystem.B.dylib" {
					library = true
				}
			} else {
				return errors.New("protected_macho_dependency_denied")
			}
		case 0x5, 0x19, 0x2, 0xb, 0x1b, 0x1d, 0x1e, 0x26, 0x29, 0x2a, 0x32, 0x24, 0x25, 0x22, 0x80000022, 0x80000028, 0x80000033, 0x80000034:
			// Structural linker metadata, signatures and entrypoint only.
		default:
			return errors.New("protected_macho_load_denied")
		}
	}
	if !loader || !library {
		return errors.New("protected_macho_loader_missing")
	}
	return nil
}

// Actual pinned Go product binaries use these exact Apple system identities.
// The OS and privileged updater are trusted; child environments do not inherit
// dyld search or insertion settings. Relative names, rpaths, weak loads and
// additional libraries remain denied by the surrounding Mach-O admission.
func approvedDarwinSystemLibrary(name string) bool {
	switch name {
	case "/usr/lib/libSystem.B.dylib", "/usr/lib/libresolv.9.dylib",
		"/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
		"/System/Library/Frameworks/Security.framework/Versions/A/Security":
		return true
	}
	return false
}
