//go:build linux

package runtime

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"

	"golang.org/x/sys/unix"
)

type sealedExecutable struct{ file *os.File }

func (e *sealedExecutable) command(args []string) *exec.Cmd {
	cmd := exec.Command("/proc/self/fd/3", args...)
	cmd.ExtraFiles = []*os.File{e.file}
	return cmd
}
func (e *sealedExecutable) close() error { return e.file.Close() }

func prepareExecutable(ctx context.Context, root *os.Root, entry, want string, max int64) (executable, error) {
	if !filepath.IsLocal(entry) {
		return nil, errors.New("member path is not contained")
	}
	parts := strings.Split(entry, string(filepath.Separator))
	for i := range parts {
		info, err := root.Lstat(filepath.Join(parts[:i+1]...))
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("member path changed or contains a symlink")
		}
	}
	source, err := root.OpenFile(entry, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("member source is unavailable")
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > max {
		return nil, errors.New("member source is not a bounded regular file")
	}
	fd, err := unix.MemfdCreate("agentmux-protected", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING|unix.MFD_EXEC)
	if err != nil {
		return nil, errors.New("executable memfd is unavailable; no path fallback is permitted")
	}
	staged := os.NewFile(uintptr(fd), "protected-snapshot")
	defer staged.Close()
	h := sha256.New()
	buffer := make([]byte, 64*1024)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, readErr := source.Read(buffer)
		total += int64(n)
		if total > max {
			return nil, errors.New("member source grew beyond its size limit")
		}
		if n > 0 {
			if _, err := staged.Write(buffer[:n]); err != nil {
				return nil, errors.New("snapshot copy failed")
			}
			h.Write(buffer[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, errors.New("member source could not be read")
		}
	}
	if "sha256:"+hex.EncodeToString(h.Sum(nil)) != want {
		return nil, errors.New("source bytes differ from the trusted binary digest")
	}
	return sealAndVerify(ctx, staged, want, max)
}

// Seal before inspecting the staged bytes: hashing source buffers cannot prove
// what another same-UID writer may have changed in the memfd before sealing.
func sealAndVerify(ctx context.Context, staged *os.File, want string, max int64) (executable, error) {
	fd := int(staged.Fd())
	if err := unix.Fchmod(fd, 0500); err != nil {
		return nil, errors.New("snapshot executable mode could not be set")
	}
	seals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL | unix.F_SEAL_EXEC
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, seals); err != nil {
		return nil, errors.New("snapshot sealing failed")
	}
	actual, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	if err != nil || actual&seals != seals {
		return nil, errors.New("required snapshot seals are absent")
	}
	info, err := staged.Stat()
	if err != nil || info.Size() > max {
		return nil, errors.New("immutable snapshot exceeds its size limit")
	}
	if _, err := staged.Seek(0, 0); err != nil {
		return nil, errors.New("immutable snapshot cannot be read")
	}
	h := sha256.New()
	buffer := make([]byte, 64*1024)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, readErr := staged.Read(buffer)
		if n > 0 {
			h.Write(buffer[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, errors.New("immutable snapshot cannot be read")
		}
	}
	if "sha256:"+hex.EncodeToString(h.Sum(nil)) != want {
		return nil, errors.New("immutable snapshot digest differs from the trusted binary digest")
	}
	image, err := elf.NewFile(staged)
	if err != nil {
		return nil, errors.New("protected executable must be static ELF, not a script")
	}
	if image.Type != elf.ET_EXEC && image.Type != elf.ET_DYN {
		return nil, errors.New("ELF executable type is incompatible")
	}
	if (goruntime.GOARCH != "amd64" && goruntime.GOARCH != "arm64") || (goruntime.GOARCH == "amd64" && image.Machine != elf.EM_X86_64) || (goruntime.GOARCH == "arm64" && image.Machine != elf.EM_AARCH64) {
		return nil, errors.New("ELF executable architecture is incompatible")
	}
	for _, program := range image.Progs {
		if program.Type == elf.PT_INTERP {
			return nil, errors.New("protected ELF interpreter dependencies are not qualified")
		}
	}
	needed, err := image.DynString(elf.DT_NEEDED)
	if err != nil || len(needed) != 0 {
		return nil, errors.New("protected ELF shared-library dependencies are not qualified")
	}
	readFD, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", fd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("sealed read-only descriptor could not be opened")
	}
	return &sealedExecutable{file: os.NewFile(uintptr(readFD), "sealed-protected-snapshot")}, nil
}
