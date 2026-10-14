//go:build linux

package runtime

import (
	"context"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"syscall"
)

// PrepareInstalledHost copies a held private installed file, then reuses the
// protected runtime's seal-and-verify implementation. No executable path is
// reopened for launch, and no dynamic interpreter or library fallback exists.
func PrepareInstalledHost(ctx context.Context, source *os.File, expectedSHA256 string, maxBytes int64) (*InstalledHostImage, error) {
	if ctx == nil || source == nil || !installedHostDigest.MatchString(expectedSHA256) || maxBytes < 1 || maxBytes > 128*1024*1024 {
		return nil, hostExecutionError("preparation_invalid")
	}
	if ctx.Err() != nil {
		return nil, hostExecutionError("preparation_cancelled")
	}
	info, err := source.Stat()
	if err != nil {
		return nil, hostExecutionError("source_unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || info.Mode().Perm()&0077 != 0 || info.Mode().Perm()&0100 == 0 || info.Size() < 1 || info.Size() > maxBytes {
		return nil, hostExecutionError("source_not_private_installed_executable")
	}
	fd, err := unix.MemfdCreate("agentmux-installed-host", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING|unix.MFD_EXEC)
	if err != nil {
		return nil, hostExecutionError("snapshot_unavailable")
	}
	staged := os.NewFile(uintptr(fd), "installed-host-snapshot")
	defer staged.Close()
	reader := io.NewSectionReader(source, 0, info.Size())
	buffer := make([]byte, 64*1024)
	for {
		if ctx.Err() != nil {
			return nil, hostExecutionError("preparation_cancelled")
		}
		n, e := reader.Read(buffer)
		if n > 0 {
			if _, err = staged.Write(buffer[:n]); err != nil {
				return nil, hostExecutionError("snapshot_copy_failed")
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, hostExecutionError("source_read_failed")
		}
	}
	image, err := sealAndVerify(ctx, staged, expectedSHA256, maxBytes)
	if err != nil {
		return nil, hostExecutionError("snapshot_verification_failed")
	}
	return &InstalledHostImage{image: image, digest: expectedSHA256}, nil
}

// Linux uses the sealed held-file API. A pathname cannot substitute for it.
func PrepareProtectedInstalledHost(context.Context, string, string, int64) (*InstalledHostImage, error) {
	return nil, ErrPlatformUnqualified
}
