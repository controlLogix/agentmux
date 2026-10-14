//go:build linux || darwin

package protocol

import (
	"errors"
	"github.com/controlLogix/agentmux/platform/privatefs"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func trustedServerDirectory(info os.FileInfo, private bool) bool {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	uid := uint32(os.Geteuid())
	if !ok || (stat.Uid != uid && stat.Uid != 0) {
		return false
	}
	if private {
		return stat.Uid == uid && info.Mode().Perm()&0077 == 0
	}
	return info.Mode().Perm()&0022 == 0 || (stat.Uid == 0 && info.Mode()&os.ModeSticky != 0)
}

func privateServerTrustFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0177 != 0 || info.Size() < 1 || info.Size() > MaxPayload {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
}

func sameServerTrustFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime() == b.ModTime() && serverTrustChangeTime(a) == serverTrustChangeTime(b)
}

// Open every path component without following links. The selected parent must
// be private; its ancestors must not let another OS user replace that parent.
func readServerTrustFile(path string) ([]byte, error) {
	return readPrivateDescriptorFile(path, "kernel_server_trust")
}

func readPrivateDescriptorFile(path, prefix string) ([]byte, error) {
	invalid := errors.New(prefix + "_file_invalid")
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || strings.IndexFunc(path, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return nil, errors.New(prefix + "_reference_invalid")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) < 2 || len(parts) > 128 {
		return nil, invalid
	}
	var handles []*os.File
	defer func() {
		for _, file := range handles {
			file.Close()
		}
	}()
	parent := unix.AT_FDCWD
	for i := -1; i < len(parts)-1; i++ {
		name := "/"
		if i >= 0 {
			name = parts[i]
		}
		fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, invalid
		}
		file := os.NewFile(uintptr(fd), "private-server-trust-parent")
		handles = append(handles, file)
		info, err := file.Stat()
		if err != nil || !trustedServerDirectory(info, i == len(parts)-2) {
			return nil, errors.New(prefix + "_parent_invalid")
		}
		kind := privatefs.PublicAncestor
		if i == len(parts)-2 {
			kind = privatefs.PrivateObject
		}
		if err := privatefs.CheckDescriptor(file, kind); err != nil {
			if errors.Is(err, privatefs.ErrPlatformUnqualified) {
				return nil, errors.New(prefix + "_platform_unqualified")
			}
			return nil, errors.New(prefix + "_parent_invalid")
		}
		parent = fd
	}
	name := parts[len(parts)-1]
	var before unix.Stat_t
	if unix.Fstatat(parent, name, &before, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return nil, invalid
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, invalid
	}
	file := os.NewFile(uintptr(fd), "private-server-trust")
	handles = append(handles, file)
	opened, err := file.Stat()
	var actual unix.Stat_t
	if err != nil || !privateServerTrustFile(opened) || unix.Fstat(fd, &actual) != nil || actual.Dev != before.Dev || actual.Ino != before.Ino {
		return nil, invalid
	}
	if privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil {
		return nil, invalid
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxPayload+1))
	final, statErr := file.Stat()
	var named unix.Stat_t
	if err != nil || statErr != nil || len(data) > MaxPayload || int64(len(data)) != opened.Size() || !privateServerTrustFile(final) || !sameServerTrustFile(opened, final) || unix.Fstatat(parent, name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || named.Dev != actual.Dev || named.Ino != actual.Ino || named.Mode != actual.Mode || named.Uid != actual.Uid || named.Nlink != 1 {
		return nil, invalid
	}
	if privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil {
		return nil, invalid
	}
	return data, nil
}
