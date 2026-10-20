package plugins

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/controlLogix/agentmux/platform/privatefs"
	"golang.org/x/sys/unix"
)

func ownerStatEqual(a, b *unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Size == b.Size && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func trustedOwnerAncestor(s *unix.Stat_t) bool {
	return s.Mode&unix.S_IFMT == unix.S_IFDIR && (s.Uid == 0 || int(s.Uid) == os.Geteuid()) && (s.Mode&0022 == 0 || (s.Uid == 0 && s.Mode&unix.S_ISVTX != 0))
}
func privateOwnerStat(s *unix.Stat_t, directory bool) bool {
	kind, mode := uint32(unix.S_IFREG), uint32(0600)
	if directory {
		kind = unix.S_IFDIR
		mode = 0700
	}
	return uint32(s.Mode)&unix.S_IFMT == kind && uint32(s.Mode)&07777 == mode && int(s.Uid) == os.Geteuid() && (directory || s.Nlink == 1)
}
func closeOwnerChain(held []*os.File, operation error) error {
	for i := len(held) - 1; i >= 0; i-- {
		operation = closeAdmission(held[i], operation)
	}
	return operation
}

// holdOwnerDirectory opens every ancestor relative to the preceding held handle.
// Public ancestors permit root-owned sticky temporary directories, never writable
// user-owned ancestors; the final directory must be owner-only 0700.
func holdOwnerDirectory(path string) (held []*os.File, failure error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !metadataText(path) || path == "/" {
		return nil, pluginError("lifecycle_private_directory_invalid")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) > 128 {
		return nil, pluginError("lifecycle_private_directory_invalid")
	}
	defer func() {
		if failure != nil {
			failure = closeOwnerChain(held, failure)
			held = nil
		}
	}()
	parent := unix.AT_FDCWD
	for index := -1; index < len(parts); index++ {
		name := "/"
		if index >= 0 {
			name = parts[index]
		}
		fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return held, pluginError("lifecycle_private_directory_invalid")
		}
		file := os.NewFile(uintptr(fd), "ordinary-private-ancestor")
		held = append(held, file)
		var s unix.Stat_t
		if unix.Fstat(fd, &s) != nil || !trustedOwnerAncestor(&s) {
			return held, pluginError("lifecycle_private_directory_invalid")
		}
		kind := privatefs.PublicAncestor
		if index == len(parts)-1 {
			kind = privatefs.PrivateObject
			if !privateOwnerStat(&s, true) {
				return held, pluginError("lifecycle_private_directory_invalid")
			}
		}
		if privatefs.CheckDescriptor(file, kind) != nil {
			return held, pluginError("lifecycle_private_access_denied")
		}
		parent = fd
	}
	return held, nil
}
func recheckOwnerChain(held []*os.File) error {
	for i, file := range held {
		var s unix.Stat_t
		if unix.Fstat(int(file.Fd()), &s) != nil || !trustedOwnerAncestor(&s) {
			return pluginError("lifecycle_private_directory_changed")
		}
		kind := privatefs.PublicAncestor
		if i == len(held)-1 {
			kind = privatefs.PrivateObject
			if !privateOwnerStat(&s, true) {
				return pluginError("lifecycle_private_directory_changed")
			}
		}
		if privatefs.CheckDescriptor(file, kind) != nil {
			return pluginError("lifecycle_private_access_denied")
		}
	}
	return nil
}

// ReadOwnerPrivateFile reads a bounded owner-only file without following any
// symlink. It validates actual held ACL/mount policy; mode bits alone do not
// establish credential privacy. Returned bytes are an explicit private disclosure.
func ReadOwnerPrivateFile(path string, limit int64) (raw []byte, failure error) {
	if limit < 1 || limit > manifestLimit || !filepath.IsAbs(path) || filepath.Clean(path) != path || !metadataText(path) {
		return nil, pluginError("lifecycle_private_file_invalid")
	}
	held, err := holdOwnerDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := closeOwnerChain(held, failure); err != failure {
			raw = nil
			failure = err
		}
	}()
	parent := held[len(held)-1]
	fd := int(parent.Fd())
	member := filepath.Base(path)
	var before unix.Stat_t
	if unix.Fstatat(fd, member, &before, unix.AT_SYMLINK_NOFOLLOW) != nil || !privateOwnerStat(&before, false) || before.Size < 0 || before.Size > limit {
		return nil, pluginError("lifecycle_private_file_invalid")
	}
	child, err := unix.Openat(fd, member, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, pluginError("lifecycle_private_file_invalid")
	}
	file := os.NewFile(uintptr(child), "ordinary-private-file")
	held = append(held, file)
	var opened unix.Stat_t
	if unix.Fstat(child, &opened) != nil || !ownerStatEqual(&before, &opened) || privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil {
		return nil, pluginError("lifecycle_private_file_invalid")
	}
	raw, err = io.ReadAll(io.LimitReader(file, limit+1))
	var after, slot unix.Stat_t
	if err != nil || int64(len(raw)) > limit || int64(len(raw)) != before.Size || unix.Fstat(child, &after) != nil || unix.Fstatat(fd, member, &slot, unix.AT_SYMLINK_NOFOLLOW) != nil || !ownerStatEqual(&before, &after) || !ownerStatEqual(&before, &slot) || privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil {
		return nil, pluginError("lifecycle_private_file_changed")
	}
	var parentHeld, parentSlot unix.Stat_t
	canonical, canonicalErr := filepath.EvalSymlinks(filepath.Dir(path))
	if canonicalErr != nil || canonical != filepath.Dir(path) || unix.Fstat(fd, &parentHeld) != nil || unix.Lstat(filepath.Dir(path), &parentSlot) != nil || parentHeld.Dev != parentSlot.Dev || parentHeld.Ino != parentSlot.Ino {
		return nil, pluginError("lifecycle_private_directory_changed")
	}
	if err := recheckOwnerChain(held[:len(held)-1]); err != nil {
		return nil, err
	}
	return raw, nil
}

func openLifecycleStateRoot(path string) (root *os.Root, failure error) {
	held, err := holdOwnerDirectory(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := closeOwnerChain(held, failure); err != failure {
			failure = err
			if root != nil {
				failure = closeAdmission(root, failure)
				root = nil
			}
		}
	}()
	last := held[len(held)-1]
	before, err := last.Stat()
	if err != nil {
		return nil, pluginError("lifecycle_private_directory_invalid")
	}
	root, err = os.OpenRoot(path)
	if err != nil {
		return nil, pluginError("lifecycle_private_directory_invalid")
	}
	actual, err := root.Stat(".")
	if err != nil || !os.SameFile(before, actual) || recheckOwnerChain(held) != nil {
		failure = closeAdmission(root, pluginError("lifecycle_private_directory_changed"))
		root = nil
		return root, failure
	}
	return root, nil
}
