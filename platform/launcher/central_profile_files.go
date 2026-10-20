//go:build linux || darwin

package launcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/controlLogix/agentmux/platform/privatefs"
	"golang.org/x/sys/unix"
)

type centralProfileFile struct {
	path      string
	file      *os.File
	info      os.FileInfo
	digest    string
	directory bool
	uid       uint32
	mode      os.FileMode
}

func centralDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func centralDirectorySame(a, b os.FileInfo) bool {
	if a == nil || b == nil || !os.SameFile(a, b) || a.Mode() != b.Mode() {
		return false
	}
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && x.Uid == y.Uid && x.Gid == y.Gid
}

// Keep original ancestor descriptors, not just path strings. The private leaf
// and central store are checked again through the same no-symlink walk at use.
func (r *CentralProfileResolution) openDirectory(ctx context.Context, path string, private bool) (*centralProfileFile, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, centralProfileError("path_invalid")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if path == "/" {
		parts = nil
	}
	if len(parts) > 128 {
		return nil, centralProfileError("path_invalid")
	}
	parent := unix.AT_FDCWD
	var last *centralProfileFile
	current := "/"
	for i := -1; i < len(parts); i++ {
		if ctx.Err() != nil {
			return nil, centralProfileError("deadline")
		}
		name := "/"
		if i >= 0 {
			name = parts[i]
			current = filepath.Join(current, name)
		}
		fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, centralProfileError("directory_unavailable")
		}
		file := os.NewFile(uintptr(fd), "central-profile-directory")
		entry := &centralProfileFile{path: current, file: file, directory: true, uid: r.uid}
		r.files = append(r.files, entry)
		info, err := file.Stat()
		if err != nil || !info.IsDir() {
			return nil, centralProfileError("directory_invalid")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != 0 && stat.Uid != r.uid) || (info.Mode().Perm()&0022 != 0 && !(stat.Uid == 0 && info.Mode()&os.ModeSticky != 0)) {
			return nil, centralProfileError("directory_untrusted")
		}
		kind := privatefs.PublicAncestor
		if (private && i == len(parts)-1) || current == r.store {
			kind = privatefs.PrivateObject
			entry.mode = 0700
			if stat.Uid != r.uid || info.Mode().Perm() != 0700 {
				return nil, centralProfileError("directory_not_private")
			}
		}
		if privatefs.CheckDescriptor(file, kind) != nil {
			return nil, centralProfileError("directory_access_denied")
		}
		entry.info = info
		last = entry
		parent = fd
	}
	return last, nil
}
func (r *CentralProfileResolution) readFile(ctx context.Context, directory *centralProfileFile, name string, uid uint32, mode os.FileMode, limit int64) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || directory == nil || filepath.Base(name) != name || name == "." || name == ".." {
		return nil, centralProfileError("file_invalid")
	}
	fd, err := unix.Openat(int(directory.file.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, centralProfileError("file_unavailable")
	}
	file := os.NewFile(uintptr(fd), "central-profile-file")
	entry := &centralProfileFile{path: filepath.Join(directory.path, name), file: file, uid: uid, mode: mode}
	r.files = append(r.files, entry)
	info, err := file.Stat()
	if err != nil || !centralFileMode(info, uid, mode) || info.Size() < 0 || info.Size() > limit || privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil {
		return nil, centralProfileError("file_not_private")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	final, e1 := file.Stat()
	named, e2 := os.Lstat(entry.path)
	if err != nil || e1 != nil || e2 != nil || !hostReadMetadataEqual(info, final) || !hostReadMetadataEqual(info, named) || int64(len(raw)) != info.Size() || ctx.Err() != nil {
		return nil, centralProfileError("file_changed")
	}
	entry.info = info
	entry.digest = centralDigest(raw)
	if directory == r.directoryFile && name == centralProfileRegistrationName {
		r.registrationFile = entry
	}
	return raw, nil
}
func centralFileMode(info os.FileInfo, uid uint32, mode os.FileMode) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode {
		return false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uid && s.Nlink == 1
}
func (r *CentralProfileResolution) recheckFiles(ctx context.Context) error {
	for _, entry := range r.files {
		if ctx.Err() != nil {
			return centralProfileError("deadline")
		}
		current, err := entry.file.Stat()
		named, e1 := os.Lstat(entry.path)
		if err != nil || e1 != nil {
			return centralProfileError("changed")
		}
		if entry.directory {
			kind := privatefs.PublicAncestor
			if entry.mode == 0700 {
				kind = privatefs.PrivateObject
			}
			if !centralDirectorySame(entry.info, current) || !centralDirectorySame(entry.info, named) || privatefs.CheckDescriptor(entry.file, kind) != nil {
				return centralProfileError("changed")
			}
		} else {
			if !centralFileMode(current, entry.uid, entry.mode) || !hostReadMetadataEqual(entry.info, current) || !hostReadMetadataEqual(entry.info, named) || privatefs.CheckDescriptor(entry.file, privatefs.PrivateObject) != nil {
				return centralProfileError("changed")
			}
			raw, err := io.ReadAll(io.NewSectionReader(entry.file, 0, current.Size()+1))
			if err != nil || int64(len(raw)) != current.Size() || centralDigest(raw) != entry.digest {
				return centralProfileError("changed")
			}
			after, err := entry.file.Stat()
			namedAfter, namedErr := os.Lstat(entry.path)
			if err != nil || namedErr != nil || !hostReadMetadataEqual(current, namedAfter) || !hostReadMetadataEqual(current, after) {
				return centralProfileError("changed")
			}
		}
	}
	return nil
}

// Unlink only the name that still identifies the original held stage. Missing
// or replaced names leave recovery to the caller without deleting another file.
func unlinkCentralProfileStage(directory *os.File, name string, staged *os.File) error {
	if directory == nil || staged == nil {
		return centralProfileError("publication_uncertain")
	}
	var held, named unix.Stat_t
	if unix.Fstat(int(staged.Fd()), &held) != nil ||
		unix.Fstatat(int(directory.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		held.Dev != named.Dev || held.Ino != named.Ino || held.Mode != named.Mode ||
		held.Uid != named.Uid || held.Gid != named.Gid || held.Nlink != named.Nlink ||
		held.Size != named.Size || held.Mode&unix.S_IFMT != unix.S_IFREG {
		return centralProfileError("publication_uncertain")
	}
	if unix.Unlinkat(int(directory.Fd()), name, 0) != nil {
		return centralProfileError("publication_uncertain")
	}
	return nil
}
