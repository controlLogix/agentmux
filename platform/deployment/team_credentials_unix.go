//go:build linux || darwin

package deployment

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/controlLogix/agentmux/platform/privatefs"

	"golang.org/x/sys/unix"
)

func teamDescriptorAdmission(file *os.File, kind privatefs.AccessKind, failure string) error {
	if err := privatefs.CheckDescriptor(file, kind); err != nil {
		if errors.Is(err, privatefs.ErrPlatformUnqualified) {
			return teamError("private_platform_unqualified")
		}
		return teamError(failure)
	}
	return nil
}

func teamPrivateStat(stat *unix.Stat_t, uid uint32, directory bool) bool {
	mode := uint32(stat.Mode)
	kind := uint32(unix.S_IFREG)
	if directory {
		kind = unix.S_IFDIR
	}
	return stat.Uid == uid && mode&0077 == 0 && mode&unix.S_IFMT == kind && (directory || stat.Nlink == 1)
}

func teamReadPrivate(directory, member string, uid uint32) ([]byte, error) {
	return teamReadPrivateChecked(directory, member, uid, nil)
}

func teamTrustedAncestor(stat *unix.Stat_t, uid uint32) bool {
	mode := uint32(stat.Mode)
	return mode&unix.S_IFMT == unix.S_IFDIR && (stat.Uid == 0 || stat.Uid == uid) &&
		(mode&0022 == 0 || (stat.Uid == 0 && mode&unix.S_ISVTX != 0))
}

func teamCredentialStatUnchanged(a, b *unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Size == b.Size && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

// The optional callback is an internal regression seam. Normal credential reads
// always pass nil; no public policy or resolver can inject file operations.
func teamReadPrivateChecked(directory, member string, uid uint32, beforeRead func()) ([]byte, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || !filepath.IsLocal(member) || filepath.Base(member) != member {
		return nil, teamError("private_directory_invalid")
	}
	parts := strings.Split(strings.TrimPrefix(directory, "/"), "/")
	// The root descriptor counts toward the same 128-directory bound used by
	// the protocol's private credential/trust reader.
	if len(parts)+1 > 128 {
		return nil, teamError("private_directory_invalid")
	}
	for _, part := range parts {
		if part == "" {
			return nil, teamError("private_directory_invalid")
		}
	}
	var held []*os.File
	defer func() {
		for _, file := range held {
			file.Close()
		}
	}()
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, teamError("private_directory_invalid")
	}
	ancestorFile := os.NewFile(uintptr(fd), "private-team-ancestor")
	held = append(held, ancestorFile)
	var base unix.Stat_t
	if unix.Fstat(fd, &base) != nil || !teamTrustedAncestor(&base, uid) {
		return nil, teamError("private_directory_invalid")
	}
	if err := teamDescriptorAdmission(ancestorFile, privatefs.PublicAncestor, "private_directory_invalid"); err != nil {
		return nil, err
	}
	for _, part := range parts {
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return nil, teamError("private_directory_invalid")
		}
		fd = next
		ancestorFile = os.NewFile(uintptr(fd), "private-team-ancestor")
		held = append(held, ancestorFile)
		var ancestor unix.Stat_t
		if unix.Fstat(fd, &ancestor) != nil || !teamTrustedAncestor(&ancestor, uid) {
			return nil, teamError("private_directory_invalid")
		}
		if err := teamDescriptorAdmission(ancestorFile, privatefs.PublicAncestor, "private_directory_invalid"); err != nil {
			return nil, err
		}
	}
	var rootStat unix.Stat_t
	if unix.Fstat(fd, &rootStat) != nil || !teamPrivateStat(&rootStat, uid, true) {
		return nil, teamError("private_directory_invalid")
	}
	if err := teamDescriptorAdmission(ancestorFile, privatefs.PrivateObject, "private_directory_invalid"); err != nil {
		return nil, err
	}
	var before unix.Stat_t
	if unix.Fstatat(fd, member, &before, unix.AT_SYMLINK_NOFOLLOW) != nil || !teamPrivateStat(&before, uid, false) || before.Size <= 0 || before.Size > 64*1024 {
		return nil, teamError("private_file_invalid")
	}
	memberFD, err := unix.Openat(fd, member, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, teamError("private_file_invalid")
	}
	file := os.NewFile(uintptr(memberFD), "private-team-credential")
	defer file.Close()
	var opened unix.Stat_t
	if unix.Fstat(memberFD, &opened) != nil || !teamPrivateStat(&opened, uid, false) || !teamCredentialStatUnchanged(&before, &opened) {
		return nil, teamError("private_file_changed")
	}
	if err := teamDescriptorAdmission(file, privatefs.PrivateObject, "private_file_invalid"); err != nil {
		return nil, err
	}
	if beforeRead != nil {
		beforeRead()
	}
	raw, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	var after, final unix.Stat_t
	if err != nil || len(raw) > 64*1024 || unix.Fstatat(fd, member, &after, unix.AT_SYMLINK_NOFOLLOW) != nil || unix.Fstat(memberFD, &final) != nil || !teamPrivateStat(&after, uid, false) || !teamPrivateStat(&final, uid, false) || !teamCredentialStatUnchanged(&before, &after) || !teamCredentialStatUnchanged(&before, &final) || int64(len(raw)) != before.Size {
		return nil, teamError("private_file_changed")
	}
	if err := teamDescriptorAdmission(file, privatefs.PrivateObject, "private_file_invalid"); err != nil {
		return nil, err
	}
	// A retained directory handle must still be the selected canonical path.
	var current unix.Stat_t
	resolved, resolveErr := filepath.EvalSymlinks(directory)
	if resolveErr != nil || resolved != directory || unix.Lstat(directory, &current) != nil || !teamPrivateStat(&current, uid, true) || current.Dev != rootStat.Dev || current.Ino != rootStat.Ino {
		return nil, teamError("private_directory_changed")
	}
	for _, ancestor := range held {
		var stat unix.Stat_t
		if unix.Fstat(int(ancestor.Fd()), &stat) != nil || !teamTrustedAncestor(&stat, uid) {
			return nil, teamError("private_directory_invalid")
		}
		if err := teamDescriptorAdmission(ancestor, privatefs.PublicAncestor, "private_directory_invalid"); err != nil {
			return nil, err
		}
	}
	if err := teamDescriptorAdmission(ancestorFile, privatefs.PrivateObject, "private_directory_invalid"); err != nil {
		return nil, err
	}
	return raw, nil
}
