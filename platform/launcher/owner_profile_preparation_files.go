//go:build linux || darwin

package launcher

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/controlLogix/agentmux/platform/privatefs"
	"golang.org/x/sys/unix"
)

type ownerProfilePreparationDirectory struct{ entry *centralProfileFile }
type ownerProfilePreparationStage struct {
	name, destination string
	file              *os.File
	published         bool
}

func openOwnerProfileChild(parent int, name string) (int, error) {
	return unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
}

func ownerProfileOutsideRoots(path string, roots []string) bool {
	for _, root := range roots {
		rel, err := filepath.Rel(root, path)
		if err != nil || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return false
		}
	}
	return true
}

func (r *OwnerProfilePreparation) createDirectory(ctx context.Context) (*ownerProfilePreparationDirectory, error) {
	parent, err := r.files.openDirectory(ctx, r.account.home, false)
	if err != nil {
		return nil, err
	}
	for i, name := range []string{"Library", "Application Support", "Agentmux", "profiles", r.request.Owner.ProfileID} {
		if err := r.recheckPublication(ctx); err != nil {
			return nil, err
		}
		fd := int(parent.file.Fd())
		var named unix.Stat_t
		statErr := unix.Fstatat(fd, name, &named, unix.AT_SYMLINK_NOFOLLOW)
		created := false
		if statErr == unix.ENOENT {
			// The original parent is already retained before mutation. Even a
			// failed mkdir can require inspection; never delete by a new lookup.
			r.mutated = true
			if unix.Mkdirat(fd, name, 0700) != nil {
				return nil, centralProfileError("directory_creation_uncertain")
			}
			created = true
			if unix.Fstatat(fd, name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil {
				return nil, centralProfileError("directory_creation_uncertain")
			}
		} else if statErr != nil || i == 4 {
			return nil, centralProfileError("profile_already_exists")
		}
		childFD, err := r.deps.openDirectory(fd, name)
		if err != nil {
			return nil, centralProfileError("directory_unavailable")
		}
		child := &centralProfileFile{path: filepath.Join(parent.path, name), file: os.NewFile(uintptr(childFD), "owner-profile-directory"), directory: true, uid: r.account.uid}
		r.files.files = append(r.files.files, child)
		info, err := child.file.Stat()
		if err != nil || !info.IsDir() {
			return nil, centralProfileError("directory_invalid")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		kind := privatefs.PublicAncestor
		if i >= 2 || created {
			child.mode = 0700
			kind = privatefs.PrivateObject
			if !ok || stat.Uid != r.account.uid || info.Mode().Perm() != 0700 {
				return nil, centralProfileError("directory_not_private")
			}
		} else if !ok || (stat.Uid != 0 && stat.Uid != r.account.uid) || info.Mode().Perm()&0022 != 0 {
			return nil, centralProfileError("directory_untrusted")
		}
		if privatefs.CheckDescriptor(child.file, kind) != nil {
			return nil, centralProfileError("directory_access_denied")
		}
		child.info = info
		if uint64(named.Dev) != uint64(stat.Dev) || named.Ino != stat.Ino {
			return nil, centralProfileError("directory_changed")
		}
		if created && r.deps.syncDirectory(&ownerProfilePreparationDirectory{parent}) != nil {
			return nil, centralProfileError("directory_creation_uncertain")
		}
		if err := r.recheckPublication(ctx); err != nil {
			return nil, err
		}
		parent = child
		if i == 3 {
			// The lock remains on the retained store descriptor until Close.
			if unix.Flock(int(parent.file.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
				return nil, centralProfileError("preparation_busy")
			}
		}
	}
	r.files.directoryFile = parent
	return &ownerProfilePreparationDirectory{parent}, nil
}

func (r *OwnerProfilePreparation) publish(ctx context.Context, directory *ownerProfilePreparationDirectory, name string, raw []byte) error {
	if err := r.recheckPublication(ctx); err != nil {
		return err
	}
	if filepath.Base(name) != name || name == "." || name == ".." || len(raw) == 0 {
		return centralProfileError("file_invalid")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return centralProfileError("publication_failed")
	}
	stageName := ".prepare-" + hex.EncodeToString(nonce[:])
	fd := int(directory.entry.file.Fd())
	r.mutated = true
	stageFD, err := unix.Openat(fd, stageName, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return centralProfileError("publication_failed")
	}
	staged := os.NewFile(uintptr(stageFD), "owner-profile-stage")
	r.files.stages = append(r.files.stages, staged)
	r.stages = append(r.stages, ownerProfilePreparationStage{stageName, name, staged, false})
	stage := &r.stages[len(r.stages)-1]
	info, err := staged.Stat()
	if err != nil || !centralFileMode(info, r.account.uid, 0600) || privatefs.CheckDescriptor(staged, privatefs.PrivateObject) != nil {
		return centralProfileError("stage_not_private")
	}
	if n, err := staged.Write(raw); err != nil || n != len(raw) {
		return centralProfileError("publication_failed")
	}
	if staged.Sync() != nil {
		return centralProfileError("publication_failed")
	}
	if err := r.recheckPublication(ctx); err != nil {
		return err
	}
	var named unix.Stat_t
	info, err = staged.Stat()
	stat, ok := infoSys(info)
	if err != nil || !ok || !centralFileMode(info, r.account.uid, 0600) || unix.Fstatat(fd, stageName, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || uint64(named.Dev) != uint64(stat.Dev) || named.Ino != stat.Ino || privatefs.CheckDescriptor(staged, privatefs.PrivateObject) != nil {
		return centralProfileError("stage_changed")
	}
	readback, err := io.ReadAll(io.NewSectionReader(staged, 0, int64(len(raw))+1))
	if err != nil || centralDigest(readback) != centralDigest(raw) {
		return centralProfileError("stage_changed")
	}
	if unix.Linkat(fd, stageName, fd, name, 0) != nil {
		return centralProfileError("file_already_exists")
	}
	stage.published = true
	if unlinkCentralProfileStage(directory.entry.file, stageName, staged) != nil {
		return centralProfileError("publication_uncertain")
	}
	if r.deps.syncDirectory(directory) != nil {
		return centralProfileError("publication_uncertain")
	}
	actual, err := r.files.readFile(ctx, directory.entry, name, r.account.uid, 0600, int64(len(raw)))
	if err != nil || centralDigest(actual) != centralDigest(raw) {
		return centralProfileError("publication_uncertain")
	}
	final := r.files.files[len(r.files.files)-1]
	held, err := staged.Stat()
	if err != nil || !os.SameFile(held, final.info) {
		return centralProfileError("publication_uncertain")
	}
	return r.recheckPublication(ctx)
}

func infoSys(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}
