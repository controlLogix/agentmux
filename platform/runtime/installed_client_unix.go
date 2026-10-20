//go:build linux || darwin

package runtime

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"strings"
	"syscall"

	"github.com/controlLogix/agentmux/platform/privatefs"
	"golang.org/x/sys/unix"
)

type clientTreeAdmission struct {
	path            string
	manifest        ClientManifest
	id              string
	parents         []*os.File
	identities      []unix.Stat_t
	entries         map[string]unix.Stat_t
	owner           uint32
	check           func(*os.File, privatefs.AccessKind) error
	native          func(string, []byte, map[string]ClientFile) error
	closeFailure    error
	uncertainCloses []*os.File
}

func PrepareInstalledClient(parent context.Context, id string) (*InstalledClientAdmission, error) {
	if parent == nil || !ValidClientInstallationID(id) {
		return nil, &clientFailure{code: "selection_invalid"}
	}
	if goruntime.GOOS != "darwin" || goruntime.GOARCH != "arm64" {
		return nil, ErrPlatformUnqualified
	}
	if os.Geteuid() == 0 {
		return nil, &clientFailure{code: "ordinary_user_required"}
	}
	ctx, cancel := clientAdmissionContext(parent)
	defer cancel()
	tree, err := admitClientTree(ctx, filepath.Join(InstalledClientBase, id), id, 0, privatefs.CheckDescriptor, nil)
	if err != nil {
		return nil, err
	}
	frontend, err := PrepareProtectedInstalledFrontend(ctx, StableFrontendPath, tree.manifest.FrontendDigest, 128*1024*1024)
	if err != nil {
		cleanup := tree.close()
		return nil, &clientFailure{code: "frontend_rejected", cause: errors.Join(err, cleanup), owner: tree}
	}
	return &InstalledClientAdmission{id: id, manifest: tree.manifest, backend: tree, frontend: frontend}, nil
}

func clientStat(file *os.File, owner uint32, mode uint32, directory bool, check func(*os.File, privatefs.AccessKind) error) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil || stat.Uid != owner || uint32(stat.Mode&07777) != mode {
		return stat, &clientFailure{code: "permission_invalid"}
	}
	kind := privatefs.PrivateObject
	if directory {
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			return stat, &clientFailure{code: "directory_invalid"}
		}
		kind = privatefs.PublicAncestor
	} else if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		return stat, &clientFailure{code: "file_invalid"}
	}
	if err := check(file, kind); err != nil {
		return stat, &clientFailure{code: "native_permission_invalid", cause: err}
	}
	// Reading may change atime. Content, permissions and inode identity remain
	// part of the admission comparison.
	stat.Atim = unix.Timespec{}
	return stat, nil
}

func (a *clientTreeAdmission) close() error {
	for _, file := range a.parents {
		if err := file.Close(); err != nil {
			a.closeFailure = errors.Join(a.closeFailure, err)
			a.uncertainCloses = append(a.uncertainCloses, file)
		}
	}
	a.parents = nil
	return a.closeFailure
}

func admitClientTree(ctx context.Context, path, id string, owner uint32, check func(*os.File, privatefs.AccessKind) error, native func(string, []byte, map[string]ClientFile) error) (admitted *clientTreeAdmission, failure error) {
	a := &clientTreeAdmission{path: path, id: id, owner: owner, check: check, native: native}
	defer func() {
		if admitted == nil {
			if cleanup := a.close(); cleanup != nil {
				failure = &clientFailure{code: "cleanup_failed", cause: errors.Join(failure, cleanup), owner: a}
			}
		}
	}()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(parts) > 64 {
		return nil, &clientFailure{code: "path_invalid"}
	}
	parent := unix.AT_FDCWD
	for index := -1; index < len(parts); index++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		name := "/"
		if index >= 0 {
			name = parts[index]
		}
		fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, &clientFailure{code: "path_unavailable"}
		}
		file := os.NewFile(uintptr(fd), "installed-client-parent")
		a.parents = append(a.parents, file)
		// Test callers retain real system ancestors and a private user subtree.
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil {
			return nil, &clientFailure{code: "path_unavailable"}
		}
		if owner != 0 && stat.Uid == 0 {
			if stat.Mode&0022 != 0 && stat.Mode&unix.S_ISVTX == 0 {
				return nil, &clientFailure{code: "permission_invalid"}
			}
			if err := check(file, privatefs.PublicAncestor); err != nil {
				return nil, err
			}
		} else {
			mode := uint32(0755)
			if owner != 0 {
				mode = uint32(stat.Mode & 0777)
				if mode&0022 != 0 {
					return nil, &clientFailure{code: "permission_invalid"}
				}
			}
			stat, err = clientStat(file, owner, mode, true, check)
			if err != nil {
				return nil, err
			}
		}
		a.identities = append(a.identities, stat)
		parent = fd
	}
	root := a.parents[len(a.parents)-1]
	raw, err := a.readFile(ctx, root, "client-manifest.json", 0444, -1, ClientManifestLimit)
	if err != nil || ClientDigest(raw) != "sha256:"+id {
		return nil, &clientFailure{code: "manifest_rejected", cause: err}
	}
	a.manifest, err = DecodeClientManifest(raw)
	if err != nil {
		return nil, err
	}
	a.entries, err = a.scan(ctx, root, raw)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (a *clientTreeAdmission) readFile(ctx context.Context, parent *os.File, name string, mode uint32, size, limit int64) (raw []byte, failure error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &clientFailure{code: "file_unavailable"}
	}
	file := os.NewFile(uintptr(fd), "installed-client-file")
	defer func() {
		if err := file.Close(); err != nil {
			failure = &clientFailure{code: "cleanup_failed", cause: errors.Join(failure, err), owner: file}
		}
	}()
	before, err := clientStat(file, a.owner, mode, false, a.check)
	if err != nil || before.Size < 0 || before.Size > limit || (size >= 0 && before.Size != size) {
		return nil, &clientFailure{code: "file_rejected", cause: err}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	raw, err = io.ReadAll(io.NewSectionReader(file, 0, before.Size+1))
	after, afterErr := clientStat(file, a.owner, mode, false, a.check)
	if err != nil || afterErr != nil || !reflect.DeepEqual(before, after) || int64(len(raw)) != before.Size {
		return nil, &clientFailure{code: "file_changed"}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return raw, nil
}

func (a *clientTreeAdmission) scan(ctx context.Context, root *os.File, manifest []byte) (map[string]unix.Stat_t, error) {
	roster := map[string]ClientFile{}
	dirs := map[string]bool{}
	for _, file := range a.manifest.Files {
		roster[file.Path] = file
		for dir := filepath.Dir(file.Path); dir != "."; dir = filepath.Dir(dir) {
			dirs[dir] = true
		}
	}
	if len(dirs) > 1024 {
		return nil, &clientFailure{code: "tree_bound"}
	}
	wanted := make(map[string]ClientFile, len(roster)+1)
	for name, file := range roster {
		wanted[name] = file
	}
	wanted["client-manifest.json"] = ClientFile{Path: "client-manifest.json", Digest: ClientDigest(manifest), Size: int64(len(manifest)), Mode: 0444}
	entries := map[string]unix.Stat_t{}
	nativeFiles := map[string][]byte{}
	var walk func(*os.File, string) error
	walk = func(directory *os.File, prefix string) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, err := directory.Seek(0, 0); err != nil {
			return &clientFailure{code: "directory_unavailable"}
		}
		children, err := directory.ReadDir(ClientMaxFiles + 1025)
		if (err != nil && err != io.EOF) || len(children) > ClientMaxFiles+1024 {
			return &clientFailure{code: "tree_bound"}
		}
		for _, child := range children {
			name := filepath.Join(prefix, child.Name())
			if child.Type()&os.ModeSymlink != 0 {
				return &clientFailure{code: "link_rejected"}
			}
			if dirs[name] {
				fd, err := unix.Openat(int(directory.Fd()), child.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
				if err != nil {
					return &clientFailure{code: "directory_unavailable"}
				}
				file := os.NewFile(uintptr(fd), "installed-client-directory")
				stat, failure := clientStat(file, a.owner, 0755, true, a.check)
				if failure == nil {
					failure = walk(file, name)
				}
				if closeErr := file.Close(); closeErr != nil {
					failure = &clientFailure{code: "cleanup_failed", cause: errors.Join(failure, closeErr), owner: file}
				}
				if failure != nil {
					return failure
				}
				stat.Atim = unix.Timespec{}
				entries[name] = stat
				delete(dirs, name)
			} else {
				expected, ok := wanted[name]
				if !ok {
					return &clientFailure{code: "unexpected_file"}
				}
				raw, err := a.readFile(ctx, directory, child.Name(), expected.Mode, expected.Size, ClientFileLimit)
				if err != nil || ClientDigest(raw) != expected.Digest {
					return &clientFailure{code: "file_rejected", cause: err}
				}
				if name != "client-manifest.json" {
					if a.native != nil {
						if err := a.native(name, raw, roster); err != nil {
							return err
						}
					} else if ClientNativeCandidate(name, raw) {
						nativeFiles[name] = raw
					}
				}
				var stat unix.Stat_t
				if unix.Fstatat(int(directory.Fd()), child.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW) != nil {
					return &clientFailure{code: "file_changed"}
				}
				stat.Atim = unix.Timespec{}
				entries[name] = stat
				delete(wanted, name)
			}
		}
		return nil
	}
	if err := walk(root, "."); err != nil {
		return nil, err
	}
	if len(wanted) != 0 || len(dirs) != 0 {
		return nil, &clientFailure{code: "missing_file"}
	}
	if a.native == nil {
		if err := CheckClientNativePayload(nativeFiles, roster); err != nil {
			return nil, err
		}
	}
	return entries, nil
}

func (a *clientTreeAdmission) recheck(ctx context.Context) (failure error) {
	if len(a.parents) == 0 || a.closeFailure != nil {
		return &clientFailure{code: "closed"}
	}
	fresh, err := admitClientTree(ctx, a.path, a.id, a.owner, a.check, a.native)
	if err != nil {
		return err
	}
	defer func() {
		if err := fresh.close(); err != nil {
			failure = &clientFailure{code: "cleanup_failed", cause: errors.Join(failure, err), owner: fresh}
		}
	}()
	if len(fresh.parents) != len(a.parents) || !reflect.DeepEqual(fresh.entries, a.entries) {
		return &clientFailure{code: "tree_changed"}
	}
	for i, old := range a.identities {
		var held unix.Stat_t
		if unix.Fstat(int(a.parents[i].Fd()), &held) != nil || held.Dev != old.Dev || held.Ino != old.Ino || fresh.identities[i].Dev != old.Dev || fresh.identities[i].Ino != old.Ino {
			return &clientFailure{code: "path_changed"}
		}
	}
	return nil
}

func execInstalledClient(path string, args, environment []string) error {
	if err := syscall.Exec(path, args, environment); err != nil {
		return &clientFailure{code: "exec_failed", cause: err}
	}
	return nil
}
