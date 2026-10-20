//go:build linux || darwin

package installer

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	protected "github.com/controlLogix/agentmux/platform/runtime"
	"golang.org/x/sys/unix"
)

// readClientBelow permits empty Python package marker files while retaining the
// same no-follow, single-link source rules as the foundation installer.
func readClientBelow(ctx context.Context, root *os.File, name string, size int64) ([]byte, error) {
	file, err := openClientBelow(root, name, false)
	if err != nil {
		return nil, err
	}
	raw, failure := readClientHeld(ctx, file, size)
	failure = closeOwned(file, failure)
	return raw, failure
}

func readClientHeld(ctx context.Context, file *os.File, size int64) ([]byte, error) {
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() != size || size < 0 || size > protected.ClientFileLimit {
		return nil, refusal("client_file_rejected", err)
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return nil, refusal("client_file_rejected", nil)
	}
	if ctx.Err() != nil {
		return nil, refusal("deadline", ctx.Err())
	}
	raw, err := io.ReadAll(io.NewSectionReader(file, 0, size+1))
	after, statErr := file.Stat()
	if err != nil || statErr != nil || int64(len(raw)) != size || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, refusal("source_changed", err)
	}
	if ctx.Err() != nil {
		return nil, refusal("deadline", ctx.Err())
	}
	return raw, nil
}

func openClientBelow(root *os.File, name string, directory bool) (*os.File, error) {
	if root == nil || !filepath.IsLocal(name) || filepath.Clean(name) != name || name == "." {
		return nil, refusal("client_path_invalid", nil)
	}
	parts := strings.Split(name, "/")
	parent := int(root.Fd())
	var held *os.File
	for index, part := range parts {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
		if index < len(parts)-1 || directory {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(parent, part, flags, 0)
		if err != nil {
			return nil, closeOwned(held, refusal("client_path_invalid", err))
		}
		file := os.NewFile(uintptr(fd), "installer-client-path")
		if err := closeOwned(held, nil); err != nil {
			return nil, closeOwned(file, err)
		}
		held, parent = file, fd
	}
	return held, nil
}

func clientDirectories(p *ClientPackage) []string {
	set := map[string]bool{}
	for _, file := range p.files {
		for dir := filepath.Dir(file.name); dir != "."; dir = filepath.Dir(dir) {
			set[dir] = true
		}
	}
	result := make([]string, 0, len(set))
	for dir := range set {
		result = append(result, dir)
	}
	sort.Strings(result)
	return result
}

func verifyClientTree(ctx context.Context, root *os.File, p *ClientPackage, policy *destinationPolicy) error {
	files := make(map[string]payload, len(p.files))
	directories := map[string]bool{".": true}
	for _, file := range p.files {
		files[file.name] = file
	}
	for _, dir := range clientDirectories(p) {
		directories[dir] = true
	}
	if len(directories) > 1024 {
		return refusal("client_manifest_rejected", nil)
	}
	var walk func(*os.File, string) error
	walk = func(directory *os.File, prefix string) error {
		if ctx.Err() != nil {
			return refusal("deadline", ctx.Err())
		}
		if policy != nil {
			if err := policy.directory(directory); err != nil {
				return err
			}
		}
		if _, err := directory.Seek(0, 0); err != nil {
			return refusal("destination_conflict", err)
		}
		entries, err := directory.ReadDir(protected.ClientMaxFiles + 1025)
		if (err != nil && err != io.EOF) || len(entries) > protected.ClientMaxFiles+1024 {
			return refusal("destination_conflict", err)
		}
		for _, entry := range entries {
			name := filepath.Join(prefix, entry.Name())
			if entry.Type()&os.ModeSymlink != 0 {
				return refusal("destination_conflict", nil)
			}
			if directories[name] {
				file, err := openClientBelow(directory, entry.Name(), true)
				if err != nil {
					return err
				}
				failure := walk(file, name)
				if err := closeOwned(file, failure); err != nil {
					return err
				}
				delete(directories, name)
			} else {
				expected, ok := files[name]
				if !ok {
					return refusal("destination_conflict", nil)
				}
				file, err := openClientBelow(directory, entry.Name(), false)
				if err != nil {
					return err
				}
				var failure error
				if policy != nil {
					failure = policy.file(file, expected.mode)
				}
				if failure == nil {
					raw, readErr := readClientHeld(ctx, file, int64(len(expected.data)))
					if readErr != nil || hash(raw) != hash(expected.data) {
						failure = refusal("destination_conflict", readErr)
					}
				}
				if err := closeOwned(file, failure); err != nil {
					return err
				}
				delete(files, name)
			}
		}
		return nil
	}
	if err := walk(root, "."); err != nil {
		return err
	}
	if len(files) != 0 || len(directories) != 1 {
		return refusal("destination_conflict", nil)
	}
	return nil
}

func InstallClient(parent context.Context, p *ClientPackage) (ClientResult, error) {
	if parent == nil {
		return ClientResult{}, refusal("context_invalid", nil)
	}
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		return ClientResult{}, refusal("platform_unqualified", nil)
	}
	if os.Geteuid() != 0 {
		return ClientResult{}, refusal("administrator_required", nil)
	}
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()
	if !validClientPackage(p) {
		return ClientResult{}, refusal("package_invalid", nil)
	}
	if err := checkClientFoundation(ctx, p); err != nil {
		return ClientResult{}, err
	}
	// The existing product base must already come from foundation installation.
	product, err := openDirectory(ctx, filepath.Dir(protected.InstalledClientBase), protectedDirectory)
	if err != nil {
		return ClientResult{}, err
	}
	createdBase := false
	if err := unix.Mkdirat(int(product.Fd()), "clients", 0755); err == nil {
		createdBase = true
	} else if err != unix.EEXIST {
		return ClientResult{}, closeOwned(product, refusal("destination_unavailable", err))
	}
	base, err := openClientBelow(product, "clients", true)
	err = closeOwned(product, err)
	if err != nil {
		return ClientResult{}, closeOwned(base, err)
	}
	if createdBase {
		if err := base.Chmod(0755); err != nil {
			return ClientResult{}, closeOwned(base, refusal("copy_failed", err))
		}
	}
	result, failure := installClientAt(ctx, base, p, destinationPolicy{protectedDirectory, protectedFile})
	failure = closeOwned(base, failure)
	return result, failure
}

func checkClientFoundation(ctx context.Context, p *ClientPackage) (failure error) {
	root, err := openDirectory(ctx, filepath.Join(ProtectedReleaseBase, p.manifest.FoundationInstallationID), protectedDirectory)
	if err != nil {
		return refusal("client_foundation_rejected", err)
	}
	defer func() { failure = closeOwned(root, failure) }()
	var pins []string
	for _, name := range []string{"release-manifest.json", "protected-assembly.json", "agentmux-runtime"} {
		file, err := openClientBelow(root, name, false)
		if err != nil {
			return refusal("client_foundation_rejected", err)
		}
		mode := os.FileMode(0444)
		limit := int64(metadataLimit)
		if name == "agentmux-runtime" {
			mode, limit = 0555, runtimeLimit
		}
		failure := protectedFile(file, mode)
		var raw []byte
		if failure == nil {
			raw, failure = readHeld(ctx, file, limit)
		}
		failure = closeOwned(file, failure)
		if failure != nil {
			return refusal("client_foundation_rejected", failure)
		}
		pins = append(pins, hash(raw))
	}
	if pins[2] != p.manifest.FrontendDigest || strings.TrimPrefix(hash([]byte(strings.Join(pins, "\x00"))), "sha256:") != p.manifest.FoundationInstallationID {
		return refusal("client_foundation_rejected", nil)
	}
	return nil
}

func installClientAt(ctx context.Context, base *os.File, p *ClientPackage, policy destinationPolicy) (result ClientResult, failure error) {
	if ctx == nil || base == nil || !validClientPackage(p) {
		return ClientResult{}, refusal("package_invalid", nil)
	}
	if err := policy.directory(base); err != nil {
		return ClientResult{}, err
	}
	created := false
	if err := unix.Mkdirat(int(base.Fd()), p.id, 0755); err == nil {
		created = true
	} else if err != unix.EEXIST {
		return ClientResult{}, refusal("destination_unavailable", err)
	}
	root, err := openClientBelow(base, p.id, true)
	if err != nil {
		return ClientResult{}, bindInstallation(err, p.id)
	}
	defer func() {
		failure = closeOwned(root, failure)
		if failure != nil {
			result = ClientResult{}
			failure = bindInstallation(failure, p.id)
		}
	}()
	if created {
		if err := root.Chmod(0755); err != nil {
			return ClientResult{}, refusal("copy_failed", err)
		}
	}
	if err := policy.directory(root); err != nil {
		return ClientResult{}, err
	}
	if created {
		for _, dir := range clientDirectories(p) {
			parent := root
			if filepath.Dir(dir) != "." {
				parent, err = openClientBelow(root, filepath.Dir(dir), true)
				if err != nil {
					return ClientResult{}, err
				}
			}
			failure := error(nil)
			if err := unix.Mkdirat(int(parent.Fd()), filepath.Base(dir), 0755); err != nil {
				failure = refusal("copy_failed", err)
			}
			if failure == nil {
				child, err := openClientBelow(parent, filepath.Base(dir), true)
				if err != nil {
					failure = err
				} else {
					failure = child.Chmod(0755)
					if failure == nil {
						failure = policy.directory(child)
					}
					failure = closeOwned(child, failure)
				}
			}
			if parent != root {
				failure = closeOwned(parent, failure)
			}
			if failure != nil {
				return ClientResult{}, failure
			}
		}
		for _, file := range p.files {
			parent := root
			if filepath.Dir(file.name) != "." {
				parent, err = openClientBelow(root, filepath.Dir(file.name), true)
				if err != nil {
					return ClientResult{}, err
				}
			}
			failure := policy.directory(parent)
			if failure == nil {
				failure = writeNew(ctx, parent, filepath.Base(file.name), file, policy)
			}
			if failure == nil {
				failure = parent.Sync()
			}
			if parent != root {
				failure = closeOwned(parent, failure)
			}
			if failure != nil {
				return ClientResult{}, failure
			}
		}
		if err := root.Sync(); err != nil {
			return ClientResult{}, refusal("sync_failed", err)
		}
		if err := base.Sync(); err != nil {
			return ClientResult{}, refusal("sync_failed", err)
		}
	}
	if err := verifyClientTree(ctx, root, p, &policy); err != nil {
		return ClientResult{}, err
	}
	outcome := "reused"
	if created {
		outcome = "installed"
	}
	return p.Result(outcome), nil
}
