//go:build linux || darwin

package installer

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/controlLogix/agentmux/platform/privatefs"
	"golang.org/x/sys/unix"
)

func closeOwned(file *os.File, primary error) error {
	if file == nil {
		return primary
	}
	if err := file.Close(); err != nil {
		return &Failure{code: "cleanup_failed", cause: errors.Join(primary, err), files: []*os.File{file}}
	}
	return primary
}

func openSourceDirectory(ctx context.Context, path string) (*os.File, error) {
	return openDirectory(ctx, path, nil)
}

// Every component is opened through the held parent without following links.
func openDirectory(ctx context.Context, path string, admit func(*os.File) error) (*os.File, error) {
	if !canonical(path) {
		return nil, refusal("path_invalid", nil)
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if path == "/" {
		parts = nil
	}
	if len(parts) > 128 {
		return nil, refusal("path_invalid", nil)
	}
	parent := unix.AT_FDCWD
	var held *os.File
	for i := -1; i < len(parts); i++ {
		if err := ctx.Err(); err != nil {
			return nil, closeOwned(held, refusal("deadline", err))
		}
		name := "/"
		if i >= 0 {
			name = parts[i]
		}
		fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, closeOwned(held, refusal("directory_unavailable", err))
		}
		current := os.NewFile(uintptr(fd), "installer-directory")
		if admit != nil {
			if err := admit(current); err != nil {
				return nil, closeOwned(current, closeOwned(held, err))
			}
		}
		if err := closeOwned(held, nil); err != nil {
			return nil, closeOwned(current, err)
		}
		held, parent = current, fd
	}
	return held, nil
}

func readBelow(ctx context.Context, directory *os.File, name string, limit int64) ([]byte, error) {
	if directory == nil || !filepath.IsLocal(name) || filepath.Clean(name) != name || name == "." || limit < 1 {
		return nil, refusal("source_invalid", nil)
	}
	parts := strings.Split(name, string(filepath.Separator))
	parent := int(directory.Fd())
	var opened *os.File
	for _, component := range parts[:len(parts)-1] {
		fd, err := unix.Openat(parent, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, closeOwned(opened, refusal("source_invalid", err))
		}
		next := os.NewFile(uintptr(fd), "installer-source-parent")
		if err := closeOwned(opened, nil); err != nil {
			return nil, closeOwned(next, err)
		}
		opened, parent = next, fd
	}
	fd, err := unix.Openat(parent, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, closeOwned(opened, refusal("source_unavailable", err))
	}
	file := os.NewFile(uintptr(fd), "installer-source")
	raw, failure := readHeld(ctx, file, limit)
	failure = closeOwned(file, failure)
	failure = closeOwned(opened, failure)
	if failure != nil {
		return nil, failure
	}
	return raw, nil
}

func readAbsolute(ctx context.Context, path string, limit int64) ([]byte, error) {
	if !canonical(path) {
		return nil, refusal("source_invalid", nil)
	}
	root, err := openSourceDirectory(ctx, filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	raw, failure := readBelow(ctx, root, filepath.Base(path), limit)
	failure = closeOwned(root, failure)
	if failure != nil {
		return nil, failure
	}
	return raw, nil
}

func readHeld(ctx context.Context, file *os.File, limit int64) ([]byte, error) {
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 1 || before.Size() > limit {
		return nil, refusal("source_invalid", err)
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return nil, refusal("source_invalid", nil)
	}
	var raw []byte
	buffer := make([]byte, 64*1024)
	for {
		if err := ctx.Err(); err != nil {
			return nil, refusal("deadline", err)
		}
		n, readErr := file.Read(buffer)
		if int64(len(raw)+n) > limit {
			return nil, refusal("source_invalid", nil)
		}
		raw = append(raw, buffer[:n]...)
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, refusal("source_unavailable", readErr)
		}
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != int64(len(raw)) || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		return nil, refusal("source_changed", err)
	}
	return raw, nil
}

func readSelection(ctx context.Context, path string, ownerUID uint32) ([]byte, error) {
	admit := func(file *os.File) error {
		info, err := file.Stat()
		if err != nil {
			return refusal("selection_invalid", err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != 0 && stat.Uid != ownerUID) || (info.Mode().Perm()&0022 != 0 && !(stat.Uid == 0 && info.Mode()&os.ModeSticky != 0)) || privatefs.CheckDescriptor(file, privatefs.PublicAncestor) != nil {
			return refusal("selection_invalid", nil)
		}
		return nil
	}
	root, err := openDirectory(ctx, filepath.Dir(path), admit)
	if err != nil {
		return nil, err
	}
	info, err := root.Stat()
	if err != nil {
		return nil, closeOwned(root, refusal("selection_invalid", err))
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID || info.Mode().Perm() != 0700 || privatefs.CheckDescriptor(root, privatefs.PrivateObject) != nil {
		return nil, closeOwned(root, refusal("selection_invalid", nil))
	}
	fd, err := unix.Openat(int(root.Fd()), filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, closeOwned(root, refusal("selection_invalid", err))
	}
	file := os.NewFile(uintptr(fd), "installer-selection")
	info, err = file.Stat()
	if err != nil {
		return nil, closeOwned(file, closeOwned(root, refusal("selection_invalid", err)))
	}
	stat, ok = info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID || info.Mode().Perm() != 0600 || privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil {
		return nil, closeOwned(file, closeOwned(root, refusal("selection_invalid", nil)))
	}
	raw, failure := readHeld(ctx, file, metadataLimit)
	failure = closeOwned(file, closeOwned(root, failure))
	if failure != nil {
		return nil, failure
	}
	return raw, nil
}
