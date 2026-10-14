//go:build linux || darwin

package assembly

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
)

func openMemberFile(root *os.Root, entry string) (*os.File, error) {
	if !filepath.IsLocal(entry) || filepath.Clean(entry) != entry {
		return nil, errors.New("member path is not contained")
	}
	// os.Root can resolve symlinks before applying OpenFile flags. Walk direct
	// directory handles so O_NOFOLLOW applies to each original path component.
	directory, err := root.OpenFile(".", os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(entry, string(filepath.Separator))
	for _, part := range parts[:len(parts)-1] {
		fd, openErr := unix.Openat(int(directory.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		directory.Close()
		if openErr != nil {
			return nil, openErr
		}
		directory = os.NewFile(uintptr(fd), "member-directory")
	}
	fd, err := unix.Openat(int(directory.Fd()), parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	directory.Close()
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "member")
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("member is not a regular file")
	}
	return f, nil
}
