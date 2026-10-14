//go:build linux || darwin

package protocol

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func privateOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
func readPrivateFile(path string) ([]byte, error) {
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != filepath.Clean(path) {
		return nil, errors.New("kernel_credential_reference_invalid")
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 || !privateOwner(info) {
		return nil, errors.New("kernel_credential_parent_invalid")
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, errors.New("kernel_credential_reference_invalid")
	}
	defer root.Close()
	file, err := root.OpenFile(filepath.Base(path), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("kernel_credential_reference_invalid")
	}
	defer file.Close()
	info, err = file.Stat()
	stat, ok := func() (*syscall.Stat_t, bool) {
		if info == nil {
			return nil, false
		}
		v, ok := info.Sys().(*syscall.Stat_t)
		return v, ok
	}()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0177 != 0 || !privateOwner(info) || info.Size() > MaxPayload || !ok || stat.Nlink != 1 {
		return nil, errors.New("kernel_credential_file_invalid")
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxPayload+1))
	if err != nil || len(data) > MaxPayload {
		return nil, errors.New("kernel_credential_file_invalid")
	}
	return data, nil
}
