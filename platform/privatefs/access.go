// Package privatefs checks access policy on an already held file descriptor.
// Callers still enforce ownership, mode, link count, path and content identity.
package privatefs

import (
	"errors"
	"os"
)

type AccessKind uint8

const (
	PrivateObject AccessKind = iota + 1
	PublicAncestor
)

var (
	ErrInvalidDescriptor   = errors.New("private_fs_descriptor_invalid")
	ErrAccessDenied        = errors.New("private_fs_access_denied")
	ErrPlatformUnqualified = errors.New("private_fs_platform_unqualified")
)

// CheckDescriptor never opens a path or derives authority from a principal
// name. RawConn.Control protects the held descriptor during the native check.
// Darwin also requires a local mount with ownership enforcement enabled.
func CheckDescriptor(file *os.File, kind AccessKind) error {
	if file == nil || (kind != PrivateObject && kind != PublicAncestor) {
		return ErrInvalidDescriptor
	}
	info, err := file.Stat()
	if err != nil || (!info.Mode().IsRegular() && !info.IsDir()) || (kind == PublicAncestor && !info.IsDir()) {
		return ErrInvalidDescriptor
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return ErrInvalidDescriptor
	}
	var result error
	if raw.Control(func(fd uintptr) { result = checkNativeDescriptor(fd, kind) }) != nil {
		return ErrInvalidDescriptor
	}
	return result
}
