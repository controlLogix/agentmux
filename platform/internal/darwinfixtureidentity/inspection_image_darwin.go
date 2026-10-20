//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// InspectionCommand is one production argv form. ContainerArgument is -1 for
// literal arguments; otherwise that slot contains a full container ID followed
// by the exact suffix in Args. No other argument admits substitutions.
type InspectionCommand struct {
	Args              []string
	ContainerArgument int
}

func (c InspectionCommand) Matches(args []string) bool {
	if len(args) != len(c.Args) {
		return false
	}
	for i, want := range c.Args {
		if i == c.ContainerArgument {
			if !strings.HasSuffix(args[i], want) {
				return false
			}
			id := strings.TrimSuffix(args[i], want)
			if len(id) != 64 || strings.IndexFunc(id, func(r rune) bool { return !strings.ContainsRune("0123456789abcdef", r) }) >= 0 {
				return false
			}
		} else if args[i] != want {
			return false
		}
	}
	return true
}

// InspectionSelection pins the explicitly selected local Docker executable
// before launching the host. Same-UID code and the installed Docker updater
// remain trusted, as on the production Docker path. No PATH discovery occurs.
type InspectionSelection struct {
	mu       sync.Mutex
	path     string
	digest   string
	file     *os.File
	identity unix.Stat_t
	commands []InspectionCommand
	refs     int
	consumed bool
	failure  error
	checks   []*os.File
}

func PrepareInspectionSelection(ctx context.Context, path string, commands []InspectionCommand) (*InspectionSelection, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(commands) < 1 || len(commands) > 16 {
		return nil, failed("fixture_inspection_selection_invalid", nil)
	}
	selection := &InspectionSelection{path: path, refs: 1}
	for _, command := range commands {
		if len(command.Args) < 4 || len(command.Args) > 16 || command.Args[0] != path || command.Args[1] != "--context" || command.Args[2] == "" || command.ContainerArgument < -1 || command.ContainerArgument >= len(command.Args) || (command.ContainerArgument >= 0 && command.ContainerArgument < 3) {
			return nil, failed("fixture_inspection_selection_invalid", nil)
		}
		selection.commands = append(selection.commands, InspectionCommand{Args: append([]string(nil), command.Args...), ContainerArgument: command.ContainerArgument})
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, failed("fixture_inspection_image_refused", err)
	}
	selection.file = os.NewFile(uintptr(fd), "selected-inspection-image")
	if err = unix.Fstat(fd, &selection.identity); err == nil {
		s := selection.identity
		if s.Mode&unix.S_IFMT != unix.S_IFREG || s.Mode&0111 == 0 || s.Mode&0022 != 0 || (s.Uid != 0 && s.Uid != uint32(os.Geteuid())) || s.Size < 1 || s.Size > 128*1024*1024 {
			err = failed("fixture_inspection_image_refused", nil)
		}
	}
	if err == nil {
		selection.digest, err = inspectionDigest(ctx, selection.file, selection.identity.Size)
	}
	if err == nil {
		err = selection.recheck(ctx)
	}
	if err != nil {
		selection.failure = err
		return selection, err
	}
	return selection, nil
}

func inspectionDigest(ctx context.Context, file *os.File, size int64) (string, error) {
	reader := io.NewSectionReader(file, 0, size+1)
	hash := sha256.New()
	buffer := make([]byte, 64*1024)
	defer clear(buffer)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, err := reader.Read(buffer)
		total += int64(n)
		if total > size {
			return "", failed("fixture_inspection_image_changed", nil)
		}
		hash.Write(buffer[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	if total != size || ctx.Err() != nil {
		return "", failed("fixture_inspection_image_changed", ctx.Err())
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func sameInspectionFile(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func (s *InspectionSelection) recheck(ctx context.Context) (failure error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.consumed || s.failure != nil || s.file == nil {
		return failed("fixture_inspection_image_unavailable", s.failure)
	}
	defer func() {
		if failure != nil {
			s.failure = failure
		}
	}()
	fd, err := unix.Open(s.path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return failed("fixture_inspection_image_changed", err)
	}
	fresh := os.NewFile(uintptr(fd), "selected-inspection-recheck")
	s.checks = append(s.checks, fresh)
	defer func() { failure = errors.Join(failure, fresh.Close()) }()
	var held, current unix.Stat_t
	if unix.Fstat(int(s.file.Fd()), &held) != nil || unix.Fstat(fd, &current) != nil || !sameInspectionFile(s.identity, held) || !sameInspectionFile(s.identity, current) {
		return failed("fixture_inspection_image_changed", nil)
	}
	got, err := inspectionDigest(ctx, s.file, held.Size)
	var final unix.Stat_t
	if err != nil || got != s.digest || unix.Fstat(int(s.file.Fd()), &final) != nil || !sameInspectionFile(s.identity, final) {
		return failed("fixture_inspection_image_changed", err)
	}
	return nil
}

func (s *InspectionSelection) target(args []string) (expectedImage, bool) {
	for _, command := range s.commands {
		if command.Matches(args) {
			return expectedImage{Path: s.path, Digest: s.digest, Args: append([]string(nil), args[1:]...), inspection: s}, true
		}
	}
	return expectedImage{}, false
}

func (s *InspectionSelection) retain() { s.mu.Lock(); defer s.mu.Unlock(); s.refs++ }
func (s *InspectionSelection) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.consumed {
		return s.failure
	}
	s.refs--
	if s.refs == 0 {
		s.consumed = true
		s.failure = errors.Join(s.failure, s.file.Close())
	}
	return s.failure
}
