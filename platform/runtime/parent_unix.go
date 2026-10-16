//go:build linux || darwin

package runtime

import (
	"context"
	"errors"
	"os"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

func validateLifetimeLease(file *os.File) error {
	if file == nil {
		return nil
	}
	info, err := file.Stat()
	if err != nil {
		return errors.New("lifetime lease descriptor is unavailable")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 {
		return errors.New("lifetime lease descriptor is not private and owned")
	}
	return nil
}

func prepareChildLifetime(lease *os.File) (reader, writer, copy *os.File, err error) {
	if err = validateLifetimeLease(lease); err != nil {
		return nil, nil, nil, err
	}
	reader, writer, err = os.Pipe()
	if err != nil {
		return nil, nil, nil, errors.New("parent-lifetime pipe creation failed")
	}
	if lease != nil {
		fd, duplicateErr := unix.FcntlInt(lease.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if duplicateErr != nil {
			cleanupErr := closeChildStartFiles(reader, writer, nil)
			return nil, nil, nil, errors.Join(errors.New("lifetime lease duplication failed"), cleanupErr)
		}
		copy = os.NewFile(uintptr(fd), "protected-lifetime-lease")
		if err = validateLifetimeLease(copy); err != nil {
			cleanupErr := closeChildStartFiles(reader, writer, copy)
			return nil, nil, nil, errors.Join(err, cleanupErr)
		}
		original, originalErr := lease.Stat()
		duplicated, copyErr := copy.Stat()
		if originalErr != nil || copyErr != nil || !os.SameFile(original, duplicated) {
			cleanupErr := closeChildStartFiles(reader, writer, copy)
			return nil, nil, nil, errors.Join(errors.New("lifetime lease descriptor changed"), cleanupErr)
		}
	}
	return reader, writer, copy, nil
}

func closeChildStartFiles(files ...*os.File) error {
	var err error
	for _, file := range files {
		if file != nil {
			if file.Close() != nil {
				err = errors.New("owned lifecycle descriptor cleanup failed")
			}
		}
	}
	return err
}

// ParentLifetime owns the child's inherited read descriptor and cancels when
// its launcher exits. No messages travel on this pipe. The inherited lease
// descriptor, when present, stays open until process exit; it is not owned here.
// This is lifecycle control, not a sandbox or an alternative application bus.
func ParentLifetime(parent context.Context) (context.Context, context.CancelFunc, error) {
	if parent == nil {
		return nil, nil, errors.New("parent-lifetime context is required")
	}
	value := os.Getenv("AGENTMUX_KERNEL_PARENT_FD")
	fd, err := strconv.Atoi(value)
	if err != nil || fd < 3 || fd > 1024 || strconv.Itoa(fd) != value {
		return nil, nil, errors.New("parent-lifetime descriptor is invalid")
	}
	var info unix.Stat_t
	statErr := unix.Fstat(fd, &info)
	flags, flagErr := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	// Receipt and lifetime descriptors share the platform pipe metadata rules.
	// Access direction and UID are checked here for this inherited reader.
	if statErr != nil || flagErr != nil || info.Mode&unix.S_IFMT != unix.S_IFIFO || !bootstrapReceiptPipeMetadataValid(info) || info.Uid != uint32(os.Geteuid()) || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return nil, nil, errors.New("parent-lifetime descriptor is not a private owned read pipe")
	}
	// ExtraFiles converts inherited descriptors to blocking mode. Register this
	// reader with Go's poller so closing it actually interrupts a pending read.
	if unix.SetNonblock(fd, true) != nil {
		return nil, nil, errors.New("parent-lifetime pipe polling setup failed")
	}
	file := os.NewFile(uintptr(fd), "protected-parent-lifetime")
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	hookDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(hookDone); file.Close() })
	go func() { defer close(done); defer file.Close(); var data [1]byte; _, _ = file.Read(data[:]); cancel() }()
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			cancel()
			file.Close()
			if !stop() {
				<-hookDone
			}
			<-done
		})
	}
	return ctx, cleanup, nil
}
