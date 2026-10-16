//go:build darwin

package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func assertDarwinParentDescriptorRefused(t *testing.T, file *os.File) {
	t.Helper()
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		t.Fatal("owned parent descriptor duplication failed")
	}
	owned := true
	defer func() {
		if owned {
			unix.Close(fd)
		}
	}()
	t.Setenv("AGENTMUX_KERNEL_PARENT_FD", strconv.Itoa(fd))
	_, cleanup, err := ParentLifetime(context.Background())
	if err == nil {
		owned = false
		cleanup()
		t.Fatal("invalid parent descriptor was accepted")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
		t.Fatal("refusal consumed the caller-owned descriptor")
	}
}

func TestDarwinParentLifetimeRejectsInvalidDescriptors(t *testing.T) {
	for _, value := range []string{"", "2", "-1", "04", "1025", "100000", "invalid"} {
		t.Setenv("AGENTMUX_KERNEL_PARENT_FD", value)
		if _, cleanup, err := ParentLifetime(context.Background()); err == nil {
			cleanup()
			t.Fatal("invalid descriptor grammar was accepted")
		}
	}
	file, err := os.CreateTemp(t.TempDir(), "regular-parent")
	if err != nil {
		t.Fatal("owned regular descriptor unavailable")
	}
	t.Cleanup(func() { file.Close() })
	assertDarwinParentDescriptorRefused(t, file)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal("actual anonymous pipe unavailable")
	}
	t.Cleanup(func() { reader.Close(); writer.Close() })
	assertDarwinParentDescriptorRefused(t, writer)
	t.Setenv("AGENTMUX_KERNEL_PARENT_FD", strconv.Itoa(int(reader.Fd())))
	if _, cleanup, err := ParentLifetime(nil); err == nil {
		cleanup()
		t.Fatal("nil parent context was accepted")
	}
	if _, err := reader.Stat(); err != nil {
		t.Fatal("nil-context refusal consumed the reader")
	}
}

func TestDarwinParentLifetimeEOFBytesAndCancelledReadJoin(t *testing.T) {
	for _, kind := range []string{"eof", "bytes", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal("actual anonymous pipe unavailable")
			}
			t.Cleanup(func() { reader.Close(); writer.Close() })
			var info unix.Stat_t
			if err := unix.Fstat(int(reader.Fd()), &info); err != nil || info.Mode != unix.S_IFIFO|0660 || info.Dev != 0 || info.Rdev != 0 || info.Nlink != 0 || info.Flags != 0 {
				t.Fatal("actual Darwin anonymous read-pipe metadata differs")
			}
			fd, err := unix.FcntlInt(reader.Fd(), unix.F_DUPFD_CLOEXEC, 3)
			if err != nil {
				t.Fatal("owned parent pipe duplication failed")
			}
			t.Setenv("AGENTMUX_KERNEL_PARENT_FD", strconv.Itoa(fd))
			parent, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			ctx, cleanup, err := ParentLifetime(parent)
			if err != nil {
				unix.Close(fd)
				t.Fatal("actual anonymous read pipe was refused")
			}
			t.Cleanup(cleanup)
			switch kind {
			case "eof":
				if err := writer.Close(); err != nil {
					t.Fatal("owned parent writer close failed")
				}
			case "bytes":
				if _, err := writer.Write([]byte("unexpected")); err != nil {
					t.Fatal("unexpected parent byte control failed")
				}
			case "cancel":
				cancel()
			}
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("parent lifetime did not cancel")
			}
			done := make(chan struct{})
			go func() { cleanup(); cleanup(); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("parent reader cleanup did not join")
			}
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
				t.Fatal("owned parent reader was not closed after join")
			}
			if _, err := reader.Stat(); err != nil {
				t.Fatal("parent cleanup closed the separate caller reader")
			}
		})
	}
}

func TestDarwinParentLifetimeNamedFIFORefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "named-parent")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal("named FIFO control creation failed")
	}
	reader, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal("named FIFO reader unavailable")
	}
	t.Cleanup(func() { reader.Close() })
	writer, err := os.OpenFile(path, os.O_WRONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal("named FIFO writer unavailable")
	}
	t.Cleanup(func() { writer.Close() })
	if err := reader.Chmod(0660); err != nil {
		t.Fatal("named FIFO mode control failed")
	}
	for _, name := range []string{"linked", "unlinked"} {
		t.Run(name, func(t *testing.T) {
			if name == "unlinked" {
				if err := os.Remove(path); err != nil {
					t.Fatal("owned named FIFO unlink failed")
				}
			}
			var info unix.Stat_t
			if err := unix.Fstat(int(reader.Fd()), &info); err != nil || info.Mode != unix.S_IFIFO|0660 || info.Uid != uint32(os.Geteuid()) || info.Dev == 0 {
				t.Fatal("named FIFO type, mode, UID, or filesystem control differs")
			}
			if (name == "linked" && info.Nlink != 1) || (name == "unlinked" && info.Nlink != 0) {
				t.Fatal("named FIFO link-state control differs")
			}
			flags, err := unix.FcntlInt(reader.Fd(), unix.F_GETFL, 0)
			if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
				t.Fatal("named FIFO read-only control differs")
			}
			assertDarwinParentDescriptorRefused(t, reader)
		})
	}
}

func TestDarwinParentLeaseValidationAndDuplication(t *testing.T) {
	file, err := os.OpenFile(filepath.Join(t.TempDir(), "lease"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal("actual lifetime lease unavailable")
	}
	t.Cleanup(func() { file.Close() })
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("actual lifetime lease lock unavailable")
	}
	reader, writer, copy, err := prepareChildLifetime(file)
	if err != nil {
		t.Fatal("actual lifetime descriptors could not be prepared")
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			closeChildStartFiles(reader, writer, copy)
		}
	})
	flags, err := unix.FcntlInt(copy.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("lease duplicate is not close-on-exec")
	}
	original, originalErr := file.Stat()
	duplicated, duplicateErr := copy.Stat()
	if originalErr != nil || duplicateErr != nil || !os.SameFile(original, duplicated) {
		t.Fatal("lease duplicate does not identify the actual caller file")
	}
	closed = true
	if err := closeChildStartFiles(reader, writer, copy); err != nil {
		t.Fatal("owned lifetime descriptor cleanup failed")
	}
	if _, err := copy.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("owned lease duplicate was not closed")
	}
	if _, err := file.Stat(); err != nil {
		t.Fatal("caller lifetime lease was closed")
	}
	if err := file.Chmod(0644); err != nil {
		t.Fatal("public lease mode control failed")
	}
	if validateLifetimeLease(file) == nil {
		t.Fatal("public lifetime lease was accepted")
	}
	if err := file.Chmod(0600); err != nil {
		t.Fatal("private lease mode restoration failed")
	}
	if err := file.Close(); err != nil {
		t.Fatal("owned caller lease close failed")
	}
	if validateLifetimeLease(file) == nil {
		t.Fatal("closed lifetime lease was accepted")
	}
	pipeReader, pipeWriter, err := os.Pipe()
	if err != nil {
		t.Fatal("actual pipe lease refusal control unavailable")
	}
	t.Cleanup(func() { pipeReader.Close(); pipeWriter.Close() })
	if validateLifetimeLease(pipeReader) == nil {
		t.Fatal("pipe was accepted as a regular lifetime lease")
	}
}
