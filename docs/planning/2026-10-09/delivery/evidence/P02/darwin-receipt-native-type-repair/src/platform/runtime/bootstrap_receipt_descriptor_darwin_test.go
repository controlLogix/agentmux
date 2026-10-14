//go:build darwin && cgo

package runtime

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

func TestDarwinReceiptRequiresActualAnonymousWritePipe(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal("owned pipe unavailable")
	}
	defer reader.Close()
	defer writer.Close()
	check := func(fd int) bool {
		var s unix.Stat_t
		flags, e := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		return e == nil && unix.Fstat(fd, &s) == nil && bootstrapReceiptDescriptorValid(fd, &s, flags)
	}
	if !check(int(writer.Fd())) || check(int(reader.Fd())) {
		t.Fatal("actual pipe direction refused or read end admitted")
	}
	if !receiptAnonymousPipe(int(reader.Fd())) {
		t.Fatal("native anonymous type query failed")
	}
	file, err := os.CreateTemp(t.TempDir(), "regular")
	if err != nil {
		t.Fatal("owned file unavailable")
	}
	defer file.Close()
	if receiptAnonymousPipe(int(file.Fd())) || check(int(file.Fd())) {
		t.Fatal("regular file admitted")
	}
	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal("owned socket unavailable")
	}
	defer unix.Close(sockets[0])
	defer unix.Close(sockets[1])
	if receiptAnonymousPipe(sockets[0]) || check(sockets[0]) {
		t.Fatal("socket admitted")
	}
	path := filepath.Join(t.TempDir(), "named-fifo")
	if unix.Mkfifo(path, 0600) != nil {
		t.Fatal("owned FIFO unavailable")
	}
	rd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal("owned FIFO reader unavailable")
	}
	defer unix.Close(rd)
	wr, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal("owned FIFO writer unavailable")
	}
	defer unix.Close(wr)
	if receiptAnonymousPipe(wr) || check(wr) {
		t.Fatal("named FIFO admitted")
	}
	if unix.Fchmod(wr, 0660) != nil || receiptAnonymousPipe(wr) || check(wr) {
		t.Fatal("named FIFO mode granted anonymous identity")
	}
}
