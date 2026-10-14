//go:build linux

package runtime

import (
	"golang.org/x/sys/unix"
	"os"
	"testing"
)

func TestReceiptLinuxDescriptorPreservesAdmission(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal("owned pipe unavailable")
	}
	defer reader.Close()
	defer writer.Close()
	var stat unix.Stat_t
	flags, err := unix.FcntlInt(writer.Fd(), unix.F_GETFL, 0)
	if err != nil || unix.Fstat(int(writer.Fd()), &stat) != nil {
		t.Fatal("owned descriptor unavailable")
	}
	if !bootstrapReceiptDescriptorValid(int(writer.Fd()), &stat, flags) {
		t.Fatal("genuine writer refused")
	}
	for _, fault := range []string{"mode", "owner", "type", "read", "readwrite", "nil"} {
		t.Run(fault, func(t *testing.T) {
			changed := stat
			chosen := flags
			ptr := &changed
			switch fault {
			case "mode":
				changed.Mode |= 0040
			case "owner":
				changed.Uid++
			case "type":
				changed.Mode = unix.S_IFREG | 0600
			case "read":
				chosen = unix.O_RDONLY
			case "readwrite":
				chosen = unix.O_RDWR
			case "nil":
				ptr = nil
			}
			if bootstrapReceiptDescriptorValid(int(writer.Fd()), ptr, chosen) {
				t.Fatal("invalid writer admitted")
			}
		})
	}
}
