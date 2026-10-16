//go:build darwin

package runtime

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBootstrapReceiptDarwinAnonymousPipeMetadata(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reader.Close(); writer.Close() })
	var original unix.Stat_t
	if err := unix.Fstat(int(writer.Fd()), &original); err != nil {
		t.Fatal(err)
	}
	if !bootstrapReceiptPipeMetadataValid(original) {
		t.Fatal("actual anonymous pipe metadata refused")
	}
	for _, name := range []string{"mode", "device", "special_device", "linked", "flags", "regular_file"} {
		t.Run(name, func(t *testing.T) {
			changed := original
			switch name {
			case "mode":
				changed.Mode = unix.S_IFIFO | 0666
			case "device":
				changed.Dev = 1
			case "special_device":
				changed.Rdev = 1
			case "linked":
				changed.Nlink = 1
			case "flags":
				changed.Flags = 1
			case "regular_file":
				changed.Mode = unix.S_IFREG | 0660
			}
			if bootstrapReceiptPipeMetadataValid(changed) {
				t.Fatal("changed anonymous pipe metadata accepted")
			}
		})
	}
}

func TestBootstrapReceiptDarwinNamedFIFORefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "named-fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	reader, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(reader)
	writer, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(writer)
	if err := unix.Fchmod(writer, 0660); err != nil {
		t.Fatal(err)
	}
	for _, unlinked := range []bool{false, true} {
		if unlinked {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
		var info unix.Stat_t
		if err := unix.Fstat(writer, &info); err != nil {
			t.Fatal(err)
		}
		if info.Mode != unix.S_IFIFO|0660 {
			t.Fatal("named FIFO did not match anonymous pipe type and mode")
		}
		if info.Dev == 0 || (unlinked && info.Nlink != 0) {
			t.Fatal("named FIFO filesystem identity or unlink observation changed")
		}
		if bootstrapReceiptPipeMetadataValid(info) {
			t.Fatal("named FIFO accepted as anonymous receipt pipe")
		}
	}
}
