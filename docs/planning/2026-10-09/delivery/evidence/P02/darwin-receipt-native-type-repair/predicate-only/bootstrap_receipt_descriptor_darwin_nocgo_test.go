//go:build darwin && !cgo

package runtime

import (
	"golang.org/x/sys/unix"
	"testing"
)

func TestDarwinReceiptWithoutCGORefuses(t *testing.T) {
	s := unix.Stat_t{Mode: unix.S_IFIFO | 0660}
	if bootstrapReceiptDescriptorValid(3, &s, unix.O_WRONLY) {
		t.Fatal("native identity missing but writer admitted")
	}
}
