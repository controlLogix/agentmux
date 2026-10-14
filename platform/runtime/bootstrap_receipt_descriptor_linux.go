//go:build linux

package runtime

import (
	"golang.org/x/sys/unix"
	"os"
)

// Linux preserves its existing inherited-pipe metadata admission.
func bootstrapReceiptDescriptorValid(_ int, info *unix.Stat_t, flags int) bool {
	return info != nil && info.Mode&unix.S_IFMT == unix.S_IFIFO && info.Mode&0077 == 0 && info.Uid == uint32(os.Geteuid()) && flags&unix.O_ACCMODE == unix.O_WRONLY
}
