//go:build darwin

package runtime

import "golang.org/x/sys/unix"

// Darwin reports fixed 0660 metadata for anonymous pipes; chmod is unsupported.
// Zero filesystem device and link fields distinguish this kernel pipe metadata
// from a named FIFO, including one unlinked after another process opened it.
// This checks descriptor shape only. The caller still checks write-only access,
// UID, binding and concrete ownership; metadata grants no startup authority.
func bootstrapReceiptPipeMetadataValid(info unix.Stat_t) bool {
	return info.Mode == unix.S_IFIFO|0660 && info.Dev == 0 &&
		info.Rdev == 0 && info.Nlink == 0 && info.Flags == 0
}
