//go:build linux

package runtime

import "golang.org/x/sys/unix"

func bootstrapReceiptPipeMetadataValid(info unix.Stat_t) bool {
	return info.Mode&0077 == 0
}
