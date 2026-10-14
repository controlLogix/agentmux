//go:build darwin && !cgo

package runtime

import "golang.org/x/sys/unix"

// Native pipe identity is required; metadata alone cannot qualify the writer.
func bootstrapReceiptDescriptorValid(_ int, _ *unix.Stat_t, _ int) bool { return false }
