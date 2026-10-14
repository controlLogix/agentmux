//go:build darwin

package protocol

import (
	"os"
	"syscall"
)

func serverTrustChangeTime(info os.FileInfo) [2]int64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return [2]int64{}
	}
	return [2]int64{stat.Ctimespec.Sec, stat.Ctimespec.Nsec}
}
