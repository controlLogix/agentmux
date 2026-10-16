//go:build darwin

// This separate cooperative image tests runtime lifecycle behavior. It is not
// the identity fixture, a signed product release, a broker, or the installed CLI.
package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"time"

	protected "github.com/controlLogix/agentmux/platform/runtime"
	"golang.org/x/sys/unix"
)

func main() { os.Exit(run()) }

func run() (result int) {
	if len(os.Args) != 4 || (os.Args[1] != "parent" && os.Args[1] != "parent-ready") {
		return 70
	}
	role := os.Args[2]
	if role != "boot" && role != "kernel-lifecycle" && role != "internal-communication" && role != "exported-status" {
		return 70
	}
	if os.Getenv("AGENTMUX_KERNEL_ROLE") != role {
		return 70
	}
	name := filepath.Base(os.Args[0])
	if name != "runtime-fixture" && name != "agentmux-"+role {
		return 70
	}
	deadline, err := strconv.ParseInt(os.Args[3], 10, 64)
	if err != nil || strconv.FormatInt(deadline, 10) != os.Args[3] {
		return 70
	}
	remaining := time.Until(time.Unix(0, deadline))
	if remaining <= 0 || remaining > 15*time.Second {
		return 70
	}
	parentFD := 3
	if os.Args[1] == "parent-ready" {
		parentFD = 4
	}
	if os.Getenv("AGENTMUX_KERNEL_PARENT_FD") != strconv.Itoa(parentFD) {
		return 70
	}
	leaseFD := 0
	if value := os.Getenv("AGENTMUX_KERNEL_LEASE_FD"); value != "" {
		leaseFD = parentFD + 1
		if value != strconv.Itoa(leaseFD) {
			return 70
		}
		var info unix.Stat_t
		flags, flagErr := unix.FcntlInt(uintptr(leaseFD), unix.F_GETFL, 0)
		if unix.Fstat(leaseFD, &info) != nil || flagErr != nil || info.Mode&unix.S_IFMT != unix.S_IFREG ||
			info.Mode&0077 != 0 || info.Uid != uint32(os.Geteuid()) || info.Nlink != 1 || flags&unix.O_ACCMODE != unix.O_RDWR {
			return 70
		}
		lease := os.NewFile(uintptr(leaseFD), "runtime-fixture-lease")
		defer func() {
			if lease.Close() != nil {
				result = 70
			}
		}()
	}
	parent, cancel := context.WithDeadline(context.Background(), time.Unix(0, deadline))
	defer cancel()
	lifetime, cleanup, err := protected.ParentLifetime(parent)
	if err != nil {
		return 70
	}
	defer cleanup()
	if json.NewEncoder(os.Stdout).Encode(struct {
		Ready    bool   `json:"ready"`
		Role     string `json:"role"`
		ParentFD int    `json:"parentFD"`
		LeaseFD  int    `json:"leaseFD"`
	}{true, role, parentFD, leaseFD}) != nil {
		return 70
	}
	if os.Args[1] == "parent-ready" {
		var info unix.Stat_t
		flags, flagErr := unix.FcntlInt(3, unix.F_GETFL, 0)
		if unix.Fstat(3, &info) != nil || flagErr != nil || info.Mode != unix.S_IFIFO|0660 ||
			info.Dev != 0 || info.Rdev != 0 || info.Nlink != 0 || info.Flags != 0 || info.Uid != uint32(os.Geteuid()) || flags&unix.O_ACCMODE != unix.O_WRONLY {
			return 70
		}
		ready := os.NewFile(3, "runtime-fixture-ready")
		n, writeErr := ready.Write([]byte{1})
		closeErr := ready.Close()
		if writeErr != nil || closeErr != nil || n != 1 {
			return 70
		}
	}
	<-lifetime.Done()
	if parent.Err() != nil {
		return 124
	}
	return 0
}
