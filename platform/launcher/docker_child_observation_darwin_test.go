//go:build darwin

package launcher

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// These watches observe exit only. A private fixture handshake selects a PID,
// then current-parent, UID and birth-time checks fence kqueue registration.
// They cannot signal, adopt, reap or mint runtime process authority. The Docker
// driver's original exec.Cmd and sole Wait remain the process owners.
type dockerDarwinChildObservation struct {
	queue          int
	pid            int
	closeAttempted bool
}

func dockerDarwinObserveChild(t *testing.T, pid int) *dockerDarwinChildObservation {
	t.Helper()
	if pid <= 0 || os.Getuid() != os.Geteuid() {
		t.Fatal("controlled child observation credentials invalid")
	}
	before, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || before == nil || before.Proc.P_pid != int32(pid) || before.Eproc.Ppid != int32(os.Getpid()) ||
		before.Eproc.Ucred.Uid != uint32(os.Geteuid()) || before.Eproc.Pcred.P_ruid != uint32(os.Getuid()) ||
		before.Proc.P_stat == 0 || before.Proc.P_stat == 5 || before.Proc.P_starttime.Sec <= 0 {
		t.Fatal("controlled direct child observation refused")
	}
	queue, err := unix.Kqueue()
	if err != nil {
		t.Fatal("controlled child exit watch unavailable")
	}
	observer := &dockerDarwinChildObservation{queue: queue, pid: pid}
	t.Cleanup(func() {
		if !observer.closeAttempted {
			observer.closeAttempted = true
			if unix.Close(observer.queue) != nil {
				t.Error("controlled child exit watch close failed")
			}
		}
	})
	if _, err := unix.FcntlInt(uintptr(queue), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		t.Fatal("controlled child watch inheritance refused")
	}
	change := unix.Kevent_t{Ident: uint64(pid), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD | unix.EV_ENABLE | unix.EV_ONESHOT | unix.EV_RECEIPT, Fflags: unix.NOTE_EXIT | unix.NOTE_EXEC}
	var receipt [1]unix.Kevent_t
	zero := unix.Timespec{}
	// Never retry a changelist whose registration outcome is uncertain.
	n, err := unix.Kevent(queue, []unix.Kevent_t{change}, receipt[:], &zero)
	if err != nil || n != 1 || receipt[0].Ident != uint64(pid) || receipt[0].Filter != unix.EVFILT_PROC || receipt[0].Flags&unix.EV_ERROR == 0 || receipt[0].Data != 0 {
		t.Fatal("controlled child watch registration unconfirmed")
	}
	after, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || after == nil || after.Proc.P_pid != before.Proc.P_pid || after.Proc.P_starttime != before.Proc.P_starttime ||
		after.Eproc.Ppid != before.Eproc.Ppid || after.Eproc.Ucred.Uid != before.Eproc.Ucred.Uid ||
		after.Eproc.Pcred.P_ruid != before.Eproc.Pcred.P_ruid || after.Proc.P_stat == 0 || after.Proc.P_stat == 5 {
		t.Fatal("controlled child changed during exit watch admission")
	}
	var events [1]unix.Kevent_t
	n, err = dockerDarwinPollObservation(queue, events[:])
	if err != nil || n != 0 {
		t.Fatal("controlled child exited or executed during watch admission")
	}
	return observer
}

func dockerDarwinPollObservation(queue int, events []unix.Kevent_t) (int, error) {
	zero := unix.Timespec{}
	for attempt := 0; attempt < 3; attempt++ {
		n, err := unix.Kevent(queue, nil, events, &zero)
		if !errors.Is(err, unix.EINTR) {
			return n, err
		}
	}
	return 0, unix.EINTR
}

func dockerDarwinAssertChildrenExited(t *testing.T, observers []*dockerDarwinChildObservation, message string) {
	t.Helper()
	if len(observers) != 3 {
		t.Fatal("controlled child exit watch roster incomplete")
	}
	seen := map[int]bool{}
	for _, observer := range observers {
		if observer == nil || observer.closeAttempted || seen[observer.pid] {
			t.Fatal("controlled child exit watch unavailable")
		}
		seen[observer.pid] = true
		var events [1]unix.Kevent_t
		n, err := dockerDarwinPollObservation(observer.queue, events[:])
		if err != nil || n != 1 || events[0].Ident != uint64(observer.pid) || events[0].Filter != unix.EVFILT_PROC ||
			events[0].Flags&unix.EV_ERROR != 0 || events[0].Fflags&(unix.NOTE_EXIT|unix.NOTE_EXEC) != unix.NOTE_EXIT {
			t.Fatal(message)
		}
	}
}
