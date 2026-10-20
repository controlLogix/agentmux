//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import "golang.org/x/sys/unix"

// Request a registration receipt without draining pending process events.
// The following identity and event checks still decide admission. Never repeat
// EV_ADD after EINTR: that could replace an already registered one-shot watch.
func registerProcessWatch(queue int, id identity) error {
	change := []unix.Kevent_t{{Ident: uint64(id.PID), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD | unix.EV_ONESHOT | unix.EV_RECEIPT, Fflags: unix.NOTE_EXIT | unix.NOTE_EXEC}}
	var events [1]unix.Kevent_t
	zero := unix.Timespec{}
	count, err := unix.Kevent(queue, change, events[:], &zero)
	return childWatchRegistrationResult(id, count, events[0], err)
}

// Registration events are private diagnostic observations, never admitted
// process watches or evidence that an original process exited.
type watchRegistrationObservation struct {
	id           identity
	count        int
	event        unix.Kevent_t
	syscallError error
}

func childWatchRegistrationResult(id identity, count int, event unix.Kevent_t, syscallError error) error {
	if syscallError == nil && count == 1 && event.Ident == uint64(id.PID) && event.Filter == unix.EVFILT_PROC && event.Flags&(unix.EV_ERROR|unix.EV_RECEIPT) == unix.EV_ERROR|unix.EV_RECEIPT && event.Data == 0 && event.Fflags == unix.NOTE_EXIT|unix.NOTE_EXEC {
		return nil
	}
	owner := &watchRegistrationObservation{id: id, count: count, event: event, syscallError: syscallError}
	stage := "fixture_watch_registration_unexpected"
	var cause error
	if syscallError != nil {
		stage, cause = "fixture_watch_registration_syscall", syscallError
	} else if count == 1 && event.Ident == uint64(id.PID) && event.Filter == unix.EVFILT_PROC {
		switch {
		case event.Flags&unix.EV_ERROR != 0:
			stage = "fixture_watch_registration_ev_error"
			// For EV_ERROR, the SDK defines data as the errno value. An
			// unavailable or malformed value must not become an inferred ESRCH.
			if event.Data > 0 && event.Data <= 1<<31-1 {
				cause = unix.Errno(event.Data)
			}
		case event.Fflags&unix.NOTE_EXEC != 0:
			stage = "fixture_watch_registration_exec"
		case event.Fflags&unix.NOTE_EXIT != 0:
			stage = "fixture_watch_registration_exit"
		}
	}
	return &failure{stage: "fixture_child_watch_registration_refused", cause: &failure{stage: stage, cause: cause, retained: owner}, retained: owner}
}

func watchRegistrationFailureCategory(stage string) bool {
	switch stage {
	case "fixture_watch_registration_syscall", "fixture_watch_registration_ev_error", "fixture_watch_registration_exit", "fixture_watch_registration_exec", "fixture_watch_registration_unexpected":
		return true
	}
	return false
}

func watchRegistrationErrnoCategory(cause error) string {
	errno, typed := cause.(unix.Errno)
	if cause == nil || (typed && errno == 0) {
		return "fixture_watch_registration_errno_unavailable"
	}
	if !typed {
		return "fixture_watch_registration_errno_unclassified"
	}
	switch errno {
	case unix.ESRCH:
		return "fixture_watch_registration_errno_esrch"
	case unix.EPERM:
		return "fixture_watch_registration_errno_eperm"
	case unix.EACCES:
		return "fixture_watch_registration_errno_eacces"
	case unix.EINVAL:
		return "fixture_watch_registration_errno_einval"
	case unix.EINTR:
		return "fixture_watch_registration_errno_eintr"
	case unix.EBADF:
		return "fixture_watch_registration_errno_ebadf"
	case unix.EIO:
		return "fixture_watch_registration_errno_eio"
	case unix.ENOMEM:
		return "fixture_watch_registration_errno_enomem"
	case unix.ENOENT:
		return "fixture_watch_registration_errno_enoent"
	case unix.ENOTSUP:
		return "fixture_watch_registration_errno_enotsup"
	case unix.ENOSYS:
		return "fixture_watch_registration_errno_enosys"
	default:
		return "fixture_watch_registration_errno_other"
	}
}
