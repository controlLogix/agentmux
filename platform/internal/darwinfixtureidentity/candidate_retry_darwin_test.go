//go:build darwin && cgo && agentmux_bootstrap_docker && agentmux_darwin_identity_candidate

package darwinfixtureidentity

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCandidatePollRetriesOnlyInterruption(t *testing.T) {
	start := time.Unix(0, 0)
	calls := 0
	read := func(wait time.Duration) (int, unix.Kevent_t, error) {
		calls++
		if wait != 50*time.Millisecond {
			t.Fatal("candidate_poll_wait_bound_failed")
		}
		if calls == 1 {
			return 0, unix.Kevent_t{}, unix.EINTR
		}
		return 1, unix.Kevent_t{Filter: unix.EVFILT_PROC}, nil
	}
	event, interruptions, err := candidatePollEvent(read, func() time.Time { return start }, start.Add(3*time.Second))
	if err != nil || calls != 2 || interruptions != 1 || event.Filter != unix.EVFILT_PROC {
		t.Fatal("candidate_poll_interruption_control_failed")
	}
}

func TestCandidatePollNonInterruptionFailsClosed(t *testing.T) {
	for _, cause := range []error{unix.EBADF, unix.EINVAL, unix.EFAULT, unix.ENOENT, unix.ENOMEM, unix.EACCES, unix.EPERM, errors.New("private_injected_failure")} {
		start := time.Unix(0, 0)
		calls := 0
		read := func(time.Duration) (int, unix.Kevent_t, error) {
			calls++
			return 0, unix.Kevent_t{}, cause
		}
		_, interruptions, err := candidatePollEvent(read, func() time.Time { return start }, start.Add(3*time.Second))
		if !errors.Is(err, cause) || calls != 1 || interruptions != 0 {
			t.Fatal("candidate_poll_noninterruption_control_failed")
		}
		if candidateEventErrorLabel(err) == "candidate_event_read_interrupted" {
			t.Fatal("candidate_poll_error_class_changed")
		}
	}
}

func TestCandidatePollDeadlineNeverResets(t *testing.T) {
	start := time.Unix(0, 0)
	clock := start
	deadline := start.Add(3 * time.Second)
	calls := 0
	read := func(wait time.Duration) (int, unix.Kevent_t, error) {
		calls++
		if wait <= 0 || wait > 50*time.Millisecond || wait > deadline.Sub(clock) {
			t.Fatal("candidate_poll_deadline_wait_failed")
		}
		clock = clock.Add(time.Second)
		return 0, unix.Kevent_t{}, unix.EINTR
	}
	_, interruptions, err := candidatePollEvent(read, func() time.Time { return clock }, deadline)
	if !errors.Is(err, candidatePollDeadline) || calls != 3 || interruptions != 3 || !clock.Equal(deadline) {
		t.Fatal("candidate_poll_deadline_reset")
	}
	// Less than one poll interval remains: the requested wait shrinks to it.
	clock = deadline.Add(-time.Millisecond)
	read = func(wait time.Duration) (int, unix.Kevent_t, error) {
		if wait != time.Millisecond {
			t.Fatal("candidate_poll_final_wait_not_bounded")
		}
		clock = deadline
		return 0, unix.Kevent_t{}, nil
	}
	_, interruptions, err = candidatePollEvent(read, func() time.Time { return clock }, deadline)
	if !errors.Is(err, candidatePollDeadline) || interruptions != 0 {
		t.Fatal("candidate_poll_empty_result_deadline_failed")
	}
}
