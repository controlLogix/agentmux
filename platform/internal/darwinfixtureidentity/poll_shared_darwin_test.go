//go:build darwin && cgo && agentmux_bootstrap_docker && ((agentmux_darwin_identity_candidate && !agentmux_darwin_identity_protected_normal) || (agentmux_darwin_identity_protected_normal && !agentmux_darwin_identity_candidate && !agentmux_darwin_identity_protected_candidate))

package darwinfixtureidentity

import (
	"errors"
	"golang.org/x/sys/unix"
	"time"
)

var candidatePollDeadline = errors.New("candidate_event_deadline")
var candidatePollCount = errors.New("candidate_event_count_invalid")

// candidatePollEvent has no process authority. Its caller supplies a fixed
// deadline; interruption never replaces that deadline or retries a changelist.
func candidatePollEvent(read func(time.Duration) (int, unix.Kevent_t, error), now func() time.Time, deadline time.Time) (unix.Kevent_t, int, error) {
	interruptions := 0
	for {
		remaining := deadline.Sub(now())
		if remaining <= 0 {
			return unix.Kevent_t{}, interruptions, candidatePollDeadline
		}
		n, event, err := read(min(50*time.Millisecond, remaining))
		if errors.Is(err, unix.EINTR) {
			interruptions++
			continue
		}
		if err != nil {
			return unix.Kevent_t{}, interruptions, err
		}
		if n == 0 {
			continue
		}
		if n != 1 {
			return unix.Kevent_t{}, interruptions, candidatePollCount
		}
		return event, interruptions, nil
	}
}
