//go:build linux

package runtime

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
)

func TestPidfdSurvivalDiagnosticKeepsClosedFacts(t *testing.T) {
	cases := []struct {
		name     string
		count    int
		err      error
		revents  int16
		expected string
	}{
		{"zero", 0, nil, 0, "pidfd_survival_observation_refused: count=0 error=none revents=0"},
		{"interrupted", -1, syscall.EINTR, 0, "pidfd_survival_observation_refused: count=-1 error=interrupted revents=0"},
		{"wrapped_interrupted", -1, fmt.Errorf("private detail: %w", syscall.EINTR), 0, "pidfd_survival_observation_refused: count=-1 error=interrupted revents=0"},
		{"kernel_error", -1, syscall.EBADF, 32, "pidfd_survival_observation_refused: count=-1 error=kernel_error revents=32"},
		{"spoofed_error", -1, errors.New("EINTR private detail"), 0, "pidfd_survival_observation_refused: count=-1 error=kernel_error revents=0"},
		{"event", 1, nil, 1, "pidfd_survival_observation_refused: count=1 error=none revents=1"},
		{"error_and_event", 1, syscall.EINTR, 1, "pidfd_survival_observation_refused: count=1 error=interrupted revents=1"},
		{"negative_without_error", -1, nil, 0, "pidfd_survival_observation_refused: count=-1 error=none revents=0"},
		{"flags_without_count", 0, nil, 32, "pidfd_survival_observation_refused: count=0 error=none revents=32"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := pidfdSurvivalDiagnostic(c.count, c.err, c.revents); got != c.expected {
				t.Fatal("closed observation facts changed")
			}
		})
	}
}
