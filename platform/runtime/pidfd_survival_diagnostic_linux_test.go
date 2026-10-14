//go:build linux

package runtime

import (
	"errors"
	"fmt"
	"syscall"
)

// This explains a refused test observation; it never declares child liveness.
func pidfdSurvivalDiagnostic(count int, err error, revents int16) string {
	code := "none"
	if err != nil {
		code = "kernel_error"
		if errors.Is(err, syscall.EINTR) {
			code = "interrupted"
		}
	}
	return fmt.Sprintf("pidfd_survival_observation_refused: count=%d error=%s revents=%d", count, code, revents)
}
