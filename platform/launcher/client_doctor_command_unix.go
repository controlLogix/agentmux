//go:build darwin || linux

package launcher

import (
	"context"
	"os/exec"
)

// Standard cancellation signals the original process through Go's lifecycle
// checks. WaitDelay bounds owned pipe readers; it does not establish descendant
// termination. Do not signal a process group after the leader may be reaped.
func clientDoctorCommand(ctx context.Context, client string) *exec.Cmd {
	return clientDoctorProbeCommand(ctx, client, false)
}

func clientDoctorProbeCommand(ctx context.Context, client string, auth bool) *exec.Cmd {
	if auth && client == "codex" {
		return exec.CommandContext(ctx, client, "login", "status")
	}
	if auth && client == "claude" {
		return exec.CommandContext(ctx, client, "auth", "status")
	}
	return exec.CommandContext(ctx, client, "--version")
}
