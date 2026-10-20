//go:build !darwin && !linux

package launcher

import (
	"context"
	"os/exec"
)

// RunClientDoctor refuses unsupported hosts before reaching command creation.
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
