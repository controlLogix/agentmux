//go:build linux || darwin

package main

import (
	"context"
	"errors"
	"path/filepath"
	"regexp"
	"strings"

	protected "github.com/controlLogix/agentmux/platform/runtime"
)

func parseInstalledClient(args []string) (operation, id, selection string, err error) {
	if len(args) < 5 || len(args) > 6 || (args[0] != "mcp" && args[0] != "startup" && args[0] != "dashboard" && args[0] != "launch-claude-desktop" && args[0] != "claude-code-hook") || args[1] != "--client-installation" || !protected.ValidClientInstallationID(args[2]) || args[3] != "--selection" || !filepath.IsAbs(args[4]) || filepath.Clean(args[4]) != args[4] || len(args[4]) > 4096 || strings.ContainsAny(args[4], "\x00\r\n") {
		return "", "", "", errors.New("installed_client_arguments_invalid")
	}
	operation = args[0]
	if len(args) == 6 {
		if operation != "claude-code-hook" || args[5] != "--managed-worker" {
			return "", "", "", errors.New("installed_client_arguments_invalid")
		}
		operation = "claude-code-hook-worker"
	}
	return operation, args[2], args[4], nil
}

type installedClientSetupOptions struct {
	id, selection, receipt, operation string
	apply                             bool
}

func parseInstalledClientSetup(args []string) (installedClientSetupOptions, error) {
	if (len(args) != 9 && len(args) != 10) || (args[0] != "client-setup" && args[0] != "claude-hook-setup") || args[1] != "--client-installation" || !protected.ValidClientInstallationID(args[2]) || args[3] != "--selection" || args[5] != "--receipt" || args[7] != "--operation" || (len(args) == 10 && args[9] != "--apply") {
		return installedClientSetupOptions{}, errors.New("installed_client_arguments_invalid")
	}
	for _, path := range []string{args[4], args[6]} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || strings.ContainsAny(path, "\x00\r\n") {
			return installedClientSetupOptions{}, errors.New("installed_client_arguments_invalid")
		}
	}
	switch args[8] {
	case "install", "remove", "restore", "recover":
	default:
		return installedClientSetupOptions{}, errors.New("installed_client_arguments_invalid")
	}
	return installedClientSetupOptions{args[2], args[4], args[6], args[8], len(args) == 10}, nil
}

var localEnrollmentRequestDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

var definitionsOwnerHub = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

func runInstalledClient(ctx context.Context, args []string) (failure error) {
	if len(args) > 0 && args[0] == "application-enroll" {
		// application-enroll --client-installation ID --request PATH --request-sha256 DIGEST
		if len(args) != 7 || args[1] != "--client-installation" || !protected.ValidClientInstallationID(args[2]) ||
			args[3] != "--request" || !filepath.IsAbs(args[4]) || filepath.Clean(args[4]) != args[4] || len(args[4]) > 4096 ||
			strings.ContainsAny(args[4], "\x00\r\n") || args[5] != "--request-sha256" || !localEnrollmentRequestDigest.MatchString(args[6]) {
			return errors.New("installed_client_arguments_invalid")
		}
		admitted, err := protected.PrepareInstalledClient(ctx, args[2])
		if err != nil {
			return err
		}
		defer func() { failure = errors.Join(failure, admitted.Close()) }()
		return admitted.ExecLocalEnrollment(ctx, args[4], args[6])
	}
	if len(args) > 0 && args[0] == "retire-definitions-owner" {
		// retire-definitions-owner --client-installation ID --repository-root PATH --hub-id HUB [--apply]
		if (len(args) != 7 && len(args) != 8) || args[1] != "--client-installation" || !protected.ValidClientInstallationID(args[2]) ||
			args[3] != "--repository-root" || !filepath.IsAbs(args[4]) || filepath.Clean(args[4]) != args[4] || len(args[4]) > 4096 ||
			strings.ContainsAny(args[4], "\x00\r\n") || args[5] != "--hub-id" || !definitionsOwnerHub.MatchString(args[6]) ||
			(len(args) == 8 && args[7] != "--apply") {
			return errors.New("installed_client_arguments_invalid")
		}
		admitted, err := protected.PrepareInstalledClient(ctx, args[2])
		if err != nil {
			return err
		}
		defer func() { failure = errors.Join(failure, admitted.Close()) }()
		return admitted.ExecDefinitionsOwnerRetirement(ctx, args[4], args[6], len(args) == 8)
	}
	if len(args) > 0 && (args[0] == "client-setup" || args[0] == "claude-hook-setup") {
		selected, err := parseInstalledClientSetup(args)
		if err != nil {
			return err
		}
		admitted, err := protected.PrepareInstalledClient(ctx, selected.id)
		if err != nil {
			return err
		}
		defer func() { failure = errors.Join(failure, admitted.Close()) }()
		if args[0] == "claude-hook-setup" {
			return admitted.ExecClaudeHookSetup(ctx, selected.selection, selected.receipt, selected.operation, selected.apply)
		}
		return admitted.ExecSetup(ctx, selected.selection, selected.receipt, selected.operation, selected.apply)
	}
	if len(args) > 0 && (args[0] == "startup" || args[0] == "mcp") {
		return runInstalledClientRequest(ctx, args, func(ctx context.Context, id string) (installedClientSession, error) {
			owner, err := protected.PrepareInstalledClient(ctx, id)
			if owner == nil {
				return nil, err
			}
			return owner, err
		})
	}
	operation, id, selection, err := parseInstalledClient(args)
	if err != nil {
		return err
	}
	admitted, err := protected.PrepareInstalledClient(ctx, id)
	if err != nil {
		return err
	}
	defer func() { failure = errors.Join(failure, admitted.Close()) }()
	return admitted.Exec(ctx, operation, selection)
}
