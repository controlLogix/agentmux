//go:build linux || darwin

package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	protected "github.com/controlLogix/agentmux/platform/runtime"
)

func validRepositoryClientRoot(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && !strings.HasPrefix(path, "//") && len(path) <= 4096 && utf8.ValidString(path) && len(strings.Split(path, "/")) <= 128 && strings.IndexFunc(path, unicode.IsControl) < 0
}

type installedClientRequest struct{ operation, id, selection, repository string }

func parseInstalledClientRequest(args []string) (installedClientRequest, error) {
	invalid := errors.New("installed_client_arguments_invalid")
	if len(args) == 0 || (args[0] != "startup" && args[0] != "mcp") {
		return installedClientRequest{}, invalid
	}
	selected := installedClientRequest{operation: args[0]}
	worker, jsonOutput := false, false
	seen := map[string]bool{}
	for i := 1; i < len(args); i++ {
		key := args[i]
		if seen[key] {
			return installedClientRequest{}, invalid
		}
		seen[key] = true
		if key == "--managed-worker" {
			worker = true
			continue
		}
		if key != "--client-installation" && key != "--selection" && key != "--repository-root" && key != "--output" {
			return installedClientRequest{}, invalid
		}
		i++
		if i >= len(args) || args[i] == "" || strings.HasPrefix(args[i], "--") {
			return installedClientRequest{}, invalid
		}
		switch key {
		case "--client-installation":
			selected.id = args[i]
		case "--selection":
			selected.selection = args[i]
		case "--repository-root":
			selected.repository = args[i]
		case "--output":
			if args[0] != "startup" || (args[i] != "json" && args[i] != "human") {
				return installedClientRequest{}, invalid
			}
			jsonOutput = args[i] == "json"
		}
	}
	if !protected.ValidClientInstallationID(selected.id) {
		return installedClientRequest{}, invalid
	}
	if selected.selection != "" {
		if !filepath.IsAbs(selected.selection) || filepath.Clean(selected.selection) != selected.selection || len(selected.selection) > 4096 || strings.ContainsAny(selected.selection, "\x00\r\n") {
			return installedClientRequest{}, invalid
		}
		// Explicit selection wins. The unused repository value supplies no authority.
		selected.repository = ""
	} else if !validRepositoryClientRoot(selected.repository) {
		return installedClientRequest{}, invalid
	}
	if worker {
		selected.operation += "-worker"
	}
	if jsonOutput {
		selected.operation += "-json"
	}
	return selected, nil
}

type installedClientSession interface {
	Exec(context.Context, string, string) error
	ExecRepository(context.Context, string, string) error
	Close() error
}

type installedClientRequestFailure struct {
	owner installedClientSession
	cause error
}

func (*installedClientRequestFailure) Error() string { return "installed_client_startup_failed" }

type installedClientPrepare func(context.Context, string) (installedClientSession, error)

func runInstalledClientRequest(ctx context.Context, args []string, prepare installedClientPrepare) (failure error) {
	selected, err := parseInstalledClientRequest(args)
	if err != nil {
		return err
	}
	owner, err := prepare(ctx, selected.id)
	if owner != nil {
		defer func() {
			if closeErr := owner.Close(); closeErr != nil {
				failure = &installedClientRequestFailure{owner: owner, cause: errors.Join(failure, closeErr)}
			}
		}()
	}
	if err != nil {
		return err
	}
	if owner == nil {
		return errors.New("installed_client_admission_invalid")
	}
	if selected.selection != "" {
		return owner.Exec(ctx, selected.operation, selected.selection)
	}
	return owner.ExecRepository(ctx, selected.operation, selected.repository)
}
