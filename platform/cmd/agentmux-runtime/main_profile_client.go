//go:build linux || darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/controlLogix/agentmux/platform/launcher"
)

type profileClientOptions struct{ profile, repository, operation string }

func parseProfileClient(args []string) (profileClientOptions, error) {
	var selected profileClientOptions
	if len(args) != 7 || args[0] != "profile-client" || args[1] != "--profile-id" || args[3] != "--repository-root" || args[5] != "--operation" {
		return selected, errors.New("profile_client_arguments_invalid")
	}
	selected = profileClientOptions{args[2], args[4], args[6]}
	if !regexp.MustCompile(`^profile_[0-9a-f]{32}$`).MatchString(selected.profile) || !validRepositoryClientRoot(selected.repository) {
		return profileClientOptions{}, errors.New("profile_client_arguments_invalid")
	}
	switch selected.operation {
	case "startup", "startup-json", "startup-worker", "startup-worker-json", "mcp", "mcp-worker", "dashboard", "claude-code-hook", "claude-code-hook-worker":
		return selected, nil
	default:
		return profileClientOptions{}, errors.New("profile_client_arguments_invalid")
	}
}

type profileClientOwner interface {
	ExecClient(context.Context, string) error
	Close() error
}

type profileClientResolve func(context.Context, string, string) (profileClientOwner, error)

type profileClientFailure struct {
	owner   profileClientOwner
	cause   error
	cleanup bool
}

func (*profileClientFailure) Error() string                { return "profile_client_setup_required" }
func (e *profileClientFailure) Format(s fmt.State, _ rune) { fmt.Fprint(s, e.Error()) }

func runProfileClient(ctx context.Context, args []string) error {
	return runProfileClientWith(ctx, args, func(ctx context.Context, id, repository string) (profileClientOwner, error) {
		owner, err := launcher.ResolveCentralProfile(ctx, id, repository)
		if owner == nil {
			return nil, err
		}
		return owner, err
	})
}

func runProfileClientWith(parent context.Context, args []string, resolve profileClientResolve) (failure error) {
	if parent == nil || parent.Err() != nil {
		return errors.New("request_context_invalid")
	}
	selected, err := parseProfileClient(args)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	owner, err := resolve(ctx, selected.profile, selected.repository)
	if owner != nil {
		// ExecClient rechecks and retains this same central admission until
		// direct process replacement. No path is printed and reinterpreted.
		defer func() {
			if closeErr := owner.Close(); closeErr != nil {
				failure = &profileClientFailure{owner: owner, cause: errors.Join(failure, closeErr), cleanup: true}
			}
		}()
	}
	if err != nil || owner == nil {
		return &profileClientFailure{owner: owner, cause: err}
	}
	if err := owner.ExecClient(ctx, selected.operation); err != nil {
		return &profileClientFailure{owner: owner, cause: err}
	}
	return nil
}

type profileClientCommandDiagnostic struct {
	SchemaVersion string `json:"schemaVersion"`
	Kind          string `json:"kind"`
	Code          string `json:"code"`
	Action        string `json:"action"`
	Message       string `json:"message"`
}

func profileClientDiagnostic(failure error) (profileClientCommandDiagnostic, bool) {
	owned, ok := failure.(*profileClientFailure)
	if !ok {
		return profileClientCommandDiagnostic{}, false
	}
	value := profileClientCommandDiagnostic{SchemaVersion: "1.0.0", Kind: "client-profile-diagnostic", Code: "setup_required", Action: "configure_registered_profile", Message: "Select a registered central profile and an already approved repository. No profile or instance was created."}
	if owned.cleanup {
		value.Code, value.Action = "profile_cleanup_pending", "inspect_profile_cleanup"
		value.Message = "Profile admission cleanup remains incomplete. Keep the original owner and inspect it before retrying."
	}
	return value, true
}

// The outer deadline includes parsing, admission and any failure output.
func runProfileClientCommand(parent context.Context, args []string, output io.Writer) error {
	return runProfileClientCommandWith(parent, args, output, runProfileClient)
}
func runProfileClientCommandWith(parent context.Context, args []string, output io.Writer, run func(context.Context, []string) error) error {
	if parent == nil {
		return errors.New("request_context_invalid")
	}
	total, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	failure := run(total, args)
	if failure == nil {
		return nil
	}
	diagnostic, ok := profileClientDiagnostic(failure)
	if !ok {
		diagnostic = profileClientCommandDiagnostic{SchemaVersion: "1.0.0", Kind: "client-profile-diagnostic", Code: "setup_required", Action: "configure_registered_profile", Message: "Select a registered central profile and an already approved repository. No profile or instance was created."}
	}
	return errors.Join(failure, writePreparationJSON(total, output, diagnostic))
}

// runProfileCore preserves the original central owner through the installed handoff.
func runProfileCore(parent context.Context, args []string) error {
	return runProfileCoreWith(parent, args, func(ctx context.Context, id, repository string) (profileCoreOwner, error) {
		owner, err := launcher.ResolveCentralProfile(ctx, id, repository)
		if owner == nil {
			return nil, err
		}
		return owner, err
	})
}

type profileCoreOwner interface {
	profileClientOwner
	ExecCoreClient(context.Context, []string) error
}

func runProfileCoreWith(parent context.Context, args []string, resolve func(context.Context, string, string) (profileCoreOwner, error)) (failure error) {
	if parent == nil || len(args) < 7 || args[0] != "profile-core" || args[1] != "--profile-id" ||
		args[3] != "--repository-root" || args[5] != "--" ||
		!regexp.MustCompile(`^profile_[0-9a-f]{32}$`).MatchString(args[2]) || !validRepositoryClientRoot(args[4]) {
		return errors.New("profile_client_arguments_invalid")
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	owner, err := resolve(ctx, args[2], args[4])
	if owner != nil {
		defer func() {
			if closeErr := owner.Close(); closeErr != nil {
				failure = &profileClientFailure{owner: owner, cause: errors.Join(failure, closeErr), cleanup: true}
			}
		}()
	}
	if err != nil || owner == nil {
		return &profileClientFailure{owner: owner, cause: err}
	}
	if err := owner.ExecCoreClient(ctx, args[6:]); err != nil {
		return &profileClientFailure{owner: owner, cause: err}
	}
	return nil
}
