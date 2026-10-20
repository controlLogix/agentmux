//go:build linux || darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/controlLogix/agentmux/platform/launcher"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

const centralProfileRegistrationLimit = 10 * time.Second

var centralRegistrationProfileID = regexp.MustCompile(`^profile_[0-9a-f]{32}$`)

// This explicit owner command registers already prepared enrollment. It does
// not select a repository, create a profile or invoke a startup operation.
func parseCentralProfileRegistration(args []string) (launcher.CentralProfileRegistrationRequest, error) {
	var request launcher.CentralProfileRegistrationRequest
	invalid := func() (launcher.CentralProfileRegistrationRequest, error) {
		return launcher.CentralProfileRegistrationRequest{}, errors.New("central_profile_registration_arguments_invalid")
	}
	if len(args) == 0 || len(args) > 43 || args[0] != "register-central-profile" {
		return invalid()
	}
	for _, arg := range args {
		if len(arg) > 4096 || strings.ContainsRune(arg, 0) {
			return invalid()
		}
	}
	flags := flag.NewFlagSet("register-central-profile", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var profile, client, environment, project string
	profileFlag := singleApplicationFlag{value: &profile}
	clientFlag := singleApplicationFlag{value: &client}
	environmentFlag := singleApplicationFlag{value: &environment}
	projectFlag := singleApplicationFlag{value: &project}
	var roots workspaces
	flags.Var(&profileFlag, "profile-id", "Explicit existing central profile ID")
	flags.Var(&clientFlag, "client-installation", "Explicit protected client installation ID")
	flags.Var(&roots, "workspace", "Already approved workspace root; repeat for each enrolled workspace")
	flags.Var(&environmentFlag, "environment", "Explicit environment display/context value")
	flags.Var(&projectFlag, "project", "Explicit project display/context value; does not grant project access")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || !profileFlag.present || !clientFlag.present || !centralRegistrationProfileID.MatchString(profile) || !protected.ValidClientInstallationID(client) || len(roots) == 0 || len(roots) > 16 || (!environmentFlag.present && !projectFlag.present) {
		return invalid()
	}
	seen := map[string]bool{}
	for _, root := range roots {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root || strings.IndexFunc(root, func(r rune) bool { return unicode.IsControl(r) }) >= 0 || seen[root] {
			return invalid()
		}
		seen[root] = true
	}
	for _, value := range []struct {
		present bool
		text    string
	}{{environmentFlag.present, environment}, {projectFlag.present, project}} {
		if value.present && (value.text == "" || len(value.text) > 128 || !utf8.ValidString(value.text) || strings.TrimSpace(value.text) != value.text || strings.IndexFunc(value.text, func(r rune) bool { return unicode.IsControl(r) || r == '\u2028' || r == '\u2029' }) >= 0) {
			return invalid()
		}
	}
	request.ProfileID = profile
	request.ClientInstallationID = client
	request.ApprovedWorkspaceRoots = append([]string(nil), roots...)
	if environmentFlag.present {
		request.Context.Environment = &environment
	}
	if projectFlag.present {
		request.Context.Project = &project
	}
	return request, nil
}

type centralRegistrationCommandOwner interface{ Close() error }
type centralRegistrationCommandRegister func(context.Context, launcher.CentralProfileRegistrationRequest) (centralRegistrationCommandOwner, error)

// Failure keeps the original owner when publication or cleanup is uncertain.
// The command must not close it implicitly, retry registration or claim that
// exiting the process repairs registration.json or an uncertain stage.
type centralRegistrationCommandFailure struct {
	owner   centralRegistrationCommandOwner
	cause   error
	outcome string
}

func (e *centralRegistrationCommandFailure) Error() string {
	return "central_profile_registration_" + e.outcome
}
func (e *centralRegistrationCommandFailure) Format(state fmt.State, _ rune) {
	fmt.Fprint(state, e.Error())
}
func (e *centralRegistrationCommandFailure) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.Error())
}

type centralRegistrationCommandResult struct {
	SchemaVersion string `json:"schemaVersion"`
	Kind          string `json:"kind"`
	Outcome       string `json:"outcome"`
	Action        string `json:"action"`
	Message       string `json:"message"`
}

func centralRegistrationResult(outcome string) centralRegistrationCommandResult {
	result := centralRegistrationCommandResult{"1.0.0", "central-profile-registration-result", outcome, "check_prepared_enrollment", "Registration was refused. Check the explicit owner-prepared profile, host policy, client selection and protected client installation. No startup readiness was observed."}
	switch outcome {
	case "registered":
		result.Action = "select_registered_profile"
		result.Message = "The existing central profile was registered. Startup readiness was not checked."
	case "review_required":
		result.Action = "inspect_registration_before_retry"
		result.Message = "Registration publication or cleanup is uncertain. Keep the original recovery owner and inspect the central registration and stage files before retrying. Process exit does not complete recovery."
	}
	return result
}

func runCentralProfileRegistration(parent context.Context, args []string, output io.Writer) error {
	return runCentralProfileRegistrationWith(parent, args, output, func(ctx context.Context, request launcher.CentralProfileRegistrationRequest) (centralRegistrationCommandOwner, error) {
		owner, err := launcher.RegisterCentralProfile(ctx, request)
		if owner == nil {
			return nil, err
		}
		return owner, err
	})
}
func runCentralProfileRegistrationWith(parent context.Context, args []string, output io.Writer, register centralRegistrationCommandRegister) error {
	if parent == nil || parent.Err() != nil || output == nil {
		return errors.New("request_context_invalid")
	}
	// One total budget includes parsing, admission, publication, close and output.
	total, cancel := context.WithTimeout(parent, centralProfileRegistrationLimit)
	defer cancel()
	request, err := parseCentralProfileRegistration(args)
	if err != nil {
		return err
	}
	work, cancelWork := frontendWorkContext(total)
	defer cancelWork()
	owner, failure := register(work, request)
	outcome := "registered"
	if failure != nil {
		outcome = "refused"
		if owner != nil {
			outcome = "review_required"
		}
	} else if owner == nil {
		outcome = "refused"
		failure = errors.New("central_profile_registration_owner_missing")
	} else if closeErr := owner.Close(); closeErr != nil {
		outcome = "review_required"
		failure = closeErr
	}
	result := centralRegistrationResult(outcome)
	if outputErr := writePreparationJSON(total, output, result); outputErr != nil {
		// Even confirmed registration may have reached disk before output failed.
		// Preserve its original owner and report an outcome that requires inspection.
		if outcome == "registered" {
			outcome = "review_required"
		}
		return &centralRegistrationCommandFailure{owner: owner, cause: errors.Join(failure, outputErr), outcome: outcome}
	}
	if failure != nil {
		return &centralRegistrationCommandFailure{owner: owner, cause: failure, outcome: outcome}
	}
	return nil
}

// The main diagnostic dispatcher can use this fixed response without invoking
// an arbitrary error's methods or exposing private paths and metadata.
func centralProfileRegistrationDiagnostic(failure error) (centralRegistrationCommandResult, bool) {
	failureOwner, ok := failure.(*centralRegistrationCommandFailure)
	if !ok {
		return centralRegistrationCommandResult{}, false
	}
	return centralRegistrationResult(failureOwner.outcome), true
}

// The caller supplies the outer command context, established before parsing.
// Reuse its remaining deadline and signal cancellation for terminal diagnostics;
// never start a fresh command budget after registration or stdout has failed.
func writeCentralProfileRegistrationDiagnostic(ctx context.Context, output io.Writer, failure error) error {
	if diagnostic, ok := centralProfileRegistrationDiagnostic(failure); ok {
		return writePreparationJSON(ctx, output, diagnostic)
	}
	return writePreparationJSON(ctx, output, launcher.ProjectRequestDiagnostic(failure))
}
