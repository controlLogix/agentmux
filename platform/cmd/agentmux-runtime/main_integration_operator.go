//go:build linux || darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/controlLogix/agentmux/platform/internal/wirejson"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/launcher"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

const integrationOperatorRequestLimit = 65536

type integrationOperatorInput struct {
	SchemaVersion       string          `json:"schemaVersion"`
	Kind                string          `json:"kind"`
	OriginalOperationID string          `json:"originalOperationId"`
	ResolutionRequest   json.RawMessage `json:"resolutionRequest"`
}

type integrationOperatorOptions struct {
	policy, installation, selection, digest, custody string
	workspaces                                       workspaces
}

func decodeIntegrationOperatorInput(raw []byte) (integrationOperatorInput, error) {
	invalid := func() (integrationOperatorInput, error) {
		return integrationOperatorInput{}, errors.New("integration_operator_request_invalid")
	}
	if wirejson.Validate(raw, integrationOperatorRequestLimit) != nil {
		return invalid()
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 4 {
		return invalid()
	}
	for _, name := range []string{"schemaVersion", "kind", "originalOperationId", "resolutionRequest"} {
		if _, ok := fields[name]; !ok {
			return invalid()
		}
	}
	var command integrationOperatorInput
	if json.Unmarshal(raw, &command) != nil ||
		command.SchemaVersion != protocol.Version || command.Kind != "integration-effect-provision-request" ||
		!regexp.MustCompile(`^[a-z][a-z0-9_-]{0,95}$`).MatchString(command.OriginalOperationID) ||
		len(command.ResolutionRequest) == 0 || len(command.ResolutionRequest) > integrationOperatorRequestLimit {
		return invalid()
	}
	return command, nil
}

func parseIntegrationOperator(args []string) (integrationOperatorOptions, error) {
	invalid := func() (integrationOperatorOptions, error) {
		return integrationOperatorOptions{}, errors.New("integration_operator_arguments_invalid")
	}
	if len(args) < 13 || args[0] != "provision-integration-effect" {
		return invalid()
	}
	var options integrationOperatorOptions
	flags := flag.NewFlagSet("provision-integration-effect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.policy, "host-policy", "", "Private installed host policy")
	flags.Var(&options.workspaces, "workspace", "Explicit workspace root")
	flags.StringVar(&options.installation, "application-services-installation", "", "Protected package")
	flags.StringVar(&options.selection, "application-services-selection", "", "Protected selection")
	flags.StringVar(&options.digest, "application-services-selection-sha256", "", "Selection digest")
	flags.StringVar(&options.custody, "custody-root", "", "Protected secret custody")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || options.policy == "" ||
		len(options.workspaces) == 0 || len(options.workspaces) > 16 ||
		!protected.ValidClientInstallationID(options.installation) ||
		!filepath.IsAbs(options.selection) || filepath.Clean(options.selection) != options.selection ||
		!filepath.IsAbs(options.custody) || filepath.Clean(options.custody) != options.custody ||
		!ownerPreparationDigest.MatchString(options.digest) {
		return invalid()
	}
	for _, value := range append([]string{options.policy, options.selection, options.custody}, options.workspaces...) {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value || len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
			return invalid()
		}
	}
	return options, nil
}

func runIntegrationOperator(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	options, err := parseIntegrationOperator(args)
	if err != nil || ctx == nil || ctx.Err() != nil || input == nil || output == nil {
		return errors.Join(errors.New("integration_operator_request_invalid"), err)
	}
	request, err := io.ReadAll(io.LimitReader(input, integrationOperatorRequestLimit+1))
	if err != nil || len(request) == 0 || len(request) > integrationOperatorRequestLimit {
		return errors.New("integration_operator_request_invalid")
	}
	command, err := decodeIntegrationOperatorInput(request)
	if err != nil {
		return err
	}
	host, err := launcher.LoadEnrolledHostPolicy(launcher.HostPolicySelection{
		Path: options.policy, OwnerUID: uint32(os.Geteuid()),
		WorkspaceRoots: append([]string(nil), options.workspaces...)})
	if err != nil {
		return err
	}
	return host.ProvisionIntegrationEffect(ctx, launcher.ApplicationServiceProcessSelection{
		InstallationID: options.installation, Path: options.selection,
		SHA256: options.digest}, options.custody, command.OriginalOperationID,
		command.ResolutionRequest, output)
}
