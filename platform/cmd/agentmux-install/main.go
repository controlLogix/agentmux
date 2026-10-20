// agentmux-install verifies and explicitly installs a selected native release.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"github.com/controlLogix/agentmux/platform/installer"
	"github.com/controlLogix/agentmux/platform/launcher"
)

type workspaces []string

func (w *workspaces) String() string         { return "explicit workspace roots" }
func (w *workspaces) Set(value string) error { *w = append(*w, value); return nil }

func run(parent context.Context, args []string, output io.Writer) error {
	if parent == nil || len(args) == 0 {
		return errors.New("installer_command_invalid")
	}
	operation := args[0]
	if operation != "verify" && operation != "install" && operation != "check" && operation != "install-launcher" && operation != "verify-client" && operation != "install-client" {
		return errors.New("installer_command_invalid")
	}
	flags := flag.NewFlagSet("agentmux-install", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var path, digest, hostPolicy, replaceLauncher string
	var owner uint64
	var roots workspaces
	flags.StringVar(&path, "selection", "", "Explicit private installation selection")
	flags.StringVar(&digest, "selection-sha256", "", "Separately retained selection digest")
	flags.Uint64Var(&owner, "owner-uid", uint64(os.Geteuid()), "Owner of the private installation selection")
	flags.StringVar(&replaceLauncher, "replace-launcher-sha256", "", "Explicit current launcher digest for replacement")
	flags.StringVar(&hostPolicy, "host-policy", "", "Existing private enrolled host policy")
	flags.Var(&roots, "workspace", "Explicit workspace root; may be repeated")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || owner == 0 || owner > 1<<32-1 {
		return errors.New("installer_command_invalid")
	}
	replaceRequested := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "replace-launcher-sha256" {
			replaceRequested = true
		}
	})
	if replaceRequested && operation != "install-launcher" {
		return errors.New("installer_command_invalid")
	}
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()
	var result any
	var err error
	if operation == "check" {
		if path != "" || digest != "" || hostPolicy == "" || len(roots) == 0 || owner != uint64(os.Geteuid()) {
			return errors.New("installer_command_invalid")
		}
		result, err = installer.CheckEnrollment(ctx, launcher.HostPolicySelection{Path: hostPolicy, OwnerUID: uint32(owner), WorkspaceRoots: roots})
	} else if operation == "verify-client" || operation == "install-client" {
		if path == "" || digest == "" || hostPolicy != "" || len(roots) != 0 {
			return errors.New("installer_command_invalid")
		}
		selected, readErr := installer.ReadClientSelection(ctx, path, digest, uint32(owner))
		if readErr != nil {
			return readErr
		}
		prepared, prepareErr := installer.PrepareClient(ctx, selected)
		if prepareErr != nil {
			return prepareErr
		}
		if operation == "verify-client" {
			result = prepared.Result("verified")
		} else {
			result, err = installer.InstallClient(ctx, prepared)
		}
	} else {
		if path == "" || digest == "" || hostPolicy != "" || len(roots) != 0 {
			return errors.New("installer_command_invalid")
		}
		selected, readErr := installer.ReadSelection(ctx, path, digest, uint32(owner))
		if readErr != nil {
			return readErr
		}
		prepared, prepareErr := installer.Prepare(ctx, selected)
		if prepareErr != nil {
			return prepareErr
		}
		if operation == "verify" {
			result = prepared.Result("verified")
		} else if operation == "install-launcher" {
			result, err = installer.InstallLauncher(ctx, prepared, replaceLauncher)
		} else {
			result, err = installer.Install(ctx, prepared)
		}
	}
	if err != nil {
		return err
	}
	if json.NewEncoder(output).Encode(result) != nil {
		return errors.New("installer_output_failed")
	}
	return nil
}

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		_ = json.NewEncoder(os.Stderr).Encode(installer.Diagnose(err))
		os.Exit(1)
	}
}
