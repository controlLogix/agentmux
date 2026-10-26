//go:build darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/controlLogix/agentmux/platform/appruntime"
)

const applicationRuntimeCommandLimit = 30 * time.Second

type applicationRuntimeRequest struct {
	operation string
	directory string
	inputs    appruntime.Inputs
}

// The explicit local owner of this installation's application NATS runtime.
// It never touches the protected infrastructure broker or another user's data.
func parseApplicationRuntime(args []string) (applicationRuntimeRequest, error) {
	invalid := func() (applicationRuntimeRequest, error) {
		return applicationRuntimeRequest{}, errors.New("application_runtime_arguments_invalid")
	}
	if len(args) < 2 || len(args) > 8 || args[0] != "application-runtime" {
		return invalid()
	}
	for _, arg := range args {
		if len(arg) > 4096 || strings.ContainsRune(arg, 0) {
			return invalid()
		}
	}
	request := applicationRuntimeRequest{operation: args[1]}
	flags := flag.NewFlagSet("application-runtime", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var server, port, directory string
	serverFlag := singleApplicationFlag{value: &server}
	portFlag := singleApplicationFlag{value: &port}
	directoryFlag := singleApplicationFlag{value: &directory}
	flags.Var(&serverFlag, "nats-server", "Absolute path of the pinned native nats-server "+appruntime.NATSVersion)
	flags.Var(&portFlag, "port", "Loopback port fixed at first initialization")
	flags.Var(&directoryFlag, "directory", "Explicit private runtime directory; defaults to the per-user location")
	if flags.Parse(args[2:]) != nil || flags.NArg() != 0 {
		return invalid()
	}
	if directoryFlag.present {
		if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
			return invalid()
		}
		request.directory = directory
	}
	switch request.operation {
	case "init":
		request.inputs.NATSServer = server
		if portFlag.present {
			value, err := strconv.Atoi(port)
			if err != nil || value < 1024 || value > 65535 {
				return invalid()
			}
			request.inputs.Port = value
		}
	case "start", "stop", "status":
		if serverFlag.present || portFlag.present {
			return invalid()
		}
	default:
		return invalid()
	}
	return request, nil
}

type applicationRuntimeOutput struct {
	SchemaVersion string               `json:"schemaVersion"`
	Kind          string               `json:"kind"`
	Operation     string               `json:"operation"`
	Outcome       string               `json:"outcome"`
	RuntimeID     string               `json:"runtimeId,omitempty"`
	Endpoint      string               `json:"endpoint,omitempty"`
	PID           int                  `json:"pid,omitempty"`
	Manifest      *appruntime.Manifest `json:"manifest,omitempty"`
}

func runApplicationRuntime(ctx context.Context, args []string, output io.Writer) error {
	request, err := parseApplicationRuntime(args)
	if err != nil {
		return err
	}
	path := request.directory
	if path == "" {
		if path, err = appruntime.DefaultDirectory(); err != nil {
			return err
		}
	}
	result := applicationRuntimeOutput{SchemaVersion: appruntime.SchemaVersion, Kind: "application-runtime-result", Operation: request.operation}
	switch request.operation {
	case "init":
		initialized, err := appruntime.Initialize(ctx, path, request.inputs)
		if err != nil {
			return err
		}
		result.Outcome, result.RuntimeID, result.Endpoint = initialized.Outcome, initialized.Manifest.RuntimeID, initialized.Manifest.Endpoint
		result.Manifest = &initialized.Manifest
	default:
		operation := map[string]func(context.Context, string) (appruntime.Status, error){
			"start": appruntime.Start, "stop": appruntime.Stop, "status": appruntime.Observe}[request.operation]
		status, err := operation(ctx, path)
		if err != nil {
			return err
		}
		result.Outcome, result.RuntimeID, result.Endpoint, result.PID = status.State, status.RuntimeID, status.Endpoint, status.PID
	}
	return json.NewEncoder(output).Encode(result)
}

// Only closed lifecycle codes reach stderr; paths and causes stay private.
func writeApplicationRuntimeDiagnostic(output io.Writer, failure error) error {
	code := "application_runtime_failed"
	for _, known := range []error{appruntime.ErrBusy, appruntime.ErrAmbiguous, appruntime.ErrConflict, appruntime.ErrInputs,
		appruntime.ErrUnsafePath, appruntime.ErrServer, appruntime.ErrNotInitialized, appruntime.ErrPortInUse,
		appruntime.ErrNotReady, appruntime.ErrStopUncertain, appruntime.ErrRunningUnready} {
		if errors.Is(failure, known) {
			code = known.Error()
		}
	}
	if failure != nil && failure.Error() == "application_runtime_arguments_invalid" {
		code = failure.Error()
	}
	return json.NewEncoder(output).Encode(map[string]string{"schemaVersion": appruntime.SchemaVersion,
		"kind": "application-runtime-diagnostic", "code": code})
}
