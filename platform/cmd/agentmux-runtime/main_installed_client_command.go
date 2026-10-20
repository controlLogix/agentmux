//go:build linux || darwin

package main

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/controlLogix/agentmux/platform/launcher"
)

// The first installed-client hop shares one budget through parsing, package
// admission, exec refusal and failure output. Successful exec replaces this
// process without installing signal handlers or changing inherited streams.
func runInstalledClientCommand(parent context.Context, args []string, output io.Writer) error {
	return runInstalledClientCommandWith(parent, args, output, runInstalledClient)
}

func runInstalledClientCommandWith(parent context.Context, args []string, output io.Writer, run func(context.Context, []string) error) error {
	if parent == nil {
		return errors.New("request_context_invalid")
	}
	total, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	failure := run(total, args)
	if failure == nil {
		return nil
	}
	return errors.Join(failure, writePreparationJSON(total, output, launcher.ProjectRequestDiagnostic(failure)))
}
