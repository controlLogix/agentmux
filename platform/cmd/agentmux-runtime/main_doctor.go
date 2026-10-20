//go:build linux || darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/controlLogix/agentmux/platform/launcher"
)

var errDoctorChecksIncomplete = errors.New("doctor_checks_incomplete")

func emitDoctor(output io.Writer, report launcher.DoctorReport) error {
	if err := json.NewEncoder(output).Encode(report); err != nil {
		return errors.New("output_failed")
	}
	if !report.DiagnosticsPassed {
		return errDoctorChecksIncomplete
	}
	return nil
}

// doctorPolicy remains an internal boundary after private policy admission.
// Client checks cannot bypass a failed enrollment or choose command arguments.
type doctorPolicy interface {
	Doctor(context.Context) (launcher.DoctorReport, error)
}

// runDoctorWithClient adds opt-in client prerequisites within the existing
// frontend deadline. With no selected client the original report is unchanged.
func runDoctorWithClient(ctx context.Context, policy doctorPolicy, client string, output io.Writer) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("request_context_invalid")
	}
	if client != "" && !launcher.ValidClientDoctorID(client) {
		return errors.New("arguments_invalid")
	}
	report, err := policy.Doctor(ctx)
	if err != nil {
		return err
	}
	if client == "" {
		return emitDoctor(output, report)
	}
	clients := launcher.RunClientDoctor(ctx, client)
	return emitDoctorWithClient(output, report, clients)
}

func emitDoctorWithClient(output io.Writer, report launcher.DoctorReport, client launcher.ClientDoctorReport) error {
	report.DiagnosticsPassed = report.DiagnosticsPassed && client.DiagnosticsPassed
	combined := struct {
		launcher.DoctorReport
		ClientDiagnostics launcher.ClientDoctorReport `json:"clientDiagnostics"`
	}{report, client}
	if err := json.NewEncoder(output).Encode(combined); err != nil {
		return errors.New("output_failed")
	}
	if !report.DiagnosticsPassed || !client.DiagnosticsPassed {
		return errDoctorChecksIncomplete
	}
	return nil
}
