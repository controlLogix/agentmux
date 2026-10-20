//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/launcher"
)

func TestDoctorCommandRequiresExplicitEnrollment(t *testing.T) {
	args := []string{"doctor", "--host-policy", "/private/host-policy.json", "--workspace", "/work"}
	parsed, err := parse(args)
	if err != nil || parsed.operation != "doctor" {
		t.Fatal("explicit doctor command rejected")
	}
	for _, invalid := range [][]string{{"doctor"}, append(append([]string(nil), args...), "--invocation-id", "attempt_"+strings.Repeat("a", 32))} {
		if _, err := parse(invalid); err == nil {
			t.Fatal("doctor accepted missing enrollment or a host invocation")
		}
	}
	args[2] = t.TempDir() + "/absent-policy.json"
	var output bytes.Buffer
	if run(context.Background(), args, &output) == nil || output.Len() != 0 {
		t.Fatal("doctor bypassed private policy admission or invented a report")
	}
}

func TestDoctorOutputPreservesUnknownChecksAndFailsIncomplete(t *testing.T) {
	report := launcher.DoctorReport{Scope: "Read-only diagnostics; not application readiness or phase acceptance.",
		Checks: []launcher.DoctorCheck{{Name: "broker", Status: launcher.DoctorUnknown, Code: launcher.DoctorNotProbed}}}
	var output bytes.Buffer
	if emitDoctor(&output, report) == nil {
		t.Fatal("incomplete diagnostic returned success")
	}
	var decoded launcher.DoctorReport
	if json.Unmarshal(output.Bytes(), &decoded) != nil || decoded.DiagnosticsPassed || len(decoded.Checks) != 1 || decoded.Checks[0].Status != launcher.DoctorUnknown {
		t.Fatal("incomplete report lost its unknown result")
	}
	output.Reset()
	if emitRequestDiagnostic(&output, errDoctorChecksIncomplete) != nil || !strings.Contains(output.String(), `"action":"read_doctor_checks"`) {
		t.Fatal("incomplete checks lost their safe recovery action")
	}
	ctx, cancel := frontendTotalContext(context.Background(), "doctor", time.Now())
	defer cancel()
	deadline, _ := ctx.Deadline()
	if time.Until(deadline) > 5*time.Second {
		t.Fatal("doctor exceeds the five-second frontend budget")
	}
}

type fixtureDoctorPolicy struct {
	report launcher.DoctorReport
	err    error
	called bool
	cancel context.CancelFunc
}

func (p *fixtureDoctorPolicy) Doctor(context.Context) (launcher.DoctorReport, error) {
	p.called = true
	if p.cancel != nil {
		p.cancel()
	}
	return p.report, p.err
}

func TestClientDoctorRequiresAdmittedPolicyAndClosedSelection(t *testing.T) {
	for _, client := range []string{"sh", "codex --version", "../claude"} {
		policy := &fixtureDoctorPolicy{}
		var output bytes.Buffer
		if runDoctorWithClient(context.Background(), policy, client, &output) == nil || policy.called || output.Len() != 0 {
			t.Fatal("invalid selection reached enrollment or emitted data")
		}
	}
	policy := &fixtureDoctorPolicy{err: errors.New("fixture admission refused")}
	var output bytes.Buffer
	if runDoctorWithClient(context.Background(), policy, "codex", &output) == nil || !policy.called || output.Len() != 0 {
		t.Fatal("client probes bypassed failed admission")
	}
}

func TestClientDoctorNoSelectionKeepsOriginalReport(t *testing.T) {
	policy := &fixtureDoctorPolicy{report: launcher.DoctorReport{DiagnosticsPassed: true, Scope: "fixture"}}
	var output, original bytes.Buffer
	if runDoctorWithClient(context.Background(), policy, "", &output) != nil || emitDoctor(&original, policy.report) != nil {
		t.Fatal("unselected doctor changed success")
	}
	if output.String() != original.String() {
		t.Fatal("unselected doctor changed the report contract")
	}
}

func TestClientDoctorOutputCannotPromoteUnknownClient(t *testing.T) {
	var output bytes.Buffer
	base := launcher.DoctorReport{DiagnosticsPassed: true, Checks: []launcher.DoctorCheck{{Name: "profile", Status: launcher.DoctorPassed, Code: launcher.DoctorObserved}}}
	client := launcher.ClientDoctorReport{DiagnosticsPassed: false}
	if !errors.Is(emitDoctorWithClient(&output, base, client), errDoctorChecksIncomplete) {
		t.Fatal("unknown client diagnostics returned success")
	}
	var decoded map[string]json.RawMessage
	if json.Unmarshal(output.Bytes(), &decoded) != nil || decoded["clientDiagnostics"] == nil || decoded["checks"] == nil {
		t.Fatal("client report lost base diagnostics or client contribution")
	}
}

func TestClientDoctorRetainsSharedDeadlineAfterAdmission(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	policy := &fixtureDoctorPolicy{report: launcher.DoctorReport{DiagnosticsPassed: true}, cancel: cancel}
	var output bytes.Buffer
	if !errors.Is(runDoctorWithClient(ctx, policy, "codex", &output), errDoctorChecksIncomplete) {
		t.Fatal("expired admission promoted client readiness")
	}
	var decoded struct {
		DiagnosticsPassed bool `json:"diagnosticsPassed"`
	}
	if json.Unmarshal(output.Bytes(), &decoded) != nil || decoded.DiagnosticsPassed {
		t.Fatal("selected incomplete client diagnostics changed aggregate success")
	}
}

func TestClientDoctorCLISelectionPreservesEnrollmentBoundary(t *testing.T) {
	policy := t.TempDir() + "/absent-policy.json"
	for _, client := range []string{"claude", "codex", "pi", "claude-desktop"} {
		args := []string{"doctor", "--host-policy", policy, "--workspace", "/fixture/work space", "--client", client}
		parsed, err := parse(args)
		if err != nil || parsed.client != client {
			t.Fatal("closed client selection was not preserved")
		}
		var output bytes.Buffer
		if run(context.Background(), args, &output) == nil || output.Len() != 0 {
			t.Fatal("selected client bypassed enrollment or emitted a report before admission")
		}
	}
	for _, args := range [][]string{
		{"doctor", "--host-policy", policy, "--workspace", "/fixture", "--client", ""},
		{"doctor", "--host-policy", policy, "--workspace", "/fixture", "--client", "codex --help"},
		{"start", "--host-policy", policy, "--workspace", "/fixture", "--client", "codex"},
	} {
		if _, err := parse(args); err == nil {
			t.Fatal("invalid client option accepted")
		}
	}
}
