//go:build (linux || darwin) && agentmux_bootstrap_docker

package launcher

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

// Match only the complete admitted stderr diagnostic, never L04 text or
// descriptive substrings. Unconfirmed Docker failure is not occupied-port proof.
func composeFailureActionable(stderr []byte, category string) bool {
	var out RequestDiagnostic
	if protocol.DecodeClosedJSON(stderr, &out, 4096) != nil || !ValidRequestDiagnostic(out) {
		return false
	}
	return composeFailureDiagnosticActionable(out, category)
}

func composeFailureDiagnosticActionable(out RequestDiagnostic, category string) bool {
	if !ValidRequestDiagnostic(out) {
		return false
	}
	if category == "selection" {
		return out.Kind == "launcher-diagnostic" && out.Code == "docker_environment_conflict" && out.Action == "use_enrolled_selection"
	}
	if category == "port" {
		return out.Kind == "launcher-diagnostic" && out.Code == "selected_host_port_occupied" && out.Action == "resolve_selected_port_conflict"
	}
	return false
}

// The expected attempt comes from the exact creator-owned host, not from the
// candidate history document. The existing validator also enforces closed
// fields, relevance, failure meaning and the complete diagnostic representation.
func composeFailureHistoryActionable(raw []byte, expectedAttempt string, now time.Time, category string) bool {
	out, code := composeCLIFailureHistoryCode(raw, expectedAttempt, now)
	return code == "" && composeFailureDiagnosticActionable(out.Diagnostic, category)
}

func TestInstalledCLIFailureDiagnosticMatcherIsClosed(t *testing.T) {
	good := ProjectRequestDiagnostic(refusal("environment_conflict"))
	raw, err := json.Marshal(good)
	if err != nil || !composeFailureActionable(raw, "selection") {
		t.Fatal("exact admitted selection diagnostic rejected")
	}
	for _, mutate := range []func(*RequestDiagnostic){
		func(v *RequestDiagnostic) { v.Code = "unsupported" },
		func(v *RequestDiagnostic) { v.Message = "The selected port is unsupported." },
		func(v *RequestDiagnostic) { v.Action = "selected" },
		func(v *RequestDiagnostic) { v.Kind = "startup-status-observation" },
	} {
		bad := good
		mutate(&bad)
		raw, err := json.Marshal(bad)
		if err != nil || composeFailureActionable(raw, "selection") || composeFailureActionable(raw, "port") {
			t.Fatal("unapproved or substring diagnostic admitted")
		}
	}
	commandFailure, err := json.Marshal(ProjectRequestDiagnostic(refusal("command_failed")))
	if err != nil || composeFailureActionable(commandFailure, "port") {
		t.Fatal("unconfirmed command failure became occupied-port evidence")
	}
	port, err := json.Marshal(ProjectRequestDiagnostic(refusal("selected_host_port_occupied")))
	if err != nil || !composeFailureActionable(port, "port") || composeFailureActionable(port, "selection") {
		t.Fatal("exact selected-port diagnostic lost its category")
	}
}

func TestInstalledCLIPortHistoryMatcherIsClosed(t *testing.T) {
	now := time.Now().UTC()
	attempt := "attempt_" + strings.Repeat("a", 32)
	good := BootstrapTerminalHistory{SchemaVersion: "1.0.0", Kind: "bootstrap-terminal-history", Meaning: "previous_recorded_terminal_failure", InvocationID: attempt, CompletedAt: now.Add(-time.Second).Format(time.RFC3339Nano), Diagnostic: requestDiagnostic("selected_host_port_occupied"), RecordedCleanup: "unknown"}
	encode := func(value BootstrapTerminalHistory) []byte {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal("port history fixture encoding failed")
		}
		return raw
	}
	if !composeFailureHistoryActionable(encode(good), attempt, now, "port") {
		t.Fatal("exact creator-bound port history rejected")
	}
	for _, mutate := range []func(*BootstrapTerminalHistory){
		func(v *BootstrapTerminalHistory) { v.InvocationID = "attempt_" + strings.Repeat("b", 32) },
		func(v *BootstrapTerminalHistory) { v.CompletedAt = now.Add(time.Second).Format(time.RFC3339Nano) },
		func(v *BootstrapTerminalHistory) {
			v.CompletedAt = now.Add(-bootstrapHistoryRelevance - time.Second).Format(time.RFC3339Nano)
		},
		func(v *BootstrapTerminalHistory) { v.Kind = "startup-status-observation" },
		func(v *BootstrapTerminalHistory) { v.Diagnostic = requestDiagnostic("docker_command_failed") },
		func(v *BootstrapTerminalHistory) { v.Diagnostic.Action = "stop_occupant" },
		func(v *BootstrapTerminalHistory) {
			v.Diagnostic.Message = "private Docker stderr: address already in use"
		},
		func(v *BootstrapTerminalHistory) { v.RecordedCleanup = "complete" },
	} {
		bad := good
		mutate(&bad)
		if composeFailureHistoryActionable(encode(bad), attempt, now, "port") {
			t.Fatal("unqualified port history became actionable proof")
		}
	}
	for _, raw := range [][]byte{
		append([]byte(`{"kind":"bootstrap-terminal-history",`), encode(good)[1:]...),
		append([]byte(`{"unknown":true,`), encode(good)[1:]...),
		[]byte(`{"code":"selected_host_port_occupied"}`),
	} {
		if composeFailureHistoryActionable(raw, attempt, now, "port") {
			t.Fatal("unclosed port history became actionable proof")
		}
	}
}
