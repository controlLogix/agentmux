//go:build linux && agentmux_bootstrap_docker

package launcher

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

// History is a record of a past failure. It must never pass as a receipt or
// current readiness, and this fixture requires the actual creator's attempt.
func composeCLIFailureHistoryCode(raw []byte, expectedAttempt string, now time.Time) (BootstrapTerminalHistory, string) {
	var out BootstrapTerminalHistory
	var fields map[string]json.RawMessage
	if len(raw) == 0 || len(raw) > 64*1024 || json.Unmarshal(raw, &fields) != nil || len(fields) != 7 || protocol.DecodeClosedJSON(raw, &out, 64*1024) != nil {
		return out, "cli_history_shape_invalid"
	}
	if out.SchemaVersion != "1.0.0" || out.Kind != "bootstrap-terminal-history" || out.Meaning != "previous_recorded_terminal_failure" || !ownerBridgeInvocation.MatchString(expectedAttempt) || out.InvocationID != expectedAttempt {
		return out, "cli_history_attempt_invalid"
	}
	expected, err := terminalHistory(&bootstrapHistoryFailure{InvocationID: out.InvocationID, CompletedAt: out.CompletedAt, DiagnosticCode: out.Diagnostic.Code, Cleanup: out.RecordedCleanup}, now)
	if err != nil || expected == nil || !reflect.DeepEqual(*expected, out) {
		return out, "cli_history_record_invalid"
	}
	return out, ""
}

func TestComposeCLIFailureHistoryIsExact(t *testing.T) {
	now := time.Now().UTC()
	attempt := "attempt_" + strings.Repeat("a", 32)
	good := BootstrapTerminalHistory{SchemaVersion: "1.0.0", Kind: "bootstrap-terminal-history", Meaning: "previous_recorded_terminal_failure", InvocationID: attempt, CompletedAt: now.Add(-time.Second).Format(time.RFC3339Nano), Diagnostic: requestDiagnostic("docker_command_failed"), RecordedCleanup: "unknown"}
	encode := func(v BootstrapTerminalHistory) []byte {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if _, code := composeCLIFailureHistoryCode(encode(good), attempt, now); code != "" {
		t.Fatal("valid failed attempt refused", code)
	}
	for _, tc := range []struct {
		name   string
		change func(*BootstrapTerminalHistory)
	}{
		{"receipt", func(v *BootstrapTerminalHistory) { v.Kind = "bootstrap-progress" }},
		{"different_attempt", func(v *BootstrapTerminalHistory) { v.InvocationID = "attempt_" + strings.Repeat("b", 32) }},
		{"current_meaning", func(v *BootstrapTerminalHistory) { v.Meaning = "current_ready" }},
		{"future", func(v *BootstrapTerminalHistory) { v.CompletedAt = now.Add(time.Second).Format(time.RFC3339Nano) }},
		{"completed_cleanup", func(v *BootstrapTerminalHistory) { v.RecordedCleanup = "complete" }},
		{"altered_diagnostic", func(v *BootstrapTerminalHistory) { v.Diagnostic.Message = "Private engine output" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := good
			tc.change(&v)
			if _, code := composeCLIFailureHistoryCode(encode(v), attempt, now); code == "" {
				t.Fatal("invalid history accepted")
			}
		})
	}
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"duplicate", append([]byte(`{"kind":"bootstrap-terminal-history",`), encode(good)[1:]...)},
		{"unknown", append([]byte(`{"extra":true,`), encode(good)[1:]...)},
		{"oversized", []byte(strings.Repeat(" ", 64*1024+1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, code := composeCLIFailureHistoryCode(tc.raw, attempt, now); code == "" {
				t.Fatal("invalid history shape accepted")
			}
		})
	}
}
