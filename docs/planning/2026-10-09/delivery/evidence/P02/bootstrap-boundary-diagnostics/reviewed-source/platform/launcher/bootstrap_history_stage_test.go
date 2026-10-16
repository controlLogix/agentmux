//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBootstrapHistoryBoundaryStageRoundTrip(t *testing.T) {
	for _, stage := range []string{"initial_warm_inspection", "post_lease_inspection", "broker_start"} {
		t.Run(stage, func(t *testing.T) {
			first, op, f, lease, binding := historyFixture(t)
			enterHistoryFixture(t, first, op, f)
			if op.complete(nil, bootstrapBoundaryFailure(stage, refusal("command_failed"))) != nil || first.RecordTerminal(op.startup) != nil {
				t.Fatal("stage_terminal_publication_failed")
			}
			raw, _, err := readHistoryFile(op.startup, first.root, first.binding.OwnerUID)
			if err != nil {
				t.Fatal("stage_terminal_read_failed")
			}
			record, err := decodeBootstrapHistory(raw, time.Now().UTC())
			if err != nil || record.LatestAttempt.Terminal.DiagnosticStage == nil || *record.LatestAttempt.Terminal.DiagnosticStage != stage {
				t.Fatal("stage_roundtrip_failed")
			}
			relevant := historyRelevantFailure(record, time.Now().UTC())
			if relevant == nil || relevant.DiagnosticStage == nil || *relevant.DiagnosticStage != stage {
				t.Fatal("creator_relevant_conversion_lost_stage")
			}
			public, err := terminalHistory(relevant, time.Now().UTC())
			if err != nil {
				t.Fatal("public_conversion_failed")
			}
			var fields map[string]any
			if json.Unmarshal(mustStatusJSON(public), &fields) != nil || len(fields) != 7 {
				t.Fatal("public_history_shape_changed")
			}
			if strings.Contains(string(mustStatusJSON(public)), "diagnosticStage") || strings.Contains(string(mustStatusJSON(public)), stage) {
				t.Fatal("private_stage_entered_serialized_nested_public_history")
			}
			if _, present := fields["diagnosticStage"]; present {
				t.Fatal("private_stage_exposed")
			}
			invalid := record
			terminal := *record.LatestAttempt.Terminal
			unknown := "future_stage"
			terminal.DiagnosticStage = &unknown
			invalid.LatestAttempt.Terminal = &terminal
			if _, err := decodeBootstrapHistory(mustStatusJSON(invalid), time.Now().UTC()); err == nil {
				t.Fatal("unknown_latest_stage_accepted")
			}
			terminal = *record.LatestAttempt.Terminal
			terminal.Outcome = "completed"
			terminal.DiagnosticCode = nil
			invalid.LatestAttempt.Terminal = &terminal
			if _, err := decodeBootstrapHistory(mustStatusJSON(invalid), time.Now().UTC()); err == nil {
				t.Fatal("completed_stage_accepted")
			}
			legacy := record
			terminal = *record.LatestAttempt.Terminal
			terminal.DiagnosticStage = nil
			legacy.LatestAttempt.Terminal = &terminal
			if _, err := decodeBootstrapHistory(mustStatusJSON(legacy), time.Now().UTC()); err != nil {
				t.Fatal("legacy_absent_stage_rejected")
			}
			if first.Close(op.startup) != nil || lease.Close() != nil {
				t.Fatal("first_stage_owner_close_failed")
			}
			general, err := readBootstrapHistory(op.startup, f.owner, binding.RuntimeDigest)
			if err != nil || general == nil || general.DiagnosticStage == nil || *general.DiagnosticStage != stage {
				t.Fatal("general_reader_lost_stage")
			}
			nextLease, err := AcquireBootstrapLock(op.startup, f.profile.ProfileDirectory, f.profile.InstanceID, "owner-status-service")
			if err != nil {
				t.Fatal("next_service_lease_failed")
			}
			defer func() {
				if nextLease.Close() != nil {
					t.Error("next_service_lease_close_failed")
				}
			}()
			next, err := newBootstrapOperation(op.startup, op.lifetime, op.server, nextLease, "attempt_"+strings.Repeat("b", 32))
			if err != nil {
				t.Fatal("next_stage_operation_failed")
			}
			binding.ColdInvocationID = next.attemptID
			second, err := openBootstrapHistory(op.startup, next, binding)
			if second != nil {
				defer func() {
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					if second.Close(ctx) != nil {
						t.Error("second_stage_owner_close_failed")
					}
				}()
			}
			if err != nil || next.enter(next.startup, f.config, f.profile, next.attemptID) != nil || second.Begin(next.startup) != nil {
				t.Fatal("stage_rollover_failed")
			}
			raw, _, err = readHistoryFile(next.startup, second.root, second.binding.OwnerUID)
			if err != nil {
				t.Fatal("rollover_read_failed")
			}
			record, err = decodeBootstrapHistory(raw, time.Now().UTC())
			if err != nil || record.PreviousFailure == nil || record.PreviousFailure.DiagnosticStage == nil || *record.PreviousFailure.DiagnosticStage != stage {
				t.Fatal("previous_failure_lost_stage")
			}
			record.PreviousFailure.DiagnosticStage = &unknown
			if _, err := decodeBootstrapHistory(mustStatusJSON(record), time.Now().UTC()); err == nil {
				t.Fatal("unknown_previous_stage_accepted")
			}
		})
	}
}
