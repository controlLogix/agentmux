//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBootstrapFailedReadActualOwnedExecutor(t *testing.T) {
	t.Setenv("DOCKER_CONTEXT", "")
	t.Setenv("DOCKER_HOST", "")
	executable := filepath.Join(t.TempDir(), "fixed-read")
	if os.WriteFile(executable, []byte("#!/bin/sh\nexit 7\n"), 0700) != nil {
		t.Fatal("owned_executor_fixture_failed")
	}
	d := &Docker{config: DockerConfig{Executable: executable, Context: "fixed", Timeout: time.Second}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, failure := d.runFixedRead(ctx, "version", nil, "version", "--format", dockerVersionReadFormat)
	metric := bootstrapFailedReadFromError(failure)
	if failure == nil || failure.Error() != "docker_command_failed" || metric == nil || metric.Kind != "version" || !validBootstrapFailedRead(metric) || ctx.Err() != nil {
		t.Fatal("actual_joined_read_failure_metric_missing")
	}
	// A failed version read is an engine check whose cause is unconfirmed.
	if got := ProjectRequestDiagnostic(failure); got.Code != "docker_engine_check_failed" || !ValidRequestDiagnostic(got) {
		t.Fatal("public_diagnostic_changed")
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if fmt.Sprintf(format, failure) != failure.Error() {
			t.Fatal("private_metric_format_leak")
		}
	}
	b, err := json.Marshal(failure)
	if err != nil || string(b) != "{}" {
		t.Fatal("private_metric_json_leak")
	}
}

func TestBootstrapFailedReadClosedBoundsAndGraph(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	original := refusal("command_failed")
	valid := failedDockerRead("roster", ctx, time.Now(), time.Second, time.Second, original)
	if !errors.Is(valid, original) || bootstrapFailedReadFromError(valid) == nil {
		t.Fatal("original_cause_lost")
	}
	for name, failure := range map[string]error{
		"opaque":             unknownBoundaryGraffiti{},
		"text":               errors.New("roster elapsedNanoseconds"),
		"mutation":           failedDockerRead("compose_up", ctx, time.Now(), time.Second, time.Second, original),
		"zero_effective_cap": failedDockerRead("version", ctx, time.Now(), time.Second, 0, original),
		"over_command_cap":   failedDockerRead("version", ctx, time.Now(), 5*time.Second, 5*time.Second, original),
		"cap_exceeds_parent": failedDockerRead("version", ctx, time.Now(), time.Second, 2*time.Second, original),
		"absent_budget":      failedDockerRead("version", ctx, time.Now(), 0, time.Second, original),
		"invalid_budget":     failedDockerRead("version", ctx, time.Now(), 61*time.Second, time.Second, original),
		"expired_elapsed":    failedDockerRead("version", ctx, time.Now().Add(-121*time.Second), time.Second, time.Second, original),
	} {
		t.Run(name, func(t *testing.T) {
			if bootstrapFailedReadFromError(failure) != nil {
				t.Fatal("unqualified_metric_accepted")
			}
		})
	}
	oversized := make([]error, 65)
	for i := range oversized {
		oversized[i] = valid
	}
	if bootstrapFailedReadFromError(errors.Join(oversized...)) != nil {
		t.Fatal("metric_graph_bound_changed")
	}
	conflicting := failedDockerRead("version", ctx, time.Now(), time.Second, time.Second, original)
	if bootstrapFailedReadFromError(errors.Join(valid, conflicting)) != nil {
		t.Fatal("ambiguous_metric_accepted")
	}
	public, err := terminalHistory(&bootstrapHistoryFailure{InvocationID: "attempt_" + strings.Repeat("a", 32), CompletedAt: historyTimestamp(time.Now().UTC()), DiagnosticCode: "request_failed", Cleanup: "unknown", FailedRead: bootstrapFailedReadFromError(valid)}, time.Now().UTC())
	if err != nil || strings.Contains(string(mustStatusJSON(public)), "failedRead") {
		t.Fatal("metric_public_projection_leak")
	}
}
