//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/launcher"
)

func TestFrontendHistoryBudgetKeepsOriginalReserve(t *testing.T) {
	for _, operation := range []string{"ensure", "status"} {
		t.Run(operation, func(t *testing.T) {
			entered := time.Now()
			total, cancel := frontendTotalContext(context.Background(), operation, entered)
			defer cancel()
			ctx, stop, err := frontendHistoryContext(total)
			if err != nil {
				t.Fatal("bounded history context unavailable")
			}
			defer stop()
			deadline, _ := ctx.Deadline()
			original, _ := total.Deadline()
			if deadline.After(original.Add(-frontendReceiptCleanupLimit-frontendHistoryOutputAllowance)) || time.Until(deadline) > frontendHistoryLimit {
				t.Fatal("history extended original deadline or consumed reserved cleanup")
			}
			cancel()
			if ctx.Err() == nil {
				t.Fatal("history detached original cancellation")
			}
		})
	}
	parent, cancel := context.WithDeadline(context.Background(), time.Now().Add(1300*time.Millisecond))
	defer cancel()
	if ctx, stop, err := frontendHistoryContext(parent); err == nil {
		stop()
		t.Fatal("exhausted reserved allowance admitted history", ctx)
	}
	if _, _, err := frontendHistoryContext(context.Background()); err == nil {
		t.Fatal("unbounded history admitted")
	}
}

func TestFrontendHistoryNeverMasksHardRequestFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, code := range []string{"owner_bridge_authority_rejected", "owner_bridge_reply_invalid", "host_policy_owner_enrollment_invalid", "owner_bridge_owned_connection_cleanup_failed", "owner_bridge_no_responders"} {
		var output bytes.Buffer
		if emitted, err := statusHistoryFallback(ctx, &output, nil, errors.New(code)); emitted || err != nil || output.Len() != 0 {
			t.Fatal("hard failure emitted general history")
		}
		if emitted, err := creatorHistoryFallback(ctx, &output, nil, nil, errors.New(code)); emitted || err != nil || output.Len() != 0 {
			t.Fatal("hard failure emitted creator history")
		}
	}
}

func TestFrontendHistoryKeepsNonzeroResultAndSeparateShape(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	failure := errors.New("owner_bridge_reply_unavailable")
	history := &launcher.BootstrapTerminalHistory{SchemaVersion: "1.0.0", Kind: "bootstrap-terminal-history", Meaning: "previous_recorded_terminal_failure", InvocationID: "attempt_" + strings.Repeat("a", 32), CompletedAt: time.Now().UTC().Format(time.RFC3339Nano), Diagnostic: launcher.ProjectRequestDiagnostic(context.DeadlineExceeded), RecordedCleanup: "unknown"}
	var output bytes.Buffer
	emitted, err := emitPreviousBootstrapFailure(ctx, &output, history, failure)
	if !emitted || err != failure || !bytes.Contains(output.Bytes(), []byte(`"kind":"bootstrap-terminal-history"`)) || bytes.Contains(output.Bytes(), []byte(`"disposition"`)) || bytes.Contains(output.Bytes(), []byte(`"instance"`)) {
		t.Fatal("history became successful current status or lost original failure")
	}
	if emitted, err := emitPreviousBootstrapFailure(ctx, io.Discard, nil, failure); emitted || err != nil {
		t.Fatal("absent history changed fallback")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	output.Reset()
	if emitted, err := emitPreviousBootstrapFailure(canceled, &output, history, failure); emitted || err != nil || output.Len() != 0 {
		t.Fatal("canceled history emitted output")
	}
}

func TestFrontendHistoryFailedWriterRetainsOriginalFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	failure := errors.New("owner_bridge_reply_unavailable")
	history := &launcher.BootstrapTerminalHistory{SchemaVersion: "1.0.0", Kind: "bootstrap-terminal-history", Meaning: "previous_recorded_terminal_failure", InvocationID: "attempt_" + strings.Repeat("a", 32), CompletedAt: time.Now().UTC().Format(time.RFC3339Nano), Diagnostic: launcher.ProjectRequestDiagnostic(context.DeadlineExceeded), RecordedCleanup: "unknown"}
	reader, writer := io.Pipe()
	t.Cleanup(func() { reader.Close(); writer.Close() })
	if reader.Close() != nil {
		t.Fatal("owned failed-writer fixture unavailable")
	}
	emitted, err := emitPreviousBootstrapFailure(ctx, writer, history, failure)
	if !emitted || err == nil || !errors.Is(err, failure) {
		t.Fatal("failed output discarded the original request failure")
	}
}
