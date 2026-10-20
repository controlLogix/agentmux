//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/launcher"
	"golang.org/x/sys/unix"
)

func TestPreparationLiteralCommandAndTotalDeadline(t *testing.T) {
	args := []string{"prepare", "--host-policy", "/private/policy", "--workspace", "/work"}
	if options, err := parse(args); err != nil || options.operation != "prepare" {
		t.Fatal("explicit preparation command rejected")
	}
	if _, err := parse(append(args, "--invocation-id", "attempt_"+strings.Repeat("a", 32))); err == nil {
		t.Fatal("preparation accepted a host invocation")
	}
	entered := time.Now().Add(-3 * time.Second)
	for operation, limit := range map[string]time.Duration{"prepare": 180 * time.Second, "ensure": 10 * time.Second, "status": 5 * time.Second, "doctor": 5 * time.Second} {
		ctx, cancel := frontendTotalContext(context.Background(), operation, entered)
		deadline, ok := ctx.Deadline()
		cancel()
		if !ok || !deadline.Equal(entered.Add(limit)) {
			t.Fatal("operation budget restarted after admission")
		}
	}
	parent, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	ctx, cancel := frontendTotalContext(parent, "prepare", entered)
	defer cancel()
	deadline, _ := ctx.Deadline()
	outer, _ := parent.Deadline()
	if !deadline.Equal(outer) {
		t.Fatal("preparation extended its parent deadline")
	}
}

type preparationRefusedWriter struct{}

func (preparationRefusedWriter) Write([]byte) (int, error) {
	return 0, errors.New("synthetic-private-writer-error")
}

func TestPreparationOutputIsClosedAndBounded(t *testing.T) {
	frame := launcher.BrokerImagePreparationResult{SchemaVersion: "1.0.0", Kind: "broker-image-preparation-result", Outcome: "prepared", Stage: "prepared", Readiness: "not_observed"}
	var output bytes.Buffer
	if err := writePreparationJSON(context.Background(), &output, frame); err != nil {
		t.Fatal(err)
	}
	var decoded launcher.BrokerImagePreparationResult
	if json.Unmarshal(output.Bytes(), &decoded) != nil || decoded != frame || bytes.Count(output.Bytes(), []byte{'\n'}) != 1 {
		t.Fatal("preparation output changed its public result")
	}
	if err := writePreparationJSON(context.Background(), preparationRefusedWriter{}, frame); err == nil || strings.Contains(err.Error(), "synthetic-private") {
		t.Fatal("writer failure was absent or exposed private details")
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal("output pipe unavailable")
	}
	defer reader.Close()
	defer writer.Close()
	// This pipe belongs only to this test. Fill it without a descendant or a
	// blocked writer goroutine, then restore its original blocking mode.
	fd := int(writer.Fd())
	if unix.SetNonblock(fd, true) != nil {
		t.Fatal("pipe fill control unavailable")
	}
	chunk := bytes.Repeat([]byte{'x'}, 4096)
	for {
		_, err := unix.Write(fd, chunk)
		if err == unix.EAGAIN {
			break
		}
		if err != nil {
			t.Fatal("pipe fill control failed")
		}
	}
	if unix.SetNonblock(fd, false) != nil {
		t.Fatal("pipe mode restore failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := writePreparationJSON(ctx, writer, frame); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("backpressured output did not honor the parent budget")
	}
	if time.Since(started) > 150*time.Millisecond {
		t.Fatal("backpressured output exceeded its bounded wait")
	}
}
