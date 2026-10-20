//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestInstalledClientCommandParseDiagnosticsAreClosed(t *testing.T) {
	for _, command := range []string{"startup", "mcp", "client-setup", "launch-claude-desktop", "claude-code-hook"} {
		var output bytes.Buffer
		if err := runInstalledClientCommand(context.Background(), []string{command, "PRIVATE"}, &output); err == nil || bytes.Contains(output.Bytes(), []byte("PRIVATE")) || bytes.Count(output.Bytes(), []byte{'\n'}) != 1 {
			t.Fatal("parse refusal missing or exposed arguments", command)
		}
	}
}

func TestInstalledClientCommandFailureOutputUsesRemainingBudget(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	fd := int(writer.Fd())
	if unix.SetNonblock(fd, true) != nil {
		t.Fatal("pipe setup failed")
	}
	for {
		_, err := unix.Write(fd, bytes.Repeat([]byte{'x'}, 4096))
		if err == unix.EAGAIN {
			break
		}
		if err != nil {
			t.Fatal("pipe fill failed")
		}
	}
	if unix.SetNonblock(fd, false) != nil {
		t.Fatal("pipe restore failed")
	}
	// Actual parse refusal exercises the production runner. Admission and exec
	// refusal seams consume part of the same budget before backpressured output.
	for _, stage := range []string{"parse", "admission", "exec", "cancel", "expired"} {
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
		outer, _ := ctx.Deadline()
		started := time.Now()
		if stage == "expired" {
			cancel()
		}
		run := runInstalledClient
		if stage != "parse" {
			run = func(inner context.Context, _ []string) error {
				deadline, _ := inner.Deadline()
				if !deadline.Equal(outer) {
					t.Fatal("installed client restarted command deadline")
				}
				if stage == "cancel" {
					cancel()
				} else if stage != "expired" {
					select {
					case <-time.After(35 * time.Millisecond):
					case <-inner.Done():
					}
				}
				return errors.New("PRIVATE " + stage)
			}
		}
		failure := runInstalledClientCommandWith(ctx, []string{"startup", "PRIVATE"}, writer, run)
		cancel()
		expected := context.DeadlineExceeded
		if stage == "cancel" || stage == "expired" {
			expected = context.Canceled
		}
		if !errors.Is(failure, expected) || time.Since(started) > 180*time.Millisecond {
			t.Fatal("full stderr escaped original budget", stage)
		}
	}
}

func TestInstalledClientCommandSuccessDoesNotWrite(t *testing.T) {
	var output bytes.Buffer
	var observed bool
	err := runInstalledClientCommandWith(context.Background(), []string{"mcp"}, &output, func(ctx context.Context, args []string) error {
		observed = true
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 10*time.Second || time.Until(deadline) < 9*time.Second || strings.Join(args, " ") != "mcp" {
			t.Fatal("first hop lost finite budget or arguments")
		}
		return nil
	})
	if err != nil || !observed || output.Len() != 0 {
		t.Fatal("successful direct-exec handoff wrote a diagnostic")
	}
}
