//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestProfileClientCommandParseFailureIsClosed(t *testing.T) {
	var output bytes.Buffer
	if err := runProfileClientCommand(context.Background(), []string{"profile-client", "PRIVATE"}, &output); err == nil || bytes.Contains(output.Bytes(), []byte("PRIVATE")) || bytes.Count(output.Bytes(), []byte{'\n'}) != 1 {
		t.Fatal("parse error output was absent or exposed arguments")
	}
}
func TestProfileClientCommandOutputSharesDeadlineAndCancellation(t *testing.T) {
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
	for _, cancelled := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
		outer, _ := ctx.Deadline()
		started := time.Now()
		failure := runProfileClientCommandWith(ctx, []string{"profile-client"}, writer, func(inner context.Context, _ []string) error {
			deadline, _ := inner.Deadline()
			if !deadline.Equal(outer) {
				t.Fatal("profile command restarted outer deadline")
			}
			if cancelled {
				cancel()
			} else {
				select {
				case <-time.After(35 * time.Millisecond):
				case <-inner.Done():
				}
			}
			return errors.New("profile_client_arguments_invalid")
		})
		cancel()
		expected := context.DeadlineExceeded
		if cancelled {
			expected = context.Canceled
		}
		if !errors.Is(failure, expected) || time.Since(started) > 180*time.Millisecond {
			t.Fatal("blocked failure output exceeded original command budget", failure)
		}
	}
}
