//go:build darwin && cgo && agentmux_bootstrap_docker && ((agentmux_darwin_identity_candidate && agentmux_darwin_identity_protected_candidate && !agentmux_darwin_identity_protected_normal) || (agentmux_darwin_identity_protected_normal && !agentmux_darwin_identity_candidate && !agentmux_darwin_identity_protected_candidate))

package darwinfixtureidentity

import (
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// cleanupBudget never consults a clock or replaces the supplied start. Even a
// refused margin returns the same bounded cleanup deadline for safe fallback.
func cleanupBudget(start, absolute time.Time) (time.Time, error) {
	deadline := start.Add(2 * time.Second)
	if absolute.IsZero() || start.After(absolute.Add(-3*time.Second)) {
		return deadline, errors.New("protected_candidate_cleanup_deadline_margin_refused")
	}
	return deadline, nil
}

// readProtectedCleanupReceipt borrows its reader. The actual owning wrapper
// always consumes that reader's close once, including failed receipt reads.
func readProtectedCleanupReceipt(reader *os.File, deadline time.Time) error {
	if reader == nil {
		return failed("protected_candidate_cleanup_receipt_missing", nil)
	}
	if err := reader.SetReadDeadline(deadline); err != nil {
		return failed("protected_candidate_cleanup_receipt_deadline_failed", err)
	}
	var value [1]byte
	n, err := reader.Read(value[:])
	if err != nil || n != 1 || value[0] != 1 {
		return failed("protected_candidate_cleanup_receipt_refused", err)
	}
	n, err = reader.Read(value[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		return failed("protected_candidate_cleanup_receipt_eof_refused", err)
	}
	return nil
}

func TestProtectedCandidateCleanupReceiptControls(t *testing.T) {
	cases := []struct {
		name                     string
		payload                  []byte
		keepWriterOpen, accepted bool
	}{
		{name: "receipt_then_eof", payload: []byte{1}, accepted: true},
		{name: "forced_exit_style_empty_eof"},
		{name: "wrong_byte", payload: []byte{2}},
		{name: "extra_byte", payload: []byte{1, 1}},
		{name: "receipt_without_eof", payload: []byte{1}, keepWriterOpen: true},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal("cleanup_control_pipe_unavailable")
			}
			writerClosed := false
			t.Cleanup(func() {
				if err := reader.Close(); err != nil {
					t.Error("cleanup_control_reader_close_failed")
				}
				if !writerClosed {
					writerClosed = true
					if writer.Close() != nil {
						t.Error("cleanup_control_writer_close_failed")
					}
				}
			})
			if len(item.payload) > 0 {
				n, err := writer.Write(item.payload)
				if err != nil || n != len(item.payload) {
					t.Fatal("cleanup_control_write_failed")
				}
			}
			if !item.keepWriterOpen {
				writerClosed = true
				if writer.Close() != nil {
					t.Fatal("cleanup_control_writer_close_failed")
				}
			}
			// A tiny synchronous write fits the pipe; no writer goroutine exists.
			deadline := time.Now().Add(25 * time.Millisecond)
			err = readProtectedCleanupReceipt(reader, deadline)
			if (err == nil) != item.accepted {
				t.Fatal("cleanup_control_receipt_acceptance_mismatch")
			}
			if item.keepWriterOpen && !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("cleanup_control_missing_eof_not_deadline_bounded")
			}
		})
	}
}

func TestProtectedCandidateCleanupDeadlineControls(t *testing.T) {
	start := time.Unix(100, 0)
	absolute := start.Add(3 * time.Second)
	deadline, err := cleanupBudget(start, absolute)
	if err != nil || !deadline.Equal(start.Add(2*time.Second)) {
		t.Fatal("cleanup_control_exact_margin_refused")
	}
	again, err := cleanupBudget(start, absolute)
	if err != nil || !again.Equal(deadline) {
		t.Fatal("cleanup_control_deadline_reset")
	}
	generous, err := cleanupBudget(start, absolute.Add(time.Hour))
	if err != nil || !generous.Equal(deadline) {
		t.Fatal("cleanup_control_deadline_depends_on_lifetime")
	}
	for _, limit := range []time.Time{time.Time{}, absolute.Add(-time.Nanosecond)} {
		refused, err := cleanupBudget(start, limit)
		if err == nil || !refused.Equal(deadline) {
			t.Fatal("cleanup_control_late_margin_accepted")
		}
	}
}

// The status check is observational only; a synthetic identity grants no native
// authority. Data is the wait-style exit status supplied by NOTE_EXITSTATUS.
func protectedCandidateHostStatusOK(expected uint64, event unix.Kevent_t) bool {
	return event.Ident == expected && event.Filter == unix.EVFILT_PROC &&
		event.Flags&unix.EV_ERROR == 0 && event.Fflags == unix.NOTE_EXIT|unix.NOTE_EXITSTATUS && event.Data == 0
}

func TestProtectedCandidateHostStatusControls(t *testing.T) {
	const syntheticIdentity = 7
	valid := unix.Kevent_t{Ident: syntheticIdentity, Filter: unix.EVFILT_PROC, Fflags: unix.NOTE_EXIT | unix.NOTE_EXITSTATUS}
	if !protectedCandidateHostStatusOK(syntheticIdentity, valid) {
		t.Fatal("host_status_control_success_refused")
	}
	cases := map[string]unix.Kevent_t{}
	for _, item := range []struct {
		name string
		data int64
	}{{"close_failure", 70 << 8}, {"forced_deadline", 124 << 8}, {"signal", 9}} {
		event := valid
		event.Data = item.data
		cases[item.name] = event
	}
	event := valid
	event.Fflags = unix.NOTE_EXIT
	cases["missing_status"] = event
	event = valid
	event.Fflags |= unix.NOTE_EXEC
	cases["exec"] = event
	event = valid
	event.Ident++
	cases["wrong_identity"] = event
	event = valid
	event.Filter = unix.EVFILT_READ
	cases["wrong_filter"] = event
	event = valid
	event.Flags |= unix.EV_ERROR
	cases["error_flag"] = event
	for name, event := range cases {
		t.Run(name, func(t *testing.T) {
			if protectedCandidateHostStatusOK(syntheticIdentity, event) {
				t.Fatal("host_status_control_failure_accepted")
			}
		})
	}
}
