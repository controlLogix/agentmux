//go:build linux || darwin

package launcher

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// Test runs never write to the developer's system log.
func init() { writeApplicationAttestorRecord = func(string) {} }

type attestorPrivateError struct{ text string }

func (e attestorPrivateError) Error() string { return e.text }

func TestApplicationAttestorRecordNamesOnlyFixedCodesAndTypes(t *testing.T) {
	private := errors.New("nats: tls://user:secret@10.0.0.1 /Users/private/profile")
	cases := []struct {
		hostLive bool
		result   error
		want     string
	}{
		{true, nil, "host=live codes=none sentinels=none cause=none services_cleanup=false"},
		{true, applicationEvidenceError("transport_unavailable", private),
			"host=live codes=transport_unavailable sentinels=none cause=*errors.errorString services_cleanup=false"},
		// Services ending cancels the attestor; a lost connection must read differently.
		{true, errors.Join(applicationEvidenceError("deadline", context.Canceled), applicationEvidenceError("services_unavailable", nil)),
			"host=live codes=deadline,services_unavailable sentinels=canceled cause=none services_cleanup=false"},
		{true, applicationEvidenceError("transport_unavailable", fmt.Errorf("publish: %w", nats.ErrConnectionClosed)),
			"host=live codes=transport_unavailable sentinels=nats_connection_closed cause=none services_cleanup=false"},
		{true, errors.Join(applicationEvidenceError("observation_expired", context.DeadlineExceeded), nats.ErrTimeout),
			"host=live codes=observation_expired sentinels=deadline_exceeded,nats_timeout cause=none services_cleanup=false"},
		{false, errors.Join(applicationEvidenceError("lifetime_ended", nil), serviceProcessOwnershipError(nil),
			fmt.Errorf("closing %s: %w", "/private/path", ErrTransportCleanup)),
			"host=ending codes=lifetime_ended sentinels=transport_cleanup cause=*launcher.applicationServiceOwnershipFailure services_cleanup=true"},
		{true, attestorPrivateError{"password=hunter2"},
			"host=live codes=none sentinels=none cause=launcher.attestorPrivateError services_cleanup=false"},
		{true, applicationEvidenceError("transport_unavailable", &net.OpError{Op: "dial /private/socket"}),
			"host=live codes=transport_unavailable sentinels=none cause=*net.OpError services_cleanup=false"},
		{true, applicationEvidenceError("Bad Code /path", nil),
			"host=live codes=uncoded sentinels=none cause=none services_cleanup=false"},
	}
	for _, c := range cases {
		got := applicationAttestorRecord(c.hostLive, c.result)
		if got != "application_attestor_ended "+c.want {
			t.Fatalf("record\n got %s\nwant application_attestor_ended %s", got, c.want)
		}
		for _, leaked := range []string{"secret", "10.0.0.1", "/Users", "/private", "/path", "hunter2", "nats:", "dial", "Bad"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("record leaked %q: %s", leaked, got)
			}
		}
	}
}

func TestApplicationAttestorRecordIsBounded(t *testing.T) {
	var codes []error
	for _, code := range []string{"deadline", "busy", "kernel_invalid", "update_invalid", "receipt_invalid"} {
		codes = append(codes, applicationEvidenceError(code, nil), applicationEvidenceError(code, nil))
	}
	got := applicationAttestorRecord(true, errors.Join(codes...))
	if !strings.Contains(got, " codes=deadline,busy,kernel_invalid,update_invalid ") {
		t.Fatalf("codes not bounded and deduplicated: %s", got)
	}
}

func TestApplicationAttestorEndNeverFailsTheHost(t *testing.T) {
	var records []string
	writeApplicationAttestorRecord = func(record string) { records = append(records, record) }
	defer func() { writeApplicationAttestorRecord = func(string) {} }()
	ctx, cancel := context.WithCancel(context.Background())
	recordApplicationAttestorEnd(ctx, applicationEvidenceError("authority_rejected", nil))
	cancel()
	recordApplicationAttestorEnd(ctx, nil)
	recordApplicationAttestorEnd(nil, applicationEvidenceError("owner_invalid", nil))
	var typedNil *applicationEvidenceFailure
	recordApplicationAttestorEnd(context.Background(), errors.Join(typedNil))
	want := []string{"host=live codes=authority_rejected ", "host=ending codes=none ", "host=ending codes=owner_invalid ",
		"application_attestor_ended record=failed"}
	if len(records) != len(want) {
		t.Fatalf("records %q", records)
	}
	for i := range want {
		if !strings.Contains(records[i], want[i]) {
			t.Fatalf("record %d = %q, want %q", i, records[i], want[i])
		}
	}
}

func TestAttestorTicksReportOncePerMinuteWithCountsOnly(t *testing.T) {
	var records []string
	writeApplicationAttestorRecord = func(record string) { records = append(records, record) }
	defer func() { writeApplicationAttestorRecord = func(string) {} }()
	clock := time.Unix(1000, 0)
	ticks := newAttestorTicks(func() time.Time { return clock })
	ticks.stages(attestorStages{10 * time.Millisecond, 0, 100 * time.Millisecond, 600 * time.Millisecond, 0, 40 * time.Millisecond})
	ticks.record(200*time.Millisecond, false)
	ticks.stages(attestorStages{30 * time.Millisecond, 2 * time.Millisecond, 300 * time.Millisecond, 200 * time.Millisecond, 0, 60 * time.Millisecond})
	ticks.record(1500*time.Millisecond, false)
	clock = clock.Add(30 * time.Second)
	ticks.record(300*time.Millisecond, true)
	if len(records) != 0 {
		t.Fatalf("reported before a minute: %q", records)
	}
	clock = clock.Add(31 * time.Second)
	ticks.record(100*time.Millisecond, false)
	clock = clock.Add(10 * time.Second)
	ticks.record(100*time.Millisecond, false)
	want := "application_attestor_ticks ticks=4 skipped=1 late=1 slowest_ms=1500 avg_ms verify=20 profile=1 broker=200 kernel=400 roles=0 exchange=50"
	if len(records) != 1 || records[0] != want {
		t.Fatalf("records %q, want %q", records, want)
	}
}
