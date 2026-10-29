//go:build linux || darwin

package launcher

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

// The attestor's end stops the owned application services, and its error is
// otherwise read only at host shutdown. One system-log record names why it
// ended, from fixed names only: evidence codes (literals in this package),
// known sentinels, Go type names and flags. Never an error message, subject,
// path or credential. Read it with:
//
//	log show --last 1h --predicate 'eventMessage BEGINSWITH "application_attestor_"'
var writeApplicationAttestorRecord = writeSystemLog

var (
	attestorCode     = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+){0,7}$`)
	attestorTypeName = regexp.MustCompile(`^\*?[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$`)
)

const attestorRecordCodes = 4

// Sentinels share one type (*errors.errorString), so they are named by identity.
var attestorSentinels = []struct {
	name string
	err  error
}{
	{"canceled", context.Canceled},
	{"deadline_exceeded", context.DeadlineExceeded},
	{"transport_cleanup", ErrTransportCleanup},
	{"nats_timeout", nats.ErrTimeout},
	{"nats_connection_closed", nats.ErrConnectionClosed},
	{"nats_no_responders", nats.ErrNoResponders},
	{"nats_slow_consumer", nats.ErrSlowConsumer},
	{"nats_authorization", nats.ErrAuthorization},
	{"nats_auth_expired", nats.ErrAuthExpired},
	{"nats_auth_revoked", nats.ErrAuthRevoked},
	{"nats_account_auth_expired", nats.ErrAccountAuthExpired},
	{"nats_permission_violation", nats.ErrPermissionViolation},
	{"nats_stale_connection", nats.ErrStaleConnection},
	{"nats_bad_subscription", nats.ErrBadSubscription},
}

func recordApplicationAttestorEnd(lifetime context.Context, result error) {
	record := "application_attestor_ended record=failed"
	func() {
		// The record is diagnostic only and never changes the host's outcome.
		defer func() { _ = recover() }()
		record = applicationAttestorRecord(lifetime != nil && lifetime.Err() == nil, result)
	}()
	writeApplicationAttestorRecord(record)
}

func applicationAttestorRecord(hostLive bool, result error) string {
	var codes, sentinels []string
	cause := "none"
	add := func(values *[]string, value string) {
		if len(*values) < attestorRecordCodes && !slices.Contains(*values, value) {
			*values = append(*values, value)
		}
	}
	var walk func(error, int)
	walk = func(err error, depth int) {
		if err == nil || depth > 16 {
			return
		}
		for _, known := range attestorSentinels {
			if err == known.err {
				add(&sentinels, known.name)
				return
			}
		}
		evidence, _ := err.(*applicationEvidenceFailure)
		if evidence != nil {
			if attestorCode.MatchString(evidence.code) {
				add(&codes, evidence.code)
			} else {
				add(&codes, "uncoded")
			}
		}
		leaf := true
		switch unwrapped := err.(type) {
		case interface{ Unwrap() []error }:
			for _, next := range unwrapped.Unwrap() {
				leaf = leaf && next == nil
				walk(next, depth+1)
			}
		case interface{ Unwrap() error }:
			next := unwrapped.Unwrap()
			leaf = next == nil
			walk(next, depth+1)
		}
		if leaf && evidence == nil && cause == "none" {
			cause = attestorTypeOf(err)
		}
	}
	walk(result, 0)
	if len(codes) == 0 {
		codes = []string{"none"}
	}
	if len(sentinels) == 0 {
		sentinels = []string{"none"}
	}
	host := "ending"
	if hostLive {
		host = "live"
	}
	var services *applicationServiceOwnershipFailure
	return fmt.Sprintf("application_attestor_ended host=%s codes=%s sentinels=%s cause=%s services_cleanup=%t",
		host, strings.Join(codes, ","), strings.Join(sentinels, ","), cause, errors.As(result, &services))
}

func attestorTypeOf(err error) string {
	name := fmt.Sprintf("%T", err)
	if len(name) > 96 || !attestorTypeName.MatchString(name) {
		return "unnamed"
	}
	return name
}

// attestorTicks counts how the attestor's ticks went and, once a minute, writes
// one record of counts and the slowest tick in milliseconds. A Work reply can be
// valid only while the attestor's latest evidence is, so a slow or skipped tick
// shortens every request; this record shows whether that happened.
type attestorTicks struct {
	now                  func() time.Time
	started              time.Time
	ticks, skipped, late int
	slowest              time.Duration
	// timed counts issued ticks whose stage durations are summed in spent.
	timed int
	spent attestorStages
}

// Steps of one issued attestor tick, timed for the once-a-minute record.
const (
	attestorStageVerify = iota
	attestorStageProfile
	attestorStageBroker
	attestorStageKernel
	attestorStageRoles
	attestorStageExchange
	// Parts of the kernel step.
	attestorStageKernelAuthority
	attestorStageKernelConnect
	attestorStageKernelSubscribe
	attestorStageKernelWait
	attestorStageKernelClose
	// The received snapshot's age, and the time between kernel publishes.
	attestorStageKernelAge
	attestorStageKernelPublish
	attestorStageCount
)

type attestorStages [attestorStageCount]time.Duration

var attestorStageNames = [attestorStageCount]string{"verify", "profile", "broker", "kernel", "roles", "exchange",
	"kernel.authority", "kernel.connect", "kernel.subscribe", "kernel.wait", "kernel.close",
	"kernel.age", "kernel.publish"}

// stages adds one issued tick's step durations.
func (s *attestorTicks) stages(took attestorStages) {
	s.timed++
	for i, d := range took {
		s.spent[i] += d
	}
}

const attestorTickReport = time.Minute

func newAttestorTicks(now func() time.Time) *attestorTicks {
	return &attestorTicks{now: now, started: now()}
}

func (s *attestorTicks) record(took time.Duration, skipped bool) {
	s.ticks++
	if skipped {
		s.skipped++
	}
	if took > applicationAttestInterval {
		s.late++
	}
	if took > s.slowest {
		s.slowest = took
	}
	if s.now().Sub(s.started) < attestorTickReport {
		return
	}
	record := fmt.Sprintf("application_attestor_ticks ticks=%d skipped=%d late=%d slowest_ms=%d",
		s.ticks, s.skipped, s.late, s.slowest.Milliseconds())
	if s.timed > 0 {
		record += " avg_ms"
		for i, d := range s.spent {
			record += fmt.Sprintf(" %s=%d", attestorStageNames[i], (d / time.Duration(s.timed)).Milliseconds())
		}
	}
	writeApplicationAttestorRecord(record)
	*s = attestorTicks{now: s.now, started: s.now()}
}
