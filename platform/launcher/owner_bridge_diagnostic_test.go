//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/nats-io/nats.go"
)

type bridgeDiagnosticOpaque struct{}

func (bridgeDiagnosticOpaque) Error() string { panic("unknown Error called") }
func (bridgeDiagnosticOpaque) Unwrap() error { panic("unknown Unwrap called") }
func (bridgeDiagnosticOpaque) Is(error) bool { panic("unknown Is called") }
func (bridgeDiagnosticOpaque) As(any) bool   { panic("unknown As called") }

func TestBridgeContextDiagnosticActualRequestDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	client := &OwnerBridgeClient{}
	_, failure := client.Request(ctx, "status", "attempt_0123456789abcdef0123456789abcdef")
	if failure == nil || failure.Error() != "owner_bridge_deadline" || ProjectRequestDiagnostic(failure).Code != "request_deadline" {
		t.Fatal("actual request deadline not retained")
	}
	// The diagnostic cause is private; existing operational sentinel behavior stays unchanged.
	if errors.Is(failure, context.DeadlineExceeded) || errors.Is(failure, context.Canceled) {
		t.Fatal("operational errors.Is changed")
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	_, failure = client.Request(canceled, "status", "attempt_0123456789abcdef0123456789abcdef")
	if failure == nil || failure.Error() != "owner_bridge_deadline" || ProjectRequestDiagnostic(failure).Code != "request_failed" {
		t.Fatal("cancellation invented a deadline")
	}
}

func TestBridgeContextDiagnosticPresentationAndSentinels(t *testing.T) {
	value := bridgeFailure{code: "deadline", contextCause: context.DeadlineExceeded}
	for _, actual := range []any{value, &value} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if fmt.Sprintf(format, actual) != "owner_bridge_deadline" {
				t.Fatal("private leaf state exposed")
			}
		}
		raw, err := json.Marshal(actual)
		if err != nil || string(raw) != `"owner_bridge_deadline"` {
			t.Fatal("private leaf JSON changed")
		}
	}
	for _, code := range []string{"deadline", "reply_unavailable", "connection_unavailable", "request_invalid", "future_unknown"} {
		failure := bridgeError(code)
		if failure.Error() != "owner_bridge_"+code || errors.Is(failure, context.DeadlineExceeded) || errors.Is(failure, bridgeError(code)) {
			t.Fatal("legacy error behavior changed")
		}
	}
	if bridgeError("authority_rejected") != errOwnerBridgeAuthority || !IsOwnerBridgeAuthorityError(bridgeError("authority_rejected")) {
		t.Fatal("authority sentinel changed")
	}
}

func TestBridgeContextDiagnosticUnknownAndPriority(t *testing.T) {
	genuine := bridgeContextError("reply_unavailable", context.DeadlineExceeded)
	var nilTyped *bridgeFailure
	cases := []struct {
		name    string
		failure error
		code    string
	}{
		{"observed", genuine, "request_deadline"},
		{"raw_text", errors.New("owner_bridge_deadline"), "request_failed"},
		{"label_only", bridgeError("deadline"), "request_failed"},
		{"unknown_cause", bridgeContextError("deadline", bridgeDiagnosticOpaque{}), "request_failed"},
		{"opaque_graph", bridgeDiagnosticOpaque{}, "request_failed"},
		{"nil", nil, "request_failed"}, {"nil_typed", nilTyped, "request_failed"},
		{"cleanup", &TransportCleanupError{cause: genuine}, "owned_cleanup_incomplete"},
		{"authentication", errors.Join(genuine, nats.ErrAuthorization), "runtime_authority_rejected"},
		{"authority", errors.Join(genuine, errOwnerBridgeAuthority), "runtime_authority_rejected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ProjectRequestDiagnostic(tc.failure)
			if got.Code != tc.code || !ValidRequestDiagnostic(got) {
				t.Fatal("closed diagnostic or priority changed")
			}
		})
	}
	children := make([]error, 65)
	for i := range children {
		children[i] = genuine
	}
	if ProjectRequestDiagnostic(errors.Join(children...)).Code != "request_failed" {
		t.Fatal("graph bound changed")
	}
}

// This component uses genuine authenticated NATS with the existing explicitly
// controlled Docker inspection fixture. It does not qualify an actual engine.
func TestBridgeContextDiagnosticActualReplyWaitDeadline(t *testing.T) {
	fixtureContext, stopFixture := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(stopFixture)
	f := newBridgeFixture(t)
	host := bridgeDiagnosticOwnedBroker(t, fixtureContext, f)
	client, err := LoadOwnerBridgeClient(f.config, f.enrollment)
	if err != nil {
		t.Fatal("actual enrolled client failed")
	}
	sub, err := host.SubscribeSync(client.subjects.Request)
	if err != nil {
		t.Fatal("actual HOST request subscription failed")
	}
	defer func() {
		if sub.Unsubscribe() != nil {
			t.Error("owned HOST subscription cleanup failed")
		}
	}()
	ctx, cancel := context.WithTimeout(fixtureContext, 2*time.Second)
	defer cancel()
	if host.FlushWithContext(ctx) != nil {
		t.Fatal("actual HOST subscription not admitted")
	}
	done := make(chan error, 1)
	joined := false
	go func() {
		_, failure := client.Request(ctx, "status", "attempt_0123456789abcdef0123456789abcdef")
		done <- failure
	}()
	var retainedFailure error
	defer func() {
		cancel()
		if !joined {
			retainedFailure = <-done
			joined = true
		}
		if cleanup, ok := retainedFailure.(*TransportCleanupError); ok {
			if cleanup.Close() != nil {
				t.Error("actual request owned cleanup incomplete")
			}
		}
	}()
	msg, err := sub.NextMsgWithContext(ctx)
	if err != nil || msg == nil || validateOwnerBridgeJSON(msg.Data, "host-owner-status-request", protocol.MaxPayload) != nil {
		t.Fatal("actual request did not reach HOST before deadline")
	}
	failure := <-done
	retainedFailure = failure
	joined = true
	if ctx.Err() != context.DeadlineExceeded || failure == nil || failure.Error() != "owner_bridge_reply_unavailable" || ProjectRequestDiagnostic(failure).Code != "request_deadline" {
		t.Fatal("actual reply wait expiry lost exact cause")
	}
	if errors.Is(failure, context.DeadlineExceeded) {
		t.Fatal("reply wait operational sentinel behavior changed")
	}
}
