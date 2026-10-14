package launcher

import (
	"context"
	"errors"
	"github.com/nats-io/nats.go"
	"io"
	"testing"
)

func TestOwnerBridgeReplyCancellationKeepsFailures(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	cases := []struct {
		name                                string
		lifetime                            context.Context
		before, publish, flush, after, boot error
		code                                string
	}{
		{"cancel_late_eof", canceled, nil, nil, context.Canceled, io.EOF, nil, ""},
		{"cancel_late_closed", canceled, nil, nil, context.Canceled, nats.ErrConnectionClosed, nil, ""},
		{"preexisting_eof", canceled, io.EOF, nil, context.Canceled, nil, nil, "owner_bridge_reply_failed"},
		{"publish_failure", canceled, nil, nats.ErrConnectionClosed, context.Canceled, nil, nil, "owner_bridge_reply_failed"},
		{"authority_before", canceled, nats.ErrPermissionViolation, nil, context.Canceled, nil, nil, "owner_bridge_authority_rejected"},
		{"authority_after", canceled, nil, nil, context.Canceled, nats.ErrPermissionViolation, nil, "owner_bridge_authority_rejected"},
		{"deadline", canceled, nil, nil, context.DeadlineExceeded, nil, nil, "owner_bridge_reply_failed"},
		{"disconnected_flush", canceled, nil, nil, nats.ErrConnectionClosed, nil, nil, "owner_bridge_reply_failed"},
		{"unknown_flush", canceled, nil, nil, errors.New("unknown private failure"), nil, nil, "owner_bridge_reply_failed"},
		{"only_request_canceled", context.Background(), nil, nil, context.Canceled, nil, nil, "owner_bridge_reply_failed"},
		{"startup_failure", canceled, nil, nil, context.Canceled, io.EOF, errors.New("actual startup failure"), "owner_bridge_startup_failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ownerBridgeReplyOutcome(c.lifetime, c.before, c.publish, c.flush, c.after, c.boot)
			if c.code == "" {
				if err != nil {
					t.Fatal("shutdown became failure")
				}
			} else if err == nil || err.Error() != c.code {
				t.Fatal("required hard failure lost")
			}
		})
	}
}
