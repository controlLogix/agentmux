//go:build linux || darwin

package launcher

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestOwnerBridgeReplyFlushShutdownBoundary(t *testing.T) {
	bootstrapFailure := errors.New("actual bootstrap failure")
	for _, tc := range []struct {
		name             string
		flush            error
		cancelLifetime   bool
		requestDeadline  bool
		authority        error
		bootstrap        error
		want             error
		wantReplyFailure bool
	}{
		{name: "direct lifetime cancellation", flush: context.Canceled, cancelLifetime: true},
		{name: "unrelated closed connection with concurrent cancellation", flush: nats.ErrConnectionClosed, cancelLifetime: true, wantReplyFailure: true},
		{name: "closed connection", flush: nats.ErrConnectionClosed, wantReplyFailure: true},
		{name: "request only deadline", flush: context.DeadlineExceeded, requestDeadline: true, wantReplyFailure: true},
		{name: "request deadline with lifetime cancellation", flush: context.DeadlineExceeded, requestDeadline: true, cancelLifetime: true, wantReplyFailure: true},
		{name: "authority survives cancellation", flush: context.Canceled, cancelLifetime: true, authority: errOwnerBridgeAuthority, want: errOwnerBridgeAuthority},
		{name: "bootstrap survives cancellation", flush: context.Canceled, cancelLifetime: true, bootstrap: bootstrapFailure, want: bootstrapFailure},
		{name: "wrapped cancellation lacks direct proof", flush: errors.Join(context.Canceled, nats.ErrConnectionClosed), cancelLifetime: true, wantReplyFailure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lifetime, stop := context.WithCancel(context.Background())
			defer stop()
			request, cancel := context.WithTimeout(lifetime, 5*time.Second)
			defer cancel()
			if tc.requestDeadline {
				cancel()
				var expired context.CancelFunc
				request, expired = context.WithDeadline(lifetime, time.Now().Add(-time.Second))
				defer expired()
			}
			if tc.cancelLifetime {
				stop()
			}
			err := ownerBridgeReplyFlushResult(lifetime, request, tc.flush, tc.authority, tc.bootstrap)
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("lost original cause: %v", err)
				}
			} else if tc.wantReplyFailure {
				if err == nil || err.Error() != "owner_bridge_reply_failed" {
					t.Fatalf("transport failure hidden: %v", err)
				}
			} else if err != nil {
				t.Fatalf("shutdown failed: %v", err)
			}
		})
	}
}

func TestOwnerBridgeReplyFlushShutdownRetainsCleanupOwner(t *testing.T) {
	lifetime, stop := context.WithCancel(context.Background())
	request, cancel := context.WithTimeout(lifetime, 5*time.Second)
	defer cancel()
	stop()
	cleanup := &TransportCleanupError{}
	bootstrap := errors.Join(errors.New("actual bootstrap failure"), cleanup)
	err := ownerBridgeReplyFlushResult(lifetime, request, context.Canceled, errOwnerBridgeAuthority, bootstrap)
	var retained *TransportCleanupError
	if !errors.As(err, &retained) || retained != cleanup || !errors.Is(err, bootstrap) || !errors.Is(err, errOwnerBridgeAuthority) {
		t.Fatal("shutdown lost cleanup owner, bootstrap cause, or authority cause")
	}
}
