package protocol

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/controlLogix/agentmux/platform/localtls"
)

func TestActorCleanupFailureRetainsExactOwnership(t *testing.T) {
	actor := &Actor{tlsDialer: &localtls.Dialer{}}
	gotActor, err := actor.openFailure(errors.New("kernel_broker_unavailable"))
	if gotActor != nil {
		t.Fatal("failed constructor returned a usable actor")
	}
	var retained *CleanupError
	if !errors.As(err, &retained) || retained.actor != actor {
		t.Fatal("cleanup failure lost exact owned actor")
	}
	if !errors.Is(err, ErrCleanup) {
		t.Fatal("cleanup failure was hidden")
	}
	for _, format := range []string{"%s", "%v", "%+v", "%#v", "%q"} {
		if got := fmt.Sprintf(format, err); got != "kernel_cleanup_failed" {
			t.Fatal("cleanup formatting exposed private state")
		}
	}
	if retained.Close() == nil {
		t.Fatal("repeat failed cleanup claimed success")
	}
	// The zero-value dialer is an invalid owned-resource control, not a fault-injected
	// production transport. The localtls tests exercise actual failed socket closes.
}

func TestActorSuccessfulCleanupIsIdempotent(t *testing.T) {
	actor := &Actor{}
	if actor.Close() != nil || actor.Close() != nil {
		t.Fatal("empty exact owner cleanup failed")
	}
	got, err := actor.openFailure(errors.New("kernel_broker_unavailable"))
	if got != nil || err == nil || errors.Is(err, ErrCleanup) {
		t.Fatal("clean constructor failure changed ownership")
	}
	retained := &CleanupError{actor: actor, cause: errors.New("kernel_broker_unavailable")}
	if retained.Close() != nil || retained.Close() != nil {
		t.Fatal("successful retained cleanup was not idempotent")
	}
}

func TestServeReportsCleanupOnCancellation(t *testing.T) {
	actor := &Actor{tlsDialer: &localtls.Dialer{}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := actor.Serve(ctx, nil, nil)
	if !errors.Is(err, ErrCleanup) {
		t.Fatal("cancellation hid cleanup failure")
	}
	var retained *CleanupError
	if !errors.As(err, &retained) || retained.actor != actor || retained.Close() == nil {
		t.Fatal("Serve lost exact failed cleanup ownership")
	}
}
