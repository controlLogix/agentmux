package runtime

import (
	"context"
	"errors"
	"testing"
	"time"
)

// This fixture exercises context and token precedence only. It contains no
// child process and does not establish signal delivery or actual reaping.
func completedStopContextGroup() *Group {
	done := make(chan struct{})
	close(done)
	token := make(chan struct{}, 1)
	token <- struct{}{}
	return &Group{allDone: done, stopToken: token}
}

func assertStopContextTokenAvailable(t *testing.T, group *Group) {
	t.Helper()
	select {
	case <-group.stopToken:
	default:
		t.Fatal("stop did not preserve the serialization token")
	}
	select {
	case group.stopToken <- struct{}{}:
	default:
		t.Fatal("stop duplicated the serialization token")
	}
}

func TestStopContextPrecedenceAlreadyCanceledOrExpired(t *testing.T) {
	for _, kind := range []string{"canceled", "expired"} {
		t.Run(kind, func(t *testing.T) {
			var ctx context.Context
			var cancel context.CancelFunc
			want := context.Canceled
			if kind == "canceled" {
				ctx, cancel = context.WithCancel(context.Background())
				cancel()
			} else {
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				want = context.DeadlineExceeded
			}
			defer cancel()
			if ctx.Err() != want {
				t.Fatal("context control is not already canceled or expired")
			}
			group := completedStopContextGroup()
			for range 256 {
				if err := group.Stop(ctx); err != want || !errors.Is(err, want) {
					t.Fatal("completed group or available token overrode the original context error")
				}
				assertStopContextTokenAvailable(t, group)
			}
		})
	}
}

func TestStopContextPrecedenceHealthyCompletedGroup(t *testing.T) {
	group := completedStopContextGroup()
	for range 256 {
		if err := group.Stop(context.Background()); err != nil {
			t.Fatal("healthy completed-group stop failed")
		}
		assertStopContextTokenAvailable(t, group)
	}
	if err := group.Stop(nil); err == nil || err.Error() != "stop context is required" {
		t.Fatal("nil context validation changed")
	}
	assertStopContextTokenAvailable(t, group)
}

func TestStopContextPrecedencePreservesOwnedValidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, group := range []*Group{nil, {}, {allDone: make(chan struct{})}, {stopToken: make(chan struct{}, 1)}} {
		for _, supplied := range []context.Context{nil, ctx} {
			if err := group.Stop(supplied); err == nil || err.Error() != "process group is not owned by this supervisor" {
				t.Fatal("context precedence bypassed group ownership validation")
			}
		}
	}
}
