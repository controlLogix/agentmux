//go:build linux

package runtime

import (
	"context"
	"errors"
	"sync"
	"syscall"
	"testing"
	"time"
)

func roleStopGroup(t *testing.T, graceful bool) *Group {
	t.Helper()
	root, raw, trust, opts := releaseFixture(t)
	if graceful {
		opts[0].Args = []string{"fixture-child", "term"}
	}
	g, err := prepared(t, root, raw, trust).Start(context.Background(), opts, budgets())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stop(t, g) })
	observations(t, g)
	return g
}

func assertRoleOnlyExited(t *testing.T, g *Group, role string) {
	t.Helper()
	exited := 0
	for _, s := range g.Status() {
		if s.Role == role {
			if !s.Exited {
				t.Fatal("selected role was not reaped")
			}
			exited++
		} else if s.Exited {
			t.Fatal("another role was stopped")
		}
	}
	if exited != 1 {
		t.Fatal("selected owned role missing")
	}
	select {
	case <-g.Done():
		t.Fatal("single-role stop completed the whole group")
	default:
	}
}

func TestStopRoleOwnedChildAndRepeatedCalls(t *testing.T) {
	for _, graceful := range []bool{true, false} {
		name := "kill"
		if graceful {
			name = "term"
		}
		t.Run(name, func(t *testing.T) {
			g := roleStopGroup(t, graceful)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := g.StopRole(ctx, "boot"); err != nil {
				t.Fatal(err)
			}
			assertRoleOnlyExited(t, g, "boot")
			for _, child := range g.children {
				if child.role == "boot" {
					status, ok := child.cmd.ProcessState.Sys().(syscall.WaitStatus)
					expected := syscall.SIGKILL
					if graceful {
						expected = syscall.SIGTERM
					}
					if !ok || status.Signal() != expected {
						t.Fatal("owned child exit signal did not match TERM or KILL path")
					}
				}
			}
			if err := g.StopRole(ctx, "boot"); err != nil {
				t.Fatal("repeated stop failed")
			}
			stop(t, g)
			if err := g.StopRole(ctx, "boot"); err != nil {
				t.Fatal("already stopped group failed")
			}
		})
	}
}

func TestStopRoleInvalidCallsHaveNoEffect(t *testing.T) {
	g := roleStopGroup(t, false)
	for _, role := range []string{"", "other", "BOOT", "1234", "../boot"} {
		if err := g.StopRole(context.Background(), role); err == nil {
			t.Fatal("invalid role accepted")
		}
	}
	if err := g.StopRole(nil, "boot"); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := g.StopRole(ctx, "boot"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled call accepted")
	}
	if err := (&Group{}).StopRole(context.Background(), "boot"); err == nil {
		t.Fatal("unowned group accepted")
	}
	var missing *Group
	if err := missing.StopRole(context.Background(), "boot"); err == nil {
		t.Fatal("nil group accepted")
	}
	for _, s := range g.Status() {
		if s.Exited {
			t.Fatal("invalid call stopped a child")
		}
	}
}

func TestStopRoleEarlierDeadlineKillsAndExistingWaitReaps(t *testing.T) {
	g := roleStopGroup(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := g.StopRole(ctx, "boot")
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("unexpected deadline result")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("caller deadline was not bounded")
	}
	// The original Wait goroutine must finish even when this caller has no
	// remaining time to observe the actual reap synchronously.
	end := time.Now().Add(time.Second)
	for time.Now().Before(end) {
		for _, s := range g.Status() {
			if s.Role == "boot" && s.Exited {
				assertRoleOnlyExited(t, g, "boot")
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("owned killed child was not reaped")
}

func TestStopRoleUsesWholeGroupSerialization(t *testing.T) {
	g := roleStopGroup(t, false)
	<-g.stopToken
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	start := time.Now()
	err := g.StopRole(ctx, "boot")
	cancel()
	g.stopToken <- struct{}{}
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 500*time.Millisecond {
		t.Fatal("shared token wait did not respect caller deadline")
	}
	for _, s := range g.Status() {
		if s.Exited {
			t.Fatal("waiting call signalled a child")
		}
	}
	var wg sync.WaitGroup
	results := make(chan error, 3)
	for _, role := range []string{"boot", "kernel-lifecycle"} {
		wg.Add(1)
		go func(role string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			results <- g.StopRole(ctx, role)
		}(role)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		results <- g.Stop(ctx)
	}()
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range g.Status() {
		if !s.Exited {
			t.Fatal("concurrent shutdown left a live child")
		}
	}
}
