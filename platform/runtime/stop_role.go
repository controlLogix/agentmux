package runtime

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"time"
)

// StopRole signals only the selected child handle owned by this Group. It shares
// Stop's serialization token and observes the existing Wait goroutine's result.
// It does not stop other roles, find a PID, adopt a process, or start another Wait.
func (g *Group) StopRole(parent context.Context, role string) error {
	if g == nil || g.allDone == nil || g.stopToken == nil {
		return errors.New("process group is not owned by this supervisor")
	}
	if parent == nil {
		return errors.New("stop context is required")
	}
	if role != "boot" && role != "kernel-lifecycle" && role != "internal-communication" && role != "exported-status" {
		return errors.New("stop role is not a protected member")
	}
	total := g.deadlines.StopGrace + g.deadlines.ReapTimeout
	if g.deadlines.StopGrace <= 0 || g.deadlines.ReapTimeout <= 0 || total <= 0 {
		return errors.New("positive lifecycle deadlines are required")
	}
	ctx, cancel := context.WithTimeout(parent, total)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-g.stopToken:
		defer func() { g.stopToken <- struct{}{} }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if g.recovery != nil {
		g.childrenMu.Lock()
		g.recovery.enabled[role] = false
		g.childrenMu.Unlock()
		defer g.finishRecovery()
	}
	var child *owned
	for _, candidate := range g.currentChildren() {
		if candidate != nil && candidate.role == role {
			if child != nil {
				return errors.New("owned role is repeated")
			}
			child = candidate
		}
	}
	if child == nil || child.cmd == nil || child.cmd.Process == nil || child.done == nil {
		return errors.New("protected role was not started by this group")
	}
	select {
	case <-child.done:
		return nil
	default:
	}
	_ = child.cmd.Process.Signal(syscall.SIGTERM)
	grace := time.NewTimer(g.deadlines.StopGrace)
	defer grace.Stop()
	select {
	case <-child.done:
		return nil
	case <-ctx.Done():
	case <-grace.C:
	}
	// A cancelled call still kills this exact owned child after TERM; it reports
	// incomplete reaping honestly if the caller's remaining budget is exhausted.
	_ = child.cmd.Process.Kill()
	reap := time.NewTimer(g.deadlines.ReapTimeout)
	defer reap.Stop()
	select {
	case <-child.done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("owned role reaping is incomplete: %w", ctx.Err())
	case <-reap.C:
		return errors.New("owned role reaping deadline exceeded")
	}
}
