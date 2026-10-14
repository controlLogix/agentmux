// Package status publishes bounded kernel information, not application L04 status.
package status

import (
	"context"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"time"
)

func Run(ctx context.Context, c protocol.Config, subjects protocol.SubjectSet) error {
	actor, err := protocol.Open(ctx, c, "exported-status", subjects)
	if err != nil {
		return err
	}
	return actor.Serve(ctx, func(v protocol.View) protocol.Decision { return protocol.Decision{State: "ready"} }, func(e protocol.Event, v protocol.View) protocol.Snapshot {
		readiness := "degraded"
		if v.AllReadyExcept("") {
			readiness = "ready"
		}
		at, _ := time.Parse(time.RFC3339Nano, e.ObservedAt)
		return protocol.Snapshot{SchemaVersion: protocol.Version, Kind: "kernel-info", Scope: e.Scope, Role: e.Role, Incarnation: e.Incarnation, Revision: e.Revision, ObservedAt: e.ObservedAt, ValidUntil: at.Add(actor.StaleAfter()).UTC().Format(time.RFC3339Nano), KernelReadiness: readiness, Members: v.Members}
	})
}
