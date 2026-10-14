// Package lifecycle publishes protected peer observations; direct process controls remain with the supervisor.
package lifecycle

import (
	"context"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

func Run(ctx context.Context, c protocol.Config, subjects protocol.SubjectSet) error {
	actor, err := protocol.Open(ctx, c, "kernel-lifecycle", subjects)
	if err != nil {
		return err
	}
	return actor.Serve(ctx, func(v protocol.View) protocol.Decision {
		codes := []string{}
		if !v.AllReadyExcept("kernel-lifecycle") {
			codes = append(codes, "peer_unavailable")
		}
		return protocol.Decision{State: "ready", ErrorCodes: codes, Members: v.Members}
	}, nil)
}
