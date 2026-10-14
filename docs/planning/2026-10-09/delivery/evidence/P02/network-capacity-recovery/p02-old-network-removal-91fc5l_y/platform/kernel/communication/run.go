package communication

import (
	"context"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

// Run owns only this protected process's scoped NATS connection and observation loop.
func Run(ctx context.Context, c protocol.Config, subjects protocol.SubjectSet) error {
	actor, err := protocol.Open(ctx, c, "internal-communication", subjects)
	if err != nil {
		return err
	}
	return actor.Serve(ctx, func(v protocol.View) protocol.Decision { return protocol.Decision{State: "ready"} }, nil)
}
