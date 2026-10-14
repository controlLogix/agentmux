// Package boot observes the required protected peers before declaring kernel boot ready.
package boot

import (
	"context"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

func Run(ctx context.Context, c protocol.Config, subjects protocol.SubjectSet) error {
	actor, err := protocol.Open(ctx, c, "boot", subjects)
	if err != nil {
		return err
	}
	return actor.Serve(ctx, func(v protocol.View) protocol.Decision {
		if v.AllReadyExcept("boot") {
			return protocol.Decision{State: "ready"}
		}
		return protocol.Decision{State: "degraded", ErrorCodes: []string{"peer_unavailable"}}
	}, nil)
}
