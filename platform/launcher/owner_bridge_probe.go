//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/nats-io/nats.go"
)

// probe is restricted to the initial ensure call. Default and final requests
// retain their existing waiting behavior.
func (c *OwnerBridgeClient) probe(parent context.Context, invocationID string) (result StartupStatusObservation, failure error) {
	empty := StartupStatusObservation{}
	if c == nil || parent == nil || !ownerBridgeInvocation.MatchString(invocationID) {
		return empty, bridgeError("request_invalid")
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		return empty, bridgeError("deadline")
	}
	credential, _, err := loadBridgeCredential(c.config, c.enrollment, deployment.OwnerBridgeClientUser)
	if err != nil {
		return empty, err
	}
	id, err := hostInvocationID("request_")
	if err != nil {
		return empty, bridgeError("nonce_failed")
	}
	nc, dialer, err := bridgeConnect(ctx, c.config, credential)
	if err != nil {
		return empty, err
	}
	defer nc.Close()
	defer func() {
		if cleanup, failed := closeOwnedTransport(dialer, failure, "owner_bridge_owned_connection_cleanup_failed"); failed {
			result, failure = empty, cleanup
		}
	}()
	// Connect installed fixed private handling before callbacks could run.
	// NATS still records each protocol error in LastError before ordered PONG.
	// ChanSubscription does not support SetPendingLimits in the pinned client.
	// A one-message channel and server-side one-message unsubscribe bound the
	// queue. The pinned factory's native payload ceiling bounds that one frame.
	if nc.MaxPayload() <= 0 || nc.MaxPayload() > 1024*1024 {
		return empty, bridgeError("reply_invalid")
	}
	replySubject := c.subjects.ReplyPrefix + id[len("request_"):]
	messages := make(chan *nats.Msg, 1)
	sub, err := nc.ChanSubscribe(replySubject, messages)
	if err != nil {
		return empty, bridgeError("subscribe_failed")
	}
	defer sub.Unsubscribe()
	if sub.AutoUnsubscribe(1) != nil {
		return empty, bridgeError("subscribe_failed")
	}
	if err = nc.FlushWithContext(ctx); err != nil {
		if authority := ownerBridgeProbeAuthorityError(nc); authority != nil {
			return empty, authority
		}
		if ctx.Err() != nil {
			return empty, bridgeError("deadline")
		}
		return empty, bridgeError("connection_unavailable")
	}
	if authority := ownerBridgeProbeAuthorityError(nc); authority != nil {
		return empty, authority
	}
	request := ownerBridgeRequest{protocol.Version, "host-owner-status-request", "ensure", id, invocationID, c.config.Kernel.Scope, bridgeTime(time.Now())}
	raw, _ := json.Marshal(request)
	if err = nc.PublishRequest(c.subjects.Request, replySubject, raw); err == nil {
		err = nc.FlushWithContext(ctx)
	}
	if authority := ownerBridgeProbeAuthorityError(nc); authority != nil {
		return empty, authority
	}
	if ctx.Err() != nil {
		return empty, bridgeError("deadline")
	}
	if err != nil {
		return empty, bridgeError("connection_unavailable")
	}
	var msg *nats.Msg
	select {
	case msg = <-messages:
	case <-ctx.Done():
		if authority := ownerBridgeProbeAuthorityError(nc); authority != nil {
			return empty, authority
		}
		return empty, bridgeError("deadline")
	}
	if authority := ownerBridgeProbeAuthorityError(nc); authority != nil {
		return empty, authority
	}
	if ctx.Err() != nil {
		return empty, bridgeError("deadline")
	}
	if validOwnerBridgeNoResponders(msg, c.subjects.Request, replySubject) {
		return empty, bridgeError("no_responders")
	}
	var reply ownerBridgeReply
	if msg == nil || len(msg.Header) != 0 || msg.Reply != "" || msg.Subject != replySubject || decodeBridgeReply(msg.Data, &reply) != nil || reply.RequestID != id || reply.InvocationID != invocationID || reply.Scope != c.config.Kernel.Scope || !bridgeFresh(reply.SentAt, time.Now()) || !bridgeObservationBound(reply.Observation, c.enrollment, invocationID, time.Now()) {
		return empty, bridgeError("reply_invalid")
	}
	if ctx.Err() != nil {
		return empty, bridgeError("deadline")
	}
	return reply.Observation, nil
}

func ownerBridgeProbeAuthorityError(nc *nats.Conn) error {
	if authority := ownerBridgeAuthorityLastError(nc); authority != nil {
		return authority
	}
	if nc.LastError() != nil {
		return bridgeError("reply_invalid")
	}
	return nil
}

// This is the exact pinned2.15.0 native no-responders frame. It is an interest
// hint only; it supplies no instance observation or child ownership authority.
func validOwnerBridgeNoResponders(msg *nats.Msg, request, reply string) bool {
	return msg != nil && msg.Subject == reply && msg.Reply == "" && len(msg.Data) == 0 && len(msg.Header) == 2 && len(msg.Header["Status"]) == 1 && msg.Header["Status"][0] == "503" && len(msg.Header["Nats-Subject"]) == 1 && msg.Header["Nats-Subject"][0] == request
}
