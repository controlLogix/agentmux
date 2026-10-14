//go:build linux || darwin

package launcher

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/nats-io/nats.go"
)

func TestOwnerBridgeNativeNoRespondersFrame(t *testing.T) {
	f := newBridgeFixture(t)
	f.startBroker(t)
	nc, err := f.rawTLSClient(t, deployment.OwnerBridgeClientUser)
	if err != nil {
		t.Fatal("real pinned client refused")
	}
	subjects, err := deployment.OwnerBridgeSubjects(f.config.Kernel.Scope)
	if err != nil {
		t.Fatal("fixed subjects refused")
	}
	reply := subjects.ReplyPrefix + strings.Repeat("a", 32)
	messages := make(chan *nats.Msg, 1)
	sub, err := nc.ChanSubscribe(reply, messages)
	if err != nil {
		t.Fatal("fixed reply subscription refused")
	}
	defer sub.Unsubscribe()
	if sub.AutoUnsubscribe(1) != nil {
		t.Fatal("single native reply limit refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if nc.FlushWithContext(ctx) != nil || nc.PublishRequest(subjects.Request, reply, []byte("native no subscriber diagnostic")) != nil || nc.FlushWithContext(ctx) != nil {
		t.Fatal("native probe publication failed")
	}
	select {
	case msg := <-messages:
		if msg == nil || msg.Subject != reply || msg.Reply != "" || len(msg.Data) != 0 || len(msg.Header) != 2 || len(msg.Header["Status"]) != 1 || msg.Header["Status"][0] != "503" || len(msg.Header["Nats-Subject"]) != 1 || msg.Header["Nats-Subject"][0] != subjects.Request {
			t.Fatal("pinned native no-responders shape differs")
		}
	case <-ctx.Done():
		t.Fatal("native no-responders frame unavailable")
	}
}

func TestOwnerBridgeInitialProbeNoResponderHint(t *testing.T) {
	f := newBridgeFixture(t)
	f.startBroker(t)
	client, err := LoadOwnerBridgeClient(f.config, f.enrollment)
	if err != nil {
		t.Fatal("enrolled probe client refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = client.probe(ctx, "attempt_"+strings.Repeat("b", 32))
	if err == nil || err.Error() != "owner_bridge_no_responders" {
		t.Fatal("initial probe did not return the native no-responders hint")
	}
}

func TestOwnerBridgeProbeNativeHintShapeRefusals(t *testing.T) {
	request, reply := "fixed.request", "fixed.reply"
	for _, name := range []string{"exact", "nil", "body", "reply", "subject", "extra_header", "status_alias", "status_duplicate", "other_status", "request_mismatch", "request_duplicate", "description"} {
		t.Run(name, func(t *testing.T) {
			msg := &nats.Msg{Subject: reply, Header: nats.Header{"Status": []string{"503"}, "Nats-Subject": []string{request}}}
			switch name {
			case "nil":
				msg = nil
			case "body":
				msg.Data = []byte("not empty")
			case "reply":
				msg.Reply = "redirect"
			case "subject":
				msg.Subject = "other.reply"
			case "extra_header":
				msg.Header["Extra"] = []string{"value"}
			case "status_alias":
				delete(msg.Header, "Status")
				msg.Header["status"] = []string{"503"}
			case "status_duplicate":
				msg.Header["Status"] = []string{"503", "503"}
			case "other_status":
				msg.Header["Status"] = []string{"404"}
			case "request_mismatch":
				msg.Header["Nats-Subject"] = []string{"other.request"}
			case "request_duplicate":
				msg.Header["Nats-Subject"] = []string{request, request}
			case "description":
				msg.Header["Description"] = []string{"No Responders"}
			}
			if validOwnerBridgeNoResponders(msg, request, reply) != (name == "exact") {
				t.Fatal("native hint shape admission differs")
			}
		})
	}
}

func TestOwnerBridgeOptionalReplyMustMatchValidatedNonce(t *testing.T) {
	f := newBridgeFixture(t)
	subjects, _ := deployment.OwnerBridgeSubjects(f.config.Kernel.Scope)
	now := time.Now()
	request := ownerBridgeRequest{protocol.Version, "host-owner-status-request", "ensure", "request_" + strings.Repeat("c", 32), "attempt_" + strings.Repeat("d", 32), f.config.Kernel.Scope, bridgeTime(now)}
	derived := subjects.ReplyPrefix + request.RequestID[len("request_"):]
	for _, reply := range []string{"", derived, derived + ".extra", subjects.ReplyPrefix + strings.Repeat("e", 32), "_INBOX.arbitrary", subjects.ReplyPrefix + ">", "another.hub.reply"} {
		msg := &nats.Msg{Subject: subjects.Request, Reply: reply, Data: mustStatusJSON(request)}
		_, err := validateBridgeRequest(msg, f.config.Kernel.Scope, subjects, now)
		if (err == nil) != (reply == "" || reply == derived) {
			t.Fatal("optional fixed reply admission differs")
		}
	}
	msg := &nats.Msg{Subject: subjects.Request, Reply: derived, Header: nats.Header{"Extra": []string{"value"}}, Data: mustStatusJSON(request)}
	if _, err := validateBridgeRequest(msg, f.config.Kernel.Scope, subjects, now); err == nil {
		t.Fatal("header-bearing exact reply request accepted")
	}
	request.RequestID = "request_*"
	msg.Header = nil
	msg.Data = mustStatusJSON(request)
	if _, err := validateBridgeRequest(msg, f.config.Kernel.Scope, subjects, now); err == nil {
		t.Fatal("invalid JSON nonce admitted through reply field")
	}
}

func TestOwnerBridgeProbeAvailablePreservesLegacyRouting(t *testing.T) {
	f := newBridgeFixture(t)
	f.startBroker(t)
	f.startActors(t)
	if _, err := deployment.ProvisionAndProbe(context.Background(), f.config.Health); err != nil {
		t.Fatal("actual FILE fixture probe unavailable")
	}
	client, err := LoadOwnerBridgeClient(f.config, f.enrollment)
	if err != nil {
		t.Fatal("enrolled client refused")
	}
	server, err := LoadOwnerBridgeServer(f.config, f.owner, f.enrollment)
	if err != nil {
		t.Fatal("enrolled server refused")
	}
	invocation := "attempt_" + strings.Repeat("f", 32)
	// Cached Session facts are transport input only, not real cold-start proof.
	input := ownerObservationFixture(f.policy, f.profile, "reused")
	session := &Session{Status: input.status, observedAt: input.receivedAt, startupAttemptID: invocation}
	ctx, cancel := context.WithCancel(context.Background())
	done, ready := make(chan error, 1), make(chan struct{})
	go func() { done <- server.serve(ctx, invocation, session, nil, ready) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("owned probe service did not join")
		}
	}()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("actual service subscription unavailable")
	}
	if out, err := client.probe(context.Background(), invocation); err != nil || out.Disposition != "reused" {
		t.Fatal("exact reply probe did not receive correlated L04")
	}
	if out, err := client.Request(context.Background(), "ensure", invocation); err != nil || out.Disposition != "reused" {
		t.Fatal("legacy empty reply did not receive correlated L04")
	}
}

func TestOwnerBridgeProbeRejectsActualMalformedHint(t *testing.T) {
	f := newBridgeFixture(t)
	f.startBroker(t)
	client, err := LoadOwnerBridgeClient(f.config, f.enrollment)
	if err != nil {
		t.Fatal("enrolled client refused")
	}
	server, err := f.rawTLSClient(t, deployment.OwnerBridgeServerUser)
	if err != nil {
		t.Fatal("actual responder refused")
	}
	requests, err := server.SubscribeSync(client.subjects.Request)
	if err != nil {
		t.Fatal("fixed responder subscription refused")
	}
	defer requests.Unsubscribe()
	for _, name := range []string{"extra_header", "body", "reply_redirect"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if server.FlushWithContext(ctx) != nil {
				t.Fatal("actual responder flush failed")
			}
			done := make(chan error, 1)
			joined := false
			go func() { _, err := client.probe(ctx, "attempt_"+strings.Repeat("a", 32)); done <- err }()
			defer func() {
				cancel()
				if !joined {
					select {
					case <-done:
					case <-time.After(time.Second):
						t.Error("owned probe call did not join")
					}
				}
			}()
			request, err := requests.NextMsgWithContext(ctx)
			if err != nil {
				t.Fatal("actual probe request unavailable")
			}
			validated, err := validateBridgeRequest(request, f.config.Kernel.Scope, client.subjects, time.Now())
			if err != nil || request.Reply != client.subjects.ReplyPrefix+validated.RequestID[len("request_"):] {
				t.Fatal("actual probe nonce reply differs")
			}
			msg := &nats.Msg{Subject: request.Reply, Header: nats.Header{"Status": []string{"503"}, "Nats-Subject": []string{client.subjects.Request}}}
			switch name {
			case "extra_header":
				msg.Header["Extra"] = []string{"value"}
			case "body":
				msg.Data = []byte("not native")
			case "reply_redirect":
				msg.Reply = client.subjects.ReplyPrefix + strings.Repeat("b", 32)
			}
			if server.PublishMsg(msg) != nil || server.FlushWithContext(ctx) != nil {
				t.Fatal("actual malformed hint publication failed")
			}
			select {
			case err = <-done:
				joined = true
			case <-ctx.Done():
				t.Fatal("malformed hint probe did not finish")
			}
			if err == nil || err.Error() != "owner_bridge_reply_invalid" {
				t.Fatal("malformed native hint became a startup hint")
			}
		})
	}
}

func TestOwnerBridgeProbePermissionFailureStaysHard(t *testing.T) {
	f := newBridgeFixture(t)
	f.startBroker(t)
	nc, err := f.rawTLSClient(t, deployment.OwnerBridgeClientUser)
	if err != nil {
		t.Fatal("actual enrolled client refused")
	}
	nc.SetErrorHandler(func(*nats.Conn, *nats.Subscription, error) {})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if nc.Publish("$SYS.REQ.SERVER.PING", nil) != nil || nc.FlushWithContext(ctx) != nil {
		t.Fatal("actual permission control did not flush")
	}
	if err := ownerBridgeProbeAuthorityError(nc); err == nil || err.Error() != "owner_bridge_authority_rejected" {
		t.Fatal("actual permission violation became an unavailable hint")
	}
}

func TestOwnerBridgeProbeCanceledContextHasNoHint(t *testing.T) {
	f := newBridgeFixture(t)
	client, err := LoadOwnerBridgeClient(f.config, f.enrollment)
	if err != nil {
		t.Fatal("enrolled client refused")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.probe(ctx, "attempt_"+strings.Repeat("a", 32)); err == nil || err.Error() != "owner_bridge_deadline" {
		t.Fatal("canceled probe became a startup hint")
	}
}
