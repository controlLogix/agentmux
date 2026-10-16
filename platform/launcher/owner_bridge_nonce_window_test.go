//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/nats-io/nats.go"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The native TLS broker, authenticated service handler and acquired owner
// lease are real. enter/complete below are documented private operation
// transitions, not a substituted production Bootstrap or the historical
// intermittent Run cause. No Docker/installed-host acceptance is claimed.
func TestOwnerBridgeNonceCancellationBeforeCompletionKeepsReply(t *testing.T) {
	f := newBridgeFixture(t)
	f.startBroker(t)
	op, err := func() (*bootstrapOperation, error) {
		server, e := LoadOwnerBridgeServer(f.config, f.owner, f.enrollment)
		if e != nil {
			return nil, e
		}
		startup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		t.Cleanup(cancel)
		lifetime, stop := context.WithCancel(context.Background())
		t.Cleanup(stop)
		lease, e := AcquireBootstrapLock(startup, f.profile.ProfileDirectory, f.profile.InstanceID, "owner-status-service")
		if e != nil {
			return nil, e
		}
		t.Cleanup(func() {
			if lease.Close() != nil {
				t.Error("actual lease cleanup failed")
			}
		})
		return newBootstrapOperation(startup, lifetime, server, lease, "attempt_"+strings.Repeat("a", 32))
	}()
	if err != nil {
		t.Fatal("actual private operation admission failed")
	}
	core, cancelCore := context.WithCancel(op.startup)
	t.Cleanup(cancelCore)
	if op.enter(core, f.config, f.profile, op.attemptID) != nil {
		t.Fatal("component actual entry unavailable")
	}
	ready := make(chan struct{})
	done := make(chan error, 1)
	lifetime, cancelLifetime := context.WithCancel(op.lifetime)
	joined := false
	go func() { done <- op.server.serveLoop(lifetime, op.startup, op.attemptID, nil, nil, ready, op) }()
	t.Cleanup(func() {
		cancelLifetime()
		if !joined {
			select {
			case <-done:
				joined = true
			case <-time.After(3 * time.Second):
				t.Error("owned service handler not joined")
			}
		}
	})
	select {
	case <-ready:
	case <-op.startup.Done():
		t.Fatal("actual handler subscription unavailable")
	}
	requestCtx, stopRequest := context.WithTimeout(op.startup, 5*time.Second)
	defer stopRequest()
	credential, subjects, err := loadBridgeCredential(f.config, f.enrollment, "runtime-client")
	if err != nil {
		t.Fatal("actual client credential unavailable")
	}
	nc, dialer, err := bridgeConnect(requestCtx, f.config, credential)
	if err != nil {
		t.Fatal("authenticated TLS client unavailable")
	}
	t.Cleanup(func() {
		if closeBridgeConnection(nc, dialer, nil) != nil {
			t.Error("exact connection cleanup failed")
		}
	})
	nonce := "request_" + strings.Repeat("b", 32)
	invocation := "attempt_" + strings.Repeat("c", 32)
	sub, err := nc.SubscribeSync(subjects.ReplyPrefix + strings.TrimPrefix(nonce, "request_"))
	if err != nil || nc.FlushWithContext(requestCtx) != nil {
		t.Fatal("actual reply subscription unavailable")
	}
	defer sub.Unsubscribe()
	raw, err := json.Marshal(ownerBridgeRequest{protocol.Version, "host-owner-status-request", "status", nonce, invocation, f.config.Kernel.Scope, bridgeTime(time.Now())})
	if err != nil {
		t.Fatal("fixed request unavailable")
	}
	cancelCore() // The admitted core is canceled, but completion has not occurred.
	if nc.Publish(subjects.Request, raw) != nil || nc.FlushWithContext(requestCtx) != nil {
		t.Fatal("authenticated canceled-core request unavailable")
	}
	before, stopBefore := context.WithTimeout(requestCtx, 200*time.Millisecond)
	premature, receiveErr := sub.NextMsgWithContext(before)
	stopBefore()
	if premature != nil || !errors.Is(receiveErr, context.DeadlineExceeded) {
		t.Fatal("boundary did not remain completion-in-flight")
	}
	t.Log("safe boundary: canceled core, completion still open, first authenticated request flushed, no premature response")
	if op.complete(nil, core.Err()) != nil {
		t.Fatal("actual component completion transition failed")
	}
	// Same immutable request ID/body; no new nonce or extended deadline.
	if nc.Publish(subjects.Request, raw) != nil || nc.FlushWithContext(requestCtx) != nil {
		t.Fatal("same request retransmission failed")
	}
	msg, replyErr := sub.NextMsgWithContext(requestCtx)
	if replyErr != nil {
		t.Logf("safe completed boundary: nonceUnchanged=true completed=true replyDeadline=%t replyClosed=%t serviceJoined=%t", errors.Is(replyErr, context.DeadlineExceeded), errors.Is(replyErr, nats.ErrConnectionClosed), joined)
		t.Fatal("accepted canceled-core nonce lost its completed reply")
	}
	var reply ownerBridgeReply
	if decodeBridgeReply(msg.Data, &reply) != nil || reply.RequestID != nonce || reply.InvocationID != invocation || reply.Observation.Disposition != "failed" {
		t.Fatal("completed reply shape/correlation invalid")
	}
	select {
	case result := <-done:
		joined = true
		if result == nil {
			t.Fatal("actual failed service outcome lost")
		}
	case <-requestCtx.Done():
		t.Fatal("actual completed service did not join")
	}
}

func TestOwnerBridgeNonceWaitEligibilityBoundaries(t *testing.T) {
	for _, fault := range []string{"unbounded", "non_cancelled", "spoofed_refusal", "scope", "profile", "enrollment", "closed_lease", "replacement", "symlink", "already_completed", "expires"} {
		t.Run(fault, func(t *testing.T) {
			op, f, lease, _, _ := pendingOperationFixture(t)
			core, cancel := context.WithCancel(op.startup)
			defer cancel()
			if op.enter(core, f.config, f.profile, op.attemptID) != nil {
				t.Fatal("actual component entry failed")
			}
			if fault != "non_cancelled" {
				cancel()
			}
			ctx, stop := context.WithTimeout(op.startup, 100*time.Millisecond)
			defer stop()
			refusal := errOperationNotPending
			switch fault {
			case "unbounded":
				ctx = context.Background()
			case "spoofed_refusal":
				refusal = errors.New("bootstrap_operation_not_pending")
			case "scope":
				op.scope.HubID = "foreign_hub"
			case "profile":
				op.profile.DisplayName = "changed"
			case "enrollment":
				op.server.enrollment.Owner.Identity.Revision++
			case "closed_lease":
				if lease.Close() != nil {
					t.Fatal("fixture exact lease close failed")
				}
			case "replacement", "symlink":
				name := op.leaseFile.Name()
				saved := name + ".original"
				if os.Rename(name, saved) != nil {
					t.Fatal("fixture original lease retention failed")
				}
				if fault == "replacement" {
					if os.WriteFile(name, []byte("foreign"), 0600) != nil {
						t.Fatal("replacement fixture failed")
					}
				} else {
					if os.Symlink(filepath.Base(saved), name) != nil {
						t.Fatal("symlink fixture failed")
					}
				}
				t.Cleanup(func() {
					if os.Remove(name) != nil || os.Rename(saved, name) != nil {
						t.Error("fixture exact canonical lease restore failed")
					}
				})
			case "already_completed":
				if op.complete(nil, core.Err()) != nil {
					t.Fatal("actual completed transition failed")
				}
			}
			waited, err := op.awaitCanceledCoreCompletion(ctx, refusal)
			if fault == "already_completed" {
				if !waited || err != nil || ctx.Err() != nil {
					t.Fatal("completed cancellation race rejected")
				}
				return
			}
			if waited {
				t.Fatal("unqualified boundary authorized completion")
			}
			if fault == "expires" {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("original remaining context not honored")
				}
				if op.complete(nil, core.Err()) != nil {
					t.Fatal("late component completion failed")
				}
				late, lateErr := op.awaitCanceledCoreCompletion(ctx, refusal)
				if late || lateErr == nil {
					t.Fatal("expired original context accepted late completion")
				}
				return
			}
			if ctx.Err() != nil {
				t.Fatal("refusal waited until deadline instead of rejecting")
			}
			if fault == "non_cancelled" || fault == "spoofed_refusal" {
				if err != nil {
					t.Fatal("non-canceled or spoofed refusal changed result")
				}
				return
			}
			expected := "bootstrap_operation_binding_invalid"
			switch fault {
			case "unbounded":
				expected = "bootstrap_operation_deadline_missing"
			case "closed_lease", "replacement", "symlink":
				expected = "bootstrap_operation_lease_invalid"
			}
			if err == nil || err.Error() != expected {
				t.Fatal("exact boundary refusal missing")
			}
		})
	}
}
