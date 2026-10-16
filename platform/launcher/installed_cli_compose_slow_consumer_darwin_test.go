//go:build darwin && cgo && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/localtls"
	"github.com/nats-io/nats.go"
)

type darwinSlowConsumerFault struct {
	connection   *nats.Conn
	subscription *nats.Subscription
	cause        error
}

type darwinSlowConsumerConnection struct {
	connection    *nats.Conn
	dialer        *localtls.Dialer
	attempted     bool
	failure       error
	faults        chan darwinSlowConsumerFault
	allowedSlow   *nats.Subscription
	callbacksDone chan struct{}
	faultOverflow atomic.Bool
}

// Close only these exact owned connections. A failed close remains a failed
// test even if the cleanup retry later succeeds; it never becomes readiness.
func (owned *darwinSlowConsumerConnection) close() error {
	if owned.attempted {
		return owned.failure
	}
	owned.attempted = true
	if owned.connection != nil {
		owned.connection.Close()
	}
	owned.failure, _ = closeOwnedTransport(owned.dialer, nil, "kernel_status_owned_connection_cleanup_failed")
	if owned.connection != nil {
		timer := time.NewTimer(time.Second)
		defer timer.Stop()
		select {
		case <-owned.callbacksDone:
		case <-timer.C:
			owned.failure = errors.Join(owned.failure, errors.New("slow_consumer_close_callbacks_incomplete"))
		}
	}
	return owned.failure
}

func darwinSlowConsumerConnect(t *testing.T, f *bootstrapDockerFixture, ctx context.Context, faults chan darwinSlowConsumerFault) *darwinSlowConsumerConnection {
	t.Helper()
	dialer, err := f.Config.Kernel.TLS.NewDialer(ctx, time.Second)
	if err != nil {
		t.Fatal("slow consumer enrolled TLS dialer unavailable")
	}
	owned := &darwinSlowConsumerConnection{dialer: dialer, faults: faults, callbacksDone: make(chan struct{})}
	t.Cleanup(func() {
		if err := owned.close(); err != nil {
			f.RetainForRecovery(t)
			t.Error("slow consumer owned transport cleanup failed")
			if errors.Is(err, ErrTransportCleanup) {
				var retained *TransportCleanupError
				if !errors.As(err, &retained) || retained == nil || retained.dialer == nil {
					t.Error("slow consumer cleanup owner unavailable")
				} else if retained.Close() != nil {
					t.Error("slow consumer exact transport cleanup retry failed")
				}
			}
		}
		darwinSlowConsumerCheckFaults(t, owned)
	})
	owned.connection, err = nats.Connect(f.Config.Kernel.Endpoint,
		nats.UserInfo(communication.OrdinaryPlugin, f.Config.Kernel.Password),
		nats.TLSHandshakeFirst(), nats.SetCustomDialer(dialer), nats.NoReconnect(),
		nats.IgnoreDiscoveredServers(), nats.Timeout(time.Second),
		nats.ClosedHandler(func(_ *nats.Conn) { close(owned.callbacksDone) }),
		nats.ErrorHandler(func(connection *nats.Conn, subscription *nats.Subscription, cause error) {
			// Never block a NATS callback, expose private error text or close a channel
			// while the connection can still deliver a callback.
			select {
			case faults <- darwinSlowConsumerFault{connection, subscription, cause}:
			default:
				owned.faultOverflow.Store(true)
			}
		}))
	if err != nil || owned.connection == nil {
		t.Fatal("slow consumer scoped ordinary connection refused")
	}
	return owned
}

// NATS dispatches the closed callback after earlier queued error callbacks.
// Post-close checks therefore cover the completed callback stream, while checks
// during recovery are checkpoints. Callback-buffer overflow is an explicit fail.
func darwinSlowConsumerCheckFaults(t *testing.T, owned *darwinSlowConsumerConnection) bool {
	t.Helper()
	valid := true
	if owned.faultOverflow.Load() {
		valid = false
		t.Error("slow consumer callback capture overflowed")
	}
	for {
		select {
		case fault := <-owned.faults:
			if owned.allowedSlow == nil || fault.connection != owned.connection || fault.subscription != owned.allowedSlow || !errors.Is(fault.cause, nats.ErrSlowConsumer) {
				valid = false
				t.Error("slow consumer connection reported an unexpected asynchronous error")
			}
		default:
			return valid
		}
	}
}

func darwinSlowConsumerStatus(t *testing.T, f *bootstrapDockerFixture, selection HostPolicySelection, record hostPolicyRecord,
	original *composeDarwinCLIFront, baseline StartupStatusObservation, deadline time.Time, name string) StartupStatusObservation {
	t.Helper()
	if time.Until(deadline) < darwinScenarioRefusalBudget {
		t.Fatal("slow consumer status cannot fit its original scenario budget")
	}
	front := composeDarwinCLIPrepare(t, f, selection, record, "status")
	darwinScenarioStart(t, f, front, darwinScenarioRefusalBudget)
	out := darwinScenarioResponse(t, f, front, record, name, darwinScenarioRefusalBudget, false)
	if time.Now().After(deadline) || out == nil || out.Disposition != "reused" || front.lifetime != nil ||
		!reflect.DeepEqual(out.Caller, baseline.Caller) || out.Instance.Readiness != "degraded" ||
		!reflect.DeepEqual(out.Instance.InstanceID, baseline.Instance.InstanceID) ||
		!reflect.DeepEqual(out.Instance.ProfileID, baseline.Instance.ProfileID) ||
		!reflect.DeepEqual(out.Instance.InstalledVersion, baseline.Instance.InstalledVersion) ||
		!reflect.DeepEqual(out.Instance.RunningVersion, baseline.Instance.RunningVersion) ||
		!reflect.DeepEqual(out.Instance.Endpoint, baseline.Instance.Endpoint) ||
		out.Persistence.Availability != "available" ||
		!reflect.DeepEqual(out.Persistence.ServerID, baseline.Persistence.ServerID) ||
		!reflect.DeepEqual(out.Persistence.DomainID, baseline.Persistence.DomainID) ||
		out.Work.State != "unavailable" || out.Work.Active != nil || out.Hubs.InventoryState != "unavailable" {
		t.Fatal("stalled subscriber changed accepted scoped installed status")
	}
	for _, role := range protocol.Roles() {
		found := false
		for _, service := range out.Instance.Services {
			if service.ServiceID == role && service.Readiness == "ready" && service.ObservedAt != nil && service.SourceRevision != nil {
				found = true
			}
		}
		if !found {
			t.Fatal("stalled subscriber prevented a fresh ready role observation")
		}
	}
	// The normal installed response validator above checks persistence evidence;
	// do not replace it with a fabricated write-ready or unknown value.
	original.lifetime.assertUnchanged(t, f)
	return *out
}

func TestInstalledCLIDarwinRealComposeSlowConsumerIsolationAndRecovery(t *testing.T) {
	f, selection, record := composeDarwinCLIEnrolledFixture(t)
	original := darwinScenarioCold(t, f, selection, record, "darwin-slow-consumer-cold")
	deadline := original.output.started.Add(f.Config.StartupTimeout)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	baselineStatus, _ := darwinScenarioRefresh(t, f, deadline)
	stored := darwinScenarioStored(t, f)
	baseline, err := ObserveKernel(ctx, f.Config.Kernel)
	if err != nil || baseline.KernelReadiness != "ready" {
		t.Fatal("slow consumer actual enrolled baseline unavailable")
	}
	cursor := protocol.SnapshotCursor{}
	if _, gap, err := cursor.Accept(mustStatusJSON(baseline), f.Config.Kernel.Scope, time.Now(), 3*time.Second); err != nil || gap {
		t.Fatal("slow consumer initial actual snapshot cursor refused")
	}
	wire, err := communication.Subjects(f.Config.Kernel.Scope.HubID)
	if err != nil {
		t.Fatal("slow consumer enrolled subjects refused")
	}
	faults := make(chan darwinSlowConsumerFault, 16)
	stalled := darwinSlowConsumerConnect(t, f, ctx, faults)
	subscription, err := stalled.connection.SubscribeSync(wire.Update)
	if err != nil {
		t.Fatal("slow consumer permitted update subscription refused")
	}
	stalled.allowedSlow = subscription
	t.Cleanup(func() {
		if subscription.IsValid() && subscription.Unsubscribe() != nil {
			t.Error("slow consumer subscription cleanup failed")
		}
	})
	if subscription.SetPendingLimits(1, protocol.MaxPayload) != nil || stalled.connection.FlushWithContext(ctx) != nil {
		t.Fatal("slow consumer bounded subscription admission failed")
	}
	stallDeadline := time.Now().Add(8 * time.Second)
	if deadline.Before(stallDeadline) {
		stallDeadline = deadline
	}
	stall, stop := context.WithDeadline(ctx, stallDeadline)
	defer stop()
	select {
	case fault := <-faults:
		if fault.connection != stalled.connection || fault.subscription != subscription || !errors.Is(fault.cause, nats.ErrSlowConsumer) {
			t.Fatal("stalled subscriber returned an unexpected transport failure")
		}
	case <-stall.Done():
		t.Fatal("actual subscriber did not report bounded slow consumer overflow")
	}
	dropped, dropErr := subscription.Dropped()
	pending, pendingBytes, pendingErr := subscription.Pending()
	if dropErr != nil || pendingErr != nil || dropped <= 0 || pending < 0 || pending > 1 || pendingBytes < 0 || pendingBytes > protocol.MaxPayload {
		t.Fatal("stalled subscription did not retain bounded pending data and explicit loss")
	}
	during := darwinSlowConsumerStatus(t, f, selection, record, original, baselineStatus, deadline, "darwin-slow-consumer-during-status")
	live, err := ObserveKernel(ctx, f.Config.Kernel)
	if err != nil || live.KernelReadiness != "ready" || live.Incarnation != baseline.Incarnation || live.Revision <= baseline.Revision {
		t.Fatal("stalled subscriber corrupted live kernel status publication")
	}
	if subscription.Unsubscribe() != nil {
		t.Fatal("stalled subscription release failed")
	}
	if !darwinSlowConsumerCheckFaults(t, stalled) {
		t.Fatal("slow consumer asynchronous failure prevents recovery acceptance")
	}
	if stalled.close() != nil {
		t.Fatal("stalled subscriber transport did not close")
	}
	if !darwinSlowConsumerCheckFaults(t, stalled) {
		t.Fatal("slow consumer asynchronous failure prevents recovery acceptance")
	}
	// Reconnect only to the same enrolled broker/principal. A full snapshot
	// resynchronizes the cursor while its real revision jump still reports a gap.
	recoveredFaults := make(chan darwinSlowConsumerFault, 16)
	recovered := darwinSlowConsumerConnect(t, f, ctx, recoveredFaults)
	snapshots, err := recovered.connection.SubscribeSync(wire.Snapshot)
	if err != nil {
		t.Fatal("reconnected ordinary snapshot subscription refused")
	}
	t.Cleanup(func() {
		if snapshots.IsValid() && snapshots.Unsubscribe() != nil {
			t.Error("reconnected snapshot subscription cleanup failed")
		}
	})
	if recovered.connection.FlushWithContext(ctx) != nil {
		t.Fatal("reconnected snapshot subscription flush failed")
	}
	receive, finish := context.WithTimeout(ctx, 3*time.Second)
	message, err := snapshots.NextMsgWithContext(receive)
	finish()
	if err != nil || message == nil {
		t.Fatal("reconnected consumer did not receive an actual fresh snapshot")
	}
	snapshot, gap, err := cursor.Accept(message.Data, f.Config.Kernel.Scope, time.Now(), 3*time.Second)
	if err != nil || !gap || snapshot.Incarnation != baseline.Incarnation || snapshot.Revision <= baseline.Revision+1 || snapshot.KernelReadiness != "ready" {
		t.Fatal("actual recovered snapshot did not expose lost revisions and resynchronize")
	}
	if _, _, err := cursor.Accept(message.Data, f.Config.Kernel.Scope, time.Now(), 3*time.Second); err == nil {
		t.Fatal("recovered snapshot replay was accepted")
	}
	if !darwinSlowConsumerCheckFaults(t, recovered) {
		t.Fatal("slow consumer asynchronous failure prevents recovery acceptance")
	}
	after := darwinSlowConsumerStatus(t, f, selection, record, original, baselineStatus, deadline, "darwin-slow-consumer-recovered-status")
	if snapshots.Unsubscribe() != nil {
		t.Fatal("reconnected snapshot subscription release failed")
	}
	if !darwinSlowConsumerCheckFaults(t, recovered) {
		t.Fatal("slow consumer asynchronous failure prevents recovery acceptance")
	}
	if recovered.close() != nil {
		t.Fatal("reconnected subscriber transport did not close")
	}
	if !darwinSlowConsumerCheckFaults(t, recovered) {
		t.Fatal("slow consumer asynchronous failure prevents recovery acceptance")
	}
	original.lifetime.assertUnchanged(t, f)
	stored.assertPreserved(t, f, "darwin-slow-consumer-resource-preservation.json")
	if ctx.Err() != nil {
		t.Fatal("slow consumer scenario exceeded its original startup budget")
	}
	f.WriteEvidence(t, "darwin-slow-consumer-isolation-recovery.json", map[string]any{
		"actualSubscriberOverflow": true, "droppedMessages": dropped, "pendingMessages": pending, "pendingBytes": pendingBytes,
		"stallBoundNanoseconds": int64(8 * time.Second), "sameKernelIncarnation": true, "baselineRevision": baseline.Revision,
		"recoveredRevision": snapshot.Revision, "revisionGapVisible": gap, "replayRefused": true,
		"duringDisposition": during.Disposition, "afterDisposition": after.Disposition, "instanceReadiness": after.Instance.Readiness,
		"sameCreatingHostAndFourRoles": true, "sameBroker": true, "sameVolume": true, "originalRecordRetained": true,
		"internalActorQueueOverflowClaimed": false,
	})
}
