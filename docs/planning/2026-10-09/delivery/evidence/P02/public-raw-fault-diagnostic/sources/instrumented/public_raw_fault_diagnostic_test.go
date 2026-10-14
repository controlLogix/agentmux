package deployment

import (
	"context"
	"errors"
	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"net"
	"sync"
	"testing"
	"time"
)

// Diagnostic copy only: no production API or shared source change.
var rawPublicState struct {
	sync.Mutex
	armed  bool
	socket *observeOwnedConnection
	before any
	cause  error
}

func rawPublicArmSocket(s *observeOwnedConnection) {
	rawPublicState.Lock()
	defer rawPublicState.Unlock()
	if rawPublicState.armed && rawPublicState.socket == nil {
		s.Conn = &probeFailCloseOnce{Conn: s.Conn}
		rawPublicState.socket = s
	}
}
func rawPublicCapture(d *observeDialer, facts any, err error) {
	rawPublicState.Lock()
	defer rawPublicState.Unlock()
	if rawPublicState.socket != nil && rawPublicState.socket.owner == d {
		rawPublicState.before = facts
		rawPublicState.cause = err
	}
}
func rawPublicBegin(t *testing.T) {
	t.Helper()
	rawPublicState.Lock()
	rawPublicState.armed = true
	rawPublicState.socket = nil
	rawPublicState.before = nil
	rawPublicState.cause = nil
	rawPublicState.Unlock()
	t.Cleanup(func() {
		rawPublicState.Lock()
		s := rawPublicState.socket
		rawPublicState.armed = false
		rawPublicState.Unlock()
		if s != nil {
			ctx, c := context.WithTimeout(context.Background(), time.Second)
			defer c()
			s.owner.closeContext(ctx)
			if s.owner.closeContext(ctx) != nil {
				t.Error("exact diagnostic socket cleanup failed")
			}
		}
	})
}
func rawPublicCheck(t *testing.T, err error) any {
	t.Helper()
	rawPublicState.Lock()
	s, b, cause := rawPublicState.socket, rawPublicState.before, rawPublicState.cause
	rawPublicState.Unlock()
	var retained *RawTransportCleanupError
	if s == nil || b == nil || cause != nil || !errors.As(err, &retained) || retained.dialer != s.owner || !errors.Is(err, ErrRawTransportCleanup) {
		t.Fatal("successful actual caller lost exact cleanup owner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if retained.Close(ctx) != nil || retained.Close(ctx) != nil {
		t.Fatal("exact caller retry failed")
	}
	s.owner.mu.Lock()
	remaining := len(s.owner.sockets)
	s.owner.mu.Unlock()
	if remaining != 0 {
		t.Fatal("caller retry left owned hooks")
	}
	actual := s.Conn.(*probeFailCloseOnce).Conn
	if _, e := actual.Write([]byte("closed")); !errors.Is(e, net.ErrClosed) {
		t.Fatal("actual TCP socket not closed after retry")
	}
	return b
}
func TestRawPublicCallerCleanupInvalidatesFacts(t *testing.T) {
	t.Run("team", func(t *testing.T) {
		f := newTeamBasicFixture(t)
		f.publish(t)
		resolver, _ := teamBasicResolver(t, f.policy, communication.OrdinaryPlugin, f.password)
		c, e := NewTeamConnection(f.policy, resolver)
		if e != nil {
			t.Fatal("actual team admission failed")
		}
		baseline, e := c.Observe(context.Background())
		if e != nil || baseline.Snapshot == nil || !baseline.TLSVerified || !baseline.Authenticated || !baseline.ServerIdentityVerified {
			t.Fatal("actual team baseline lacks facts")
		}
		rawPublicBegin(t)
		out, e := c.Observe(context.Background())
		before := rawPublicCheck(t, e).(TeamConnectionObservation)
		if before.Snapshot == nil || !before.TLSVerified || !before.Authenticated || !before.ServerIdentityVerified || before.Code != "read_only_observed" {
			t.Fatal("actual precleanup team facts absent")
		}
		if out != (TeamConnectionObservation{DomainAvailability: "unavailable", KernelAvailability: "unavailable", Code: "cleanup_failed"}) {
			t.Fatal("team returned facts after failed cleanup")
		}
	})
	t.Run("probe", func(t *testing.T) {
		f := newHealthFixture(t, false)
		if _, e := ProvisionAndProbe(context.Background(), f.options); e != nil {
			t.Fatal("actual probe seed failed")
		}
		baseline, e := Probe(context.Background(), f.options)
		if e != nil || baseline.Sequence == 0 {
			t.Fatal("actual probe baseline lacks readback")
		}
		rawPublicBegin(t)
		out, e := Probe(context.Background(), f.options)
		before := rawPublicCheck(t, e).(ProbeResult)
		if before.Sequence == 0 || before.ServerName != f.options.ServerName || before.Domain != f.options.Domain {
			t.Fatal("actual precleanup probe readback absent")
		}
		if out != (ProbeResult{}) {
			t.Fatal("probe returned facts after failed cleanup")
		}
		f.assertConnections(t, 0)
	})
	t.Run("observe", func(t *testing.T) {
		f := readOnlyObservationFixture(t, true)
		o := ObserveOptions{f.options, true}
		baseline, e := Observe(context.Background(), o)
		if e != nil || baseline.PersistenceEvidence != PersistenceRecordSeen || baseline.RecordSequence == 0 {
			t.Fatal("actual observer baseline lacks record")
		}
		rawPublicBegin(t)
		out, e := Observe(context.Background(), o)
		before := rawPublicCheck(t, e).(Observation)
		if !before.BrokerVerified || before.PersistenceEvidence != PersistenceRecordSeen || before.RecordSequence != baseline.RecordSequence || before.RecordDigest != baseline.RecordDigest {
			t.Fatal("actual precleanup observer facts absent")
		}
		if out.BrokerVerified || out.ServerName != "" || out.ServerVersion != "" || out.Domain != "" || out.Stream != "" || out.RecordSequence != 0 || out.RecordObservedAt != "" || out.RecordDigest != "" || out.PersistenceEvidence != PersistenceUnknown || out.Code != "observation_incomplete" {
			t.Fatal("observer returned facts after failed cleanup")
		}
		f.assertConnections(t, 0)
	})
}
