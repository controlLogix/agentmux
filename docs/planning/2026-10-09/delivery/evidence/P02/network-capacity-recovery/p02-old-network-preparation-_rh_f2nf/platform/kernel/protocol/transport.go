package protocol

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/controlLogix/agentmux/platform/localtls"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
)

// SubjectSet is copied from the deployment's communication.Subjects contract.
type SubjectSet struct {
	Commands map[string]string
	Events   map[string]string
	Snapshot string
	Update   string
}

func (s SubjectSet) valid(hub string) bool {
	prefix := "amx.v1.h." + hub + ".kernel."
	if len(s.Commands) != 4 || len(s.Events) != 4 || s.Snapshot != prefix+"status.snapshot" || s.Update != prefix+"status.update" {
		return false
	}
	for _, role := range Roles() {
		if s.Commands[role] != prefix+"internal."+role+".command" || s.Events[role] != prefix+"internal."+role+".event" {
			return false
		}
	}
	return true
}
func (s SubjectSet) copy() SubjectSet {
	out := SubjectSet{Commands: map[string]string{}, Events: map[string]string{}, Snapshot: s.Snapshot, Update: s.Update}
	for role, value := range s.Commands {
		out.Commands[role] = value
	}
	for role, value := range s.Events {
		out.Events[role] = value
	}
	return out
}

type peer struct {
	event    Event
	received time.Time
	retired  map[string]bool
}

// View is a value snapshot. It exposes observations, not a shared broker client or host service.
type View struct {
	Members         []Member
	BrokerConnected bool
}

func (v View) AllReadyExcept(role string) bool {
	for _, m := range v.Members {
		if m.Role != role && m.State != "ready" {
			return false
		}
	}
	return v.BrokerConnected && len(v.Members) == 4
}

type Decision struct {
	State      string
	ErrorCodes []string
	Members    []Member
}

type Actor struct {
	config      Config
	role        string
	conn        *nats.Conn
	tlsDialer   *localtls.Dialer
	messages    chan *nats.Msg
	fault       chan struct{}
	connected   atomic.Bool
	incarnation string
	revision    uint64
	peers       map[string]*peer
	subjects    SubjectSet
}

func Open(ctx context.Context, config Config, role string, s SubjectSet) (*Actor, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("kernel_context_unavailable")
	}
	c, err := config.prepared(role)
	if err != nil {
		return nil, err
	}
	if !s.valid(c.Credentials.Scope.HubID) {
		return nil, errors.New("kernel_subjects_invalid")
	}
	s = s.copy()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errors.New("kernel_incarnation_unavailable")
	}
	a := &Actor{config: c, role: role, messages: make(chan *nats.Msg, 128), fault: make(chan struct{}, 1), incarnation: hex.EncodeToString(nonce[:]), peers: map[string]*peer{}, subjects: s.copy()}
	a.connected.Store(true)
	options := []nats.Option{nats.UserInfo(c.Credentials.Username, c.Credentials.Password), nats.Timeout(time.Second), nats.MaxReconnects(10), nats.ReconnectWait(200 * time.Millisecond), nats.ReconnectBufSize(0), nats.IgnoreDiscoveredServers(), nats.DisconnectErrHandler(func(_ *nats.Conn, _ error) { a.connected.Store(false) }), nats.ReconnectHandler(func(_ *nats.Conn) { a.connected.Store(true) }), nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, _ error) {
		select {
		case a.fault <- struct{}{}:
		default:
		}
	})}
	if c.ServerTrust != nil {
		dialer, err := c.ServerTrust.NewDialer(ctx, time.Second)
		if err != nil {
			return nil, errors.New("kernel_server_trust_unavailable")
		}
		a.tlsDialer = dialer
		options = append(options, nats.TLSHandshakeFirst(), nats.SetCustomDialer(dialer))
	}
	conn, err := nats.Connect(c.Credentials.NATSURL, options...)
	if err != nil {
		if localtls.IsAuthorityError(err) {
			return a.openFailure(errors.New("kernel_server_authentication_failed"))
		}
		return a.openFailure(errors.New("kernel_broker_unavailable"))
	}
	a.conn = conn
	fail := func() (*Actor, error) { return a.openFailure(errors.New("kernel_subscription_unavailable")) }
	forward := func(msg *nats.Msg) {
		if len(msg.Data) > MaxPayload {
			msg = &nats.Msg{Subject: msg.Subject, Reply: msg.Reply}
		}
		select {
		case a.messages <- msg:
		default:
			select {
			case a.fault <- struct{}{}:
			default:
			}
		}
	}
	for _, r := range Roles() {
		sub, err := conn.Subscribe(s.Events[r], forward)
		if err != nil {
			return fail()
		}
		if err := sub.SetPendingLimits(128, 128*MaxPayload); err != nil {
			return fail()
		}
	}
	sub, err := conn.Subscribe(s.Commands[role], forward)
	if err != nil {
		return fail()
	}
	if err := sub.SetPendingLimits(128, 128*MaxPayload); err != nil {
		return fail()
	}
	flush, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := conn.FlushWithContext(flush); err != nil {
		return fail()
	}
	return a, nil
}

// ErrCleanup means an exact owned transport could not yet be closed.
var ErrCleanup = errors.New("kernel_cleanup_failed")

// CleanupError retains failed-constructor ownership for an explicit Close retry.
// It never formats the actor, its credentials, or its transport handles.
type CleanupError struct {
	actor *Actor
	cause error
}

func (*CleanupError) Error() string                    { return "kernel_cleanup_failed" }
func (e *CleanupError) Format(state fmt.State, _ rune) { fmt.Fprint(state, e.Error()) }
func (e *CleanupError) Unwrap() error                  { return errors.Join(e.cause, ErrCleanup) }
func (e *CleanupError) Close() error {
	if e == nil {
		return nil
	}
	return e.actor.Close()
}
func (a *Actor) openFailure(cause error) (*Actor, error) {
	if err := a.Close(); err != nil {
		return nil, &CleanupError{actor: a, cause: cause}
	}
	return nil, cause
}
func (a *Actor) Close() error {
	if a == nil {
		return nil
	}
	var cleanup error
	if a.tlsDialer != nil && a.tlsDialer.Close() != nil {
		cleanup = ErrCleanup
	}
	if a.conn != nil {
		a.conn.Close()
	}
	return cleanup
}
func (a *Actor) Scope() Scope              { return a.config.Credentials.Scope }
func (a *Actor) StaleAfter() time.Duration { return a.config.StaleAfter }
func (a *Actor) view(now time.Time) View {
	v := View{Members: []Member{}, BrokerConnected: a.connected.Load()}
	for _, role := range Roles() {
		m := Member{Role: role, State: "unknown"}
		if p, ok := a.peers[role]; ok {
			e := p.event
			m = Member{Role: role, State: e.State, Incarnation: e.Incarnation, Revision: e.Revision, ObservedAt: e.ObservedAt}
			if !v.BrokerConnected || now.Sub(p.received) > a.config.StaleAfter || !fresh(e.ObservedAt, now, a.config.StaleAfter) {
				m.State = "stale"
			}
		}
		v.Members = append(v.Members, m)
	}
	return v
}
func (a *Actor) accept(msg *nats.Msg, now time.Time) bool {
	if msg.Reply != "" {
		return false
	}
	role := ""
	for _, r := range Roles() {
		if msg.Subject == a.subjects.Events[r] {
			role = r
			break
		}
	}
	if role == "" {
		return false
	}
	e, err := DecodeEvent(msg.Data, a.Scope(), role, now, a.config.StaleAfter)
	if err != nil {
		return false
	}
	if role == a.role && e.Incarnation != a.incarnation {
		return false
	}
	p, ok := a.peers[role]
	if !ok {
		p = &peer{retired: map[string]bool{}}
		a.peers[role] = p
	} else if p.event.Incarnation == e.Incarnation {
		if e.Revision <= p.event.Revision {
			return false
		}
	} else {
		if p.retired[e.Incarnation] || len(p.retired) >= 32 {
			return false
		}
		p.retired[p.event.Incarnation] = true
	}
	p.event = e
	p.received = now
	return true
}
func (a *Actor) emit(ctx context.Context, decision Decision, now time.Time, export func(Event, View) Snapshot) error {
	if a.revision >= MaxRevision {
		return errors.New("kernel_revision_exhausted")
	}
	a.revision++
	if decision.ErrorCodes == nil {
		decision.ErrorCodes = []string{}
	}
	if decision.Members == nil {
		decision.Members = []Member{}
	}
	e := Event{Version, "kernel-role-observation", a.Scope(), a.role, a.incarnation, a.revision, now.UTC().Format(time.RFC3339Nano), decision.State, decision.ErrorCodes, decision.Members}
	if _, err := DecodeEvent(mustJSON(e), a.Scope(), a.role, now, a.config.StaleAfter); err != nil {
		return errors.New("kernel_local_observation_invalid")
	}
	if !a.connected.Load() {
		return nil
	}
	if err := a.conn.Publish(a.subjects.Events[a.role], mustJSON(e)); err != nil {
		return errors.New("kernel_observation_unavailable")
	}
	if export != nil {
		if a.role != "exported-status" {
			return errors.New("kernel_export_role_invalid")
		}
		frame := export(e, a.view(now))
		bytes := mustJSON(frame)
		if _, err := DecodeSnapshot(bytes, a.Scope(), now, a.config.StaleAfter); err != nil {
			return errors.New("kernel_local_snapshot_invalid")
		}
		for _, subject := range []string{a.subjects.Snapshot, a.subjects.Update} {
			if err := a.conn.Publish(subject, bytes); err != nil {
				return errors.New("kernel_snapshot_unavailable")
			}
		}
	}
	flush, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := a.conn.FlushWithContext(flush); err != nil {
		return errors.New("kernel_observation_unavailable")
	}
	return nil
}
func mustJSON(value any) []byte { data, _ := json.Marshal(value); return data }

// Serve uses only NATS for peer traffic. Local evaluation callbacks belong to this process's own role.
func (a *Actor) Serve(ctx context.Context, evaluate func(View) Decision, export func(Event, View) Snapshot) (result error) {
	defer func() {
		if a.Close() != nil {
			result = &CleanupError{actor: a, cause: result}
		}
	}()
	if ctx == nil {
		return errors.New("kernel_context_unavailable")
	}
	if ctx.Err() != nil {
		return nil
	}
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_ = a.emit(shutdown, Decision{State: "stopping"}, a.config.Services.Clock.Now(), nil)
	}()
	ticker := time.NewTicker(a.config.Interval)
	defer ticker.Stop()
	lastEmit := time.Time{}
	publish := func() error {
		now := a.config.Services.Clock.Now()
		lastEmit = now
		return a.emit(ctx, evaluate(a.view(now)), now, export)
	}
	if err := publish(); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-a.fault:
			return errors.New("kernel_broker_permission_or_delivery_failed")
		case msg := <-a.messages:
			now := a.config.Services.Clock.Now()
			if msg.Subject == a.subjects.Commands[a.role] {
				if msg.Reply == "" {
					if _, err := DecodeCommand(msg.Data, a.Scope(), a.role); err == nil && now.Sub(lastEmit) >= a.config.Interval {
						if err := publish(); err != nil {
							if ctx.Err() != nil {
								return nil
							}
							return err
						}
					}
				}
			} else if !a.accept(msg, now) {
				a.config.Services.Logger.Code("kernel_event_rejected")
			}
		case <-ticker.C:
			if a.conn.IsClosed() {
				return errors.New("kernel_broker_unavailable")
			}
			if err := publish(); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
		}
	}
}
