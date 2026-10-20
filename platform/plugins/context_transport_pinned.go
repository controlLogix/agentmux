package plugins

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/controlLogix/agentmux/platform/localtls"
	"github.com/nats-io/nats.go"
)

// PinnedNATSContextProvider uses the existing exact context credential profile
// with the admitted local TLS-first endpoint, CA, DNS identity and leaf pin.
// It owns each dialer until all context leases and socket cleanup have joined.
type PinnedNATSContextProvider struct {
	mu            sync.Mutex
	base          *contextProvider
	trust         *localtls.ClientTrust
	lifetime      context.Context
	cancel        context.CancelFunc
	dialers       []*localtls.Dialer
	closedDialers map[*localtls.Dialer]bool
	active        int
	closing       bool
	closed        bool
}

func (*PinnedNATSContextProvider) Format(state fmt.State, _ rune) {
	fmt.Fprint(state, "[private pinned context provider]")
}
func (*PinnedNATSContextProvider) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-pinned-context-provider"}`), nil
}

func NewPinnedNATSContextProvider(ctx context.Context, options NATSContextOptions, trust *localtls.ClientTrust, ports ContextPorts) (*PinnedNATSContextProvider, error) {
	if ctx == nil || ctx.Err() != nil || trust == nil || options.ServerURL != trust.Policy().Endpoint {
		return nil, pluginError("context_transport_options_invalid")
	}
	provider, err := NewNATSContextProvider(ctx, options, ports)
	if err != nil {
		return nil, err
	}
	base := provider.(*contextProvider)
	if !bytes.Equal(base.ca, trust.Policy().RootsPEM) {
		return nil, pluginError("context_ca_invalid")
	}
	lifetime, cancel := context.WithCancel(context.Background())
	p := &PinnedNATSContextProvider{base: base, trust: trust, lifetime: lifetime, cancel: cancel, closedDialers: map[*localtls.Dialer]bool{}}
	base.connect = p.connect
	return p, nil
}
func (p *PinnedNATSContextProvider) Open(ctx context.Context, binding ContextBinding) (ContextLease, error) {
	if p == nil || ctx == nil {
		return nil, pluginError("context_transport_unavailable")
	}
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		return nil, pluginError("context_transport_unavailable")
	}
	p.active++
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.active--; p.mu.Unlock() }()
	lease, err := p.base.Open(ctx, binding)
	if nilContextDependency(lease) {
		return nil, err
	}
	policy := p.trust.Policy()
	return &pinnedContextLease{ContextLease: lease, serverName: policy.ServerName, leaf: policy.LeafCertificateSHA256}, err
}

type pinnedContextLease struct {
	ContextLease
	serverName, leaf string
}

func (l *pinnedContextLease) Bootstrap() ContextBootstrap {
	bootstrap := l.ContextLease.Bootstrap()
	bootstrap.transport.ServerName = l.serverName
	bootstrap.transport.LeafCertificateSHA256 = l.leaf
	return bootstrap
}
func (p *PinnedNATSContextProvider) connect(ctx context.Context, transport ContextTransport) (contextConnection, error) {
	fail := func(c *contextNATS) (contextConnection, error) {
		return c, pluginError("context_transport_unavailable")
	}
	if ctx == nil || ctx.Err() != nil {
		return nil, pluginError("context_transport_unavailable")
	}
	budget := 2 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		budget = min(budget, time.Until(deadline))
	}
	if budget <= 0 {
		return nil, pluginError("context_transport_unavailable")
	}
	dialer, err := p.trust.NewDialer(p.lifetime, budget)
	if err != nil {
		return nil, pluginError("context_transport_unavailable")
	}
	p.mu.Lock()
	p.dialers = append(p.dialers, dialer)
	p.mu.Unlock()
	c := &contextNATS{done: make(chan struct{})}
	admission, cancel := context.WithTimeout(ctx, budget)
	stopped := make(chan struct{})
	stop := context.AfterFunc(admission, func() { _ = dialer.Close(); close(stopped) })
	c.conn, err = nats.Connect(p.base.options.ServerURL, nats.UserJWTAndSeed(p.base.server.jwt, p.base.server.seed), nats.TLSHandshakeFirst(), nats.SetCustomDialer(dialer), nats.NoReconnect(), nats.IgnoreDiscoveredServers(), nats.NoEcho(), nats.Timeout(budget), nats.FlusherTimeout(100*time.Millisecond), nats.ClosedHandler(func(*nats.Conn) { c.lost() }), nats.ErrorHandler(func(*nats.Conn, *nats.Subscription, error) { c.lost() }))
	if !stop() {
		<-stopped
	}
	failed := err != nil || admission.Err() != nil
	cancel()
	if failed {
		if c.conn == nil {
			c.lost()
		}
		return fail(c)
	}
	c.requests, err = c.conn.SubscribeSync(transport.RequestSubject)
	if err == nil {
		c.results, err = c.conn.SubscribeSync(transport.ResultSubject)
	}
	if err == nil {
		err = c.requests.SetPendingLimits(contextServiceLimit, 4*contextWireLimit)
	}
	if err == nil {
		err = c.results.SetPendingLimits(contextOperationLimit, 4*contextWireLimit)
	}
	if err == nil {
		flush, cancel := context.WithTimeout(ctx, budget)
		err = c.conn.FlushWithContext(flush)
		cancel()
	}
	if err != nil || ctx.Err() != nil {
		return fail(c)
	}
	return c, nil
}
func (p *PinnedNATSContextProvider) Close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if ctx == nil {
		return pluginError("context_cleanup_incomplete")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closing = true
	if p.closed {
		return nil
	}
	p.base.mu.Lock()
	owners := len(p.base.owners) + len(p.base.opening)
	p.base.mu.Unlock()
	if p.active != 0 || owners != 0 || ctx.Err() != nil {
		return pluginError("context_cleanup_incomplete")
	}
	p.cancel()
	failed := false
	for _, dialer := range p.dialers {
		if p.closedDialers[dialer] {
			continue
		}
		if dialer.Close() != nil {
			failed = true
		} else {
			p.closedDialers[dialer] = true
		}
	}
	if failed {
		return pluginError("context_cleanup_incomplete")
	}
	p.base.server.seed = ""
	clear(p.base.server.raw)
	for id, credential := range p.base.clients {
		credential.seed = ""
		clear(credential.raw)
		p.base.clients[id] = credential
	}
	p.closed = true
	return nil
}
