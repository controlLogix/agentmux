package launcher

import (
	"context"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/nats-io/nats.go"
)

type KernelStatusOptions struct {
	Endpoint, Password string
	Scope              protocol.Scope
	Timeout            time.Duration
}

func kernelStatusError(code string) error { return errors.New("kernel_status_" + code) }

type kernelStatusSocket struct {
	connection net.Conn
	stop       func() bool
	done       chan struct{}
}
type kernelStatusDialer struct {
	ctx     context.Context
	address string
	mu      sync.Mutex
	closed  bool
	sockets []kernelStatusSocket
}

// Cancellation closes only sockets created by this observer, including a
// socket whose peer has not finished the NATS greeting or TLS handshake.
func (d *kernelStatusDialer) Dial(network, address string) (net.Conn, error) {
	if address != d.address {
		return nil, kernelStatusError("invalid")
	}
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()
	if closed {
		return nil, kernelStatusError("cancelled")
	}
	c, err := (&net.Dialer{}).DialContext(d.ctx, network, address)
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	stop := context.AfterFunc(d.ctx, func() { c.Close(); close(done) })
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		if stop() {
			c.Close()
		} else {
			<-done
		}
		return nil, kernelStatusError("cancelled")
	}
	d.sockets = append(d.sockets, kernelStatusSocket{c, stop, done})
	d.mu.Unlock()
	return c, nil
}
func (d *kernelStatusDialer) close() {
	d.mu.Lock()
	d.closed = true
	sockets := d.sockets
	d.sockets = nil
	d.mu.Unlock()
	for _, s := range sockets {
		if s.stop() {
			s.connection.Close()
		} else {
			<-s.done
		}
	}
}

var kernelStatusID = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,95}$`)
var kernelStatusDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var kernelStatusVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
var kernelStatusPassword = regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`)

func kernelStatusEndpoint(o KernelStatusOptions) (string, error) {
	u, err := url.Parse(o.Endpoint)
	if err != nil || u == nil || (u.Scheme != "nats" && u.Scheme != "tls") || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(o.Endpoint, " \t\r\n,") {
		return "", kernelStatusError("invalid")
	}
	host, port, err := net.SplitHostPort(u.Host)
	n, pErr := strconv.Atoi(port)
	if err != nil || host == "" || pErr != nil || n < 1 || n > 65535 {
		return "", kernelStatusError("invalid")
	}
	s := o.Scope
	if !kernelStatusID.MatchString(s.HubID) || !kernelStatusID.MatchString(s.InstanceID) || !kernelStatusID.MatchString(s.ProfileID) || !kernelStatusDigest.MatchString(s.AssemblyDigest) || !kernelStatusDigest.MatchString(s.ReleaseManifestDigest) || !kernelStatusVersion.MatchString(s.ReleaseVersion) || !kernelStatusPassword.MatchString(o.Password) || o.Timeout <= 0 || o.Timeout > 5*time.Second {
		return "", kernelStatusError("invalid")
	}
	return u.Host, nil
}

// ObserveKernel reads one full protected snapshot using the ordinary plugin
// account. It publishes nothing and does not request internal or management
// data. A late subscriber has no prior revision from which to infer a gap.
// Kernel information alone does not prove work or federation readiness.
func ObserveKernel(parent context.Context, o KernelStatusOptions) (protocol.Snapshot, error) {
	var empty protocol.Snapshot
	if parent == nil {
		return empty, kernelStatusError("invalid")
	}
	address, err := kernelStatusEndpoint(o)
	if err != nil {
		return empty, err
	}
	if parent.Err() != nil {
		return empty, kernelStatusError("cancelled")
	}
	ctx, cancel := context.WithTimeout(parent, o.Timeout)
	defer cancel()
	dialer := &kernelStatusDialer{ctx: ctx, address: address}
	defer dialer.close()
	faults := make(chan struct{}, 1)
	failure := func(err error) error {
		if errors.Is(err, nats.ErrAuthorization) || errors.Is(err, nats.ErrPermissionViolation) || errors.Is(err, nats.ErrAuthExpired) || errors.Is(err, nats.ErrAuthRevoked) {
			return kernelStatusError("invalid")
		}
		select {
		case <-faults:
			return kernelStatusError("invalid")
		default:
		}
		if parent.Err() != nil {
			return kernelStatusError("cancelled")
		}
		return kernelStatusError("unavailable")
	}
	nc, err := nats.Connect(o.Endpoint, nats.UserInfo(communication.OrdinaryPlugin, o.Password), nats.NoReconnect(), nats.IgnoreDiscoveredServers(), nats.NoEcho(), nats.Timeout(o.Timeout), nats.SetCustomDialer(dialer), nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, _ error) {
		select {
		case faults <- struct{}{}:
		default:
		}
	}))
	if err != nil {
		return empty, failure(err)
	}
	defer nc.Close()
	wire, _ := communication.Subjects(o.Scope.HubID)
	messages := make(chan *nats.Msg, 8)
	sub, err := nc.ChanSubscribe(wire.Snapshot, messages)
	if err != nil {
		return empty, failure(err)
	}
	defer sub.Unsubscribe()
	if err = nc.FlushWithContext(ctx); err != nil {
		return empty, failure(err)
	}
	select {
	case <-faults:
		return empty, kernelStatusError("invalid")
	default:
	}
	select {
	case <-ctx.Done():
		return empty, failure(ctx.Err())
	case <-faults:
		return empty, kernelStatusError("invalid")
	case message := <-messages:
		if message == nil || message.Subject != wire.Snapshot || message.Reply != "" || len(message.Data) > protocol.MaxPayload {
			return empty, kernelStatusError("invalid")
		}
		snapshot, err := protocol.DecodeSnapshot(message.Data, o.Scope, time.Now(), 3*time.Second)
		if err != nil {
			return empty, kernelStatusError("invalid")
		}
		if parent.Err() != nil {
			return empty, kernelStatusError("cancelled")
		}
		if ctx.Err() != nil {
			return empty, kernelStatusError("unavailable")
		}
		select {
		case <-faults:
			return empty, kernelStatusError("invalid")
		default:
		}
		return snapshot, nil
	}
}
