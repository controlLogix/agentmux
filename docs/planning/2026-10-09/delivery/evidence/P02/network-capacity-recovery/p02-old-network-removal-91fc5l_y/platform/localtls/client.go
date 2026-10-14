// Package localtls authenticates the explicitly enrolled local NATS server.
// It contains public trust material only, never client or server private keys.
package localtls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidPolicy         = errors.New("local_tls_policy_invalid")
	ErrServerAuthentication  = errors.New("local_tls_server_authentication_failed")
	ErrConnectionUnavailable = errors.New("local_tls_connection_unavailable")
	ErrDeadline              = errors.New("local_tls_deadline")
	ErrCleanup               = errors.New("local_tls_cleanup_failed")
)

const MaxRootsPEM = 16 * 1024

type Policy struct {
	Endpoint              string
	ServerName            string
	RootsPEM              []byte
	LeafCertificateSHA256 string
}

type ClientTrust struct {
	policy  Policy
	address string
	roots   *x509.CertPool
	leaf    [sha256.Size]byte
}

var leafDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func IsAuthorityError(err error) bool {
	return errors.Is(err, ErrInvalidPolicy) || errors.Is(err, ErrServerAuthentication)
}

// NewClientTrust accepts only the selected loopback endpoint, an explicit DNS
// identity, one enrolled CA and the exact server leaf certificate digest.
func NewClientTrust(p Policy) (*ClientTrust, error) {
	u, err := url.Parse(p.Endpoint)
	if err != nil || u.Scheme != "tls" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(p.Endpoint, "?#\x00\r\n ,\t") {
		return nil, ErrInvalidPolicy
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || host != "127.0.0.1" || port == "" || !leafDigest.MatchString(p.LeafCertificateSHA256) || len(p.ServerName) == 0 || len(p.ServerName) > 253 || net.ParseIP(p.ServerName) != nil || strings.ToLower(p.ServerName) != p.ServerName {
		return nil, ErrInvalidPolicy
	}
	number, portErr := strconv.Atoi(port)
	if portErr != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
		return nil, ErrInvalidPolicy
	}
	for _, label := range strings.Split(p.ServerName, ".") {
		if !dnsLabel.MatchString(label) {
			return nil, ErrInvalidPolicy
		}
	}
	if len(p.RootsPEM) > MaxRootsPEM {
		return nil, ErrInvalidPolicy
	}
	data := bytes.TrimSpace(p.RootsPEM)
	if len(data) == 0 || len(data) > MaxRootsPEM || !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) || bytes.Count(data, []byte("-----BEGIN CERTIFICATE-----")) != 1 || bytes.Count(data, []byte("-----END CERTIFICATE-----")) != 1 {
		return nil, ErrInvalidPolicy
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || !bytes.Equal(data, bytes.TrimSpace(pem.EncodeToMemory(block))) {
		return nil, ErrInvalidPolicy
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	now := time.Now()
	if err != nil || !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) || ca.CheckSignatureFrom(ca) != nil {
		return nil, ErrInvalidPolicy
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	trust := &ClientTrust{policy: p, address: u.Host, roots: roots}
	trust.policy.RootsPEM = append([]byte(nil), p.RootsPEM...)
	decoded, _ := hex.DecodeString(strings.TrimPrefix(p.LeafCertificateSHA256, "sha256:"))
	copy(trust.leaf[:], decoded)
	return trust, nil
}

func (t *ClientTrust) Policy() Policy {
	if t == nil {
		return Policy{}
	}
	p := t.policy
	p.RootsPEM = append([]byte(nil), p.RootsPEM...)
	return p
}

// Dialer owns the exact sockets opened through this trust policy. The caller
// supplies only its lifetime and a bounded timeout; TLS settings are fixed.
type Dialer struct {
	trust          *ClientTrust
	ctx            context.Context
	cancel         context.CancelFunc
	timeout        time.Duration
	mu             sync.Mutex
	closed         bool
	closeMu        sync.Mutex
	closeAttempted bool
	connections    map[*ownedConnection]struct{}
	calls          sync.WaitGroup
	stopped        chan struct{}
}

func (t *ClientTrust) NewDialer(parent context.Context, timeout time.Duration) (*Dialer, error) {
	if t == nil || t.roots == nil || t.address == "" || parent == nil || timeout <= 0 || timeout > 5*time.Second {
		return nil, ErrInvalidPolicy
	}
	if parent.Err() != nil {
		return nil, ErrDeadline
	}
	ctx, cancel := context.WithCancel(parent)
	d := &Dialer{trust: t, ctx: ctx, cancel: cancel, timeout: timeout, connections: map[*ownedConnection]struct{}{}, stopped: make(chan struct{})}
	context.AfterFunc(ctx, func() {
		d.mu.Lock()
		d.closed = true
		connections := make([]*ownedConnection, 0, len(d.connections))
		for conn := range d.connections {
			connections = append(connections, conn)
		}
		d.mu.Unlock()
		for _, conn := range connections {
			conn.Close()
		}
		close(d.stopped)
	})
	return d, nil
}

type ownedConnection struct {
	net.Conn
	owner  *Dialer
	mu     sync.Mutex
	closed bool
}

func (c *ownedConnection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	err := c.Conn.Close()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	c.closed = true
	c.owner.mu.Lock()
	delete(c.owner.connections, c)
	c.owner.mu.Unlock()
	return nil
}

// SkipTLSHandshake tells the pinned NATS client not to wrap the already
// authenticated TLS socket a second time. Use its TLSHandshakeFirst option.
func (*Dialer) SkipTLSHandshake() bool { return true }

func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	if d == nil || d.trust == nil || d.ctx == nil || network != "tcp" || address != d.trust.address {
		return nil, ErrInvalidPolicy
	}
	d.mu.Lock()
	if d.closed || d.ctx.Err() != nil {
		d.mu.Unlock()
		return nil, ErrDeadline
	}
	d.calls.Add(1)
	d.mu.Unlock()
	defer d.calls.Done()
	ctx, cancel := context.WithTimeout(d.ctx, d.timeout)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		if ctx.Err() != nil || d.ctx.Err() != nil {
			return nil, ErrDeadline
		}
		return nil, ErrConnectionUnavailable
	}
	owned := &ownedConnection{Conn: raw, owner: d}
	d.mu.Lock()
	if d.closed || ctx.Err() != nil {
		d.connections[owned] = struct{}{}
		d.mu.Unlock()
		owned.Close()
		return nil, ErrDeadline
	}
	d.connections[owned] = struct{}{}
	d.mu.Unlock()
	config := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: d.trust.roots, ServerName: d.trust.policy.ServerName,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 || sha256.Sum256(state.PeerCertificates[0].Raw) != d.trust.leaf {
				return ErrServerAuthentication
			}
			return nil
		}}
	conn := tls.Client(owned, config)
	if err = conn.HandshakeContext(ctx); err != nil {
		conn.Close()
		if ctx.Err() != nil || d.ctx.Err() != nil {
			return nil, ErrDeadline
		}
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			return nil, ErrDeadline
		}
		return nil, ErrServerAuthentication
	}
	// Handshake cancellation ends here. Successful sockets remain owned by the
	// parent lifetime, so its per-handshake timer cannot close a live actor.
	if d.ctx.Err() != nil {
		conn.Close()
		return nil, ErrDeadline
	}
	return conn, nil
}

func (d *Dialer) Close() error {
	if d == nil {
		return nil
	}
	if d.cancel == nil || d.stopped == nil {
		return ErrInvalidPolicy
	}
	d.closeMu.Lock()
	defer d.closeMu.Unlock()
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()
	d.cancel()
	<-d.stopped
	d.calls.Wait()
	d.mu.Lock()
	remaining := make([]*ownedConnection, 0, len(d.connections))
	for conn := range d.connections {
		remaining = append(remaining, conn)
	}
	retry := d.closeAttempted
	d.closeAttempted = true
	d.mu.Unlock()
	if retry {
		for _, conn := range remaining {
			conn.Close()
		}
	}
	d.mu.Lock()
	failed := len(d.connections) != 0
	d.mu.Unlock()
	if failed {
		return ErrCleanup
	}
	return nil
}
