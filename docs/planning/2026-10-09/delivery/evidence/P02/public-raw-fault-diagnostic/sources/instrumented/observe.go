package deployment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
)

type ObserveOptions struct {
	ProbeOptions
	ReadExistingRecord bool
}

type PersistenceEvidence string

const (
	PersistenceUnknown    PersistenceEvidence = "unknown"
	PersistenceConfigSeen PersistenceEvidence = "configuration-observed"
	PersistenceRecordSeen PersistenceEvidence = "existing-record-observed"
)

// Observation exposes only validated, bounded infrastructure observations.
// Neither configuration nor an existing record proves current write permission,
// restart durability, protected-role readiness or application readiness.
type Observation struct {
	ServerName          string              `json:"serverName"`
	ServerVersion       string              `json:"serverVersion"`
	Domain              string              `json:"domain"`
	Stream              string              `json:"stream"`
	BrokerVerified      bool                `json:"brokerVerified"`
	PersistenceEvidence PersistenceEvidence `json:"persistenceEvidence"`
	Code                string              `json:"code"`
	RecordSequence      uint64              `json:"recordSequence,omitempty"`
	RecordObservedAt    string              `json:"recordObservedAt,omitempty"`
	RecordDigest        string              `json:"recordDigest,omitempty"`
	ElapsedMS           int64               `json:"elapsedMs"`
	Scope               string              `json:"scope"`
}

func observeError(code string) error { return errors.New("observe_" + code) }

type observeSocket struct {
	connection *observeOwnedConnection
	stop       func() bool
	done       chan struct{}
}

// The custom dialer owns every socket returned by DialContext. Cancellation
// closes those same sockets during greeting/TLS setup; cleanup stops or joins
// each cancellation hook. It never discovers or closes another connection.
type observeDialer struct {
	ctx                           context.Context
	address                       string
	mu                            sync.Mutex
	sockets                       map[*observeOwnedConnection]observeSocket
	closed                        bool
	active                        int
	idle                          chan struct{}
	closeGate                     chan struct{}
	failureSerial, reportedSerial uint64
}

// Every wrapper is minted only after this dialer opens its own TCP socket.
// Failed actual closes retain both the socket and a reportable failure even
// when a later SDK or cancellation close succeeds.
type observeOwnedConnection struct {
	net.Conn
	owner  *observeDialer
	mu     sync.Mutex
	closed bool
}

func (c *observeOwnedConnection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	err := c.Conn.Close()
	c.owner.mu.Lock()
	defer c.owner.mu.Unlock()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		c.owner.failureSerial++
		return err
	}
	c.closed = true
	return nil
}

func (d *observeDialer) Dial(network, address string) (net.Conn, error) {
	if d == nil || d.ctx == nil || network != "tcp" || address != d.address {
		return nil, observeError("endpoint_selection_mismatch")
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, observeError("connection_owner_closed")
	}
	if d.active == 0 {
		d.idle = make(chan struct{})
	}
	d.active++
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.active--
		if d.active == 0 {
			close(d.idle)
		}
		d.mu.Unlock()
	}()
	connection, err := (&net.Dialer{}).DialContext(d.ctx, network, address)
	if err != nil {
		return nil, err
	}
	owned := &observeOwnedConnection{Conn: connection, owner: d}
	rawPublicArmSocket(owned)
	d.mu.Lock()
	if d.sockets == nil {
		d.sockets = make(map[*observeOwnedConnection]observeSocket)
	}
	done := make(chan struct{})
	stop := context.AfterFunc(d.ctx, func() { defer close(done); owned.Close() })
	d.sockets[owned] = observeSocket{owned, stop, done}
	closed := d.closed
	d.mu.Unlock()
	if closed {
		if stop() {
			owned.Close()
			close(done)
		} else {
			<-done
		}
		return nil, observeError("connection_owner_closed")
	}
	return owned, nil
}

func (d *observeDialer) close() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return d.closeContext(ctx)
}

func (d *observeDialer) closeContext(ctx context.Context) error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	d.closed = true
	if d.closeGate == nil {
		d.closeGate = make(chan struct{}, 1)
		d.closeGate <- struct{}{}
	}
	gate := d.closeGate
	d.mu.Unlock()
	if ctx == nil || ctx.Done() == nil {
		return ErrRawTransportCleanup
	}
	if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil {
		return ErrRawTransportCleanup
	}
	select {
	case <-gate:
	case <-ctx.Done():
		return ErrRawTransportCleanup
	}
	defer func() { gate <- struct{}{} }()
	d.mu.Lock()
	idle := d.idle
	active := d.active
	d.mu.Unlock()
	if active != 0 {
		select {
		case <-idle:
		case <-ctx.Done():
			return ErrRawTransportCleanup
		}
	}
	d.mu.Lock()
	sockets := make([]observeSocket, 0, len(d.sockets))
	for _, socket := range d.sockets {
		sockets = append(sockets, socket)
	}
	d.mu.Unlock()
	for _, socket := range sockets {
		if ctx.Err() != nil {
			return ErrRawTransportCleanup
		}
		var closeErr error
		if socket.stop() {
			closeErr = socket.connection.Close()
			close(socket.done)
		} else {
			select {
			case <-socket.done:
			case <-ctx.Done():
				return ErrRawTransportCleanup
			}
			closeErr = socket.connection.Close()
		}
		if closeErr == nil {
			d.mu.Lock()
			delete(d.sockets, socket.connection)
			d.mu.Unlock()
		}
	}
	d.mu.Lock()
	failed := len(d.sockets) != 0 || d.failureSerial != d.reportedSerial
	d.reportedSerial = d.failureSerial
	d.mu.Unlock()
	if failed {
		return ErrRawTransportCleanup
	}
	return nil
}

func observeFailure(ctx context.Context, err error, denied bool, fallback string) error {
	if denied || errors.Is(err, nats.ErrPermissionViolation) || errors.Is(err, nats.ErrAuthorization) {
		return observeError("permission_or_authentication_denied")
	}
	if ctx.Err() != nil {
		return observeError("deadline_or_cancellation")
	}
	return observeError(fallback)
}

// Observe authenticates and issues only account INFO, fixed stream INFO, and
// optional existing MSG.GET requests. These are read-only API requests, not a
// health publication or stream lifecycle operation. It never creates, updates,
// deletes, publishes a health record, provisions, or calls the writing Probe.
func Observe(parent context.Context, o ObserveOptions) (result Observation, err error) {
	started := time.Now()
	defer func() { result.ElapsedMS = time.Since(started).Milliseconds() }()
	result.Scope = "Read-only infrastructure observation; not write, recovery or application readiness proof."
	result.PersistenceEvidence = PersistenceUnknown
	result.Code = "not_observed"
	if validateProbe(o.ProbeOptions) != nil || parent == nil {
		return result, observeError("options_invalid")
	}
	ctx, cancel := context.WithTimeout(parent, o.Timeout)
	defer cancel()
	defer func() {
		if ctx.Err() != nil && err == nil {
			result.PersistenceEvidence = PersistenceUnknown
			result.Code = "observation_incomplete"
			result.RecordSequence, result.RecordObservedAt, result.RecordDigest = 0, "", ""
			err = observeError("deadline_or_cancellation")
		}
	}()
	if ctx.Err() != nil {
		return result, observeError("deadline_or_cancellation")
	}
	deadline, _ := ctx.Deadline()
	transport, ownedTLS, historicalPlain, transportErr := localProbeTransport(ctx, o.ProbeOptions)
	if transportErr != nil {
		return result, observeError("tls_transport_invalid")
	}
	var nc *nats.Conn
	defer func() {
		var failed bool
		rawPublicCapture(historicalPlain, result, err)
		err, failed = closeProbeTransport(ownedTLS, historicalPlain, err, "observe_connection_cleanup_failed")
		if failed {
			result = Observation{PersistenceEvidence: PersistenceUnknown, Code: "observation_incomplete", Scope: "Read-only infrastructure observation; not write, recovery or application readiness proof."}
		}
		if nc != nil {
			nc.Close()
		}
	}()
	var permissionDenied atomic.Bool
	options := append(transport, nats.UserInfo(HealthUser, o.Password),
		nats.Timeout(time.Until(deadline)), nats.NoReconnect(), nats.NoEcho(),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			if errors.Is(err, nats.ErrPermissionViolation) {
				permissionDenied.Store(true)
			}
		}))
	connected, connectErr := nats.Connect(o.Endpoint, options...)
	nc = connected
	if connectErr != nil {
		return result, observeFailure(ctx, connectErr, permissionDenied.Load(), "connection_unavailable")
	}
	if nc.ConnectedServerName() != o.ServerName || nc.ConnectedServerVersion() != o.ServerVersion {
		return result, observeError("broker_identity_mismatch")
	}
	js, jsErr := nc.JetStream(nats.Domain(o.Domain))
	if jsErr != nil {
		return result, observeError("jetstream_context_unavailable")
	}
	account, accountErr := js.AccountInfo(nats.Context(ctx))
	if accountErr != nil {
		return result, observeFailure(ctx, accountErr, permissionDenied.Load(), "account_or_domain_unavailable")
	}
	if account.Domain != o.Domain {
		return result, observeError("domain_mismatch")
	}
	// Publish no identity observations until both broker identity and the actual
	// account domain have been checked against the explicit selection.
	result.ServerName, result.ServerVersion, result.Domain = nc.ConnectedServerName(), nc.ConnectedServerVersion(), account.Domain
	result.Stream = HealthStream(o.HubID)
	result.BrokerVerified = true
	info, infoErr := js.StreamInfo(result.Stream, nats.Context(ctx))
	if errors.Is(infoErr, nats.ErrStreamNotFound) {
		result.Code = "health_stream_absent"
		return result, nil
	}
	if infoErr != nil {
		return result, observeFailure(ctx, infoErr, permissionDenied.Load(), "stream_observation_unavailable")
	}
	if !compatibleHealth(info.Config, o.HubID) {
		return result, observeError("stream_incompatible")
	}
	result.PersistenceEvidence = PersistenceConfigSeen
	result.Code = "health_configuration_observed"
	if !o.ReadExistingRecord {
		return result, nil
	}
	if info.State.Msgs == 0 || info.State.LastSeq == 0 {
		result.PersistenceEvidence = PersistenceUnknown
		result.Code = "health_record_absent"
		return result, nil
	}
	record, readErr := js.GetMsg(result.Stream, info.State.LastSeq, nats.Context(ctx))
	if errors.Is(readErr, nats.ErrMsgNotFound) {
		// Expiry or concurrent deletion is absence, never a reason to write a replacement.
		result.PersistenceEvidence = PersistenceUnknown
		result.Code = "health_record_absent"
		return result, nil
	}
	if readErr != nil {
		result.PersistenceEvidence = PersistenceUnknown
		return result, observeFailure(ctx, readErr, permissionDenied.Load(), "record_observation_unavailable")
	}
	const prefix = "agentmux-health-v1:"
	data := string(record.Data)
	if record.Subject != HealthSubject(o.HubID) || record.Sequence != info.State.LastSeq || record.Time.IsZero() ||
		len(data) != len(prefix)+64 || !strings.HasPrefix(data, prefix) {
		result.PersistenceEvidence = PersistenceUnknown
		return result, observeError("record_invalid")
	}
	nonce := data[len(prefix):]
	decoded, decodeErr := hex.DecodeString(nonce)
	if decodeErr != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != nonce || record.Header.Get(nats.MsgIdHdr) != nonce {
		result.PersistenceEvidence = PersistenceUnknown
		return result, observeError("record_invalid")
	}
	if ctx.Err() != nil {
		result.PersistenceEvidence = PersistenceUnknown
		return result, observeError("deadline_or_cancellation")
	}
	checksum := sha256.Sum256(record.Data)
	result.PersistenceEvidence = PersistenceRecordSeen
	result.Code = "existing_health_record_observed"
	result.RecordSequence = record.Sequence
	result.RecordObservedAt = record.Time.UTC().Format(time.RFC3339Nano)
	result.RecordDigest = "sha256:" + hex.EncodeToString(checksum[:])
	return result, nil
}
