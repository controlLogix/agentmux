package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/controlLogix/agentmux/platform/localtls"
	"github.com/nats-io/nats.go"
)

// Values come from the host's enrolled profile. This connector does not infer
// enrollment from a file path, a TLS connection or a signed application frame.
type NativeAuthorityNATSOptions struct {
	ServerURL, Subject, CredentialsFile string
	AccountPublicKey, ReplyPrefix       string
	PublishSubjects                     []string
	Trust                               *localtls.ClientTrust
	// Lifetime is host-owned; admission cancellation only bounds connection setup.
	// Nil preserves the existing caller-context lifetime.
	Lifetime context.Context
}

func (NativeAuthorityNATSOptions) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private native authority transport]")
}
func (NativeAuthorityNATSOptions) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-native-authority-transport"}`), nil
}

type NativeAuthorityNATSExchange struct {
	conn         *nats.Conn
	dialer       *localtls.Dialer
	replyPrefix  string
	subject      string
	done, joined chan struct{}
	mu           sync.Mutex
	closing      bool
	active       int
	joinOnce     sync.Once
	doneOnce     sync.Once
	failed       atomic.Bool
}

func (NativeAuthorityNATSExchange) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private native authority connection]")
}
func (NativeAuthorityNATSExchange) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-native-authority-connection"}`), nil
}

var nativeAuthorityReplyPrefix = regexp.MustCompile(`^_INBOX\.[A-Za-z0-9_-]{16,64}$`)
var nativeAuthorityInbox = regexp.MustCompile(`^_INBOX\.[A-Za-z0-9_-]{16,128}(?:\.[A-Za-z0-9_-]{1,128})?$`)

func NewNativeAuthorityNATSExchange(ctx context.Context, options NativeAuthorityNATSOptions) (*NativeAuthorityNATSExchange, error) {
	return newNativeAuthorityNATSExchange(ctx, options, readLifecycleCredentialPolicy)
}

func newNativeAuthorityNATSExchange(ctx context.Context, options NativeAuthorityNATSOptions, readCredential func(string, string, []string, []string, bool) (lifecycleCredential, error)) (*NativeAuthorityNATSExchange, error) {
	if ctx == nil || ctx.Err() != nil || options.Trust == nil || options.ServerURL != options.Trust.Policy().Endpoint || !lifecycleSubject(options.Subject) || !nativeAuthorityReplyPrefix.MatchString(options.ReplyPrefix) || len(options.PublishSubjects) == 0 || len(options.PublishSubjects) > 16 {
		return nil, pluginError("context_authority_configuration_invalid")
	}
	permitted := false
	for _, subject := range options.PublishSubjects {
		if subject == options.Subject {
			permitted = true
		}
		if !lifecycleSubject(subject) {
			return nil, pluginError("context_authority_configuration_invalid")
		}
	}
	if !permitted {
		return nil, pluginError("context_authority_configuration_invalid")
	}
	credential, err := readCredential(options.CredentialsFile, options.AccountPublicKey, options.PublishSubjects, []string{options.ReplyPrefix + ".>"}, true)
	if err != nil {
		return nil, managerFailure(err, "context_authority_configuration_invalid")
	}
	transport := &NativeAuthorityNATSExchange{subject: options.Subject, replyPrefix: options.ReplyPrefix, done: make(chan struct{}), joined: make(chan struct{})}
	budget := 2 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		budget = min(budget, time.Until(deadline))
	}
	if budget <= 0 {
		return nil, pluginError("context_authority_unavailable")
	}
	lifetime := options.Lifetime
	if lifetime == nil {
		lifetime = ctx
	}
	dialer, err := options.Trust.NewDialer(lifetime, budget)
	if err != nil {
		return nil, pluginError("context_authority_unavailable")
	}
	transport.dialer = dialer
	connectCtx, cancel := context.WithTimeout(ctx, budget)
	stopped := make(chan struct{})
	stop := context.AfterFunc(connectCtx, func() { _ = dialer.Close(); close(stopped) })
	transport.conn, err = nats.Connect(options.ServerURL, nats.UserJWTAndSeed(credential.jwt, credential.seed), nats.TLSHandshakeFirst(), nats.SetCustomDialer(dialer), nats.NoReconnect(), nats.IgnoreDiscoveredServers(), nats.NoEcho(), nats.Timeout(budget), nats.FlusherTimeout(100*time.Millisecond),
		nats.ClosedHandler(func(*nats.Conn) { transport.doneOnce.Do(func() { close(transport.done) }) }), nats.ErrorHandler(func(*nats.Conn, *nats.Subscription, error) { transport.failed.Store(true) }))
	if !stop() {
		<-stopped
	}
	failed := err != nil || connectCtx.Err() != nil
	cancel()
	if failed {
		if transport.conn == nil {
			transport.doneOnce.Do(func() { close(transport.done) })
		} else {
			transport.conn.Close()
		}
		return transport, pluginError("context_authority_unavailable")
	}

	if ctx.Err() != nil {
		// Return the original owner even on failure so callers can join callbacks.
		transport.conn.Close()
		return transport, pluginError("context_authority_unavailable")
	}
	return transport, nil
}
func (t *NativeAuthorityNATSExchange) Exchange(ctx context.Context, reply string, raw []byte) (result []byte, err error) {
	return t.exchange(ctx, reply, raw, false)
}

// ExchangeCapability uses a separately bounded transport frame. It does not
// increase the original envelope, response, or retained owner-record limits.
func (t *NativeAuthorityNATSExchange) ExchangeCapability(ctx context.Context, reply string, raw []byte) ([]byte, error) {
	return t.exchange(ctx, reply, raw, true)
}

func (t *NativeAuthorityNATSExchange) exchange(ctx context.Context, reply string, raw []byte, capability bool) (result []byte, err error) {
	fail := pluginError("context_authority_unavailable")
	limit, expiryField := nativeAuthorityLimit, "expiresAt"
	var wireErr error
	if capability {
		limit, expiryField = nativeCapabilityRequestLimit, "validUntil"
		wireErr = nativeCapabilitySchema("capability-service-request", raw)
	} else {
		wireErr = nativeAuthoritySchema("request", raw)
	}
	if ctx == nil || ctx.Err() != nil || !nativeAuthorityInbox.MatchString(reply) || !strings.HasPrefix(reply, t.replyPrefix+".") || len(reply) > 264 || len(raw) > limit || wireErr != nil {
		return nil, fail
	}
	var signedReply string
	if json.Unmarshal(fieldsForClaim(fieldsForClaim(raw, "claims"), "replySubject"), &signedReply) != nil || signedReply != reply {
		return nil, fail
	}
	var expires string
	if json.Unmarshal(fieldsForClaim(fieldsForClaim(raw, "claims"), expiryField), &expires) != nil {
		return nil, fail
	}
	deadline, parseErr := nativeAuthorityTime(expires)
	if parseErr != nil || !time.Now().Before(deadline) {
		return nil, fail
	}
	work, cancel := context.WithDeadline(ctx, minTime(deadline, time.Now().Add(contextCallBudget)))
	defer cancel()
	ctx = work
	return t.exchangeBound(ctx, reply, raw)
}

// ExchangeConfiguration uses the ordinary configuration read/watch envelope.
// It does not admit capability wrappers or grant authority from a subject name.
func (t *NativeAuthorityNATSExchange) ExchangeConfiguration(ctx context.Context, reply string, raw []byte) ([]byte, error) {
	fail := pluginError("context_configuration_unavailable")
	if ctx == nil || ctx.Err() != nil || !nativeAuthorityInbox.MatchString(reply) || !strings.HasPrefix(reply, t.replyPrefix+".") || len(reply) > 264 || len(raw) > nativeAuthorityLimit || nativeAuthoritySchema("envelope", raw) != nil {
		return nil, fail
	}
	var request struct {
		ContractID string `json:"contractId"`
		Operation  struct {
			Deadline string `json:"deadline"`
		} `json:"operation"`
		IngressAttestation struct {
			Claims struct {
				ExpiresAt string `json:"expiresAt"`
			} `json:"claims"`
		} `json:"ingressAttestation"`
	}
	if json.Unmarshal(raw, &request) != nil || (request.ContractID != "configuration-read" && request.ContractID != "configuration-watch" && request.ContractID != "configuration-set") {
		return nil, fail
	}
	deadline, e1 := nativeAuthorityTime(request.Operation.Deadline)
	expires, e2 := nativeAuthorityTime(request.IngressAttestation.Claims.ExpiresAt)
	if e1 != nil || e2 != nil {
		return nil, fail
	}
	deadline = minTime(deadline, expires)
	if !time.Now().Before(deadline) {
		return nil, fail
	}
	work, cancel := context.WithDeadline(ctx, minTime(deadline, time.Now().Add(contextCallBudget)))
	defer cancel()
	result, err := t.exchangeBound(work, reply, raw)
	if err != nil && work.Err() != nil && t.ConfigurationReusable() {
		return nil, &nativeConfigurationFailure{cause: work.Err(), owner: t}
	}
	return result, err
}

// ConfigurationReusable is false after a failed original subscription cleanup
// or transport loss. Such a request cannot be rearmed through another lookup.
func (t *NativeAuthorityNATSExchange) ConfigurationReusable() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.closing && !t.failed.Load() && t.conn != nil && t.conn.IsConnected()
}

func (t *NativeAuthorityNATSExchange) ExchangeConfigurationWatchClose(ctx context.Context, reply string, raw []byte) ([]byte, error) {
	fail := pluginError("context_cleanup_incomplete")
	if ctx == nil || ctx.Err() != nil || !nativeAuthorityInbox.MatchString(reply) || !strings.HasPrefix(reply, t.replyPrefix+".") || len(raw) > nativeAuthorityLimit || nativeAuthoritySchema("configuration-watch-close", raw) != nil {
		return nil, fail
	}
	var claims nativeConfigurationWatchCloseClaims
	if json.Unmarshal(fieldsForClaim(raw, "claims"), &claims) != nil || claims.ReplySubject != reply {
		return nil, fail
	}
	deadline, err := nativeAuthorityTime(claims.ExpiresAt)
	issued, issuedErr := nativeAuthorityTime(claims.IssuedAt)
	if err != nil || issuedErr != nil || issued.After(time.Now()) || !time.Now().Before(deadline) || deadline.Sub(issued) > contextCallBudget {
		return nil, fail
	}
	work, cancel := context.WithDeadline(ctx, minTime(deadline, time.Now().Add(contextCallBudget)))
	defer cancel()
	return t.exchangeBound(work, reply, raw)
}

// ExchangeSubscription carries only the closed, host-signed lease control
// schema over the original selected configuration subject and private inbox.
func (t *NativeAuthorityNATSExchange) ExchangeSubscription(ctx context.Context, reply string, raw []byte) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || !nativeAuthorityInbox.MatchString(reply) || !strings.HasPrefix(reply, t.replyPrefix+".") || len(raw) > nativeAuthorityLimit || nativeAuthoritySchema("configuration-subscription-control", raw) != nil {
		return nil, pluginError("context_subscription_unavailable")
	}
	var claims nativeSubscriptionControl
	if json.Unmarshal(fieldsForClaim(raw, "claims"), &claims) != nil || claims.ReplySubject != reply {
		return nil, pluginError("context_subscription_unavailable")
	}
	deadline, err := nativeAuthorityTime(claims.ExpiresAt)
	if err != nil || !time.Now().Before(deadline) {
		return nil, pluginError("context_subscription_unavailable")
	}
	work, cancel := context.WithDeadline(ctx, minTime(deadline, time.Now().Add(contextCallBudget)))
	defer cancel()
	return t.exchangeBound(work, reply, raw)
}

func (t *NativeAuthorityNATSExchange) exchangeBound(ctx context.Context, reply string, raw []byte) (result []byte, err error) {
	fail := pluginError("context_authority_unavailable")

	t.mu.Lock()
	if t.closing || t.active >= contextServiceLimit || t.failed.Load() || t.conn == nil || !t.conn.IsConnected() {
		t.mu.Unlock()
		return nil, fail
	}
	t.active++
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		t.active--
		if t.closing && t.active == 0 {
			t.joinOnce.Do(func() { close(t.joined) })
		}
		t.mu.Unlock()
	}()
	sub, e := t.conn.SubscribeSync(reply)
	if e != nil {
		return nil, fail
	}
	defer func() {
		if sub.Unsubscribe() != nil {
			t.failed.Store(true)
			result = nil
			err = fail
		}
	}()
	if sub.SetPendingLimits(1, nativeAuthorityLimit) != nil || t.conn.FlushWithContext(ctx) != nil || t.conn.PublishRequest(t.subject, reply, raw) != nil {
		return nil, fail
	}
	message, e := sub.NextMsgWithContext(ctx)
	if e != nil || ctx.Err() != nil || t.failed.Load() || message.Subject != reply || len(message.Header) != 0 || len(message.Data) > nativeAuthorityLimit {
		return nil, fail
	}
	return bytes.Clone(message.Data), nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func (t *NativeAuthorityNATSExchange) Close(ctx context.Context) error {
	if ctx == nil {
		return pluginError("context_cleanup_incomplete")
	}
	t.mu.Lock()
	t.closing = true
	if t.active == 0 {
		t.joinOnce.Do(func() { close(t.joined) })
	}
	t.mu.Unlock()
	if t.conn != nil {
		t.conn.Close()
	}
	if t.dialer != nil && t.dialer.Close() != nil {
		return pluginError("context_cleanup_incomplete")
	}
	for _, done := range []<-chan struct{}{t.done, t.joined} {
		select {
		case <-done:
		case <-ctx.Done():
			return pluginError("context_cleanup_incomplete")
		}
	}
	return nil
}
