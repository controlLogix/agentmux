package deployment

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/controlLogix/agentmux/platform/localtls"
	"github.com/nats-io/nats.go"
)

type ProbeOptions struct {
	Endpoint, Password, HubID, ServerName, Domain, ServerVersion string
	Timeout                                                      time.Duration
	// TLS is mandatory for installed profiles. Nil belongs only to the explicit
	// historical helper boundary, not an authenticated installed connection.
	TLS *localtls.ClientTrust
}

// ProbeResult reports infrastructure observations, not protected application readiness.
// ServerName is the configured logical name; a raw NATS server ID is not a hub ID.
type ProbeResult struct {
	ServerName, ServerVersion, Domain, Stream string
	Sequence                                  uint64
	Created                                   bool
}

// HealthConfig has bounded storage and one exact subject, with no business data.
func HealthConfig(hubID string) nats.StreamConfig {
	return nats.StreamConfig{Name: HealthStream(hubID), Subjects: []string{HealthSubject(hubID)}, Storage: nats.FileStorage, Replicas: 1, Retention: nats.LimitsPolicy, Discard: nats.DiscardOld, MaxConsumers: 1, MaxMsgs: 128, MaxBytes: 64 * 1024, MaxMsgsPerSubject: -1, MaxMsgSize: 512, MaxAge: 24 * time.Hour, Duplicates: 2 * time.Minute}
}

func probeError(code string) error { return errors.New("health_" + code) }

var probeVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

func validateProbe(o ProbeOptions) error {
	if !identifier.MatchString(o.HubID) || !identifier.MatchString(o.ServerName) || !identifier.MatchString(o.Domain) || !secret.MatchString(o.Password) || !probeVersion.MatchString(o.ServerVersion) || o.Timeout <= 0 || o.Timeout > 5*time.Second {
		return probeError("options_invalid")
	}
	u, err := url.Parse(o.Endpoint)
	if err != nil || (u.Scheme != "nats" && u.Scheme != "tls") || u.User != nil || u.Path != "" || u.Opaque != "" || u.Host == "" || strings.ContainsAny(o.Endpoint, "?#\x00\r\n") {
		return probeError("endpoint_invalid")
	}
	host, port, err := net.SplitHostPort(u.Host)
	number, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || portErr != nil || number == 0 || (host != "127.0.0.1" && host != "::1") {
		return probeError("endpoint_invalid")
	}
	if o.TLS != nil && o.TLS.Policy().Endpoint != o.Endpoint {
		return probeError("tls_endpoint_mismatch")
	}
	return nil
}

// compatibleHealth compares all configuration fields, including optional features.
// Only server-assigned creation metadata is outside this configuration comparison.
func compatibleHealth(actual nats.StreamConfig, hubID string) bool {
	// NATS 2.15 adds these capability/version observations to otherwise unchanged
	// configuration. They do not authorize stream features or user metadata.
	if actual.Metadata != nil {
		if !reflect.DeepEqual(actual.Metadata, map[string]string{"_nats.level": "5", "_nats.req.level": "0", "_nats.ver": "2.15.0"}) {
			return false
		}
		actual.Metadata = nil
	}
	return reflect.DeepEqual(actual, HealthConfig(hubID))
}

// ProvisionAndProbe creates only an absent health stream. Existing incompatible
// streams are refused without update, delete, migration or broker restart.
func ProvisionAndProbe(ctx context.Context, o ProbeOptions) (ProbeResult, error) {
	return runProbe(ctx, o, true)
}

// Probe requires an existing compatible stream. It never provisions infrastructure.
func Probe(ctx context.Context, o ProbeOptions) (ProbeResult, error) { return runProbe(ctx, o, false) }

func runProbe(parent context.Context, o ProbeOptions, cold bool) (result ProbeResult, err error) {
	if err := validateProbe(o); err != nil {
		return ProbeResult{}, err
	}
	if parent == nil {
		return ProbeResult{}, probeError("context_invalid")
	}
	ctx, cancel := context.WithTimeout(parent, o.Timeout)
	defer cancel()
	if ctx.Err() != nil {
		return ProbeResult{}, probeError("deadline")
	}
	deadline, _ := ctx.Deadline()
	transport, ownedTLS, historicalPlain, transportErr := localProbeTransport(ctx, o)
	if transportErr != nil {
		return ProbeResult{}, probeError("tls_transport_invalid")
	}
	var nc *nats.Conn
	defer func() {
		var failed bool
		rawPublicCapture(historicalPlain, result, err)
		err, failed = closeProbeTransport(ownedTLS, historicalPlain, err, "health_connection_cleanup_failed")
		if failed {
			result = ProbeResult{}
		}
		if nc != nil {
			nc.Close()
		}
		if ctx.Err() != nil && err == nil {
			result = ProbeResult{}
			err = probeError("deadline")
		}
	}()
	options := append(transport, nats.UserInfo(HealthUser, o.Password), nats.Timeout(time.Until(deadline)), nats.NoReconnect(), nats.NoEcho(), nats.ErrorHandler(func(*nats.Conn, *nats.Subscription, error) {}))
	nc, err = nats.Connect(o.Endpoint, options...)
	if err != nil {
		if ctx.Err() != nil {
			return ProbeResult{}, probeError("deadline")
		}
		return ProbeResult{}, probeError("connect_failed")
	}
	result = ProbeResult{ServerName: nc.ConnectedServerName(), ServerVersion: nc.ConnectedServerVersion(), Domain: nc.ConnectedDomain(), Stream: HealthStream(o.HubID)}
	if result.ServerName != o.ServerName || result.ServerVersion != o.ServerVersion || result.Domain != o.Domain {
		return ProbeResult{}, probeError("broker_identity_mismatch")
	}
	js, err := nc.JetStream(nats.Domain(o.Domain))
	if err != nil {
		return ProbeResult{}, probeError("context_failed")
	}
	account, err := js.AccountInfo(nats.Context(ctx))
	if err != nil {
		return ProbeResult{}, probeError("domain_unavailable")
	}
	if account.Domain != o.Domain {
		return ProbeResult{}, probeError("broker_identity_mismatch")
	}
	result.Domain = account.Domain
	info, err := js.StreamInfo(result.Stream, nats.Context(ctx))
	if errors.Is(err, nats.ErrStreamNotFound) && cold {
		config := HealthConfig(o.HubID)
		info, err = js.AddStream(&config, nats.Context(ctx))
		result.Created = err == nil
		// Concurrent compatible creation can win; observe it without updating it.
		if err != nil && ctx.Err() == nil {
			info, err = js.StreamInfo(result.Stream, nats.Context(ctx))
		}
	}
	if err != nil {
		return ProbeResult{}, probeError("stream_unavailable")
	}
	if !compatibleHealth(info.Config, o.HubID) {
		return ProbeResult{}, probeError("stream_incompatible")
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ProbeResult{}, probeError("record_failed")
	}
	data := []byte("agentmux-health-v1:" + hex.EncodeToString(nonce[:]))
	message := nats.NewMsg(HealthSubject(o.HubID))
	message.Data = data
	message.Header.Set(nats.MsgIdHdr, hex.EncodeToString(nonce[:]))
	ack, err := js.PublishMsg(message, nats.Context(ctx))
	if err != nil || ack.Stream != result.Stream || ack.Domain != o.Domain || ack.Sequence == 0 {
		return ProbeResult{}, probeError("write_failed")
	}
	stored, err := js.GetMsg(result.Stream, ack.Sequence, nats.Context(ctx))
	if err != nil || stored.Subject != message.Subject || !bytes.Equal(stored.Data, data) {
		return ProbeResult{}, probeError("read_failed")
	}
	if ctx.Err() != nil {
		return ProbeResult{}, probeError("deadline")
	}
	result.Sequence = ack.Sequence
	return result, nil
}
