package deployment

import (
	"context"
	"github.com/controlLogix/agentmux/platform/localtls"
	"net/url"

	"github.com/nats-io/nats.go"
)

// Secure transport returns only a fixed-endpoint authenticated socket. NATS
// cannot discover another server or send CONNECT before the TLS dialer admits
// the normal certificate chain, DNS identity and enrolled leaf pin.
// Nil trust preserves the explicit historical helpers; installed admission
// must reject that boundary before credentials are supplied to these helpers.
func localProbeTransport(ctx context.Context, o ProbeOptions) ([]nats.Option, *localtls.Dialer, *observeDialer, error) {
	if o.TLS != nil {
		if o.TLS.Policy().Endpoint != o.Endpoint {
			return nil, nil, nil, probeError("tls_endpoint_mismatch")
		}
		dialer, err := o.TLS.NewDialer(ctx, o.Timeout)
		if err != nil {
			return nil, nil, nil, err
		}
		return []nats.Option{nats.SetCustomDialer(dialer), nats.TLSHandshakeFirst(), nats.IgnoreDiscoveredServers()}, dialer, nil, nil
	}
	endpoint, err := url.Parse(o.Endpoint)
	if err != nil {
		return nil, nil, nil, probeError("endpoint_invalid")
	}
	dialer := &observeDialer{ctx: ctx, address: endpoint.Host}
	return []nats.Option{nats.SetCustomDialer(dialer)}, nil, dialer, nil
}
