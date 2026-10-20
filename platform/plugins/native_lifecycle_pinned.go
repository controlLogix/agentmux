package plugins

import (
	"context"
	"time"

	"github.com/nats-io/nats.go"
)

func (p *nativeInstance) connectLifecycle(ctx context.Context, budget time.Duration, options []nats.Option) error {
	if p.driver.options.LifecycleTrust == nil {
		if p.driver.tls != nil {
			options = append(options, nats.Secure(p.driver.tls.Clone()))
		}
		var err error
		p.conn, err = nats.Connect(p.driver.options.ServerURL, options...)
		return err
	}
	if ctx == nil || ctx.Err() != nil || budget <= 0 {
		return pluginError("lifecycle_transport_unavailable")
	}
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	p.lifecycleCancel = cancelLifetime
	dialer, err := p.driver.options.LifecycleTrust.NewDialer(lifetime, budget)
	if err != nil {
		return err
	}
	p.lifecycleDialer = dialer
	admission, cancel := context.WithTimeout(ctx, budget)
	stopped := make(chan struct{})
	stop := context.AfterFunc(admission, func() { _ = dialer.Close(); close(stopped) })
	options = append(options, nats.TLSHandshakeFirst(), nats.SetCustomDialer(dialer))
	p.conn, err = nats.Connect(p.driver.options.ServerURL, options...)
	if !stop() {
		<-stopped
	}
	failed := err != nil || admission.Err() != nil
	cancel()
	if failed {
		return pluginError("lifecycle_transport_unavailable")
	}
	return nil
}
