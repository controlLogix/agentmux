package launcher

import "context"

// InspectOwnedTLSBroker preserves the existing selected broker, image, port,
// volume and private configuration checks, then binds both injected TLS files.
// Digests come from admitted private enrollment, never the observed container.
func (d *Docker) InspectOwnedTLSBroker(ctx context.Context, o OwnershipPreflight, image string, port int, config, certificate, key [32]byte) (OwnedBroker, error) {
	if ctx == nil || certificate == ([32]byte{}) || key == ([32]byte{}) {
		return OwnedBroker{}, refusal("broker_tls_expectation_invalid")
	}
	broker, err := d.inspectOwnedBrokerIdentity(ctx, o, image, port, config)
	if err != nil {
		return OwnedBroker{}, err
	}
	if ctx.Err() != nil {
		return OwnedBroker{}, refusal("command_timeout_outcome_unknown")
	}
	if broker.State == "absent" {
		return broker, nil
	}
	if err := d.verifyOwnedTLSArchives(ctx, broker.ContainerID, config, certificate, key); err != nil {
		return OwnedBroker{}, err
	}
	if ctx.Err() != nil {
		return OwnedBroker{}, refusal("command_timeout_outcome_unknown")
	}
	return broker, nil
}
