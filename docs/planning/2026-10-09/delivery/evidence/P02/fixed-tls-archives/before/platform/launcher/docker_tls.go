package launcher

import "context"

// InspectOwnedTLSBroker preserves the existing selected broker, image, port,
// volume and private configuration checks, then binds both injected TLS files.
// Digests come from admitted private enrollment, never the observed container.
func (d *Docker) InspectOwnedTLSBroker(ctx context.Context, o OwnershipPreflight, image string, port int, config, certificate, key [32]byte) (OwnedBroker, error) {
	if ctx == nil || certificate == ([32]byte{}) || key == ([32]byte{}) {
		return OwnedBroker{}, refusal("broker_tls_expectation_invalid")
	}
	broker, err := d.InspectOwnedBroker(ctx, o, image, port, config)
	if err != nil {
		return OwnedBroker{}, err
	}
	if ctx.Err() != nil {
		return OwnedBroker{}, refusal("command_timeout_outcome_unknown")
	}
	if broker.State == "absent" {
		return broker, nil
	}
	for _, file := range []struct {
		name   string
		digest [32]byte
		limit  int64
	}{{"server-cert.pem", certificate, 16 * 1024}, {"server-key.pem", key, 8 * 1024}} {
		raw, err := d.run(ctx, nil, "cp", broker.ContainerID+":/etc/nats/"+file.name, "-")
		if err != nil {
			return OwnedBroker{}, err
		}
		if err := verifyPrivateFileArchive(raw, file.digest, file.name, file.limit); err != nil {
			return OwnedBroker{}, refusal("broker_tls_file_mismatch")
		}
	}
	if ctx.Err() != nil {
		return OwnedBroker{}, refusal("command_timeout_outcome_unknown")
	}
	return broker, nil
}
