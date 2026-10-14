//go:build linux || darwin

package launcher

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"strings"
)

// This admission binds private inline files; it does not inspect Docker or
// authenticate a network peer. The complete Compose allowlist is checked too.
func bootstrapComposeBrokerBytes(c BootstrapConfig) ([]byte, error) {
	var doc composeDocument
	if !uniqueComposeJSON(c.Compose) || json.Unmarshal(c.Compose, &doc) != nil || len(doc.Services) != 1 {
		return nil, bootstrapError("broker_config_binding_invalid")
	}
	expectedCount := 1
	if c.LocalTLS != nil {
		expectedCount = 3
	}
	if len(doc.Configs) != expectedCount {
		return nil, bootstrapError("broker_config_binding_invalid")
	}
	for _, service := range doc.Services {
		if len(service.Configs) != expectedCount {
			return nil, bootstrapError("broker_config_binding_invalid")
		}
		var broker []byte
		seen := map[string]bool{}
		for _, ref := range service.Configs {
			config, ok := doc.Configs[ref.Source]
			if !ok || seen[ref.Source] || ref.UID != "0" || ref.GID != "0" || ref.Mode != 0400 {
				return nil, bootstrapError("broker_config_binding_invalid")
			}
			seen[ref.Source] = true
			raw := []byte(strings.ReplaceAll(config.Content, "$$", "$"))
			switch ref.Target {
			case "/etc/nats/private.conf":
				if broker != nil || sha256.Sum256(raw) != c.BrokerConfigDigest || (c.LocalTLS != nil && ref.Source != "broker_config") {
					return nil, bootstrapError("broker_config_binding_invalid")
				}
				broker = raw
			case "/etc/nats/server-cert.pem":
				if c.LocalTLS == nil || ref.Source != "server_cert" || !bytes.Equal(raw, c.LocalTLS.ServerCertificatePEM()) {
					return nil, bootstrapError("broker_tls_binding_invalid")
				}
			case "/etc/nats/server-key.pem":
				if c.LocalTLS == nil || ref.Source != "server_key" || !bytes.Equal(raw, c.LocalTLS.ServerKeyPEM()) {
					return nil, bootstrapError("broker_tls_binding_invalid")
				}
			default:
				return nil, bootstrapError("broker_config_binding_invalid")
			}
		}
		if len(broker) == 0 {
			return nil, bootstrapError("broker_config_binding_invalid")
		}
		return broker, nil
	}
	return nil, bootstrapError("broker_config_binding_invalid")
}
