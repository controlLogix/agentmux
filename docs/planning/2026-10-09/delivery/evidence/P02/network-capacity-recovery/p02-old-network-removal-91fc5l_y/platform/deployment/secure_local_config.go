package deployment

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"

	"github.com/controlLogix/agentmux/platform/kernel/communication"
)

const PrivateServerCertTarget = "/etc/nats/server-cert.pem"
const PrivateServerKeyTarget = "/etc/nats/server-key.pem"

func secureLocalError() error { return errors.New("secure_local_config_invalid") }

func strictLocalTLSBlock() map[string]any {
	return map[string]any{"cert_file": PrivateServerCertTarget, "key_file": PrivateServerKeyTarget, "handshake_first": true, "min_version": "1.3"}
}

func validateLocalTLSMaterial(material *LocalTLSMaterial) error {
	if material == nil {
		return secureLocalError()
	}
	if _, err := NewLocalTLSMaterial(material.profileID, material.roots, material.certificate, material.key); err != nil {
		return secureLocalError()
	}
	return nil
}

// The secure factories preserve the complete plain factory output, then add
// strict server TLS. They neither install trust nor widen account permissions.
// Returned bytes contain passwords and remain private.
func BuildSecureLocalConfig(p StorageProfile, credentials communication.Credentials, healthPassword string, material *LocalTLSMaterial) ([]byte, error) {
	if validateLocalTLSMaterial(material) != nil {
		return nil, secureLocalError()
	}
	base, err := BuildLocalConfig(p, credentials, healthPassword)
	if err != nil {
		return nil, err
	}
	return addStrictLocalTLS(base)
}

func BuildSecureLocalConfigWithOwnerBridge(p StorageProfile, credentials communication.Credentials, healthPassword string, settings OwnerBridgeSettings, material *LocalTLSMaterial) ([]byte, error) {
	if validateLocalTLSMaterial(material) != nil || settings.Scope.ProfileID != material.profileID {
		return nil, secureLocalError()
	}
	base, err := BuildLocalConfigWithOwnerBridge(p, credentials, healthPassword, settings)
	if err != nil {
		return nil, err
	}
	return addStrictLocalTLS(base)
}

func addStrictLocalTLS(base []byte) ([]byte, error) {
	config, err := decodeSecureBrokerJSON(base)
	if err != nil {
		return nil, err
	}
	for name := range config {
		if strings.EqualFold(name, "tls") {
			return nil, secureLocalError()
		}
	}
	config["tls"] = strictLocalTLSBlock()
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(config) != nil || output.Len() > MaxPrivateConfigBytes {
		return nil, secureLocalError()
	}
	return output.Bytes(), nil
}

func decodeSecureBrokerJSON(raw []byte) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > MaxPrivateConfigBytes {
		return nil, secureLocalError()
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if secureJSONUnique(d, 0) != nil {
		return nil, secureLocalError()
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, secureLocalError()
	}
	var config map[string]any
	d = json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&config) != nil || config == nil {
		return nil, secureLocalError()
	}
	return config, nil
}

func secureJSONUnique(d *json.Decoder, depth int) error {
	if depth > 64 {
		return secureLocalError()
	}
	token, err := d.Token()
	if err != nil {
		return secureLocalError()
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return secureLocalError()
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return secureLocalError()
			}
			seen[name] = true
			if secureJSONUnique(d, depth+1) != nil {
				return secureLocalError()
			}
		}
	case '[':
		for d.More() {
			if secureJSONUnique(d, depth+1) != nil {
				return secureLocalError()
			}
		}
	default:
		return secureLocalError()
	}
	end, err := d.Token()
	if err != nil {
		return secureLocalError()
	}
	if (delimiter == '{' && end != json.Delim('}')) || (delimiter == '[' && end != json.Delim(']')) {
		return secureLocalError()
	}
	return nil
}

func validateStrictLocalTLSConfig(raw []byte) error {
	config, err := decodeSecureBrokerJSON(raw)
	if err != nil {
		return err
	}
	for name := range config {
		if strings.EqualFold(name, "tls") && name != "tls" {
			return secureLocalError()
		}
	}
	if !reflect.DeepEqual(config["tls"], strictLocalTLSBlock()) {
		return secureLocalError()
	}
	return nil
}
