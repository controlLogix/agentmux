package deployment

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// RenderSecureCompose injects only the enrolled server leaf and key alongside
// the private broker config. The CA signing key never reaches the document.
// Exact private output bytes, including certificates, require launcher binding.
// Like the legacy renderer, inline configs require a writable container layer;
// Docker administrators can read them and exports can retain their bytes.
func RenderSecureCompose(s ComposeSpec, material *LocalTLSMaterial) ([]byte, error) {
	if validateLocalTLSMaterial(material) != nil || s.ProfileID != material.profileID || validateStrictLocalTLSConfig(s.BrokerConfig) != nil {
		return nil, errors.New("secure_compose_material_or_config_invalid")
	}
	base, err := RenderCompose(s)
	if err != nil {
		return nil, err
	}
	var document renderedCompose
	if json.Unmarshal(base, &document) != nil {
		return nil, errors.New("secure_compose_encode_failed")
	}
	broker := document.Services["nats"]
	broker.Configs = append(broker.Configs,
		renderedConfigRef{Source: "server_cert", Target: PrivateServerCertTarget, UID: "0", GID: "0", Mode: 0400},
		renderedConfigRef{Source: "server_key", Target: PrivateServerKeyTarget, UID: "0", GID: "0", Mode: 0400})
	document.Services["nats"] = broker
	document.Configs["server_cert"] = renderedConfig{Content: strings.ReplaceAll(string(material.ServerCertificatePEM()), "$", "$$")}
	document.Configs["server_key"] = renderedConfig{Content: strings.ReplaceAll(string(material.ServerKeyPEM()), "$", "$$")}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(document) != nil {
		return nil, errors.New("secure_compose_encode_failed")
	}
	return output.Bytes(), nil
}
