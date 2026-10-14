package deployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"testing"
)

func TestSecureComposePreservesStackAndInjectsExactThreeObjects(t *testing.T) {
	m, _, config := secureFactoryFixture(t)
	s := composeFixture()
	s.ProfileID = localTLSFixtureProfile
	s.BrokerConfig = config
	legacy, err := RenderCompose(s)
	if err != nil {
		t.Fatal("baseline render failed")
	}
	body, err := RenderSecureCompose(s, m)
	if err != nil {
		t.Fatal("secure render failed")
	}
	again, err := RenderSecureCompose(s, m)
	if err != nil || !bytes.Equal(body, again) {
		t.Fatal("secure render not deterministic")
	}
	var before, after renderedCompose
	if json.Unmarshal(legacy, &before) != nil || json.Unmarshal(body, &after) != nil {
		t.Fatal("rendered Compose JSON invalid")
	}
	refs := after.Services["nats"].Configs
	want := []renderedConfigRef{{Source: "broker_config", Target: PrivateConfigTarget, UID: "0", GID: "0", Mode: 0400}, {Source: "server_cert", Target: PrivateServerCertTarget, UID: "0", GID: "0", Mode: 0400}, {Source: "server_key", Target: PrivateServerKeyTarget, UID: "0", GID: "0", Mode: 0400}}
	if len(after.Configs) != 3 || !reflect.DeepEqual(refs, want) {
		t.Fatal("private inline objects or refs changed")
	}
	if unescapeComposePairs(t, after.Configs["broker_config"].Content) != string(config) || unescapeComposePairs(t, after.Configs["server_cert"].Content) != string(m.ServerCertificatePEM()) || unescapeComposePairs(t, after.Configs["server_key"].Content) != string(m.ServerKeyPEM()) {
		t.Fatal("private material bytes changed in rendering")
	}
	broker := after.Services["nats"]
	broker.Configs = broker.Configs[:1]
	after.Services["nats"] = broker
	delete(after.Configs, "server_cert")
	delete(after.Configs, "server_key")
	if !reflect.DeepEqual(before, after) {
		t.Fatal("secure renderer changed broker, label, port or persistence boundaries")
	}
	changed := bytes.Clone(body)
	changed[len(changed)/2] ^= 1
	if sha256.Sum256(changed) == sha256.Sum256(body) {
		t.Fatal("full private output digest failed to bind changed bytes")
	}
}

func TestSecureComposeRejectsMissingMismatchedOrPlainMaterial(t *testing.T) {
	m, _, config := secureFactoryFixture(t)
	s := composeFixture()
	s.ProfileID = localTLSFixtureProfile
	s.BrokerConfig = config
	if body, err := RenderSecureCompose(s, nil); err == nil || body != nil {
		t.Fatal("missing TLS material admitted")
	}
	s.ProfileID = "profile_ffffffffffffffffffffffffffffffff"
	if body, err := RenderSecureCompose(s, m); err == nil || body != nil {
		t.Fatal("cross-profile material admitted")
	}
	s.ProfileID = localTLSFixtureProfile
	s.BrokerConfig = []byte(`{"tls":{"handshake_first":false}}`)
	if body, err := RenderSecureCompose(s, m); err == nil || body != nil {
		t.Fatal("plaintext-first broker admitted")
	}
}
