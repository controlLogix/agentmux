package deployment

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

func secureFactoryFixture(t *testing.T) (*LocalTLSMaterial, StorageProfile, []byte) {
	t.Helper()
	m, err := EnrollLocalTLS(context.Background(), localTLSFixtureProfile)
	if err != nil {
		t.Fatal("secure fixture enrollment failed")
	}
	p, c, health, settings := ownerBridgeConfigFixture(t)
	settings.Scope.ProfileID = localTLSFixtureProfile
	raw, err := BuildSecureLocalConfigWithOwnerBridge(p, c, health, settings, m)
	if err != nil {
		t.Fatal("secure fixture factory failed")
	}
	return m, p, raw
}

func TestSecureLocalFactoriesPreserveCompleteLegacyDeclarations(t *testing.T) {
	m, err := EnrollLocalTLS(context.Background(), localTLSFixtureProfile)
	if err != nil {
		t.Fatal("secure material unavailable")
	}
	p, c, health, settings := ownerBridgeConfigFixture(t)
	settings.Scope.ProfileID = localTLSFixtureProfile
	for _, owner := range []bool{false, true} {
		var plain, secure []byte
		if owner {
			plain, err = BuildLocalConfigWithOwnerBridge(p, c, health, settings)
			if err == nil {
				secure, err = BuildSecureLocalConfigWithOwnerBridge(p, c, health, settings, m)
			}
		} else {
			plain, err = BuildLocalConfig(p, c, health)
			if err == nil {
				secure, err = BuildSecureLocalConfig(p, c, health, m)
			}
		}
		if err != nil {
			t.Fatal("valid secure factory failed")
		}
		before, err := decodeSecureBrokerJSON(plain)
		if err != nil {
			t.Fatal("legacy factory JSON invalid")
		}
		after, err := decodeSecureBrokerJSON(secure)
		if err != nil {
			t.Fatal("secure factory JSON invalid")
		}
		if validateStrictLocalTLSConfig(secure) != nil || !reflect.DeepEqual(after["tls"], strictLocalTLSBlock()) {
			t.Fatal("strict TLS requirements missing")
		}
		delete(after, "tls")
		if !reflect.DeepEqual(before, after) {
			t.Fatal("TLS addition changed account, storage or listener declarations")
		}
		if _, exists := before["tls"]; exists {
			t.Fatal("legacy boundary silently became secure")
		}
	}
	if raw, err := BuildSecureLocalConfig(p, c, health, nil); err == nil || raw != nil {
		t.Fatal("missing material permitted plaintext fallback")
	}
	settings.Scope.ProfileID = "profile_ffffffffffffffffffffffffffffffff"
	if raw, err := BuildSecureLocalConfigWithOwnerBridge(p, c, health, settings, m); err == nil || raw != nil {
		t.Fatal("material crossed profile scope")
	}
	p.MaxFileBytes = 0
	if raw, err := BuildSecureLocalConfig(p, c, health, m); err == nil || raw != nil {
		t.Fatal("secure factory bypassed storage limits")
	}
}

func TestSecureBrokerConfigRejectsFallbackAliasAndDuplicateInputs(t *testing.T) {
	_, _, valid := secureFactoryFixture(t)
	for _, kind := range []string{"missing-tls", "plaintext-first", "auto-fallback", "duration-fallback", "tls12", "cert-target", "key-target", "extra-option", "case-alias"} {
		t.Run(kind, func(t *testing.T) {
			config, err := decodeSecureBrokerJSON(valid)
			if err != nil {
				t.Fatal("fixture config invalid")
			}
			tls := config["tls"].(map[string]any)
			switch kind {
			case "missing-tls":
				delete(config, "tls")
			case "plaintext-first":
				tls["handshake_first"] = false
			case "auto-fallback":
				tls["handshake_first"] = "auto"
			case "duration-fallback":
				tls["handshake_first"] = "300ms"
			case "tls12":
				tls["min_version"] = "1.2"
			case "cert-target":
				tls["cert_file"] = "/other/certificate"
			case "key-target":
				tls["key_file"] = "/other/key"
			case "extra-option":
				tls["verify"] = false
			case "case-alias":
				config["TLS"] = map[string]any{"handshake_first": false}
			}
			raw, err := json.Marshal(config)
			if err != nil {
				t.Fatal("negative config encode failed")
			}
			if validateStrictLocalTLSConfig(raw) == nil {
				t.Fatal("weaker or ambiguous TLS was admitted")
			}
		})
	}
	for _, raw := range [][]byte{[]byte(`{"tls":{},"tls":{}}`), []byte(`{"accounts":{"HOST":{},"HOST":{}}}`), append(bytes.Clone(valid), []byte("{}")...), []byte(`[]`), []byte(`null`)} {
		if validateStrictLocalTLSConfig(raw) == nil {
			t.Fatal("ambiguous configuration was admitted")
		}
	}
}
