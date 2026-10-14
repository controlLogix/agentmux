//go:build linux || darwin

package launcher

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

func bridgeAdmissionFixture(t *testing.T) *bootstrapConfigFixture {
	t.Helper()
	f := newBootstrapConfigFixture(t)
	f.config.OwnerBridge = &deployment.OwnerBridgeSettings{Scope: f.config.Kernel.Scope,
		ServerPassword: strings.Repeat("e", 48), ClientPassword: strings.Repeat("f", 48)}
	var document struct {
		JetStream struct {
			Store  string `json:"store_dir"`
			Memory int64  `json:"max_memory_store"`
			File   int64  `json:"max_file_store"`
		} `json:"jetstream"`
	}
	if json.Unmarshal(f.broker, &document) != nil {
		t.Fatal("broker fixture decode failed")
	}
	var err error
	f.broker, err = deployment.BuildLocalConfigWithOwnerBridge(deployment.StorageProfile{
		HubID: f.config.Health.HubID, ServerName: f.config.Health.ServerName, Domain: f.config.Health.Domain,
		StoreDirectory: document.JetStream.Store, MaxMemoryBytes: document.JetStream.Memory, MaxFileBytes: document.JetStream.File,
		Listener: bridgeFixtureListener()}, f.users, f.config.Health.Password, *f.config.OwnerBridge)
	if err != nil {
		t.Fatal("owner bridge factory fixture failed")
	}
	return f
}

func mutateBridgeScope(scope *protocol.Scope, field string) {
	switch field {
	case "hub":
		scope.HubID = "different_hub"
	case "instance":
		scope.InstanceID = "different_instance"
	case "profile":
		scope.ProfileID = "different_profile"
	case "assembly":
		scope.AssemblyDigest = "sha256:" + strings.Repeat("a", 64)
	case "release":
		scope.ReleaseManifestDigest = "sha256:" + strings.Repeat("b", 64)
	case "version":
		scope.ReleaseVersion = "2.0.0"
	}
}

func bridgeDocument(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var document map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&document) != nil {
		t.Fatal("broker fixture decode failed")
	}
	return document
}

func TestOwnerBridgeAdmissionExplicitFactoryPositive(t *testing.T) {
	f := bridgeAdmissionFixture(t)
	f.enroll(t)
	users, err := bootstrapBrokerCredentials(f.broker, f.config)
	if err != nil || !reflect.DeepEqual(users, f.users) {
		t.Fatal("explicit owner bridge changed protected role identities")
	}
	f.config.brokerUsers = users
	if err := validateBootstrapRoles(f.config, f.profile); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerBridgeAdmissionBindingsDeniedBeforeDocker(t *testing.T) {
	for _, field := range []string{"nil-policy", "hub", "instance", "profile", "assembly", "release", "version", "server-password", "client-password"} {
		t.Run(field, func(t *testing.T) {
			f := bridgeAdmissionFixture(t)
			switch field {
			case "nil-policy":
				f.config.OwnerBridge = nil
			case "server-password":
				f.config.OwnerBridge.ServerPassword = strings.Repeat("1", 48)
			case "client-password":
				f.config.OwnerBridge.ClientPassword = strings.Repeat("2", 48)
			default:
				mutateBridgeScope(&f.config.OwnerBridge.Scope, field)
			}
			f.assertNoDocker(t, "bootstrap_owner_bridge_credential_binding_invalid")
		})
	}
}

func TestOwnerBridgeAdmissionWidenedAccountDeniedBeforeDocker(t *testing.T) {
	for _, field := range []string{"server-publish", "server-subscribe", "client-publish", "client-subscribe", "jetstream", "imports"} {
		t.Run(field, func(t *testing.T) {
			f := bridgeAdmissionFixture(t)
			document := bridgeDocument(t, f.broker)
			host := document["accounts"].(map[string]any)[deployment.OwnerBridgeAccount].(map[string]any)
			switch field {
			case "jetstream":
				host["jetstream"] = true
			case "imports":
				host["imports"] = []any{map[string]any{"stream": map[string]any{"account": "KERNEL", "subject": ">"}}}
			default:
				index := 0
				if strings.HasPrefix(field, "client-") {
					index = 1
				}
				permission := "publish"
				if strings.HasSuffix(field, "subscribe") {
					permission = "subscribe"
				}
				host["users"].([]any)[index].(map[string]any)["permissions"].(map[string]any)[permission] = map[string]any{"allow": []string{">"}}
			}
			f.broker = configFixtureJSON(t, document)
			f.assertNoDocker(t, "bootstrap_broker_policy_invalid")
		})
	}
}
