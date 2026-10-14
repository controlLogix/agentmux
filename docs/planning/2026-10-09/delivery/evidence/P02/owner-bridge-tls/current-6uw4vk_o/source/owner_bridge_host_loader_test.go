//go:build linux || darwin

package launcher

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

func bridgeFixtureListener() communication.Listener {
	return communication.Listener{Mode: communication.ContainerInternal, Port: 4222}
}

func bridgeHostFixture(t *testing.T) *hostTestFixture {
	t.Helper()
	f := hostConfigFixture(t)
	release, err := LoadInstalledRelease(f.policy.ExternalRelease)
	if err != nil {
		t.Fatal(err)
	}
	trust := release.Trust()
	f.policy.OwnerBridge = &deployment.OwnerBridgeSettings{Scope: protocol.Scope{
		HubID: f.metadata.HubID, InstanceID: f.profile.InstanceID, ProfileID: f.profile.ProfileID,
		AssemblyDigest: trust.AssemblyDigest, ReleaseManifestDigest: trust.ReleaseManifestDigest, ReleaseVersion: trust.ReleaseVersion},
		ServerPassword: strings.Repeat("e", 48), ClientPassword: strings.Repeat("f", 48)}
	f.broker, err = deployment.BuildSecureLocalConfigWithOwnerBridge(deployment.StorageProfile{
		HubID: f.metadata.HubID, ServerName: f.metadata.ServerName, Domain: f.metadata.Domain,
		StoreDirectory: f.metadata.StoreDirectory, MaxMemoryBytes: f.metadata.MaxMemoryBytes, MaxFileBytes: f.metadata.MaxFileBytes,
		Listener: bridgeFixtureListener()}, f.credentials, f.health, *f.policy.OwnerBridge, f.material)
	if err != nil {
		t.Fatal("host bridge factory fixture failed")
	}
	bridgeHostEnroll(t, f)
	return f
}

func bridgeHostEnroll(t *testing.T, f *hostTestFixture) {
	t.Helper()
	release, err := LoadInstalledRelease(f.policy.ExternalRelease)
	if err != nil {
		t.Fatal(err)
	}
	compose, err := deployment.RenderSecureCompose(deployment.ComposeSpec{Project: f.profile.ComposeProject,
		InstanceID: f.profile.InstanceID, ProfileID: f.profile.ProfileID, ReleaseDigest: f.profile.ReleaseFingerprint,
		Image: release.BrokerPins().Image, HostPort: 4222, BrokerConfig: f.broker}, f.material)
	if err != nil {
		t.Fatal("host bridge Compose fixture failed")
	}
	digest := sha256.Sum256(compose)
	f.profile.ConfigDigest = "sha256:" + hex.EncodeToString(digest[:])
	profile, _ := json.Marshal(f.profile)
	releaseTestWrite(t, f.profile.ProfileDirectory, "profile.json", profile)
	releaseTestWrite(t, f.profile.ProfileDirectory, "broker.json", f.broker)
}

func TestOwnerBridgeHostLoaderOptionalPolicyAndValueCopy(t *testing.T) {
	f := bridgeHostFixture(t)
	config, err := LoadBootstrapConfig(f.policy)
	if err != nil || config.OwnerBridge == nil || *config.OwnerBridge != *f.policy.OwnerBridge || config.OwnerBridge == f.policy.OwnerBridge {
		t.Fatal("loader did not return an independent enrolled owner bridge value")
	}
	expected := *config.OwnerBridge
	f.policy.OwnerBridge.ServerPassword = strings.Repeat("1", 48)
	f.policy.OwnerBridge.Scope.ProfileID = "changed_profile"
	if *config.OwnerBridge != expected {
		t.Fatal("caller policy mutation changed loaded bridge settings")
	}
	config.OwnerBridge.ClientPassword = strings.Repeat("2", 48)
	if f.policy.OwnerBridge.ClientPassword != expected.ClientPassword {
		t.Fatal("returned bridge mutation changed enrolled policy")
	}
	legacy := hostConfigFixture(t)
	config, err = LoadBootstrapConfig(legacy.policy)
	if err != nil || config.OwnerBridge != nil {
		t.Fatal("legacy factory gained an implicit owner bridge")
	}
}

func TestOwnerBridgeHostLoaderRejectsBindings(t *testing.T) {
	for _, field := range []string{"nil-policy", "hub", "instance", "profile", "assembly", "release", "version", "server-password", "client-password", "runtime-server", "runtime-domain", "runtime-memory", "runtime-file", "runtime-store"} {
		t.Run(field, func(t *testing.T) {
			f := bridgeHostFixture(t)
			expected := "host_config_owner_bridge_scope_invalid"
			switch field {
			case "nil-policy":
				f.policy.OwnerBridge = nil
				expected = "host_config_broker_policy_invalid"
			case "server-password":
				f.policy.OwnerBridge.ServerPassword = strings.Repeat("1", 48)
				expected = "host_config_broker_policy_invalid"
			case "client-password":
				f.policy.OwnerBridge.ClientPassword = strings.Repeat("2", 48)
				expected = "host_config_broker_policy_invalid"
			case "runtime-server":
				f.metadata.ServerName = "changed_server"
				expected = "host_config_broker_policy_invalid"
			case "runtime-domain":
				f.metadata.Domain = "changed_domain"
				expected = "host_config_broker_policy_invalid"
			case "runtime-memory":
				f.metadata.MaxMemoryBytes++
				expected = "host_config_runtime_broker_mismatch"
			case "runtime-file":
				f.metadata.MaxFileBytes++
				expected = "host_config_runtime_broker_mismatch"
			case "runtime-store":
				f.metadata.StoreDirectory = "/data/different"
				expected = "host_config_runtime_broker_mismatch"
			default:
				mutateBridgeScope(&f.policy.OwnerBridge.Scope, field)
			}
			raw, _ := json.Marshal(f.metadata)
			releaseTestWrite(t, f.profile.ProfileDirectory, "runtime.json", raw)
			bridgeHostEnroll(t, f)
			config, err := LoadBootstrapConfig(f.policy)
			if err == nil || err.Error() != expected || !reflect.DeepEqual(config, BootstrapConfig{}) {
				t.Fatalf("binding refusal did not return %s without partial settings", expected)
			}
		})
	}
}
