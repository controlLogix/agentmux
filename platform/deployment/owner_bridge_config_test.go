package deployment

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

func ownerBridgeConfigFixture(t *testing.T) (StorageProfile, communication.Credentials, string, OwnerBridgeSettings) {
	t.Helper()
	c, health := deploymentSecrets(t)
	_, server := deploymentSecrets(t)
	_, client := deploymentSecrets(t)
	scope := protocol.Scope{HubID: "fixture_hub", InstanceID: "fixture_instance", ProfileID: "fixture_profile", AssemblyDigest: "sha256:" + strings.Repeat("a", 64), ReleaseManifestDigest: "sha256:" + strings.Repeat("b", 64), ReleaseVersion: "1.0.0"}
	p := StorageProfile{HubID: scope.HubID, ServerName: "fixture_server", Domain: "fixture_domain", StoreDirectory: filepath.Join(t.TempDir(), "store"), MaxMemoryBytes: 1024 * 1024, MaxFileBytes: 4 * 1024 * 1024, Listener: communication.Listener{Mode: communication.NativeLoopback, Port: 4222}}
	return p, c, health, OwnerBridgeSettings{Scope: scope, ServerPassword: server, ClientPassword: client}
}

func TestOwnerBridgeFactoryPreservesExistingAccountsAndBoundsGrants(t *testing.T) {
	p, c, health, settings := ownerBridgeConfigFixture(t)
	base, err := BuildLocalConfig(p, c, health)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := BuildLocalConfigWithOwnerBridge(p, c, health, settings)
	if err != nil {
		t.Fatal(err)
	}
	decode := func(raw []byte) map[string]any {
		var result map[string]any
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if d.Decode(&result) != nil {
			t.Fatal("factory produced invalid JSON")
		}
		return result
	}
	before, after := decode(base), decode(raw)
	accounts := after["accounts"].(map[string]any)
	host := accounts[OwnerBridgeAccount].(map[string]any)
	if len(host) != 1 {
		t.Fatal("owner account gained unrelated services")
	}
	subjects, err := OwnerBridgeSubjects(settings.Scope)
	if err != nil {
		t.Fatal(err)
	}
	users := host["users"].([]any)
	if len(users) != 2 {
		t.Fatal("owner account principal set changed")
	}
	for index, user := range users {
		u := user.(map[string]any)
		permissions := u["permissions"].(map[string]any)
		publish, subscribe := subjects.ReplyPrefix+">", subjects.Request
		if index == 1 {
			publish, subscribe = subscribe, publish
		}
		if !reflect.DeepEqual(permissions, map[string]any{"publish": map[string]any{"allow": []any{publish}}, "subscribe": map[string]any{"allow": []any{subscribe}}}) {
			t.Fatal("owner transport gained broader permissions")
		}
	}
	delete(accounts, OwnerBridgeAccount)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("additive owner transport changed existing broker behavior")
	}
	for _, text := range []string{fmt.Sprint(settings), fmt.Sprintf("%#v", settings)} {
		if strings.Contains(text, settings.ServerPassword) || strings.Contains(text, settings.ClientPassword) {
			t.Fatal("settings formatting exposed a credential")
		}
	}
}

func TestOwnerBridgeFactoryRejectsScopeAndSharedSecrets(t *testing.T) {
	p, c, health, settings := ownerBridgeConfigFixture(t)
	for _, name := range []string{"hub", "instance", "profile", "assembly", "release", "version", "same", "health", "protected", "short"} {
		t.Run(name, func(t *testing.T) {
			changed := settings
			switch name {
			case "hub":
				changed.Scope.HubID = "other_hub"
			case "instance":
				changed.Scope.InstanceID = "*"
			case "profile":
				changed.Scope.ProfileID = "fixture.profile"
			case "assembly":
				changed.Scope.AssemblyDigest = "sha256:short"
			case "release":
				changed.Scope.ReleaseManifestDigest = "sha256:short"
			case "version":
				changed.Scope.ReleaseVersion = "01.0.0"
			case "same":
				changed.ClientPassword = changed.ServerPassword
			case "health":
				changed.ServerPassword = health
			case "protected":
				changed.ClientPassword = c["boot"]
			case "short":
				changed.ServerPassword = "short"
			}
			if raw, err := BuildLocalConfigWithOwnerBridge(p, c, health, changed); err == nil || raw != nil {
				t.Fatal("unbound scope or shared credential admitted")
			}
		})
	}
}
