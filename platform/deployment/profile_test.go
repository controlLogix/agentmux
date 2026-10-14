package deployment

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/nats-io/nats.go"
)

func TestStorageFactoryPreservesProtectedBoundary(t *testing.T) {
	c, password := deploymentSecrets(t)
	p := StorageProfile{HubID: "fixture_hub", ServerName: "fixture_server", Domain: "fixture_domain", StoreDirectory: filepath.Join(t.TempDir(), "store"), MaxMemoryBytes: 1024 * 1024, MaxFileBytes: 4 * 1024 * 1024, Listener: communication.Listener{Mode: communication.NativeLoopback, Port: 4222}}
	base, err := communication.BuildConfigWithListener(p.HubID, p.Listener, c)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := BuildLocalConfig(p, c, password)
	if err != nil {
		t.Fatal(err)
	}
	var original, actual map[string]any
	json.Unmarshal(base, &original)
	json.Unmarshal(raw, &actual)
	accounts := actual["accounts"].(map[string]any)
	if len(accounts) != 4 {
		t.Fatal("unexpected account membership")
	}
	for name, account := range original["accounts"].(map[string]any) {
		if !reflect.DeepEqual(account, accounts[name]) {
			t.Fatal("protected account boundary changed")
		}
	}
	if actual["listen"] != original["listen"] || actual["system_account"] != original["system_account"] || actual["server_name"] != p.ServerName {
		t.Fatal("listener or identity changed")
	}
	js := actual["jetstream"].(map[string]any)
	if len(js) != 5 || js["store_dir"] != p.StoreDirectory || js["domain"] != p.Domain || js["max_memory_store"] != float64(p.MaxMemoryBytes) || js["max_file_store"] != float64(p.MaxFileBytes) || js["sync_interval"] != "always" {
		t.Fatal("storage profile changed")
	}
	health := accounts[HealthAccount].(map[string]any)
	if len(health) != 2 || health["jetstream"] != "enabled" {
		t.Fatal("health account widened")
	}
	users := health["users"].([]any)
	if len(users) != 1 {
		t.Fatal("health membership changed")
	}
	user := users[0].(map[string]any)
	if user["user"] != HealthUser || user["password"] != password {
		t.Fatal("health identity changed")
	}
	permissions := user["permissions"].(map[string]any)
	if len(permissions) != 2 {
		t.Fatal("health permissions changed")
	}
	api := "$JS." + p.Domain + ".API.STREAM."
	expected := []any{HealthSubject(p.HubID), "$JS." + p.Domain + ".API.INFO", "$JS.API.INFO"}
	for _, operation := range []string{"CREATE.", "INFO.", "MSG.GET."} {
		expected = append(expected, api+operation+HealthStream(p.HubID), "$JS.API.STREAM."+operation+HealthStream(p.HubID))
	}
	if !reflect.DeepEqual(permissions["publish"], map[string]any{"allow": expected}) || !reflect.DeepEqual(permissions["subscribe"], map[string]any{"allow": []any{"_INBOX.>"}}) {
		t.Fatal("health permission surface widened")
	}
}

func TestStorageFactoryRejectsInvalidDeclarations(t *testing.T) {
	c, password := deploymentSecrets(t)
	base := StorageProfile{HubID: "fixture_hub", ServerName: "fixture_server", Domain: "fixture_domain", StoreDirectory: filepath.Join(t.TempDir(), "store"), MaxMemoryBytes: 1024 * 1024, MaxFileBytes: 4 * 1024 * 1024, Listener: communication.Listener{Mode: communication.NativeLoopback, Port: 4222}}
	for _, kind := range []string{"hub", "server", "domain", "path", "root-path", "control-path", "memory", "file", "password", "shared-password", "missing-role"} {
		t.Run(kind, func(t *testing.T) {
			p := base
			secrets := communication.Credentials{}
			for k, v := range c {
				secrets[k] = v
			}
			health := password
			switch kind {
			case "hub":
				p.HubID = "Hub"
			case "server":
				p.ServerName = "not.name"
			case "domain":
				p.Domain = "*"
			case "path":
				p.StoreDirectory = "relative/store"
			case "root-path":
				p.StoreDirectory = string(filepath.Separator)
			case "control-path":
				p.StoreDirectory += "\x00"
			case "memory":
				p.MaxMemoryBytes = 0
			case "file":
				p.MaxFileBytes = 0
			case "password":
				health = "invalid"
			case "shared-password":
				health = c["boot"]
			case "missing-role":
				delete(secrets, "boot")
			}
			if raw, err := BuildLocalConfig(p, secrets, health); err == nil || raw != nil {
				t.Fatal("invalid declaration produced private config")
			}
		})
	}
}

func TestHealthReplicaAndOptionalFeatureComparison(t *testing.T) {
	for _, kind := range []string{"replica", "mirror", "sealed", "rollup", "direct", "metadata"} {
		t.Run(kind, func(t *testing.T) {
			c := HealthConfig("fixture_hub")
			switch kind {
			case "replica":
				c.Replicas = 2
			case "mirror":
				c.Mirror = &nats.StreamSource{Name: "other"}
			case "sealed":
				c.Sealed = true
			case "rollup":
				c.AllowRollup = true
			case "direct":
				c.AllowDirect = true
			case "metadata":
				c.Metadata = map[string]string{"_nats.level": "5", "_nats.req.level": "0", "_nats.ver": "2.15.0", "untrusted": "extra"}
			}
			if compatibleHealth(c, "fixture_hub") {
				t.Fatal("incompatible feature accepted")
			}
		})
	}
}
