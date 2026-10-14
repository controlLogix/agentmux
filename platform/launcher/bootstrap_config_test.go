//go:build linux || darwin

package launcher

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

type bootstrapConfigFixture struct {
	config     BootstrapConfig
	profile    Profile
	broker     []byte
	users      communication.Credentials
	commandLog string
}

func TestBootstrapConfigCannotRelaxApprovedSyncPolicy(t *testing.T) {
	for _, mode := range []string{"missing", "periodic"} {
		t.Run(mode, func(t *testing.T) {
			f := newBootstrapConfigFixture(t)
			var document map[string]any
			decoder := json.NewDecoder(bytes.NewReader(f.broker))
			decoder.UseNumber()
			if decoder.Decode(&document) != nil {
				t.Fatal("actual broker factory JSON unavailable")
			}
			storage, ok := document["jetstream"].(map[string]any)
			if !ok || storage["sync_interval"] != "always" {
				t.Fatal("approved broker flush policy missing from fixture")
			}
			if mode == "missing" {
				delete(storage, "sync_interval")
			} else {
				storage["sync_interval"] = "10s"
			}
			f.broker = configFixtureJSON(t, document)
			// Enrollment and all byte digests match the altered configuration.
			// The fixed policy must still refuse it before any Docker command.
			f.assertNoDocker(t, "bootstrap_broker_policy_invalid")
		})
	}
}

func newBootstrapConfigFixture(t *testing.T) *bootstrapConfigFixture {
	t.Helper()
	policy, p := profileFixture(t)
	random := func() string {
		var b [24]byte
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal("fixture entropy unavailable")
		}
		return hex.EncodeToString(b[:])
	}
	users := communication.Credentials{}
	for _, name := range []string{communication.Administrator, communication.OrdinaryPlugin, "boot", "kernel-lifecycle", "internal-communication", "exported-status"} {
		users[name] = random()
	}
	password := random()
	scope := protocol.Scope{HubID: "config_hub", InstanceID: p.InstanceID, ProfileID: p.ProfileID, AssemblyDigest: "sha256:" + strings.Repeat("c", 64), ReleaseManifestDigest: p.ReleaseFingerprint, ReleaseVersion: "1.0.0"}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("fixture executable unavailable")
	}
	p.Docker = &ProfileDocker{Executable: executable, Context: "fixture", Endpoint: "unix:///tmp/docker.sock", EngineID: "fixture-engine", Backend: NativeUnix, ClientVersion: "29.8.0", ServerVersion: "29.8.0", ComposeVersion: "5.5.1"}
	c := BootstrapConfig{ProfilePolicy: policy, Health: deployment.ProbeOptions{Endpoint: p.NATSEndpoint, Password: password, HubID: scope.HubID, ServerName: "config_server", Domain: "config_domain", ServerVersion: "2.15.0", Timeout: time.Second}, Kernel: KernelStatusOptions{Endpoint: p.NATSEndpoint, Password: users[communication.OrdinaryPlugin], Scope: scope, Timeout: time.Second}, Deadlines: protected.Deadlines{StartTimeout: time.Second, StopGrace: 50 * time.Millisecond, ReapTimeout: time.Second}, StartupTimeout: 5 * time.Second, BrokerImage: "docker.io/library/nats@sha256:" + strings.Repeat("d", 64)}
	c.ReleaseTrust.AssemblyDigest = scope.AssemblyDigest
	c.ReleaseTrust.ReleaseManifestDigest = scope.ReleaseManifestDigest
	c.ReleaseTrust.ReleaseVersion = scope.ReleaseVersion
	c.ReleaseTrust.KernelAPIMajor = 1
	raw, err := deployment.BuildLocalConfig(deployment.StorageProfile{HubID: scope.HubID, ServerName: c.Health.ServerName, Domain: c.Health.Domain, StoreDirectory: "/data/jetstream", MaxMemoryBytes: 1024 * 1024, MaxFileBytes: 4 * 1024 * 1024, Listener: communication.Listener{Mode: communication.ContainerInternal, Port: 4222}}, users, password)
	if err != nil {
		t.Fatal("real fixed factory failed")
	}
	for i, role := range protocol.Roles() {
		path := filepath.Join(p.ProfileDirectory, role+".json")
		credentials := protocol.Credentials{SchemaVersion: protocol.Version, Role: role, Username: role, Password: users[role], NATSURL: p.NATSEndpoint, Scope: scope}
		data, _ := json.Marshal(credentials)
		if os.WriteFile(path, data, 0600) != nil {
			t.Fatal("private fixture role file unavailable")
		}
		c.Roles[i] = protected.RoleOptions{ID: role, Env: map[string]string{"AGENTMUX_NATS_URL": p.NATSEndpoint, "AGENTMUX_INSTANCE_ID": p.InstanceID, "AGENTMUX_PROFILE_ID": p.ProfileID, "AGENTMUX_NATS_CREDS_FILE": path}}
	}
	fixture := &bootstrapConfigFixture{config: c, profile: p, broker: raw, users: users, commandLog: filepath.Join(t.TempDir(), "commands")}
	t.Setenv("AMX_DOCKER_FIXTURE", "1")
	t.Setenv("AMX_DOCKER_LOG", fixture.commandLog)
	t.Setenv("AMX_DOCKER_MODE", "")
	t.Setenv("DOCKER_HOST", "")
	t.Setenv("DOCKER_CONTEXT", "")
	return fixture
}

func configFixtureJSON(t *testing.T, value any) []byte {
	t.Helper()
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(value) != nil {
		t.Fatal("fixture JSON encoding failed")
	}
	return out.Bytes()
}

func (f *bootstrapConfigFixture) enroll(t *testing.T) {
	t.Helper()
	body, err := deployment.RenderCompose(deployment.ComposeSpec{Project: f.profile.ComposeProject, InstanceID: f.profile.InstanceID, ProfileID: f.profile.ProfileID, ReleaseDigest: f.profile.ReleaseFingerprint, Image: f.config.BrokerImage, HostPort: 4222, BrokerConfig: f.broker})
	if err != nil {
		t.Fatal("fixture Compose rendering failed")
	}
	f.config.Compose = body
	f.config.BrokerConfigDigest = sha256.Sum256(f.broker)
	hash := sha256.Sum256(body)
	f.profile.ConfigDigest = "sha256:" + hex.EncodeToString(hash[:])
	if err := EnrollProfile(f.config.ProfilePolicy, f.profile); err != nil {
		t.Fatal("explicit fixture enrollment failed")
	}
}

func (f *bootstrapConfigFixture) assertNoDocker(t *testing.T, expected string) {
	t.Helper()
	f.enroll(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := Bootstrap(ctx, context.Background(), f.config)
	if session != nil {
		session.Close(ctx)
	}
	if err == nil || err.Error() != expected {
		t.Fatalf("preflight did not return expected safe code %s", expected)
	}
	if _, err := os.Stat(f.commandLog); !os.IsNotExist(err) {
		t.Fatal("invalid preflight reached Docker subprocess")
	}
}

func TestBootstrapConfigRealFactoryAndPrivateRolePositive(t *testing.T) {
	f := newBootstrapConfigFixture(t)
	users, err := bootstrapBrokerCredentials(f.broker, f.config)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 6 || !reflect.DeepEqual(users, f.users) {
		t.Fatal("fixed six credential identities changed")
	}
	f.config.brokerUsers = users
	if err := validateBootstrapRoles(f.config, f.profile); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.commandLog); !os.IsNotExist(err) {
		t.Fatal("pure preflight invoked Docker")
	}
}

func TestBootstrapConfigBrokerPolicyDeniedBeforeDocker(t *testing.T) {
	for _, kind := range []string{"health-password", "observer-password", "kernel-acl", "ordinary-acl", "namespace", "domain", "server", "store-escape", "unknown-account", "unknown-field", "duplicate-key", "memory-limit", "file-limit", "broker-size"} {
		t.Run(kind, func(t *testing.T) {
			f := newBootstrapConfigFixture(t)
			var raw map[string]any
			json.Unmarshal(f.broker, &raw)
			accounts := raw["accounts"].(map[string]any)
			kernel := accounts[communication.ProtectedAccount].(map[string]any)["users"].([]any)
			ordinary := accounts[communication.ApplicationAccount].(map[string]any)["users"].([]any)[0].(map[string]any)
			expected := "bootstrap_broker_policy_invalid"
			switch kind {
			case "health-password":
				f.config.Health.Password = strings.Repeat("a", 48)
				expected = "bootstrap_health_credential_binding_invalid"
			case "observer-password":
				f.config.Kernel.Password = strings.Repeat("a", 48)
				expected = "bootstrap_observer_credential_binding_invalid"
			case "kernel-acl":
				kernel[0].(map[string]any)["permissions"].(map[string]any)["publish"] = map[string]any{"allow": []string{">"}}
			case "ordinary-acl":
				ordinary["permissions"].(map[string]any)["publish"] = map[string]any{"allow": []string{">"}}
			case "namespace":
				f.config.Health.HubID = "other_hub"
				f.config.Kernel.Scope.HubID = "other_hub"
			case "domain":
				raw["jetstream"].(map[string]any)["domain"] = "other_domain"
			case "server":
				raw["server_name"] = "other_server"
			case "store-escape":
				raw["jetstream"].(map[string]any)["store_dir"] = "/data/../private"
			case "unknown-account":
				accounts["EXTRA"] = map[string]any{"users": []any{}}
			case "unknown-field":
				raw["debug"] = true
			case "memory-limit":
				raw["jetstream"].(map[string]any)["max_memory_store"] = 0
			case "file-limit":
				raw["jetstream"].(map[string]any)["max_file_store"] = 0
			}
			f.broker = configFixtureJSON(t, raw)
			if kind == "duplicate-key" {
				f.broker = append([]byte(`{"server_name":"other_server",`), f.broker[1:]...)
			}
			if kind == "broker-size" {
				f.broker = append(f.broker, bytes.Repeat([]byte(" "), deployment.MaxPrivateConfigBytes)...)
				if _, err := bootstrapBrokerCredentials(f.broker, f.config); err == nil {
					t.Fatal("oversized private broker bytes accepted")
				}
				if _, err := os.Stat(f.commandLog); !os.IsNotExist(err) {
					t.Fatal("oversized preflight invoked Docker")
				}
				return
			}
			if _, err := bootstrapBrokerCredentials(f.broker, f.config); err == nil || err.Error() != expected {
				t.Fatal("concrete policy mutation not rejected")
			}
			f.assertNoDocker(t, expected)
		})
	}
}

func TestBootstrapConfigRoleFilesDeniedBeforeDocker(t *testing.T) {
	for _, kind := range []string{"role-password", "mode", "symlink", "hardlink", "outside-profile", "wrong-scope", "env-role", "owner-uid", "role-size", "unknown-role-field", "duplicate-role-field", "extra-env", "literal-args"} {
		t.Run(kind, func(t *testing.T) {
			f := newBootstrapConfigFixture(t)
			users, err := bootstrapBrokerCredentials(f.broker, f.config)
			if err != nil {
				t.Fatal(err)
			}
			f.config.brokerUsers = users
			path := f.config.Roles[0].Env["AGENTMUX_NATS_CREDS_FILE"]
			data, _ := os.ReadFile(path)
			var credentials protocol.Credentials
			json.Unmarshal(data, &credentials)
			expected := "bootstrap_role_credentials_invalid"
			switch kind {
			case "role-password":
				credentials.Password = strings.Repeat("a", 48)
				os.WriteFile(path, configFixtureJSON(t, credentials), 0600)
			case "mode":
				os.Chmod(path, 0644)
				expected = "bootstrap_role_file_invalid"
			case "symlink":
				if os.Rename(path, path+".real") != nil || os.Symlink(path+".real", path) != nil {
					t.Fatal("real symlink fixture failed")
				}
				expected = "bootstrap_role_file_invalid"
			case "hardlink":
				if os.Link(path, path+".link") != nil {
					t.Fatal("fixture hardlink failed")
				}
				expected = "bootstrap_role_file_invalid"
			case "outside-profile":
				outside := filepath.Join(t.TempDir(), "role.json")
				os.WriteFile(outside, data, 0600)
				f.config.Roles[0].Env["AGENTMUX_NATS_CREDS_FILE"] = outside
				expected = "bootstrap_role_file_invalid"
			case "wrong-scope":
				credentials.Scope.InstanceID = "other_instance"
				os.WriteFile(path, configFixtureJSON(t, credentials), 0600)
			case "env-role":
				f.config.Roles[0].ID = "ordinary-plugin"
				expected = "bootstrap_role_binding_invalid"
			case "owner-uid":
				f.profile.OwnerUID++
				expected = "bootstrap_role_file_invalid"
			case "role-size":
				os.WriteFile(path, bytes.Repeat([]byte(" "), protocol.MaxPayload+1), 0600)
				expected = "bootstrap_role_file_invalid"
			case "unknown-role-field":
				var value map[string]any
				json.Unmarshal(data, &value)
				value["unknown"] = true
				os.WriteFile(path, configFixtureJSON(t, value), 0600)
			case "duplicate-role-field":
				os.WriteFile(path, append([]byte(`{"role":"other",`), data[1:]...), 0600)
			case "extra-env":
				f.config.Roles[0].Env["PATH"] = "synthetic"
				expected = "bootstrap_role_binding_invalid"
			case "literal-args":
				f.config.Roles[0].Args = []string{"unexpected"}
				expected = "bootstrap_role_binding_invalid"
			}
			if err := validateBootstrapRoles(f.config, f.profile); err == nil || err.Error() != expected {
				t.Fatal("real private file mutation not rejected")
			}
			// The altered expected UID tests actual file metadata independently; an
			// enrolled profile with a wrong UID is denied earlier by LoadProfile.
			if kind == "owner-uid" {
				if _, err := os.Stat(f.commandLog); !os.IsNotExist(err) {
					t.Fatal("UID check invoked Docker")
				}
				return
			}
			f.assertNoDocker(t, expected)
		})
	}
}

func TestBootstrapConfigDeadlineLimitsDeniedBeforeDocker(t *testing.T) {
	for _, kind := range []string{"startup", "role-start", "grace", "reap", "health", "observer", "startup-zero", "role-start-zero", "grace-zero", "reap-zero", "health-zero", "observer-zero"} {
		t.Run(kind, func(t *testing.T) {
			f := newBootstrapConfigFixture(t)
			expected := "bootstrap_context_invalid"
			switch kind {
			case "startup":
				f.config.StartupTimeout = 61 * time.Second
			case "role-start":
				f.config.Deadlines.StartTimeout = 31 * time.Second
			case "grace":
				f.config.Deadlines.StopGrace = 11 * time.Second
			case "reap":
				f.config.Deadlines.ReapTimeout = 11 * time.Second
			case "health":
				f.config.Health.Timeout = 6 * time.Second
				expected = "bootstrap_probe_limits_invalid"
			case "observer":
				f.config.Kernel.Timeout = 6 * time.Second
				expected = "bootstrap_probe_limits_invalid"
			case "startup-zero":
				f.config.StartupTimeout = 0
			case "role-start-zero":
				f.config.Deadlines.StartTimeout = 0
			case "grace-zero":
				f.config.Deadlines.StopGrace = 0
			case "reap-zero":
				f.config.Deadlines.ReapTimeout = 0
			case "health-zero":
				f.config.Health.Timeout = 0
				expected = "bootstrap_probe_limits_invalid"
			case "observer-zero":
				f.config.Kernel.Timeout = 0
				expected = "bootstrap_probe_limits_invalid"
			}
			f.assertNoDocker(t, expected)
		})
	}
}
