package deployment

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/nats-io/nats.go"
)

// Query only the disposable fixture's enrolled administrator. Keep its private
// configuration and complete server response out of test output and artifacts.
func fixtureSyncAlways(t *testing.T, f *healthFixture) bool {
	t.Helper()
	raw, err := os.ReadFile(f.config)
	if err != nil {
		t.Fatal("private fixture configuration unavailable")
	}
	var config struct {
		Accounts map[string]struct {
			Users []struct{ User, Password string } `json:"users"`
		} `json:"accounts"`
	}
	if json.Unmarshal(raw, &config) != nil {
		t.Fatal("private fixture configuration invalid")
	}
	users := config.Accounts[communication.SystemAccount].Users
	if len(users) != 1 || users[0].User != communication.Administrator {
		t.Fatal("fixture administrator identity changed")
	}
	nc, err := nats.Connect(f.options.Endpoint, nats.UserInfo(users[0].User, users[0].Password), nats.Timeout(time.Second), nats.NoReconnect())
	if err != nil {
		t.Fatal("fixture administrator connection failed")
	}
	defer nc.Close()
	if nc.ConnectedServerVersion() != "2.15.0" || nc.ConnectedServerName() != f.options.ServerName {
		t.Fatal("fixture broker identity changed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	message, err := nc.RequestWithContext(ctx, "$SYS.REQ.SERVER."+nc.ConnectedServerId()+".VARZ", nil)
	if err != nil {
		t.Fatal("authenticated fixture configuration observation failed")
	}
	var response struct {
		Data struct {
			ServerID  string `json:"server_id"`
			Version   string `json:"version"`
			JetStream struct {
				Config struct {
					Domain     string `json:"domain"`
					SyncAlways bool   `json:"sync_always"`
				} `json:"config"`
			} `json:"jetstream"`
		} `json:"data"`
	}
	if json.Unmarshal(message.Data, &response) != nil || response.Data.ServerID != nc.ConnectedServerId() || response.Data.Version != "2.15.0" || response.Data.JetStream.Config.Domain != f.options.Domain {
		t.Fatal("authenticated fixture configuration identity invalid")
	}
	return response.Data.JetStream.Config.SyncAlways
}

func TestLocalSyncPolicyPinnedBrokerSyntaxAndObservation(t *testing.T) {
	f := newHealthFixture(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// The broker's diagnostics can contain private paths. Retain only success.
	if exec.CommandContext(ctx, f.binary, "-t", "-c", f.config).Run() != nil {
		t.Fatal("pinned broker refused the generated sync policy")
	}
	if !fixtureSyncAlways(t, f) {
		t.Fatal("generated policy did not enable always-sync in the running broker")
	}
	t.Log("Pinned NATS 2.15.0 accepted generated configuration; authenticated SYS observation confirms sync_always=true. This does not prove power-loss safety.")
}

func TestLocalSyncPolicyObservationDistinguishesRelaxedConfigurations(t *testing.T) {
	for _, mode := range []string{"missing", "periodic"} {
		t.Run(mode, func(t *testing.T) {
			f := newHealthFixture(t, false)
			f.stop(t)
			raw, err := os.ReadFile(f.config)
			if err != nil {
				t.Fatal("private fixture configuration unavailable")
			}
			var config map[string]any
			if json.Unmarshal(raw, &config) != nil {
				t.Fatal("private fixture configuration invalid")
			}
			js := config["jetstream"].(map[string]any)
			delete(js, "sync_interval")
			if mode == "periodic" {
				js["sync_interval"] = "10s"
			}
			if os.WriteFile(f.config, fixtureConfigJSON(t, config), 0600) != nil {
				t.Fatal("private negative-control configuration write failed")
			}
			f.start(t)
			if fixtureSyncAlways(t, f) {
				t.Fatal("relaxed configuration was mistaken for always-sync")
			}
		})
	}
}
