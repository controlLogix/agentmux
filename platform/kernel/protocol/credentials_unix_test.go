//go:build linux || darwin

package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validCredentials() Credentials {
	return Credentials{Version, "boot", "boot", strings.Repeat("a", 48), "nats://127.0.0.1:4222", testScope()}
}
func TestPrivateCredentialFileAndSupervisorBindings(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "role.json")
	f := serverTrustTestMaterial(t)
	c := validCredentials()
	c.NATSURL = f.record.Endpoint
	t.Setenv("AGENTMUX_NATS_SERVER_TRUST_FILE", writeTrustRecord(t, f.record))
	data, _ := json.Marshal(c)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"AGENTMUX_KERNEL_ROLE": "boot", "AGENTMUX_KERNEL_API_MAJOR": "1", "AGENTMUX_NATS_CREDS_FILE": path, "AGENTMUX_INSTANCE_ID": c.Scope.InstanceID, "AGENTMUX_PROFILE_ID": c.Scope.ProfileID, "AGENTMUX_NATS_URL": c.NATSURL}
	for k, v := range env {
		t.Setenv(k, v)
	}
	cfg, err := LoadEnvironment()
	if err != nil || cfg.Credentials.Role != "boot" {
		t.Fatal("valid private role file rejected")
	}
	for _, key := range []string{"AGENTMUX_KERNEL_ROLE", "AGENTMUX_KERNEL_API_MAJOR", "AGENTMUX_INSTANCE_ID", "AGENTMUX_PROFILE_ID", "AGENTMUX_NATS_URL"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "wrong")
			if _, err := LoadEnvironment(); err == nil {
				t.Fatal("supervisor mismatch accepted")
			}
		})
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEnvironment(); err == nil {
		t.Fatal("public credential file accepted")
	}
	os.Chmod(path, 0600)
	link := filepath.Join(dir, "linked.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTMUX_NATS_CREDS_FILE", link)
	if _, err := LoadEnvironment(); err == nil {
		t.Fatal("credential symlink accepted")
	}
	t.Setenv("AGENTMUX_NATS_CREDS_FILE", path)
	hardlink := filepath.Join(dir, "hardlink.json")
	if err := os.Link(path, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEnvironment(); err == nil {
		t.Fatal("aliased credential inode accepted")
	}
	os.Remove(hardlink)
	os.Chmod(dir, 0755)
	if _, err := LoadEnvironment(); err == nil {
		t.Fatal("public credential parent accepted")
	}
	os.Chmod(dir, 0700)
	if err := os.WriteFile(path, append(data[:len(data)-1], []byte(`,"role":"boot"}`)...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEnvironment(); err == nil {
		t.Fatal("duplicate credential field accepted")
	}
}

func TestExportedStatusPublishesFasterByDefault(t *testing.T) {
	for role, want := range map[string]time.Duration{"boot": time.Second, "exported-status": exportInterval} {
		c := validCredentials()
		c.Role, c.Username = role, role
		prepared, err := (Config{Credentials: c}).prepared(role)
		if err != nil || prepared.Interval != want || prepared.StaleAfter != 3*time.Second {
			t.Fatalf("%s: interval %v stale %v err %v", role, prepared.Interval, prepared.StaleAfter, err)
		}
	}
	c := validCredentials()
	c.Role, c.Username = "exported-status", "exported-status"
	if prepared, err := (Config{Credentials: c, Interval: 500 * time.Millisecond}).prepared("exported-status"); err != nil || prepared.Interval != 500*time.Millisecond {
		t.Fatalf("explicit interval not kept: %v %v", prepared.Interval, err)
	}
}
