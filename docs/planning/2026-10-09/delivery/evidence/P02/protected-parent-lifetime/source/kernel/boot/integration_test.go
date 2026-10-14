package boot_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/controlLogix/agentmux/platform/kernel/boot"
	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/lifecycle"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/kernel/status"
	"github.com/nats-io/nats.go"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	url     string
	secrets communication.Credentials
	scope   protocol.Scope
	wire    protocol.SubjectSet
}

func setup(t *testing.T) fixture {
	t.Helper()
	binary := os.Getenv("AGENTMUX_TEST_NATS")
	if binary == "" {
		t.Fatal("prepared NATS executable required")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	secrets := communication.Credentials{}
	roles := protocol.Roles()
	names := append([]string{communication.Administrator, communication.OrdinaryPlugin}, roles[:]...)
	for _, name := range names {
		var value [24]byte
		if _, err := rand.Read(value[:]); err != nil {
			t.Fatal("fixture entropy unavailable")
		}
		secrets[name] = hex.EncodeToString(value[:])
	}
	config, err := communication.BuildConfig("fixture_hub", port, secrets)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	path := filepath.Join(dir, "private.json")
	os.WriteFile(path, config, 0600)
	log, err := os.OpenFile(filepath.Join(dir, "private.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-c", path)
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		t.Fatal("fixture broker startup failed")
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait(); log.Close() })
	url := "nats://127.0.0.1:" + strconv.Itoa(port)
	end := time.Now().Add(3 * time.Second)
	for time.Now().Before(end) {
		conn, err := nats.Connect(url, nats.UserInfo(communication.OrdinaryPlugin, secrets[communication.OrdinaryPlugin]), nats.NoReconnect(), nats.Timeout(100*time.Millisecond))
		if err == nil {
			conn.Close()
			s, _ := communication.Subjects("fixture_hub")
			return fixture{url, secrets, protocol.Scope{HubID: "fixture_hub", InstanceID: "fixture_instance", ProfileID: "fixture_profile", AssemblyDigest: "sha256:" + strings.Repeat("a", 64), ReleaseManifestDigest: "sha256:" + strings.Repeat("b", 64), ReleaseVersion: "1.0.0"}, protocol.SubjectSet{Commands: s.Commands, Events: s.Events, Snapshot: s.Snapshot, Update: s.Update}}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("fixture broker unavailable")
	return fixture{}
}
func (f fixture) client(t *testing.T, role string) *nats.Conn {
	t.Helper()
	conn, err := nats.Connect(f.url, nats.UserInfo(role, f.secrets[role]), nats.NoReconnect(), nats.Timeout(time.Second))
	if err != nil {
		t.Fatal("fixture connection failed")
	}
	t.Cleanup(conn.Close)
	return conn
}
func (f fixture) start(t *testing.T, role string) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	c := protocol.Config{Credentials: protocol.Credentials{SchemaVersion: protocol.Version, Role: role, Username: role, Password: f.secrets[role], NATSURL: f.url, Scope: f.scope}, Interval: 40 * time.Millisecond, StaleAfter: 160 * time.Millisecond}
	go func() {
		var err error
		switch role {
		case "boot":
			err = boot.Run(ctx, c, f.wire)
		case "kernel-lifecycle":
			err = lifecycle.Run(ctx, c, f.wire)
		case "internal-communication":
			err = communication.Run(ctx, c, f.wire)
		case "exported-status":
			err = status.Run(ctx, c, f.wire)
		}
		done <- err
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error("protected fixture actor failed:", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("actor did not finish within cleanup deadline")
		}
	})
	return cancel
}
func await(t *testing.T, sub *nats.Subscription, scope protocol.Scope, ready bool) protocol.Snapshot {
	t.Helper()
	end := time.Now().Add(3 * time.Second)
	for time.Now().Before(end) {
		msg, err := sub.NextMsg(500 * time.Millisecond)
		if err != nil {
			continue
		}
		snapshot, err := protocol.DecodeSnapshot(msg.Data, scope, time.Now(), 160*time.Millisecond)
		if err != nil {
			t.Fatal("exported snapshot violated codec")
		}
		if (snapshot.KernelReadiness == "ready") == ready {
			return snapshot
		}
	}
	t.Fatal("expected actual kernel observation not received")
	return protocol.Snapshot{}
}
func TestRealRolesLateSnapshotUpdatesAndPeerLoss(t *testing.T) {
	f := setup(t)
	cancels := map[string]context.CancelFunc{}
	for _, role := range protocol.Roles() {
		cancels[role] = f.start(t, role)
	}
	reader := f.client(t, communication.OrdinaryPlugin)
	sub, err := reader.SubscribeSync(f.wire.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	reader.FlushTimeout(time.Second)
	first := await(t, sub, f.scope, true)
	late := f.client(t, communication.OrdinaryPlugin)
	lateSub, err := late.SubscribeSync(f.wire.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	updates, err := late.SubscribeSync(f.wire.Update)
	if err != nil {
		t.Fatal(err)
	}
	late.FlushTimeout(time.Second)
	later := await(t, lateSub, f.scope, true)
	if later.Incarnation != first.Incarnation || later.Revision <= first.Revision {
		t.Fatal("late snapshot lost actor revision")
	}
	msg, err := updates.NextMsg(time.Second)
	if err != nil {
		t.Fatal("revisioned updates missing")
	}
	update, err := protocol.DecodeSnapshot(msg.Data, f.scope, time.Now(), 160*time.Millisecond)
	if err != nil || update.Incarnation != later.Incarnation {
		t.Fatal("update incarnation invalid")
	}
	cancels["internal-communication"]()
	lost := await(t, sub, f.scope, false)
	for _, member := range lost.Members {
		if member.Role == "internal-communication" && member.State == "ready" {
			t.Fatal("lost peer remained healthy")
		}
	}
}
func TestBootNeverReadyWithMissingProtectedPeer(t *testing.T) {
	f := setup(t)
	f.start(t, "boot")
	f.start(t, "kernel-lifecycle")
	f.start(t, "exported-status")
	reader := f.client(t, communication.OrdinaryPlugin)
	sub, _ := reader.SubscribeSync(f.wire.Snapshot)
	reader.FlushTimeout(time.Second)
	snapshot := await(t, sub, f.scope, false)
	// A broker-authenticated own-role publisher still cannot widen the instance/release context.
	attacker := f.client(t, "internal-communication")
	wrong := f.scope
	wrong.AssemblyDigest = "sha256:" + strings.Repeat("c", 64)
	event := protocol.Event{SchemaVersion: protocol.Version, Kind: "kernel-role-observation", Scope: wrong, Role: "internal-communication", Incarnation: strings.Repeat("a", 32), Revision: 1, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), State: "ready", ErrorCodes: []string{}, Members: []protocol.Member{}}
	bytes, _ := json.Marshal(event)
	if err := attacker.Publish(f.wire.Events["internal-communication"], bytes); err != nil {
		t.Fatal(err)
	}
	attacker.FlushTimeout(time.Second)
	if snapshot.KernelReadiness == "ready" {
		t.Fatal("missing peer boot accepted")
	}
	end := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(end) {
		event.Revision++
		event.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
		bytes, _ = json.Marshal(event)
		attacker.Publish(f.wire.Events["internal-communication"], bytes)
		attacker.FlushTimeout(time.Second)
		msg, err := sub.NextMsg(100 * time.Millisecond)
		if err == nil {
			var value protocol.Snapshot
			if json.Unmarshal(msg.Data, &value) != nil || value.KernelReadiness == "ready" {
				t.Fatal("absent peer invented readiness")
			}
			for _, member := range value.Members {
				if member.Role == "internal-communication" && member.State != "unknown" {
					t.Fatal("wrong-release peer was admitted")
				}
			}
		}
	}
}
