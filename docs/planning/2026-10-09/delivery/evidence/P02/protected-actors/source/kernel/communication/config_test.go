package communication

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func fixtureSecrets(t *testing.T) Credentials {
	t.Helper()
	c := Credentials{}
	for _, name := range append([]string{Administrator, OrdinaryPlugin}, roles[:]...) {
		var b [24]byte
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal("cannot prepare fixture secret")
		}
		c[name] = hex.EncodeToString(b[:])
	}
	return c
}

func TestConfigRejectsWidenedIdentityAndCredentials(t *testing.T) {
	c := fixtureSecrets(t)
	for _, hub := range []string{"", ">", "hub.*", "hub.with.dot", "../hub", "Hub", "hub\n"} {
		if _, err := BuildConfig(hub, 4222, c); err == nil {
			t.Fatalf("accepted invalid hub token %q", hub)
		}
	}
	for _, port := range []int{0, -1, 65536} {
		if _, err := BuildConfig("hub", port, c); err == nil {
			t.Fatal("accepted invalid listener")
		}
	}
	delete(c, "boot")
	if _, err := BuildConfig("hub", 4222, c); err == nil {
		t.Fatal("missing protected member accepted")
	}
	c = fixtureSecrets(t)
	c["extra"] = c["boot"]
	if _, err := BuildConfig("hub", 4222, c); err == nil {
		t.Fatal("extra member accepted")
	}
	c = fixtureSecrets(t)
	c[OrdinaryPlugin] = c["boot"]
	if _, err := BuildConfig("hub", 4222, c); err == nil {
		t.Fatal("shared identity secret accepted")
	}
}

func TestConfigContainsOnlyFixedAccountsAndExactExports(t *testing.T) {
	data, err := BuildConfig("fixture-hub", 4222, fixtureSecrets(t))
	if err != nil {
		t.Fatal(err)
	}
	var cfg configuration
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal("generated config invalid")
	}
	if cfg.Listen != "127.0.0.1:4222" || cfg.SystemAccount != SystemAccount || len(cfg.Accounts) != 3 {
		t.Fatal("unexpected listener/account layout")
	}
	if len(cfg.Accounts[ProtectedAccount].Users) != 4 || len(cfg.Accounts[ProtectedAccount].Exports) != 2 || len(cfg.Accounts[ApplicationAccount].Imports) != 2 {
		t.Fatal("unexpected protected membership/export layout")
	}
	if len(cfg.Accounts[SystemAccount].Exports) != 0 {
		t.Fatal("system account was exported")
	}
}

type brokerFixture struct {
	url     string
	secrets Credentials
}

func startBroker(t *testing.T) brokerFixture {
	t.Helper()
	binary := os.Getenv("AGENTMUX_TEST_NATS")
	if binary == "" {
		t.Fatal("AGENTMUX_TEST_NATS must identify the prepared disposable broker")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("cannot reserve fixture port")
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	secrets := fixtureSecrets(t)
	data, err := BuildConfig("fixture-hub", port, secrets)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "private-config.json")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal("cannot prepare private fixture config")
	}
	log, err := os.OpenFile(filepath.Join(dir, "private-broker.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-c", configPath)
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		log.Close()
		t.Fatal("fixture broker failed to start")
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); _ = log.Close() })
	url := listenerURL(port)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := nats.Connect(url, nats.UserInfo(Administrator, secrets[Administrator]), nats.Timeout(150*time.Millisecond), nats.NoReconnect())
		if err == nil {
			conn.Close()
			return brokerFixture{url, secrets}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("private fixture broker readiness failed; no configuration contents emitted")
	return brokerFixture{}
}

func listenerURL(port int) string { return "nats://127.0.0.1:" + strconv.Itoa(port) }

func (f brokerFixture) connect(t *testing.T, name string) (*nats.Conn, chan error) {
	t.Helper()
	events := make(chan error, 16)
	conn, err := nats.Connect(f.url, nats.UserInfo(name, f.secrets[name]), nats.NoReconnect(), nats.Timeout(time.Second), nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
		select {
		case events <- err:
		default:
		}
	}))
	if err != nil {
		t.Fatal("scoped fixture client could not connect")
	}
	t.Cleanup(conn.Close)
	return conn, events
}

func expectDenied(t *testing.T, conn *nats.Conn, events chan error) {
	t.Helper()
	if err := conn.FlushTimeout(time.Second); err != nil {
		t.Fatal("fixture flush failed")
	}
	select {
	case err := <-events:
		if !strings.Contains(strings.ToLower(err.Error()), "permissions violation") {
			t.Fatal("expected broker permission rejection")
		}
	case <-time.After(time.Second):
		t.Fatal("broker accepted forbidden operation")
	}
}

func TestRealBrokerStatusExportsAndProtectedRolePermissions(t *testing.T) {
	f := startBroker(t)
	s, _ := Subjects("fixture-hub")
	app, appErrors := f.connect(t, OrdinaryPlugin)
	status, statusErrors := f.connect(t, "exported-status")
	boot, _ := f.connect(t, "boot")
	for _, subject := range []string{s.Snapshot, s.Update} {
		sub, err := app.SubscribeSync(subject)
		if err != nil {
			t.Fatal(err)
		}
		if err := app.FlushTimeout(time.Second); err != nil {
			t.Fatal(err)
		}
		if err := status.Publish(subject, []byte("fixture-observation")); err != nil {
			t.Fatal(err)
		}
		if err := status.FlushTimeout(time.Second); err != nil {
			t.Fatal(err)
		}
		msg, err := sub.NextMsg(time.Second)
		if err != nil || string(msg.Data) != "fixture-observation" {
			t.Fatal("permitted exported status did not cross accounts")
		}
		sub.Unsubscribe()
	}
	select {
	case <-appErrors:
		t.Fatal("permitted application status denied")
	default:
	}
	select {
	case <-statusErrors:
		t.Fatal("permitted status publication denied")
	default:
	}
	for _, role := range roles {
		member, _ := f.connect(t, role)
		sub, err := member.SubscribeSync(s.Commands[role])
		if err != nil {
			t.Fatal(err)
		}
		member.FlushTimeout(time.Second)
		boot.Publish(s.Commands[role], []byte("fixture-command"))
		boot.FlushTimeout(time.Second)
		if _, err := sub.NextMsg(time.Second); err != nil {
			t.Fatal("protected command did not reach exact member")
		}
		events, err := status.SubscribeSync(s.Events[role])
		if err != nil {
			t.Fatal(err)
		}
		status.FlushTimeout(time.Second)
		member.Publish(s.Events[role], []byte("fixture-event"))
		member.FlushTimeout(time.Second)
		if _, err := events.NextMsg(time.Second); err != nil {
			t.Fatal("protected member event was denied")
		}
		events.Unsubscribe()
		sub.Unsubscribe()
	}
}

func TestRealBrokerOrdinaryPublishSubscribeAndRequestDenials(t *testing.T) {
	f := startBroker(t)
	s, _ := Subjects("fixture-hub")
	publish := []string{s.Snapshot, s.Update, s.Commands["boot"], s.Events["boot"], "$SYS.REQ.SERVER.PING", "$JS.API.STREAM.CREATE.FORGED", "$JS.API.CONSUMER.CREATE.FORGED", "_INBOX.forged"}
	for _, subject := range publish {
		t.Run("publish-"+subject, func(t *testing.T) {
			conn, events := f.connect(t, OrdinaryPlugin)
			if err := conn.Publish(subject, []byte("forbidden")); err != nil {
				t.Fatal("client failed before broker admission")
			}
			expectDenied(t, conn, events)
		})
	}
	subscribe := []string{">", "amx.v1.h.fixture-hub.kernel.>", "amx.v1.h.fixture-hub.kernel.status.*", s.Commands["boot"], s.Events["boot"], "$SYS.>", "$JS.>", "_INBOX.>", "amx.v1.h.other.kernel.status.snapshot"}
	for _, subject := range subscribe {
		t.Run("subscribe-"+subject, func(t *testing.T) {
			conn, events := f.connect(t, OrdinaryPlugin)
			if _, err := conn.SubscribeSync(subject); err != nil {
				t.Fatal("client failed before broker admission")
			}
			expectDenied(t, conn, events)
		})
	}
	conn, events := f.connect(t, OrdinaryPlugin)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := conn.RequestWithContext(ctx, s.Snapshot, nil); err == nil {
		t.Fatal("ordinary request unexpectedly succeeded")
	}
	expectDenied(t, conn, events)
}

func TestRealBrokerProtectedRolesCannotForgeOrManage(t *testing.T) {
	f := startBroker(t)
	s, _ := Subjects("fixture-hub")
	for _, role := range roles {
		forbidden := []string{"$SYS.REQ.SERVER.PING", "$JS.API.STREAM.CREATE.FORGED"}
		if role != "exported-status" {
			forbidden = append(forbidden, s.Snapshot, s.Update)
		}
		if role != "boot" && role != "kernel-lifecycle" {
			forbidden = append(forbidden, s.Commands["boot"])
		}
		for _, subject := range forbidden {
			t.Run(role+"-"+subject, func(t *testing.T) {
				conn, events := f.connect(t, role)
				conn.Publish(subject, nil)
				expectDenied(t, conn, events)
			})
		}
	}
	conn, events := f.connect(t, Administrator)
	conn.SubscribeSync(s.Snapshot)
	expectDenied(t, conn, events)
	for _, name := range append([]string{OrdinaryPlugin}, roles[:]...) {
		if _, err := nats.Connect(f.url, nats.UserInfo(name, f.secrets[Administrator]), nats.NoReconnect(), nats.Timeout(time.Second)); err == nil {
			t.Fatal("system secret authenticated as ordinary/protected identity")
		}
	}
}

func TestListenerModeRequiresExplicitSelection(t *testing.T) {
	for _, mode := range []ListenerMode{"", "ambient", "remote"} {
		if _, err := BuildConfigWithListener("hub", Listener{Mode: mode, Port: 4222}, fixtureSecrets(t)); err == nil {
			t.Fatal("invalid listener mode accepted")
		}
	}
	for _, mode := range []ListenerMode{NativeLoopback, ContainerInternal} {
		data, err := BuildConfigWithListener("hub", Listener{Mode: mode, Port: 4222}, fixtureSecrets(t))
		if err != nil {
			t.Fatal(err)
		}
		var cfg configuration
		if err := json.Unmarshal(data, &cfg); err != nil {
			t.Fatal(err)
		}
		want := "127.0.0.1:4222"
		if mode == ContainerInternal {
			want = "0.0.0.0:4222"
		}
		if cfg.Listen != want || len(cfg.Accounts) != 3 {
			t.Fatal("listener selection changed authentication or binding")
		}
		if strings.Contains(string(data), `\u003e`) {
			t.Fatal("config escaped NATS wildcards with unsupported Unicode syntax")
		}
	}
	c := fixtureSecrets(t)
	c[OrdinaryPlugin] = strings.Repeat("x", 32) + "\x01"
	if _, err := BuildConfig("hub", 4222, c); err == nil {
		t.Fatal("unsafe secret syntax accepted")
	}
}

func TestRealBrokerReadManagementAndOtherCommandDenials(t *testing.T) {
	f := startBroker(t)
	s, _ := Subjects("fixture-hub")
	for _, role := range roles {
		other := "boot"
		if role == "boot" {
			other = "exported-status"
		}
		for _, subject := range []string{"$SYS.>", "$JS.>", s.Commands[other]} {
			t.Run(role+"-read-"+subject, func(t *testing.T) {
				conn, events := f.connect(t, role)
				conn.SubscribeSync(subject)
				expectDenied(t, conn, events)
			})
		}
	}
	admin, _ := f.connect(t, Administrator)
	if _, err := admin.Request("$SYS.REQ.SERVER.PING", nil, time.Second); err != nil {
		t.Fatal("separate administrator cannot use broker monitoring")
	}
}

func TestRealBrokerForgeryCannotReachStatusSubscriber(t *testing.T) {
	f := startBroker(t)
	s, _ := Subjects("fixture-hub")
	reader, _ := f.connect(t, OrdinaryPlugin)
	sub, err := reader.SubscribeSync(s.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	reader.FlushTimeout(time.Second)
	publisher, _ := f.connect(t, "exported-status")
	publisher.Publish(s.Snapshot, []byte("legitimate-control"))
	publisher.FlushTimeout(time.Second)
	msg, err := sub.NextMsg(time.Second)
	if err != nil || string(msg.Data) != "legitimate-control" {
		t.Fatal("forgery oracle lacks positive status delivery")
	}
	attacker, events := f.connect(t, OrdinaryPlugin)
	attacker.Publish(s.Snapshot, []byte("forged-observation"))
	expectDenied(t, attacker, events)
	if msg, err := sub.NextMsg(100 * time.Millisecond); err != nats.ErrTimeout || msg != nil {
		t.Fatal("forged observation reached authorized subscriber")
	}
}
