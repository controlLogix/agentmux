//go:build linux || darwin

package boot_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/boot"
	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/lifecycle"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/kernel/status"
	"github.com/controlLogix/agentmux/platform/localtls"
	"github.com/nats-io/nats.go"
)

const recoveryInterval = 40 * time.Millisecond
const recoveryStaleAfter = 160 * time.Millisecond

// Open currently permits ten reconnects, each with a one-second connection
// timeout, a 200ms wait and the SDK's default one-second TLS jitter.
// This observation bound includes one actor tick and scheduling allowance; it
// does not change any actor option or extend its reconnect budget.
const recoveryTerminalBound = 24 * time.Second

type recoveryRole struct {
	done chan struct{}
	err  error // Read only after done closes.
}

type recoveryFixture struct {
	t                        *testing.T
	binary, config, endpoint string
	trust                    *localtls.ClientTrust
	scope                    protocol.Scope
	wire                     protocol.SubjectSet
	secrets                  communication.Credentials
	broker                   *exec.Cmd
	brokerDone               chan error
	log                      *os.File
	roles                    map[string]*recoveryRole
	trap                     net.Listener
	trapDone                 chan struct{}
	trapConnections          atomic.Int32
}

// This fixture extends the real boot-role test with the same TLS-first leaf
// pinning used by TestRealActorUsesPinnedTLSFirstAndReconnectsOnlyToEnrolledEndpoint.
// It keeps BuildConfig's account permissions and exported subjects intact.
func newRecoveryFixture(t *testing.T) *recoveryFixture {
	t.Helper()
	f := &recoveryFixture{t: t, binary: os.Getenv("AGENTMUX_TEST_NATS"), roles: map[string]*recoveryRole{}}
	if f.binary == "" {
		t.Fatal("prepared NATS 2.15.0 executable required")
	}
	// Keep source pins and actual public observations in the test event stream.
	// These pins cover this fixture and the directly exercised role/transport
	// sources; they are not an attestation for the complete product candidate.
	for _, path := range []string{"broker_recovery_test.go", "run.go", "../lifecycle/run.go", "../communication/run.go", "../communication/config.go", "../status/run.go", "../protocol/transport.go", "../protocol/codec.go", "../protocol/credentials.go", "../protocol/server_trust.go", "../../localtls/client.go"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("recovery source pin unavailable")
		}
		pin := sha256.Sum256(raw)
		t.Logf("recovery source sha256 %s %x", path, pin)
		t.Cleanup(func() {
			current, err := os.ReadFile(path)
			if err != nil || sha256.Sum256(current) != pin {
				t.Errorf("recovery source changed during execution: %s", path)
			}
		})
	}
	directory := t.TempDir()
	if evidence := os.Getenv("AGENTMUX_BROKER_RECOVERY_EVIDENCE"); evidence != "" {
		var err error
		directory, err = os.MkdirTemp(evidence, "private-broker-")
		if err != nil {
			t.Fatal("private recovery evidence directory unavailable")
		}
		// This explicit private evidence destination retains the exact broker
		// config, TLS material and joined log on failure as well as success.
		t.Logf("private recovery broker artifacts: %s", directory)
	}
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("private recovery directory unavailable")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("recovery port unavailable")
	}
	address := listener.Addr().(*net.TCPAddr)
	f.endpoint = "tls://" + address.String()
	if listener.Close() != nil {
		t.Fatal("recovery port reservation close failed")
	}
	f.scope = protocol.Scope{HubID: "recovery_hub", InstanceID: "recovery_instance", ProfileID: "recovery_profile", AssemblyDigest: "sha256:" + strings.Repeat("a", 64), ReleaseManifestDigest: "sha256:" + strings.Repeat("b", 64), ReleaseVersion: "1.0.0"}
	f.secrets = communication.Credentials{}
	roles := protocol.Roles()
	for _, name := range append([]string{communication.Administrator, communication.OrdinaryPlugin}, roles[:]...) {
		var secret [24]byte
		if _, err := rand.Read(secret[:]); err != nil {
			t.Fatal("recovery credential entropy unavailable")
		}
		f.secrets[name] = hex.EncodeToString(secret[:])
	}
	raw, err := communication.BuildConfig(f.scope.HubID, address.Port, f.secrets)
	if err != nil {
		t.Fatal("recovery account configuration refused")
	}
	var document map[string]any
	if json.Unmarshal(raw, &document) != nil {
		t.Fatal("recovery configuration decode failed")
	}
	subjects, err := communication.Subjects(f.scope.HubID)
	if err != nil {
		t.Fatal("recovery subjects refused")
	}
	f.wire = protocol.SubjectSet{Commands: subjects.Commands, Events: subjects.Events, Snapshot: subjects.Snapshot, Update: subjects.Update}
	certPath, keyPath := filepath.Join(directory, "cert.pem"), filepath.Join(directory, "key.pem")
	f.trust = recoveryTrust(t, f.scope, f.endpoint, certPath, keyPath)
	f.trap, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("owned alternate-endpoint trap unavailable")
	}
	f.trapDone = make(chan struct{})
	go func() {
		defer close(f.trapDone)
		for {
			connection, err := f.trap.Accept()
			if err != nil {
				return
			}
			f.trapConnections.Add(1)
			connection.Close()
		}
	}()
	t.Cleanup(func() {
		f.stopBroker()
		f.trap.Close()
		select {
		case <-f.trapDone:
		case <-time.After(time.Second):
			t.Error("alternate-endpoint trap did not join")
		}
		if f.trapConnections.Load() != 0 {
			t.Error("an actor or observer contacted an unenrolled advertised endpoint")
		}
		if f.broker != nil {
			t.Error("private broker log retained with unjoined owned broker")
		} else if f.log != nil && f.log.Close() != nil {
			t.Error("private broker log close failed")
		}
	})
	document["server_name"] = "recovery_server"
	document["client_advertise"] = f.trap.Addr().String()
	document["tls"] = map[string]any{"cert_file": certPath, "key_file": keyPath, "min_version": "1.3", "handshake_first": true}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	// NATS accepts the original UTF-8 JSON subjects, not HTML/Unicode escapes.
	encoder.SetEscapeHTML(false)
	err = encoder.Encode(document)
	f.config = filepath.Join(directory, "nats.json")
	if err != nil || os.WriteFile(f.config, encoded.Bytes(), 0600) != nil {
		t.Fatal("private TLS recovery configuration unavailable")
	}
	f.log, err = os.OpenFile(filepath.Join(directory, "broker.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal("private recovery broker log unavailable")
	}
	f.startBroker()
	// Probe readiness before starting roles; an unavailable initial broker is
	// fixture failure, not reconnect or protected-role recovery evidence.
	reader, closeReader := f.reader(time.Now().Add(3 * time.Second))
	if reader.ConnectedServerVersion() != "2.15.0" {
		t.Fatal("recovery broker is not the prepared NATS 2.15.0")
	}
	closeReader()
	t.Logf("actual local recovery host: GOOS=%s GOARCH=%s; in-process protected roles, not installed CLI qualification", runtime.GOOS, runtime.GOARCH)
	return f
}

func recoveryTrust(t *testing.T, scope protocol.Scope, endpoint, certPath, keyPath string) *localtls.ClientTrust {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("recovery CA key unavailable")
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal("recovery CA unavailable")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("recovery leaf key unavailable")
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), DNSNames: []string{"recovery.agentmux.invalid"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal("recovery leaf unavailable")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil || os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0600) != nil || os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600) != nil {
		t.Fatal("private recovery TLS material unavailable")
	}
	leafHash := sha256.Sum256(leafDER)
	trust, err := protocol.ValidateServerTrustRecord(protocol.ServerTrustRecord{SchemaVersion: protocol.Version, Endpoint: endpoint, ServerName: "recovery.agentmux.invalid", RootsPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), LeafCertificateSHA256: "sha256:" + hex.EncodeToString(leafHash[:]), Scope: scope}, scope, endpoint)
	if err != nil {
		t.Fatal("scoped recovery TLS trust refused")
	}
	return trust
}

func (f *recoveryFixture) startBroker() {
	f.t.Helper()
	if f.broker != nil {
		f.t.Fatal("recovery fixture attempted duplicate broker start")
	}
	command := exec.Command(f.binary, "-c", f.config)
	command.Stdout, command.Stderr = f.log, f.log
	if command.Start() != nil {
		f.t.Fatal("actual recovery TLS broker start failed")
	}
	f.broker, f.brokerDone = command, make(chan error, 1)
	done := f.brokerDone
	go func() { done <- command.Wait() }()
}

func (f *recoveryFixture) stopBroker() {
	if f.broker == nil {
		return
	}
	command, done := f.broker, f.brokerDone
	joined := func(err error) {
		// Only the original Wait result releases this concrete owner. A timeout
		// leaves both handles available for cleanup retry and blocks startBroker.
		f.broker = nil
		f.brokerDone = nil
		f.t.Log("owned recovery broker Wait joined; terminal ownership cleared")
		if err != nil {
			f.t.Error("owned recovery broker exited unsuccessfully")
		}
	}
	select {
	case err := <-done:
		joined(err)
		return
	default:
	}
	signalErr := command.Process.Signal(os.Interrupt)
	select {
	case err := <-done:
		joined(err)
	case <-time.After(time.Second):
		killErr := command.Process.Kill()
		select {
		case err := <-done:
			joined(err)
		case <-time.After(time.Second):
			f.t.Error("owned recovery broker did not join after kill; concrete owner retained")
		}
		if killErr != nil {
			f.t.Error("owned recovery broker kill failed")
		}
		f.t.Error("owned recovery broker required forced shutdown")
	}
	if signalErr != nil {
		f.t.Error("owned recovery broker interrupt failed")
	}
}

func (f *recoveryFixture) reader(deadline time.Time) (*nats.Conn, func()) {
	f.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	dialer, err := f.trust.NewDialer(ctx, 100*time.Millisecond)
	if err != nil {
		cancel()
		f.t.Fatal("recovery observer trust refused")
	}
	var reader *nats.Conn
	for time.Now().Before(deadline) {
		reader, err = nats.Connect(f.endpoint, nats.UserInfo(communication.OrdinaryPlugin, f.secrets[communication.OrdinaryPlugin]), nats.TLSHandshakeFirst(), nats.SetCustomDialer(dialer), nats.NoReconnect(), nats.IgnoreDiscoveredServers(), nats.Timeout(100*time.Millisecond))
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	closeReader := func() {
		if reader != nil {
			reader.Close()
		}
		if dialer.Close() != nil {
			f.t.Error("owned recovery observer TLS cleanup failed")
		}
		cancel()
	}
	if err != nil || reader == nil {
		closeReader()
		// Join the actual broker output writer before reporting setup failure.
		f.stopBroker()
		f.t.Fatal("actual pinned TLS recovery observer unavailable")
	}
	state, err := reader.TLSConnectionState()
	if err != nil || state.Version != tls.VersionTLS13 || reader.ConnectedUrl() != f.endpoint || len(reader.DiscoveredServers()) != 0 {
		closeReader()
		f.t.Fatal("recovery observer used unexpected TLS or endpoint")
	}
	return reader, closeReader
}

func (f *recoveryFixture) startRoles() {
	f.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	f.t.Cleanup(func() {
		cancel()
		for role, run := range f.roles {
			select {
			case <-run.done:
			case <-time.After(2 * time.Second):
				f.t.Errorf("protected role %s did not join", role)
			}
		}
	})
	for _, role := range protocol.Roles() {
		config := protocol.Config{Credentials: protocol.Credentials{SchemaVersion: protocol.Version, Role: role, Username: role, Password: f.secrets[role], NATSURL: f.endpoint, Scope: f.scope}, ServerTrust: f.trust, Interval: recoveryInterval, StaleAfter: recoveryStaleAfter}
		run := &recoveryRole{done: make(chan struct{})}
		f.roles[role] = run
		go func() {
			defer close(run.done)
			switch role {
			case "boot":
				run.err = boot.Run(ctx, config, f.wire)
			case "kernel-lifecycle":
				run.err = lifecycle.Run(ctx, config, f.wire)
			case "internal-communication":
				run.err = communication.Run(ctx, config, f.wire)
			case "exported-status":
				run.err = status.Run(ctx, config, f.wire)
			}
		}()
	}
}

func (f *recoveryFixture) liveRoles() {
	f.t.Helper()
	for role, run := range f.roles {
		select {
		case <-run.done:
			f.t.Fatalf("protected role %s exited before recovery: %v", role, run.err)
		default:
		}
	}
}

func (f *recoveryFixture) snapshotReader(deadline time.Time) (*nats.Subscription, func()) {
	f.t.Helper()
	reader, closeReader := f.reader(deadline)
	sub, err := reader.SubscribeSync(f.wire.Snapshot)
	if err != nil || reader.FlushTimeout(time.Second) != nil {
		closeReader()
		f.t.Fatal("recovery scoped snapshot subscription unavailable")
	}
	return sub, closeReader
}

func (f *recoveryFixture) ready(sub *nats.Subscription, deadline time.Time, after time.Time) (protocol.Snapshot, []byte) {
	f.t.Helper()
	for time.Now().Before(deadline) {
		f.liveRoles()
		message, err := sub.NextMsg(100 * time.Millisecond)
		if err != nil {
			continue
		}
		snapshot, err := protocol.DecodeSnapshot(message.Data, f.scope, time.Now(), recoveryStaleAfter)
		if err != nil {
			f.t.Fatal("actual recovery snapshot violated scope or freshness")
		}
		if snapshot.KernelReadiness != "ready" {
			continue
		}
		members := map[string]bool{}
		for _, member := range snapshot.Members {
			observed, err := time.Parse(time.RFC3339Nano, member.ObservedAt)
			if err != nil || observed.Before(after) || member.State != "ready" || member.Incarnation == "" || members[member.Role] {
				f.t.Fatal("ready recovery snapshot retained stale or duplicate members")
			}
			members[member.Role] = true
		}
		if len(members) != len(protocol.Roles()) {
			f.t.Fatal("ready recovery snapshot omitted protected roles")
		}
		// Retain actual public event bytes in go test -json, not a reconstructed
		// event or broker logs/configuration containing private credentials.
		f.t.Logf("actual scoped TLS snapshot: %s", message.Data)
		return snapshot, append([]byte(nil), message.Data...)
	}
	f.t.Fatal("protected roles did not restore fresh ready snapshots within existing reconnect budget")
	return protocol.Snapshot{}, nil
}

func TestProtectedRolesTLSBrokerRecoveryPreservesIncarnations(t *testing.T) {
	f := newRecoveryFixture(t)
	f.startRoles()
	sub, closeReader := f.snapshotReader(time.Now().Add(3 * time.Second))
	before, raw := f.ready(sub, time.Now().Add(3*time.Second), time.Time{})
	closeReader()
	f.stopBroker()
	lostAt := time.Now()
	// Remain disconnected longer than the accepted freshness window, but well
	// within the unmodified reconnect budget. No clock or broker is mocked.
	time.Sleep(recoveryStaleAfter + 80*time.Millisecond)
	if _, err := protocol.DecodeSnapshot(raw, f.scope, time.Now(), recoveryStaleAfter); err == nil {
		t.Fatal("last healthy snapshot remained admissible after actual broker loss")
	}
	f.liveRoles()
	restartedAt := time.Now()
	f.startBroker()
	sub, closeReader = f.snapshotReader(lostAt.Add(recoveryTerminalBound))
	defer closeReader()
	after, _ := f.ready(sub, lostAt.Add(recoveryTerminalBound), restartedAt)
	if after.Incarnation != before.Incarnation || after.Revision <= before.Revision {
		t.Fatal("broker recovery replaced the status actor or replayed its revision")
	}
	checkContinuity := func(previous, current protocol.Snapshot) {
		t.Helper()
		if current.Incarnation != previous.Incarnation || current.Revision <= previous.Revision {
			t.Fatal("broker recovery replaced the status actor or replayed its revision")
		}
		old := map[string]protocol.Member{}
		for _, member := range previous.Members {
			old[member.Role] = member
		}
		for _, member := range current.Members {
			previous, ok := old[member.Role]
			if !ok || member.Incarnation != previous.Incarnation || member.Revision < previous.Revision {
				t.Fatal("broker recovery duplicated/replaced a protected role or replayed its revision")
			}
		}
	}
	checkContinuity(before, after)
	for _, member := range after.Members {
		for _, previous := range before.Members {
			if member.Role == previous.Role && member.Revision <= previous.Revision {
				t.Fatal("recovered ready snapshot did not advance every protected role")
			}
		}
	}
	// Observe several subsequent full snapshots, rather than accepting a single
	// transient recovery frame while another incarnation is publishing.
	for i := 0; i < 4; i++ {
		next, _ := f.ready(sub, lostAt.Add(recoveryTerminalBound), restartedAt)
		checkContinuity(after, next)
		after = next
	}
	f.liveRoles()
	t.Logf("same enrolled TLS endpoint recovered in %s after broker loss", time.Since(lostAt))
}

func TestProtectedRolesTLSBrokerReconnectExhaustionIsBounded(t *testing.T) {
	f := newRecoveryFixture(t)
	f.startRoles()
	sub, closeReader := f.snapshotReader(time.Now().Add(3 * time.Second))
	_, raw := f.ready(sub, time.Now().Add(3*time.Second), time.Time{})
	closeReader()
	f.stopBroker()
	lostAt := time.Now()
	deadline := lostAt.Add(recoveryTerminalBound)
	for role, run := range f.roles {
		timer := time.NewTimer(time.Until(deadline))
		select {
		case <-run.done:
			timer.Stop()
			if run.err == nil || run.err.Error() != "kernel_broker_unavailable" {
				t.Fatalf("role %s did not report terminal broker exhaustion: %v", role, run.err)
			}
		case <-timer.C:
			t.Fatalf("role %s outlived the existing reconnect budget", role)
		}
	}
	if _, err := protocol.DecodeSnapshot(raw, f.scope, time.Now(), recoveryStaleAfter); err == nil {
		t.Fatal("exhausted roles retained an admissible healthy snapshot")
	}
	t.Logf("all four TLS roles reported bounded broker exhaustion in %s", time.Since(lostAt))
}
