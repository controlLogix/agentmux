//go:build linux || darwin

package deployment

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/nats-io/nats.go"
)

func teamBasicPrivateTempDir(t *testing.T) string {
	t.Helper()
	privateTempDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(privateTempDir, 0700) != nil {
		t.Fatal("private fixture directory unavailable")
	}
	return privateTempDir
}

func teamBasicResolver(t *testing.T, policy TeamConnectionPolicy, username, password string) (*PrivateTeamCredentialResolver, func(string)) {
	t.Helper()
	privateTempDir := teamBasicPrivateTempDir(t)
	workspace, err := filepath.Abs(".")
	if err != nil {
		t.Fatal("fixture workspace unavailable")
	}
	resolver, err := NewPrivateTeamCredentialResolver(TeamPrivateCredentialPolicy{
		Directory: privateTempDir, OwnerUID: uint32(os.Geteuid()), WorkspaceRoots: []string{workspace},
		Reference: policy.CredentialRef, Scope: policy.Scope,
	})
	if err != nil {
		t.Fatal("explicit private credential policy rejected")
	}
	write := func(selectedPassword string) {
		t.Helper()
		raw, err := json.Marshal(teamCredentialDocument{SchemaVersion: "1.0.0", Reference: policy.CredentialRef,
			Scope: policy.Scope, Username: username, Password: selectedPassword})
		if err != nil || os.WriteFile(filepath.Join(privateTempDir, policy.CredentialRef.ID+".json"), raw, 0600) != nil {
			t.Fatal("private basic credential file write failed")
		}
	}
	write(password)
	return resolver, write
}

func teamBasicNoDisclosure(t *testing.T, out TeamConnectionObservation, err error, private ...string) {
	t.Helper()
	raw, marshalErr := json.Marshal(out)
	if marshalErr != nil {
		t.Fatal("observation encoding failed")
	}
	text := string(raw)
	if err != nil {
		text += err.Error()
	}
	for _, value := range private {
		if value != "" && strings.Contains(text, value) {
			t.Fatal("observation or failure code exposed private fixture material")
		}
	}
}

type teamBasicFixture struct {
	policy    TeamConnectionPolicy
	password  string
	publisher *nats.Conn
}

func newTeamBasicFixture(t *testing.T) *teamBasicFixture {
	t.Helper()
	binary := os.Getenv("AGENTMUX_TEST_NATS")
	if binary == "" {
		t.Fatal("prepared disposable NATS executable required")
	}
	privateTempDir := teamBasicPrivateTempDir(t)
	roots, tlsConfig := jwtWorkerTLS(t, privateTempDir)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("owned fixture port unavailable")
	}
	port := listener.Addr().(*net.TCPAddr).Port
	address := listener.Addr().String()
	if listener.Close() != nil {
		t.Fatal("owned fixture port could not be released")
	}
	credentials, healthPassword := deploymentSecrets(t)
	f := &teamBasicFixture{policy: teamTestPolicy(t), password: credentials[communication.OrdinaryPlugin]}
	f.policy.Endpoint, f.policy.TLSRootsPEM = "tls://"+address, roots
	f.policy.Timeout = 2 * time.Second
	profile := StorageProfile{HubID: f.policy.Scope.Kernel.HubID, ServerName: f.policy.ExpectedServerName,
		Domain: f.policy.ExpectedDomain, StoreDirectory: filepath.Join(privateTempDir, "store"),
		MaxMemoryBytes: 1024 * 1024, MaxFileBytes: 4 * 1024 * 1024,
		Listener: communication.Listener{Mode: communication.NativeLoopback, Port: port}}
	raw, err := BuildLocalConfig(profile, credentials, healthPassword)
	if err != nil {
		t.Fatal("protected fixture broker configuration rejected")
	}
	var config map[string]any
	if json.Unmarshal(raw, &config) != nil {
		t.Fatal("protected fixture broker configuration invalid")
	}
	// Only add TLS. KERNEL exports and APPLICATION imports/ACLs remain unchanged.
	config["tls"] = map[string]any{"cert_file": filepath.Join(privateTempDir, "server.pem"),
		"key_file": filepath.Join(privateTempDir, "server-key.pem"), "timeout": 1}
	path := filepath.Join(privateTempDir, "nats.json")
	if os.WriteFile(path, fixtureConfigJSON(t, config), 0600) != nil {
		t.Fatal("private broker configuration write failed")
	}
	cmd := exec.Command(binary, "-c", path)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	done := make(chan struct{})
	started := false
	// Register ownership cleanup before starting the broker or publisher.
	t.Cleanup(func() {
		if !started {
			return
		}
		select {
		case <-done:
			return
		default:
		}
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-done:
			return
		case <-time.After(3 * time.Second):
		}
		_ = cmd.Process.Kill()
		select {
		case <-done:
			t.Error("owned fixture broker required forced cleanup")
		case <-time.After(2 * time.Second):
			t.Error("owned fixture broker did not join")
		}
	})
	t.Cleanup(func() {
		if f.publisher != nil {
			f.publisher.Close()
		}
	})
	if cmd.Start() != nil {
		t.Fatal("owned basic TLS broker start failed")
	}
	started = true
	go func() { _ = cmd.Wait(); close(done) }()
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		nc, err := nats.Connect(f.policy.Endpoint, nats.Secure(tlsConfig.Clone()),
			nats.UserInfo("exported-status", credentials["exported-status"]), nats.NoReconnect(),
			nats.IgnoreDiscoveredServers(), nats.Timeout(100*time.Millisecond))
		if err == nil {
			f.publisher = nc
			if nc.ConnectedServerName() != f.policy.ExpectedServerName || nc.ConnectedServerVersion() != "2.15.0" {
				t.Fatal("prepared broker version or server identity mismatch")
			}
			return f
		}
		select {
		case <-done:
			t.Fatal("owned basic TLS broker exited before readiness")
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatal("owned basic TLS broker readiness exceeded its budget")
	return nil
}

func (f *teamBasicFixture) publish(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done, fault := make(chan struct{}), make(chan struct{}, 1)
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("owned basic snapshot publisher did not join")
		}
		select {
		case <-fault:
			t.Error("owned basic snapshot publication failed")
		default:
		}
	})
	wire, err := communication.Subjects(f.policy.Scope.Kernel.HubID)
	if err != nil {
		t.Fatal("fixture snapshot subject invalid")
	}
	go func() {
		defer close(done)
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			now := time.Now().UTC()
			members := []protocol.Member{}
			for _, role := range protocol.Roles() {
				members = append(members, protocol.Member{Role: role, State: "ready", Incarnation: strings.Repeat("a", 32),
					Revision: 1, ObservedAt: now.Format(time.RFC3339Nano)})
			}
			frame := protocol.Snapshot{SchemaVersion: protocol.Version, Kind: "kernel-info", Scope: f.policy.Scope.Kernel,
				Role: "exported-status", Incarnation: strings.Repeat("a", 32), Revision: 1,
				ObservedAt: now.Format(time.RFC3339Nano), ValidUntil: now.Add(3 * time.Second).Format(time.RFC3339Nano),
				KernelReadiness: "ready", Members: members}
			raw, err := json.Marshal(frame)
			if err != nil || f.publisher.Publish(wire.Snapshot, raw) != nil {
				fault <- struct{}{}
				return
			}
		}
	}()
}

func TestTeamBasicRealTLSPrivateResolverAndScopedSnapshot(t *testing.T) {
	f := newTeamBasicFixture(t)
	f.publish(t)
	resolver, write := teamBasicResolver(t, f.policy, communication.OrdinaryPlugin, f.password)
	for _, mode := range []string{"valid", "wrong-password", "restored", "info-unavailable", "wrong-hostname", "wrong-trust"} {
		t.Run(mode, func(t *testing.T) {
			policy := f.policy
			write(f.password)
			badPassword := strings.Repeat("x", 48)
			switch mode {
			case "wrong-password":
				write(badPassword)
			case "info-unavailable":
				policy.ObserveDomain = true
			case "wrong-hostname":
				policy.TLSServerName = "unselected.example.test"
			case "wrong-trust":
				policy.TLSRootsPEM = teamTestPolicy(t).TLSRootsPEM
			}
			connection, err := NewTeamConnection(policy, resolver)
			if err != nil {
				t.Fatal("explicit basic TLS policy admission failed")
			}
			out, err := connection.Observe(context.Background())
			teamBasicNoDisclosure(t, out, err, f.password, badPassword, communication.OrdinaryPlugin, policy.Endpoint,
				resolver.policy.Directory)
			if mode == "wrong-password" || mode == "wrong-hostname" || mode == "wrong-trust" {
				if err == nil || err.Error() != "team_authentication_or_connection_unavailable" || out.TLSVerified || out.Authenticated ||
					out.ServerIdentityVerified || out.BrokerVerified || out.Snapshot != nil || out.ServerName != "" || out.ServerVersion != "" {
					t.Fatal("invalid basic authentication or TLS produced trusted facts")
				}
				return
			}
			if err != nil || !out.TLSVerified || !out.Authenticated || !out.ServerIdentityVerified || out.ServerName != policy.ExpectedServerName ||
				out.ServerVersion != "2.15.0" || out.Snapshot == nil || out.Snapshot.Scope != policy.Scope.Kernel ||
				out.KernelAvailability != "available" || out.Code != "read_only_observed" {
				t.Logf("basic observation: mode=%s error=%v code=%s TLS=%t auth=%t server=%t domain=%s kernel=%s snapshot=%t",
					mode, err, out.Code, out.TLSVerified, out.Authenticated, out.ServerIdentityVerified,
					out.DomainAvailability, out.KernelAvailability, out.Snapshot != nil)
				t.Fatal("protected exported status did not reach the scoped basic receiver")
			}
			// APPLICATION has no domain INFO permission. Its absence cannot erase the
			// independently authenticated TLS, server identity or snapshot evidence.
			if out.BrokerVerified || out.DomainAvailability != "unavailable" || out.Domain != "" {
				t.Fatal("unavailable domain INFO became invented domain evidence")
			}
		})
	}
}

func TestTeamBasicCallerCancellationAndEarlierDeadlineDuringSetup(t *testing.T) {
	for _, handshake := range []bool{false, true} {
		for _, earlier := range []bool{false, true} {
			name := "greeting-cancel"
			if handshake {
				name = "tls-client-hello-cancel"
			}
			if earlier {
				name += "-earlier-deadline"
			}
			t.Run(name, func(t *testing.T) {
				endpoint, ready, peerDone, cleanupPeer := probeStalledPeer(t, handshake)
				policy := teamTestPolicy(t)
				// Even a stalled plaintext greeting must use the TLS-only constructor.
				policy.Endpoint = "tls://" + strings.TrimPrefix(strings.TrimPrefix(endpoint, "nats://"), "tls://")
				policy.Timeout = 5 * time.Second
				password := strings.Repeat("c", 48)
				resolver, _ := teamBasicResolver(t, policy, "fixture_private_basic_user", password)
				connection, err := NewTeamConnection(policy, resolver)
				if err != nil {
					t.Fatal("explicit stalled TLS policy rejected")
				}
				ctx, cancel := context.WithCancel(context.Background())
				if earlier {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), 300*time.Millisecond)
				}
				finished := make(chan struct{})
				var out TeamConnectionObservation
				var observationErr error
				t.Cleanup(func() {
					cancel()
					cleanupPeer()
					select {
					case <-finished:
					case <-time.After(time.Second):
						t.Error("owned team observer did not join")
					}
				})
				begin := time.Now()
				go func() { defer close(finished); out, observationErr = connection.Observe(ctx) }()
				select {
				case <-ready:
				case <-finished:
					t.Fatal("observer returned before selected peer was ready")
				case <-time.After(time.Second):
					t.Fatal("observer did not reach the actual selected peer")
				}
				if !earlier {
					begin = time.Now()
					cancel()
				}
				select {
				case <-finished:
				case <-time.After(500 * time.Millisecond):
					t.Fatal("setup ignored caller cancellation or earlier deadline")
				}
				if time.Since(begin) > 500*time.Millisecond || observationErr == nil || observationErr.Error() != "team_deadline" ||
					out.TLSVerified || out.Authenticated || out.ServerIdentityVerified || out.BrokerVerified || out.Snapshot != nil ||
					out.ServerName != "" || out.ServerVersion != "" || out.Domain != "" || out.Code != "not_observed" ||
					out.DomainAvailability != "unavailable" || out.KernelAvailability != "unavailable" {
					t.Logf("setup observation: elapsed=%s error=%v code=%s TLS=%t auth=%t server=%t domain=%s kernel=%s snapshot=%t",
						time.Since(begin), observationErr, out.Code, out.TLSVerified, out.Authenticated, out.ServerIdentityVerified,
						out.DomainAvailability, out.KernelAvailability, out.Snapshot != nil)
					t.Fatal("cancelled setup returned facts or escaped its caller budget")
				}
				teamBasicNoDisclosure(t, out, observationErr, password, policy.Endpoint, resolver.policy.Directory, "fixture_private_basic_user")
				// Peer closure must be observed before cleanup can close its socket.
				select {
				case <-peerDone:
				case <-time.After(500 * time.Millisecond):
					t.Fatal("cancelled observer retained its owned connection")
				}
			})
		}
	}
}
