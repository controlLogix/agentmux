package deployment

import (
	"context"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"github.com/nats-io/nkeys"
)

// This test-only signer follows the NATS JWT v2 wire format, using the existing
// nkeys dependency. No client JWT decoding decides authentication or permission.
// The real server verifies the operator/account/user chain and nonce signature.
// References: github.com/nats-io/jwt/blob/main/v2/{claims,header,user_claims,account_claims}.go.
type jwtWorkerClaims struct {
	Expires  int64  `json:"exp,omitempty"`
	ID       string `json:"jti,omitempty"`
	IssuedAt int64  `json:"iat,omitempty"`
	Issuer   string `json:"iss,omitempty"`
	Name     string `json:"name,omitempty"`
	Subject  string `json:"sub,omitempty"`
}

func jwtWorkerSign(t *testing.T, signer nkeys.KeyPair, subject, kind string, fields map[string]any) string {
	t.Helper()
	issuer, err := signer.PublicKey()
	if err != nil {
		t.Fatal("fixture JWT issuer unavailable")
	}
	claims := jwtWorkerClaims{Expires: time.Now().Add(time.Hour).Unix(), IssuedAt: time.Now().Unix(), Issuer: issuer, Name: "disposable_" + kind, Subject: subject}
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal("fixture claim encoding failed")
	}
	hash := sha512.Sum512_256(raw)
	claims.ID = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash[:])
	fields["type"], fields["version"] = kind, 2
	claim := struct {
		jwtWorkerClaims
		NATS map[string]any `json:"nats"`
	}{claims, fields}
	raw, err = json.Marshal(claim)
	if err != nil {
		t.Fatal("fixture JWT encoding failed")
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"ed25519-nkey"}`))
	message := header + "." + base64.RawURLEncoding.EncodeToString(raw)
	signature, err := signer.Sign([]byte(message))
	if err != nil {
		t.Fatal("fixture JWT signing failed")
	}
	return message + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func jwtWorkerKey(t *testing.T, create func() (nkeys.KeyPair, error)) nkeys.KeyPair {
	t.Helper()
	key, err := create()
	if err != nil {
		t.Fatal("fixture NKey creation failed")
	}
	t.Cleanup(key.Wipe)
	return key
}

func jwtWorkerPublic(t *testing.T, key nkeys.KeyPair) string {
	t.Helper()
	public, err := key.PublicKey()
	if err != nil {
		t.Fatal("fixture public identity unavailable")
	}
	return public
}

func jwtWorkerUser(t *testing.T, account, user nkeys.KeyPair, publish, subscribe []string) string {
	t.Helper()
	return jwtWorkerSign(t, account, jwtWorkerPublic(t, user), "user", map[string]any{
		"pub": map[string]any{"allow": publish}, "sub": map[string]any{"allow": subscribe},
		"subs": -1, "data": -1, "payload": -1,
	})
}

type jwtWorkerResolver struct {
	token string
	seed  []byte
	scope TeamScope
}

func (r jwtWorkerResolver) Resolve(ctx context.Context, reference TeamCredentialReference) (TeamCredential, error) {
	if ctx.Err() != nil {
		return TeamCredential{}, ctx.Err()
	}
	// Every call gets a new mutable NKey; Observe owns and wipes only that copy.
	decorated := []byte("-----BEGIN NATS USER JWT-----\n" + r.token + "\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n" + string(r.seed) + "\n------END USER NKEY SEED------\n")
	defer clear(decorated)
	return NewTeamJWTCredential(reference, r.scope, decorated)
}

type jwtWorkerFixture struct {
	policy         TeamConnectionPolicy
	tls            *tls.Config
	account        nkeys.KeyPair
	user           nkeys.KeyPair
	token          string
	seed           []byte
	publisher      *nats.Conn
	handshakeFirst bool
}

func jwtWorkerConnect(f *jwtWorkerFixture, token string, key nkeys.KeyPair, handler nats.ErrHandler) (*nats.Conn, error) {
	options := []nats.Option{nats.Secure(f.tls.Clone()), nats.UserJWT(func() (string, error) { return token, nil }, key.Sign), nats.Timeout(250 * time.Millisecond), nats.NoReconnect(), nats.IgnoreDiscoveredServers(), nats.ErrorHandler(handler)}
	if f.handshakeFirst {
		options = append(options, nats.TLSHandshakeFirst())
	}
	return nats.Connect(f.policy.Endpoint, options...)
}

func newJWTWorkerFixture(t *testing.T) *jwtWorkerFixture {
	t.Helper()
	return newJWTWorkerFixtureTLSMode(t, false)
}

func newJWTWorkerFixtureTLSMode(t *testing.T, handshakeFirst bool) *jwtWorkerFixture {
	return newJWTWorkerFixtureScenario(t, handshakeFirst, false)
}

func newJWTWorkerStorageFixture(t *testing.T) *jwtWorkerFixture {
	return newJWTWorkerFixtureScenario(t, true, true)
}

func jwtWorkerStreamLimits(storage bool) (bytes, streams int) {
	if storage {
		// Three 2 MiB storage owners, four 512 KiB other owners, and two
		// 1 MiB buckets. This changes only the disposable storage test account.
		return 3*2*1048576 + 4*524288 + 2*1048576, 9
	}
	return 4 * 1024 * 1024, 4
}

func newJWTWorkerFixtureScenario(t *testing.T, handshakeFirst, storage bool) *jwtWorkerFixture {
	t.Helper()
	binary := os.Getenv("AGENTMUX_TEST_NATS")
	if binary == "" {
		t.Fatal("prepared disposable NATS executable required")
	}
	directory := t.TempDir()
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("private fixture directory unavailable")
	}
	roots, tlsConfig := jwtWorkerTLS(t, directory)
	f := &jwtWorkerFixture{tls: tlsConfig, handshakeFirst: handshakeFirst}
	f.policy = TeamConnectionPolicy{TLSServerName: "localhost", TLSRootsPEM: roots, ExpectedServerName: "jwt_fixture_server", ExpectedDomain: "jwt_fixture_domain", ExpectedServerVersion: "2.15.0", Timeout: 2 * time.Second, ObserveDomain: true,
		CredentialRef: TeamCredentialReference{ID: "jwt_fixture_reference", AuthKind: TeamJWT},
		Scope:         TeamScope{OrganizationID: "jwt_fixture_org", ProjectID: "jwt_fixture_project", Kernel: protocol.Scope{HubID: "jwt_fixture_hub", InstanceID: "jwt_fixture_instance", ProfileID: "jwt_fixture_profile", AssemblyDigest: "sha256:" + strings.Repeat("a", 64), ReleaseManifestDigest: "sha256:" + strings.Repeat("b", 64), ReleaseVersion: "1.0.0"}}}
	operator := jwtWorkerKey(t, nkeys.CreateOperator)
	system := jwtWorkerKey(t, nkeys.CreateAccount)
	f.account = jwtWorkerKey(t, nkeys.CreateAccount)
	f.user = jwtWorkerKey(t, nkeys.CreateUser)
	publisherKey := jwtWorkerKey(t, nkeys.CreateUser)
	systemPublic := jwtWorkerPublic(t, system)
	accountFields := func(js bool) map[string]any {
		limits := map[string]any{"subs": -1, "data": -1, "payload": -1, "imports": -1, "exports": -1, "wildcards": true, "conn": -1, "leaf": -1}
		if js {
			bytes, streams := jwtWorkerStreamLimits(storage)
			limits["mem_storage"], limits["disk_storage"], limits["streams"], limits["consumer"] = 1024*1024, bytes, streams, 4
		}
		return map[string]any{"limits": limits}
	}
	opToken := jwtWorkerSign(t, operator, jwtWorkerPublic(t, operator), "operator", map[string]any{"system_account": systemPublic})
	preload := map[string]string{systemPublic: jwtWorkerSign(t, operator, systemPublic, "account", accountFields(false)), jwtWorkerPublic(t, f.account): jwtWorkerSign(t, operator, jwtWorkerPublic(t, f.account), "account", accountFields(true))}
	wire, _ := communication.Subjects(f.policy.Scope.Kernel.HubID)
	f.token = jwtWorkerUser(t, f.account, f.user, []string{"$JS." + f.policy.ExpectedDomain + ".API.INFO", "$JS.API.INFO"}, []string{wire.Snapshot, "_INBOX.>"})
	seed, err := f.user.Seed()
	if err != nil {
		t.Fatal("fixture user seed unavailable")
	}
	f.seed = seed
	t.Cleanup(func() { clear(f.seed) })
	publisherToken := jwtWorkerUser(t, f.account, publisherKey, []string{wire.Snapshot}, []string{"_INBOX.>"})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("fixture port unavailable")
	}
	address := listener.Addr().String()
	listener.Close()
	f.policy.Endpoint = "tls://" + address
	serverBytes := 8 * 1024 * 1024
	if storage {
		serverBytes, _ = jwtWorkerStreamLimits(true)
	}
	config := map[string]any{"listen": address, "server_name": f.policy.ExpectedServerName, "operator": opToken, "system_account": systemPublic, "resolver": "MEMORY", "resolver_preload": preload,
		"jetstream": map[string]any{"store_dir": filepath.Join(directory, "store"), "domain": f.policy.ExpectedDomain, "max_memory_store": 1024 * 1024, "max_file_store": serverBytes, "sync_interval": "always"},
		"tls":       map[string]any{"cert_file": filepath.Join(directory, "server.pem"), "key_file": filepath.Join(directory, "server-key.pem"), "timeout": 1}}
	if handshakeFirst {
		config["tls"].(map[string]any)["handshake_first"] = true
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal("fixture configuration encoding failed")
	}
	path := filepath.Join(directory, "nats.json")
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("private fixture configuration write failed")
	}
	cmd := exec.Command(binary, "-c", path)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	done := make(chan struct{})
	started := false
	// Register before Start. Signal only this owned process and join its waiter.
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
			t.Error("fixture broker required forced cleanup")
		case <-time.After(2 * time.Second):
			t.Error("owned fixture broker could not be reaped")
		}
	})
	if cmd.Start() != nil {
		t.Fatal("owned fixture broker start failed")
	}
	started = true
	go func() { _ = cmd.Wait(); close(done) }()
	end := time.Now().Add(5 * time.Second)
	for time.Now().Before(end) {
		nc, err := jwtWorkerConnect(f, publisherToken, publisherKey, func(*nats.Conn, *nats.Subscription, error) {})
		if err == nil {
			f.publisher = nc
			t.Cleanup(nc.Close)
			if nc.ConnectedServerVersion() != f.policy.ExpectedServerVersion || nc.ConnectedServerName() != f.policy.ExpectedServerName {
				t.Fatal("fixture server pin or identity mismatch")
			}
			return f
		}
		select {
		case <-done:
			t.Fatal("owned JWT broker exited before readiness")
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatal("owned JWT broker readiness exceeded its budget")
	return nil
}

func (f *jwtWorkerFixture) publishSnapshots(t *testing.T, scope protocol.Scope) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	fault := make(chan struct{}, 1)
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("owned snapshot publisher did not join")
		}
		select {
		case <-fault:
			t.Error("fixture snapshot publication failed")
		default:
		}
	})
	wire, _ := communication.Subjects(f.policy.Scope.Kernel.HubID)
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
				members = append(members, protocol.Member{Role: role, State: "ready", Incarnation: strings.Repeat("a", 32), Revision: 1, ObservedAt: now.Format(time.RFC3339Nano)})
			}
			frame := protocol.Snapshot{SchemaVersion: protocol.Version, Kind: "kernel-info", Scope: scope, Role: "exported-status", Incarnation: strings.Repeat("a", 32), Revision: 1, ObservedAt: now.Format(time.RFC3339Nano), ValidUntil: now.Add(3 * time.Second).Format(time.RFC3339Nano), KernelReadiness: "ready", Members: members}
			raw, err := json.Marshal(frame)
			if err != nil || f.publisher.Publish(wire.Snapshot, raw) != nil {
				fault <- struct{}{}
				return
			}
		}
	}()
}

func jwtWorkerObserve(t *testing.T, policy TeamConnectionPolicy, resolver jwtWorkerResolver) (TeamConnectionObservation, error) {
	t.Helper()
	connection, err := NewTeamConnection(policy, resolver)
	if err != nil {
		t.Fatal("valid fixture policy admission failed")
	}
	return connection.Observe(context.Background())
}

func TestTeamJWTRealTLSAuthenticationAndDomainPermissions(t *testing.T) {
	for _, mode := range []string{"permitted-info", "forbidden-info", "no-info-request"} {
		t.Run(mode, func(t *testing.T) {
			f := newJWTWorkerFixture(t)
			f.publishSnapshots(t, f.policy.Scope.Kernel)
			token := f.token
			if mode == "forbidden-info" {
				wire, _ := communication.Subjects(f.policy.Scope.Kernel.HubID)
				token = jwtWorkerUser(t, f.account, f.user, []string{"fixture.never"}, []string{wire.Snapshot, "_INBOX.>"})
			}
			if mode == "no-info-request" {
				f.policy.ObserveDomain = false
			}
			var infoAudit *nats.Subscription
			if mode == "no-info-request" {
				// Give INFO permission, then watch the real account API subject.
				// A denied publish would not prove that no request was attempted.
				auditKey := jwtWorkerKey(t, nkeys.CreateUser)
				auditToken := jwtWorkerUser(t, f.account, auditKey, []string{"fixture.never"}, []string{"$JS.API.INFO"})
				audit, err := jwtWorkerConnect(f, auditToken, auditKey, func(*nats.Conn, *nats.Subscription, error) {})
				if err != nil {
					t.Fatal("fixture INFO audit connection failed")
				}
				t.Cleanup(audit.Close)
				infoAudit, err = audit.SubscribeSync("$JS.API.INFO")
				if err != nil || audit.FlushTimeout(time.Second) != nil {
					t.Fatal("fixture INFO audit subscription failed")
				}
				control, err := jwtWorkerConnect(f, f.token, f.user, func(*nats.Conn, *nats.Subscription, error) {})
				if err != nil {
					t.Fatal("fixture INFO positive control connection failed")
				}
				t.Cleanup(control.Close)
				js, err := control.JetStream(nats.Domain(f.policy.ExpectedDomain))
				if err != nil {
					t.Fatal("fixture INFO positive control context failed")
				}
				controlContext, cancelControl := context.WithTimeout(context.Background(), time.Second)
				defer cancelControl()
				account, err := js.AccountInfo(nats.Context(controlContext))
				if err != nil || account.Domain != f.policy.ExpectedDomain {
					t.Fatal("fixture INFO positive control failed")
				}
				if _, err := infoAudit.NextMsg(time.Second); err != nil {
					t.Fatal("fixture INFO audit could not see the positive control")
				}
				control.Close()
			}
			resolver := jwtWorkerResolver{token, f.seed, f.policy.Scope}
			for attempt := 0; attempt < 2; attempt++ {
				out, err := jwtWorkerObserve(t, f.policy, resolver)
				if err != nil || !out.TLSVerified || !out.Authenticated || !out.ServerIdentityVerified || out.KernelAvailability != "available" || out.Snapshot == nil || out.Snapshot.Scope != f.policy.Scope.Kernel {
					t.Fatal("real JWT TLS snapshot observation failed")
				}
				if mode == "permitted-info" {
					if !out.BrokerVerified || out.DomainAvailability != "available" || out.Domain != f.policy.ExpectedDomain {
						t.Fatal("permitted AccountInfo did not prove the selected domain")
					}
				} else if out.BrokerVerified || out.DomainAvailability != "unavailable" || out.Domain != "" {
					t.Fatal("forbidden or unrequested AccountInfo fabricated domain evidence")
				}
			}
			if infoAudit != nil {
				if _, err := infoAudit.NextMsg(50 * time.Millisecond); !errors.Is(err, nats.ErrTimeout) {
					t.Fatal("disabled domain observation issued an AccountInfo request")
				}
			}
		})
	}
}

func TestTeamJWTRealTLSAndAuthenticationRefusals(t *testing.T) {
	for _, mode := range []string{"wrong-ca", "wrong-hostname", "wrong-seed", "altered-signature", "untrusted-account"} {
		t.Run(mode, func(t *testing.T) {
			f := newJWTWorkerFixture(t)
			policy := f.policy
			resolver := jwtWorkerResolver{f.token, f.seed, f.policy.Scope}
			switch mode {
			case "wrong-ca":
				roots, _ := jwtWorkerTLS(t, t.TempDir())
				policy.TLSRootsPEM = roots
			case "wrong-hostname":
				policy.TLSServerName = "unselected.example.test"
			case "wrong-seed":
				other := jwtWorkerKey(t, nkeys.CreateUser)
				seed, err := other.Seed()
				if err != nil {
					t.Fatal("negative seed unavailable")
				}
				t.Cleanup(func() { clear(seed) })
				resolver.seed = seed
			case "altered-signature":
				parts := strings.Split(f.token, ".")
				sig, err := base64.RawURLEncoding.DecodeString(parts[2])
				if err != nil {
					t.Fatal("negative signature preparation failed")
				}
				sig[0] ^= 1
				parts[2] = base64.RawURLEncoding.EncodeToString(sig)
				resolver.token = strings.Join(parts, ".")
			case "untrusted-account":
				rogue := jwtWorkerKey(t, nkeys.CreateAccount)
				resolver.token = jwtWorkerUser(t, rogue, f.user, []string{"fixture.never"}, []string{"_INBOX.>"})
			}
			out, err := jwtWorkerObserve(t, policy, resolver)
			if err == nil || err.Error() != "team_authentication_or_connection_unavailable" || out.TLSVerified || out.Authenticated || out.BrokerVerified || out.Snapshot != nil {
				t.Fatal("actual broker admitted an invalid TLS or JWT credential")
			}
		})
	}
}

func TestTeamJWTTrustedScopeAndSnapshotRefusals(t *testing.T) {
	for _, mode := range []string{"credential-scope", "snapshot-scope", "snapshot-permission"} {
		t.Run(mode, func(t *testing.T) {
			f := newJWTWorkerFixture(t)
			resolver := jwtWorkerResolver{f.token, f.seed, f.policy.Scope}
			expected := "team_credential_binding_invalid"
			if mode == "credential-scope" {
				resolver.scope.ProjectID = "unselected_project"
			} else {
				scope := f.policy.Scope.Kernel
				if mode == "snapshot-scope" {
					scope.ProfileID = "unselected_profile"
					expected = "team_snapshot_or_scope_invalid"
				} else {
					resolver.token = jwtWorkerUser(t, f.account, f.user, []string{"$JS." + f.policy.ExpectedDomain + ".API.INFO", "$JS.API.INFO"}, []string{"_INBOX.>"})
				}
				f.publishSnapshots(t, scope)
			}
			out, err := jwtWorkerObserve(t, f.policy, resolver)
			if mode == "snapshot-permission" {
				if err != nil || !out.Authenticated || !out.TLSVerified || out.KernelAvailability != "unavailable" || out.Snapshot != nil || out.Code != "kernel_unavailable" {
					t.Fatal("broker snapshot denial became permitted kernel evidence")
				}
			} else if err == nil || err.Error() != expected || out.Snapshot != nil {
				t.Fatal("unselected credential or snapshot scope was accepted")
			}
		})
	}
}

func TestTeamJWTActualBrokerDeniesProtectedSubjects(t *testing.T) {
	f := newJWTWorkerFixture(t)
	denied := make(chan string, 4)
	wire, _ := communication.Subjects(f.policy.Scope.Kernel.HubID)
	nc, err := jwtWorkerConnect(f, f.token, f.user, func(_ *nats.Conn, _ *nats.Subscription, err error) {
		if errors.Is(err, nats.ErrPermissionViolation) {
			// nats.go 1.54 supplies nil subscriptions for these server errors.
			// Inspect only the fixed fixture operation, never print the raw error.
			if strings.Contains(err.Error(), `Subscription to "`+wire.Events["boot"]+`"`) {
				denied <- "subscribe"
			} else if strings.Contains(err.Error(), `Publish to "`+wire.Commands["boot"]+`"`) {
				denied <- "publish"
			}
		}
	})
	if err != nil {
		t.Fatal("valid scoped JWT connection failed")
	}
	t.Cleanup(nc.Close)
	if _, err := nc.SubscribeSync(wire.Events["boot"]); err != nil {
		t.Fatal("subscription control was not submitted to the real server")
	}
	if nc.Publish(wire.Commands["boot"], []byte("disposable-denial-control")) != nil {
		t.Fatal("publish control was not submitted to the real server")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if nc.FlushWithContext(ctx) != nil {
		t.Fatal("actual broker denial controls did not flush")
	}
	seen := map[string]bool{}
	for len(seen) < 2 {
		select {
		case action := <-denied:
			seen[action] = true
		case <-ctx.Done():
			t.Fatal("actual broker did not deny both protected operations")
		}
	}
}
