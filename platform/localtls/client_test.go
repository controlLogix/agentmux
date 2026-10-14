package localtls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

type testPKI struct {
	policy          Policy
	certificate     tls.Certificate
	ca              *x509.Certificate
	caKey           *ecdsa.PrivateKey
	certPEM, keyPEM []byte
}

type controlledCloseFailure struct {
	net.Conn
	attempted atomic.Bool
}

func (c *controlledCloseFailure) Close() error {
	if !c.attempted.Swap(true) {
		return errors.New("controlled_close_failure")
	}
	return c.Conn.Close()
}

func TestDialerRetainsFailedOwnedCloseForExplicitRetry(t *testing.T) {
	p := newTestPKI(t)
	trust, err := NewClientTrust(p.policy)
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := trust.NewDialer(context.Background(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	conn := &ownedConnection{Conn: &controlledCloseFailure{Conn: left}, owner: dialer}
	dialer.mu.Lock()
	dialer.connections[conn] = struct{}{}
	dialer.mu.Unlock()
	if !errors.Is(dialer.Close(), ErrCleanup) {
		t.Fatal("failed close was reported as clean")
	}
	dialer.mu.Lock()
	retained := len(dialer.connections)
	dialer.mu.Unlock()
	if retained != 1 {
		t.Fatal("failed cleanup lost its exact owned connection")
	}
	if dialer.Close() != nil {
		t.Fatal("explicit retry did not close the retained connection")
	}
	dialer.mu.Lock()
	retained = len(dialer.connections)
	dialer.mu.Unlock()
	if retained != 0 {
		t.Fatal("closed connection remained retained")
	}
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("fixture key unavailable")
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Disposable local TLS CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal("fixture CA unavailable")
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("fixture CA decode failed")
	}
	result := testPKI{policy: Policy{Endpoint: "tls://127.0.0.1:4222", ServerName: "fixture.agentmux.invalid", RootsPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, ca: ca, caKey: key}
	result.issue(t, "fixture.agentmux.invalid", now.Add(-time.Minute), now.Add(time.Hour), x509.ExtKeyUsageServerAuth)
	return result
}

func (p *testPKI) issue(t *testing.T, name string, before, after time.Time, usage x509.ExtKeyUsage) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("fixture leaf key unavailable")
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{name}, NotBefore: before, NotAfter: after, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal("fixture leaf unavailable")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("fixture leaf key encoding failed")
	}
	p.certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	p.keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	p.certificate, err = tls.X509KeyPair(p.certPEM, p.keyPEM)
	if err != nil {
		t.Fatal("fixture key pair unavailable")
	}
	digest := sha256.Sum256(der)
	p.policy.LeafCertificateSHA256 = "sha256:" + hex.EncodeToString(digest[:])
}

func TestClientTrustRejectsInvalidPolicyAndCopiesMaterial(t *testing.T) {
	p := newTestPKI(t)
	trust, err := NewClientTrust(p.policy)
	if err != nil {
		t.Fatal(err)
	}
	expected := trust.Policy().RootsPEM
	p.policy.RootsPEM[0] = 'x'
	copy := trust.Policy()
	copy.RootsPEM[0] = 'y'
	if !bytes.Equal(expected, trust.Policy().RootsPEM) {
		t.Fatal("mutable caller material changed enrolled trust")
	}
	for _, kind := range []string{"plain", "remote", "userinfo", "query", "fragment", "port-zero", "port-overflow", "port-alias", "dns-ip", "dns-wildcard", "dns-uppercase", "pin", "nil-ca", "garbage-ca", "multiple-ca", "malformed-leading-ca", "private-key", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			policy := trust.Policy()
			switch kind {
			case "plain":
				policy.Endpoint = "nats://127.0.0.1:4222"
			case "remote":
				policy.Endpoint = "tls://example.invalid:4222"
			case "userinfo":
				policy.Endpoint = "tls://user@127.0.0.1:4222"
			case "query":
				policy.Endpoint += "?"
			case "fragment":
				policy.Endpoint += "#bad"
			case "port-zero":
				policy.Endpoint = "tls://127.0.0.1:0"
			case "port-overflow":
				policy.Endpoint = "tls://127.0.0.1:65536"
			case "port-alias":
				policy.Endpoint = "tls://127.0.0.1:04222"
			case "dns-ip":
				policy.ServerName = "127.0.0.1"
			case "dns-wildcard":
				policy.ServerName = "*.agentmux.invalid"
			case "dns-uppercase":
				policy.ServerName = "Fixture.agentmux.invalid"
			case "pin":
				policy.LeafCertificateSHA256 = "sha256:" + strings.Repeat("A", 64)
			case "nil-ca":
				policy.RootsPEM = nil
			case "garbage-ca":
				policy.RootsPEM = append([]byte("unapproved preamble"), policy.RootsPEM...)
			case "multiple-ca":
				policy.RootsPEM = append(policy.RootsPEM, policy.RootsPEM...)
			case "malformed-leading-ca":
				policy.RootsPEM = append([]byte("-----BEGIN CERTIFICATE-----\n%!\n-----END CERTIFICATE-----\n"), policy.RootsPEM...)
			case "private-key":
				policy.RootsPEM = p.keyPEM
			case "oversize":
				policy.RootsPEM = append(policy.RootsPEM, bytes.Repeat([]byte(" "), MaxRootsPEM)...)
			}
			if candidate, err := NewClientTrust(policy); candidate != nil || !errors.Is(err, ErrInvalidPolicy) {
				t.Fatal("invalid local trust accepted")
			}
		})
	}
}

func TestDialerRejectsUntrustedServerBeforeCredentials(t *testing.T) {
	for _, kind := range []string{"rogue-ca", "wrong-dns", "expired", "future", "wrong-eku", "wrong-pin", "plaintext"} {
		t.Run(kind, func(t *testing.T) {
			p := newTestPKI(t)
			server := p
			switch kind {
			case "rogue-ca":
				server = newTestPKI(t)
			case "wrong-dns":
				server.issue(t, "other.agentmux.invalid", time.Now().Add(-time.Minute), time.Now().Add(time.Hour), x509.ExtKeyUsageServerAuth)
			case "expired":
				server.issue(t, p.policy.ServerName, time.Now().Add(-time.Hour), time.Now().Add(-time.Minute), x509.ExtKeyUsageServerAuth)
			case "future":
				server.issue(t, p.policy.ServerName, time.Now().Add(time.Minute), time.Now().Add(time.Hour), x509.ExtKeyUsageServerAuth)
			case "wrong-eku":
				server.issue(t, p.policy.ServerName, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), x509.ExtKeyUsageClientAuth)
			case "wrong-pin":
				server.issue(t, p.policy.ServerName, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), x509.ExtKeyUsageServerAuth)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal("fixture listener failed")
			}
			defer listener.Close()
			p.policy.Endpoint = "tls://" + listener.Addr().String()
			trust, err := NewClientTrust(p.policy)
			if err != nil {
				t.Fatal(err)
			}
			received := make(chan bool, 1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				if err != nil {
					received <- false
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				if kind == "plaintext" {
					fmt.Fprint(conn, "INFO {\"server_name\":\"fixture_server\",\"version\":\"2.15.0\",\"auth_required\":true}\r\n")
					data := make([]byte, 4096)
					n, _ := conn.Read(data)
					received <- bytes.Contains(data[:n], []byte("CONNECT"))
					return
				}
				tlsConn := tls.Server(conn, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{server.certificate}})
				if tlsConn.Handshake() != nil {
					received <- false
					return
				}
				data := make([]byte, 4096)
				n, _ := tlsConn.Read(data)
				received <- bytes.Contains(data[:n], []byte("CONNECT"))
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			dialer, err := trust.NewDialer(ctx, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer dialer.Close()
			nc, err := nats.Connect(p.policy.Endpoint, nats.UserInfo("synthetic-client", strings.Repeat("s", 48)), nats.TLSHandshakeFirst(), nats.SetCustomDialer(dialer), nats.NoReconnect(), nats.IgnoreDiscoveredServers(), nats.Timeout(time.Second))
			if nc != nil {
				nc.Close()
			}
			if err == nil || !IsAuthorityError(err) {
				t.Fatalf("untrusted peer did not produce a fixed authority rejection: %T", err)
			}
			if <-received {
				t.Fatal("untrusted peer received a credential-bearing CONNECT")
			}
			<-done
		})
	}
}

func TestDialerCancellationAndSuccessfulLifetime(t *testing.T) {
	p := newTestPKI(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("fixture listener failed")
	}
	defer listener.Close()
	p.policy.Endpoint = "tls://" + listener.Addr().String()
	trust, err := NewClientTrust(p.policy)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		accepted <- conn
		io.Copy(io.Discard, conn)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	dialer, err := trust.NewDialer(ctx, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := dialer.Dial("tcp", listener.Addr().String()); result <- err }()
	<-accepted
	start := time.Now()
	cancel()
	resultError := <-result
	if !errors.Is(resultError, ErrDeadline) || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("stalled handshake did not honor caller cancellation: %v", resultError)
	}
	if dialer.Close() != nil {
		t.Fatal("owned dialer cleanup failed")
	}
	<-done
	if _, err := dialer.Dial("tcp", listener.Addr().String()); !errors.Is(err, ErrDeadline) {
		t.Fatal("closed dialer reopened a connection")
	}
	if _, err := trust.NewDialer(context.Background(), 6*time.Second); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("unbounded handshake budget accepted")
	}
}

func TestRealNATSTLSFirstKeepsAuthenticatedSocketAfterHandshakeTimeout(t *testing.T) {
	binary := os.Getenv("AGENTMUX_TEST_NATS")
	if binary == "" {
		t.Fatal("prepared disposable NATS executable required")
	}
	version, err := exec.Command(binary, "-v").Output()
	if err != nil || !bytes.Contains(version, []byte("v2.15.0")) {
		t.Fatal("qualified NATS2.15.0 fixture required")
	}
	p := newTestPKI(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("fixture port failed")
	}
	address := listener.Addr().String()
	listener.Close()
	p.policy.Endpoint = "tls://" + address
	directory := t.TempDir()
	cert := filepath.Join(directory, "cert.pem")
	key := filepath.Join(directory, "key.pem")
	config := filepath.Join(directory, "nats.json")
	if os.WriteFile(cert, p.certPEM, 0600) != nil || os.WriteFile(key, p.keyPEM, 0600) != nil {
		t.Fatal("private fixture material unavailable")
	}
	secret := strings.Repeat("s", 48)
	raw, _ := json.Marshal(map[string]any{"listen": address, "server_name": "fixture_server", "tls": map[string]any{"cert_file": cert, "key_file": key, "min_version": "1.3", "handshake_first": true}, "authorization": map[string]any{"users": []any{map[string]any{"user": "synthetic-client", "password": secret}}}})
	if os.WriteFile(config, raw, 0600) != nil {
		t.Fatal("private fixture config unavailable")
	}
	cmd := exec.Command(binary, "-c", config)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if cmd.Start() != nil {
		t.Fatal("actual fixture broker start failed")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		cmd.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			cmd.Process.Kill()
			<-done
		}
	})
	trust, err := NewClientTrust(p.policy)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialer, err := trust.NewDialer(ctx, 300*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Close()
	var nc *nats.Conn
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		nc, err = nats.Connect(p.policy.Endpoint, nats.UserInfo("synthetic-client", secret), nats.TLSHandshakeFirst(), nats.SetCustomDialer(dialer), nats.NoReconnect(), nats.IgnoreDiscoveredServers(), nats.Timeout(time.Second))
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || nc == nil {
		t.Fatal("actual TLS-first broker connection failed")
	}
	defer nc.Close()
	state, err := nc.TLSConnectionState()
	if err != nil || state.Version != tls.VersionTLS13 || nc.ConnectedServerName() != "fixture_server" {
		t.Fatal("actual broker did not use authenticated TLS1.3")
	}
	time.Sleep(350 * time.Millisecond)
	if nc.FlushTimeout(time.Second) != nil {
		t.Fatal("completed handshake timeout closed a live socket")
	}
	cancel()
	dialer.Close()
	dialer.mu.Lock()
	remaining := len(dialer.connections)
	dialer.mu.Unlock()
	if remaining != 0 {
		t.Fatal("dialer retained an owned socket after cleanup")
	}
	// The server must not accept a historical plaintext client on this listener.
	plain, err := nats.Connect("nats://"+address, nats.UserInfo("synthetic-client", secret), nats.NoReconnect(), nats.Timeout(100*time.Millisecond))
	if plain != nil {
		plain.Close()
	}
	if err == nil {
		t.Fatal("strict TLS-first listener accepted plaintext")
	}
}
