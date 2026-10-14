package launcher

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
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/boot"
	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/lifecycle"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/kernel/status"
	"github.com/controlLogix/agentmux/platform/localtls"
	"github.com/nats-io/nats.go"
)

type observerTLSFixture struct {
	policy          localtls.Policy
	cert            tls.Certificate
	certPEM, keyPEM []byte
	root            *x509.Certificate
	rootKey         *ecdsa.PrivateKey
}

func newObserverTLSFixture(t *testing.T) observerTLSFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("fixture CA key unavailable")
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Disposable observer CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal("fixture CA unavailable")
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("fixture CA decode failed")
	}
	f := observerTLSFixture{policy: localtls.Policy{Endpoint: "tls://127.0.0.1:4222", ServerName: "observer.agentmux.invalid", RootsPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, root: parsed, rootKey: key}
	f.issue(t, now.Add(-time.Minute), now.Add(time.Hour))
	return f
}
func (f *observerTLSFixture) issue(t *testing.T, before, after time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("fixture leaf key unavailable")
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{f.policy.ServerName}, NotBefore: before, NotAfter: after, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, f.root, &key.PublicKey, f.rootKey)
	if err != nil {
		t.Fatal("fixture leaf unavailable")
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("fixture key encoding failed")
	}
	f.certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	f.keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
	f.cert, err = tls.X509KeyPair(f.certPEM, f.keyPEM)
	if err != nil {
		t.Fatal("fixture certificate pair invalid")
	}
	digest := sha256.Sum256(der)
	f.policy.LeafCertificateSHA256 = "sha256:" + hex.EncodeToString(digest[:])
}
func observerTLSScope() protocol.Scope {
	return protocol.Scope{HubID: "tls_observer_hub", InstanceID: "tls_observer_instance", ProfileID: "tls_observer_profile", AssemblyDigest: "sha256:" + strings.Repeat("a", 64), ReleaseManifestDigest: "sha256:" + strings.Repeat("b", 64), ReleaseVersion: "1.0.0"}
}

func TestKernelStatusPinnedTLSRejectsAdversaryBeforeCONNECT(t *testing.T) {
	for _, fault := range []string{"plaintext", "rogue_ca", "wrong_dns", "wrong_pin", "expired"} {
		t.Run(fault, func(t *testing.T) {
			selected := newObserverTLSFixture(t)
			presented := selected
			if fault == "rogue_ca" {
				presented = newObserverTLSFixture(t)
			}
			if fault == "expired" {
				presented.issue(t, time.Now().Add(-time.Hour), time.Now().Add(-time.Minute))
				selected.policy.LeafCertificateSHA256 = presented.policy.LeafCertificateSHA256
			}
			if fault == "wrong_dns" {
				selected.policy.ServerName = "other.agentmux.invalid"
			}
			if fault == "wrong_pin" {
				selected.policy.LeafCertificateSHA256 = "sha256:" + strings.Repeat("f", 64)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal("owned adversarial listener unavailable")
			}
			selected.policy.Endpoint = "tls://" + listener.Addr().String()
			trust, err := localtls.NewClientTrust(selected.policy)
			if err != nil {
				listener.Close()
				t.Fatal("otherwise-valid selected policy rejected")
			}
			password := strings.Repeat("private-fixture-credential-", 2)
			done := make(chan []byte, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- nil
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				if fault == "plaintext" {
					conn.Write([]byte("INFO {\"server_name\":\"tls_observer_server\",\"version\":\"2.15.0\",\"auth_required\":true}\r\n"))
					buf := make([]byte, 4096)
					n, _ := conn.Read(buf)
					done <- buf[:n]
					return
				}
				secure := tls.Server(conn, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{presented.cert}})
				if secure.Handshake() != nil {
					done <- nil
					return
				}
				secure.Write([]byte("INFO {\"server_name\":\"tls_observer_server\",\"version\":\"2.15.0\",\"auth_required\":true}\r\n"))
				buf := make([]byte, 4096)
				n, _ := secure.Read(buf)
				done <- buf[:n]
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			_, err = ObserveKernel(ctx, KernelStatusOptions{Endpoint: selected.policy.Endpoint, Password: password, Scope: observerTLSScope(), Timeout: 400 * time.Millisecond, TLS: trust})
			listener.Close()
			if !IsKernelStatusAuthorityError(err) {
				t.Fatal("server authentication rejection became unavailable", err)
			}
			select {
			case capture := <-done:
				if bytes.Contains(capture, []byte(password)) || bytes.Contains(capture, []byte("CONNECT ")) {
					t.Fatal("private credential reached an unauthenticated server")
				}
			case <-time.After(time.Second):
				t.Fatal("owned adversarial listener was not joined")
			}
		})
	}
}

func TestOwnerBridgeWithoutOwnedAuthorityNeverDials(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("owned adversarial listener unavailable")
	}
	defer listener.Close()
	tcp := listener.(*net.TCPListener)
	tcp.SetDeadline(time.Now().Add(70 * time.Millisecond))
	accepted := make(chan bool, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close()
		}
		accepted <- err == nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c := BootstrapConfig{Kernel: KernelStatusOptions{Endpoint: "nats://" + listener.Addr().String()}}
	nc, dialer, err := bridgeConnect(ctx, c, OwnerBridgeCredential{Role: "runtime-client", Password: strings.Repeat("p", 48)})
	if nc != nil {
		nc.Close()
	}
	if dialer != nil {
		dialer.Close()
	}
	if !IsOwnerBridgeAuthorityError(err) {
		t.Fatal("missing owned TLS authority was not a hard failure")
	}
	if <-accepted {
		t.Fatal("HOST connection preceded owned broker authority")
	}
}

func TestOwnerBridgeOwnedInspectionDenialNeverDials(t *testing.T) {
	for _, fault := range []string{"context", "engine", "version", "image", "port", "config", "cert", "key"} {
		t.Run(fault, func(t *testing.T) {
			f := newBridgeFixture(t)
			f.controlledDocker(t)
			t.Setenv("AMX_OWNER_BRIDGE_DOCKER_FAULT", fault)
			address := strings.TrimPrefix(f.config.Kernel.Endpoint, "tls://")
			listener, err := net.Listen("tcp", address)
			if err != nil {
				t.Fatal("owned adversarial port unavailable")
			}
			accepted := make(chan bool, 1)
			go func() {
				conn, err := listener.Accept()
				if err == nil {
					conn.Close()
				}
				accepted <- err == nil
			}()
			// Complete the actual selected-fact inspection within the product's
			// five-second total budget; a shorter fixture could mask this guard.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			nc, dialer, err := bridgeConnect(ctx, f.config, OwnerBridgeCredential{Role: "runtime-client", Password: f.config.OwnerBridge.ClientPassword})
			if nc != nil {
				nc.Close()
			}
			if dialer != nil {
				dialer.Close()
			}
			listener.Close()
			if !IsOwnerBridgeAuthorityError(err) {
				t.Fatal("owned inspection did not reach the hard selected-fact denial", err)
			}
			select {
			case got := <-accepted:
				if got {
					t.Fatal("HOST dial preceded exact owned TLS inspection")
				}
			case <-time.After(time.Second):
				t.Fatal("owned adversarial listener not joined")
			}
		})
	}
}

func TestOwnerBridgeSecureAdmissionAndInspectionPositive(t *testing.T) {
	f := newBridgeFixture(t)
	f.controlledDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	current, err := LoadBootstrapConfig(*f.config.admissionPolicy)
	if err != nil {
		t.Fatal("actual secure admission reload failed", err)
	}
	if !sameLocalBrokerEnrollment(f.config, current) {
		t.Fatal("actual reloaded secure enrollment changed")
	}
	authority, err := inspectLocalBrokerAuthority(ctx, f.config)
	if err != nil {
		p := f.profile
		driver, e := NewDocker(DockerConfig{Executable: p.Docker.Executable, Context: p.Docker.Context, Endpoint: p.Docker.Endpoint, EngineID: p.Docker.EngineID, Versions: DockerVersions{p.Docker.ClientVersion, p.Docker.ServerVersion, p.Docker.ComposeVersion}, Backend: p.Docker.Backend, Timeout: 3 * time.Second})
		if e != nil {
			t.Fatal("controlled owned driver refused", e)
		}
		u, _ := url.Parse(p.NATSEndpoint)
		_, text, _ := net.SplitHostPort(u.Host)
		port, _ := strconv.Atoi(text)
		_, inspectErr := driver.InspectOwnedTLSBroker(ctx, OwnershipPreflight{Project: p.ComposeProject, InstanceID: p.InstanceID, ProfileID: p.ProfileID, ReleaseDigest: p.ReleaseFingerprint, ConfigDigest: sha256.Sum256(f.config.Compose)}, f.config.BrokerImage, port, f.config.BrokerConfigDigest, sha256.Sum256(f.config.LocalTLS.ServerCertificatePEM()), sha256.Sum256(f.config.LocalTLS.ServerKeyPEM()))
		t.Fatal("actual controlled TLS inspection failed", err, inspectErr)
	}
	if authority.state != "running" || authority.trust == nil {
		t.Fatal("actual controlled TLS inspection missing trusted result")
	}
}

func TestOwnerBridgeTLSFreshObservationPositive(t *testing.T) {
	f := newBridgeFixture(t)
	f.startBroker(t)
	f.startActors(t)
	if _, err := deployment.ProvisionAndProbe(context.Background(), f.config.Health); err != nil {
		t.Fatal("real FILE probe unavailable", err)
	}
	server, err := LoadOwnerBridgeServer(f.config, f.owner, f.enrollment)
	if err != nil {
		t.Fatal("private server admission unavailable", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := server.refresh(ctx, "attempt_"+strings.Repeat("f", 32), nil, nil)
	if err != nil || out.Disposition != "reused" || out.Persistence.Availability != "available" || out.Persistence.Readiness != "unknown" {
		t.Fatal("actual fresh TLS/FILE observation unavailable", err, out.Disposition, out.Persistence.Availability, out.Persistence.Readiness)
	}
}

func TestOwnerBridgeTLSAuthenticationFailureIsHard(t *testing.T) {
	f := newBridgeFixture(t)
	f.startBroker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nc, dialer, err := bridgeConnect(ctx, f.config, OwnerBridgeCredential{Role: deployment.OwnerBridgeClientUser, Password: strings.Repeat("0", 32)})
	if nc != nil {
		nc.Close()
	}
	if dialer != nil {
		dialer.Close()
	}
	if !IsOwnerBridgeAuthorityError(err) {
		t.Fatal("authenticated broker credential denial became startup unavailable", err)
	}
}

func TestOwnerBridgeRetainedExpiryUsesFreshFactsOnly(t *testing.T) {
	f := newBridgeFixture(t)
	f.startBroker(t)
	f.startActors(t)
	if _, err := deployment.ProvisionAndProbe(context.Background(), f.config.Health); err != nil {
		t.Fatal("real FILE probe unavailable", err)
	}
	server, err := LoadOwnerBridgeServer(f.config, f.owner, f.enrollment)
	if err != nil {
		t.Fatal("private server admission unavailable", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	input := ownerObservationFixture(f.policy, f.profile, "reused")
	input.receivedAt = time.Now().Add(-2990 * time.Millisecond)
	input.status.Kernel.ObservedAt = input.receivedAt.UTC().Format(time.RFC3339Nano)
	input.status.Kernel.ValidUntil = input.receivedAt.Add(3 * time.Second).UTC().Format(time.RFC3339Nano)
	for i := range input.status.Kernel.Members {
		input.status.Kernel.Members[i].ObservedAt = input.status.Kernel.ObservedAt
	}
	// The retained frame is controlled input. Holding the real owner lock moves
	// mapping across receipt expiry without changing any observation timestamp.
	f.owner.mu.Lock()
	type outcome struct {
		out StartupStatusObservation
		err error
	}
	done := make(chan outcome, 1)
	go func() { out, err := f.owner.mapObservationContext(ctx, input); done <- outcome{out, err} }()
	timer := time.NewTimer(time.Until(input.receivedAt.Add(3010 * time.Millisecond)))
	<-timer.C
	f.owner.mu.Unlock()
	var stale outcome
	select {
	case stale = <-done:
	case <-ctx.Done():
		t.Fatal("owned mapper did not finish within original deadline")
	}
	if stale.err != nil || !bridgeRetainedExpired(stale.out, input.receivedAt, input.status.Kernel, f.config.Kernel.Scope, time.Now()) {
		t.Fatal("explicit retained receipt expiry was not recognized")
	}
	fresh, err := server.refresh(ctx, input.attemptID, nil, nil)
	if err != nil || fresh.Disposition != "reused" || fresh.Persistence.Readiness != "unknown" || ctx.Err() != nil {
		t.Fatal("genuine refresh failed within unchanged deadline", err)
	}
	if !input.receivedAt.Before(time.Now().Add(-3 * time.Second)) {
		t.Fatal("retained receipt was changed")
	}
	for _, code := range []string{"profile_mismatch", "runtime_owned_child_exited", "host_startup_failed"} {
		out := StartupStatusObservation{Errors: []StartupStatusError{{Code: code}}}
		if bridgeRetainedExpired(out, input.receivedAt, input.status.Kernel, f.config.Kernel.Scope, time.Now()) {
			t.Fatal("non-expiry failure authorized refresh", code)
		}
	}
	out := StartupStatusObservation{Errors: []StartupStatusError{{Code: "kernel_observation_invalid"}}}
	wrong := input.status.Kernel
	wrong.Scope.HubID = "wrong_hub"
	if bridgeRetainedExpired(out, input.receivedAt, wrong, f.config.Kernel.Scope, time.Now()) {
		t.Fatal("wrong scope authorized refresh")
	}
	if !bridgeRetainedExpired(out, input.receivedAt, input.status.Kernel, f.config.Kernel.Scope, time.Now()) {
		t.Fatal("valid retained kernel expiry was not recognized")
	}
}

func TestOwnerBridgePinnedTLSRejectsPortImpersonation(t *testing.T) {
	for _, fault := range []string{"plaintext", "rogue_ca"} {
		t.Run(fault, func(t *testing.T) {
			f := newBridgeFixture(t)
			f.controlledDocker(t)
			listener, err := net.Listen("tcp", strings.TrimPrefix(f.config.Kernel.Endpoint, "tls://"))
			if err != nil {
				t.Fatal("owned adversarial port unavailable")
			}
			presented := newObserverTLSFixture(t)
			presented.policy.ServerName = f.config.Kernel.TLS.Policy().ServerName
			presented.issue(t, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
			done := make(chan []byte, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- nil
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				if fault == "plaintext" {
					conn.Write([]byte("INFO {\"server_name\":\"fixture_server\",\"version\":\"2.15.0\",\"auth_required\":true}\r\n"))
					buf := make([]byte, 4096)
					n, _ := conn.Read(buf)
					done <- buf[:n]
					return
				}
				secure := tls.Server(conn, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{presented.cert}})
				if secure.Handshake() != nil {
					done <- nil
					return
				}
				buf := make([]byte, 4096)
				n, _ := secure.Read(buf)
				done <- buf[:n]
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			nc, dialer, err := bridgeConnect(ctx, f.config, OwnerBridgeCredential{Role: "runtime-client", Password: f.config.OwnerBridge.ClientPassword})
			if nc != nil {
				nc.Close()
			}
			if dialer != nil {
				dialer.Close()
			}
			listener.Close()
			if !IsOwnerBridgeAuthorityError(err) {
				t.Fatal("untrusted port impersonation became ordinary unavailable", err)
			}
			select {
			case capture := <-done:
				if bytes.Contains(capture, []byte(f.config.OwnerBridge.ClientPassword)) || bytes.Contains(capture, []byte("CONNECT ")) {
					t.Fatal("HOST credentials reached an unauthenticated broker")
				}
			case <-time.After(time.Second):
				t.Fatal("owned adversarial port not joined")
			}
		})
	}
}

func TestKernelStatusPinnedTLSRealActorsAndContinuity(t *testing.T) {
	pki := newObserverTLSFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("fixture port unavailable")
	}
	address := listener.Addr().String()
	listener.Close()
	pki.policy.Endpoint = "tls://" + address
	trust, err := localtls.NewClientTrust(pki.policy)
	if err != nil {
		t.Fatal("pinned fixture policy rejected")
	}
	credentials := communication.Credentials{}
	roles := protocol.Roles()
	for _, role := range append([]string{communication.Administrator, communication.OrdinaryPlugin}, roles[:]...) {
		id, err := hostInvocationID("")
		if err != nil {
			t.Fatal("fixture entropy unavailable")
		}
		credentials[role] = id
	}
	_, portText, _ := net.SplitHostPort(address)
	port := 0
	fmt.Sscan(portText, &port)
	scope := observerTLSScope()
	raw, err := communication.BuildConfig(scope.HubID, port, credentials)
	if err != nil {
		t.Fatal("fixed account factory rejected fixture")
	}
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	os.WriteFile(cert, pki.certPEM, 0600)
	os.WriteFile(key, pki.keyPEM, 0600)
	var tree map[string]any
	json.Unmarshal(raw, &tree)
	tree["tls"] = map[string]any{"cert_file": cert, "key_file": key, "min_version": "1.3", "handshake_first": true}
	var bytesConfig bytes.Buffer
	encoder := json.NewEncoder(&bytesConfig)
	encoder.SetEscapeHTML(false)
	encoder.Encode(tree)
	configPath := filepath.Join(dir, "private.conf")
	os.WriteFile(configPath, bytesConfig.Bytes(), 0600)
	binary := os.Getenv("AGENTMUX_TEST_NATS")
	if binary == "" {
		t.Fatal("prepared NATS executable required")
	}
	log, err := os.OpenFile(filepath.Join(dir, "private.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("private fixture log unavailable")
	}
	cmd := exec.Command(binary, "-c", configPath)
	cmd.Stdout, cmd.Stderr = log, log
	if cmd.Start() != nil {
		log.Close()
		t.Fatal("owned TLS broker start failed")
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait(); log.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	deadline := time.Now().Add(3 * time.Second)
	for {
		dialer, err := trust.NewDialer(ctx, 100*time.Millisecond)
		if err != nil {
			t.Fatal("pinned fixture dialer unavailable")
		}
		nc, err := nats.Connect(pki.policy.Endpoint, nats.UserInfo(communication.OrdinaryPlugin, credentials[communication.OrdinaryPlugin]), nats.TLSHandshakeFirst(), nats.SetCustomDialer(dialer), nats.NoReconnect(), nats.Timeout(100*time.Millisecond))
		dialer.Close()
		if nc != nil {
			nc.Close()
		}
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("owned TLS broker readiness unavailable")
		}
		time.Sleep(10 * time.Millisecond)
	}
	wire, _ := communication.Subjects(scope.HubID)
	subjects := protocol.SubjectSet{Commands: wire.Commands, Events: wire.Events, Snapshot: wire.Snapshot, Update: wire.Update}
	for _, role := range protocol.Roles() {
		config := protocol.Config{Credentials: protocol.Credentials{SchemaVersion: protocol.Version, Role: role, Username: role, Password: credentials[role], NATSURL: pki.policy.Endpoint, Scope: scope}, ServerTrust: trust}
		done := make(chan error, 1)
		go func() {
			var err error
			switch role {
			case "boot":
				err = boot.Run(ctx, config, subjects)
			case "kernel-lifecycle":
				err = lifecycle.Run(ctx, config, subjects)
			case "internal-communication":
				err = communication.Run(ctx, config, subjects)
			case "exported-status":
				err = status.Run(ctx, config, subjects)
			}
			done <- err
		}()
		t.Cleanup(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Error("TLS actor cleanup failed")
				}
			case <-time.After(2 * time.Second):
				t.Error("TLS actor cleanup deadline exceeded")
			}
		})
	}
	// This authenticates a standalone fixture broker. No Docker ownership or
	// installed-host qualification is claimed by this direct pinned-trust test.
	options := KernelStatusOptions{Endpoint: pki.policy.Endpoint, Password: credentials[communication.OrdinaryPlugin], Scope: scope, Timeout: 3 * time.Second, TLS: trust}
	first, err := ObserveKernel(ctx, options)
	if err != nil {
		t.Fatal("real TLS actor snapshot unavailable", err)
	}
	second, err := ObserveKernel(ctx, options)
	if err != nil || second.Incarnation != first.Incarnation || second.Revision <= first.Revision {
		t.Fatal("real TLS late snapshot continuity failed", err)
	}
}

func TestKernelStatusPinnedTLSCancellationJoinsSocket(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			pki := newObserverTLSFixture(t)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal("owned stalled port unavailable")
			}
			defer listener.Close()
			pki.policy.Endpoint = "tls://" + listener.Addr().String()
			trust, err := localtls.NewClientTrust(pki.policy)
			if err != nil {
				t.Fatal("pinned fixture policy rejected")
			}
			ctx, cancel := context.WithCancel(context.Background())
			if mode == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 150*time.Millisecond)
			}
			defer cancel()
			accepted := make(chan struct{})
			serverDone := make(chan bool, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					serverDone <- false
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				buf := make([]byte, 4096)
				n, err := conn.Read(buf)
				if err != nil || n == 0 || bytes.Contains(buf[:n], []byte("CONNECT ")) {
					serverDone <- false
					return
				}
				close(accepted)
				// No TLS response is sent. Cancellation must close the owned socket.
				_, err = conn.Read(buf)
				serverDone <- err != nil
			}()
			result := make(chan error, 1)
			before := time.Now()
			go func() {
				_, err := ObserveKernel(ctx, KernelStatusOptions{Endpoint: pki.policy.Endpoint, Password: strings.Repeat("a", 32), Scope: observerTLSScope(), Timeout: time.Second, TLS: trust})
				result <- err
			}()
			select {
			case <-accepted:
				if mode == "cancel" {
					cancel()
				}
			case <-time.After(time.Second):
				cancel()
				listener.Close()
				<-result
				<-serverDone
				t.Fatal("owned stalled handshake not reached")
			}
			select {
			case err := <-result:
				if err == nil || time.Since(before) > 500*time.Millisecond {
					t.Error("TLS observation ignored caller cancellation")
				}
			case <-time.After(time.Second):
				cancel()
				listener.Close()
				<-result
				t.Error("TLS observation did not finish")
			}
			select {
			case closed := <-serverDone:
				if !closed {
					t.Error("owned handshake socket was not closed")
				}
			case <-time.After(time.Second):
				listener.Close()
				<-serverDone
				t.Error("owned stalled server not joined")
			}
		})
	}
}
