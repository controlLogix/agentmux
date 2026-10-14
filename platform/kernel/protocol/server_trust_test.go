//go:build linux || darwin

package protocol

import (
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
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type serverTrustFixture struct {
	record    ServerTrustRecord
	cert, key []byte
}

func serverTrustTestMaterial(t *testing.T) serverTrustFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("fixture CA key unavailable")
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal("fixture CA unavailable")
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("fixture CA decode failed")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("fixture leaf key unavailable")
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), DNSNames: []string{"fixture.agentmux.invalid"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, parsed, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal("fixture leaf unavailable")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal("fixture key encoding failed")
	}
	hash := sha256.Sum256(leafDER)
	return serverTrustFixture{ServerTrustRecord{SchemaVersion: Version, Endpoint: "tls://127.0.0.1:4222", ServerName: "fixture.agentmux.invalid", RootsPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), LeafCertificateSHA256: "sha256:" + hex.EncodeToString(hash[:]), Scope: testScope()}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})}
}

func writeTrustRecord(t *testing.T, record ServerTrustRecord) string {
	t.Helper()
	directory := t.TempDir()
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("private fixture directory unavailable")
	}
	directory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal("fixture canonical path unavailable")
	}
	path := filepath.Join(directory, "server-trust.json")
	raw, err := json.Marshal(record)
	if err != nil || os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("private fixture trust unavailable")
	}
	return path
}

func TestServerTrustRecordFullScopeAndPrivateBindings(t *testing.T) {
	f := serverTrustTestMaterial(t)
	for _, kind := range []string{"hub", "instance", "profile", "assembly", "release", "version", "endpoint", "bare-pin", "mixed-pin", "missing-ca"} {
		t.Run(kind, func(t *testing.T) {
			record := f.record
			switch kind {
			case "hub":
				record.Scope.HubID = "other_hub"
			case "instance":
				record.Scope.InstanceID = "other_instance"
			case "profile":
				record.Scope.ProfileID = "other_profile"
			case "assembly":
				record.Scope.AssemblyDigest = "sha256:" + strings.Repeat("c", 64)
			case "release":
				record.Scope.ReleaseManifestDigest = "sha256:" + strings.Repeat("d", 64)
			case "version":
				record.Scope.ReleaseVersion = "2.0.0"
			case "endpoint":
				record.Endpoint = "tls://127.0.0.1:4223"
			case "bare-pin":
				record.LeafCertificateSHA256 = strings.TrimPrefix(record.LeafCertificateSHA256, "sha256:")
			case "mixed-pin":
				record.LeafCertificateSHA256 = "sha256:" + strings.Repeat("A", 64)
			case "missing-ca":
				record.RootsPEM = ""
			}
			if trust, err := LoadServerTrustFile(writeTrustRecord(t, record), f.record.Scope, f.record.Endpoint); err == nil || trust != nil {
				t.Fatal("otherwise valid trust mismatch accepted")
			}
		})
	}
	for _, kind := range []string{"public-file", "public-parent", "writable-ancestor", "symlink", "hardlink", "fifo", "unknown", "duplicate", "alias", "scope-alias", "missing", "null", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			path := writeTrustRecord(t, f.record)
			raw, _ := os.ReadFile(path)
			switch kind {
			case "public-file":
				os.Chmod(path, 0644)
			case "public-parent":
				os.Chmod(filepath.Dir(path), 0755)
			case "writable-ancestor":
				ancestor := filepath.Join(t.TempDir(), "ancestor")
				if os.Mkdir(ancestor, 0777) != nil || os.Chmod(ancestor, 0777) != nil {
					t.Fatal("ancestor fixture failed")
				}
				directory := filepath.Join(ancestor, "private")
				os.Mkdir(directory, 0700)
				path = filepath.Join(directory, "trust.json")
				os.WriteFile(path, raw, 0600)
			case "symlink":
				os.Rename(path, path+".real")
				if os.Symlink(path+".real", path) != nil {
					t.Fatal("real link fixture failed")
				}
			case "hardlink":
				if os.Link(path, path+".alias") != nil {
					t.Fatal("real hardlink fixture failed")
				}
			case "fifo":
				os.Remove(path)
				if unix.Mkfifo(path, 0600) != nil {
					t.Fatal("actual FIFO fixture failed")
				}
			case "unknown":
				raw = append([]byte(`{"unknown":true,`), raw[1:]...)
			case "duplicate":
				raw = append([]byte(`{"schemaVersion":"1.0.0",`), raw[1:]...)
			case "alias":
				raw = []byte(strings.Replace(string(raw), `"serverName":`, `"ServerName":`, 1))
			case "scope-alias":
				raw = []byte(strings.Replace(string(raw), `"hubId":`, `"HubId":`, 1))
			case "missing":
				raw = []byte(strings.Replace(string(raw), `"schemaVersion":"1.0.0",`, "", 1))
			case "null":
				raw = []byte(`null`)
			case "oversize":
				raw = []byte(strings.Repeat(" ", MaxPayload+1))
			}
			if kind == "unknown" || kind == "duplicate" || kind == "alias" || kind == "scope-alias" || kind == "missing" || kind == "null" || kind == "oversize" {
				os.WriteFile(path, raw, 0600)
			}
			if trust, err := LoadServerTrustFile(path, f.record.Scope, f.record.Endpoint); err == nil || trust != nil {
				t.Fatal("invalid trust file or closed record admitted")
			}
		})
	}
}

func TestServerTrustEnvironmentMandatoryForTLSWithoutCredentialSchemaChange(t *testing.T) {
	f := serverTrustTestMaterial(t)
	path := writeTrustRecord(t, f.record)
	credentials := validCredentials()
	credentials.NATSURL = f.record.Endpoint
	rolePath := filepath.Join(filepath.Dir(path), "role.json")
	raw, _ := json.Marshal(credentials)
	if os.WriteFile(rolePath, raw, 0600) != nil {
		t.Fatal("role fixture unavailable")
	}
	for name, value := range map[string]string{"AGENTMUX_KERNEL_ROLE": "boot", "AGENTMUX_KERNEL_API_MAJOR": "1", "AGENTMUX_NATS_CREDS_FILE": rolePath, "AGENTMUX_INSTANCE_ID": credentials.Scope.InstanceID, "AGENTMUX_PROFILE_ID": credentials.Scope.ProfileID, "AGENTMUX_NATS_URL": credentials.NATSURL, "AGENTMUX_NATS_SERVER_TRUST_FILE": path} {
		t.Setenv(name, value)
	}
	config, err := LoadEnvironment()
	if err != nil || config.ServerTrust == nil || config.Credentials != credentials {
		t.Fatal("mandatory scoped TLS artifact did not load")
	}
	t.Setenv("AGENTMUX_NATS_SERVER_TRUST_FILE", "")
	if _, err := LoadEnvironment(); err == nil {
		t.Fatal("TLS role booted without enrolled server trust")
	}
	t.Setenv("AGENTMUX_NATS_SERVER_TRUST_FILE", path)
	credentials.NATSURL = "nats://127.0.0.1:4222"
	raw, _ = json.Marshal(credentials)
	os.WriteFile(rolePath, raw, 0600)
	t.Setenv("AGENTMUX_NATS_URL", credentials.NATSURL)
	if _, err := LoadEnvironment(); err == nil {
		t.Fatal("plain role silently ignored its TLS trust reference")
	}
}

func TestRealActorUsesPinnedTLSFirstAndReconnectsOnlyToEnrolledEndpoint(t *testing.T) {
	binary := os.Getenv("AGENTMUX_TEST_NATS")
	if binary == "" {
		t.Fatal("prepared actual NATS fixture required")
	}
	f := serverTrustTestMaterial(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("fixture port unavailable")
	}
	address := listener.Addr().String()
	listener.Close()
	f.record.Endpoint = "tls://" + address
	directory := t.TempDir()
	certPath, keyPath := filepath.Join(directory, "cert.pem"), filepath.Join(directory, "key.pem")
	os.WriteFile(certPath, f.cert, 0600)
	os.WriteFile(keyPath, f.key, 0600)
	secret := strings.Repeat("a", 48)
	trap, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("owned discovery trap listener unavailable")
	}
	defer trap.Close()
	document := map[string]any{"listen": address, "authorization": map[string]any{"users": []any{map[string]any{"user": "boot", "password": secret}}}}
	document["tls"] = map[string]any{"cert_file": certPath, "key_file": keyPath, "min_version": "1.3", "handshake_first": true}
	document["server_name"] = "fixture_server"
	document["client_advertise"] = trap.Addr().String()
	raw, _ := json.Marshal(document)
	configPath := filepath.Join(directory, "nats.json")
	if os.WriteFile(configPath, raw, 0600) != nil {
		t.Fatal("broker fixture config failed")
	}
	var cmd *exec.Cmd
	var done chan error
	start := func() {
		cmd = exec.Command(binary, "-c", configPath)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if cmd.Start() != nil {
			t.Fatal("actual TLS actor broker start failed")
		}
		done = make(chan error, 1)
		current := cmd
		finished := done
		go func() { finished <- current.Wait(); close(finished) }()
	}
	stop := func() {
		if cmd == nil {
			return
		}
		cmd.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(time.Second):
			cmd.Process.Kill()
			<-done
		}
		cmd = nil
	}
	start()
	t.Cleanup(stop)
	trust, err := ValidateServerTrustRecord(f.record, f.record.Scope, f.record.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	prefix := "amx.v1.h.fixture_hub.kernel."
	subjects := SubjectSet{Commands: map[string]string{}, Events: map[string]string{}, Snapshot: prefix + "status.snapshot", Update: prefix + "status.update"}
	for _, role := range Roles() {
		subjects.Commands[role] = prefix + "internal." + role + ".command"
		subjects.Events[role] = prefix + "internal." + role + ".event"
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	config := Config{Credentials: Credentials{Version, "boot", "boot", secret, f.record.Endpoint, f.record.Scope}, ServerTrust: trust}
	var actor *Actor
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		actor, err = Open(ctx, config, "boot", subjects)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || actor == nil {
		t.Fatal("actual scoped actor TLS-first connection failed")
	}
	defer actor.Close()
	state, err := actor.conn.TLSConnectionState()
	if err != nil || state.Version != tls.VersionTLS13 {
		t.Fatal("actor did not authenticate through TLS1.3")
	}
	if len(actor.conn.DiscoveredServers()) != 0 {
		t.Fatal("actor accepted an unapproved advertised endpoint")
	}
	stop()
	until = time.Now().Add(time.Second)
	for actor.connected.Load() && time.Now().Before(until) {
		time.Sleep(10 * time.Millisecond)
	}
	if actor.connected.Load() {
		t.Fatal("stopped broker did not disconnect actor")
	}
	start()
	until = time.Now().Add(3 * time.Second)
	for !actor.connected.Load() && time.Now().Before(until) {
		time.Sleep(10 * time.Millisecond)
	}
	if !actor.connected.Load() || actor.conn.ConnectedUrl() != f.record.Endpoint {
		t.Fatal("actor did not reconnect to its pinned enrolled endpoint")
	}
	if actor.conn.FlushTimeout(time.Second) != nil {
		t.Fatal("reconnected actor TLS socket unavailable")
	}
}
