package deployment

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/localtls"
)

type localTLSBrokerFixture struct {
	material *LocalTLSMaterial
	options  ProbeOptions
}

func newLocalTLSBrokerFixture(t *testing.T) *localTLSBrokerFixture {
	t.Helper()
	binary := os.Getenv("AGENTMUX_TEST_NATS")
	if binary == "" {
		t.Fatal("prepared disposable NATS executable required")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("TLS fixture port unavailable")
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	m, p, raw := secureFactoryFixture(t)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "server-cert.pem"), filepath.Join(dir, "server-key.pem")
	if os.WriteFile(certPath, m.ServerCertificatePEM(), 0600) != nil || os.WriteFile(keyPath, m.ServerKeyPEM(), 0600) != nil {
		t.Fatal("private fixture material write failed")
	}
	config, err := decodeSecureBrokerJSON(raw)
	if err != nil {
		t.Fatal("secure fixture JSON invalid")
	}
	// Only fixture-local paths and the disposable port change. No container file
	// installation or Docker injection is qualified by this standalone broker.
	config["listen"] = "127.0.0.1:" + strconv.Itoa(port)
	tls := config["tls"].(map[string]any)
	tls["cert_file"], tls["key_file"] = certPath, keyPath
	path := filepath.Join(dir, "broker.json")
	if os.WriteFile(path, fixtureConfigJSON(t, config), 0600) != nil {
		t.Fatal("private fixture config write failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	check := exec.CommandContext(ctx, binary, "-t", "-c", path)
	check.Stdout, check.Stderr = io.Discard, io.Discard
	err = check.Run()
	cancel()
	if err != nil {
		t.Fatal("pinned broker refused strict TLS configuration")
	}
	cmd := exec.Command(binary, "-c", path)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if cmd.Start() != nil {
		t.Fatal("owned TLS broker failed to start")
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
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
		case <-time.After(3 * time.Second):
			t.Error("owned TLS broker was not joined")
		}
	})
	address := "127.0.0.1:" + strconv.Itoa(port)
	until := time.Now().Add(3 * time.Second)
	ready := false
	for time.Now().Before(until) {
		select {
		case <-done:
			t.Fatal("owned TLS broker exited before readiness")
		default:
		}
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("owned TLS broker listener unavailable")
	}
	health := config["accounts"].(map[string]any)[HealthAccount].(map[string]any)["users"].([]any)[0].(map[string]any)["password"].(string)
	endpoint := "tls://" + address
	trust, err := localtls.NewClientTrust(localtls.Policy{Endpoint: endpoint, ServerName: m.ServerName(), RootsPEM: m.RootsPEM(), LeafCertificateSHA256: m.LeafCertificateSHA256()})
	if err != nil {
		t.Fatal("enrolled client trust invalid")
	}
	return &localTLSBrokerFixture{material: m, options: ProbeOptions{Endpoint: endpoint, Password: health, HubID: p.HubID, ServerName: p.ServerName, Domain: p.Domain, ServerVersion: "2.15.0", Timeout: 3 * time.Second, TLS: trust}}
}

func TestLocalTLSProbeActualStrictBrokerWriteReadAndObservation(t *testing.T) {
	f := newLocalTLSBrokerFixture(t)
	cold, err := ProvisionAndProbe(context.Background(), f.options)
	if err != nil || !cold.Created || cold.Sequence == 0 {
		t.Fatal("authenticated TLS health write/read failed")
	}
	observed, err := Observe(context.Background(), ObserveOptions{ProbeOptions: f.options, ReadExistingRecord: true})
	if err != nil || !observed.BrokerVerified || observed.PersistenceEvidence != PersistenceRecordSeen || observed.RecordSequence != cold.Sequence {
		t.Fatal("authenticated TLS read-only record observation failed")
	}
	warm, err := Probe(context.Background(), f.options)
	if err != nil || warm.Created || warm.Sequence <= cold.Sequence {
		t.Fatal("authenticated TLS warm health probe failed")
	}
}

func TestLocalTLSProbeActualBrokerRefusesWrongTrustBeforeInfrastructureProof(t *testing.T) {
	f := newLocalTLSBrokerFixture(t)
	for _, kind := range []string{"wrong-root", "wrong-dns", "wrong-leaf-pin", "wrong-endpoint"} {
		t.Run(kind, func(t *testing.T) {
			policy := f.options.TLS.Policy()
			switch kind {
			case "wrong-root":
				other, err := EnrollLocalTLS(context.Background(), localTLSFixtureProfile)
				if err != nil {
					t.Fatal("negative CA setup failed")
				}
				policy.RootsPEM = other.RootsPEM()
			case "wrong-dns":
				policy.ServerName = "other.agentmux.invalid"
			case "wrong-leaf-pin":
				policy.LeafCertificateSHA256 = "sha256:" + strings.Repeat("0", 64)
			case "wrong-endpoint":
				policy.Endpoint = "tls://127.0.0.1:1"
			}
			trust, err := localtls.NewClientTrust(policy)
			if err != nil {
				t.Fatal("well-shaped negative trust refused too early")
			}
			options := f.options
			options.TLS = trust
			result, err := ProvisionAndProbe(context.Background(), options)
			if err == nil || result != (ProbeResult{}) {
				t.Fatal("wrong trust returned health proof")
			}
			observed, err := Observe(context.Background(), ObserveOptions{ProbeOptions: options, ReadExistingRecord: true})
			if err == nil || observed.BrokerVerified || observed.PersistenceEvidence != PersistenceUnknown || observed.RecordSequence != 0 {
				t.Fatal("wrong trust returned infrastructure observation")
			}
		})
	}
	// A positive control after all refusals proves the selected broker and policy
	// remain usable; denial is not inferred from an unavailable fixture.
	if result, err := ProvisionAndProbe(context.Background(), f.options); err != nil || result.Sequence == 0 {
		t.Fatal("post-refusal positive control failed")
	}
}
