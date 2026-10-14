package deployment

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/localtls"
)

type localTLSCapturePeer struct {
	endpoint string
	accepted chan struct{}
	finished chan []byte
	joined   chan struct{}
}

// This owned peer claims the expected NATS identity without any certificate.
// Captured bytes stay in memory and are never printed or put in evidence.
func newLocalTLSCapturePeer(t *testing.T, sendINFO bool) *localTLSCapturePeer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("capture peer listener unavailable")
	}
	p := &localTLSCapturePeer{endpoint: "tls://" + listener.Addr().String(), accepted: make(chan struct{}), finished: make(chan []byte, 1), joined: make(chan struct{})}
	go func() {
		defer close(p.joined)
		connection, err := listener.Accept()
		if err != nil {
			p.finished <- nil
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
		close(p.accepted)
		if sendINFO {
			_, _ = io.WriteString(connection, "INFO {\"server_id\":\"synthetic-server\",\"server_name\":\"fixture_server\",\"version\":\"2.15.0\",\"proto\":1,\"auth_required\":true,\"tls_required\":false,\"max_payload\":1048576}\r\n")
		}
		var captured bytes.Buffer
		chunk := make([]byte, 4096)
		for captured.Len() < 64*1024 {
			n, err := connection.Read(chunk)
			if n > 0 {
				captured.Write(chunk[:n])
			}
			// End the plain negative control as soon as it actually sends CONNECT.
			if bytes.Contains(captured.Bytes(), []byte("CONNECT ")) || err != nil {
				break
			}
		}
		p.finished <- captured.Bytes()
	}()
	t.Cleanup(func() {
		listener.Close()
		select {
		case <-p.joined:
		case <-time.After(4 * time.Second):
			t.Error("owned capture peer was not joined")
		}
	})
	return p
}

func localTLSCaptureOptions(t *testing.T, p *localTLSCapturePeer, secure bool) ProbeOptions {
	t.Helper()
	m, err := EnrollLocalTLS(context.Background(), localTLSFixtureProfile)
	if err != nil {
		t.Fatal("capture trust enrollment failed")
	}
	_, password := deploymentSecrets(t)
	o := ProbeOptions{Endpoint: p.endpoint, Password: password, HubID: "fixture_hub", ServerName: "fixture_server", Domain: "fixture_domain", ServerVersion: "2.15.0", Timeout: time.Second}
	if secure {
		o.TLS, err = localtls.NewClientTrust(localtls.Policy{Endpoint: p.endpoint, ServerName: m.ServerName(), RootsPEM: m.RootsPEM(), LeafCertificateSHA256: m.LeafCertificateSHA256()})
		if err != nil {
			t.Fatal("capture trust setup failed")
		}
	} else {
		o.Endpoint = "nats://" + p.endpoint[len("tls://"):]
	}
	return o
}

func TestLocalTLSProbeAndObserveDoNotSendCredentialsToPlainINFO(t *testing.T) {
	for _, operation := range []string{"probe", "observe", "legacy-negative-control"} {
		t.Run(operation, func(t *testing.T) {
			peer := newLocalTLSCapturePeer(t, true)
			secure := operation != "legacy-negative-control"
			o := localTLSCaptureOptions(t, peer, secure)
			if operation == "observe" {
				result, err := Observe(context.Background(), ObserveOptions{ProbeOptions: o, ReadExistingRecord: true})
				if err == nil || result.BrokerVerified {
					t.Fatal("plain claimant returned trusted observation")
				}
			} else {
				result, err := ProvisionAndProbe(context.Background(), o)
				if err == nil || result != (ProbeResult{}) {
					t.Fatal("plain claimant returned health proof")
				}
			}
			select {
			case captured := <-peer.finished:
				leaked := bytes.Contains(captured, []byte(o.Password)) || bytes.Contains(captured, []byte("CONNECT "))
				if leaked == secure {
					t.Fatal("capture assertion did not distinguish authenticated TLS from plain legacy control")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("capture peer did not finish before owned cleanup")
			}
		})
	}
}

func TestLocalTLSProbeAndObserveCancelSilentHandshakeAndJoinPeer(t *testing.T) {
	for _, operation := range []string{"probe", "observe"} {
		t.Run(operation, func(t *testing.T) {
			peer := newLocalTLSCapturePeer(t, false)
			o := localTLSCaptureOptions(t, peer, true)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if operation == "probe" {
					_, err := ProvisionAndProbe(ctx, o)
					done <- err
				} else {
					_, err := Observe(ctx, ObserveOptions{ProbeOptions: o, ReadExistingRecord: true})
					done <- err
				}
			}()
			select {
			case <-peer.accepted:
			case <-time.After(time.Second):
				t.Fatal("owned silent handshake was not reached")
			}
			begin := time.Now()
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("canceled TLS connection returned success")
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("TLS handshake ignored caller cancellation")
			}
			if time.Since(begin) > 500*time.Millisecond {
				t.Fatal("TLS caller cancellation exceeded bound")
			}
			select {
			case captured := <-peer.finished:
				if bytes.Contains(captured, []byte(o.Password)) || bytes.Contains(captured, []byte("CONNECT ")) {
					t.Fatal("silent unverified peer received credentials")
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("canceled TLS socket remained open before cleanup")
			}
		})
	}
}
