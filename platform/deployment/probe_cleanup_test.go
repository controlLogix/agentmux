package deployment

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/localtls"
	"github.com/nats-io/nats.go"
)

type probeFailCloseOnce struct {
	net.Conn
	mu    sync.Mutex
	calls int
}

func (c *probeFailCloseOnce) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.calls == 1 {
		return errors.New("private close detail")
	}
	return c.Conn.Close()
}

func probeCleanupSocket(t *testing.T) (ProbeOptions, net.Conn, *localtls.Dialer, <-chan error, context.CancelFunc) {
	return probeCleanupSocketSetup(t, "")
}
func probeCleanupSocketSetup(t *testing.T, stage string) (ProbeOptions, net.Conn, *localtls.Dialer, <-chan error, context.CancelFunc) {
	t.Helper()
	m, err := EnrollLocalTLS(context.Background(), localTLSFixtureProfile)
	if err != nil {
		t.Fatal("offline fixture enrollment failed")
	}
	certificate, err := tls.X509KeyPair(m.ServerCertificatePEM(), m.ServerKeyPEM())
	if err != nil {
		t.Fatal("fixture key pair failed")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("owned peer unavailable")
	}
	peer := make(chan error, 1)
	done := make(chan struct{})
	acceptedSignal := make(chan struct{})
	var peerMu sync.Mutex
	var accepted net.Conn
	stopping := false
	// Install cleanup before starting the peer or doing any fallible setup.
	t.Cleanup(func() {
		peerMu.Lock()
		stopping = true
		exactPeer := accepted
		peerMu.Unlock()
		listenerErr := listener.Close()
		peerClosed := exactPeer == nil
		if exactPeer != nil {
			err := exactPeer.Close()
			peerClosed = err == nil || errors.Is(err, net.ErrClosed)
		}
		joined := false
		select {
		case <-done:
			joined = true
		case <-time.After(time.Second):
			t.Error("owned peer not joined")
		}
		if path := os.Getenv("AMX_PROBE_EARLY_CLEANUP_REPORT"); stage != "" && path != "" {
			raw, _ := json.Marshal(map[string]bool{"joined": joined, "accepted": exactPeer != nil, "peerClosed": peerClosed, "listenerClosed": listenerErr == nil || errors.Is(listenerErr, net.ErrClosed)})
			if os.WriteFile(path, raw, 0600) != nil {
				t.Error("owned cleanup report unavailable")
			}
		}
	})
	go func() {
		defer close(done)
		raw, err := listener.Accept()
		if err != nil {
			peer <- err
			return
		}
		defer raw.Close()
		peerMu.Lock()
		accepted = raw
		stopNow := stopping
		close(acceptedSignal)
		peerMu.Unlock()
		if stopNow {
			raw.Close()
			return
		}
		secure := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}})
		secure.SetDeadline(time.Now().Add(3 * time.Second))
		if err = secure.Handshake(); err != nil {
			peer <- err
			return
		}
		buffer := make([]byte, 4)
		if _, err = io.ReadFull(secure, buffer); err != nil {
			peer <- err
			return
		}
		if _, err = secure.Write([]byte("pong")); err != nil {
			peer <- err
			return
		}
		_, err = secure.Read(buffer)
		peer <- err
	}()
	endpoint := "tls://" + listener.Addr().String()
	policy := localtls.Policy{Endpoint: endpoint, ServerName: m.ServerName(), RootsPEM: m.RootsPEM(), LeafCertificateSHA256: m.LeafCertificateSHA256()}
	if stage == "trust" {
		policy.RootsPEM = []byte("invalid fixture root")
	}
	trust, err := localtls.NewClientTrust(policy)
	if err != nil {
		t.Fatal("fixture trust invalid")
	}
	options := ProbeOptions{Endpoint: endpoint, TLS: trust, Timeout: time.Second}
	if stage == "transport" {
		options.Endpoint = "tls://127.0.0.1:1"
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	transport, retained, plain, err := localProbeTransport(ctx, options)
	if retained != nil {
		t.Cleanup(func() {
			if retained.Close() != nil && retained.Close() != nil {
				t.Error("exact owned dialer cleanup failed")
			}
		})
	}
	if err != nil {
		t.Fatal("actual transport unavailable")
	}
	configured := nats.GetDefaultOptions()
	for _, option := range transport {
		if option(&configured) != nil {
			t.Fatal("transport option failed")
		}
	}
	dialer, ok := configured.CustomDialer.(*localtls.Dialer)
	if !ok || retained != dialer || plain != nil {
		t.Fatal("transport did not retain concrete dialer")
	}
	if stage == "dial" {
		cancel()
	}
	if stage == "accepted-peer" {
		raw, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal("controlled peer connection failed")
		}
		t.Cleanup(func() { raw.Close() })
		select {
		case <-acceptedSignal:
		case <-time.After(time.Second):
			t.Fatal("controlled peer was not accepted")
		}
		t.Fatal("controlled setup failure after exact peer admission")
	}
	socket, err := dialer.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal("authenticated socket unavailable")
	}

	if _, err = socket.Write([]byte("ping")); err != nil {
		t.Fatal("TLS write failed")
	}
	buffer := make([]byte, 4)
	if _, err = io.ReadFull(socket, buffer); err != nil {
		t.Fatal("TLS read failed")
	}
	return options, socket, dialer, peer, cancel
}
func failProbeSocket(t *testing.T, socket net.Conn) {
	t.Helper()
	secure, ok := socket.(*tls.Conn)
	if !ok {
		t.Fatal("actual TLS socket missing")
	}
	field := reflect.ValueOf(secure.NetConn()).Elem().FieldByName("Conn")
	if !field.CanSet() || !field.CanInterface() {
		t.Fatal("owned socket test field missing")
	}
	original, ok := field.Interface().(net.Conn)
	if !ok {
		t.Fatal("owned socket missing")
	}
	field.Set(reflect.ValueOf(&probeFailCloseOnce{Conn: original}))
}
func TestProbeCleanupFailureRetainsConcreteOwner(t *testing.T) {
	for _, code := range []string{"health_connection_cleanup_failed", "observe_connection_cleanup_failed"} {
		for _, mode := range []string{"success", "prior-error", "cancel"} {
			t.Run(code+"-"+mode, func(t *testing.T) {
				_, socket, dialer, peer, cancel := probeCleanupSocket(t)
				failProbeSocket(t, socket)
				var cause error
				if mode == "prior-error" {
					cause = errors.New("private primary error /private/path")
				}
				if mode == "cancel" {
					cause = context.Canceled
					cancel()
				}
				failure, failed := closeProbeTransport(dialer, nil, cause, code)
				var retained *ProbeCleanupError
				if !failed || !errors.As(failure, &retained) || retained.dialer != dialer {
					t.Fatal("cleanup error dropped exact retained socket owner")
				}
				if cause != nil && !errors.Is(failure, cause) {
					t.Fatal("primary error was lost")
				}
				if !errors.Is(failure, localtls.ErrCleanup) {
					t.Fatal("actual socket failure was lost")
				}
				for _, input := range []any{*retained, retained} {
					for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
						if fmt.Sprintf(format, input) != code {
							t.Fatal("private details entered human output")
						}
					}
					raw, err := json.Marshal(input)
					if err != nil || string(raw) != `"`+code+`"` {
						t.Fatal("private details entered JSON")
					}
				}
				select {
				case <-peer:
					t.Fatal("peer closed before exact retry")
				default:
				}
				if retained.Close() != nil || retained.Close() != nil {
					t.Fatal("exact owned retry or idempotence failed")
				}
				select {
				case err := <-peer:
					if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
						t.Fatal("peer did not observe actual socket EOF")
					}
				case <-time.After(time.Second):
					t.Fatal("exact retry retained the actual peer")
				}
			})
		}
	}
}

func TestProbeCleanupEarlyFailureChild(t *testing.T) {
	stage := os.Getenv("AMX_PROBE_EARLY_FAILURE_STAGE")
	if stage == "" {
		return
	}
	switch stage {
	case "trust", "transport", "dial", "accepted-peer":
	default:
		t.Fatal("controlled fixture stage invalid")
	}
	probeCleanupSocketSetup(t, stage)
	t.Fatal("controlled early setup unexpectedly succeeded")
}
func TestProbeCleanupEarlyFailuresJoinOwnedResources(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("owned fixture executable unavailable")
	}
	for _, stage := range []string{"trust", "transport", "dial", "accepted-peer"} {
		t.Run(stage, func(t *testing.T) {
			report := filepath.Join(t.TempDir(), "cleanup.json")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run", "^TestProbeCleanupEarlyFailureChild$", "-test.count=1")
			cmd.Env = append(os.Environ(), "AMX_PROBE_EARLY_FAILURE_STAGE="+stage, "AMX_PROBE_EARLY_CLEANUP_REPORT="+report)
			cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
			err := cmd.Run()
			var exit *exec.ExitError
			if ctx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Fatal("controlled failure process did not exit after joined cleanup")
			}
			raw, err := os.ReadFile(report)
			if err != nil {
				t.Fatal("actual cleanup receipt missing")
			}
			var observed struct{ Joined, Accepted, PeerClosed, ListenerClosed bool }
			if json.Unmarshal(raw, &observed) != nil || !observed.Joined || !observed.PeerClosed || !observed.ListenerClosed || observed.Accepted != (stage == "accepted-peer") {
				t.Fatal("early setup left actual owned resources unjoined")
			}
		})
	}
}
