package deployment

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func probeStalledPeer(t *testing.T, tls bool) (string, <-chan struct{}, <-chan struct{}, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("owned stalled peer unavailable")
	}
	ready, done := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var connection net.Conn
	closed := false
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			listener.Close()
			mu.Lock()
			closed = true
			if connection != nil {
				connection.Close()
			}
			mu.Unlock()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("owned stalled peer did not finish cleanup")
			}
		})
	}
	t.Cleanup(cleanup)
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		mu.Lock()
		if closed {
			mu.Unlock()
			conn.Close()
			return
		}
		connection = conn
		mu.Unlock()
		defer conn.Close()
		if tls {
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.WriteString(conn, "INFO {\"server_id\":\"fixture_server\",\"server_name\":\"fixture_server\",\"version\":\"2.15.0\",\"proto\":1,\"tls_required\":true,\"max_payload\":1048576}\r\n"); err != nil {
				return
			}
			var handshake [1]byte
			if _, err := io.ReadFull(conn, handshake[:]); err != nil || handshake[0] != 22 {
				return
			}
		}
		close(ready)
		io.Copy(io.Discard, conn)
	}()
	scheme := "nats://"
	if tls {
		scheme = "tls://"
	}
	return scheme + listener.Addr().String(), ready, done, cleanup
}

func TestProbeCancellationInterruptsActualGreetingAndTLS(t *testing.T) {
	for _, cold := range []bool{false, true} {
		for _, tls := range []bool{false, true} {
			name := "warm-greeting"
			if cold {
				name = "cold-greeting"
			}
			if tls {
				name += "-tls"
			}
			t.Run(name, func(t *testing.T) {
				endpoint, ready, peerDone, cleanupPeer := probeStalledPeer(t, tls)
				ctx, cancel := context.WithCancel(context.Background())
				finished := make(chan struct{})
				var result ProbeResult
				var probeErr error
				go func() {
					defer close(finished)
					options := ProbeOptions{Endpoint: endpoint, Password: strings.Repeat("a", 48), HubID: "fixture_hub", ServerName: "fixture_server", Domain: "fixture_domain", ServerVersion: "2.15.0", Timeout: 5 * time.Second}
					if cold {
						result, probeErr = ProvisionAndProbe(ctx, options)
					} else {
						result, probeErr = Probe(ctx, options)
					}
				}()
				t.Cleanup(func() {
					cancel()
					cleanupPeer()
					select {
					case <-finished:
					case <-time.After(time.Second):
						t.Error("owned probe goroutine did not finish cleanup")
					}
				})
				select {
				case <-ready:
				case <-time.After(time.Second):
					t.Fatal("probe did not reach the actual selected greeting or TLS handshake")
				}
				cancel()
				select {
				case <-finished:
				case <-time.After(500 * time.Millisecond):
					t.Fatal("caller cancellation waited for the full connection timeout")
				}
				if probeErr == nil || probeErr.Error() != "health_deadline" || result != (ProbeResult{}) {
					t.Fatal("cancelled setup returned facts or the wrong closed failure code")
				}
				// Observe client closure before forced peer cleanup; cleanup must not
				// manufacture the socket-close evidence this assertion requires.
				select {
				case <-peerDone:
				case <-time.After(500 * time.Millisecond):
					t.Fatal("cancelled probe retained its owned connection")
				}
			})
		}
	}
}
