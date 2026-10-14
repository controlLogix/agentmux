//go:build linux || darwin

package launcher

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/localtls"
)

type failOwnedCloseOnce struct {
	net.Conn
	mu    sync.Mutex
	calls int
}

func (c *failOwnedCloseOnce) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.calls == 1 {
		return errors.New("private fixture close detail")
	}
	return c.Conn.Close()
}

// This changes only the test-owned socket's close behavior after authenticated
// TLS and Dial have finished. It neither changes trust nor injects a dialer.
func failExactSocketClose(t *testing.T, conn net.Conn) *failOwnedCloseOnce {
	t.Helper()
	secure, ok := conn.(*tls.Conn)
	if !ok {
		t.Fatal("expected authenticated TLS socket")
	}
	owned := reflect.ValueOf(secure.NetConn())
	if owned.Kind() != reflect.Pointer || owned.IsNil() || owned.Elem().Kind() != reflect.Struct {
		t.Fatal("unexpected owned socket shape")
	}
	field := owned.Elem().FieldByName("Conn")
	if !field.IsValid() || !field.CanSet() || !field.CanInterface() {
		t.Fatal("owned socket close field unavailable")
	}
	original, ok := field.Interface().(net.Conn)
	if !ok || original == nil {
		t.Fatal("exact owned socket unavailable")
	}
	wrapper := &failOwnedCloseOnce{Conn: original}
	field.Set(reflect.ValueOf(wrapper))
	return wrapper
}

func actualCleanupSocket(t *testing.T) (*localtls.Dialer, net.Conn, <-chan error) {
	t.Helper()
	pki := newObserverTLSFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("owned TLS peer unavailable")
	}
	t.Cleanup(func() { listener.Close() })
	pki.policy.Endpoint = "tls://" + listener.Addr().String()
	trust, err := localtls.NewClientTrust(pki.policy)
	if err != nil {
		t.Fatal("fixture trust rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	peer := make(chan error, 1)
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		conn, err := listener.Accept()
		if err != nil {
			peer <- err
			return
		}
		defer conn.Close()
		secure := tls.Server(conn, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pki.cert}})
		secure.SetDeadline(time.Now().Add(3 * time.Second))
		if err := secure.Handshake(); err != nil {
			peer <- err
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(secure, buf); err != nil {
			peer <- err
			return
		}
		if string(buf) != "ping" {
			peer <- errors.New("fixture bytes changed")
			return
		}
		if _, err := secure.Write([]byte("pong")); err != nil {
			peer <- err
			return
		}
		_, err = secure.Read(buf)
		peer <- err
	}()
	dialer, err := trust.NewDialer(ctx, time.Second)
	if err != nil {
		t.Fatal("owned TLS dialer rejected")
	}
	t.Cleanup(func() {
		if dialer.Close() != nil {
			t.Error("fixture-owned dialer cleanup failed")
		}
	})
	t.Cleanup(func() {
		cancel()
		_ = dialer.Close()
		_ = listener.Close()
		select {
		case <-peerDone:
		case <-time.After(time.Second):
			t.Error("fixture-owned peer cleanup did not join")
		}
	})
	conn, err := dialer.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal("actual authenticated socket unavailable")
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal("actual TLS write unavailable")
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "pong" {
		t.Fatal("actual TLS response unavailable")
	}
	return dialer, conn, peer
}

func TestTransportCleanupRetainsActualOwnedSocket(t *testing.T) {
	for _, mode := range []string{"bridge_constructor_authority", "bridge_response", "kernel_response"} {
		t.Run(mode, func(t *testing.T) {
			dialer, socket, peer := actualCleanupSocket(t)
			wrapper := failExactSocketClose(t, socket)
			code := "owner_bridge_owned_connection_cleanup_failed"
			if mode == "kernel_response" {
				code = "kernel_status_owned_connection_cleanup_failed"
			}
			var err error
			if mode == "bridge_constructor_authority" {
				err = closeBridgeConnection(nil, dialer, bridgeError("authority_rejected"))
				if !IsOwnerBridgeAuthorityError(err) {
					t.Fatal("cleanup discarded hard authority cause")
				}
			} else {
				// The actual encrypted response succeeded. Its cleanup still must
				// retain exact ownership and invalidate a public success result.
				result, failure := func() (result string, failure error) {
					result = "observed"
					defer func() {
						cleanup, failed := closeOwnedTransport(dialer, failure, code)
						if failed {
							result = ""
							failure = cleanup
						}
					}()
					return result, nil
				}()
				if result != "" {
					t.Fatal("unknown cleanup retained a public success")
				}
				err = failure
			}
			var retained *TransportCleanupError
			if !errors.As(err, &retained) || !errors.Is(err, ErrTransportCleanup) || !errors.Is(err, localtls.ErrCleanup) {
				t.Fatal("failed cleanup lost concrete ownership")
			}
			select {
			case <-peer:
				t.Fatal("failed close unexpectedly closed physical socket")
			default:
			}
			for _, value := range []any{retained, *retained} {
				for _, verb := range []string{"%v", "%+v", "%#v"} {
					if got := fmt.Sprintf(verb, value); got != code {
						t.Fatal("cleanup formatting leaked private details")
					}
				}
				raw, e := json.Marshal(value)
				if e != nil || strings.Contains(string(raw), "private") || string(raw) != fmt.Sprintf("%q", code) {
					t.Fatal("cleanup JSON leaked ownership details")
				}
			}
			if retained.Close() != nil || retained.Close() != nil {
				t.Fatal("exact owned cleanup retry failed")
			}
			select {
			case err := <-peer:
				if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatal("physical peer did not observe socket exit")
				}
			case <-time.After(time.Second):
				t.Fatal("owned peer not joined")
			}
			wrapper.mu.Lock()
			count := wrapper.calls
			wrapper.mu.Unlock()
			if count != 2 {
				t.Fatal("cleanup retried an unrelated or already closed socket")
			}
		})
	}
}
