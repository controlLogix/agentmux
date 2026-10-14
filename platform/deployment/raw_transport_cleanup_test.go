package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type rawCleanupBlockedClose struct {
	net.Conn
	gate <-chan struct{}
}

func (c *rawCleanupBlockedClose) Close() error { <-c.gate; return c.Conn.Close() }

// The test replaces only an already minted socket's embedded Conn after Dial
// completes. Production has no injection or socket-adoption API.
func rawCleanupSocket(t *testing.T) (*observeDialer, *observeOwnedConnection, net.Conn, context.CancelFunc) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("owned raw peer unavailable")
	}
	ctx, cancel := context.WithCancel(context.Background())
	owner := &observeDialer{ctx: ctx, address: listener.Addr().String()}
	accepted := make(chan net.Conn, 1)
	done := make(chan struct{})
	var peer net.Conn
	t.Cleanup(func() {
		cancel()
		listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("owned accept not joined")
		}
		if peer == nil {
			select {
			case peer = <-accepted:
			default:
			}
		}
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		owner.closeContext(cleanup)
		if owner.closeContext(cleanup) != nil {
			t.Error("exact raw socket cleanup failed")
		}
		if peer != nil {
			peer.Close()
		}
	})
	go func() {
		defer close(done)
		c, e := listener.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	c, err := owner.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal("actual owned TCP dial failed")
	}
	select {
	case peer = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("actual TCP peer did not accept")
	}
	owned, ok := c.(*observeOwnedConnection)
	if !ok {
		t.Fatal("dial did not return its concrete owned socket")
	}
	owned.Conn = &probeFailCloseOnce{Conn: owned.Conn}
	return owner, owned, peer, cancel
}

func rawCleanupRetained(t *testing.T, owner *observeDialer, cause error) (*RawTransportCleanupError, error) {
	t.Helper()
	err, failed := closeRawTransport(owner, cause, "team_connection_cleanup_failed")
	var retained *RawTransportCleanupError
	if !failed || !errors.As(err, &retained) || retained.dialer != owner || !errors.Is(err, ErrRawTransportCleanup) || (cause != nil && !errors.Is(err, cause)) {
		t.Fatal("raw cleanup lost its exact owner or primary cause")
	}
	return retained, err
}

func TestRawTransportCleanupActualSocketFailureAndRetry(t *testing.T) {
	for _, origin := range []string{"owner", "sdk", "cancel"} {
		t.Run(origin, func(t *testing.T) {
			owner, socket, peer, cancel := rawCleanupSocket(t)
			cause := errors.New("private primary detail /private/path")
			if origin == "sdk" {
				if socket.Close() == nil {
					t.Fatal("controlled SDK close did not fail")
				}
			}
			if origin == "cancel" {
				cancel()
				owner.mu.Lock()
				done := owner.sockets[socket].done
				owner.mu.Unlock()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("exact cancellation hook not joined")
				}
			}
			retained, failure := rawCleanupRetained(t, owner, cause)
			for _, value := range []any{retained, *retained} {
				for _, verb := range []string{"%s", "%v", "%+v", "%#v", "%q", "%d"} {
					if text := fmt.Sprintf(verb, value); text != retained.Error() || strings.Contains(text, "private") {
						t.Fatal("raw cleanup formatting disclosed private fields")
					}
				}
				encoded, e := json.Marshal(value)
				if e != nil || strings.Contains(string(encoded), "private") {
					t.Fatal("raw cleanup JSON disclosed private fields")
				}
			}
			if !errors.Is(failure, cause) {
				t.Fatal("safe error lost operational cause")
			}
			if origin == "owner" {
				peer.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
				var b [1]byte
				_, e := peer.Read(b[:])
				var timeout net.Error
				if !errors.As(e, &timeout) || !timeout.Timeout() {
					t.Fatal("failed first close silently released actual socket")
				}
			}
			ctx, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if retained.Close(ctx) != nil || retained.Close(ctx) != nil {
				t.Fatal("bounded exact-owner retry failed")
			}
			peer.SetReadDeadline(time.Now().Add(time.Second))
			var b [1]byte
			if n, e := peer.Read(b[:]); n != 0 || e != io.EOF {
				t.Fatal("actual owned peer has no EOF after cleanup")
			}
			owner.mu.Lock()
			remaining := len(owner.sockets)
			owner.mu.Unlock()
			if remaining != 0 {
				t.Fatal("completed cleanup retained socket/hooks")
			}
		})
	}
}

func TestRawTransportCleanupRetryRespectsHeldGateDeadline(t *testing.T) {
	owner, _, _, _ := rawCleanupSocket(t)
	retained, _ := rawCleanupRetained(t, owner, nil)
	owner.mu.Lock()
	gate := owner.closeGate
	owner.mu.Unlock()
	<-gate
	defer func() { gate <- struct{}{} }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if retained.Close(ctx) != retained || time.Since(start) > 200*time.Millisecond {
		t.Fatal("cleanup retry ignored caller deadline while gate was held")
	}
}

func TestRawTransportCleanupCancellationHookHasBoundedJoin(t *testing.T) {
	owner, socket, _, cancel := rawCleanupSocket(t)
	actual := socket.Conn.(*probeFailCloseOnce).Conn
	gate := make(chan struct{})
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(gate) }) })
	socket.Conn = &rawCleanupBlockedClose{actual, gate}
	cancel()
	start := time.Now()
	retained, _ := rawCleanupRetained(t, owner, context.Canceled)
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Fatal("initial cleanup exceeded its fixed join budget")
	}
	ctx, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	start = time.Now()
	if retained.Close(ctx) != retained || time.Since(start) > 200*time.Millisecond {
		stop()
		t.Fatal("retry left an unbounded cancellation-hook waiter")
	}
	stop()
	release.Do(func() { close(gate) })
	ctx, stop = context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if retained.Close(ctx) != nil {
		t.Fatal("released exact cancellation hook was not joined")
	}
}
