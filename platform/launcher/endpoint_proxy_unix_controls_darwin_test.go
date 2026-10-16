//go:build darwin && arm64 && cgo && agentmux_bootstrap_docker

package launcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

var endpointUnixRequest = []byte{0x17, 0, 0xff}
var endpointUnixResponse = []byte{0x91, 0, 0xff, 0x27}

type endpointUnixEvent struct {
	Seq                    int
	Side, Operation, Phase string
	Bytes, Errno           int
	EOF, Closed            bool
}
type endpointUnixTrace struct {
	sync.Mutex
	events []endpointUnixEvent
}

func (x *endpointUnixTrace) add(side, operation, phase string, n int, err error) {
	x.Lock()
	defer x.Unlock()
	x.events = append(x.events, endpointUnixEvent{len(x.events) + 1, side, operation, phase, n, endpointProxyErrno(err), errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed)})
}
func (x *endpointUnixTrace) snapshot() []endpointUnixEvent {
	x.Lock()
	defer x.Unlock()
	return append([]endpointUnixEvent(nil), x.events...)
}

type endpointUnixTraced struct {
	*endpointProxyOwnedConn
	side  string
	trace *endpointUnixTrace
}

func (c *endpointUnixTraced) Read(b []byte) (int, error) {
	c.trace.add(c.side, "read", "begin", 0, nil)
	n, e := c.endpointProxyOwnedConn.Read(b)
	c.trace.add(c.side, "read", "end", n, e)
	return n, e
}
func (c *endpointUnixTraced) Write(b []byte) (int, error) {
	c.trace.add(c.side, "write", "begin", len(b), nil)
	n, e := c.endpointProxyOwnedConn.Write(b)
	c.trace.add(c.side, "write", "end", n, e)
	return n, e
}
func (c *endpointUnixTraced) CloseWrite() error {
	c.trace.add(c.side, "half_close", "begin", 0, nil)
	e := c.endpointProxyOwnedConn.CloseWrite()
	c.trace.add(c.side, "half_close", "end", 0, e)
	return e
}
func (c *endpointUnixTraced) Close() error {
	c.trace.add(c.side, "close", "begin", 0, nil)
	e := c.endpointProxyOwnedConn.Close()
	c.trace.add(c.side, "close", "end", 0, e)
	return e
}

func endpointUnixListener(t *testing.T, name string) (*net.UnixListener, string) {
	t.Helper()
	root, err := os.MkdirTemp("/private/tmp", "amx-ux-")
	if err != nil {
		t.Fatal("private Unix control directory unavailable")
	}
	path := filepath.Join(root, name)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal("private Unix control listen failed")
	}
	l.SetUnlinkOnClose(false)
	if l.SetDeadline(time.Now().Add(5*time.Second)) != nil {
		l.Close()
		t.Fatal("control accept deadline failed")
	}
	var once sync.Once
	t.Cleanup(func() {
		once.Do(func() {
			if l.Close() != nil {
				t.Error("original control listener close failed")
			}
		})
	})
	t.Logf("privateSocket=%s; pathname retained, original listener close registered", path)
	return l, path
}
func endpointUnixOwn(t *testing.T, c *net.UnixConn) *endpointProxyOwnedConn {
	t.Helper()
	owned := &endpointProxyOwnedConn{UnixConn: c}
	t.Cleanup(func() {
		if owned.Close() != nil {
			t.Error("original control connection close failed")
		}
	})
	if c.SetDeadline(time.Now().Add(5*time.Second)) != nil {
		t.Fatal("control stream deadline failed")
	}
	return owned
}
func endpointUnixPair(t *testing.T, name string) (*endpointProxyOwnedConn, *endpointProxyOwnedConn) {
	t.Helper()
	l, path := endpointUnixListener(t, name)
	a, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal("private control dial failed")
	}
	left := endpointUnixOwn(t, a)
	b, err := l.AcceptUnix()
	if err != nil {
		t.Fatal("original private control accept failed")
	}
	return left, endpointUnixOwn(t, b)
}

// The worker keeps its accepted upstream connection OPEN after EOF. Main,
// after joining this worker, explicitly half-closes it to release the relay.
func endpointUnixServe(t *testing.T, peer *endpointProxyOwnedConn, trace *endpointUnixTrace) (chan struct{}, <-chan error, <-chan error) {
	t.Helper()
	gate := make(chan struct{})
	requestRead, done := make(chan error, 1), make(chan error, 1)
	t.Cleanup(func() {
		select {
		case <-gate:
		default:
			close(gate)
		}
		peer.Close()
		deadline := time.After(6 * time.Second)
		for {
			select {
			case _, open := <-done:
				if !open {
					return
				}
			case <-deadline:
				t.Error("original opaque upstream worker unjoined")
				return
			}
		}
	})
	go func() {
		defer close(done)
		request := make([]byte, len(endpointUnixRequest))
		_, err := io.ReadFull(peer, request)
		if err == nil && !bytes.Equal(request, endpointUnixRequest) {
			err = io.ErrUnexpectedEOF
		}
		trace.add("upstream", "request_read", "end", len(request), err)
		requestRead <- err
		if err != nil {
			done <- err
			return
		}
		<-gate
		n, err := peer.Write(endpointUnixResponse)
		trace.add("upstream", "response_write", "end", n, err)
		if err != nil {
			done <- err
			return
		}
		var one [1]byte
		n, err = peer.Read(one[:])
		trace.add("upstream", "read_after_response", "end", n, err)
		if !errors.Is(err, io.EOF) {
			done <- err
			return
		}
		done <- nil
	}()
	return gate, requestRead, done
}

func endpointUnixAwait(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("opaque worker failed errno=%d EOF=%t closed=%t", endpointProxyErrno(err), errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed))
		}
	case <-time.After(6 * time.Second):
		t.Fatal("original opaque worker did not join")
	}
}

func endpointUnixAwaitJoined(t *testing.T, done <-chan error) {
	t.Helper()
	endpointUnixAwait(t, done)
	select {
	case _, open := <-done:
		if open {
			t.Fatal("multiple original worker results")
		}
	case <-time.After(6 * time.Second):
		t.Fatal("original upstream completion channel not closed")
	}
}

func endpointUnixDirect(t *testing.T, mode string) {
	client, left := endpointUnixPair(t, "left.sock")
	right, upstream := endpointUnixPair(t, "right.sock")
	trace := &endpointUnixTrace{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan endpointProxyStreamResult, 1)
	joined := false
	t.Cleanup(func() {
		cancel()
		left.Close()
		right.Close()
		if !joined {
			select {
			case <-done:
				joined = true
			case <-time.After(6 * time.Second):
				t.Error("original relay and copier joins unconfirmed")
			}
		}
	})
	go func() {
		done <- endpointProxyRelay(ctx, &endpointUnixTraced{left, "relay-left", trace}, &endpointUnixTraced{right, "relay-right", trace}, 1024)
	}()
	gate, requestRead, peerDone := endpointUnixServe(t, upstream, trace)
	if _, err := client.Write(endpointUnixRequest); err != nil {
		t.Fatal("opaque client request failed")
	}
	endpointUnixAwait(t, requestRead)
	if mode == "half" || mode == "write-error" {
		if mode == "write-error" {
			e := client.CloseRead()
			trace.add("client", "close_read", "end", 0, e)
			if e != nil {
				t.Fatal("controlled CloseRead failed")
			}
		}
		e := client.CloseWrite()
		trace.add("client", "half_close", "end", 0, e)
		if e != nil {
			t.Fatal("controlled client half-close failed")
		}
	}
	close(gate)
	if mode != "write-error" {
		response := make([]byte, len(endpointUnixResponse))
		_, err := io.ReadFull(client, response)
		trace.add("client", "response_read", "end", len(response), err)
		if err != nil || !bytes.Equal(response, endpointUnixResponse) {
			t.Fatal("opaque response not delivered exactly")
		}
		if mode == "full" {
			e := client.Close()
			trace.add("client", "full_close", "end", 0, e)
			if e != nil {
				t.Fatal("controlled full close failed")
			}
		}
	}
	endpointUnixAwaitJoined(t, peerDone)
	e := upstream.CloseWrite()
	trace.add("upstream", "half_close_after_join", "end", 0, e)
	if mode != "write-error" && e != nil {
		t.Fatal("persistent upstream half-close failed")
	}
	var result endpointProxyStreamResult
	select {
	case result = <-done:
		joined = true
	case <-time.After(6 * time.Second):
		t.Fatal("original relay did not join")
	}
	log, _ := json.Marshal(map[string]any{"mode": mode, "result": result, "orderedWrapperEvents": trace.snapshot(), "originalRelayAndUpstreamJoined": true})
	t.Log(string(log))
	if !result.Joined || result.Cancelled || result.CloseFailed {
		t.Fatal("relay exact close/join accounting failed")
	}
	if mode == "half" && result.Failed {
		t.Fatal("genuine graceful half-close was rejected")
	}
	if mode == "full" && (!result.Failed || result.ReverseStage != "half_close" || result.ReverseErrno != int(syscall.ENOTCONN)) {
		t.Fatal("non-concrete traced stream acquired native EOF exception")
	}
	if mode == "write-error" && (!result.Failed || result.ReverseStage != "copy_io" || result.ReverseErrno != int(syscall.EPIPE)) {
		t.Fatal("genuine peer read refusal did not retain expected EPIPE write failure")
	}
}

func TestEndpointProxyUnixClientFullClosePersistentUpstream(t *testing.T) {
	endpointUnixDirect(t, "full")
}
func TestEndpointProxyUnixGracefulHalfCloseAndEOF(t *testing.T) { endpointUnixDirect(t, "half") }

// The failed CloseRead-to-EPIPE assumption remains in the retained scratch
// capture, not as a passing regression here. The genuine full-close test below
// proves the actual EPIPE boundary without changing that historical result.

func TestEndpointProxyUnixUnexpectedLocalReadAndHalfCloseFailure(t *testing.T) {
	_, left := endpointUnixPair(t, "closed-left.sock")
	right, _ := endpointUnixPair(t, "closed-right.sock")
	trace := &endpointUnixTrace{}
	if left.Close() != nil {
		t.Fatal("controlled original close failed")
	}
	closed := &endpointUnixTraced{left, "closed-relay-left", trace}
	err := closed.CloseWrite()
	if !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed native socket half-close did not fail")
	}
	r := endpointProxyRelay(context.Background(), closed, &endpointUnixTraced{right, "relay-right", trace}, 1024)
	log, _ := json.Marshal(map[string]any{"result": r, "orderedWrapperEvents": trace.snapshot(), "halfCloseOnLocallyClosedSocket": true})
	t.Log(string(log))
	if !r.Joined || !r.Failed || r.Cancelled || r.ForwardStage != "copy_io" {
		t.Fatal("unexpected native local read failure was treated as normal EOF")
	}
}

func TestEndpointProxyUnixPublishedServerResultAfterClientFullClose(t *testing.T) {
	listener, upstreamPath := endpointUnixListener(t, "upstream.sock")
	root, err := os.MkdirTemp("/private/tmp", "amx-px-")
	if err != nil {
		t.Fatal("proxy control root unavailable")
	}
	p, err := endpointProxyStart(filepath.Join(root, "proxy.sock"), upstreamPath)
	if err != nil {
		t.Fatal("ordinary proxy control start failed")
	}
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			p.stop(ctx)
			select {
			case <-p.done:
			default:
				t.Error("original proxy owner unjoined")
			}
		}
	})
	raw, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(root, "proxy.sock"), Net: "unix"})
	if err != nil {
		t.Fatal("ordinary proxy client dial failed")
	}
	client := endpointUnixOwn(t, raw)
	accepted, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal("ordinary proxy upstream accept failed")
	}
	upstream := endpointUnixOwn(t, accepted)
	trace := &endpointUnixTrace{}
	gate, requestRead, peerDone := endpointUnixServe(t, upstream, trace)
	if _, err := client.Write(endpointUnixRequest); err != nil {
		t.Fatal("opaque proxy request failed")
	}
	endpointUnixAwait(t, requestRead)
	close(gate)
	response := make([]byte, len(endpointUnixResponse))
	if _, err := io.ReadFull(client, response); err != nil || !bytes.Equal(response, endpointUnixResponse) {
		t.Fatal("opaque proxy response failed")
	}
	trace.add("client", "response_read", "end", len(response), nil)
	if client.Close() != nil {
		t.Fatal("opaque client original close failed")
	}
	trace.add("client", "full_close", "end", 0, nil)
	endpointUnixAwaitJoined(t, peerDone)
	err = upstream.CloseWrite()
	trace.add("upstream", "half_close_after_join", "end", 0, err)
	if err != nil {
		t.Fatal("persistent upstream close-write failed")
	}
	p.mu.Lock()
	var session *endpointProxySession
	if len(p.sessions) == 1 {
		for s := range p.sessions {
			session = s
		}
	}
	p.mu.Unlock()
	if session == nil {
		t.Fatal("original registered session missing")
	}
	select {
	case <-session.done:
	case <-time.After(6 * time.Second):
		t.Fatal("original server worker did not join")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	pauseErr := p.pause(ctx)
	before := p.diagnosticSnapshot()
	stopErr := p.stop(ctx)
	cancel()
	select {
	case <-p.done:
		stopped = true
	default:
		t.Fatal("original accept loop/workers did not join")
	}
	after := p.diagnosticSnapshot()
	log, _ := json.Marshal(map[string]any{"pauseStage": endpointProxyFailureStage(pauseErr), "pauseFailed": pauseErr != nil, "stopStage": endpointProxyFailureStage(stopErr), "stopFailed": stopErr != nil, "beforeStop": before, "afterStop": after, "orderedPeerEvents": trace.snapshot(), "originalUpstreamWorkerJoined": true})
	t.Log(string(log))
	if after["active"] != 0 || after["accepted"] != 1 || after["sessionsJoined"] != 1 || after["listenerJoined"] != true {
		t.Fatal("published snapshot lost original joins")
	}
	results := after["publishedResults"].([]endpointProxyStreamResult)
	if len(results) != 1 || !results[0].Joined || results[0].Cancelled || results[0].CloseFailed {
		t.Fatal("published transport completion invalid")
	}
	if results[0].Failed || after["failed"] != false || pauseErr != nil || stopErr != nil || p.closeErr != nil {
		t.Fatal("actual owned full-close still fails pause, stop or original close")
	}
	if results[0].ForwardBytes != int64(len(endpointUnixRequest)) || results[0].ReverseBytes != int64(len(endpointUnixResponse)) ||
		results[0].ReverseStage != "peer_already_disconnected" || results[0].ReverseErrno != int(syscall.ENOTCONN) {
		t.Fatal("owned EOF exception lost actual bytes, native errno or closed observation stage")
	}
}

// Separate stimulus: unlike the preserved historical CloseRead test, this
// fully closes the peer after reading the request and observes native EOF
// BEFORE attempting a write. No API response or errno is fabricated.
func TestEndpointProxyUnixGenuineNativeWriteFailureAfterPeerFullClose(t *testing.T) {
	writer, peer := endpointUnixPair(t, "native-write.sock")
	if _, err := writer.Write(endpointUnixRequest); err != nil {
		t.Fatal("native handshake write failed")
	}
	request := make([]byte, len(endpointUnixRequest))
	if _, err := io.ReadFull(peer, request); err != nil || !bytes.Equal(request, endpointUnixRequest) {
		t.Fatal("native peer request read failed")
	}
	if peer.Close() != nil {
		t.Fatal("exact native peer full-close failed")
	}
	var scratch [1]byte
	if _, err := writer.Read(scratch[:]); !errors.Is(err, io.EOF) {
		t.Fatal("native full-close EOF not observed")
	}
	n, err := writer.Write(endpointUnixResponse)
	op, ok := err.(*net.OpError)
	if !ok || op.Op != "write" || op.Net != "unix" || n != 0 || !errors.Is(err, syscall.EPIPE) || endpointProxyDisconnectedAfterEOF(writer, err) {
		t.Fatalf("native full-close write errno=%d; no EPIPE admission assumed", endpointProxyErrno(err))
	}
	left, closedPeer := endpointUnixPair(t, "relay-broken-left.sock")
	if _, err := left.Write(endpointUnixRequest); err != nil {
		t.Fatal("second native handshake write failed")
	}
	if _, err := io.ReadFull(closedPeer, request); err != nil {
		t.Fatal("second native handshake read failed")
	}
	if closedPeer.Close() != nil {
		t.Fatal("second exact peer full-close failed")
	}
	if _, err := left.Read(scratch[:]); !errors.Is(err, io.EOF) {
		t.Fatal("second exact peer EOF not observed")
	}
	right, upstream := endpointUnixPair(t, "relay-write-source.sock")
	if _, err := upstream.Write(endpointUnixResponse); err != nil {
		t.Fatal("opaque relay input write failed")
	}
	if upstream.CloseWrite() != nil {
		t.Fatal("opaque relay input half-close failed")
	}
	r := endpointProxyRelay(context.Background(), left, right, 1024)
	log, _ := json.Marshal(map[string]any{"nativeDirectWriteErrno": endpointProxyErrno(err), "nativeDirectWriteOp": op.Op, "nativeDirectWriteBytes": n,
		"realPeerFullyClosedAfterRequest": true, "relayResult": r, "originalCopiersJoined": r.Joined, "historicalCloseReadEPIPEStimulusNotReclassified": true})
	t.Log(string(log))
	if !r.Joined || !r.Failed || r.Cancelled || r.CloseFailed || r.ReverseStage != "copy_io" || r.ReverseErrno != int(syscall.EPIPE) {
		t.Fatal("real native write failure was suppressed by EOF policy")
	}
}
