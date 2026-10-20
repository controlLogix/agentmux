//go:build darwin && arm64 && cgo && agentmux_bootstrap_docker

package launcher

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"syscall"
	"testing"
)

// In-memory streams only. These controls never bind, connect or run a child.
type endpointMemoryStream struct {
	input                     *bytes.Reader
	output                    bytes.Buffer
	mu                        sync.Mutex
	closed, halfClosed        int
	closeFailure, halfFailure bool
	halfErr                   error
	blocked                   chan struct{}
	once                      sync.Once
}

func (s *endpointMemoryStream) Read(raw []byte) (int, error) {
	if s.blocked != nil {
		<-s.blocked
		return 0, io.ErrClosedPipe
	}
	return s.input.Read(raw)
}
func (s *endpointMemoryStream) Write(raw []byte) (int, error) { return s.output.Write(raw) }
func (s *endpointMemoryStream) CloseWrite() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.halfClosed++
	if s.halfErr != nil {
		return s.halfErr
	}
	if s.halfFailure {
		return errors.New("fixed_half_close_failure")
	}
	return nil
}
func (s *endpointMemoryStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed++
	if s.blocked != nil {
		s.once.Do(func() { close(s.blocked) })
	}
	if s.closeFailure {
		return errors.New("fixed_close_failure")
	}
	return nil
}

func endpointMemoryPair(a, b []byte) (*endpointMemoryStream, *endpointMemoryStream) {
	return &endpointMemoryStream{input: bytes.NewReader(a)}, &endpointMemoryStream{input: bytes.NewReader(b)}
}

func TestEndpointProxyPureByteExactAndHalfClose(t *testing.T) {
	a, b := []byte{0, 255, 13, 10, 1}, []byte("HTTP/1.1 200 OK\r\n\x00opaque")
	left, right := endpointMemoryPair(a, b)
	r := endpointProxyRelay(context.Background(), left, right, 1024)
	if !r.Joined || r.Failed || r.Cancelled || r.CloseFailed || !bytes.Equal(right.output.Bytes(), a) || !bytes.Equal(left.output.Bytes(), b) ||
		r.ForwardBytes != int64(len(a)) || r.ReverseBytes != int64(len(b)) || left.closed != 1 || right.closed != 1 || left.halfClosed != 1 || right.halfClosed != 1 {
		t.Fatal("transparent relay lost bytes, half-close, original joins or exact closes")
	}
}

func TestEndpointProxyPureResponseGateCancelsAndJoinsCopies(t *testing.T) {
	left, right := endpointMemoryPair([]byte("actual-request"), []byte("actual-response"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, withheld := false, false
	r := endpointProxyRelay(ctx, left, right, 1024, func(session context.Context) error {
		entered = true
		withheld = left.output.Len() == 0
		cancel()
		return session.Err()
	})
	if !entered || !withheld || !r.Joined || !r.Cancelled || r.Failed || r.CloseFailed || r.ReverseBytes != 0 ||
		left.output.Len() != 0 || left.closed != 1 || right.closed != 1 {
		t.Fatal("real response gate lost withheld bytes, cancellation or original copy ownership")
	}
}

func TestEndpointProxyPureResponseGateForwardsExactBytes(t *testing.T) {
	a, b := []byte("request"), []byte("response")
	left, right := endpointMemoryPair(a, b)
	entered := false
	r := endpointProxyRelay(context.Background(), left, right, 1024, func(context.Context) error { entered = true; return nil })
	if !entered || !r.Joined || r.Failed || r.CloseFailed || !bytes.Equal(left.output.Bytes(), b) || !bytes.Equal(right.output.Bytes(), a) {
		t.Fatal("released response callback changed actual bytes or original owners")
	}
	var output bytes.Buffer
	calls := 0
	writer := endpointProxyResponseWriter{context.Background(), &output, func(context.Context) error { calls++; return nil }}
	if n, err := writer.Write(nil); n != 0 || err != nil || calls != 0 {
		t.Fatal("empty write entered the actual-response gate")
	}
}

func TestEndpointProxyPureOverflowRefuses(t *testing.T) {
	left, right := endpointMemoryPair(bytes.Repeat([]byte{0xff}, 33), nil)
	r := endpointProxyRelay(context.Background(), left, right, 32)
	if !r.Joined || !r.Failed || r.CloseFailed || right.output.Len() > 32 || left.closed != 1 || right.closed != 1 {
		t.Fatal("overflow was forwarded, lost its failure or left streams unjoined")
	}
}

func TestEndpointProxyPureCancellationJoinsOriginalCopies(t *testing.T) {
	left, right := endpointMemoryPair(nil, nil)
	left.blocked, right.blocked = make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := endpointProxyRelay(ctx, left, right, 1024)
	if !r.Joined || !r.Cancelled || r.CloseFailed || left.closed != 1 || right.closed != 1 {
		t.Fatal("cancellation did not close and join both exact stream owners")
	}
}

func TestEndpointProxyPureCloseFailureRetained(t *testing.T) {
	left, right := endpointMemoryPair(nil, nil)
	left.closeFailure = true
	r := endpointProxyRelay(context.Background(), left, right, 1024)
	if !r.Joined || !r.CloseFailed || left.closed != 1 || right.closed != 1 {
		t.Fatal("close failure was presented as complete cleanup")
	}
}

func TestEndpointProxyPureHalfCloseFailureRefuses(t *testing.T) {
	left, right := endpointMemoryPair(nil, nil)
	right.halfFailure = true
	r := endpointProxyRelay(context.Background(), left, right, 1024)
	if !r.Joined || !r.Failed || left.closed != 1 || right.closed != 1 {
		t.Fatal("failed half-close lost failure or exact owner joins")
	}
}

func TestEndpointProxyPureSyntheticNotConnectedStillFails(t *testing.T) {
	left, right := endpointMemoryPair(nil, nil)
	right.halfErr = syscall.ENOTCONN
	r := endpointProxyRelay(context.Background(), left, right, 1024)
	if !r.Joined || !r.Failed || left.closed != 1 || right.closed != 1 {
		t.Fatal("non-native stream acquired disconnected-peer exception")
	}
}

func TestEndpointProxyPureInvalidLimitsDoNotTouchStreams(t *testing.T) {
	for _, capBytes := range []int64{0, -1, 16*1024*1024 + 1} {
		left, right := endpointMemoryPair(nil, nil)
		r := endpointProxyRelay(context.Background(), left, right, capBytes)
		if !r.Failed || r.Joined || left.closed != 0 || right.closed != 0 {
			t.Fatal("invalid bound acquired stream ownership")
		}
	}
}

func TestEndpointProxyPureConnectionCaps(t *testing.T) {
	for _, tc := range []struct {
		active, accepted int
		want             bool
	}{
		{0, 1, true}, {15, 512, true}, {0, 513, true}, {15, 4096, true}, {0, 4097, false},
		{16, 1, false}, {16, 513, false}, {16, 4096, false}, {-1, 1, false}, {0, 0, false},
	} {
		if endpointProxyConnectionAllowed(tc.active, tc.accepted) != tc.want {
			t.Fatal("connection ownership bound changed")
		}
	}
}

func TestEndpointProxyPureFiniteLifetimeBudget(t *testing.T) {
	if endpointProxyMaxAccepted != 4096 {
		t.Fatal("reviewed finite budget changed")
	}
	for accepted := 1; accepted <= 4096; accepted++ {
		if !endpointProxyConnectionAllowed(0, accepted) || !endpointProxyConnectionAllowed(15, accepted) {
			t.Fatal("bounded serialized admission refused before its exact lifetime limit")
		}
		if endpointProxyConnectionAllowed(16, accepted) {
			t.Fatal("lifetime headroom relaxed active ownership cap")
		}
	}
	for _, accepted := range []int{-1, 0, 4097, 8192, int(^uint(0) >> 1)} {
		if endpointProxyConnectionAllowed(0, accepted) {
			t.Fatal("nonpositive or exhausted lifetime count admitted")
		}
	}
}

func TestEndpointProxyPureBudgetKeepsByteAndStreamBounds(t *testing.T) {
	left, right := endpointMemoryPair(nil, nil)
	r := endpointProxyRelay(context.Background(), left, right, 16*1024*1024+1)
	if !r.Failed || r.Joined || left.closed != 0 || right.closed != 0 {
		t.Fatal("lifetime budget relaxed the 16MiB per-direction ceiling")
	}
	var output bytes.Buffer
	w := endpointProxyCapWriter{destination: &output, remaining: 1}
	if n, err := w.Write([]byte{1, 2}); n != 0 || !errors.Is(err, endpointProxyCapError) || output.Len() != 0 || w.remaining != 1 {
		t.Fatal("overflow bytes escaped the unchanged capped writer")
	}
}
