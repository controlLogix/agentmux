//go:build darwin && arm64 && cgo && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
)

// Fixture only. No API parsing, synthetic reply, payload capture or fallback.
// Each direction has one copier. Both copiers join before any result is read.
type endpointProxyStream interface {
	io.ReadWriteCloser
	CloseWrite() error
}

type endpointProxyStreamResult struct {
	ForwardBytes, ReverseBytes             int64
	Failed, Cancelled, CloseFailed, Joined bool
	ForwardStage, ReverseStage             string
	ForwardErrno, ReverseErrno             int
}

// Only standard native wrappers contribute numeric errno. No error text or
// arbitrary user-supplied Unwrap method is called for fixture diagnostics.
func endpointProxyErrno(err error) int {
	for i := 0; i < 8 && err != nil; i++ {
		switch value := err.(type) {
		case syscall.Errno:
			if value > 0 && value < 4096 {
				return int(value)
			}
			return 0
		case *net.OpError:
			if value == nil {
				return 0
			}
			err = value.Err
		case *os.SyscallError:
			if value == nil {
				return 0
			}
			err = value.Err
		default:
			return 0
		}
	}
	return 0
}

var endpointProxyCapError = errors.New("endpoint_proxy_stream_cap")

// Fixture-only lifetime budget. The retained installed case used 272 accepts
// before recovery and exhausted the previous 512 limit. Keep finite headroom
// for both startups, preservation reads and closeout; this is not readiness.
const endpointProxyMaxAccepted = 4096

func endpointProxyConnectionAllowed(active, accepted int) bool {
	return active >= 0 && active < 16 && accepted > 0 && accepted <= endpointProxyMaxAccepted
}

type endpointProxyCapWriter struct {
	destination io.Writer
	remaining   int64
}

func (w *endpointProxyCapWriter) Write(raw []byte) (int, error) {
	if int64(len(raw)) > w.remaining {
		return 0, endpointProxyCapError
	}
	n, err := w.destination.Write(raw)
	w.remaining -= int64(n)
	return n, err
}

// Cancellation closes the exact streams to interrupt both copies, then waits
// for those original goroutines. This function makes no guaranteed exit-time
// claim for a stream whose Close does not unblock its IO. Native streams also
// get fixed deadlines; uncertain owners remain retained by the fixture.
func endpointProxyRelay(ctx context.Context, left, right endpointProxyStream, capBytes int64) endpointProxyStreamResult {
	if ctx == nil || left == nil || right == nil || capBytes < 1 || capBytes > 16*1024*1024 {
		return endpointProxyStreamResult{Failed: true}
	}
	var result endpointProxyStreamResult
	var closeOnce sync.Once
	closeDone := make(chan struct{})
	closeBoth := func() {
		closeOnce.Do(func() {
			a, b := left.Close(), right.Close()
			result.CloseFailed = a != nil || b != nil
			close(closeDone)
		})
	}
	stopCancel := context.AfterFunc(ctx, closeBoth)
	type copied struct {
		bytes  int64
		stage  string
		errno  int
		failed bool
	}
	done := make(chan copied, 2)
	copyOne := func(dst, src endpointProxyStream) copied {
		buffer := make([]byte, 32*1024)
		n, err := io.CopyBuffer(&endpointProxyCapWriter{dst, capBytes}, src, buffer)
		if err != nil {
			closeBoth()
			return copied{n, "copy_io", endpointProxyErrno(err), true}
		}
		if err := dst.CloseWrite(); err != nil {
			// Copy reached clean EOF. A real Unix peer may already have fully
			// disconnected after consuming its response. This one exact native
			// shutdown outcome is terminal, not a failed data copy or Close.
			if endpointProxyDisconnectedAfterEOF(dst, err) {
				return copied{bytes: n, stage: "peer_already_disconnected", errno: int(syscall.ENOTCONN)}
			}
			closeBoth()
			return copied{n, "half_close", endpointProxyErrno(err), true}
		}
		return copied{bytes: n}
	}
	// Separate channels keep byte-count direction independent of finish order.
	forward := make(chan copied, 1)
	go func() { forward <- copyOne(right, left) }()
	go func() { done <- copyOne(left, right) }()
	a, b := <-forward, <-done
	stopCancel()
	closeBoth()
	<-closeDone
	result.ForwardBytes, result.ReverseBytes = a.bytes, b.bytes
	result.ForwardStage, result.ReverseStage = a.stage, b.stage
	result.ForwardErrno, result.ReverseErrno = a.errno, b.errno
	result.Cancelled = ctx.Err() != nil
	result.Failed = (a.failed || b.failed) && !result.Cancelled
	result.Joined = true
	return result
}
