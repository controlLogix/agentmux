//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
)

var errLocalPortCleanup = errors.New("local_port_owned_listener_cleanup_failed")

// LocalPortCleanupError retains only the listener created by the cold native
// preflight. It grants no authority over the listener occupying a selected port.
// Failed Close results remain errors; no raw descriptor or PID is retried.
type LocalPortCleanupError struct {
	mu               sync.Mutex
	listener         *net.TCPListener
	closeFailure     error
	lastCloseFailure error
	cause            error
}

func (*LocalPortCleanupError) Error() string                  { return "local_port_owned_listener_cleanup_failed" }
func (e *LocalPortCleanupError) Format(s fmt.State, _ rune)   { fmt.Fprint(s, e.Error()) }
func (e *LocalPortCleanupError) MarshalJSON() ([]byte, error) { return json.Marshal(e.Error()) }
func (e *LocalPortCleanupError) Unwrap() error {
	if e == nil {
		return errLocalPortCleanup
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return errors.Join(errLocalPortCleanup, e.cause, e.closeFailure, e.lastCloseFailure)
}
func (e *LocalPortCleanupError) Close() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.listener == nil {
		return nil
	}
	if err := e.listener.Close(); err != nil {
		// Even an already-closed response cannot erase the recorded failed
		// cleanup or manufacture a successful original Close observation.
		e.lastCloseFailure = err
		return e
	}
	e.listener = nil
	return nil
}

// finishLocalPortProbe consumes the actual Close result at the production call
// site. Keeping this small ownership boundary separate lets tests model a failed
// close with a real held listener, without adding a configurable cleanup hook.
func finishLocalPortProbe(listener *net.TCPListener, closeFailure, cause error) error {
	if closeFailure != nil {
		return &LocalPortCleanupError{listener: listener, closeFailure: closeFailure, cause: cause}
	}
	return cause
}

// Inspect only concrete OS wrappers from this probe's net.ListenConfig call.
// Unknown errors and their Error/Is/As/Unwrap methods are never consulted.
func localPortAddressInUse(failure error) bool {
	operation, ok := failure.(*net.OpError)
	if !ok || operation == nil || operation.Op != "listen" || operation.Net != "tcp4" {
		return false
	}
	call, ok := operation.Err.(*os.SyscallError)
	if !ok || call == nil || call.Syscall != "bind" {
		return false
	}
	errno, ok := call.Err.(syscall.Errno)
	return ok && errno == syscall.EADDRINUSE
}

// preflightLocalPort is called only by an admitted cold bootstrap, after actual
// engine/resource inspection and bootstrap lease acquisition. Warm reuse must
// return before this call. This transient bind does not reserve the port for
// Compose or establish the cause of any subsequent Docker failure.
func preflightLocalPort(ctx context.Context, backend DockerBackend, port int) error {
	if ctx == nil {
		return bootstrapError("local_port_context_invalid")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if backend == WindowsInterop {
		// Retained legacy interop gets no native-host observation or new claim.
		return nil
	}
	if backend != NativeUnix {
		return bootstrapError("local_port_selection_invalid")
	}
	if _, ok := ctx.Deadline(); !ok || port < 1 || port > 65535 {
		return bootstrapError("local_port_context_invalid")
	}
	config := net.ListenConfig{}
	listener, err := config.Listen(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		if canceled := ctx.Err(); canceled != nil {
			return canceled
		}
		if localPortAddressInUse(err) {
			return refusal("selected_host_port_occupied")
		}
		return bootstrapError("local_port_probe_unavailable")
	}
	// tcp4 is fixed above: the standard library returns a TCPListener. No
	// caller-selected dialer, listener factory, address or callback is admitted.
	tcp := listener.(*net.TCPListener)
	cause := ctx.Err()
	closeFailure := tcp.Close()
	if cause == nil {
		cause = ctx.Err()
	}
	return finishLocalPortProbe(tcp, closeFailure, cause)
}
