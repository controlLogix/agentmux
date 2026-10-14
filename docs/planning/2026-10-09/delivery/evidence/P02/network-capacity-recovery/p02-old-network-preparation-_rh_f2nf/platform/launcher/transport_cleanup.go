//go:build linux || darwin

package launcher

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/controlLogix/agentmux/platform/localtls"
)

var ErrTransportCleanup = errors.New("launcher_owned_transport_cleanup_failed")

// TransportCleanupError retains only the exact authenticated dialer whose
// owned socket cleanup failed. Close retries that ownership; it cannot adopt
// a socket, process or caller-selected cleanup operation.
type TransportCleanupError struct {
	dialer *localtls.Dialer
	cause  error
	code   string
}

func (e TransportCleanupError) Error() string {
	if e.code == "owner_bridge_owned_connection_cleanup_failed" || e.code == "kernel_status_owned_connection_cleanup_failed" {
		return e.code
	}
	return ErrTransportCleanup.Error()
}
func (e TransportCleanupError) Format(state fmt.State, _ rune) { fmt.Fprint(state, e.Error()) }
func (e TransportCleanupError) MarshalJSON() ([]byte, error)   { return json.Marshal(e.Error()) }
func (e TransportCleanupError) Unwrap() error {
	return errors.Join(e.cause, ErrTransportCleanup, localtls.ErrCleanup)
}
func (e *TransportCleanupError) Close() error {
	if e == nil || e.dialer == nil {
		return nil
	}
	if e.dialer.Close() != nil {
		return e
	}
	return nil
}

func closeOwnedTransport(dialer *localtls.Dialer, cause error, code string) (error, bool) {
	if dialer != nil && dialer.Close() != nil {
		return &TransportCleanupError{dialer: dialer, cause: cause, code: code}, true
	}
	return cause, false
}
