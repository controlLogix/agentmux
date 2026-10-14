package deployment

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/controlLogix/agentmux/platform/localtls"
)

var ErrProbeCleanup = errors.New("health_owned_transport_cleanup_failed")

// ProbeCleanupError retains the exact authenticated dialer for another Close.
// Its original deadline and owned hooks are unchanged. It cannot adopt a socket
// or invoke a caller-supplied cleanup operation.
type ProbeCleanupError struct {
	dialer *localtls.Dialer
	cause  error
	code   string
}

func (e ProbeCleanupError) Error() string {
	if e.code == "health_connection_cleanup_failed" || e.code == "observe_connection_cleanup_failed" {
		return e.code
	}
	return ErrProbeCleanup.Error()
}
func (e ProbeCleanupError) Format(state fmt.State, _ rune) { fmt.Fprint(state, e.Error()) }
func (e ProbeCleanupError) MarshalJSON() ([]byte, error)   { return json.Marshal(e.Error()) }
func (e ProbeCleanupError) Unwrap() error {
	return errors.Join(e.cause, ErrProbeCleanup, localtls.ErrCleanup)
}
func (e *ProbeCleanupError) Close() error {
	if e == nil || e.dialer == nil {
		return nil
	}
	if e.dialer.Close() != nil {
		return e
	}
	return nil
}
func closeProbeTransport(dialer *localtls.Dialer, plain *observeDialer, cause error, code string) (error, bool) {
	if dialer != nil && dialer.Close() != nil {
		return &ProbeCleanupError{dialer: dialer, cause: cause, code: code}, true
	}
	if plain != nil {
		return closeRawTransport(plain, cause, code)
	}
	return cause, false
}
