package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

var ErrRawTransportCleanup = errors.New("raw_owned_transport_cleanup_failed")

// RawTransportCleanupError retains only the concrete owner that opened these
// sockets. Retry changes no connection lifetime and cannot adopt another socket.
type RawTransportCleanupError struct {
	dialer *observeDialer
	cause  error
	code   string
}

func (e RawTransportCleanupError) Error() string {
	switch e.code {
	case "team_connection_cleanup_failed", "health_connection_cleanup_failed", "observe_connection_cleanup_failed":
		return e.code
	}
	return ErrRawTransportCleanup.Error()
}
func (e RawTransportCleanupError) Format(state fmt.State, _ rune) { fmt.Fprint(state, e.Error()) }
func (e RawTransportCleanupError) MarshalJSON() ([]byte, error)   { return json.Marshal(e.Error()) }
func (e RawTransportCleanupError) Unwrap() error                  { return errors.Join(e.cause, ErrRawTransportCleanup) }
func (e *RawTransportCleanupError) Close(ctx context.Context) error {
	if e == nil || e.dialer == nil {
		return nil
	}
	if e.dialer.closeContext(ctx) != nil {
		return e
	}
	return nil
}
func closeRawTransport(dialer *observeDialer, cause error, code string) (error, bool) {
	if dialer != nil && dialer.close() != nil {
		return &RawTransportCleanupError{dialer, cause, code}, true
	}
	return cause, false
}
