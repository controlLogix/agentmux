//go:build linux || darwin

package launcher

import (
	"encoding/json"
	"errors"
	"fmt"
)

// The result still returns this exact Session as its existing cleanup controller.
// No generic Close surface or adopted handle is added to this error wrapper.
type bootstrapCleanupFailure struct {
	session  *Session
	original error
	cleanup  error
}

func (bootstrapCleanupFailure) Error() string                    { return "bootstrap_owned_cleanup_incomplete" }
func (e bootstrapCleanupFailure) Format(state fmt.State, _ rune) { fmt.Fprint(state, e.Error()) }
func (e bootstrapCleanupFailure) MarshalJSON() ([]byte, error)   { return json.Marshal(e.Error()) }
func (e bootstrapCleanupFailure) Unwrap() error                  { return errors.Join(e.original, e.cleanup) }
func retainBootstrapCleanup(session *Session, original, cleanup error) error {
	return &bootstrapCleanupFailure{session: session, original: original, cleanup: cleanup}
}
