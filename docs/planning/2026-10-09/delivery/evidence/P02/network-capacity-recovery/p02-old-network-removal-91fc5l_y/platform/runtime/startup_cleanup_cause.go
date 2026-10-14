package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Keep both failures available to trusted callers without exposing startup
// paths through the combined failure's presentation. The returned Group still
// owns the exact children and their cleanup; this error cannot adopt a process.
type startupCleanupCause struct {
	cause error
}

func (startupCleanupCause) Error() string                    { return "startup failed; owned cleanup incomplete" }
func (e startupCleanupCause) Format(state fmt.State, _ rune) { fmt.Fprint(state, e.Error()) }
func (e startupCleanupCause) MarshalJSON() ([]byte, error)   { return json.Marshal(e.Error()) }
func (e startupCleanupCause) Unwrap() error                  { return e.cause }

func retainStartupCleanupCause(startup, cleanup error) error {
	return &startupCleanupCause{cause: errors.Join(startup, cleanup)}
}
