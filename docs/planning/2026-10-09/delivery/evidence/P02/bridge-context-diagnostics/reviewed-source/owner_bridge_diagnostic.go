//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"fmt"
)

// The private leaf retains the existing code and only an observed standard
// context sentinel. It has no Unwrap method, so operational errors.Is behavior
// remains unchanged. The public projector reads this exact type directly.
type bridgeFailure struct {
	code         string
	contextCause error
}

func (e bridgeFailure) Error() string                { return "owner_bridge_" + e.code }
func (e bridgeFailure) Format(s fmt.State, _ rune)   { fmt.Fprint(s, e.Error()) }
func (e bridgeFailure) MarshalJSON() ([]byte, error) { return json.Marshal(e.Error()) }

// Call only from an executed context-error branch. Other errors and labels
// cannot supply a retained diagnostic cause.
func bridgeContextError(code string, observed error) error {
	if code == "authority_rejected" {
		return errOwnerBridgeAuthority
	}
	value := bridgeFailure{code: code}
	if observed == context.DeadlineExceeded || observed == context.Canceled {
		value.contextCause = observed
	}
	return &value
}
