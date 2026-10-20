//go:build linux || darwin

package launcher

import (
	"encoding/json"
	"fmt"
)

// Presentation remains the existing fixed code. Protected installed-runtime
// admission may also retain its original cause for exact cleanup ownership.
type hostPolicyFailure struct {
	code  string
	cause error
}

func (e hostPolicyFailure) Error() string                { return "host_policy_" + e.code }
func (e hostPolicyFailure) Format(s fmt.State, _ rune)   { fmt.Fprint(s, e.Error()) }
func (e hostPolicyFailure) MarshalJSON() ([]byte, error) { return json.Marshal(e.Error()) }
func (e hostPolicyFailure) Unwrap() error                { return e.cause }

// Only constructor codes already returned by the reviewed policy sources gain
// a public category. Error strings and unknown wrappers grant no category.
func hostPolicyDiagnosticCategory(code string) string {
	switch code {
	case "private_root_invalid", "workspace_invalid", "inside_workspace", "private_root_unavailable", "private_root_changed", "ancestor_changed", "ancestor_invalid", "ancestor_untrusted", "ancestor_access_denied", "selection_invalid", "private_policy_root_invalid", "private_policy_invalid", "fields_invalid", "decode_invalid", "declarations_invalid", "unconfigured":
		return "host_policy_invalid"
	case "profile_invalid", "profile_binding_invalid", "bootstrap_config_invalid":
		return "host_profile_invalid"
	case "owner_binding_invalid", "owner_enrollment_invalid", "bridge_unconfigured", "bridge_private_root_invalid", "bridge_reference_invalid", "bridge_credential_invalid", "bridge_fields_invalid", "bridge_binding_invalid", "receipt_enrollment_invalid":
		return "host_enrollment_invalid"
	case "executable_unqualified", "executable_root_invalid", "executable_invalid", "executable_changed":
		return "host_executable_invalid"
	default:
		return ""
	}
}
