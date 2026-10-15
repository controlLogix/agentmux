//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/localtls"
	"github.com/nats-io/nats.go"
)

// Capture the actual standard-library wrapper types, not names supplied by an
// error. Unknown wrappers are not invoked, even when they offer Unwrap.
var diagnosticStandardWrappers = []reflect.Type{
	reflect.TypeOf(fmt.Errorf("diagnostic: %w", context.DeadlineExceeded)),
	reflect.TypeOf(fmt.Errorf("%w %w", context.DeadlineExceeded, context.Canceled)),
	reflect.TypeOf(errors.Join(context.DeadlineExceeded)),
}

func diagnosticReviewedWrapper(failure error) bool {
	switch failure.(type) {
	case bootstrapCleanupFailure, *bootstrapCleanupFailure,
		authorityCauseError, *authorityCauseError,
		*dockerInspectionFailure, kernelStatusStageError, *kernelStatusStageError,
		bridgeCompletionCause, *bridgeCompletionCause, *StartingElsewhereError,
		TransportCleanupError, *TransportCleanupError, RuntimeCleanupError, *RuntimeCleanupError,
		deployment.ProbeCleanupError, *deployment.ProbeCleanupError,
		deployment.RawTransportCleanupError, *deployment.RawTransportCleanupError,
		*protocol.CleanupError:
		return true
	}
	actual := reflect.TypeOf(failure)
	for _, known := range diagnosticStandardWrappers {
		if actual == known {
			return true
		}
	}
	return false
}

// Authority failures retain trusted causes for diagnostics and exact cleanup.
// Their outward code and the existing owner-bridge authority sentinel stay fixed.
type authorityCauseError struct {
	code  string
	cause error
}

func (e authorityCauseError) Error() string {
	switch e.code {
	case "bootstrap_local_broker_authority_invalid", "bootstrap_local_broker_authority_unavailable":
		return e.code
	default:
		return "owner_bridge_authority_rejected"
	}
}
func (e authorityCauseError) Format(state fmt.State, _ rune) { fmt.Fprint(state, e.Error()) }
func (e authorityCauseError) MarshalJSON() ([]byte, error)   { return json.Marshal(e.Error()) }
func (e authorityCauseError) Unwrap() error {
	if e.code == "owner_bridge_authority_rejected" {
		return errors.Join(errOwnerBridgeAuthority, e.cause)
	}
	return e.cause
}
func localAuthorityFailure(code string, cause error) error {
	return &authorityCauseError{code: "bootstrap_" + code, cause: cause}
}
func bridgeAuthorityFailure(cause error) error {
	return &authorityCauseError{code: "owner_bridge_authority_rejected", cause: cause}
}

// RequestDiagnostic contains static public text, not an error object or L04
// observation. It grants no authority and exposes no underlying error text.
type RequestDiagnostic struct {
	SchemaVersion string `json:"schemaVersion"`
	Kind          string `json:"kind"`
	Code          string `json:"code"`
	Action        string `json:"action"`
	Message       string `json:"message"`
}

func requestDiagnostic(code string) RequestDiagnostic {
	action, message := "check_local_runtime", "The runtime request failed. Check the enrolled policy and selected local service."
	switch code {
	case "docker_environment_conflict":
		action, message = "use_enrolled_selection", "Remove Docker environment overrides for this launch and use the enrolled local context."
	case "docker_selection_mismatch":
		action, message = "check_enrolled_selection", "The selected Docker engine does not match enrollment. Check the enrolled local context before retrying."
	case "docker_versions_unqualified":
		action, message = "use_qualified_versions", "The selected Docker or Compose version is not qualified. Use the explicitly enrolled supported versions."
	case "docker_configuration_mismatch":
		action, message = "repair_enrolled_configuration", "The Docker configuration does not match enrollment. Repair the explicit local configuration before retrying."
	case "docker_resource_conflict":
		action, message = "inspect_selected_resources", "Selected resources do not match the enrolled instance. Inspect the conflict without deleting data or starting another stack."
	case "docker_command_failed":
		action, message = "check_selected_local_service", "The selected Docker command failed. Check the selected local service; the specific cause is unconfirmed."
	case "docker_command_timeout_outcome_unknown":
		action, message = "inspect_before_retry", "The Docker command timed out and its outcome is unknown. Inspect the selected instance before retrying."
	case "runtime_authority_rejected":
		action, message = "check_enrolled_trust", "Runtime authority was rejected. Check the enrolled identity and server trust; do not bypass authentication."
	case "owned_cleanup_incomplete":
		action, message = "wait_for_owned_cleanup", "Owned cleanup is incomplete. Keep the recovery handles and finish cleanup before retrying."
	case "host_policy_invalid":
		action, message = "check_enrolled_policy", "The enrolled host policy failed validation. Check its declared selection, private access and fields before retrying."
	case "host_profile_invalid":
		action, message = "check_enrolled_profile", "The enrolled profile or bootstrap configuration failed validation. Check the existing profile binding before retrying."
	case "host_enrollment_invalid":
		action, message = "check_enrolled_owner", "The enrolled owner or bridge declarations failed validation. Check the existing identity and credential bindings before retrying."
	case "host_executable_invalid":
		action, message = "check_installed_runtime", "The installed runtime image failed validation. Check the enrolled executable and protected installation before retrying."
	case "request_deadline":
		action, message = "check_status", "The request deadline expired. Check status again; this failure does not establish readiness."
	default:
		code = "request_failed"
	}
	return RequestDiagnostic{"1.0.0", "launcher-diagnostic", code, action, message}
}

// ValidRequestDiagnostic checks the complete fixed representation. It prevents
// a consumer from treating arbitrary messages or substring matches as evidence.
func ValidRequestDiagnostic(value RequestDiagnostic) bool {
	return value == requestDiagnostic(value.Code)
}

// ProjectRequestDiagnostic follows only a bounded error graph. It never calls
// Error, Is or As methods supplied by an unknown error to classify its text.
// The original error and concrete cleanup handles remain with the caller.
func ProjectRequestDiagnostic(failure error) RequestDiagnostic {
	queue := []error{failure}
	var refusalCode, hostCategory string
	hostCategoriesConflict := false
	cleanup, specificAuth, authority, deadline := false, false, false, false
	for inspected := 0; len(queue) > 0; inspected++ {
		if inspected >= 64 {
			return requestDiagnostic("request_failed")
		}
		err := queue[0]
		queue = queue[1:]
		if err == nil || (reflect.ValueOf(err).Kind() == reflect.Pointer && reflect.ValueOf(err).IsNil()) {
			continue
		}
		switch value := err.(type) {
		case *hostPolicyFailure:
			if value != nil {
				category := hostPolicyDiagnosticCategory(value.code)
				if category != "" {
					if hostCategory != "" && hostCategory != category {
						hostCategoriesConflict = true
					}
					hostCategory = category
				}
			}
		case hostPolicyFailure:
			category := hostPolicyDiagnosticCategory(value.code)
			if category != "" {
				if hostCategory != "" && hostCategory != category {
					hostCategoriesConflict = true
				}
				hostCategory = category
			}
		case *dockerRefusalError:
			if value != nil {
				refusalCode = value.code
			}
		case dockerRefusalError:
			refusalCode = value.code
		case bootstrapCleanupFailure, *bootstrapCleanupFailure, *TransportCleanupError, TransportCleanupError, *RuntimeCleanupError, RuntimeCleanupError, *deployment.ProbeCleanupError, deployment.ProbeCleanupError, *deployment.RawTransportCleanupError, deployment.RawTransportCleanupError, *protocol.CleanupError:
			cleanup = true
		}
		cleanup = cleanup || err == ErrTransportCleanup || err == errRuntimeCleanup || err == deployment.ErrProbeCleanup || err == deployment.ErrRawTransportCleanup || err == localtls.ErrCleanup || err == protocol.ErrCleanup
		specificAuth = specificAuth || err == localtls.ErrServerAuthentication || err == localtls.ErrInvalidPolicy || err == nats.ErrAuthorization || err == nats.ErrPermissionViolation || err == nats.ErrAuthExpired || err == nats.ErrAuthRevoked
		authority = authority || err == errOwnerBridgeAuthority || err == errKernelStatusAuthority
		deadline = deadline || err == context.DeadlineExceeded || err == localtls.ErrDeadline
		if !diagnosticReviewedWrapper(err) {
			continue
		}
		switch value := err.(type) {
		case interface{ Unwrap() []error }:
			children := value.Unwrap()
			if len(children) > 63-inspected-len(queue) {
				return requestDiagnostic("request_failed")
			}
			queue = append(queue, children...)
		case interface{ Unwrap() error }:
			if len(queue) >= 63-inspected {
				return requestDiagnostic("request_failed")
			}
			queue = append(queue, value.Unwrap())
		}
	}
	if cleanup {
		return requestDiagnostic("owned_cleanup_incomplete")
	}
	if specificAuth {
		return requestDiagnostic("runtime_authority_rejected")
	}
	switch refusalCode {
	case "environment_conflict":
		return requestDiagnostic("docker_environment_conflict")
	case "invalid_selection", "nonlocal_endpoint", "endpoint_mismatch", "backend_mismatch":
		return requestDiagnostic("docker_selection_mismatch")
	case "invalid_versions", "inline_config_compose_version_unqualified", "unsupported_compose":
		return requestDiagnostic("docker_versions_unqualified")
	case "config_binding_mismatch", "unsupported_inline_config", "unsupported_inline_service", "unused_inline_config", "default_network_missing":
		return requestDiagnostic("docker_configuration_mismatch")
	case "resource_owner_mismatch", "broker_identity_mismatch", "broker_image_mismatch", "broker_roster_mismatch", "broker_data_mount_mismatch", "broker_config_identity_mismatch", "broker_tls_file_mismatch", "broker_port_mismatch", "broker_active_port_mismatch":
		return requestDiagnostic("docker_resource_conflict")
	case "command_failed":
		return requestDiagnostic("docker_command_failed")
	case "command_timeout_outcome_unknown":
		return requestDiagnostic("docker_command_timeout_outcome_unknown")
	}
	if authority {
		return requestDiagnostic("runtime_authority_rejected")
	}
	if deadline {
		return requestDiagnostic("request_deadline")
	}
	if hostCategory != "" && !hostCategoriesConflict {
		return requestDiagnostic(hostCategory)
	}
	return requestDiagnostic("request_failed")
}
