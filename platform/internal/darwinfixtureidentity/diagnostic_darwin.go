//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"errors"
	"reflect"

	"golang.org/x/sys/unix"
)

var diagnosticJoinType = reflect.TypeOf(errors.Join(ErrExited, ErrExited))

type ChildRosterDiagnostic struct {
	Reason                 string `json:"reason"`
	ExpectedCount          int    `json:"expectedCount"`
	ExpectedImageMatched   bool   `json:"expectedImageMatched"`
	ParentImageMatched     bool   `json:"parentImageMatched"`
	ParentArgumentsMatched bool   `json:"parentArgumentsMatched"`
	ExpectedArguments      int    `json:"expectedArguments"`
	ObservedArguments      int    `json:"observedArguments"`
	FirstDifferentArgument int    `json:"firstDifferentArgument"`
}

// The original opaque anchor stays reachable through this exact failure. This
// is an in-process owner; serializing its diagnostic never transfers authority.
type childMismatchOwner struct {
	anchor     *Proof
	diagnostic ChildRosterDiagnostic
}

type ChildScanDiagnostic struct {
	Reason                string `json:"reason"`
	IdentityCompared      bool   `json:"identityCompared"`
	PIDMatched            bool   `json:"pidMatched"`
	VersionMatched        bool   `json:"versionMatched"`
	CreationMatched       bool   `json:"creationMatched"`
	CreationParentMatched bool   `json:"creationParentMatched"`
	UIDMatched            bool   `json:"uidMatched"`
	RealUIDMatched        bool   `json:"realUidMatched"`
}

type childScanOwner struct {
	anchor     *Proof
	diagnostic ChildScanDiagnostic
}

func ChildScanDiagnostics(cause error) []ChildScanDiagnostic {
	queue := []error{cause}
	var out []ChildScanDiagnostic
	for visited := 0; len(queue) != 0 && visited < 64; visited++ {
		current := queue[0]
		queue = queue[1:]
		if current == nil {
			continue
		}
		if known, ok := current.(*failure); ok && known != nil {
			if known.stage == "fixture_inspection_owner_retained" {
				queue = append(queue, known.cause)
			}
			if owner, ok := known.retained.(*childScanOwner); ok && owner != nil {
				out = append(out, owner.diagnostic)
			}
			continue
		}
		if reflect.TypeOf(current) == diagnosticJoinType {
			children := current.(interface{ Unwrap() []error }).Unwrap()
			if len(children) > 64-visited-len(queue) {
				break
			}
			queue = append(queue, children...)
		}
	}
	return out
}

func ChildRosterDiagnostics(cause error) []ChildRosterDiagnostic {
	queue := []error{cause}
	var out []ChildRosterDiagnostic
	for visited := 0; len(queue) != 0 && visited < 64; visited++ {
		current := queue[0]
		queue = queue[1:]
		if current == nil {
			continue
		}
		if known, ok := current.(*failure); ok && known != nil {
			if owned, ok := known.retained.(*childMismatchOwner); ok && owned != nil {
				out = append(out, owned.diagnostic)
			}
			continue
		}
		if reflect.TypeOf(current) == diagnosticJoinType {
			children := current.(interface{ Unwrap() []error }).Unwrap()
			if len(children) > 64-visited-len(queue) {
				break
			}
			queue = append(queue, children...)
		}
	}
	return out
}

// FailureCategories returns fixed native admission categories. It never calls
// error or unwrap methods on an unknown error, or presents a private cause.
func FailureCategories(cause error) []string {
	queue := []error{cause}
	seen := map[string]bool{}
	var categories []string
	add := func(code string) {
		if !seen[code] {
			seen[code] = true
			categories = append(categories, code)
		}
	}
	for visited := 0; len(queue) != 0; visited++ {
		if visited >= 64 {
			add("fixture_diagnostic_limit")
			break
		}
		current := queue[0]
		queue = queue[1:]
		if current == nil {
			continue
		}
		if current == childNotPresent {
			add("fixture_child_not_present")
			continue
		}
		if current == noSurvivingHost {
			add("fixture_no_surviving_host")
			continue
		}
		if known, ok := current.(*failure); ok && known != nil {
			if known.stage == "fixture_child_watch_registration_refused" {
				if detail, ok := known.cause.(*failure); ok && detail != nil && watchRegistrationFailureCategory(detail.stage) {
					queue = append(queue, detail)
				}
			}
			if known.stage == "fixture_inspection_owner_retained" {
				queue = append(queue, known.cause)
			}
			if known.stage == "fixture_child_exec_incomplete" {
				if state, ok := known.retained.(*childExecTransition); ok && state != nil {
					if pending, ok := state.pending.(*failure); ok && pending != nil && (pending.stage == "fixture_child_exec_in_progress" || pending.stage == "fixture_child_arguments_refused") {
						queue = append(queue, pending)
					}
				}
			}
			if known.stage == "fixture_child_arguments_refused" || known.stage == "fixture_inspection_arguments_refused" {
				if detail, ok := known.cause.(*failure); ok && detail != nil && argumentFailureCategory(detail.stage) {
					queue = append(queue, detail)
				}
			}
			if known.stage == "fixture_child_scan_changed" {
				if detail, ok := known.cause.(*failure); ok && detail != nil && (detail.stage == "fixture_child_scan_observation_refused" || detail.stage == "fixture_child_scan_identity_changed") {
					queue = append(queue, detail)
				}
			}
			if known.stage == "fixture_child_scan_observation_refused" || known.stage == "fixture_inspection_identity_refused" || known.stage == "fixture_inspection_watch_identity_refused" {
				if detail, ok := known.cause.(*failure); ok && detail != nil && nativeObservationFailureCategory(detail.stage) {
					queue = append(queue, detail)
				}
			}
			// Only these scan wrappers may disclose a fixed candidate stage.
			// Do not unwrap arbitrary causes or expose native error text.
			if known.stage == "fixture_child_scan_refused" || known.stage == "fixture_child_roster_changed" {
				if candidate, ok := known.cause.(*failure); ok && candidate != nil && candidateFailureCategory(candidate.stage) {
					queue = append(queue, candidate)
				}
			}
			if known.stage == "fixture_candidate_identity_refused" {
				if detail, ok := known.cause.(*failure); ok && detail != nil && nativeObservationFailureCategory(detail.stage) {
					queue = append(queue, detail)
				}
			}
			switch known.stage {
			case "fixture_watch_registration_syscall", "fixture_watch_registration_ev_error":
				add(known.stage)
				add(watchRegistrationErrnoCategory(known.cause))
			case "fixture_watch_registration_exit", "fixture_watch_registration_exec", "fixture_watch_registration_unexpected":
				add(known.stage)
			case "fixture_inspection_owner_retained", "fixture_inspection_selection_invalid", "fixture_inspection_image_refused", "fixture_inspection_image_changed", "fixture_inspection_image_unavailable", "fixture_inspection_observation_refused", "fixture_inspection_watch_identity_refused", "fixture_inspection_watch_invalid", "fixture_inspection_identity_refused", "fixture_inspection_path_refused", "fixture_inspection_arguments_refused", "fixture_inspection_postwatch_admission_refused", "fixture_inspection_proof_missing", "fixture_live_host_identity_refused", "fixture_host_exit_required", "fixture_child_scan_observation_refused", "fixture_child_scan_identity_changed", "fixture_child_exec_deadline_required",
				"fixture_child_exec_in_progress", "fixture_child_exec_incomplete", "fixture_child_exec_owner_retained":
				add(known.stage)
			case "fixture_arguments_allocation_refused", "fixture_arguments_query_refused", "fixture_arguments_layout_refused",
				"fixture_arguments_buffer_refused", "fixture_arguments_count_refused", "fixture_arguments_header_refused", "fixture_arguments_shape_refused":
				add(known.stage)
				if known.stage == "fixture_arguments_query_refused" {
					add(nativeQueryErrnoCategory(known.cause))
				}
			case "fixture_native_query_refused":
				add(known.stage)
				add(nativeQueryErrnoCategory(known.cause))
			case "fixture_native_layout_refused", "fixture_native_identity_refused",
				"fixture_native_status_refused", "fixture_native_process_exited", "fixture_candidate_lineage_refused", "fixture_candidate_credentials_refused":
				add(known.stage)
			case "fixture_candidate_parent_invalid", "fixture_candidate_admission_invalid", "fixture_candidate_admission_refused",
				"fixture_candidate_enumeration_refused", "fixture_candidate_identity_refused":
				add(known.stage)
			case "fixture_context_invalid", "fixture_role_admission_cancelled", "fixture_role_arguments_refused", "fixture_role_assembly_refused", "fixture_role_images_refused",
				"fixture_role_images_unavailable", "fixture_role_images_revalidation_refused", "fixture_role_images_close_failed", "fixture_role_image_check_close_failed",
				"fixture_child_scan_cancelled", "fixture_child_roster_invalid", "fixture_child_scan_refused", "fixture_child_roster_count_refused", "fixture_child_roster_ambiguous",
				"fixture_child_scan_changed", "fixture_child_path_refused", "fixture_child_arguments_refused", "fixture_child_roster_unexpected", "fixture_child_image_refused",
				"fixture_child_watch_unavailable", "fixture_child_image_close_failed", "fixture_child_watch_registration_refused", "fixture_child_identity_changed",
				"fixture_child_admission_event_refused", "fixture_child_postwatch_admission_refused", "fixture_child_postwatch_image_refused", "fixture_child_roster_changed",
				"fixture_proof_invalid", "fixture_watch_failed", "fixture_unexpected_process_event", "fixture_observation_failed", "fixture_identity_changed",
				"fixture_watch_close_failed", "fixture_image_close_failed",
				"fixture_client_operation_refused", "fixture_client_package_refused", "fixture_client_declaration_refused", "fixture_client_launch_refused",
				"fixture_client_close_failed", "fixture_client_creation_changed", "fixture_client_exec_refused", "fixture_client_creation_unavailable",
				"fixture_client_exec_incomplete", "fixture_client_observation_failed", "fixture_client_observation_changed", "fixture_client_package_changed",
				"fixture_client_prestart_changed", "fixture_postwatch_client_changed":
				add(known.stage)
			default:
				add("fixture_unclassified_failure")
			}
			// Other causes may contain arbitrary OS, image or application text.
			continue
		}
		if reflect.TypeOf(current) == diagnosticJoinType {
			children := current.(interface{ Unwrap() []error }).Unwrap()
			if len(children) > 64-visited-len(queue) {
				add("fixture_diagnostic_limit")
				break
			}
			queue = append(queue, children...)
			continue
		}
		add("fixture_unclassified_failure")
	}
	return categories
}

// Only the concrete errno retained by the original native query supplies this
// diagnostic. Wrappers and error text never establish a native cause or change
// the query's terminal refusal into an absence result.
func nativeQueryErrnoCategory(cause error) string {
	errno, typed := cause.(unix.Errno)
	if cause == nil || (typed && errno == 0) {
		return "fixture_native_query_errno_unavailable"
	}
	if !typed {
		return "fixture_native_query_errno_unclassified"
	}
	switch errno {
	case unix.ESRCH:
		return "fixture_native_query_errno_esrch"
	case unix.EPERM:
		return "fixture_native_query_errno_eperm"
	case unix.EACCES:
		return "fixture_native_query_errno_eacces"
	case unix.EINVAL:
		return "fixture_native_query_errno_einval"
	case unix.EINTR:
		return "fixture_native_query_errno_eintr"
	case unix.EAGAIN:
		return "fixture_native_query_errno_eagain"
	case unix.EIO:
		return "fixture_native_query_errno_eio"
	case unix.ENOMEM:
		return "fixture_native_query_errno_enomem"
	case unix.EFAULT:
		return "fixture_native_query_errno_efault"
	case unix.ENOSYS:
		return "fixture_native_query_errno_enosys"
	case unix.ENOTSUP:
		return "fixture_native_query_errno_enotsup"
	case unix.ENOENT:
		return "fixture_native_query_errno_enoent"
	default:
		return "fixture_native_query_errno_other"
	}
}

func candidateFailureCategory(stage string) bool {
	switch stage {
	case "fixture_inspection_owner_retained", "fixture_candidate_parent_invalid", "fixture_candidate_admission_invalid", "fixture_candidate_admission_refused",
		"fixture_candidate_enumeration_refused", "fixture_candidate_identity_refused":
		return true
	}
	return false
}

func nativeObservationFailureCategory(stage string) bool {
	switch stage {
	case "fixture_native_query_refused", "fixture_native_layout_refused", "fixture_native_identity_refused",
		"fixture_native_status_refused", "fixture_native_process_exited", "fixture_candidate_lineage_refused", "fixture_candidate_credentials_refused":
		return true
	}
	return false
}

func argumentFailureCategory(stage string) bool {
	switch stage {
	case "fixture_arguments_allocation_refused", "fixture_arguments_query_refused", "fixture_arguments_layout_refused",
		"fixture_arguments_buffer_refused", "fixture_arguments_count_refused", "fixture_arguments_header_refused", "fixture_arguments_shape_refused":
		return true
	}
	return false
}
