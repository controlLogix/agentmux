//go:build linux || darwin

package launcher

import "reflect"

// These stages are private provenance, never readiness or mutation authority.
func validBootstrapDiagnosticStage(stage string) bool {
	switch stage {
	case "operation_completion", "invocation_validation", "profile_admission", "docker_admission", "compose_admission", "role_admission", "assembly_preparation", "operation_entry", "accepted_receipt", "initial_warm_inspection", "initial_warm_observation", "bootstrap_lease", "post_lease_inspection", "post_lease_observation", "role_leases", "broker_start", "post_start_inspection", "broker_provision", "protected_start", "readiness_inspection", "readiness_observation", "readiness_finalize":
		return true
	}
	return false
}
func bootstrapBoundaryFailure(stage string, cause error) error {
	if cause == nil || !validBootstrapDiagnosticStage(stage) {
		return cause
	}
	failure := inspectionFailure(stage, cause).(*dockerInspectionFailure)
	failure.bootstrapBoundary = true
	return failure
}
func bootstrapDiagnosticStage(cause error) *string {
	queue := []error{cause}
	found := ""
	for inspected := 0; len(queue) > 0; inspected++ {
		if inspected >= 64 {
			return nil
		}
		current := queue[0]
		queue = queue[1:]
		if current == nil || (reflect.ValueOf(current).Kind() == reflect.Pointer && reflect.ValueOf(current).IsNil()) {
			continue
		}
		if concrete, ok := current.(*dockerInspectionFailure); ok && concrete != nil && concrete.bootstrapBoundary && validBootstrapDiagnosticStage(concrete.stage) {
			if found != "" && found != concrete.stage {
				return nil
			}
			found = concrete.stage
		}
		// Reuse the bounded projector's exact reviewed types. Unknown methods
		// are never used, including inspectionStage, Error, Is, As and Unwrap.
		if !diagnosticReviewedWrapper(current) {
			continue
		}
		switch known := current.(type) {
		case interface{ Unwrap() []error }:
			children := known.Unwrap()
			if len(children) > 63-inspected-len(queue) {
				return nil
			}
			queue = append(queue, children...)
		case interface{ Unwrap() error }:
			if len(queue) >= 63-inspected {
				return nil
			}
			queue = append(queue, known.Unwrap())
		}
	}
	if found == "" {
		return nil
	}
	return &found
}
func copyBootstrapDiagnosticStage(stage *string) *string {
	if stage == nil {
		return nil
	}
	copy := *stage
	return &copy
}
