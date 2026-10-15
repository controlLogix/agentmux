//go:build linux || darwin

package launcher

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type unknownBoundaryGraffiti struct{}

func (unknownBoundaryGraffiti) Error() string           { panic("unknown_error_called") }
func (unknownBoundaryGraffiti) Unwrap() error           { panic("unknown_unwrap_called") }
func (unknownBoundaryGraffiti) inspectionStage() string { panic("unknown_stage_called") }
func TestBootstrapBoundaryStageTrustedAndClosed(t *testing.T) {
	for _, stage := range []string{"initial_warm_inspection", "post_lease_inspection", "broker_start"} {
		t.Run(stage, func(t *testing.T) {
			cause := refusal("command_timeout_outcome_unknown")
			failure := bootstrapBoundaryFailure(stage, inspectionFailure("version", cause))
			got := bootstrapDiagnosticStage(failure)
			if got == nil || *got != stage || failure.Error() != cause.Error() || !errors.Is(failure, cause) || ProjectRequestDiagnostic(failure) != ProjectRequestDiagnostic(cause) {
				t.Fatal("trusted_boundary_lost_cause_or_code")
			}
			owner := &TransportCleanupError{cause: failure}
			got = bootstrapDiagnosticStage(owner)
			if got == nil || *got != stage || ProjectRequestDiagnostic(owner).Code != "owned_cleanup_incomplete" {
				t.Fatal("cleanup_owner_or_priority_lost")
			}
		})
	}
	cases := map[string]error{"nil": nil, "opaque": unknownBoundaryGraffiti{}, "text": errors.New("initial_warm_inspection"), "command_stage": inspectionFailure("version", refusal("command_failed")), "unminted_stage": inspectionFailure("initial_warm_inspection", refusal("command_failed")), "unknown_minted_stage": &dockerInspectionFailure{stage: "private-path", cause: refusal("command_failed"), bootstrapBoundary: true}, "typed_nil": (*dockerInspectionFailure)(nil), "conflict": errors.Join(bootstrapBoundaryFailure("initial_warm_inspection", refusal("command_failed")), bootstrapBoundaryFailure("broker_start", refusal("command_failed")))}
	large := make([]error, 80)
	for i := range large {
		large[i] = errors.New("leaf")
	}
	large[79] = bootstrapBoundaryFailure("broker_start", refusal("command_failed"))
	cases["oversized"] = errors.Join(large...)
	for name, cause := range cases {
		t.Run(name, func(t *testing.T) {
			if bootstrapDiagnosticStage(cause) != nil {
				t.Fatal("untrusted_or_conflicting_stage_accepted")
			}
		})
	}
	private := bootstrapBoundaryFailure("broker_start", refusal("command_failed"))
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if fmt.Sprintf(verb, private) != private.Error() {
			t.Fatal("private_wrapper_format_fields_exposed")
		}
	}
	raw, marshalErr := json.Marshal(private)
	if marshalErr != nil || string(raw) != "{}" {
		t.Fatal("private_wrapper_json_structure_changed")
	}
	if strings.Contains(fmt.Sprint(private), "broker_start") {
		t.Fatal("private_stage_entered_public_error")
	}
}
