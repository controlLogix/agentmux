//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	protected "github.com/controlLogix/agentmux/platform/runtime"

	"github.com/nats-io/nats.go"
)

type hostPolicyDiagnosticUnknownWrapper struct{ hidden error }

func (hostPolicyDiagnosticUnknownWrapper) Error() string { panic("unknown Error invoked") }
func (hostPolicyDiagnosticUnknownWrapper) Unwrap() error { panic("unknown Unwrap invoked") }

func TestHostPolicyDiagnosticTrustedCodesAndSpoofs(t *testing.T) {
	categories := map[string][]string{
		"host_policy_invalid":     {"private_root_invalid", "workspace_invalid", "inside_workspace", "private_root_unavailable", "private_root_changed", "ancestor_changed", "ancestor_invalid", "ancestor_untrusted", "ancestor_access_denied", "selection_invalid", "private_policy_root_invalid", "private_policy_invalid", "fields_invalid", "decode_invalid", "declarations_invalid", "unconfigured"},
		"host_profile_invalid":    {"profile_invalid", "profile_binding_invalid", "bootstrap_config_invalid"},
		"host_enrollment_invalid": {"owner_binding_invalid", "owner_enrollment_invalid", "bridge_unconfigured", "bridge_private_root_invalid", "bridge_reference_invalid", "bridge_credential_invalid", "bridge_fields_invalid", "bridge_binding_invalid", "receipt_enrollment_invalid"},
		"host_executable_invalid": {"executable_unqualified", "executable_root_invalid", "executable_invalid", "executable_changed"},
	}
	for category, codes := range categories {
		for _, code := range codes {
			t.Run(code, func(t *testing.T) {
				actual := hostPolicyError(code)
				if actual.Error() != "host_policy_"+code {
					t.Fatal("existing error text changed")
				}
				got := ProjectRequestDiagnostic(actual)
				if got.Code != category || !ValidRequestDiagnostic(got) {
					t.Fatal("trusted constructor category lost")
				}
				if ProjectRequestDiagnostic(errors.New(actual.Error())).Code != "request_failed" {
					t.Fatal("spoofed text gained trusted category")
				}
				wrapped := fmt.Errorf("private path=/private/fixture password=secret: %w", actual)
				if ProjectRequestDiagnostic(wrapped) != got {
					t.Fatal("reviewed wrapper lost trusted category")
				}
				encoded, e := json.Marshal(ProjectRequestDiagnostic(wrapped))
				if e != nil || strings.Contains(string(encoded), "secret") || strings.Contains(string(encoded), "/private") {
					t.Fatal("public diagnostic leaked wrapper text")
				}
				var fields map[string]json.RawMessage
				if json.Unmarshal(encoded, &fields) != nil || len(fields) != 5 {
					t.Fatal("fixed five-field schema changed")
				}
			})
		}
	}
}

func TestHostPolicyDiagnosticUnknownAndPriority(t *testing.T) {
	var nilTyped *hostPolicyFailure
	cases := []struct {
		name    string
		failure error
		code    string
	}{
		{"nil", nil, "request_failed"}, {"nil_typed", nilTyped, "request_failed"},
		{"unknown_constructor", hostPolicyError("future_unknown"), "request_failed"},
		{"context_without_cause", hostPolicyError("context_invalid"), "request_failed"},
		{"receipt_descriptor_plumbing", hostPolicyError("receipt_descriptor_invalid"), "request_failed"},
		{"receipt_binding_plumbing", hostPolicyError("receipt_binding_invalid"), "request_failed"},
		{"unknown_wrapper", hostPolicyDiagnosticUnknownWrapper{hostPolicyError("profile_invalid")}, "request_failed"},
		{"cleanup", errors.Join(hostPolicyError("profile_invalid"), ErrTransportCleanup, nats.ErrAuthorization, context.DeadlineExceeded), "owned_cleanup_incomplete"},
		{"authentication", errors.Join(hostPolicyError("profile_invalid"), nats.ErrAuthorization, context.DeadlineExceeded), "runtime_authority_rejected"},
		{"account_expired", errors.Join(hostPolicyError("profile_invalid"), nats.ErrAuthExpired), "runtime_authority_rejected"},
		{"authority", errors.Join(hostPolicyError("profile_invalid"), errOwnerBridgeAuthority), "runtime_authority_rejected"},
		{"deadline", errors.Join(hostPolicyError("profile_invalid"), context.DeadlineExceeded), "request_deadline"},
		{"conflicting_categories", errors.Join(hostPolicyError("profile_invalid"), hostPolicyError("executable_invalid")), "request_failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ProjectRequestDiagnostic(tc.failure)
			if got.Code != tc.code || !ValidRequestDiagnostic(got) {
				t.Fatal("priority or unknown refusal changed")
			}
		})
	}
	children := make([]error, 65)
	for i := range children {
		children[i] = hostPolicyError("profile_invalid")
	}
	if ProjectRequestDiagnostic(errors.Join(children...)).Code != "request_failed" {
		t.Fatal("bounded ancestry exceeded")
	}
}

func TestHostPolicyDiagnosticLeafPresentation(t *testing.T) {
	value := hostPolicyFailure{code: "profile_invalid"}
	for _, actual := range []any{value, &value} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if fmt.Sprintf(format, actual) != "host_policy_profile_invalid" {
				t.Fatal("leaf state exposed or code changed")
			}
		}
		raw, e := json.Marshal(actual)
		if e != nil || string(raw) != `"host_policy_profile_invalid"` {
			t.Fatal("leaf JSON changed")
		}
	}
}

func TestHostPolicyProtectedAdmissionRetainsCleanupAndUnknownCauses(t *testing.T) {
	original := &os.PathError{Op: "close", Path: "/private/host-admission-marker", Err: context.DeadlineExceeded}
	failure := &hostPolicyFailure{code: "executable_unqualified", cause: errors.Join(original, protected.ErrStartupCleanup)}
	var actual *os.PathError
	if !errors.Is(failure, protected.ErrStartupCleanup) || !errors.As(failure, &actual) || actual != original {
		t.Fatal("host admission lost exact protected cleanup cause")
	}
	if ProjectRequestDiagnostic(failure).Code != "owned_cleanup_incomplete" {
		t.Fatal("host admission masked retained cleanup")
	}
	for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
		if fmt.Sprintf(format, failure) != "host_policy_executable_unqualified" {
			t.Fatal("host admission exposed private cause")
		}
	}
	if string(mustStatusJSON(failure)) != `"host_policy_executable_unqualified"` {
		t.Fatal("host admission JSON exposed private cause")
	}
	unknown := &hostPolicyFailure{code: "executable_unqualified", cause: hostPolicyDiagnosticUnknownWrapper{original}}
	if ProjectRequestDiagnostic(unknown).Code != "host_executable_invalid" {
		t.Fatal("unknown cause gained trusted cleanup authority")
	}
}
