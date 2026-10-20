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
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/localtls"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

func TestRequestDiagnosticActualDockerAdmission(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_CONTEXT", "different_context")
	t.Setenv("DOCKER_HOST", "")
	_, refusal := NewDocker(DockerConfig{Executable: executable, Context: "enrolled", Endpoint: "unix:///tmp/enrolled-docker.sock", EngineID: "enrolled", Versions: DockerVersions{"29.8.0", "29.8.0", "5.1.4"}, Timeout: time.Second, Backend: NativeUnix})
	if refusal == nil || refusal.Error() != "docker_environment_conflict" {
		t.Fatal("real admission did not refuse conflicting selection")
	}
	failure := bridgeAuthorityFailure(localAuthorityFailure("local_broker_authority_invalid", refusal))
	if ProjectRequestDiagnostic(failure).Code != "docker_environment_conflict" || !IsOwnerBridgeAuthorityError(failure) {
		t.Fatal("trusted admission cause lost through authority layers")
	}
}

type diagnosticHostileError struct{}

func (diagnosticHostileError) Error() string { panic("unknown Error must not be called") }
func (diagnosticHostileError) Is(error) bool { panic("unknown Is must not be called") }
func (diagnosticHostileError) As(any) bool   { panic("unknown As must not be called") }

type diagnosticHostileUnwrap struct{}

func (diagnosticHostileUnwrap) Error() string { return "private value" }
func (diagnosticHostileUnwrap) Unwrap() error { panic("unknown Unwrap must not be called") }

type diagnosticSliceError []string

func (diagnosticSliceError) Error() string { panic("unknown slice Error must not be called") }

func TestRequestDiagnosticUnknownAncestryIsNotInvoked(t *testing.T) {
	defer func() {
		if recover() != nil {
			t.Fatal("unknown Unwrap was invoked")
		}
	}()
	for _, failure := range []error{diagnosticHostileUnwrap{}, diagnosticSliceError{"private"}} {
		if ProjectRequestDiagnostic(failure).Code != "request_failed" {
			t.Fatal("unknown error acquired a trusted category")
		}
	}
	children := make([]error, 65)
	for i := range children {
		children[i] = context.DeadlineExceeded
	}
	if ProjectRequestDiagnostic(errors.Join(children...)).Code != "request_failed" {
		t.Fatal("oversized ancestry accepted")
	}
}

func TestRequestDiagnosticRawCleanupPriority(t *testing.T) {
	for _, owned := range []error{&deployment.RawTransportCleanupError{}, deployment.RawTransportCleanupError{}, deployment.ErrRawTransportCleanup} {
		failure := bridgeAuthorityFailure(errors.Join(refusal("environment_conflict"), owned))
		if ProjectRequestDiagnostic(failure).Code != "owned_cleanup_incomplete" {
			t.Fatal("retained raw cleanup was masked")
		}
		if !errors.Is(failure, deployment.ErrRawTransportCleanup) {
			t.Fatal("raw cleanup cause lost")
		}
	}
}

type diagnosticCycleError struct{}

func (diagnosticCycleError) Error() string    { return "private fixture secret" }
func (e *diagnosticCycleError) Unwrap() error { return e }

func TestRequestDiagnosticTrustedRefusalAndSpoof(t *testing.T) {
	for _, tc := range []struct {
		name    string
		failure error
		code    string
	}{
		{"trusted", refusal("environment_conflict"), "docker_environment_conflict"},
		{"spoof", errors.New("docker_environment_conflict"), "request_failed"},
		{"hostile", diagnosticHostileError{}, "request_failed"},
		{"wrapped", fmt.Errorf("private password=/fixture/private: %w", refusal("environment_conflict")), "docker_environment_conflict"},
		{"authority chain", bridgeAuthorityFailure(localAuthorityFailure("local_broker_authority_invalid", refusal("environment_conflict"))), "docker_environment_conflict"},
		{"unconfirmed command", refusal("command_failed"), "docker_command_failed"},
		{"unqualified version", refusal("unsupported_compose"), "docker_versions_unqualified"},
		{"deadline", context.DeadlineExceeded, "request_deadline"},
		{"cycle", &diagnosticCycleError{}, "request_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ProjectRequestDiagnostic(tc.failure)
			if got.Code != tc.code || !ValidRequestDiagnostic(got) {
				t.Fatalf("unexpected closed diagnostic: %s", got.Code)
			}
			encoded, err := json.Marshal(got)
			if err != nil || strings.Contains(string(encoded), "password") || strings.Contains(string(encoded), "/fixture") {
				t.Fatal("diagnostic exposed underlying text")
			}
		})
	}
}

func TestRequestDiagnosticRetainsJoinedCleanupAndAuthority(t *testing.T) {
	owned := &TransportCleanupError{cause: errors.New("private password=/fixture/private")}
	failure := bridgeAuthorityFailure(errors.Join(refusal("environment_conflict"), localtls.ErrServerAuthentication, owned))
	if got := ProjectRequestDiagnostic(failure); got.Code != "owned_cleanup_incomplete" {
		t.Fatalf("cleanup was masked: %s", got.Code)
	}
	var retained *TransportCleanupError
	if !errors.As(failure, &retained) || retained != owned || !errors.Is(failure, localtls.ErrServerAuthentication) || !IsOwnerBridgeAuthorityError(failure) {
		t.Fatal("typed causes or authority sentinel lost")
	}
	if ProjectRequestDiagnostic(errors.Join(refusal("command_failed"), localtls.ErrServerAuthentication)).Code != "runtime_authority_rejected" {
		t.Fatal("authentication was masked")
	}
}

func TestRequestDiagnosticAuthorityPresentationIsClosed(t *testing.T) {
	value := authorityCauseError{code: "owner_bridge_authority_rejected", cause: errors.New("private password=/fixture/private")}
	for _, failure := range []any{value, &value, dockerRefusalError{code: "environment_conflict"}, &dockerRefusalError{code: "environment_conflict"}} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if output := fmt.Sprintf(format, failure); strings.Contains(output, "private") || strings.Contains(output, "cause") || strings.Contains(output, "0x") {
				t.Fatal("format exposed private error state")
			}
		}
		encoded, err := json.Marshal(failure)
		if err != nil || strings.Contains(string(encoded), "private") || strings.Contains(string(encoded), "cause") {
			t.Fatal("JSON exposed private error state")
		}
	}
}

func TestRequestDiagnosticRejectsUnapprovedFields(t *testing.T) {
	good := ProjectRequestDiagnostic(refusal("command_failed"))
	for _, change := range []func(*RequestDiagnostic){
		func(v *RequestDiagnostic) { v.Code = "occupied_port" },
		func(v *RequestDiagnostic) { v.Action = "delete_resources" },
		func(v *RequestDiagnostic) { v.Message = "unsupported contains port but is not port evidence" },
		func(v *RequestDiagnostic) { v.Kind = "startup-status-observation" },
	} {
		bad := good
		change(&bad)
		if ValidRequestDiagnostic(bad) {
			t.Fatal("unapproved representation accepted")
		}
	}
}

func TestRequestDiagnosticSelectedPortTrustedCauseAndPrecedence(t *testing.T) {
	port := refusal("selected_host_port_occupied")
	for _, tc := range []struct {
		name    string
		failure error
		code    string
	}{
		{"trusted", port, "selected_host_port_occupied"},
		{"spoof", errors.New("selected_host_port_occupied"), "request_failed"},
		{"unconfirmed Docker", refusal("command_failed"), "docker_command_failed"},
		{"cleanup", errors.Join(port, errLocalPortCleanup), "owned_cleanup_incomplete"},
		{"authentication", errors.Join(port, localtls.ErrServerAuthentication), "runtime_authority_rejected"},
		{"authority", errors.Join(port, errOwnerBridgeAuthority), "runtime_authority_rejected"},
		{"deadline", errors.Join(port, context.DeadlineExceeded), "request_deadline"},
		{"cancelled", errors.Join(port, context.Canceled), "request_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := ProjectRequestDiagnostic(tc.failure)
			if out.Code != tc.code || !ValidRequestDiagnostic(out) {
				t.Fatal("selected-port cause or failure precedence differs")
			}
		})
	}
	good := ProjectRequestDiagnostic(port)
	if good.Action != "resolve_selected_port_conflict" {
		t.Fatal("selected-port diagnostic lacks its exact safe action")
	}
	for _, mutate := range []func(*RequestDiagnostic){
		func(v *RequestDiagnostic) { v.Code = "docker_command_failed" },
		func(v *RequestDiagnostic) { v.Action = "stop_occupant" },
		func(v *RequestDiagnostic) { v.Message = "address already in use: private Docker stderr" },
	} {
		bad := good
		mutate(&bad)
		if ValidRequestDiagnostic(bad) {
			t.Fatal("fabricated occupied-port diagnostic accepted")
		}
	}
}

func TestRequestDiagnosticSelectedPortTerminalHistoryProjection(t *testing.T) {
	now := time.Now().UTC()
	failure := &bootstrapHistoryFailure{InvocationID: "attempt_" + strings.Repeat("a", 32), CompletedAt: now.Add(-time.Second).Format(time.RFC3339Nano), DiagnosticCode: "selected_host_port_occupied", Cleanup: "unknown"}
	history, err := terminalHistory(failure, now)
	if err != nil || history == nil || history.Diagnostic != requestDiagnostic(failure.DiagnosticCode) || history.Kind != "bootstrap-terminal-history" || history.Meaning != "previous_recorded_terminal_failure" {
		t.Fatal("recorded port failure lost its closed historical diagnostic")
	}
	failure.DiagnosticCode = "address already in use: private Docker stderr"
	if history, err := terminalHistory(failure, now); err == nil || history != nil {
		t.Fatal("raw error text became a qualified historical diagnostic")
	}
}

func TestRequestDiagnosticRuntimeCleanupCausePriorityAndPresentation(t *testing.T) {
	primary := &os.PathError{Op: "start", Path: "/private/diagnostic-cleanup-primary", Err: errors.New("private-cleanup-cause")}
	port := refusal("selected_host_port_occupied")
	for _, tc := range []struct {
		name  string
		cause error
	}{
		{"original", primary},
		{"selected_port", errors.Join(primary, port)},
		{"authentication", errors.Join(primary, localtls.ErrServerAuthentication)},
		{"authority", errors.Join(primary, errOwnerBridgeAuthority)},
		{"deadline", errors.Join(primary, context.DeadlineExceeded)},
		{"cancellation", errors.Join(primary, context.Canceled)},
		{"joined", errors.Join(primary, port, localtls.ErrServerAuthentication, context.DeadlineExceeded)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := runtimeCleanupCause{cause: tc.cause}
			for _, failure := range []error{value, &value} {
				if !diagnosticReviewedWrapper(failure) || ProjectRequestDiagnostic(failure) != requestDiagnostic("owned_cleanup_incomplete") {
					t.Fatal("historical runtime cleanup lost its fixed diagnostic priority")
				}
				if !errors.Is(failure, tc.cause) || !errors.Is(failure, primary) || !errors.Is(failure, errRuntimeCleanup) {
					t.Fatal("diagnostic projection lost an original cleanup cause")
				}
				var original *os.PathError
				var pending *RuntimeCleanupError
				if !errors.As(failure, &original) || original != primary || errors.As(failure, &pending) {
					t.Fatal("historical cleanup changed the exact cause or acquired cleanup authority")
				}
				for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
					if fmt.Sprintf(format, failure) != "owner_bridge_runtime_cleanup_failed" {
						t.Fatal("runtime cleanup formatting exposed private details")
					}
				}
				encoded, err := json.Marshal(failure)
				if err != nil || string(encoded) != `"owner_bridge_runtime_cleanup_failed"` {
					t.Fatal("runtime cleanup JSON exposed private details")
				}
			}
		})
	}
}

// A type with a promoted cleanup wrapper is still an unreviewed wrapper.
type diagnosticUnreviewedRuntimeCleanup struct{ runtimeCleanupCause }

func (diagnosticUnreviewedRuntimeCleanup) Unwrap() error {
	panic("unreviewed runtime cleanup Unwrap must not be called")
}

func TestRequestDiagnosticRuntimeCleanupCauseUnknownAncestryIsNotInvoked(t *testing.T) {
	for _, unknown := range []error{diagnosticHostileUnwrap{}, diagnosticHostileError{}, diagnosticSliceError{"private"}} {
		value := runtimeCleanupCause{cause: unknown}
		for _, failure := range []error{value, &value} {
			if ProjectRequestDiagnostic(failure) != requestDiagnostic("owned_cleanup_incomplete") {
				t.Fatal("known historical cleanup lost priority around an opaque cause")
			}
		}
	}
	unknown := diagnosticUnreviewedRuntimeCleanup{runtimeCleanupCause{cause: context.DeadlineExceeded}}
	for _, failure := range []error{unknown, &unknown} {
		if diagnosticReviewedWrapper(failure) || ProjectRequestDiagnostic(failure) != requestDiagnostic("request_failed") {
			t.Fatal("unreviewed wrapper acquired a cleanup or deadline category")
		}
	}
	var absent *runtimeCleanupCause
	if ProjectRequestDiagnostic(absent) != requestDiagnostic("request_failed") {
		t.Fatal("absent historical cleanup acquired a category")
	}
}

func TestRequestDiagnosticRetainsRecoveryCleanupPriority(t *testing.T) {
	cleanup := &protected.RecoveryCleanupError{Prepared: &protected.Prepared{}}
	for _, failure := range []error{cleanup, errors.Join(cleanup, localtls.ErrServerAuthentication), errors.Join(cleanup, context.DeadlineExceeded)} {
		if ProjectRequestDiagnostic(failure) != requestDiagnostic("owned_cleanup_incomplete") {
			t.Fatal("exact recovery cleanup owner lost diagnostic priority")
		}
		if !errors.Is(failure, protected.ErrStartupCleanup) {
			t.Fatal("recovery cleanup cause was lost")
		}
		var owner *protected.RecoveryCleanupError
		if !errors.As(failure, &owner) || owner != cleanup {
			t.Fatal("recovery cleanup ownership was replaced")
		}
	}
}

func TestRequestDiagnosticLifecycleAuthorityFailures(t *testing.T) {
	for _, failure := range []error{protocol.ErrBrokerAuthentication, protocol.ErrBrokerAuthorization, protocol.ErrServerAuthentication} {
		if ProjectRequestDiagnostic(errors.Join(context.DeadlineExceeded, failure)) != requestDiagnostic("runtime_authority_rejected") {
			t.Fatal("lifecycle authority failure was hidden by a request deadline")
		}
	}
}
