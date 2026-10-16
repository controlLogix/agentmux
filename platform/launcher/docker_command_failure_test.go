//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/localtls"
)

type fail57HostileError struct{}

func (fail57HostileError) Error() string { panic("unknown Error must not run") }
func (fail57HostileError) Is(error) bool { panic("unknown Is must not run") }
func (fail57HostileError) As(any) bool   { panic("unknown As must not run") }
func (fail57HostileError) Unwrap() error { panic("unknown Unwrap must not run") }

// These controls attempt only an absent path or an ordinary non-executable file.
// They never invoke a real Docker/Compose client or contact an engine.
func TestDockerFailureActualOSStartMissingAndDenied(t *testing.T) {
	if os.Getuid() == 0 || os.Getuid() != os.Geteuid() {
		t.Fatal("ordinary equal-UID OS start controls required")
	}
	t.Setenv("DOCKER_CONTEXT", "")
	t.Setenv("DOCKER_HOST", "")
	root := t.TempDir()
	denied := filepath.Join(root, "non-executable-client")
	if err := os.WriteFile(denied, []byte("not an executable\n"), 0600); err != nil {
		t.Fatal("private OS control unavailable")
	}
	for _, tc := range []struct {
		name, client, want string
		doctor             DoctorCode
	}{
		{"missing", filepath.Join(root, "absent-client"), "docker_client_missing", DoctorClientMissing},
		{"denied", denied, "docker_client_permission_denied", DoctorClientPermission},
	} {
		t.Run(tc.name, func(t *testing.T) {
			driver, err := NewDocker(DockerConfig{Executable: tc.client, Context: "fixture",
				Endpoint: "unix:///tmp/fail57-unused.sock", EngineID: "fixture",
				Versions: DockerVersions{"29.8.0", "29.8.0", "5.5.1"}, Timeout: time.Second, Backend: NativeUnix})
			if err != nil {
				t.Fatal("fixed OS control selection refused")
			}
			output, failure := driver.run(context.Background(), nil, "compose", "version", "--short")
			if output != nil || failure == nil || failure.Error() != "docker_command_failed" {
				t.Fatal("actual OS failure lost original refusal semantics")
			}
			var actual *os.PathError
			if !errors.As(failure, &actual) || actual.Path != tc.client || actual.Op != "fork/exec" {
				t.Fatal("actual original OS cause not retained")
			}
			if ProjectRequestDiagnostic(failure).Code != tc.want {
				t.Fatal("actual OS cause did not produce its closed diagnostic")
			}
			if got := doctorInspectionResult(inspectionFailure("endpoint", failure), context.Background()); got.Code != tc.doctor {
				t.Fatal("doctor lost retained OS cause")
			}
		})
	}
}

func TestDockerFailureFixedStagesDoNotAssertSpecificCauses(t *testing.T) {
	image := "docker.io/library/nats@sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"compose", "version", "--short"}, "docker_compose_check_failed"},
		{[]string{"version", "--format", dockerVersionReadFormat}, "docker_engine_check_failed"},
		{[]string{"info", "--format", dockerInfoReadFormat}, "docker_engine_check_failed"},
		{[]string{"image", "inspect", image, "--format", "{{json .Id}}"}, "docker_cache_check_failed"},
		{[]string{"compose", "--project-name", "fixture", "--file", "-", "up", "--detach", "--wait", "--wait-timeout", "60", "--pull", "never", "--no-build"}, "docker_compose_start_failed"},
	} {
		failure := dockerCommandError("/private/SECRET/client", tc.args, fail57HostileError{}, false)
		got := ProjectRequestDiagnostic(failure)
		if got.Code != tc.want || !ValidRequestDiagnostic(got) || !strings.Contains(got.Message, "unconfirmed") {
			t.Fatal("fixed stage became a proven absence/permission cause")
		}
		for _, output := range []string{fmt.Sprintf("%v", failure), fmt.Sprintf("%+v", failure), fmt.Sprintf("%#v", failure)} {
			if output != "docker_command_failed" {
				t.Fatal("format exposed command state")
			}
		}
		encoded, err := json.Marshal(failure)
		if err != nil || string(encoded) != `"docker_command_failed"` {
			t.Fatal("JSON exposed private cause")
		}
		encoded, err = json.Marshal(got)
		if err != nil || strings.Contains(string(encoded), "SECRET") {
			t.Fatal("diagnostic exposed private path or error text")
		}
	}
}

func TestDockerFailureGenericAndForgedCausesStayGeneric(t *testing.T) {
	for _, failure := range []error{
		errors.New("permission denied: Docker daemon stopped; Compose missing; no such image"),
		errors.New("docker_client_missing"), fail57HostileError{},
		&os.PathError{Op: "fork/exec", Path: "/private/SECRET", Err: syscall.ENOENT},
	} {
		if ProjectRequestDiagnostic(failure).Code != "request_failed" {
			t.Fatal("unreviewed cause became a trusted request diagnostic")
		}
		if doctorInspectionResult(failure, context.Background()).Code != DoctorInspectionUnknown {
			t.Fatal("generic doctor error acquired a proven category")
		}
	}
	for _, primary := range []error{
		fail57HostileError{},
		&os.PathError{Op: "stat", Path: "/selected", Err: syscall.ENOENT},
		&os.PathError{Op: "fork/exec", Path: "/different", Err: syscall.ENOENT},
		&os.PathError{Op: "fork/exec", Path: "/selected", Err: errors.New("permission denied")},
		&os.PathError{Op: "fork/exec", Path: "/selected", Err: os.ErrPermission},
	} {
		failure := dockerCommandError("/selected", nil, primary, false)
		if ProjectRequestDiagnostic(failure).Code != "docker_command_failed" {
			t.Fatal("unproven exec errno acquired a client diagnosis")
		}
	}
}

func TestDockerFailureOriginalCauseContextAndCleanupPreserved(t *testing.T) {
	primary := &os.PathError{Op: "fork/exec", Path: "/selected", Err: syscall.EACCES}
	failure := dockerCommandError("/selected", nil, primary, false)
	var actual *os.PathError
	if !errors.As(failure, &actual) || actual != primary || !errors.Is(failure, syscall.EACCES) {
		t.Fatal("original typed OS object was lost")
	}
	if ProjectRequestDiagnostic(errors.Join(failure, errRuntimeCleanup)).Code != "owned_cleanup_incomplete" {
		t.Fatal("actionable OS detail masked cleanup")
	}
	if !errors.Is(errors.Join(failure, errRuntimeCleanup), primary) {
		t.Fatal("joined cleanup discarded the primary cause")
	}
	if ProjectRequestDiagnostic(errors.Join(failure, errOwnerBridgeAuthority)).Code != "runtime_authority_rejected" {
		t.Fatal("client detail masked authority")
	}
	if ProjectRequestDiagnostic(errors.Join(failure, context.DeadlineExceeded)).Code != "request_deadline" {
		t.Fatal("client detail masked caller deadline")
	}
	timeout := dockerCommandError("/selected", nil, errors.Join(primary, context.DeadlineExceeded), true)
	if timeout.Error() != "docker_command_timeout_outcome_unknown" || !errors.Is(timeout, primary) || !errors.Is(timeout, context.DeadlineExceeded) {
		t.Fatal("timeout lost outward code or original causes")
	}
	if ProjectRequestDiagnostic(timeout).Code != "docker_command_timeout_outcome_unknown" {
		t.Fatal("OS detail overclaimed a timed-out command")
	}
}

func TestDockerFailureBridgeWrapperKeepsOperationalDiagnosisAndAuthority(t *testing.T) {
	primary := &os.PathError{Op: "fork/exec", Path: "/selected", Err: syscall.ENOENT}
	command := dockerCommandError("/selected", []string{"compose", "version", "--short"}, primary, false)
	wrapped := bridgeAuthorityFailure(localAuthorityFailure("local_broker_authority_unavailable", command))
	if !IsOwnerBridgeAuthorityError(wrapped) || !errors.Is(wrapped, primary) {
		t.Fatal("bridge control-flow authority or original cause changed")
	}
	for _, tc := range []struct {
		failure error
		code    string
	}{
		{wrapped, "docker_client_missing"},
		{errors.Join(wrapped, errOwnerBridgeAuthority), "runtime_authority_rejected"},
		{bridgeAuthorityFailure(errors.Join(command, errOwnerBridgeAuthority)), "runtime_authority_rejected"},
		{errors.Join(wrapped, localtls.ErrServerAuthentication), "runtime_authority_rejected"},
		{bridgeAuthorityFailure(errors.Join(command, localtls.ErrInvalidPolicy)), "runtime_authority_rejected"},
		{errors.Join(wrapped, errRuntimeCleanup), "owned_cleanup_incomplete"},
		{errors.Join(wrapped, context.DeadlineExceeded), "request_deadline"},
		{errors.Join(wrapped, context.Canceled), "request_failed"},
		{bridgeAuthorityFailure(fail57HostileError{}), "runtime_authority_rejected"},
		{bridgeAuthorityFailure(nil), "runtime_authority_rejected"},
	} {
		if got := ProjectRequestDiagnostic(tc.failure); got.Code != tc.code || !ValidRequestDiagnostic(got) {
			t.Fatalf("bridge diagnostic precedence changed: got %s want %s", got.Code, tc.code)
		}
	}
}

func TestDockerFailureFixedStageGrammarClosed(t *testing.T) {
	for _, args := range [][]string{
		nil, {"compose"}, {"compose", "version", "private-extra"},
		{"image", "inspect", "mutable-tag", "--format", "{{json .Id}}"},
		{"info", "--format", "private-template"},
		{"compose", "--project-name", "fixture", "--file", "-", "up", "--detach", "--wait", "--wait-timeout", "60", "--pull", "always", "--no-build"},
	} {
		if dockerCommandStage(args) != "unknown" {
			t.Fatal("unapproved command shape acquired a fixed stage")
		}
	}
}

func TestDockerFailureHistoryDiagnosticCodesRemainClosed(t *testing.T) {
	codes := []string{"docker_client_missing", "docker_client_permission_denied", "docker_compose_check_failed",
		"docker_engine_check_failed", "docker_cache_check_failed", "docker_compose_start_failed"}
	var schema any
	if json.Unmarshal([]byte(bootstrapHistorySchemaText), &schema) != nil {
		t.Fatal("history schema unavailable")
	}
	matched := 0
	var visit func(any)
	visit = func(value any) {
		switch actual := value.(type) {
		case map[string]any:
			if values, ok := actual["enum"].([]any); ok {
				contains := func(want string) bool {
					for _, item := range values {
						if item == want {
							return true
						}
					}
					return false
				}
				if contains("docker_command_failed") {
					matched++
					for _, code := range codes {
						if !contains(code) || !ValidRequestDiagnostic(requestDiagnostic(code)) {
							t.Fatal("closed diagnostic missing from historical representation")
						}
					}
					if contains("permission denied: SECRET") {
						t.Fatal("arbitrary error text entered history schema")
					}
				}
			}
			for _, child := range actual {
				visit(child)
			}
		case []any:
			for _, child := range actual {
				visit(child)
			}
		}
	}
	visit(schema)
	if matched != 3 {
		t.Fatal("history diagnostic sites changed or were omitted")
	}
	for _, code := range codes {
		now := time.Now().UTC()
		failure := &bootstrapHistoryFailure{InvocationID: "attempt_" + strings.Repeat("a", 32),
			CompletedAt: now.Add(-time.Second).Format(time.RFC3339Nano), DiagnosticCode: code, Cleanup: "unknown"}
		history, err := terminalHistory(failure, now)
		if err != nil || history == nil || history.Diagnostic != requestDiagnostic(code) ||
			history.Meaning != "previous_recorded_terminal_failure" {
			t.Fatal("actionable diagnostic lost its historical-only meaning")
		}
	}
}
