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
	"testing"
	"time"

	protected "github.com/controlLogix/agentmux/platform/runtime"
)

func TestBootstrapCallerRuntimeFailureCategoryAndFixedPresentation(t *testing.T) {
	primary := &os.PathError{Op: "open", Path: "/private/fixture/secret", Err: os.ErrPermission}
	prepared := &protected.Prepared{}
	for _, code := range []string{"assembly_preparation_failed", "protected_start_failed"} {
		plain := bootstrapRuntimeFailure(code, primary, prepared)
		if plain.Error() != "bootstrap_"+code || !errors.Is(plain, primary) || ProjectRequestDiagnostic(plain).Code == "owned_cleanup_incomplete" {
			t.Fatal("ordinary runtime failure lost its cause or acquired cleanup evidence")
		}
		failure := bootstrapRuntimeFailure(code, errors.Join(primary, protected.ErrStartupCleanup), prepared)
		var retained *bootstrapFailureCause
		if !errors.As(failure, &retained) || retained.prepared != prepared || !errors.Is(failure, primary) || !errors.Is(failure, protected.ErrStartupCleanup) || !errors.Is(failure, errRuntimeCleanup) {
			t.Fatal("runtime cleanup category or exact preparation accounting was lost")
		}
		if ProjectRequestDiagnostic(failure).Code != "owned_cleanup_incomplete" {
			t.Fatal("runtime cleanup category did not reach fixed cleanup projection")
		}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			text := fmt.Sprintf(format, failure)
			if strings.Contains(text, "fixture") || strings.Contains(text, "secret") || strings.Contains(text, "0x") {
				t.Fatal("runtime failure presentation exposed an original cause or pointer")
			}
		}
		raw, err := json.Marshal(failure)
		if err != nil || strings.Contains(string(raw), "fixture") || strings.Contains(string(raw), "secret") {
			t.Fatal("runtime failure JSON exposed original cause state")
		}
	}
}

func TestBootstrapCallerActualRoleLeaseCloseFailuresAllRetained(t *testing.T) {
	directory := t.TempDir()
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("private lease fixture unavailable")
	}
	directory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal("canonical lease fixture unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var leases []*BootstrapLock
	for _, identity := range []string{"role_one", "role_two"} {
		lease, err := AcquireBootstrapLock(ctx, directory, "cleanup_cause_fixture", identity)
		if err != nil {
			t.Fatal("actual fixture lease unavailable")
		}
		leases = append(leases, lease)
		t.Cleanup(func() {
			if lease.file != nil {
				if lease.Close() != nil {
					t.Error("actual fixture lease cleanup failed before collection")
				}
			}
		})
		// Consume this exact Go file to produce a real ErrClosed from the
		// caller's subsequent Close. This is not a claim about OS close failure
		// on a live descriptor, and no numeric descriptor is retried.
		if lease.file.Close() != nil {
			t.Fatal("exact fixture file close failed")
		}
	}
	failure := closeBootstrapRoleLeases(leases)
	retained, ok := failure.(*bootstrapFailureCause)
	if !ok || len(retained.leases) != 2 || retained.leases[0] != leases[0] || retained.leases[1] != leases[1] {
		t.Fatal("role-lease cleanup lost exact consumed owner references")
	}
	outer := retained.cause.(interface{ Unwrap() []error }).Unwrap()
	actual := outer[0].(interface{ Unwrap() []error }).Unwrap()
	if len(actual) != 2 {
		t.Fatal("not every actual role close failure was collected")
	}
	for _, cause := range actual {
		var fileError *os.PathError
		if !errors.As(cause, &fileError) || fileError.Op != "close" || !errors.Is(cause, os.ErrClosed) || !errors.Is(failure, cause) {
			t.Fatal("actual role-lease close cause was replaced")
		}
	}
	port := refusal("selected_host_port_occupied")
	joined := bootstrapCloseFailure(port, failure, nil, nil, nil)
	if !errors.Is(joined, port) || !errors.Is(joined, actual[0]) || !errors.Is(joined, actual[1]) || ProjectRequestDiagnostic(joined).Code != "owned_cleanup_incomplete" {
		t.Fatal("port failure or actual close errors were lost through caller cleanup")
	}
}

func TestBootstrapCallerPreparedCloseFailureRetainsReturnedSession(t *testing.T) {
	prepared := &protected.Prepared{}
	session := &Session{startupAttemptID: "attempt_" + strings.Repeat("a", 32)}
	primary := &LocalPortCleanupError{cause: context.DeadlineExceeded}
	closeFailure := &os.PathError{Op: "close", Path: "/private/fixture/image", Err: os.ErrClosed}
	// Model only the trusted deferred Close result boundary. This does not
	// claim that an actual Prepared.Close failed in native execution.
	failure := bootstrapCloseFailure(primary, closeFailure, prepared, nil, session)
	retained := failure.(*bootstrapFailureCause)
	var original *LocalPortCleanupError
	if retained.prepared != prepared || retained.session != session || !errors.As(failure, &original) || original != primary || !errors.Is(failure, closeFailure) {
		t.Fatal("deferred preparation cleanup lost session accounting or original owner")
	}
	if ProjectRequestDiagnostic(failure).Code != "owned_cleanup_incomplete" {
		t.Fatal("deferred preparation failure became a successful or weaker projection")
	}
}
