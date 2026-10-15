//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestBootstrapCleanupFailureRetainsActualSessionAndCauses(t *testing.T) {
	// Real acquired private OS lease and actual Session.Close refusal. The same
	// still-valid bounded parent supplies recovery; no new allowance or FD adoption.
	parent, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	directory := privateLockDirectory(t)
	lease, err := AcquireBootstrapLock(parent, directory, "boundary_cleanup_instance", "bootstrap")
	if err != nil {
		t.Fatal("cleanup_lease_unavailable")
	}
	session := &Session{lock: lease, cleanupState: newSessionCleanupState(lease.file)}
	t.Cleanup(func() {
		if session.Close(parent) != nil {
			t.Error("exact_session_recovery_failed")
		}
	})
	child, stop := context.WithCancel(parent)
	stop()
	session.mu.Lock()
	cleanup := session.Close(child)
	session.mu.Unlock()
	if cleanup == nil || !session.cleanupState.pending() {
		t.Fatal("actual_close_refusal_or_owner_missing")
	}
	original := bootstrapBoundaryFailure("post_lease_inspection", refusal("command_timeout_outcome_unknown"))
	failure := retainBootstrapCleanup(session, original, cleanup)
	var retained *bootstrapCleanupFailure
	if !errors.As(failure, &retained) || retained.session != session || !errors.Is(failure, original) || !errors.Is(failure, cleanup) {
		t.Fatal("actual_session_or_failure_cause_lost")
	}
	if failure.Error() != "bootstrap_owned_cleanup_incomplete" || ProjectRequestDiagnostic(failure).Code != "owned_cleanup_incomplete" {
		t.Fatal("cleanup_priority_or_outward_code_changed")
	}
	stage := bootstrapDiagnosticStage(failure)
	if stage == nil || *stage != "post_lease_inspection" {
		t.Fatal("original_stage_lost_to_cleanup")
	}
	for _, value := range []any{*retained, retained} {
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			if fmt.Sprintf(verb, value) != "bootstrap_owned_cleanup_incomplete" {
				t.Fatal("cleanup_structure_exposed")
			}
		}
		raw, e := json.Marshal(value)
		if e != nil || string(raw) != `"bootstrap_owned_cleanup_incomplete"` {
			t.Fatal("cleanup_json_exposed")
		}
	}
	// Exact returned Session is the existing controller; wrapper adds no Close.
	if retained.session.Close(parent) != nil || retained.session.cleanupState.pending() {
		t.Fatal("same_parent_exact_recovery_failed")
	}
	contender, e := AcquireBootstrapLock(parent, directory, "boundary_cleanup_instance", "bootstrap")
	if e != nil {
		t.Fatal("actual_lease_not_released")
	}
	if contender.Close() != nil {
		t.Fatal("contender_close_failed")
	}
	if strings.Contains(failure.Error(), "post_lease_inspection") {
		t.Fatal("private_stage_entered_outward_marker")
	}
}
