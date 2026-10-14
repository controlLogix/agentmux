//go:build linux || darwin

package launcher

import (
	"errors"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
)

func TestSessionOwnerObservationRetainsProvenance(t *testing.T) {
	policy, profile := ownerStatusFixture(t)
	owner, err := LoadOwnerStatus(policy)
	if err != nil {
		t.Fatal("actual owner enrollment failed")
	}
	input := ownerObservationFixture(policy, profile, "reused")
	session := &Session{Status: input.status, startupAttemptID: input.attemptID, observedAt: input.receivedAt}
	first, err := session.OwnerObservation(owner)
	if err != nil || first.Disposition != "reused" || first.StartupAttemptID == nil || *first.StartupAttemptID != input.attemptID {
		t.Fatal("session lost its actual invocation or reuse disposition")
	}
	if first.Persistence.Readiness != "unknown" || first.Work.Active != nil || first.Hubs.InventoryState != "unavailable" {
		t.Fatal("read-only session invented write readiness or application state")
	}
	// A private value alone is not qualified write evidence. The adapter has no
	// write-ready branch until the actual probe binding is independently checked.
	session.healthProof = &completedHealthProbe{result: deployment.ProbeResult{Sequence: 1}, completedAt: time.Now()}
	second, err := session.OwnerObservation(owner)
	if err != nil || second.Persistence.Readiness != "unknown" {
		t.Fatal("unqualified private proof made persistence ready")
	}
	session.cleanupFailure = errors.New("private cleanup detail")
	failed, err := session.OwnerObservation(owner)
	if err != nil || failed.Disposition != "failed" || failed.Instance.Readiness != "not_ready" || failed.Errors[len(failed.Errors)-1].Code != "owned_cleanup_incomplete" {
		t.Fatal("known cleanup failure was hidden by a fresh cached frame")
	}
	session.cleanupFailure = nil
	session.observedAt = time.Now().Add(-time.Minute)
	stale, err := session.OwnerObservation(owner)
	if err != nil || stale.Disposition != "failed" || len(stale.Errors) == 0 || stale.Errors[0].Code != "observation_unavailable" {
		t.Fatal("session getter refreshed an old receipt time")
	}
}

func TestSessionOwnerObservationRequiresEnrolledHandle(t *testing.T) {
	if _, err := (*Session)(nil).OwnerObservation(nil); err == nil {
		t.Fatal("missing session or owner was accepted")
	}
	if _, err := (&Session{}).OwnerObservation(nil); err == nil {
		t.Fatal("missing owner handle was accepted")
	}
}
