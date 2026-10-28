//go:build linux || darwin

package launcher

import (
	"context"
	"errors"
	"testing"
	"time"

	protected "github.com/controlLogix/agentmux/platform/runtime"
)

func TestKernelRolesStateTellsBusyApartFromStale(t *testing.T) {
	policy, profile := ownerStatusFixture(t)
	snapshot := ownerObservationFixture(policy, profile, "started").status.Kernel
	controller := &lifecycleSupervision{group: &protected.Group{}}
	session := &Session{supervision: controller}
	if _, complete, busy, terminal := session.kernelRolesState(snapshot); complete || busy || terminal {
		t.Fatalf("roles with no heartbeat: complete=%t busy=%t terminal=%t", complete, busy, terminal)
	}
	controller.mu.Lock()
	_, complete, busy, terminal := session.kernelRolesState(snapshot)
	controller.mu.Unlock()
	if complete || !busy || terminal {
		t.Fatalf("held supervision lock: complete=%t busy=%t terminal=%t", complete, busy, terminal)
	}
	for name, mark := range map[string]func(*lifecycleSupervision){
		"failed role":         func(c *lifecycleSupervision) { c.failed = map[string]bool{"kernel-lifecycle": true} },
		"stopped role":        func(c *lifecycleSupervision) { c.stopped = map[string]bool{"internal-communication": true} },
		"supervision failure": func(c *lifecycleSupervision) { c.failure = errors.New("supervision failed") },
	} {
		marked := &lifecycleSupervision{group: &protected.Group{}}
		mark(marked)
		if _, complete, busy, terminal := (&Session{supervision: marked}).kernelRolesState(snapshot); complete || busy || !terminal {
			t.Fatalf("%s: complete=%t busy=%t terminal=%t", name, complete, busy, terminal)
		}
	}
}

func TestAwaitCurrentKernelRolesRetriesOnlyABusyLock(t *testing.T) {
	policy, profile := ownerStatusFixture(t)
	snapshot := ownerObservationFixture(policy, profile, "started").status.Kernel
	code := func(err error) string {
		var failure *applicationEvidenceFailure
		if !errors.As(err, &failure) {
			return "none"
		}
		return failure.code
	}

	controller := &lifecycleSupervision{group: &protected.Group{}}
	session := &Session{supervision: controller}
	started := time.Now()
	if got := code(awaitCurrentKernelRoles(context.Background(), session, snapshot)); got != "roles_not_current" ||
		time.Since(started) > 50*time.Millisecond {
		t.Fatalf("stale roles: %s after %s, want an immediate roles_not_current", got, time.Since(started))
	}

	// A lock held throughout is bounded and reported as busy.
	controller.mu.Lock()
	started = time.Now()
	got := code(awaitCurrentKernelRoles(context.Background(), session, snapshot))
	elapsed := time.Since(started)
	controller.mu.Unlock()
	if got != "roles_busy" || elapsed > time.Second {
		t.Fatalf("held lock: %s after %s", got, elapsed)
	}

	// A brief hold (one heartbeat) is retried and then judged on the actual roles.
	controller.mu.Lock()
	go func() { time.Sleep(15 * time.Millisecond); controller.mu.Unlock() }()
	if got := code(awaitCurrentKernelRoles(context.Background(), session, snapshot)); got != "roles_not_current" {
		t.Fatalf("brief hold: %s, want the retried roles result", got)
	}

	// A failed role is reported as such and is never retried.
	failed := &Session{supervision: &lifecycleSupervision{group: &protected.Group{}, failed: map[string]bool{"boot": true}}}
	if got := code(awaitCurrentKernelRoles(context.Background(), failed, snapshot)); got != "roles_failed" {
		t.Fatalf("failed role: %s", got)
	}

	// No supervision means every role is current.
	if err := awaitCurrentKernelRoles(context.Background(), &Session{}, snapshot); err != nil {
		t.Fatalf("unsupervised session: %v", err)
	}

	// The caller's deadline ends the retry, and a deadline is never skipped.
	controller.mu.Lock()
	defer controller.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Millisecond)
	defer cancel()
	if err := awaitCurrentKernelRoles(ctx, session, snapshot); err == nil || applicationMissSkippable(err, 0) {
		t.Fatalf("deadline: %v", err)
	}
}

func TestAttestorSkipsOnlyABoundedRunOfRoleMisses(t *testing.T) {
	for _, code := range []string{"roles_busy", "roles_not_current"} {
		err := errors.Join(applicationEvidenceError(code, nil))
		for misses := 0; misses < applicationTransientMisses; misses++ {
			if !applicationMissSkippable(err, misses) {
				t.Fatalf("%s miss %d was not skipped", code, misses)
			}
		}
		if applicationMissSkippable(err, applicationTransientMisses) {
			t.Fatalf("%s: a sustained miss was skipped", code)
		}
	}
	for _, err := range []error{nil, errors.New("roles_busy"),
		applicationEvidenceError("generation_changed", nil), applicationEvidenceError("generation_unavailable", nil),
		applicationEvidenceError("kernel_unavailable", nil), applicationEvidenceError("broker_unavailable", nil),
		applicationEvidenceError("profile_changed", nil), applicationEvidenceError("deadline", nil),
		applicationEvidenceError("lifetime_ended", nil), applicationEvidenceError("roles_failed", nil),
		errors.Join(applicationEvidenceError("successor_unavailable", nil), applicationEvidenceError("generation_unavailable", nil))} {
		if applicationMissSkippable(err, 0) {
			t.Fatalf("%v was skipped", err)
		}
	}
}
