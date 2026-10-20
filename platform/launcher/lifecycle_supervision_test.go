//go:build linux || darwin

package launcher

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

func TestLifecycleAuthorityFailureNeverRepairsBroker(t *testing.T) {
	f := newBridgeFixture(t)
	f.startBroker(t)
	c := f.config
	c.brokerUsers = map[string]string{"kernel-lifecycle": strings.Repeat("z", 48)}
	var attempts atomic.Int32
	controller := startLifecycleSupervision(context.Background(), c, f.profile, nil, func(context.Context) error { attempts.Add(1); return errors.New("unexpected repair") })
	defer controller.cancel()
	select {
	case <-controller.done:
	case <-time.After(2 * time.Second):
		t.Fatal("authentication refusal did not finish within its connection budget")
	}
	controller.mu.Lock()
	failure := controller.failure
	controller.mu.Unlock()
	if !errors.Is(failure, protocol.ErrBrokerAuthentication) || attempts.Load() != 0 {
		t.Fatal("authentication failure entered broker recovery", failure, attempts.Load())
	}
}

func TestLifecycleRequestExpiryBoundsLeaseWaitAndRejectsEntry(t *testing.T) {
	policy, profile := ownerStatusFixture(t)
	now := time.Now()
	request := protocol.LifecycleRequest{SchemaVersion: protocol.Version, Kind: "kernel-lifecycle-request", Scope: policy.KernelScope, SupervisorEpoch: strings.Repeat("a", 32), LifecycleIncarnation: strings.Repeat("b", 32), RequestID: strings.Repeat("c", 32), Action: "recover", Role: "boot", ExpectedGeneration: 1, IssuedAt: now.UTC().Format(time.RFC3339Nano), ExpiresAt: now.Add(80 * time.Millisecond).UTC().Format(time.RFC3339Nano)}
	ownerContext, cancelOwner := context.WithTimeout(context.Background(), time.Second)
	defer cancelOwner()
	lease, err := AcquireBootstrapLock(ownerContext, profile.ProfileDirectory, profile.InstanceID, "request_expiry")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	ctx, cancel, err := lifecycleRequestContext(context.Background(), request, policy.KernelScope, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if other, err := AcquireBootstrapLock(ctx, profile.ProfileDirectory, profile.InstanceID, "request_expiry"); err == nil || other != nil {
		t.Fatal("request expiry did not stop the held-lease wait")
	}
	if ctx.Err() != context.DeadlineExceeded {
		t.Fatal("lease wait used another budget")
	}
	controller := &lifecycleSupervision{config: BootstrapConfig{Kernel: KernelStatusOptions{Scope: policy.KernelScope}, Deadlines: protected.Deadlines{StartTimeout: time.Second}}}
	if _, err := controller.Apply(context.Background(), request); err == nil {
		t.Fatal("expired request reached owned-member lookup")
	}
	request.ExpiresAt = time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)
	request.Scope.InstanceID = "foreign"
	if _, err := controller.Apply(context.Background(), request); err == nil {
		t.Fatal("foreign request reached owned-member lookup")
	}
}

func TestLifecycleReadinessDoesNotWaitBehindReplacement(t *testing.T) {
	controller := &lifecycleSupervision{}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	session := &Session{supervision: controller}
	policy, profile := ownerStatusFixture(t)
	snapshot := ownerObservationFixture(policy, profile, "started").status.Kernel
	started := time.Now()
	roles, complete := session.currentKernelRoles(snapshot)
	if complete || len(roles) != 0 || time.Since(started) > 100*time.Millisecond {
		t.Fatal("readiness waited for a replacement or invented current roles")
	}
}

func TestLifecycleCurrentGenerationRequiresNewScopedIncarnation(t *testing.T) {
	now := time.Now()
	policy, profile := ownerStatusFixture(t)
	snapshot := ownerObservationFixture(policy, profile, "started").status.Kernel
	states := []protected.ProcessStatus{}
	observed := map[string]supervisedObservation{}
	for _, member := range snapshot.Members {
		states = append(states, protected.ProcessStatus{Role: member.Role, Generation: 1})
		observed[member.Role] = supervisedObservation{1, member.Incarnation, now}
	}
	check := func() (map[string]bool, bool) {
		return supervisedKernelRoles(snapshot, states, observed, nil, nil, policy.KernelScope, now)
	}
	if _, complete := check(); !complete {
		t.Fatal("actual current scoped generations were rejected")
	}
	states[0].Generation = 2
	allowed, complete := check()
	if complete || allowed[states[0].Role] || len(allowed) != 3 {
		t.Fatal("old-generation snapshot accepted or independent siblings lost")
	}
	observed[states[0].Role] = supervisedObservation{2, strings.Repeat("f", 32), now}
	if _, complete := check(); complete {
		t.Fatal("new process generation reused the old incarnation")
	}
	snapshot.Members[0].Incarnation = strings.Repeat("f", 32)
	if _, complete := check(); !complete {
		t.Fatal("new observed incarnation failed current generation binding")
	}
	states[0].Exited = true
	allowed, complete = check()
	if complete || allowed[states[0].Role] || len(allowed) != 3 {
		t.Fatal("exited child stayed current or surviving rows were erased")
	}
	states[0].Exited = false
	entry := observed[states[0].Role]
	entry.at = now.Add(-4 * time.Second)
	observed[states[0].Role] = entry
	if _, complete := check(); complete {
		t.Fatal("stale local receipt established current readiness")
	}
	snapshot.Scope.InstanceID = "foreign"
	if allowed, complete := check(); complete || len(allowed) != 0 {
		t.Fatal("foreign snapshot qualified a local generation")
	}
	snapshot.Scope = policy.KernelScope
	if _, complete := supervisedKernelRoles(snapshot, states[:3], observed, nil, nil, policy.KernelScope, now); complete {
		t.Fatal("partial group became fully ready")
	}
}
