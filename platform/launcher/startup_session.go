//go:build linux || darwin

package launcher

import (
	"context"
	"sync"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

const ownerObservationLimit = 5 * time.Second

func observationContextError(ctx context.Context) error {
	if ctx.Err() == context.DeadlineExceeded {
		return ownerStatusError("deadline")
	}
	return ownerStatusError("cancelled")
}

// Lock waiting uses no helper goroutine. Cancellation never leaves an unseen
// waiter that can acquire and retain this lock after the caller has returned.
func lockOwnerObservation(ctx context.Context, lock *sync.Mutex) error {
	timer := time.NewTicker(5 * time.Millisecond)
	defer timer.Stop()
	for {
		if ctx.Err() != nil {
			return observationContextError(ctx)
		}
		if lock.TryLock() {
			if ctx.Err() != nil {
				lock.Unlock()
				return observationContextError(ctx)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return observationContextError(ctx)
		case <-timer.C:
		}
	}
}

// OwnerObservation presents a retained observation to a separately enrolled
// local owner. It does not refresh NATS state or authenticate a remote caller.
// Old observations remain stale; this method cannot make them current again.
func (s *Session) OwnerObservation(owner *OwnerStatus) (StartupStatusObservation, error) {
	return s.OwnerObservationContext(context.Background(), owner)
}

// OwnerObservationContext applies one total deadline of at most five seconds,
// including both Session and owner lock acquisition. It honors earlier caller
// deadlines. Ordinary local filesystem calls cannot be interrupted: supported
// local storage must return promptly, and a late result is discarded rather
// than reported as current. This is not a blocked-filesystem latency guarantee.
func (s *Session) OwnerObservationContext(ctx context.Context, owner *OwnerStatus) (StartupStatusObservation, error) {
	if ctx == nil {
		return StartupStatusObservation{}, ownerStatusError("context_invalid")
	}
	ctx, cancel := context.WithTimeout(ctx, ownerObservationLimit)
	defer cancel()
	if ctx.Err() != nil {
		return StartupStatusObservation{}, observationContextError(ctx)
	}
	if s == nil || owner == nil {
		return StartupStatusObservation{}, ownerStatusError("observation_unavailable")
	}
	if err := lockOwnerObservation(ctx, &s.mu); err != nil {
		return StartupStatusObservation{}, err
	}
	status := s.Status
	status.Kernel.Members = append(status.Kernel.Members[:0:0], status.Kernel.Members...)
	input := ownerStatusObservation{status: status, receivedAt: s.observedAt, attemptID: s.startupAttemptID}
	if s.healthProof != nil {
		proof := *s.healthProof
		input.healthProof = &proof
	}
	s.mu.Unlock()
	if ctx.Err() != nil {
		return StartupStatusObservation{}, observationContextError(ctx)
	}
	out, err := owner.mapObservationContext(ctx, input)
	if ctx.Err() != nil {
		return StartupStatusObservation{}, observationContextError(ctx)
	}
	if err != nil {
		return out, err
	}
	if err := s.recheckOwnedKernelObservation(ctx, input.status.Kernel, &out); err != nil {
		return StartupStatusObservation{}, err
	}
	if ctx.Err() != nil {
		return StartupStatusObservation{}, observationContextError(ctx)
	}
	return out, nil
}

// Only the Session's retained Group supplies these facts. Historical generations
// never enter this observation, and process identifiers never enter L04 output.
type ownedProcessObservation struct {
	exitedRoles   []string
	terminal      bool
	cleanupFailed bool
}

// The caller holds Session.mu while choosing the actual current owned group.
func (s *Session) ownedProcessObservationLocked() ownedProcessObservation {
	observed := ownedProcessObservation{cleanupFailed: s.cleanupFailure != nil}
	group := s.group
	if group == nil {
		group = s.retiredGroup
		observed.terminal = group != nil
	}
	if group == nil {
		return observed
	}
	for _, child := range group.Status() {
		if child.Exited {
			for _, role := range protocol.Roles() {
				if child.Role == role {
					observed.exitedRoles = append(observed.exitedRoles, role)
				}
			}
		}
	}
	select {
	case <-group.Done():
		observed.terminal = true
	default:
	}
	return observed
}

func applyOwnedProcessObservation(out *StartupStatusObservation, observed ownedProcessObservation) {
	if out == nil || out.Instance.InstanceID == nil || (!observed.cleanupFailed && !observed.terminal && len(observed.exitedRoles) == 0) {
		return
	}
	out.Disposition = "failed"
	out.Instance.Readiness = "not_ready"
	out.Persistence.Readiness = "unknown"
	if observed.terminal {
		out.Instance.RunningVersion = nil
	}
	for _, role := range protocol.Roles() {
		exited := false
		for _, failed := range observed.exitedRoles {
			exited = exited || role == failed
		}
		if !exited {
			continue
		}
		found := false
		for i, service := range out.Instance.Services {
			if service.ServiceID == role {
				out.Instance.Services[i] = unknownStatusService(role, "probe_failed")
				found = true
			}
		}
		if !found {
			out.Instance.Services = append(out.Instance.Services, unknownStatusService(role, "probe_failed"))
		}
		out.Errors = append(out.Errors, StartupStatusError{Component: "instance", Code: "owned_role_exited", Message: "The owned protected role " + role + " has exited.", Retryable: true})
	}
	code, message := "owned_runtime_exited", "An owned protected process has exited."
	if observed.cleanupFailed {
		code, message = "owned_cleanup_incomplete", "Cleanup of the owned runtime is incomplete."
	}
	out.Errors = append(out.Errors, StartupStatusError{Component: "instance", Code: code, Message: message, Retryable: true})
}

// The last generation check follows mapping so recovery during owner validation
// cannot turn a previous member incarnation into current readiness.
func (s *Session) recheckOwnedKernelObservation(ctx context.Context, snapshot protocol.Snapshot, out *StartupStatusObservation) error {
	if err := lockOwnerObservation(ctx, &s.mu); err != nil {
		return err
	}
	roles, current := s.currentKernelRoles(snapshot)
	owned := s.ownedProcessObservationLocked()
	s.mu.Unlock()
	filterCurrentKernelRoles(out, roles, current)
	applyOwnedProcessObservation(out, owned)
	return nil
}

func filterCurrentKernelRoles(out *StartupStatusObservation, roles map[string]bool, current bool) {
	if current {
		return
	}
	out.Disposition = "failed"
	out.Instance.Readiness = "not_ready"
	out.Persistence.Readiness = "unknown"
	verified := false
	for i, service := range out.Instance.Services {
		for _, role := range protocol.Roles() {
			if service.ServiceID == role {
				if roles[role] {
					verified = true
				} else {
					out.Instance.Services[i] = unknownStatusService(role, "unknown")
				}
			}
		}
	}
	if !verified {
		out.Instance.RunningVersion = nil
	}
	out.Errors = append(out.Errors, StartupStatusError{Component: "instance", Code: "kernel_observation_unavailable", Message: "A current protected member observation is unavailable.", Retryable: true})
}
