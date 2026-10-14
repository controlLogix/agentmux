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
	cleanupFailed := s.cleanupFailure != nil
	ownedExited := s.retiredGroup != nil
	if s.group != nil {
		for _, child := range s.group.Status() {
			if child.Exited {
				ownedExited = true
			}
		}
		select {
		case <-s.group.Done():
			ownedExited = true
		default:
		}
	}
	s.mu.Unlock()
	if ctx.Err() != nil {
		return StartupStatusObservation{}, observationContextError(ctx)
	}
	out, err := owner.mapObservationContext(ctx, input)
	if ctx.Err() != nil {
		return StartupStatusObservation{}, observationContextError(ctx)
	}
	if err != nil || out.Instance.InstanceID == nil || (!cleanupFailed && !ownedExited) {
		return out, err
	}
	// Known owned-process facts override a still-fresh cached ready frame. A
	// reused session owns no group and cannot infer another owner's shutdown.
	code, message := "owned_runtime_exited", "An owned protected process has exited."
	if cleanupFailed {
		code, message = "owned_cleanup_incomplete", "Cleanup of the owned runtime is incomplete."
	}
	out.Disposition = "failed"
	out.Instance.Readiness = "not_ready"
	out.Instance.RunningVersion = nil
	for i := range out.Instance.Services {
		for _, role := range protocol.Roles() {
			if out.Instance.Services[i].ServiceID == role {
				out.Instance.Services[i] = unknownStatusService(role, "probe_failed")
			}
		}
	}
	out.Errors = append(out.Errors, StartupStatusError{Component: "instance", Code: code, Message: message, Retryable: true})
	if ctx.Err() != nil {
		return StartupStatusObservation{}, observationContextError(ctx)
	}
	return out, nil
}
