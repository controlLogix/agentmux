//go:build linux || darwin

package launcher

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/controlLogix/agentmux/platform/localtls"
)

type applicationAttestorHost struct {
	enrollment ApplicationAttestorNATSEnrollment
	mu         sync.Mutex
	started    bool
	result     error
	done       chan struct{}
	services   applicationHostServiceStart
}

type applicationHostServiceOwner interface {
	Stop(context.Context) error
	Done() <-chan struct{}
	LifetimeDone() <-chan struct{}
	Available() bool
}

type applicationHostServiceStart func(context.Context, <-chan struct{}) (applicationHostServiceOwner, error)

// WithApplicationAttestor installs a separately admitted application selection
// before Run. It never enrolls credentials, changes broker grants or starts I/O.
// The returned server shares the original host admission and uses a separate
// application NATS connection; ordinary startup remains unchanged when omitted.
func (s *OwnerBridgeServer) WithApplicationAttestor(enrollment ApplicationAttestorNATSEnrollment) (*OwnerBridgeServer, error) {
	if s == nil || s.application != nil || s.config.Kernel.TLS == nil || enrollment.Scope != s.config.Kernel.Scope || enrollment.Trust == nil || enrollment.ServerName != enrollment.Trust.Policy().ServerName || enrollment.Trust.Policy().Endpoint == s.config.Kernel.Endpoint {
		return nil, applicationEvidenceError("enrollment_invalid", nil)
	}
	if _, err := localtls.NewClientTrust(enrollment.Trust.Policy()); err != nil {
		return nil, applicationEvidenceError("connection_invalid", err)
	}
	if _, err := applicationAttestorSubject(enrollment); err != nil {
		return nil, err
	}
	enrollment.Credentials = bytes.Clone(enrollment.Credentials)
	copied := *s
	copied.application = &applicationAttestorHost{enrollment: enrollment, done: make(chan struct{})}
	return &copied, nil
}

// ApplicationAttestorResult is optional application status, never a kernel
// readiness or business-access grant. The caller must retain any cleanup error.
func (s *OwnerBridgeServer) ApplicationAttestorResult() (bool, error) {
	if s == nil || s.application == nil {
		return false, applicationEvidenceError("unconfigured", nil)
	}
	app := s.application
	app.mu.Lock()
	defer app.mu.Unlock()
	select {
	case <-app.done:
		return true, app.result
	default:
		return false, nil
	}
}

func (s *OwnerBridgeServer) startApplicationAttestor(lifetime context.Context, operation *bootstrapOperation) <-chan struct{} {
	absent := make(chan struct{})
	if s.application == nil {
		close(absent)
		return absent
	}
	app := s.application
	app.mu.Lock()
	if app.started {
		app.mu.Unlock()
		close(absent)
		return absent
	}
	app.started = true
	app.mu.Unlock()
	go func() {
		result := runApplicationAttestorWithServices(lifetime, operation, app.enrollment, app.services)
		recordApplicationAttestorEnd(lifetime, result)
		app.mu.Lock()
		app.result = result
		clear(app.enrollment.Credentials)
		app.mu.Unlock()
		close(app.done)
	}()
	return app.done
}

func runApplicationAttestorWithServices(lifetime context.Context, operation *bootstrapOperation, enrollment ApplicationAttestorNATSEnrollment, start applicationHostServiceStart) (failure error) {
	if start == nil {
		return runApplicationAttestor(lifetime, operation, enrollment)
	}
	if lifetime == nil || operation == nil || operation.done == nil {
		return applicationEvidenceError("owner_invalid", nil)
	}
	select {
	case <-lifetime.Done():
		return applicationEvidenceError("lifetime_ended", nil)
	case <-operation.done:
	}
	// Admit the actual owning kernel operation before starting service I/O.
	check, cancel := context.WithTimeout(lifetime, applicationEvidenceLimit)
	producer, err := newApplicationRuntimeProducer(check, operation, enrollment.InitialGeneration)
	cancel()
	if err != nil {
		return err
	}
	producer.close()
	return runOwnedApplicationServices(lifetime, start, func(ctx context.Context) error {
		return runApplicationAttestor(ctx, operation, enrollment)
	})
}

func runOwnedApplicationServices(lifetime context.Context, start applicationHostServiceStart, attest func(context.Context) error) (failure error) {
	if lifetime == nil || lifetime.Err() != nil || start == nil || attest == nil {
		return applicationEvidenceError("lifetime_ended", nil)
	}
	startup, cancel := context.WithTimeout(lifetime, 10*time.Second)
	owner, err := start(startup, lifetime.Done())
	cancel()
	if owner != nil {
		defer func() {
			stop, cancel := context.WithTimeout(context.WithoutCancel(lifetime), 5*time.Second)
			defer cancel()
			stopErr := owner.Stop(stop)
			select {
			case <-owner.Done():
			case <-stop.Done():
				stopErr = errors.Join(stopErr, serviceProcessOwnershipError(owner))
			}
			if stopErr != nil {
				failure = errors.Join(failure, serviceProcessOwnershipError(owner), stopErr)
			}
		}()
	}
	if err != nil {
		return err
	}
	if owner == nil || !owner.Available() || owner.LifetimeDone() == nil || owner.Done() == nil {
		return applicationEvidenceError("services_unavailable", nil)
	}
	return attestWhileServicesLive(lifetime, owner, attest)
}

// Keep the concrete owner reachable when cleanup is uncertain. The outer host
// must preserve this error instead of treating application shutdown as complete.
type applicationServiceOwnershipFailure struct{ owner any }

func (*applicationServiceOwnershipFailure) Error() string {
	return "application_services_cleanup_incomplete"
}
func serviceProcessOwnershipError(owner any) error {
	return &applicationServiceOwnershipFailure{owner: owner}
}

func attestWhileServicesLive(lifetime context.Context, owner applicationHostServiceOwner, attest func(context.Context) error) error {
	if lifetime.Err() != nil {
		return applicationEvidenceError("lifetime_ended", nil)
	}
	if !owner.Available() || serviceLifetimeEnded(owner.LifetimeDone()) {
		return applicationEvidenceError("services_unavailable", nil)
	}
	ctx, cancel := context.WithCancel(lifetime)
	defer cancel()
	joined := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-owner.LifetimeDone():
			cancel()
		case <-finished:
		case <-lifetime.Done():
		}
	}()
	err := attest(ctx)
	close(finished)
	<-joined
	if lifetime.Err() == nil && (!owner.Available() || serviceLifetimeEnded(owner.LifetimeDone())) {
		return errors.Join(err, applicationEvidenceError("services_unavailable", nil))
	}
	return err
}

func serviceLifetimeEnded(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func runApplicationAttestor(lifetime context.Context, operation *bootstrapOperation, enrollment ApplicationAttestorNATSEnrollment) (failure error) {
	if lifetime == nil || operation == nil || operation.done == nil {
		return applicationEvidenceError("owner_invalid", nil)
	}
	select {
	case <-lifetime.Done():
		return applicationEvidenceError("lifetime_ended", nil)
	case <-operation.done:
	}
	if lifetime.Err() != nil {
		return applicationEvidenceError("lifetime_ended", nil)
	}
	ctx, cancel := context.WithTimeout(lifetime, applicationEvidenceLimit)
	producer, err := newApplicationRuntimeProducer(ctx, operation, enrollment.InitialGeneration)
	cancel()
	if err != nil {
		return err
	}
	defer func() { producer.close() }()
	// Keep this exact transport alive only for a bounded terminal end exchange
	// after the host context ends. No request may use that cleanup-only lifetime.
	transportLifetime, stopTransport := context.WithCancel(context.WithoutCancel(lifetime))
	defer stopTransport()
	transport, err := connectApplicationAttestor(transportLifetime, lifetime, enrollment)
	if err != nil {
		return err
	}
	var last *ApplicationRuntimeEvidence
	defer func() {
		if last != nil {
			endContext, cancel := context.WithTimeout(context.WithoutCancel(lifetime), time.Second)
			endErr := transport.exchange(endContext, last, true)
			cancel()
			failure = errors.Join(failure, endErr)
		}
		failure = transport.close(failure)
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		evidence, err := producer.observe(lifetime)
		if err != nil {
			var changed *applicationEvidenceFailure
			if errors.As(err, &changed) && changed.code == "generation_changed" && last != nil && producer.generation < applicationMaxGeneration && lifetime.Err() == nil {
				// A successor is admitted only after the identity owner acknowledges the
				// exact old lifetime's end. An ambiguous end never permits replacement.
				endContext, cancel := context.WithTimeout(lifetime, time.Second)
				ending := last
				last = nil
				endErr := transport.exchange(endContext, ending, true)
				cancel()
				if endErr != nil {
					return errors.Join(err, endErr)
				}
				nextGeneration := producer.generation + 1
				producer.close()
				ctx, cancel := context.WithTimeout(lifetime, applicationEvidenceLimit)
				producer, err = newApplicationRuntimeProducer(ctx, operation, nextGeneration)
				cancel()
				if err != nil {
					return err
				}
				continue
			}
			return err
		}
		// Retain even an uncertain publication so cleanup can attempt its exact end.
		last = evidence
		if err = transport.exchange(lifetime, evidence, false); err != nil {
			return err
		}
		select {
		case <-lifetime.Done():
			return nil
		case <-producer.group.Done():
			return nil
		case <-ticker.C:
		}
	}
}
