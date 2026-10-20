//go:build linux || darwin

package launcher

import (
	"context"
	"errors"
	"testing"
	"time"
)

type applicationServiceCompositionOwner struct {
	done, lifetime chan struct{}
	stops          int
	stopFailure    error
}

func (o *applicationServiceCompositionOwner) Done() <-chan struct{}         { return o.done }
func (o *applicationServiceCompositionOwner) LifetimeDone() <-chan struct{} { return o.lifetime }
func (o *applicationServiceCompositionOwner) Available() bool {
	return !serviceLifetimeEnded(o.lifetime)
}
func (o *applicationServiceCompositionOwner) Stop(context.Context) error {
	o.stops++
	if !serviceLifetimeEnded(o.lifetime) {
		close(o.lifetime)
	}
	close(o.done)
	return o.stopFailure
}

func TestApplicationServiceCompositionRevokesAttestorAndJoinsOwner(t *testing.T) {
	owner := &applicationServiceCompositionOwner{done: make(chan struct{}), lifetime: make(chan struct{})}
	lifetime, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := runOwnedApplicationServices(lifetime, func(start context.Context, hostDone <-chan struct{}) (applicationHostServiceOwner, error) {
		if start.Err() != nil || hostDone != lifetime.Done() {
			t.Error("services did not receive the actual host lifetime")
		}
		return owner, nil
	}, func(attestor context.Context) error {
		close(owner.lifetime)
		select {
		case <-attestor.Done():
		case <-lifetime.Done():
			t.Error("service lifetime did not revoke attestation")
		}
		return nil
	})
	if err == nil || owner.stops != 1 || !serviceLifetimeEnded(owner.done) {
		t.Fatal("service loss did not retain and join the original owner")
	}
}

func TestApplicationServiceCompositionKeepsPartialOwnerAndCleanupFailure(t *testing.T) {
	startFailure, stopFailure := errors.New("start_failed"), errors.New("stop_failed")
	owner := &applicationServiceCompositionOwner{done: make(chan struct{}), lifetime: make(chan struct{}), stopFailure: stopFailure}
	err := runOwnedApplicationServices(context.Background(), func(context.Context, <-chan struct{}) (applicationHostServiceOwner, error) {
		return owner, startFailure
	}, func(context.Context) error {
		t.Fatal("partial startup reached attestation")
		return nil
	})
	var retained *applicationServiceOwnershipFailure
	if !errors.Is(err, startFailure) || !errors.Is(err, stopFailure) || !errors.As(err, &retained) || retained.owner != owner || owner.stops != 1 || !serviceLifetimeEnded(owner.done) {
		t.Fatal("partial startup lost its error, owner or joined shutdown")
	}
}

func TestApplicationServiceCompositionWaitsForOwningKernelOperation(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	cancel()
	err := runApplicationAttestorWithServices(lifetime, &bootstrapOperation{done: make(chan struct{})}, ApplicationAttestorNATSEnrollment{}, func(context.Context, <-chan struct{}) (applicationHostServiceOwner, error) {
		t.Fatal("service started without its completed owning kernel operation")
		return nil, nil
	})
	if err == nil {
		t.Fatal("cancelled host lifetime admitted service startup")
	}
}

func TestApplicationServiceCompositionCancelledParentCannotStartServices(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	cancel()
	err := runOwnedApplicationServices(lifetime, func(context.Context, <-chan struct{}) (applicationHostServiceOwner, error) {
		t.Fatal("cancelled parent started services")
		return nil, nil
	}, func(context.Context) error {
		t.Fatal("cancelled parent started attestation")
		return nil
	})
	if err == nil {
		t.Fatal("cancelled parent was accepted")
	}
}

func TestApplicationServiceCompositionDeadServiceCannotStartAttestor(t *testing.T) {
	owner := &applicationServiceCompositionOwner{done: make(chan struct{}), lifetime: make(chan struct{})}
	close(owner.lifetime)
	err := runOwnedApplicationServices(context.Background(), func(context.Context, <-chan struct{}) (applicationHostServiceOwner, error) {
		return owner, nil
	}, func(context.Context) error {
		t.Fatal("dead service started attestation")
		return nil
	})
	if err == nil || owner.stops != 1 || !serviceLifetimeEnded(owner.done) {
		t.Fatal("dead service lost its joined owner")
	}
}

func TestApplicationServiceCompositionRetainsPreProcessCleanupOwner(t *testing.T) {
	retained := &struct{}{}
	original := serviceProcessOwnershipError(retained)
	err := runOwnedApplicationServices(context.Background(), func(context.Context, <-chan struct{}) (applicationHostServiceOwner, error) {
		return nil, original
	}, func(context.Context) error {
		t.Fatal("pre-process failure started attestation")
		return nil
	})
	var cleanup *applicationServiceOwnershipFailure
	if !errors.As(err, &cleanup) || cleanup.owner != retained {
		t.Fatal("pre-process cleanup ownership was discarded")
	}
}
