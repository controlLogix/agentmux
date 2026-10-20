package protocol

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/controlLogix/agentmux/platform/localtls"
	"github.com/nats-io/nats.go"
)

var ErrBrokerAuthorization = errors.New("kernel_broker_authorization_failed")

var authorityStandardWrappers = []reflect.Type{
	reflect.TypeOf(fmt.Errorf("%w", nats.ErrAuthorization)),
	reflect.TypeOf(fmt.Errorf("%w %w", nats.ErrAuthorization, nats.ErrAuthRevoked)),
	reflect.TypeOf(errors.Join(nats.ErrAuthorization)),
}

// Inspect only known sentinels and standard wrappers. A callback error cannot
// supply text, Error, Is, As or arbitrary Unwrap methods for classification.
func closedAuthorityFailure(failure error) uint32 {
	queue := []error{failure}
	for inspected := 0; len(queue) > 0 && inspected < 64; inspected++ {
		current := queue[0]
		queue = queue[1:]
		switch current {
		case ErrBrokerAuthentication, nats.ErrAuthorization, nats.ErrAuthExpired, nats.ErrAuthRevoked, nats.ErrAccountAuthExpired:
			return 1
		case ErrServerAuthentication, localtls.ErrInvalidPolicy, localtls.ErrServerAuthentication:
			return 2
		case ErrBrokerAuthorization, nats.ErrPermissionViolation:
			return 3
		}
		// The pinned NATS client uses a private protocol-error type for the
		// initial handshake. Only that compiler-owned package/type may run its
		// reviewed Is method, and only against these fixed library sentinels.
		actual := reflect.TypeOf(current)
		if actual != nil && actual.Kind() == reflect.Pointer && actual.Elem().PkgPath() == "github.com/nats-io/nats.go" && actual.Elem().Name() == "natsProtoErr" && !reflect.ValueOf(current).IsNil() {
			match := current.(interface{ Is(error) bool })
			for _, sentinel := range []error{nats.ErrAuthorization, nats.ErrAuthExpired, nats.ErrAuthRevoked, nats.ErrAccountAuthExpired} {
				if match.Is(sentinel) {
					return 1
				}
			}
			if match.Is(nats.ErrPermissionViolation) {
				return 3
			}
		}
		known := false
		for _, wrapper := range authorityStandardWrappers {
			if reflect.TypeOf(current) == wrapper {
				known = true
			}
		}
		if !known {
			continue
		}
		if wrapped, ok := current.(interface{ Unwrap() []error }); ok {
			queue = append(queue, wrapped.Unwrap()...)
		} else if wrapped, ok := current.(interface{ Unwrap() error }); ok {
			queue = append(queue, wrapped.Unwrap())
		}
	}
	return 0
}

func authorityFailureCode(code uint32) error {
	switch code {
	case 1:
		return ErrBrokerAuthentication
	case 2:
		return ErrServerAuthentication
	case 3:
		return ErrBrokerAuthorization
	default:
		return nil
	}
}

func (a *Actor) recordAuthorityFailure(failure error) {
	if code := closedAuthorityFailure(failure); code != 0 {
		a.authorityFailure.CompareAndSwap(0, code)
		select {
		case a.fault <- struct{}{}:
		default:
		}
	}
}

func (a *Actor) authorityError() error {
	if a.conn != nil {
		a.recordAuthorityFailure(a.conn.LastError())
	}
	return authorityFailureCode(a.authorityFailure.Load())
}
