package protocol

import (
	"errors"
	"fmt"
	"testing"

	"github.com/controlLogix/agentmux/platform/localtls"
	"github.com/nats-io/nats.go"
)

type unknownAuthorityFailure struct{}

func (unknownAuthorityFailure) Error() string { panic("unknown Error must not run") }
func (unknownAuthorityFailure) Is(error) bool { panic("unknown Is must not run") }
func (unknownAuthorityFailure) Unwrap() error { panic("unknown Unwrap must not run") }

func TestAuthorityFailureUsesOnlyKnownClosedCauses(t *testing.T) {
	for _, failure := range []error{nats.ErrAuthorization, nats.ErrAuthExpired, nats.ErrAuthRevoked, nats.ErrAccountAuthExpired, fmt.Errorf("%w", nats.ErrAuthRevoked)} {
		if closedAuthorityFailure(failure) != 1 {
			t.Fatal("known authentication refusal lost its terminal category")
		}
	}
	if closedAuthorityFailure(fmt.Errorf("%w", nats.ErrPermissionViolation)) != 3 || closedAuthorityFailure(localtls.ErrServerAuthentication) != 2 {
		t.Fatal("permission or enrolled TLS refusal became retryable")
	}
	unknown := unknownAuthorityFailure{}
	if closedAuthorityFailure(unknown) != 0 || closedAuthorityFailure(errors.Join(unknown)) != 0 {
		t.Fatal("unknown methods supplied authority classification")
	}
	a := &Actor{fault: make(chan struct{}, 1)}
	a.recordAuthorityFailure(fmt.Errorf("%w", nats.ErrPermissionViolation))
	if a.authorityError() != ErrBrokerAuthorization {
		t.Fatal("asynchronous permission refusal lost its atomic category")
	}
}
