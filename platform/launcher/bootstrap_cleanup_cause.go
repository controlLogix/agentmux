//go:build linux || darwin

package launcher

import (
	"encoding/json"
	"errors"
	"fmt"

	protected "github.com/controlLogix/agentmux/platform/runtime"
)

// bootstrapFailureCause retains the actual causes and concrete owner references
// from trusted Bootstrap calls. It grants no new cleanup/control authority.
// A consumed os.File or image Close must not be retried through a raw descriptor.
type bootstrapFailureCause struct {
	code     string
	cause    error
	prepared *protected.Prepared
	leases   []*BootstrapLock
	session  *Session
}

func (e *bootstrapFailureCause) Error() string {
	if e != nil {
		switch e.code {
		case "assembly_preparation_failed", "protected_start_failed", "owned_cleanup_incomplete", "lease_close_failed":
			return "bootstrap_" + e.code
		}
	}
	return "bootstrap_owned_cleanup_incomplete"
}
func (e *bootstrapFailureCause) Format(state fmt.State, _ rune) { fmt.Fprint(state, e.Error()) }
func (e *bootstrapFailureCause) MarshalJSON() ([]byte, error)   { return json.Marshal(e.Error()) }
func (e *bootstrapFailureCause) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Only the exact runtime Prepare/Start return reaches this classifier. Unknown
// application errors do not acquire a globally traversable runtime wrapper.
func bootstrapRuntimeFailure(code string, cause error, prepared *protected.Prepared) error {
	if errors.Is(cause, protected.ErrStartupCleanup) {
		cause = errors.Join(cause, errRuntimeCleanup)
	}
	return &bootstrapFailureCause{code: code, cause: cause, prepared: prepared}
}

// Only actual failed Close callers use this helper. Joining preserves the
// original failure, every close cause and each supplied concrete owner. Nothing
// formats a cause or tries to discover/reconstruct a replacement descriptor.
func bootstrapCloseFailure(primary, cleanup error, prepared *protected.Prepared, leases []*BootstrapLock, session *Session) error {
	return &bootstrapFailureCause{
		code: "owned_cleanup_incomplete", cause: errors.Join(primary, cleanup, errRuntimeCleanup),
		prepared: prepared, leases: append([]*BootstrapLock(nil), leases...), session: session,
	}
}

func closeBootstrapRoleLeases(leases []*BootstrapLock) error {
	var failures []error
	var owners []*BootstrapLock
	for _, lease := range leases {
		if err := lease.Close(); err != nil {
			failures = append(failures, err)
			owners = append(owners, lease)
		}
	}
	if len(failures) == 0 {
		return nil
	}
	return bootstrapCloseFailure(nil, errors.Join(failures...), nil, owners, nil)
}
