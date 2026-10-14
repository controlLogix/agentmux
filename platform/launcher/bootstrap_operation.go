//go:build linux || darwin

package launcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/privatefs"
)

// bootstrapOperation belongs to one actual service-lease-owning Run. The
// bootstrap core alone records admission and its actual return. Correlation,
// lock metadata and a live process do not manufacture this capability.
type bootstrapOperation struct {
	state             *bootstrapOperationState
	startup, lifetime context.Context
	server            *OwnerBridgeServer
	leaseFile         *os.File
	createdAt         time.Time
	attemptID         string
	scope             protocol.Scope
	profile           Profile
	compose, assembly [32]byte
	enteredDone, done chan struct{}
}

// All mutable fields share one state object. Formatting the private capability
// copies only immutable references, never fields being updated by bootstrap.
type bootstrapOperationState struct {
	mu                 sync.Mutex
	core               context.Context
	entered, completed bool
	session            *Session
	failure            error
	completedAt        time.Time
}

func (bootstrapOperation) Format(s fmt.State, _ rune) { fmt.Fprint(s, "[private bootstrap operation]") }
func (bootstrapOperation) MarshalJSON() ([]byte, error) {
	return json.Marshal("[private bootstrap operation]")
}

var errOperationNotPending = errors.New("bootstrap_operation_not_pending")

func operationError(code string) error {
	if code == "not_pending" {
		return errOperationNotPending
	}
	return errors.New("bootstrap_operation_" + code)
}

func newBootstrapOperation(startup, lifetime context.Context, server *OwnerBridgeServer, lease *BootstrapLock, attemptID string) (*bootstrapOperation, error) {
	if startup == nil || lifetime == nil || startup.Err() != nil || lifetime.Err() != nil {
		return nil, operationError("context_invalid")
	}
	if _, ok := startup.Deadline(); !ok {
		return nil, operationError("deadline_missing")
	}
	if server == nil || server.owner == nil || server.owner.profile == nil || lease == nil || lease.file == nil || !ownerBridgeInvocation.MatchString(attemptID) {
		return nil, operationError("owner_invalid")
	}
	c := server.config
	if c.admissionPolicy == nil || c.Kernel.authority == nil || c.LocalTLS == nil || c.Kernel.TLS == nil || c.Health.TLS == nil || c.Kernel.Scope != server.owner.policy.KernelScope || !reflect.DeepEqual(c.ProfilePolicy, server.owner.policy.Profile) || !reflect.DeepEqual(server.enrollment.Owner, server.owner.policy.Enrollment) {
		return nil, operationError("binding_invalid")
	}
	file := lease.file // Run alone owns Close until the operation has joined.
	identity := sha256.Sum256([]byte(c.Kernel.Scope.InstanceID + "\x00owner-status-service"))
	expected := filepath.Join(c.ProfilePolicy.Directory, "bootstrap-"+hex.EncodeToString(identity[:])+".lock")
	info, err := file.Stat()
	if err != nil || file.Name() != expected || !privateProfileInfo(info, c.ProfilePolicy.OwnerUID, false) {
		return nil, operationError("lease_invalid")
	}
	p := *server.owner.profile
	p.Docker = cloneOperationDocker(p.Docker)
	return &bootstrapOperation{state: &bootstrapOperationState{}, createdAt: time.Now().UTC(), startup: startup, lifetime: lifetime, server: server, leaseFile: file, attemptID: attemptID, scope: c.Kernel.Scope, profile: p, compose: sha256.Sum256(c.Compose), assembly: sha256.Sum256(c.Assembly), done: make(chan struct{}), enteredDone: make(chan struct{})}, nil
}

func cloneOperationDocker(p *ProfileDocker) *ProfileDocker {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// enter is called only after the core's complete admission and protected
// executable preparation. It stores that call's actual bounded context.
func (o *bootstrapOperation) enter(core context.Context, c BootstrapConfig, p Profile, attemptID string) error {
	if o == nil || o.state == nil || core == nil || core.Err() != nil {
		return operationError("context_invalid")
	}
	deadline, ok := core.Deadline()
	if !ok {
		return operationError("deadline_missing")
	}
	startupDeadline, _ := o.startup.Deadline()
	if deadline.After(startupDeadline) {
		return operationError("deadline_widened")
	}
	o.state.mu.Lock()
	defer o.state.mu.Unlock()
	if o.state.entered || o.state.completed || o.startup.Err() != nil || o.lifetime.Err() != nil {
		return operationError("state_invalid")
	}
	if attemptID != o.attemptID || c.Kernel.Scope != o.scope || c.Kernel.authority != o.server.config.Kernel.authority || c.admissionPolicy != o.server.config.admissionPolicy || sha256.Sum256(c.Compose) != o.compose || sha256.Sum256(c.Assembly) != o.assembly || !reflect.DeepEqual(p, o.profile) || !reflect.DeepEqual(c.ReleaseTrust, o.server.config.ReleaseTrust) || !reflect.DeepEqual(c.ProfilePolicy, o.server.config.ProfilePolicy) {
		return operationError("binding_invalid")
	}
	o.state.core, o.state.entered = core, true
	close(o.enteredDone)
	return nil
}

// complete retains the exact returned session even on a bookkeeping failure,
// so Run can clean its actual children before releasing the service lease.
func (o *bootstrapOperation) complete(session *Session, failure error) error {
	if o == nil || o.state == nil {
		return operationError("owner_invalid")
	}
	o.state.mu.Lock()
	defer o.state.mu.Unlock()
	if o.state.completed {
		return operationError("already_completed")
	}
	var invalid error
	if failure == nil && (!o.state.entered || session == nil) || session != nil && session.startupAttemptID != o.attemptID {
		invalid = operationError("result_invalid")
	}
	o.state.session, o.state.failure, o.state.completed = session, errors.Join(failure, invalid), true
	o.state.completedAt = time.Now().UTC()
	close(o.done)
	return invalid
}

func (o *bootstrapOperation) completedTime() time.Time {
	if o == nil || o.state == nil {
		return time.Time{}
	}
	o.state.mu.Lock()
	defer o.state.mu.Unlock()
	return o.state.completedAt
}

func (o *bootstrapOperation) resultContext(ctx context.Context) (*Session, error) {
	if o == nil || o.state == nil || ctx == nil {
		return nil, operationError("context_invalid")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-o.done:
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	o.state.mu.Lock()
	defer o.state.mu.Unlock()
	return o.state.session, o.state.failure
}

func (o *bootstrapOperation) pending(owner *OwnerStatus) error {
	if o == nil || o.state == nil || o.leaseFile == nil || owner == nil || o.server == nil || o.server.owner != owner {
		return operationError("owner_invalid")
	}
	// The descriptor is the captured acquired lease, not a looked-up file or
	// caller-provided PID. Run cannot close it before joining the operation.
	if _, err := o.leaseFile.Stat(); err != nil {
		return operationError("lease_invalid")
	}
	o.state.mu.Lock()
	defer o.state.mu.Unlock()
	if !o.state.entered || o.state.completed || o.state.core == nil || o.startup.Err() != nil || o.lifetime.Err() != nil || o.state.core.Err() != nil {
		return operationError("not_pending")
	}
	if o.scope != owner.policy.KernelScope || !reflect.DeepEqual(owner.profile, &o.profile) || !reflect.DeepEqual(o.server.enrollment.Owner, owner.policy.Enrollment) {
		return operationError("binding_invalid")
	}
	return nil
}

// awaitCanceledCoreCompletion handles only the trusted pending-state refusal
// from this entered operation. It never retries a mapper or releases a nonce.
func (o *bootstrapOperation) awaitCanceledCoreCompletion(ctx context.Context, refusal error) (bool, error) {
	if ctx == nil || ctx.Err() != nil {
		return false, operationError("context_invalid")
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || !time.Now().Before(deadline) {
		return false, operationError("deadline_missing")
	}
	if refusal != errOperationNotPending {
		return false, nil
	}
	if o == nil || o.state == nil || o.server == nil || o.server.owner == nil || o.leaseFile == nil {
		return false, nil
	}
	owner := o.server.owner
	c := o.server.config
	identity := sha256.Sum256([]byte(o.scope.InstanceID + "\x00owner-status-service"))
	expected := filepath.Join(c.ProfilePolicy.Directory, "bootstrap-"+hex.EncodeToString(identity[:])+".lock")
	info, leaseErr := o.leaseFile.Stat()
	if leaseErr != nil || o.leaseFile.Name() != expected || !privateProfileInfo(info, c.ProfilePolicy.OwnerUID, false) {
		return false, operationError("lease_invalid")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	root, rootErr := openProfileDirectory(c.ProfilePolicy)
	if rootErr != nil {
		return false, operationError("lease_invalid")
	}
	current, pathErr := root.Lstat(filepath.Base(expected))
	closeErr := root.Close()
	// The pinned Unix Go Root consumes its handle and returns nil; it does not
	// expose physical close failure. Check its public result without raw-FD retry.
	if closeErr != nil {
		return false, historyError("cleanup_failed", closeErr)
	}
	if pathErr != nil || !privateProfileInfo(current, c.ProfilePolicy.OwnerUID, false) ||
		!os.SameFile(info, current) || privatefs.CheckDescriptor(o.leaseFile, privatefs.PrivateObject) != nil {
		return false, operationError("lease_invalid")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := lockOwnerObservation(ctx, &o.state.mu); err != nil {
		return false, err
	}
	// pending checks cancellation before binding; do not inherit that ordering
	// when granting a wait exception for a consumed authenticated request.
	bound := o.scope == owner.policy.KernelScope && c.Kernel.Scope == o.scope &&
		reflect.DeepEqual(owner.profile, &o.profile) &&
		reflect.DeepEqual(o.server.enrollment.Owner, owner.policy.Enrollment) &&
		reflect.DeepEqual(c.ProfilePolicy, owner.policy.Profile) &&
		sha256.Sum256(c.Compose) == o.compose && sha256.Sum256(c.Assembly) == o.assembly
	eligible := bound && o.state.entered && o.state.core != nil && o.state.core.Err() != nil
	o.state.mu.Unlock()
	if !bound {
		return false, operationError("binding_invalid")
	}
	if !eligible {
		return false, nil
	}
	// No mutex, filesystem operation or detached goroutine is held while waiting.
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-o.done:
		if err := ctx.Err(); err != nil {
			return false, err
		}
		return true, nil
	}
}
