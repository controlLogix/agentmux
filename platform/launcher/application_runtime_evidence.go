//go:build linux || darwin

package launcher

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

const applicationEvidenceLimit = 3 * time.Second
const applicationMaxGeneration = uint64(9007199254740991)

// ApplicationRuntimeEvidence contains unsigned facts from an actual host-owned
// operation. It carries neither application permission nor signing authority.
// Only this package can construct a valid value; zero values are refused.
type ApplicationRuntimeEvidence struct {
	producer            *applicationRuntimeProducer
	scope               protocol.Scope
	generation          uint64
	lifetimeID          string
	issuedAt, expiresAt time.Time
	roles               [4]applicationRoleGeneration
}

func (*ApplicationRuntimeEvidence) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "[private unsigned application runtime evidence]")
}
func (*ApplicationRuntimeEvidence) MarshalJSON() ([]byte, error) {
	return nil, applicationEvidenceError("serialization_forbidden", nil)
}

type applicationRoleGeneration struct {
	role       string
	generation uint64
	pid        int
}

type applicationRuntimeProducer struct {
	mu         sync.Mutex
	operation  *bootstrapOperation
	session    *Session
	group      *protected.Group
	generation uint64
	lifetimeID string
	roles      [4]applicationRoleGeneration
	closed     bool
}

type applicationEvidenceFailure struct {
	code  string
	cause error
}

func (e *applicationEvidenceFailure) Error() string                { return "application_runtime_" + e.code }
func (e *applicationEvidenceFailure) Unwrap() error                { return e.cause }
func (e *applicationEvidenceFailure) Format(s fmt.State, _ rune)   { fmt.Fprint(s, e.Error()) }
func (e *applicationEvidenceFailure) MarshalJSON() ([]byte, error) { return json.Marshal(e.Error()) }
func applicationEvidenceError(code string, cause error) error {
	return &applicationEvidenceFailure{code, cause}
}

// newApplicationRuntimeProducer is called only by the host's actual operation.
// initialGeneration comes from explicit application enrollment, not a frontend
// request or the kernel status revision. Enrollment owns restart monotonicity.
func newApplicationRuntimeProducer(ctx context.Context, operation *bootstrapOperation, initialGeneration uint64) (*applicationRuntimeProducer, error) {
	if ctx == nil || ctx.Err() != nil || operation == nil || operation.lifetime == nil || operation.lifetime.Err() != nil || initialGeneration == 0 || initialGeneration > applicationMaxGeneration {
		return nil, applicationEvidenceError("owner_invalid", nil)
	}
	session, err := operation.resultContext(ctx)
	if err != nil || session == nil || operation.server == nil || operation.server.owner == nil || operation.server.config.Kernel.Scope != operation.scope {
		return nil, applicationEvidenceError("owner_invalid", err)
	}
	if err := lockOwnerObservation(ctx, &session.mu); err != nil {
		return nil, err
	}
	group := session.group
	valid := group != nil && session.retiredGroup == nil && session.cleanupFailure == nil && session.startupAttemptID == operation.attemptID && session.supervision != nil
	session.mu.Unlock()
	if !valid {
		return nil, applicationEvidenceError("owner_invalid", nil)
	}
	roles, err := applicationGenerationVector(group.Status())
	if err != nil {
		return nil, err
	}
	lifetime, err := applicationLifetimeID()
	if err != nil {
		return nil, err
	}
	return &applicationRuntimeProducer{operation: operation, session: session, group: group, generation: initialGeneration, lifetimeID: lifetime, roles: roles}, nil
}

func applicationLifetimeID() (string, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", applicationEvidenceError("entropy_unavailable", err)
	}
	return hex.EncodeToString(nonce[:]), nil
}

func applicationGenerationVector(states []protected.ProcessStatus) ([4]applicationRoleGeneration, error) {
	var result [4]applicationRoleGeneration
	if len(states) != len(result) {
		return result, applicationEvidenceError("generation_unavailable", nil)
	}
	for index, role := range protocol.Roles() {
		count := 0
		for _, state := range states {
			if state.Role != role {
				continue
			}
			count++
			if state.Exited || state.PID <= 0 || state.Generation == 0 || state.Generation > applicationMaxGeneration {
				return result, applicationEvidenceError("generation_unavailable", nil)
			}
			result[index] = applicationRoleGeneration{role, state.Generation, state.PID}
		}
		if count != 1 {
			return result, applicationEvidenceError("generation_unavailable", nil)
		}
	}
	return result, nil
}

// verify rejects a recovered member, a terminal group or a changed Session.
// It runs before signing and again immediately before transport publication.
func (p *applicationRuntimeProducer) verify(ctx context.Context, expected [4]applicationRoleGeneration) error {
	if p == nil || ctx == nil || ctx.Err() != nil || p.operation == nil || p.operation.lifetime == nil || p.operation.lifetime.Err() != nil || p.group == nil || p.session == nil {
		return applicationEvidenceError("lifetime_ended", nil)
	}
	select {
	case <-p.group.Done():
		return applicationEvidenceError("lifetime_ended", nil)
	default:
	}
	if err := lockOwnerObservation(ctx, &p.session.mu); err != nil {
		return err
	}
	valid := p.session.group == p.group && p.session.retiredGroup == nil && p.session.cleanupFailure == nil && p.session.supervision != nil && p.session.startupAttemptID == p.operation.attemptID
	p.session.mu.Unlock()
	if !valid {
		return applicationEvidenceError("lifetime_ended", nil)
	}
	actual, err := applicationGenerationVector(p.group.Status())
	if err != nil || actual != expected {
		return applicationEvidenceError("generation_changed", err)
	}
	return nil
}

// observe performs fresh native broker and kernel verification. It accepts no
// observation, generation vector, profile or runtime identity from a client.
func (p *applicationRuntimeProducer) observe(parent context.Context) (*ApplicationRuntimeEvidence, error) {
	if parent == nil {
		return nil, applicationEvidenceError("context_invalid", nil)
	}
	ctx, cancel := context.WithTimeout(parent, applicationEvidenceLimit)
	defer cancel()
	if p == nil || !p.mu.TryLock() {
		return nil, applicationEvidenceError("busy", nil)
	}
	defer p.mu.Unlock()
	if p.closed {
		return nil, applicationEvidenceError("lifetime_ended", nil)
	}
	if err := p.verify(ctx, p.roles); err != nil {
		p.closed = true
		return nil, err
	}
	c := p.operation.server.config
	profile, err := LoadProfile(c.ProfilePolicy)
	if err != nil {
		return nil, applicationEvidenceError("profile_unavailable", err)
	}
	declaration := profile.Declaration()
	if declaration.ProfileID != p.operation.scope.ProfileID || declaration.InstanceID != p.operation.scope.InstanceID || declaration.ReleaseFingerprint != p.operation.scope.ReleaseManifestDigest || declaration.ConfigDigest != "sha256:"+hexDigest(c.Compose) || declaration.NATSEndpoint != c.Kernel.Endpoint {
		return nil, applicationEvidenceError("profile_changed", nil)
	}
	facts, proof, err := inspectLocalBrokerOperation(ctx, c)
	if err != nil || facts.state != "running" {
		return nil, applicationEvidenceError("broker_unavailable", err)
	}
	snapshot, err := observeKernelWithProof(ctx, c.Kernel, proof)
	if err != nil {
		return nil, applicationEvidenceError("kernel_unavailable", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	expiry, err := applicationSnapshotExpiry(snapshot, p.operation.scope, now)
	if err != nil {
		return nil, err
	}
	if err := lockOwnerObservation(ctx, &p.session.mu); err != nil {
		return nil, err
	}
	_, current := p.session.currentKernelRoles(snapshot)
	p.session.mu.Unlock()
	if !current {
		return nil, applicationEvidenceError("generation_unavailable", nil)
	}
	if err := p.verify(ctx, p.roles); err != nil {
		p.closed = true
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, applicationEvidenceError("deadline", ctx.Err())
	}
	return &ApplicationRuntimeEvidence{producer: p, scope: p.operation.scope, generation: p.generation, lifetimeID: p.lifetimeID, issuedAt: now, expiresAt: expiry, roles: p.roles}, nil
}

func applicationSnapshotExpiry(snapshot protocol.Snapshot, scope protocol.Scope, now time.Time) (time.Time, error) {
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return time.Time{}, applicationEvidenceError("kernel_invalid", err)
	}
	admitted, err := protocol.DecodeSnapshot(raw, scope, now, applicationEvidenceLimit)
	if err != nil || admitted.KernelReadiness != "ready" {
		return time.Time{}, applicationEvidenceError("kernel_unavailable", err)
	}
	expiry, err := time.Parse(time.RFC3339Nano, admitted.ValidUntil)
	if err != nil || !now.Before(expiry) {
		return time.Time{}, applicationEvidenceError("kernel_unavailable", err)
	}
	if bound := now.Add(applicationEvidenceLimit); expiry.After(bound) {
		expiry = bound
	}
	return expiry, nil
}

// Recheck verifies retained ownership and freshness without extending validity.
func (e *ApplicationRuntimeEvidence) Recheck(ctx context.Context) error {
	if e == nil || e.producer == nil || ctx == nil || ctx.Err() != nil || !time.Now().Before(e.expiresAt) || e.issuedAt.After(time.Now()) {
		return applicationEvidenceError("evidence_unavailable", nil)
	}
	p := e.producer
	if !p.mu.TryLock() {
		return applicationEvidenceError("busy", nil)
	}
	defer p.mu.Unlock()
	if p.closed || p.generation != e.generation || p.lifetimeID != e.lifetimeID || p.operation.scope != e.scope {
		return applicationEvidenceError("lifetime_ended", nil)
	}
	return p.verify(ctx, e.roles)
}

// Facts returns a copy for the enrolled attestor. It does not contain policy,
// workspace or application-scope references: enrollment must supply those.
func (e *ApplicationRuntimeEvidence) Facts(ctx context.Context) (protocol.Scope, uint64, string, time.Time, time.Time, error) {
	if err := e.Recheck(ctx); err != nil {
		return protocol.Scope{}, 0, "", time.Time{}, time.Time{}, err
	}
	return e.scope, e.generation, e.lifetimeID, e.issuedAt, e.expiresAt, nil
}

// Lifetime returns the immutable identity needed to sign an end update after
// this evidence has expired or its runtime has stopped. It grants no new lease.
func (e *ApplicationRuntimeEvidence) Lifetime() (protocol.Scope, uint64, string, error) {
	if e == nil || e.producer == nil || e.generation == 0 || len(e.lifetimeID) != 64 {
		return protocol.Scope{}, 0, "", applicationEvidenceError("evidence_unavailable", nil)
	}
	return e.scope, e.generation, e.lifetimeID, nil
}

func (p *applicationRuntimeProducer) close() {
	if p != nil {
		p.mu.Lock()
		p.closed = true
		p.mu.Unlock()
	}
}
