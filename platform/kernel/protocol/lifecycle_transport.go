package protocol

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/nats-io/nats.go"
)

// LifecycleOperations is implemented only by the trusted exact-handle owner.
// Inventory describes ownership; Apply must independently check generation,
// current ownership, immutable release admission and its own recovery limits.
type LifecycleOperations interface {
	Inventory() []LifecycleMember
	Apply(context.Context, LifecycleRequest) (uint64, error)
}

// LifecycleObservations lets the owner bind a newly observed incarnation to
// its current process generation. It does not turn an inventory into readiness.
type LifecycleObservations interface {
	Observe(string, uint64, Event)
}

func lifecycleTimes(now time.Time) (string, string) {
	return now.UTC().Format(time.RFC3339Nano), now.Add(3 * time.Second).UTC().Format(time.RFC3339Nano)
}

func (a *Actor) publishLifecycle(value any) error {
	if !a.conn.IsConnected() {
		return nil
	}
	if err := a.conn.Publish(a.subjects.Commands["kernel-lifecycle"], mustJSON(value)); err != nil {
		a.recordAuthorityFailure(err)
		if authority := a.authorityError(); authority != nil {
			return authority
		}
		return errors.New("kernel_lifecycle_publish_failed")
	}
	return nil
}

type completedLifecycleOperation struct {
	request LifecycleRequest
	result  LifecycleResult
}

// RunLifecycleSupervisor uses the existing narrow lifecycle principal and its
// protected command subject. It never publishes a role event or readiness.
func RunLifecycleSupervisor(ctx context.Context, c Config, subjects SubjectSet, operations LifecycleOperations) (failure error) {
	if operations == nil {
		return errors.New("kernel_lifecycle_owner_required")
	}
	a, err := Open(ctx, c, "kernel-lifecycle", subjects)
	if err != nil {
		return err
	}
	a.observationOnly = true
	defer func() {
		if a.Close() != nil {
			failure = &CleanupError{actor: a, cause: failure}
		}
	}()
	ticker := time.NewTicker(a.config.Interval)
	defer ticker.Stop()
	epoch := a.incarnation
	var revision uint64
	completed := map[string]completedLifecycleOperation{}
	var history error
	generations := map[string]uint64{}
	started := map[string]time.Time{}
	retired := map[string]map[string]bool{}
	selfAttempted := map[uint64]bool{}
	attempts := map[string]int{}
	current := func(now time.Time) LifecycleInventory {
		members := operations.Inventory()
		for i := range members {
			role := members[i].Role
			if generations[role] != members[i].Generation {
				if retired[role] == nil {
					retired[role] = map[string]bool{}
				}
				if previous := a.peers[role]; previous != nil {
					retired[role][previous.event.Incarnation] = true
				}
				delete(a.peers, role)
				generations[role] = members[i].Generation
				started[role] = now
			}
			if peer := a.peers[members[i].Role]; peer != nil {
				members[i].Incarnation = peer.event.Incarnation
			}
		}
		issued, expires := lifecycleTimes(now)
		revision++
		return LifecycleInventory{Version, "kernel-lifecycle-inventory", c.Credentials.Scope, epoch, revision, members, issued, expires}
	}
	announce := func() error {
		// Reconnecting inventory cannot reach the broker. In particular, do not
		// spend child replacement attempts before that child's broker is back.
		if !a.conn.IsConnected() {
			return nil
		}
		now := a.config.Services.Clock.Now()
		inventory := current(now)
		if _, err := DecodeLifecycleInventory(mustJSON(inventory), c.Credentials.Scope, now); err != nil {
			return err
		}
		if err := a.publishLifecycle(inventory); err != nil {
			return err
		}
		// A stopped lifecycle child cannot request its own recovery. The exact
		// handle owner makes this one bounded infrastructure attempt per generation.
		for _, member := range inventory.Members {
			if member.Role != "kernel-lifecycle" || member.State != "exited" || selfAttempted[member.Generation] || attempts[member.Role] >= 2 {
				continue
			}
			if !a.conn.IsConnected() {
				return nil
			}
			selfAttempted[member.Generation] = true
			attempts[member.Role]++
			var nonce [16]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				return errors.New("kernel_lifecycle_nonce_unavailable")
			}
			issued, expires := lifecycleTimes(now)
			request := LifecycleRequest{Version, "kernel-lifecycle-request", c.Credentials.Scope, epoch, a.incarnation, hex.EncodeToString(nonce[:]), "recover", member.Role, member.Generation, member.Incarnation, issued, expires}
			expiry, _ := time.Parse(time.RFC3339Nano, request.ExpiresAt)
			operationContext, cancelOperation := context.WithDeadline(ctx, expiry)
			_, operationErr := operations.Apply(operationContext, request)
			cancelOperation()
			// Bind the replacement generation before selecting queued events.
			// Otherwise its first event can be attributed to the old generation
			// and its new incarnation retired at the next inventory tick.
			current(a.config.Services.Clock.Now())
			if operationErr != nil {
				history = errors.Join(history, operationErr)
			}
		}
		return nil
	}
	if err := announce(); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return history
		case <-a.fault:
			if authority := a.authorityError(); authority != nil {
				return errors.Join(history, authority)
			}
			return errors.Join(history, errors.New("kernel_lifecycle_delivery_failed"))
		case <-ticker.C:
			if a.conn.IsClosed() {
				if authority := a.authorityError(); authority != nil {
					return errors.Join(history, authority)
				}
				return errors.Join(history, errors.New("kernel_broker_unavailable"))
			}
			if err := announce(); err != nil {
				return errors.Join(history, err)
			}
		case msg := <-a.messages:
			now := a.config.Services.Clock.Now()
			if msg.Subject != a.subjects.Commands["kernel-lifecycle"] {
				for role, subject := range a.subjects.Events {
					if subject != msg.Subject {
						continue
					}
					event, decodeErr := DecodeEvent(msg.Data, c.Credentials.Scope, role, now, a.config.StaleAfter)
					at, _ := time.Parse(time.RFC3339Nano, event.ObservedAt)
					if decodeErr == nil && !retired[role][event.Incarnation] && !at.Before(started[role]) && a.accept(msg, now) {
						if observations, ok := operations.(LifecycleObservations); ok {
							observations.Observe(role, generations[role], event)
						}
					}
				}
				continue
			}
			if msg.Reply != "" {
				continue
			}
			request, err := DecodeLifecycleRequest(msg.Data, c.Credentials.Scope, now)
			if err != nil || request.SupervisorEpoch != epoch {
				continue
			}
			issuer := a.peers["kernel-lifecycle"]
			if issuer == nil || issuer.event.Incarnation != request.LifecycleIncarnation || now.Sub(issuer.received) > a.config.StaleAfter {
				continue
			}
			inventory := current(now)
			var member *LifecycleMember
			issuerCurrent := false
			for i := range inventory.Members {
				if inventory.Members[i].Role == "kernel-lifecycle" && inventory.Members[i].State == "running" && inventory.Members[i].Incarnation == request.LifecycleIncarnation {
					issuerCurrent = true
				}
				if inventory.Members[i].Role == request.Role {
					member = &inventory.Members[i]
				}
			}
			if !issuerCurrent || member == nil || member.Generation != request.ExpectedGeneration || member.Incarnation != request.ExpectedIncarnation {
				continue
			}
			for id, old := range completed {
				if !lifecycleFresh(old.request.IssuedAt, old.request.ExpiresAt, now) {
					delete(completed, id)
				}
			}
			if old, ok := completed[request.RequestID]; ok {
				if old.request == request {
					if err := a.publishLifecycle(old.result); err != nil {
						return errors.Join(history, err)
					}
				}
				continue
			}
			if len(completed) >= 128 {
				continue
			}
			// A queued request may outlive its authenticated connection. Leave
			// its attempt and completion unconsumed while reconnecting.
			if !a.conn.IsConnected() {
				continue
			}
			generation, operationErr := member.Generation, error(nil)
			refused := attempts[request.Role] >= 3
			if !refused {
				attempts[request.Role]++
				expiry, _ := time.Parse(time.RFC3339Nano, request.ExpiresAt)
				operationContext, cancelOperation := context.WithDeadline(ctx, expiry)
				generation, operationErr = operations.Apply(operationContext, request)
				cancelOperation()
			}
			if generation == 0 {
				generation = member.Generation
			}
			outcome, code := "completed", "owned_operation_completed"
			if refused {
				outcome, code = "refused", "owned_operation_refused"
			}
			if operationErr != nil {
				outcome, code = "failed", "owned_operation_failed"
				history = errors.Join(history, operationErr)
			}
			issued, expires := lifecycleTimes(a.config.Services.Clock.Now())
			result := LifecycleResult{Version, "kernel-lifecycle-result", c.Credentials.Scope, epoch, request.RequestID, request.Role, generation, outcome, code, issued, expires}
			completed[request.RequestID] = completedLifecycleOperation{request, result}
			if err := a.publishLifecycle(result); err != nil {
				return errors.Join(history, err)
			}
			if err := announce(); err != nil {
				return errors.Join(history, err)
			}
		}
	}
}

// ServeLifecycle adds sibling recovery coordination to the lifecycle actor.
// Inventory never changes role readiness: that still comes from scoped events.
func (a *Actor) ServeLifecycle(ctx context.Context, evaluate func(View) Decision) error {
	if a == nil || a.role != "kernel-lifecycle" {
		return errors.New("kernel_lifecycle_role_required")
	}
	var inventory LifecycleInventory
	pending := map[string]LifecycleRequest{}
	completed := map[string]uint64{}
	a.lifecycleMessage = func(msg *nats.Msg, now time.Time) (bool, error) {
		if msg.Reply != "" {
			return false, nil
		}
		if value, err := DecodeLifecycleInventory(msg.Data, a.Scope(), now); err == nil {
			if inventory.SupervisorEpoch != "" && value.SupervisorEpoch != inventory.SupervisorEpoch && lifecycleFresh(inventory.IssuedAt, inventory.ExpiresAt, now) {
				return true, nil
			}
			if value.SupervisorEpoch == inventory.SupervisorEpoch && value.Revision <= inventory.Revision {
				return true, nil
			}
			if value.SupervisorEpoch != inventory.SupervisorEpoch {
				pending = map[string]LifecycleRequest{}
				completed = map[string]uint64{}
			}
			inventory = value
			return true, nil
		}
		if result, err := DecodeLifecycleResult(msg.Data, a.Scope(), now); err == nil {
			if request, ok := pending[result.Role]; ok && request.RequestID == result.RequestID && request.SupervisorEpoch == result.SupervisorEpoch {
				completed[result.Role] = request.ExpectedGeneration
				delete(pending, result.Role)
			}
			return true, nil
		}
		return false, nil
	}
	a.lifecycleTick = func(now time.Time) error {
		if !a.conn.IsConnected() || !lifecycleFresh(inventory.IssuedAt, inventory.ExpiresAt, now) {
			return nil
		}
		for _, member := range inventory.Members {
			if member.Role == "kernel-lifecycle" || member.State != "exited" || completed[member.Role] >= member.Generation {
				continue
			}
			request, ok := pending[member.Role]
			if !ok {
				var nonce [16]byte
				if _, err := rand.Read(nonce[:]); err != nil {
					return errors.New("kernel_lifecycle_nonce_unavailable")
				}
				issued, expires := lifecycleTimes(now)
				request = LifecycleRequest{Version, "kernel-lifecycle-request", a.Scope(), inventory.SupervisorEpoch, a.incarnation, hex.EncodeToString(nonce[:]), "recover", member.Role, member.Generation, member.Incarnation, issued, expires}
				pending[member.Role] = request
			} else if !lifecycleFresh(request.IssuedAt, request.ExpiresAt, now) {
				completed[member.Role] = request.ExpectedGeneration
				delete(pending, member.Role)
				continue
			}
			if err := a.publishLifecycle(request); err != nil {
				return err
			}
		}
		return nil
	}
	return a.Serve(ctx, evaluate, nil)
}
