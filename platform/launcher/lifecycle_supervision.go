//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

type supervisedObservation struct {
	generation  uint64
	incarnation string
	at          time.Time
}

// lifecycleSupervision belongs only to the cold-start owner. Reused sessions
// never acquire process control or adopt another owner's members.
type lifecycleSupervision struct {
	mu               sync.Mutex
	group            *protected.Group
	config           BootstrapConfig
	profile          Profile
	failed, stopped  map[string]bool
	observed         map[string]supervisedObservation
	cancel           context.CancelFunc
	done             chan struct{}
	failure, cleanup error
	recoverBroker    func(context.Context) error
}

func startLifecycleSupervision(parent context.Context, c BootstrapConfig, profile Profile, group *protected.Group, recoverBroker func(context.Context) error) *lifecycleSupervision {
	ctx, cancel := context.WithCancel(parent)
	s := &lifecycleSupervision{group: group, config: c, profile: profile, failed: map[string]bool{}, stopped: map[string]bool{}, observed: map[string]supervisedObservation{}, cancel: cancel, done: make(chan struct{}), recoverBroker: recoverBroker}
	go func() {
		defer close(s.done)
		wire, err := communication.Subjects(c.Kernel.Scope.HubID)
		if err != nil {
			s.record(err)
			return
		}
		config := protocol.Config{Credentials: protocol.Credentials{SchemaVersion: protocol.Version, Role: "kernel-lifecycle", Username: "kernel-lifecycle", Password: c.brokerUsers["kernel-lifecycle"], NATSURL: c.Kernel.Endpoint, Scope: c.Kernel.Scope}, ServerTrust: c.Kernel.TLS, Interval: 200 * time.Millisecond, StaleAfter: 3 * time.Second}
		for attempt := 0; ; attempt++ {
			err := protocol.RunLifecycleSupervisor(ctx, config, protocol.SubjectSet{Commands: wire.Commands, Events: wire.Events, Snapshot: wire.Snapshot, Update: wire.Update}, s)
			if ctx.Err() != nil {
				s.record(err)
				return
			}
			if errors.Is(err, protocol.ErrCleanup) || errors.Is(err, protocol.ErrBrokerAuthentication) || errors.Is(err, protocol.ErrBrokerAuthorization) || errors.Is(err, protocol.ErrServerAuthentication) || attempt >= 2 || s.recoverBroker == nil {
				s.record(err)
				return
			}
			operation, cancel := context.WithTimeout(ctx, 10*time.Second)
			recoveryErr := s.recoverBroker(operation)
			cancel()
			if recoveryErr != nil {
				s.record(errors.Join(err, recoveryErr))
				return
			}
		}
	}()
	return s
}

func (s *lifecycleSupervision) record(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failure = errors.Join(s.failure, err)
	if errors.Is(err, protocol.ErrCleanup) || errors.Is(err, protected.ErrStartupCleanup) {
		s.cleanup = errors.Join(s.cleanup, err)
	}
}

func (s *lifecycleSupervision) Inventory() []protocol.LifecycleMember {
	states := s.group.Status()
	s.mu.Lock()
	defer s.mu.Unlock()
	members := make([]protocol.LifecycleMember, 0, len(states))
	for _, state := range states {
		status := "running"
		if state.Exited {
			status = "exited"
			if !state.RecoveryEnabled {
				status = "failed"
			}
		}
		if s.stopped[state.Role] && state.Exited {
			status = "stopped"
		}
		if s.failed[state.Role] {
			status = "failed"
		}
		members = append(members, protocol.LifecycleMember{Role: state.Role, Generation: state.Generation, State: status})
	}
	return members
}

func (s *lifecycleSupervision) Observe(role string, generation uint64, event protocol.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observed[role] = supervisedObservation{generation, event.Incarnation, time.Now()}
}

func lifecycleRequestContext(parent context.Context, request protocol.LifecycleRequest, scope protocol.Scope, limit time.Duration) (context.Context, context.CancelFunc, error) {
	if parent == nil || parent.Err() != nil {
		return nil, nil, bootstrapError("member_recovery_cancelled")
	}
	encoded, encodeErr := json.Marshal(request)
	if encodeErr != nil {
		return nil, nil, bootstrapError("member_recovery_request_invalid")
	}
	validated, requestErr := protocol.DecodeLifecycleRequest(encoded, scope, time.Now())
	if requestErr != nil || limit <= 0 {
		return nil, nil, bootstrapError("member_recovery_request_invalid")
	}
	expires, _ := time.Parse(time.RFC3339Nano, validated.ExpiresAt)
	if maximum := time.Now().Add(limit); maximum.Before(expires) {
		expires = maximum
	}
	ctx, cancel := context.WithDeadline(parent, expires)
	return ctx, cancel, nil
}

func (s *lifecycleSupervision) Apply(parent context.Context, request protocol.LifecycleRequest) (generation uint64, failure error) {
	ctx, cancel, requestErr := lifecycleRequestContext(parent, request, s.config.Kernel.Scope, s.config.Deadlines.StartTimeout)
	if requestErr != nil {
		return 0, requestErr
	}
	defer cancel()
	states := s.group.Status()
	var selected *protected.ProcessStatus
	for i := range states {
		if states[i].Role == request.Role {
			selected = &states[i]
		}
	}
	if selected == nil || selected.Generation != request.ExpectedGeneration {
		return 0, bootstrapError("member_generation_changed")
	}
	generation = selected.Generation
	if request.Action == "stop" {
		s.mu.Lock()
		s.stopped[request.Role] = true
		s.mu.Unlock()
		return generation, s.group.StopRole(ctx, request.Role)
	}
	if request.Action != "recover" || !selected.Exited || s.config.admissionPolicy == nil {
		return generation, bootstrapError("member_recovery_refused")
	}
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if failure != nil {
			s.failed[request.Role] = true
			if errors.Is(failure, protocol.ErrCleanup) || errors.Is(failure, protected.ErrStartupCleanup) || errors.Is(failure, errRuntimeCleanup) {
				s.cleanup = errors.Join(s.cleanup, failure)
			}
		} else {
			delete(s.failed, request.Role)
		}
	}()
	// Reload private enrollment and the complete signed release. The request
	// chooses only the owned role; it cannot supply an image, path or arguments.
	fresh, err := LoadBootstrapConfig(*s.config.admissionPolicy)
	if err != nil {
		return generation, err
	}
	loaded, err := LoadProfile(s.config.ProfilePolicy)
	if err != nil || !reflect.DeepEqual(loaded.Declaration(), s.profile) || fresh.ReleaseTrust != s.config.ReleaseTrust || fresh.Kernel.Scope != s.config.Kernel.Scope {
		return generation, bootstrapError("member_recovery_enrollment_changed")
	}
	selection, _ := loaded.LocalDocker()
	lease, err := AcquireBootstrapLock(ctx, s.profile.ProfileDirectory, s.profile.InstanceID, selection.EngineID+":runtime:"+request.Role)
	if err != nil {
		return generation, err
	}
	defer func() {
		if err := lease.Close(); err != nil {
			failure = &bootstrapFailureCause{code: "lease_close_failed", cause: errors.Join(failure, err, errRuntimeCleanup), leases: []*BootstrapLock{lease}}
		}
	}()
	replacement, err := protected.Prepare(ctx, fresh.Assembly, fresh.PackageDirectory, fresh.ReleaseTrust, protected.Limits{})
	if err != nil {
		return generation, bootstrapRuntimeFailure("member_preparation_failed", err, replacement)
	}
	var option protected.RoleOptions
	for _, candidate := range fresh.Roles {
		if candidate.ID == request.Role {
			option = candidate
		}
	}
	option.LifetimeLease = lease.file
	s.mu.Lock()
	delete(s.observed, request.Role)
	generation, err = s.group.RecoverRole(ctx, request.Role, request.ExpectedGeneration, replacement, option)
	s.mu.Unlock()
	return generation, err
}

func (s *lifecycleSupervision) close(ctx context.Context) error {
	s.cancel()
	select {
	case <-s.done:
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.cleanup
	case <-ctx.Done():
		return bootstrapError("member_supervision_cleanup_incomplete")
	}
}

// The caller may hold Session.mu. These helpers never acquire it.
func (s *Session) currentKernelSnapshot(snapshot protocol.Snapshot) bool {
	_, complete := s.currentKernelRoles(snapshot)
	return complete
}

func (s *Session) currentKernelRoles(snapshot protocol.Snapshot) (map[string]bool, bool) {
	allowed, complete, _, _ := s.kernelRolesState(snapshot)
	return allowed, complete
}

// kernelRolesState also reports busy when supervision held its lock (for a
// heartbeat or a replacement) and terminal when supervision failed or marked a
// role failed or stopped, so a caller can tell both apart from a stale heartbeat.
func (s *Session) kernelRolesState(snapshot protocol.Snapshot) (allowed map[string]bool, complete, busy, terminal bool) {
	if s == nil || s.supervision == nil {
		allowed := map[string]bool{}
		for _, role := range protocol.Roles() {
			allowed[role] = true
		}
		return allowed, true, false, false
	}
	controller := s.supervision
	// A replacement may hold this lock while spawning. Status must remain
	// bounded and report unknown rather than wait behind that operation.
	if !controller.mu.TryLock() {
		return map[string]bool{}, false, true, false
	}
	defer controller.mu.Unlock()
	allowed, complete = supervisedKernelRoles(snapshot, controller.group.Status(), controller.observed, controller.failed, controller.stopped, controller.config.Kernel.Scope, time.Now())
	terminal = controller.failure != nil
	for _, role := range protocol.Roles() {
		terminal = terminal || controller.failed[role] || controller.stopped[role]
	}
	return allowed, complete && !terminal, false, terminal
}

func supervisedKernelRoles(snapshot protocol.Snapshot, states []protected.ProcessStatus, observed map[string]supervisedObservation, failed, stopped map[string]bool, scope protocol.Scope, now time.Time) (map[string]bool, bool) {
	allowed := map[string]bool{}
	if snapshot.Scope != scope {
		return allowed, false
	}
	for _, state := range states {
		observation, ok := observed[state.Role]
		if state.Exited || failed[state.Role] || stopped[state.Role] || !ok || observation.generation != state.Generation || observation.at.After(now) || now.Sub(observation.at) > 3*time.Second {
			continue
		}
		for _, member := range snapshot.Members {
			if member.Role == state.Role && member.Incarnation == observation.incarnation {
				allowed[state.Role] = true
			}
		}
	}
	complete := len(states) == 4 && len(snapshot.Members) == 4
	for _, role := range protocol.Roles() {
		complete = complete && allowed[role]
	}
	return allowed, complete
}
