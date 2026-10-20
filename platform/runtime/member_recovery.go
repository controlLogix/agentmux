package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/assembly"
)

// RecoveryPolicy is opt-in. It permits at most two admitted spawn attempts per
// member; callers still need current scoped NATS observations for readiness.
type RecoveryPolicy struct {
	MaxAttemptsPerRole int
	Timeout            time.Duration
}

type memberRecovery struct {
	policy      RecoveryPolicy
	release     assembly.Trust
	generations map[string]uint64
	attempts    map[string]int
	enabled     map[string]bool
	options     map[string]RoleOptions
	retired     []*owned
	inflight    int
	stopping    atomic.Bool
	done        sync.Once
}

// StartRecoverable keeps admission open after member exit until Stop, context
// cancellation, or exhaustion of all eligible members. Unlike default Start,
// Done therefore includes the recovery lifetime, not just the initial children.
func (p *Prepared) StartRecoverable(ctx context.Context, supplied [4]RoleOptions, deadlines Deadlines, policy RecoveryPolicy) (*Group, error) {
	if p == nil || p.release.AssemblyDigest == "" || policy.MaxAttemptsPerRole < 1 || policy.MaxAttemptsPerRole > 2 || policy.Timeout <= 0 || policy.Timeout > deadlines.StartTimeout {
		return nil, errors.New("protected recovery policy is invalid")
	}
	return p.start(ctx, supplied, deadlines, &memberRecovery{policy: policy, release: p.release,
		generations: map[string]uint64{}, attempts: map[string]int{}, enabled: map[string]bool{}, options: map[string]RoleOptions{}})
}

// RecoveryCleanupError retains the exact unused prepared images and both the
// operation and disposal causes. Private images and causes never enter output.
type RecoveryCleanupError struct {
	Prepared *Prepared
	cause    error
}

func (e *RecoveryCleanupError) Error() string {
	return "protected recovery failed; owned image cleanup incomplete"
}
func (e *RecoveryCleanupError) Format(state fmt.State, _ rune) { fmt.Fprint(state, e.Error()) }
func (e *RecoveryCleanupError) MarshalJSON() ([]byte, error)   { return json.Marshal(e.Error()) }
func (e *RecoveryCleanupError) Unwrap() error                  { return errors.Join(ErrStartupCleanup, e.cause) }

// RetryClose retains a failed native close as unresolved. Current file backends
// consume their handles on the first close, even on failure. Repeating that
// close is not evidence of success; no backend-safe retry capability is declared.
func (e *RecoveryCleanupError) RetryClose() error {
	if e == nil || e.Prepared == nil {
		return errors.New("recovery cleanup owner is unavailable")
	}
	return e
}

func closeRecoveryPrepared(p *Prepared) error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.consumed = true
	var result error
	for i, image := range p.images {
		if p.recoveryCleanup[i] != nil {
			result = errors.Join(result, p.recoveryCleanup[i])
			continue
		}
		if image == nil {
			continue
		}
		if err := image.close(); err != nil {
			p.recoveryCleanup[i] = err
			result = errors.Join(result, err)
		} else {
			p.images[i] = nil
		}
	}
	return result
}

func (g *Group) generationLocked(role string) uint64 {
	if g.recovery == nil {
		return 1
	}
	return g.recovery.generations[role]
}
func (g *Group) recoveryEnabledLocked(role string) bool {
	return g.recovery != nil && !g.recovery.stopping.Load() && g.recovery.enabled[role] && g.recovery.attempts[role] < g.recovery.policy.MaxAttemptsPerRole
}

func (g *Group) RoleGeneration(role string) (uint64, bool) {
	if g == nil {
		return 0, false
	}
	g.childrenMu.RLock()
	defer g.childrenMu.RUnlock()
	for _, child := range g.children {
		if child.role == role {
			return g.generationLocked(role), true
		}
	}
	return 0, false
}
func (g *Group) currentChildren() []*owned {
	g.childrenMu.RLock()
	defer g.childrenMu.RUnlock()
	return append([]*owned(nil), g.children...)
}
func (g *Group) allChildren() []*owned {
	g.childrenMu.RLock()
	defer g.childrenMu.RUnlock()
	result := append([]*owned(nil), g.children...)
	if g.recovery != nil {
		result = append(result, g.recovery.retired...)
	}
	return result
}
func (g *Group) closeRecoveryAdmission() {
	if g.recovery == nil {
		return
	}
	g.recovery.stopping.Store(true)
	g.finishRecovery()
}
func (g *Group) finishRecovery() {
	if g.recovery == nil {
		return
	}
	g.childrenMu.Lock()
	defer g.childrenMu.Unlock()
	r := g.recovery
	if r.inflight != 0 {
		return
	}
	if !r.stopping.Load() {
		for role, enabled := range r.enabled {
			if enabled && r.attempts[role] < r.policy.MaxAttemptsPerRole {
				return
			}
		}
	}
	for _, child := range g.children {
		select {
		case <-child.done:
		default:
			return
		}
	}
	r.done.Do(func() { close(g.allDone) })
}
func (g *Group) watchChildren() {
	if g.recovery == nil {
		go func() {
			for _, child := range g.currentChildren() {
				<-child.done
			}
			close(g.allDone)
		}()
		return
	}
	for _, child := range g.currentChildren() {
		g.watchRecoveryChild(child)
	}
	g.finishRecovery()
}
func (g *Group) watchRecoveryChild(child *owned) {
	go func() { <-child.done; g.finishRecovery() }()
}

// RecoverRole consumes a freshly verified full assembly, even on refusal. It
// never adopts a PID or accepts launch paths from a wire request. Only a dead,
// fully reaped current member may be replaced. Args and environment stay fixed;
// the trusted caller supplies a newly acquired role lifetime lease.
func (g *Group) RecoverRole(parent context.Context, role string, expectedGeneration uint64, replacement *Prepared, option RoleOptions) (generation uint64, failure error) {
	tokenHeld := false
	defer func() {
		if cleanup := closeRecoveryPrepared(replacement); cleanup != nil {
			failure = &RecoveryCleanupError{Prepared: replacement, cause: errors.Join(failure, cleanup)}
		}
		if tokenHeld {
			g.stopToken <- struct{}{}
		}
	}()
	if g == nil || g.recovery == nil || replacement == nil || parent == nil {
		return 0, errors.New("protected recovery is not configured")
	}
	ctx, cancel := context.WithTimeout(parent, g.recovery.policy.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	select {
	case <-g.stopToken:
		tokenHeld = true
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	checked, err := copyRoleOptions(option)
	if err != nil {
		return 0, err
	}
	g.childrenMu.Lock()
	r := g.recovery
	index := -1
	for i, child := range g.children {
		if child.role == role {
			index = i
		}
	}
	if index < 0 || option.ID != role || r.stopping.Load() || !r.enabled[role] || r.generations[role] != expectedGeneration || r.attempts[role] >= r.policy.MaxAttemptsPerRole {
		g.childrenMu.Unlock()
		return 0, errors.New("protected recovery selection is stale, stopped or exhausted")
	}
	old := g.children[index]
	select {
	case <-old.done:
	default:
		g.childrenMu.Unlock()
		return 0, errors.New("protected member has not completed owned reaping")
	}
	old.mu.Lock()
	oldCleanup := old.cleanupError
	old.mu.Unlock()
	if oldCleanup != nil {
		g.childrenMu.Unlock()
		return 0, retainStartupCleanupCause(errors.New("protected member cleanup is incomplete"), oldCleanup)
	}
	original := r.options[role]
	if !reflect.DeepEqual(checked.Args, original.Args) || !reflect.DeepEqual(checked.Env, original.Env) || (original.LifetimeLease != nil && checked.LifetimeLease == nil) {
		g.childrenMu.Unlock()
		return 0, errors.New("protected recovery launch settings differ from initial admission")
	}
	replacement.mu.Lock()
	if replacement.consumed || replacement.release != r.release {
		replacement.mu.Unlock()
		g.childrenMu.Unlock()
		return 0, errors.New("protected replacement release is not the current fixed assembly")
	}
	member := -1
	for i, id := range replacement.roles {
		if id == role {
			member = i
		}
	}
	if member < 0 || replacement.images[member] == nil {
		replacement.mu.Unlock()
		g.childrenMu.Unlock()
		return 0, errors.New("protected replacement member is missing")
	}
	replacement.consumed = true
	image := replacement.images[member]
	r.attempts[role]++
	r.inflight++
	g.childrenMu.Unlock()
	child, startErr := spawnOwned(ctx, role, image, checked, g.deadlines)
	replacement.mu.Unlock()
	g.childrenMu.Lock()
	r.inflight--
	if child != nil {
		r.retired = append(r.retired, old)
		g.children[index] = child
		r.generations[role]++
		generation = r.generations[role]
	}
	g.childrenMu.Unlock()
	if child != nil {
		g.watchRecoveryChild(child)
	}
	g.finishRecovery()
	if startErr != nil {
		return generation, startErr
	}
	if err := ctx.Err(); err != nil {
		return generation, err
	}
	return generation, nil
}

func spawnOwned(ctx context.Context, role string, image executable, option RoleOptions, deadlines Deadlines) (*owned, error) {
	cmd := image.command(option.Args)
	cmd.Args[0] = "agentmux-" + role
	cmd.Dir = "/"
	cmd.Env = []string{"AGENTMUX_KERNEL_ROLE=" + role, "AGENTMUX_KERNEL_API_MAJOR=1"}
	parentReader, parentWriter, leaseCopy, err := prepareChildLifetime(option.LifetimeLease)
	if err != nil {
		return nil, err
	}
	parentFD := 3 + len(cmd.ExtraFiles)
	cmd.ExtraFiles = append(cmd.ExtraFiles, parentReader)
	cmd.Env = append(cmd.Env, fmt.Sprintf("AGENTMUX_KERNEL_PARENT_FD=%d", parentFD))
	if leaseCopy != nil {
		leaseFD := 3 + len(cmd.ExtraFiles)
		cmd.ExtraFiles = append(cmd.ExtraFiles, leaseCopy)
		cmd.Env = append(cmd.Env, fmt.Sprintf("AGENTMUX_KERNEL_LEASE_FD=%d", leaseFD))
	}
	keys := make([]string, 0, len(option.Env))
	for key := range option.Env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		cmd.Env = append(cmd.Env, key+"="+option.Env[key])
	}
	child := &owned{role: role, cmd: cmd, done: make(chan struct{}), exitCode: -1, parentWriter: parentWriter}
	cmd.Stdout = &child.output
	cmd.Stderr = &child.output
	cmd.WaitDelay = deadlines.ReapTimeout
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, closeChildStartFiles(parentReader, parentWriter, leaseCopy))
	}
	if validator, ok := image.(interface{ validateForStart(context.Context) error }); ok {
		if err := validator.validateForStart(ctx); err != nil {
			return nil, errors.Join(err, closeChildStartFiles(parentReader, parentWriter, leaseCopy))
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, closeChildStartFiles(parentReader, parentWriter, leaseCopy))
	}
	if err := cmd.Start(); err != nil {
		return nil, errors.Join(err, closeChildStartFiles(parentReader, parentWriter, leaseCopy))
	}
	copyCleanup := closeChildStartFiles(parentReader, leaseCopy)
	go func(c *owned) {
		waitErr := c.cmd.Wait()
		writerCleanup := closeChildStartFiles(c.parentWriter)
		c.mu.Lock()
		c.cleanupError = writerCleanup
		c.waitError = errors.Join(waitErr, writerCleanup)
		if c.cmd.ProcessState != nil {
			c.exitCode = c.cmd.ProcessState.ExitCode()
		}
		c.mu.Unlock()
		close(c.done)
	}(child)
	return child, copyCleanup
}

// The caller owns stopToken and has closed recovery admission. One deadline
// covers reverse-order TERM, KILL and the original Wait/output completion.
func (g *Group) stopRecoverable(ctx context.Context) error {
	children := g.currentChildren()
	ordered := make([]*owned, 0, len(children))
	for _, role := range []string{"exported-status", "internal-communication", "kernel-lifecycle", "boot"} {
		for _, child := range children {
			if child.role == role {
				ordered = append(ordered, child)
			}
		}
	}
	graceEnd := time.Now().Add(g.deadlines.StopGrace)
	if deadline, ok := ctx.Deadline(); ok && graceEnd.After(deadline.Add(-g.deadlines.ReapTimeout)) {
		graceEnd = deadline.Add(-g.deadlines.ReapTimeout)
	}
	killRemaining := func(from int) {
		for _, child := range ordered[from:] {
			select {
			case <-child.done:
			default:
				_ = child.cmd.Process.Kill()
			}
		}
	}
	for index, child := range ordered {
		select {
		case <-child.done:
			continue
		default:
		}
		if ctx.Err() != nil {
			killRemaining(index)
			return g.withImageCleanupCause(fmt.Errorf("owned ordered shutdown reaping is incomplete: %w", ctx.Err()))
		}
		_ = child.cmd.Process.Signal(syscall.SIGTERM)
		share := time.Until(graceEnd) / time.Duration(len(ordered)-index)
		if share < 0 {
			share = 0
		}
		timer := time.NewTimer(share)
		exited := false
		select {
		case <-child.done:
			exited = true
		case <-timer.C:
		case <-ctx.Done():
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		if exited {
			continue
		}
		_ = child.cmd.Process.Kill()
		select {
		case <-child.done:
		case <-ctx.Done():
			killRemaining(index + 1)
			return g.withImageCleanupCause(fmt.Errorf("owned ordered shutdown reaping is incomplete: %w", ctx.Err()))
		}
	}
	g.finishRecovery()
	return g.withImageCleanupCause(g.resourceCleanupError())
}
