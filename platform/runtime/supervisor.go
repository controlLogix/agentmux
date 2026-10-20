// Package runtime owns only the protected processes it starts itself.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/assembly"
)

var ErrPlatformUnqualified = errors.New("descriptor execution is not qualified on this platform")

const outputLimit = 32 * 1024

type Limits struct{ MaxBinaryBytes int64 }
type Deadlines struct{ StartTimeout, StopGrace, ReapTimeout time.Duration }

// RoleOptions contains literal arguments and explicit values for approved keys.
// Role identity and API environment values are supplied by the supervisor itself.
type RoleOptions struct {
	ID   string
	Args []string
	Env  map[string]string
	// LifetimeLease is an actual acquired advisory-lock descriptor supplied by
	// the trusted launcher. The caller must retain it through Start and serialize
	// its own Close. The runtime checks file ownership, not prior lock acquisition.
	LifetimeLease *os.File
}

type executable interface {
	command([]string) *exec.Cmd
	close() error
}

type Prepared struct {
	mu              sync.Mutex
	consumed        bool
	images          [4]executable
	roles           [4]string
	release         assembly.Trust
	recoveryCleanup [4]error
}

// Prepare verifies the external release policy, then checks the digest of each
// independently staged executable. A Verified path alone never grants execution.
func Prepare(ctx context.Context, raw []byte, packageDir string, trust assembly.Trust, limits Limits) (prepared *Prepared, failure error) {
	if ctx == nil {
		return nil, errors.New("preparation context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(raw) > 1024*1024 {
		return nil, errors.New("assembly exceeds the preparation size limit")
	}
	if limits.MaxBinaryBytes == 0 {
		limits.MaxBinaryBytes = 128 * 1024 * 1024
	}
	if limits.MaxBinaryBytes < 1 || limits.MaxBinaryBytes > 1024*1024*1024 {
		return nil, errors.New("binary preparation limit is invalid")
	}
	verified, err := assembly.Verify(raw, packageDir, trust)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(verified.PackageRoot())
	if err != nil {
		return nil, errors.New("verified package root is unavailable")
	}
	p := &Prepared{release: verified.Release()}
	defer func() {
		if cleanup := root.Close(); cleanup != nil {
			failure = retainStartupCleanupCause(failure, cleanup)
		}
		if failure != nil {
			prepared = nil
			if cleanup := p.Close(); cleanup != nil {
				failure = retainStartupCleanupCause(failure, cleanup)
			}
		}
	}()
	for i, member := range verified.Members() {
		entry, err := filepath.Rel(verified.PackageRoot(), member.Path)
		if err != nil {
			return nil, errors.New("verified member is outside the package")
		}
		image, err := prepareExecutable(ctx, root, entry, member.BinaryDigest, limits.MaxBinaryBytes)
		if err != nil {
			return nil, fmt.Errorf("prepare %s: %w", member.ID, err)
		}
		p.images[i] = image
		p.roles[i] = member.ID
	}
	return p, nil
}

// Close releases unused snapshots. It does not stop a Group already started.
func (p *Prepared) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.consumed = true
	var failures []error
	for i, image := range p.images {
		if p.recoveryCleanup[i] != nil {
			failures = append(failures, p.recoveryCleanup[i])
			continue
		}
		if image != nil {
			p.images[i] = nil
			failures = append(failures, image.close())
		}
	}
	if cleanup := errors.Join(failures...); cleanup != nil {
		return retainStartupCleanupCause(nil, cleanup)
	}
	return nil
}

type boundedOutput struct {
	mu        sync.Mutex
	data      []byte
	truncated bool
}

func (b *boundedOutput) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(data)
	space := outputLimit - len(b.data)
	if len(data) > space {
		b.truncated = true
		data = data[:space]
	}
	b.data = append(b.data, data...)
	return n, nil
}
func (b *boundedOutput) copy() ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.data...), b.truncated
}

type owned struct {
	role         string
	cmd          *exec.Cmd
	done         chan struct{}
	output       boundedOutput
	mu           sync.Mutex
	exitCode     int
	waitError    error
	parentWriter *os.File
	cleanupError error
}
type Group struct {
	childrenMu          sync.RWMutex
	recovery            *memberRecovery
	children            []*owned
	deadlines           Deadlines
	allDone             chan struct{}
	stopToken           chan struct{}
	cleanupMu           sync.Mutex
	contextCleanupError error
	contextCleanupDone  chan struct{}
	// Written before publication and retained as history, never as retry authority.
	imageCleanupError error
}
type ProcessStatus struct {
	Role            string
	PID             int
	Exited          bool
	ExitCode        int
	Generation      uint64
	RecoveryEnabled bool
}

var envKeys = map[string]bool{"AGENTMUX_NATS_URL": true, "AGENTMUX_NATS_CREDS_FILE": true, "AGENTMUX_NATS_SERVER_TRUST_FILE": true, "AGENTMUX_INSTANCE_ID": true, "AGENTMUX_PROFILE_ID": true}

func options(roles [4]string, supplied [4]RoleOptions) (map[string]RoleOptions, error) {
	result := map[string]RoleOptions{}
	for _, option := range supplied {
		found := false
		for _, role := range roles {
			if option.ID == role && role != "" {
				found = true
			}
		}
		if !found {
			return nil, errors.New("launch role is not a protected member")
		}
		if _, exists := result[option.ID]; exists {
			return nil, errors.New("launch role is repeated")
		}
		checked, err := copyRoleOptions(option)
		if err != nil {
			return nil, err
		}
		result[option.ID] = checked
	}
	return result, nil
}

func copyRoleOptions(option RoleOptions) (RoleOptions, error) {
	if len(option.Args) > 64 {
		return RoleOptions{}, errors.New("too many literal arguments")
	}
	args := append([]string(nil), option.Args...)
	size := 0
	for _, arg := range args {
		size += len(arg)
		if strings.ContainsRune(arg, 0) || size > 64*1024 {
			return RoleOptions{}, errors.New("literal arguments exceed their safe bounds")
		}
	}
	env := map[string]string{}
	for key, value := range option.Env {
		if !envKeys[key] || strings.ContainsRune(value, 0) || len(value) > 4096 {
			return RoleOptions{}, errors.New("launch environment contains an unapproved key or value")
		}
		env[key] = value
	}
	if err := validateLifetimeLease(option.LifetimeLease); err != nil {
		return RoleOptions{}, err
	}
	return RoleOptions{ID: option.ID, Args: args, Env: env, LifetimeLease: option.LifetimeLease}, nil
}

// Start launches four independent children from prepared descriptors. The parent
// context owns this bounded initial lifecycle; detaching a healthy runtime is later work.
func (p *Prepared) Start(ctx context.Context, supplied [4]RoleOptions, deadlines Deadlines) (*Group, error) {
	return p.start(ctx, supplied, deadlines, nil)
}

func (p *Prepared) start(ctx context.Context, supplied [4]RoleOptions, deadlines Deadlines, recovery *memberRecovery) (*Group, error) {
	if p == nil {
		return nil, errors.New("prepared assembly is required")
	}
	if ctx == nil {
		return nil, errors.New("startup context is required")
	}
	if deadlines.StartTimeout <= 0 || deadlines.StopGrace <= 0 || deadlines.ReapTimeout <= 0 {
		return nil, errors.New("positive lifecycle deadlines are required")
	}
	p.mu.Lock()
	if p.consumed {
		p.mu.Unlock()
		return nil, errors.New("prepared assembly has already been consumed")
	}
	selected, err := options(p.roles, supplied)
	if err != nil {
		p.mu.Unlock()
		return nil, err
	}
	p.consumed = true
	if recovery != nil {
		for role, option := range selected {
			recovery.generations[role] = 1
			recovery.enabled[role] = true
			recovery.options[role] = option
		}
	}
	g := &Group{recovery: recovery, deadlines: deadlines, allDone: make(chan struct{}), stopToken: make(chan struct{}, 1)}
	g.stopToken <- struct{}{}
	startCtx, cancel := context.WithTimeout(ctx, deadlines.StartTimeout)
	defer cancel()
	for i, role := range p.roles {
		if err = startCtx.Err(); err != nil {
			break
		}
		child, startErr := spawnOwned(startCtx, role, p.images[i], selected[role], deadlines)
		if child != nil {
			g.children = append(g.children, child)
		}
		if startErr != nil {
			err = startErr
			break
		}
	}
	var imageFailures []error
	for i, image := range p.images {
		if image != nil {
			p.images[i] = nil
			imageFailures = append(imageFailures, image.close())
		}
	}
	g.imageCleanupError = errors.Join(imageFailures...)
	p.mu.Unlock()
	g.watchChildren()

	if err == nil {
		err = startCtx.Err()
	}
	err = g.withImageCleanupCause(err)
	if err != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), deadlines.StopGrace+deadlines.ReapTimeout)
		defer cleanupCancel()
		cleanupErr := g.Stop(cleanupCtx)
		if cleanupErr != nil {
			return g, retainStartupCleanupCause(err, cleanupErr)
		}
		return g, fmt.Errorf("protected startup failed: %w", err)
	}
	g.contextCleanupDone = make(chan struct{})
	go func() {
		defer close(g.contextCleanupDone)
		select {
		case <-ctx.Done():
			cleanupCtx, cancel := context.WithTimeout(context.Background(), deadlines.StopGrace+deadlines.ReapTimeout)
			defer cancel()
			cleanupErr := g.Stop(cleanupCtx)
			g.cleanupMu.Lock()
			g.contextCleanupError = cleanupErr
			g.cleanupMu.Unlock()
		case <-g.allDone:
		}
	}()
	return g, nil
}

func (g *Group) Status() []ProcessStatus {
	g.childrenMu.RLock()
	defer g.childrenMu.RUnlock()
	result := make([]ProcessStatus, 0, len(g.children))
	for _, child := range g.children {
		exited := false
		select {
		case <-child.done:
			exited = true
		default:
		}
		child.mu.Lock()
		code := child.exitCode
		child.mu.Unlock()
		result = append(result, ProcessStatus{Role: child.role, PID: child.cmd.Process.Pid, Exited: exited, ExitCode: code, Generation: g.generationLocked(child.role), RecoveryEnabled: g.recoveryEnabledLocked(child.role)})
	}
	return result
}

// Output returns only a bounded copy of protected-role diagnostics, never an unbounded pipe.
func (g *Group) Output(role string) ([]byte, bool) {
	for _, child := range g.currentChildren() {
		if child.role == role {
			return child.output.copy()
		}
	}
	return nil, false
}
func (g *Group) Done() <-chan struct{} { return g.allDone }

// CleanupError preserves automatic context-cleanup failures even if children
// later exit. Done proves reaping, not successful descriptor cleanup. Callers
// must report the safe error separately from the actual process observations.
func (g *Group) CleanupError() error {
	if g == nil {
		return errors.New("process group is not owned by this supervisor")
	}
	// After actual reaping, join the bounded automatic cleanup path before
	// reporting its result. A failed Start has no lifetime watcher to join.
	if g.allDone != nil && g.contextCleanupDone != nil {
		select {
		case <-g.allDone:
			<-g.contextCleanupDone
		default:
		}
	}
	g.cleanupMu.Lock()
	err := g.contextCleanupError
	g.cleanupMu.Unlock()
	return g.withImageCleanupCause(errors.Join(err, g.resourceCleanupError()))
}

// Preserve private disposal causes even when a caller's context has expired.
// This field is immutable after Start and grants no descriptor or process retry.
func (g *Group) withImageCleanupCause(failure error) error {
	if g.imageCleanupError != nil {
		return retainStartupCleanupCause(failure, g.imageCleanupError)
	}
	return failure
}

func (g *Group) resourceCleanupError() error {
	var result error
	for _, child := range g.allChildren() {
		child.mu.Lock()
		err := child.cleanupError
		child.mu.Unlock()
		result = errors.Join(result, err)
	}
	return result
}

// Stop signals only Process handles returned by this Group's Start calls.
// It never finds, adopts, signals or waits for caller-supplied PIDs or process groups.
func (g *Group) Stop(ctx context.Context) error {
	if g == nil || g.allDone == nil || g.stopToken == nil {
		return errors.New("process group is not owned by this supervisor")
	}
	if ctx == nil {
		return errors.New("stop context is required")
	}
	if err := ctx.Err(); err != nil {
		return g.withImageCleanupCause(err)
	}
	if g.recovery != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, g.deadlines.StopGrace+g.deadlines.ReapTimeout)
		defer cancel()
	}
	g.closeRecoveryAdmission()
	select {
	case <-g.stopToken:
		defer func() { g.stopToken <- struct{}{} }()
	case <-ctx.Done():
		return g.withImageCleanupCause(ctx.Err())
	}
	if err := ctx.Err(); err != nil {
		return g.withImageCleanupCause(err)
	}
	select {
	case <-g.allDone:
		return g.withImageCleanupCause(g.resourceCleanupError())
	default:
	}
	if g.recovery != nil {
		return g.stopRecoverable(ctx)
	}
	for _, child := range g.currentChildren() {
		select {
		case <-child.done:
			continue
		default:
		}
		child.cmd.Process.Signal(syscall.SIGTERM)
	}
	grace := time.NewTimer(g.deadlines.StopGrace)
	defer grace.Stop()
	select {
	case <-g.allDone:
		return g.withImageCleanupCause(g.resourceCleanupError())
	case <-ctx.Done():
	case <-grace.C:
	}
	for _, child := range g.currentChildren() {
		select {
		case <-child.done:
			continue
		default:
		}
		child.cmd.Process.Kill()
	}
	reap := time.NewTimer(g.deadlines.ReapTimeout)
	defer reap.Stop()
	select {
	case <-g.allDone:
		return g.withImageCleanupCause(g.resourceCleanupError())
	case <-ctx.Done():
		return g.withImageCleanupCause(fmt.Errorf("owned process reaping is incomplete: %w", ctx.Err()))
	case <-reap.C:
		return g.withImageCleanupCause(errors.New("owned process reaping deadline exceeded"))
	}
}
