// Package runtime owns only the protected processes it starts itself.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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
	mu       sync.Mutex
	consumed bool
	images   [4]executable
	roles    [4]string
}

// Prepare verifies the external release policy, then checks the digest of each
// independently staged executable. A Verified path alone never grants execution.
func Prepare(ctx context.Context, raw []byte, packageDir string, trust assembly.Trust, limits Limits) (*Prepared, error) {
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
	defer root.Close()
	p := &Prepared{}
	for i, member := range verified.Members() {
		entry, err := filepath.Rel(verified.PackageRoot(), member.Path)
		if err != nil {
			p.Close()
			return nil, errors.New("verified member is outside the package")
		}
		image, err := prepareExecutable(ctx, root, entry, member.BinaryDigest, limits.MaxBinaryBytes)
		if err != nil {
			p.Close()
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
	var first error
	for i, image := range p.images {
		if image != nil {
			if err := image.close(); err != nil && first == nil {
				first = err
			}
			p.images[i] = nil
		}
	}
	return first
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
	children            []*owned
	deadlines           Deadlines
	allDone             chan struct{}
	stopToken           chan struct{}
	cleanupMu           sync.Mutex
	contextCleanupError error
	contextCleanupDone  chan struct{}
}
type ProcessStatus struct {
	Role     string
	PID      int
	Exited   bool
	ExitCode int
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
		if len(option.Args) > 64 {
			return nil, errors.New("too many literal arguments")
		}
		args := append([]string(nil), option.Args...)
		size := 0
		for _, arg := range args {
			size += len(arg)
			if strings.ContainsRune(arg, 0) || size > 64*1024 {
				return nil, errors.New("literal arguments exceed their safe bounds")
			}
		}
		env := map[string]string{}
		for key, value := range option.Env {
			if !envKeys[key] || strings.ContainsRune(value, 0) || len(value) > 4096 {
				return nil, errors.New("launch environment contains an unapproved key or value")
			}
			env[key] = value
		}
		if err := validateLifetimeLease(option.LifetimeLease); err != nil {
			return nil, err
		}
		result[option.ID] = RoleOptions{ID: option.ID, Args: args, Env: env, LifetimeLease: option.LifetimeLease}
	}
	return result, nil
}

// Start launches four independent children from prepared descriptors. The parent
// context owns this bounded initial lifecycle; detaching a healthy runtime is later work.
func (p *Prepared) Start(ctx context.Context, supplied [4]RoleOptions, deadlines Deadlines) (*Group, error) {
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
	g := &Group{deadlines: deadlines, allDone: make(chan struct{}), stopToken: make(chan struct{}, 1)}
	g.stopToken <- struct{}{}
	startCtx, cancel := context.WithTimeout(ctx, deadlines.StartTimeout)
	defer cancel()
	for i, role := range p.roles {
		if err = startCtx.Err(); err != nil {
			break
		}
		option := selected[role]
		cmd := p.images[i].command(option.Args)
		cmd.Args[0] = "agentmux-" + role
		cmd.Dir = "/"
		cmd.Env = []string{"AGENTMUX_KERNEL_ROLE=" + role, "AGENTMUX_KERNEL_API_MAJOR=1"}
		parentReader, parentWriter, leaseCopy, lifetimeErr := prepareChildLifetime(option.LifetimeLease)
		if lifetimeErr != nil {
			err = lifetimeErr
			break
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
		// Bound exec.Cmd's output-copy wait if a trusted role violates the no-descendant contract.
		cmd.WaitDelay = deadlines.ReapTimeout
		if err = startCtx.Err(); err != nil {
			err = errors.Join(err, closeChildStartFiles(parentReader, parentWriter, leaseCopy))
			break
		}
		// Protected path backends must recheck their held installation immediately
		// before spawning. Sealed descriptor backends need no path revalidation.
		if validator, ok := p.images[i].(interface{ validateForStart(context.Context) error }); ok {
			if err = validator.validateForStart(startCtx); err != nil {
				err = errors.Join(err, closeChildStartFiles(parentReader, parentWriter, leaseCopy))
				break
			}
		}
		if err = cmd.Start(); err != nil {
			err = errors.Join(err, closeChildStartFiles(parentReader, parentWriter, leaseCopy))
			break
		}
		// The child owns its inherited copies. Only the private writer stays here.
		copyCleanupErr := closeChildStartFiles(parentReader, leaseCopy)
		g.children = append(g.children, child)
		go func(c *owned) {
			e := c.cmd.Wait()
			writerCleanupErr := closeChildStartFiles(c.parentWriter)
			e = errors.Join(e, writerCleanupErr)
			c.mu.Lock()
			c.cleanupError = writerCleanupErr
			c.waitError = e
			if c.cmd.ProcessState != nil {
				c.exitCode = c.cmd.ProcessState.ExitCode()
			}
			c.mu.Unlock()
			close(c.done)
		}(child)
		if copyCleanupErr != nil {
			err = copyCleanupErr
			break
		}
	}
	for i, image := range p.images {
		if image != nil {
			image.close()
			p.images[i] = nil
		}
	}
	p.mu.Unlock()
	go func() {
		for _, child := range g.children {
			<-child.done
		}
		close(g.allDone)
	}()
	if err == nil {
		err = startCtx.Err()
	}
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
		result = append(result, ProcessStatus{Role: child.role, PID: child.cmd.Process.Pid, Exited: exited, ExitCode: code})
	}
	return result
}

// Output returns only a bounded copy of protected-role diagnostics, never an unbounded pipe.
func (g *Group) Output(role string) ([]byte, bool) {
	for _, child := range g.children {
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
	return errors.Join(err, g.resourceCleanupError())
}

func (g *Group) resourceCleanupError() error {
	var result error
	for _, child := range g.children {
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
	select {
	case <-g.stopToken:
		defer func() { g.stopToken <- struct{}{} }()
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-g.allDone:
		return g.resourceCleanupError()
	default:
	}
	for _, child := range g.children {
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
		return g.resourceCleanupError()
	case <-ctx.Done():
	case <-grace.C:
	}
	for _, child := range g.children {
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
		return g.resourceCleanupError()
	case <-ctx.Done():
		return fmt.Errorf("owned process reaping is incomplete: %w", ctx.Err())
	case <-reap.C:
		return errors.New("owned process reaping deadline exceeded")
	}
}
