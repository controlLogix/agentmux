//go:build linux || darwin

package runtime

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// HostInvocation carries only literal policy selection, never credentials or
// generic application arguments. Readiness is observed separately over NATS.
type HostInvocation struct {
	InvocationID   string
	PolicyPath     string
	WorkspaceRoots []string
}

type InstalledHostImage struct {
	mu       sync.Mutex
	image    executable
	consumed bool
	digest   string
}

// HostProcess retains the exact child handle and its sole wait operation.
// It is not an authority to signal a caller-supplied PID or another daemon.
type HostProcess struct {
	cmd       *exec.Cmd
	done      chan struct{}
	mu        sync.Mutex
	exitError error
}

func hostExecutionError(code string) error { return errors.New("installed_host_" + code) }

var installedHostDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (h *InstalledHostImage) Close() error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.consumed = true
	if h.image != nil {
		e := h.image.close()
		h.image = nil
		if e != nil {
			return hostExecutionError("snapshot_close_failed")
		}
	}
	return nil
}

func literalHostPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && len(path) <= 4096 && strings.IndexFunc(path, func(r rune) bool { return r < 32 || r == 127 }) < 0
}

func hostArguments(i HostInvocation) ([]string, error) {
	if !regexp.MustCompile(`^attempt_[0-9a-f]{32}$`).MatchString(i.InvocationID) || !literalHostPath(i.PolicyPath) || len(i.WorkspaceRoots) == 0 || len(i.WorkspaceRoots) > 16 {
		return nil, hostExecutionError("invocation_invalid")
	}
	args := []string{"host", "--host-policy", i.PolicyPath, "--invocation-id", i.InvocationID}
	seen := map[string]bool{}
	for _, root := range i.WorkspaceRoots {
		if !literalHostPath(root) || seen[root] {
			return nil, hostExecutionError("invocation_invalid")
		}
		seen[root] = true
		args = append(args, "--workspace", root)
	}
	return args, nil
}

func installedHostEnvironment() ([]string, error) {
	account, err := user.Current()
	if err != nil || account.Uid != strconv.Itoa(os.Geteuid()) {
		return nil, hostExecutionError("os_identity_unavailable")
	}
	env := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "HOME=" + account.HomeDir, "USER=" + account.Username, "LOGNAME=" + account.Username}
	// WSL's existing interop socket is OS infrastructure required by the selected
	// Windows-owned client. No sockets are created or searched for as a fallback.
	if value := os.Getenv("WSL_INTEROP"); runtime.GOOS == "linux" && value != "" {
		if !literalHostPath(value) || !strings.HasPrefix(value, "/run/WSL/") {
			return nil, hostExecutionError("interop_environment_invalid")
		}
		info, e := os.Lstat(value)
		if e != nil || info.Mode()&os.ModeSocket == 0 {
			return nil, hostExecutionError("interop_environment_invalid")
		}
		env = append(env, "WSL_INTEROP="+value)
	}
	return env, nil
}

// StartHost bounds validation and spawn only. Cancelling the frontend context
// after Start succeeds does not terminate the host. The host owns its signal
// lifetime and the protected child EOF/leases. No status travels on a local pipe.
func (h *InstalledHostImage) StartHost(ctx context.Context, invocation HostInvocation) (*HostProcess, error) {
	return h.startHost(ctx, invocation, nil)
}

func (h *InstalledHostImage) startHost(ctx context.Context, invocation HostInvocation, receipt *bootstrapReceiptPipe) (*HostProcess, error) {
	if ctx == nil || ctx.Err() != nil || h == nil {
		return nil, hostExecutionError("start_cancelled")
	}
	args, err := hostArguments(invocation)
	if err != nil {
		return nil, err
	}
	env, err := installedHostEnvironment()
	if err != nil {
		return nil, err
	}
	for !h.mu.TryLock() {
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, hostExecutionError("start_cancelled")
		case <-timer.C:
		}
	}
	defer h.mu.Unlock()
	if h.consumed || h.image == nil {
		return nil, hostExecutionError("image_consumed")
	}
	if ctx.Err() != nil {
		return nil, hostExecutionError("start_cancelled")
	}
	cmd := h.image.command(args)
	cmd.Env = env
	if receipt != nil {
		if h.digest != receipt.binding.RuntimeDigest {
			return nil, receiptError("binding_invalid")
		}
		fd := 3 + len(cmd.ExtraFiles)
		cmd.ExtraFiles = append(cmd.ExtraFiles, receipt.writer)
		cmd.Env = append(cmd.Env, bootstrapReceiptFDEnvironment+"="+strconv.Itoa(fd))
	}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.WaitDelay = 2 * time.Second
	// Nil standard streams use the null device, avoiding inherited terminals,
	// application pipes, credentials in output and terminal-close cancellation.
	if validator, ok := h.image.(interface{ validateForStart(context.Context) error }); ok {
		if err := validator.validateForStart(ctx); err != nil {
			return nil, hostExecutionError("image_changed")
		}
	}
	if ctx.Err() != nil {
		return nil, hostExecutionError("start_cancelled")
	}
	if cmd.Start() != nil {
		return nil, hostExecutionError("start_failed")
	}
	h.consumed = true
	p := &HostProcess{cmd: cmd, done: make(chan struct{})}
	go func() {
		e := cmd.Wait()
		p.mu.Lock()
		if e != nil {
			p.exitError = hostExecutionError("exited_failed")
		}
		p.mu.Unlock()
		close(p.done)
	}()
	return p, nil
}

func (p *HostProcess) Done() <-chan struct{} {
	if p == nil {
		return nil
	}
	return p.done
}
func (p *HostProcess) Wait(ctx context.Context) error {
	if p == nil || ctx == nil {
		return hostExecutionError("wait_invalid")
	}
	select {
	case <-p.done:
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.exitError
	case <-ctx.Done():
		return hostExecutionError("wait_cancelled")
	}
}
func (p *HostProcess) Stop(ctx context.Context) error {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return hostExecutionError("stop_invalid")
	}
	select {
	case <-p.done:
		return p.Wait(ctx)
	default:
	}
	if p.cmd.Process.Signal(syscall.SIGTERM) != nil {
		select {
		case <-p.done:
			return p.Wait(ctx)
		default:
			return hostExecutionError("signal_failed")
		}
	}
	return p.Wait(ctx)
}
