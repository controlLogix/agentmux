//go:build (darwin && arm64) || ((linux || darwin) && agentmux_application_services)

package launcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/plugins"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

type serviceProcessFailure struct {
	code   string
	cause  error
	owners []any
}

func (e *serviceProcessFailure) Error() string                { return "application_services_" + e.code }
func (e *serviceProcessFailure) Format(s fmt.State, _ rune)   { fmt.Fprint(s, e.Error()) }
func (e *serviceProcessFailure) Unwrap() error                { return e.cause }
func (e *serviceProcessFailure) MarshalJSON() ([]byte, error) { return json.Marshal(e.Error()) }
func serviceProcessError(code string, cause error, owners ...any) error {
	return &serviceProcessFailure{code, cause, owners}
}

type applicationServiceChild interface {
	Start() (bool, error)
	CloseUnstarted() error
	Wait() error
	Signal(os.Signal) error
}
type applicationServiceInput interface {
	io.WriteCloser
	SetWriteDeadline(time.Time) error
}
type applicationServiceFactory func(io.Writer, io.Writer) (applicationServiceChild, applicationServiceInput, error)

type installedApplicationServiceChild struct {
	cmd           *exec.Cmd
	reader        *os.File
	readerClosed  bool
	readerFailure error
}

func (c *installedApplicationServiceChild) CloseUnstarted() error {
	if !c.readerClosed {
		c.readerClosed = true
		c.readerFailure = c.reader.Close()
	}
	return c.readerFailure
}
func (c *installedApplicationServiceChild) Start() (bool, error) {
	if err := c.cmd.Start(); err != nil {
		return false, err
	}
	// The child inherited its descriptor. The parent consumes only its own
	// reader, while the writer remains ours through the original wait.
	return true, c.CloseUnstarted()
}
func (c *installedApplicationServiceChild) Wait() error              { return c.cmd.Wait() }
func (c *installedApplicationServiceChild) Signal(s os.Signal) error { return c.cmd.Process.Signal(s) }

func newInstalledApplicationServiceChild(id string, lease *os.File) applicationServiceFactory {
	return func(stdout, stderr io.Writer) (applicationServiceChild, applicationServiceInput, error) {
		root := filepath.Join(protected.InstalledClientBase, id)
		cmd := exec.Command(filepath.Join(root, protected.ClientInterpreter), "-I", "-S", filepath.Join(root, protected.ClientBootstrap), "application-services")
		cmd.Dir = "/"
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=en_US.UTF-8", "LC_CTYPE=UTF-8"}
		cmd.Stdout, cmd.Stderr = stdout, stderr
		cmd.ExtraFiles = []*os.File{lease}
		cmd.WaitDelay = time.Second
		reader, input, err := os.Pipe()
		if err != nil {
			return nil, nil, err
		}
		cmd.Stdin = reader
		return &installedApplicationServiceChild{cmd: cmd, reader: reader}, input, nil
	}
}

type applicationServiceState struct {
	SchemaVersion   string         `json:"schemaVersion"`
	Kind            string         `json:"kind"`
	LifetimeID      string         `json:"lifetimeId"`
	SelectionSHA256 string         `json:"selectionSHA256"`
	KernelScope     protocol.Scope `json:"kernelScope"`
	State           string         `json:"state"`
}

// ApplicationServiceProcess implements the ordinary process ownership contract.
// LifetimeDone revokes availability immediately. Done separately means the sole
// original wait and output readers, plus the host-lifetime monitor, have joined.
type ApplicationServiceProcess struct {
	mu                                                        sync.Mutex
	request                                                   applicationServiceStart
	packageOwner                                              applicationServicePackage
	lease                                                     io.Closer
	child                                                     applicationServiceChild
	input                                                     applicationServiceInput
	inputClosed                                               bool
	inputFailure                                              error
	ready, drained, invalid, started, cleaned                 bool
	failure, exitError                                        error
	stdout, stderr                                            []byte
	stdoutTotal, stderrTotal                                  int
	readySignal, processDone, done, lifetimeDone, monitorDone chan struct{}
	stopToken                                                 chan struct{}
	lifetimeOnce                                              sync.Once
	drainOnce                                                 sync.Once
	hostLifetime                                              <-chan struct{}
}

func (*ApplicationServiceProcess) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "[owned application services]")
}
func (*ApplicationServiceProcess) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"owned-application-services"}`), nil
}

var _ plugins.OwnedInstance = (*ApplicationServiceProcess)(nil)
var _ plugins.InstanceAvailability = (*ApplicationServiceProcess)(nil)
var _ plugins.InstanceLifetime = (*ApplicationServiceProcess)(nil)

func newApplicationServiceProcess(request applicationServiceStart, admission applicationServicePackage, lease io.Closer) *ApplicationServiceProcess {
	p := &ApplicationServiceProcess{request: request, packageOwner: admission, lease: lease, readySignal: make(chan struct{}), processDone: make(chan struct{}), done: make(chan struct{}), lifetimeDone: make(chan struct{}), monitorDone: make(chan struct{}), stopToken: make(chan struct{}, 1)}
	p.stopToken <- struct{}{}
	return p
}

func serviceChannelClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func (p *ApplicationServiceProcess) endLifetime() {
	p.mu.Lock()
	p.invalid = true
	p.mu.Unlock()
	p.lifetimeOnce.Do(func() { close(p.lifetimeDone) })
}

func startApplicationServiceProcess(ctx context.Context, request applicationServiceStart, admission applicationServicePackage, lease io.Closer, hostLifetime <-chan struct{}, factory applicationServiceFactory) (*ApplicationServiceProcess, error) {
	p := newApplicationServiceProcess(request, admission, lease)
	p.hostLifetime = hostLifetime
	refuse := func(cause error) (*ApplicationServiceProcess, error) {
		if p.child != nil {
			if err := p.child.CloseUnstarted(); err != nil {
				p.failure = errors.Join(p.failure, serviceProcessError("input_reader_close_failed", err, p.child))
			}
		}
		p.endLifetime()
		p.mu.Lock()
		p.exitError = cause
		p.mu.Unlock()
		close(p.processDone)
		close(p.monitorDone)
		close(p.done)
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		return p, errors.Join(cause, p.Stop(cleanup))
	}
	if ctx == nil || ctx.Err() != nil || hostLifetime == nil || serviceChannelClosed(hostLifetime) || admission == nil || lease == nil || factory == nil {
		return refuse(serviceProcessError("start_cancelled", nil))
	}
	child, input, err := factory(applicationServiceOutput{p, false}, applicationServiceOutput{p, true})
	p.child, p.input = child, input
	if err != nil || child == nil || input == nil {
		return refuse(serviceProcessError("preparation_failed", err, p))
	}
	if err := admission.Recheck(ctx); err != nil {
		return refuse(serviceProcessError("package_changed", err, p))
	}
	if ctx.Err() != nil || serviceChannelClosed(hostLifetime) {
		return refuse(serviceProcessError("start_cancelled", ctx.Err(), p))
	}
	created, startErr := child.Start()
	if !created {
		return refuse(serviceProcessError("start_failed", startErr, p))
	}
	p.started = true
	if startErr != nil {
		p.mu.Lock()
		p.failure = errors.Join(p.failure, serviceProcessError("input_reader_close_failed", startErr, child))
		p.mu.Unlock()
	}
	go func() {
		err := child.Wait()
		p.mu.Lock()
		if err != nil {
			p.exitError = serviceProcessError("process_failed", err)
		}
		if errors.Is(err, exec.ErrWaitDelay) {
			p.failure = errors.Join(p.failure, serviceProcessError("output_join_incomplete", err, p))
			p.invalid = true
		}
		if len(p.stdout) != 0 {
			p.failure = errors.Join(p.failure, serviceProcessError("output_invalid", nil, p))
			p.invalid = true
		}
		p.mu.Unlock()
		p.endLifetime()
		p.closeInput()
		close(p.processDone)
		<-p.monitorDone
		close(p.done)
	}()
	go func() {
		defer close(p.monitorDone)
		select {
		case <-p.processDone:
		case <-hostLifetime:
			p.endLifetime()
			stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := p.stopChild(stop)
			cancel()
			if err != nil {
				p.mu.Lock()
				p.failure = errors.Join(p.failure, err)
				p.mu.Unlock()
			}
		}
	}()
	if startErr != nil {
		p.endLifetime()
		return p, serviceProcessError("start_failed", startErr, p)
	}
	raw, err := json.Marshal(request)
	if err == nil {
		err = p.writeInput(ctx, append(raw, '\n'))
	}
	if err != nil {
		p.endLifetime()
		return p, serviceProcessError("start_delivery_failed", err, p)
	}
	if err := p.WaitReady(ctx); err != nil {
		p.endLifetime()
		return p, err
	}
	return p, nil
}

func (p *ApplicationServiceProcess) Done() <-chan struct{} {
	if p == nil {
		return nil
	}
	return p.done
}
func (p *ApplicationServiceProcess) LifetimeDone() <-chan struct{} {
	if p == nil {
		return nil
	}
	return p.lifetimeDone
}
func (p *ApplicationServiceProcess) ExitError() error {
	if p == nil {
		return serviceProcessError("owner_invalid", nil)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exitError
}
func (p *ApplicationServiceProcess) Available() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ready && !p.invalid && !serviceChannelClosed(p.processDone) && !serviceChannelClosed(p.hostLifetime)
}
func (p *ApplicationServiceProcess) WaitReady(ctx context.Context) error {
	if ctx == nil || p == nil || p.done == nil {
		return serviceProcessError("context_invalid", nil)
	}
	select {
	case <-p.readySignal:
		if p.Available() {
			return nil
		}
	case <-p.done:
	case <-p.lifetimeDone:
	case <-ctx.Done():
		p.endLifetime()
		return serviceProcessError("start_cancelled", ctx.Err(), p)
	}
	return serviceProcessError("start_unavailable", nil, p)
}

func (p *ApplicationServiceProcess) writeInput(ctx context.Context, raw []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.input == nil || p.inputClosed {
		return serviceProcessError("input_closed", nil)
	}
	deadline := time.Now().Add(100 * time.Millisecond)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := p.input.SetWriteDeadline(deadline); err != nil {
		return err
	}
	n, err := p.input.Write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	return err
}
func (p *ApplicationServiceProcess) closeInput() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.input == nil || p.inputClosed {
		return p.inputFailure
	}
	p.inputClosed = true
	p.inputFailure = p.input.Close()
	return p.inputFailure
}

func (p *ApplicationServiceProcess) stopChild(ctx context.Context) error {
	if !serviceChannelClosed(p.processDone) {
		p.drainOnce.Do(func() {
			raw, _ := json.Marshal(struct {
				SchemaVersion string `json:"schemaVersion"`
				Kind          string `json:"kind"`
				LifetimeID    string `json:"lifetimeId"`
			}{protocol.Version, "application-services-stop", p.request.LifetimeID})
			_ = p.writeInput(ctx, append(raw, '\n'))
			_ = p.closeInput()
		})
		deadline := time.Now().Add(5 * time.Second)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		remaining := time.Until(deadline)
		for i, signal := range []os.Signal{nil, syscall.SIGTERM, syscall.SIGKILL} {
			if i > 0 && !serviceChannelClosed(p.processDone) {
				_ = p.child.Signal(signal)
			}
			wait := remaining / 4
			if i == 2 {
				wait = time.Until(deadline)
			}
			timer := time.NewTimer(max(0, wait))
			select {
			case <-p.processDone:
			case <-ctx.Done():
			case <-timer.C:
			}
			timer.Stop()
			if serviceChannelClosed(p.processDone) {
				break
			}
		}
	}
	if !serviceChannelClosed(p.processDone) {
		return serviceProcessError("cleanup_incomplete", ctx.Err(), p)
	}
	return nil
}

func (p *ApplicationServiceProcess) Stop(ctx context.Context) error {
	if ctx == nil || p == nil || p.stopToken == nil {
		return serviceProcessError("context_invalid", nil, p)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	select {
	case <-ctx.Done():
		return serviceProcessError("cleanup_incomplete", ctx.Err(), p)
	case <-p.stopToken:
	}
	defer func() { p.stopToken <- struct{}{} }()
	p.endLifetime()
	p.mu.Lock()
	cleaned, prior := p.cleaned, p.failure
	started := p.started
	p.mu.Unlock()
	if cleaned {
		return prior
	}
	if err := p.stopChild(ctx); err != nil {
		return err
	}
	select {
	case <-p.done:
	case <-ctx.Done():
		return serviceProcessError("cleanup_incomplete", ctx.Err(), p)
	}
	inputErr := p.closeInput()
	p.mu.Lock()
	if p.failure != nil {
		failure := p.failure
		p.mu.Unlock()
		return serviceProcessError("cleanup_incomplete", failure, p)
	}
	if started && (!p.drained || p.exitError != nil) {
		p.failure = errors.Join(p.failure, serviceProcessError("drain_unconfirmed", p.exitError, p))
	}
	if inputErr != nil {
		p.failure = errors.Join(p.failure, serviceProcessError("input_close_failed", inputErr, p))
	}
	failure := p.failure
	p.mu.Unlock()
	if failure != nil {
		return serviceProcessError("cleanup_incomplete", failure, p)
	}
	// Connections and service workers must have drained before the child emits
	// drained and exits. Only that joined outcome releases package and OS lease.
	var closeErr error
	var closedOwners []any
	if p.packageOwner != nil {
		closedOwners = append(closedOwners, p.packageOwner)
		closeErr = p.packageOwner.Close()
		p.packageOwner = nil
	}
	if closeErr == nil && p.lease != nil {
		closedOwners = append(closedOwners, p.lease)
		closeErr = p.lease.Close()
		p.lease = nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if closeErr != nil {
		p.failure = serviceProcessError("owner_close_failed", closeErr, append(closedOwners, p)...)
		return p.failure
	}
	p.cleaned = true
	return nil
}

type applicationServiceOutput struct {
	owner  *ApplicationServiceProcess
	stderr bool
}

func (p *ApplicationServiceProcess) failOutputLocked(code string) {
	if p.failure == nil {
		p.failure = serviceProcessError(code, nil, p)
	}
	p.invalid = true
}

func (w applicationServiceOutput) Write(raw []byte) (int, error) {
	p := w.owner
	p.mu.Lock()
	defer p.mu.Unlock()
	defer func() {
		if p.invalid {
			p.lifetimeOnce.Do(func() { close(p.lifetimeDone) })
		}
	}()
	if w.stderr {
		p.stderrTotal += len(raw)
		if len(p.stderr) < 65536 {
			p.stderr = append(p.stderr, raw[:min(len(raw), 65536-len(p.stderr))]...)
		}
		if p.stderrTotal > 65536 {
			p.failOutputLocked("output_limit")
		}
		return len(raw), nil
	}
	p.stdoutTotal += len(raw)
	if p.stdoutTotal > 65536 || len(p.stdout)+len(raw) > 16384 {
		p.failOutputLocked("output_limit")
		return len(raw), nil
	}
	p.stdout = append(p.stdout, raw...)
	for {
		index := bytes.IndexByte(p.stdout, '\n')
		if index < 0 {
			break
		}
		line := append([]byte(nil), p.stdout[:index]...)
		p.stdout = p.stdout[index+1:]
		var state applicationServiceState
		if protocol.DecodeClosedJSON(line, &state, 16384) != nil || state.SchemaVersion != protocol.Version || state.Kind != "application-services-state" || state.LifetimeID != p.request.LifetimeID || state.SelectionSHA256 != p.request.SelectionSHA256 || state.KernelScope != p.request.KernelScope {
			p.failOutputLocked("state_binding_invalid")
			continue
		}
		switch state.State {
		case "ready":
			if p.ready || p.drained || p.invalid {
				p.failOutputLocked("state_order_invalid")
				continue
			}
			p.ready = true
			close(p.readySignal)
		case "drained":
			if p.drained {
				p.failOutputLocked("state_order_invalid")
				continue
			}
			p.drained = true
			p.invalid = true
		default:
			p.failOutputLocked("state_invalid")
		}
	}
	return len(raw), nil
}
