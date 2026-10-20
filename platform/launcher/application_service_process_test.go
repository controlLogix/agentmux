//go:build (darwin && arm64) || ((linux || darwin) && agentmux_application_services)

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

type serviceTestOwner struct {
	mu                     sync.Mutex
	checks, closes         int
	checkError, closeError error
	onClose                func()
}

func (o *serviceTestOwner) Recheck(context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.checks++
	return o.checkError
}
func (o *serviceTestOwner) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closes++
	if o.onClose != nil {
		o.onClose()
	}
	return o.closeError
}
func (o *serviceTestOwner) count() int { o.mu.Lock(); defer o.mu.Unlock(); return o.closes }

type serviceTestChild struct {
	request                           applicationServiceStart
	output                            io.Writer
	ready, drain                      bool
	startError, waitError, closeError error
	createdError                      error
	outputDuringStart                 bool
	mu                                sync.Mutex
	waits, starts, closes             int
	firstInput, stop, exited          chan struct{}
	inputOnce, stopOnce               sync.Once
	onInput                           func()
}

func newServiceTestChild(request applicationServiceStart) *serviceTestChild {
	return &serviceTestChild{request: request, ready: true, drain: true, firstInput: make(chan struct{}), stop: make(chan struct{}), exited: make(chan struct{})}
}
func (c *serviceTestChild) frame(state string) {
	raw, _ := json.Marshal(applicationServiceState{protocol.Version, "application-services-state", c.request.LifetimeID, c.request.SelectionSHA256, c.request.KernelScope, state})
	c.output.Write(append(raw, '\n'))
}
func (c *serviceTestChild) CloseUnstarted() error { return nil }
func (c *serviceTestChild) Start() (bool, error) {
	c.mu.Lock()
	c.starts++
	c.mu.Unlock()
	if c.startError != nil {
		return false, c.startError
	}
	if c.outputDuringStart {
		c.output.Write([]byte("invalid output\n"))
	}
	go func() {
		<-c.firstInput
		if c.ready {
			c.frame("ready")
		}
		<-c.stop
		if c.drain {
			c.frame("drained")
		}
		close(c.exited)
	}()
	return true, c.createdError
}
func (c *serviceTestChild) Wait() error {
	c.mu.Lock()
	c.waits++
	c.mu.Unlock()
	<-c.exited
	return c.waitError
}
func (c *serviceTestChild) Signal(os.Signal) error {
	c.stopOnce.Do(func() { close(c.stop) })
	return nil
}
func (c *serviceTestChild) SetWriteDeadline(time.Time) error { return nil }
func (c *serviceTestChild) Write(raw []byte) (int, error) {
	c.inputOnce.Do(func() {
		if c.onInput != nil {
			c.onInput()
		}
		close(c.firstInput)
	})
	return len(raw), nil
}
func (c *serviceTestChild) Close() error {
	c.mu.Lock()
	c.closes++
	c.mu.Unlock()
	c.stopOnce.Do(func() { close(c.stop) })
	return c.closeError
}
func (c *serviceTestChild) factory(output, _ io.Writer) (applicationServiceChild, applicationServiceInput, error) {
	c.output = output
	return c, c, nil
}

func serviceTestRequest() applicationServiceStart {
	return applicationServiceStart{SchemaVersion: protocol.Version, Kind: "application-services-start", LifetimeID: "service_0123456789abcdef0123456789abcdef", SelectionSHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", KernelScope: protocol.Scope{HubID: "fixture_hub", InstanceID: "fixture_instance", ProfileID: "fixture_profile"}}
}
func stopServiceTest(t *testing.T, p *ApplicationServiceProcess) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := p.Stop(ctx)
	select {
	case <-p.Done():
	case <-ctx.Done():
		t.Fatal("original service wait, output and monitor did not join")
	}
	return err
}

func TestApplicationServiceProcessOwnsReadyDrainWaitAndLeases(t *testing.T) {
	request := serviceTestRequest()
	child := newServiceTestChild(request)
	admission, lease := &serviceTestOwner{}, &serviceTestOwner{}
	admission.onClose = func() {
		select {
		case <-child.exited:
		default:
			t.Error("package released before service drain and wait")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p, err := startApplicationServiceProcess(ctx, request, admission, lease, make(chan struct{}), child.factory)
	if err != nil || !p.Available() {
		t.Fatal("exact admitted service did not become available")
	}
	if err := stopServiceTest(t, p); err != nil {
		t.Fatal("clean service drain failed")
	}
	if p.Available() || !serviceChannelClosed(p.LifetimeDone()) || admission.count() != 1 || lease.count() != 1 {
		t.Fatal("service ownership was not released exactly once after join")
	}
	if stopServiceTest(t, p) != nil || admission.count() != 1 || lease.count() != 1 {
		t.Fatal("repeated stop replaced or reclosed consumed owners")
	}
	child.mu.Lock()
	defer child.mu.Unlock()
	if child.waits != 1 || child.starts != 1 || child.closes != 1 {
		t.Fatal("original process or input ownership was duplicated")
	}
}

func TestApplicationServiceCancelledStartupRetainsOriginalChild(t *testing.T) {
	request := serviceTestRequest()
	child := newServiceTestChild(request)
	child.ready = false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	child.onInput = cancel
	admission, lease := &serviceTestOwner{}, &serviceTestOwner{}
	p, err := startApplicationServiceProcess(ctx, request, admission, lease, make(chan struct{}), child.factory)
	if p == nil || err == nil || p.Available() || admission.count() != 0 || lease.count() != 0 {
		t.Fatal("cancelled startup lost its child or prematurely released its owners")
	}
	if stopServiceTest(t, p) != nil || admission.count() != 1 || lease.count() != 1 {
		t.Fatal("cancelled startup did not join the original clean drain")
	}
}

func TestApplicationServiceStartFailureClosesUnstartedResources(t *testing.T) {
	request := serviceTestRequest()
	child := newServiceTestChild(request)
	child.startError = errors.New("start_refused")
	admission, lease := &serviceTestOwner{}, &serviceTestOwner{}
	p, err := startApplicationServiceProcess(context.Background(), request, admission, lease, make(chan struct{}), child.factory)
	if p == nil || err == nil || !serviceChannelClosed(p.Done()) || admission.count() != 1 || lease.count() != 1 {
		t.Fatal("unstarted service admission or lease was abandoned")
	}
	child.mu.Lock()
	defer child.mu.Unlock()
	if child.waits != 0 || child.closes != 1 {
		t.Fatal("unstarted command gained a wait owner or lost its input")
	}
}

func TestApplicationServiceCreatedChildSurvivesParentReaderFailure(t *testing.T) {
	request := serviceTestRequest()
	child := newServiceTestChild(request)
	child.createdError = errors.New("reader_close_failed")
	child.outputDuringStart = true
	admission, lease := &serviceTestOwner{}, &serviceTestOwner{}
	p, err := startApplicationServiceProcess(context.Background(), request, admission, lease, make(chan struct{}), child.factory)
	if p == nil || err == nil || p.Available() || admission.count() != 0 || lease.count() != 0 {
		t.Fatal("post-creation failure lost its child or released its owners")
	}
	p.mu.Lock()
	priorOutputFailure := p.failure != nil && strings.Contains(p.failure.Error(), "state_binding_invalid")
	p.mu.Unlock()
	if !priorOutputFailure {
		t.Fatal("reader cleanup failure replaced the original output failure")
	}
	// Let the original child receive its normal start input so its stop path
	// can drain. The parent-reader failure remains sticky after the sole wait.
	child.Write([]byte("start\n"))
	if stopServiceTest(t, p) == nil || admission.count() != 0 || lease.count() != 0 {
		t.Fatal("uncertain reader cleanup released the package or lease")
	}
	child.mu.Lock()
	defer child.mu.Unlock()
	if child.waits != 1 || child.starts != 1 || child.closes != 1 {
		t.Fatal("created child did not keep its original wait and input owner")
	}
}

func TestApplicationServiceHostLifetimeRevokesBeforeJoinedCleanup(t *testing.T) {
	request := serviceTestRequest()
	child := newServiceTestChild(request)
	lifetime := make(chan struct{})
	admission, lease := &serviceTestOwner{}, &serviceTestOwner{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p, err := startApplicationServiceProcess(ctx, request, admission, lease, lifetime, child.factory)
	if err != nil {
		t.Fatal("service startup failed")
	}
	close(lifetime)
	select {
	case <-p.LifetimeDone():
	case <-ctx.Done():
		t.Fatal("host lifetime did not revoke service availability")
	}
	if p.Available() {
		t.Fatal("service stayed available after host loss")
	}
	if stopServiceTest(t, p) != nil {
		t.Fatal("host-ended service did not retain and join its original cleanup")
	}
}

func TestApplicationServiceUnconfirmedDrainAndConsumedCloseRemainFenced(t *testing.T) {
	for _, failure := range []string{"drain", "input", "package"} {
		t.Run(failure, func(t *testing.T) {
			request := serviceTestRequest()
			child := newServiceTestChild(request)
			admission, lease := &serviceTestOwner{}, &serviceTestOwner{}
			switch failure {
			case "drain":
				child.drain = false
			case "input":
				child.closeError = errors.New("close_failed")
			case "package":
				admission.closeError = errors.New("close_failed")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			p, err := startApplicationServiceProcess(ctx, request, admission, lease, make(chan struct{}), child.factory)
			if err != nil {
				t.Fatal("control service startup failed")
			}
			if stopServiceTest(t, p) == nil || lease.count() != 0 || p.Available() {
				t.Fatal("uncertain cleanup released the replacement fence")
			}
			count := admission.count()
			if stopServiceTest(t, p) == nil || admission.count() != count || lease.count() != 0 {
				t.Fatal("repeated cleanup converted uncertainty into success or retried a consumed close")
			}
		})
	}
}

func TestApplicationServiceOutputBindingRefusesForeignLifetime(t *testing.T) {
	request := serviceTestRequest()
	p := newApplicationServiceProcess(request, &serviceTestOwner{}, &serviceTestOwner{})
	state := applicationServiceState{protocol.Version, "application-services-state", "service_other", request.SelectionSHA256, request.KernelScope, "ready"}
	raw, _ := json.Marshal(state)
	applicationServiceOutput{p, false}.Write(append(raw, '\n'))
	if p.Available() || !serviceChannelClosed(p.LifetimeDone()) || p.failure == nil {
		t.Fatal("foreign process state established readiness")
	}
}

func TestApplicationServiceDrainedRevokesAvailabilityBeforeProcessExit(t *testing.T) {
	request := serviceTestRequest()
	child := newServiceTestChild(request)
	child.drain = false
	admission, lease := &serviceTestOwner{}, &serviceTestOwner{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p, err := startApplicationServiceProcess(ctx, request, admission, lease, make(chan struct{}), child.factory)
	if err != nil || !p.Available() {
		t.Fatal("control service did not become available")
	}
	child.frame("drained")
	if p.Available() || !serviceChannelClosed(p.LifetimeDone()) {
		t.Fatal("drained service kept its dispatch lifetime")
	}
	if serviceChannelClosed(p.Done()) || serviceChannelClosed(child.exited) || admission.count() != 0 || lease.count() != 0 {
		t.Fatal("drained frame replaced process exit evidence or released original owners")
	}
	if stopServiceTest(t, p) != nil || admission.count() != 1 || lease.count() != 1 {
		t.Fatal("original child was not joined before releasing its admitted package and lease")
	}
}
