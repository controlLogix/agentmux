package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type managerTestDriver struct {
	mu       sync.Mutex
	requests []StartRequest
	start    func(context.Context, StartRequest) (OwnedInstance, error)
}

func (d *managerTestDriver) Start(ctx context.Context, request StartRequest) (OwnedInstance, error) {
	d.mu.Lock()
	d.requests = append(d.requests, request)
	d.mu.Unlock()
	return d.start(ctx, request)
}
func (d *managerTestDriver) count() int { d.mu.Lock(); defer d.mu.Unlock(); return len(d.requests) }
func (d *managerTestDriver) requested() []StartRequest {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]StartRequest(nil), d.requests...)
}

type managerPreflightDriver struct {
	*managerTestDriver
	preflight func(context.Context, Plan) error
}

func (d *managerPreflightDriver) Preflight(ctx context.Context, plan Plan) error {
	return d.preflight(ctx, plan)
}

type managerTestProcess struct {
	mu         sync.Mutex
	ready      chan struct{}
	done       chan struct{}
	once       sync.Once
	readyError error
	exitError  error
	stopError  error
	stops      int
	onStop     func()
}

func managerReadyProcess() *managerTestProcess {
	p := &managerTestProcess{ready: make(chan struct{}), done: make(chan struct{})}
	close(p.ready)
	return p
}
func (p *managerTestProcess) WaitReady(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.ready:
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.readyError
	}
}
func (p *managerTestProcess) Done() <-chan struct{} { return p.done }
func (p *managerTestProcess) ExitError() error      { p.mu.Lock(); defer p.mu.Unlock(); return p.exitError }
func (p *managerTestProcess) Stop(ctx context.Context) error {
	p.mu.Lock()
	p.stops++
	err, onStop := p.stopError, p.onStop
	p.mu.Unlock()
	if onStop != nil {
		onStop()
	}
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	p.once.Do(func() { close(p.done) })
	return nil
}
func (p *managerTestProcess) exit(err error) {
	p.mu.Lock()
	p.exitError = err
	p.mu.Unlock()
	p.once.Do(func() { close(p.done) })
}
func (p *managerTestProcess) stopCount() int { p.mu.Lock(); defer p.mu.Unlock(); return p.stops }

type managerAvailableProcess struct {
	*managerTestProcess
	authority atomic.Bool
}

func (p *managerAvailableProcess) Available() bool { return p.authority.Load() }

func managerPackage(t *testing.T, id string, edit func(*Manifest)) AdmittedPackage {
	t.Helper()
	m := fixtureManifest(id)
	m.Contributions = []Contribution{{Kind: "tool", ID: "inspect_" + id, ContractRef: "urn:example:inspect"}}
	if edit != nil {
		edit(&m)
	}
	return fixturePackage(t, m, nil)
}
func managerRequest(packages ...AdmittedPackage) ActivationRequest {
	r := ActivationRequest{Catalog: packages, Instances: map[string]string{}, Contracts: []ContractBinding{{Kind: "tool", ContractRef: "urn:example:inspect"}}}
	for _, p := range packages {
		r.Roots = append(r.Roots, p.Pin())
		r.Selected = append(r.Selected, p.Pin())
		r.Instances[p.Pin().PackageID] = "instance_" + p.Pin().PackageID
		r.Configurations = append(r.Configurations, ConfigurationInput{Pin: p.Pin(), Raw: []byte(`{}`)})
	}
	return r
}
func managerForTest(t *testing.T, parent context.Context, driver Driver) *Manager {
	t.Helper()
	m, err := NewManager(parent, driver, ManagerOptions{Platform: Platform{OS: "darwin", Arch: "arm64"}, InstallationMode: "independent", ActivationTimeout: 2 * time.Second, CleanupTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := m.Close(ctx); err != nil {
			t.Errorf("manager cleanup: %v", err)
		}
	})
	return m
}
func managerWait(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !predicate() {
		select {
		case <-deadline.C:
			t.Fatal("manager state did not arrive")
		case <-tick.C:
		}
	}
}
func managerSignal(t *testing.T, event <-chan struct{}) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(3 * time.Second):
		t.Fatal("owned operation did not arrive")
	}
}

func TestManagerPreflightPreservesActiveSet(t *testing.T) {
	a := managerPackage(t, "alpha", nil)
	b := managerPackage(t, "bravo", nil)
	driver := &managerTestDriver{start: func(context.Context, StartRequest) (OwnedInstance, error) { return managerReadyProcess(), nil }}
	m := managerForTest(t, context.Background(), driver)
	first, err := m.Activate(context.Background(), managerRequest(a))
	if err != nil {
		t.Fatal(err)
	}
	original, err := m.Resolve("tool", "inspect_alpha")
	if err != nil {
		t.Fatal(err)
	}
	requests := []ActivationRequest{managerRequest(b), managerRequest(a, b), managerRequest(a)}
	requests[1].Configurations[1].Raw = []byte(`[]`)
	requests[2].Configurations[0].Raw = []byte(`{"changed":true}`)
	for _, request := range requests {
		if _, err := m.Activate(context.Background(), request); err == nil {
			t.Fatal("unsupported activation succeeded")
		}
		entry, err := m.Resolve("tool", "inspect_alpha")
		if err != nil || entry.Owner != original.Owner || m.Snapshot().Revision != first.Revision || driver.count() != 1 {
			t.Fatal("preflight changed active owner")
		}
	}
	duplicate := managerPackage(t, "duplicate", func(m *Manifest) { m.Contributions[0].ID = "inspect_alpha" })
	if _, err := m.Activate(context.Background(), managerRequest(a, duplicate)); err == nil || driver.count() != 1 {
		t.Fatal("duplicate handler reached driver")
	}
	missing := managerPackage(t, "missing", func(m *Manifest) {
		m.Dependencies = []Dependency{{PackageID: "absent", MinimumVersion: "1.0.0", ExclusiveMaximumVersion: "2.0.0"}}
	})
	if _, err := m.Activate(context.Background(), managerRequest(a, missing)); err == nil || driver.count() != 1 {
		t.Fatal("missing dependency reached driver")
	}
	changed := managerPackage(t, "alpha", func(m *Manifest) { m.Version = "2.0.0" })
	if _, err := m.Activate(context.Background(), managerRequest(changed)); err == nil || driver.count() != 1 {
		t.Fatal("replacement reached driver")
	}
}

func TestManagerDriverPreflightRejectsWholePlanBeforeStarting(t *testing.T) {
	a, b := managerPackage(t, "alpha", nil), managerPackage(t, "bravo", nil)
	base := &managerTestDriver{start: func(context.Context, StartRequest) (OwnedInstance, error) { return managerReadyProcess(), nil }}
	preflights := 0
	driver := &managerPreflightDriver{managerTestDriver: base, preflight: func(ctx context.Context, plan Plan) error {
		preflights++
		if ctx.Err() != nil || len(plan.Packages()) != 2 {
			t.Fatal("driver did not receive complete bounded plan")
		}
		return pluginError("plugin_executable_unsupported")
	}}
	m := managerForTest(t, context.Background(), driver)
	invalid := managerRequest(a, b)
	invalid.Configurations[1].Raw = []byte(`[]`)
	if _, err := m.Activate(context.Background(), invalid); err == nil || preflights != 0 {
		t.Fatal("driver preflight preceded configuration admission")
	}
	if _, err := m.Activate(context.Background(), managerRequest(a, b)); err == nil || err.Error() != "plugin_executable_unsupported" {
		t.Fatal("driver refusal lost")
	}
	if base.count() != 0 || preflights != 1 || m.Snapshot().Revision != 0 {
		t.Fatal("whole-plan refusal started an earlier package")
	}
}

func TestManagerAuthorityLossRevokesHandlesBeforeProcessJoin(t *testing.T) {
	a := managerPackage(t, "alpha", nil)
	process := &managerAvailableProcess{managerTestProcess: managerReadyProcess()}
	process.authority.Store(true)
	driver := &managerTestDriver{start: func(context.Context, StartRequest) (OwnedInstance, error) { return process, nil }}
	m := managerForTest(t, context.Background(), driver)
	if _, err := m.Activate(context.Background(), managerRequest(a)); err != nil {
		t.Fatal(err)
	}
	old, _ := m.Resolve("tool", "inspect_alpha")
	process.authority.Store(false)
	if completed(process.Done()) {
		t.Fatal("authority loss fabricated a process join")
	}
	if _, err := m.Resolve("tool", "inspect_alpha"); err == nil || m.CheckActive(old.Owner) == nil {
		t.Fatal("lost transport authority still permits dispatch")
	}
	if m.Snapshot().Instances[0].State != "degraded" || driver.count() != 1 {
		t.Fatal("authority loss hidden or restarted before original join")
	}
}

func TestManagerAuthorityLossDuringCandidateReadinessPreventsPublication(t *testing.T) {
	a, b := managerPackage(t, "alpha", nil), managerPackage(t, "bravo", nil)
	first := &managerAvailableProcess{managerTestProcess: managerReadyProcess()}
	first.authority.Store(true)
	pending := &managerTestProcess{ready: make(chan struct{}), done: make(chan struct{})}
	started := make(chan struct{})
	driver := &managerTestDriver{start: func(_ context.Context, r StartRequest) (OwnedInstance, error) {
		if r.Owner.Pin.PackageID == "alpha" {
			return first, nil
		}
		close(started)
		return pending, nil
	}}
	m := managerForTest(t, context.Background(), driver)
	result := make(chan error, 1)
	go func() { _, err := m.Activate(context.Background(), managerRequest(a, b)); result <- err }()
	managerSignal(t, started)
	first.authority.Store(false)
	close(pending.ready)
	if err := <-result; err == nil || m.Snapshot().Revision != 0 || len(m.Snapshot().Instances) != 0 {
		t.Fatal("candidate published after earlier authority loss")
	}
	if first.stopCount() != 1 || pending.stopCount() != 1 || !completed(first.Done()) || !completed(pending.Done()) {
		t.Fatal("unpublished owners not joined")
	}
}

func TestManagerPublishesOnlyAfterAllReadiness(t *testing.T) {
	a, b := managerPackage(t, "alpha", nil), managerPackage(t, "bravo", nil)
	started := make(chan struct{})
	pending := &managerTestProcess{ready: make(chan struct{}), done: make(chan struct{})}
	driver := &managerTestDriver{start: func(_ context.Context, request StartRequest) (OwnedInstance, error) {
		if request.Owner.Pin.PackageID == "bravo" {
			close(started)
			return pending, nil
		}
		return managerReadyProcess(), nil
	}}
	m := managerForTest(t, context.Background(), driver)
	if _, err := m.Activate(context.Background(), managerRequest(a)); err != nil {
		t.Fatal(err)
	}
	old, _ := m.Resolve("tool", "inspect_alpha")
	result := make(chan error, 1)
	go func() { _, err := m.Activate(context.Background(), managerRequest(a, b)); result <- err }()
	managerSignal(t, started)
	if _, err := m.Resolve("tool", "inspect_bravo"); err == nil || len(m.Snapshot().Instances) != 1 {
		t.Fatal("unready candidate published")
	}
	if current, err := m.Resolve("tool", "inspect_alpha"); err != nil || current.Owner != old.Owner {
		t.Fatal("old handler unavailable during candidate startup")
	}
	close(pending.ready)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if _, err := m.Resolve("tool", "inspect_bravo"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Activate(context.Background(), managerRequest(a, b)); err != nil || driver.count() != 2 {
		t.Fatal("identical active pins restarted")
	}
}

func TestManagerPostStartFailureCleansOnlyAdditionsInReverseOrder(t *testing.T) {
	a, b := managerPackage(t, "alpha", nil), managerPackage(t, "bravo", nil)
	c := managerPackage(t, "charlie", func(m *Manifest) {
		m.Dependencies = []Dependency{{PackageID: "bravo", MinimumVersion: "1.0.0", ExclusiveMaximumVersion: "2.0.0"}}
	})
	var mu sync.Mutex
	var stopped []string
	processes := map[string]*managerTestProcess{}
	driver := &managerTestDriver{start: func(_ context.Context, r StartRequest) (OwnedInstance, error) {
		id := r.Owner.Pin.PackageID
		p := managerReadyProcess()
		p.onStop = func() { mu.Lock(); stopped = append(stopped, id); mu.Unlock() }
		processes[id] = p
		if id == "charlie" {
			return p, errors.New("private failure marker")
		}
		return p, nil
	}}
	m := managerForTest(t, context.Background(), driver)
	if _, err := m.Activate(context.Background(), managerRequest(a)); err != nil {
		t.Fatal(err)
	}
	before := m.Snapshot()
	if _, err := m.Activate(context.Background(), managerRequest(a, b, c)); err == nil {
		t.Fatal("partial initialization accepted")
	}
	mu.Lock()
	got := strings.Join(stopped, ",")
	mu.Unlock()
	if got != "charlie,bravo" || processes["alpha"].stopCount() != 0 || m.Snapshot().Revision != before.Revision {
		t.Fatal("old owner changed or cleanup order wrong")
	}
	if _, err := m.Resolve("tool", "inspect_alpha"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%+v", m.Snapshot()), "private failure marker") {
		t.Fatal("private failure leaked")
	}
}

func TestManagerPreservesKnownConsumedCloseFailure(t *testing.T) {
	a := managerPackage(t, "alpha", nil)
	process := managerReadyProcess()
	private := errors.New("private descriptor failure")
	cleanup := &AdmissionCleanupFailure{operation: pluginError("native_stage_unavailable"), cause: private}
	driver := &managerTestDriver{start: func(context.Context, StartRequest) (OwnedInstance, error) { return process, cleanup }}
	m := managerForTest(t, context.Background(), driver)
	_, err := m.Activate(context.Background(), managerRequest(a))
	var retained *AdmissionCleanupFailure
	if !errors.As(err, &retained) || retained != cleanup || !errors.Is(err, private) || process.stopCount() != 1 {
		t.Fatal("startup normalization discarded original consumed close failure")
	}
	raw, marshalErr := json.Marshal(err)
	if marshalErr != nil || strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err)+string(raw), "private descriptor failure") {
		t.Fatal("retained cleanup cause was exposed")
	}
}

func TestManagerRetainsUncertainCleanupAndConsumesFailedGeneration(t *testing.T) {
	a, b := managerPackage(t, "alpha", nil), managerPackage(t, "bravo", nil)
	failed := managerReadyProcess()
	failed.readyError = errors.New("private start failure")
	failed.stopError = errors.New("private join failure")
	attempts := 0
	driver := &managerTestDriver{start: func(_ context.Context, r StartRequest) (OwnedInstance, error) {
		if r.Owner.Pin.PackageID == "bravo" {
			attempts++
			if attempts == 1 {
				return failed, nil
			}
		}
		return managerReadyProcess(), nil
	}}
	m := managerForTest(t, context.Background(), driver)
	if _, err := m.Activate(context.Background(), managerRequest(a)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Activate(context.Background(), managerRequest(a, b)); err == nil || m.Snapshot().RetainedCleanup != 1 {
		t.Fatal("lost uncertain owner")
	}
	if _, err := m.Activate(context.Background(), managerRequest(a, b)); err == nil || driver.count() != 2 {
		t.Fatal("started while cleanup unresolved")
	}
	if _, err := m.Resolve("tool", "inspect_alpha"); err != nil {
		t.Fatal("uncertain candidate removed active set")
	}
	failed.mu.Lock()
	failed.stopError = nil
	failed.mu.Unlock()
	if err := m.RetryCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Activate(context.Background(), managerRequest(a, b)); err != nil {
		t.Fatal(err)
	}
	current, err := m.Resolve("tool", "inspect_bravo")
	if err != nil || current.Owner.Generation != 2 || m.Snapshot().RetainedCleanup != 0 || failed.stopCount() != 2 {
		t.Fatal("failed generation or original owner lost")
	}
}

func TestManagerRepeatedCleanupFailureKeepsBoundedCauseHistory(t *testing.T) {
	a := managerPackage(t, "alpha", nil)
	process := managerReadyProcess()
	process.readyError = errors.New("start failed")
	first := errors.New("first private cleanup failure")
	process.stopError = first
	driver := &managerTestDriver{start: func(context.Context, StartRequest) (OwnedInstance, error) { return process, nil }}
	m := managerForTest(t, context.Background(), driver)
	if _, err := m.Activate(context.Background(), managerRequest(a)); err == nil {
		t.Fatal("uncertain cleanup accepted")
	}
	var latest error
	for attempt := 0; attempt < 64; attempt++ {
		latest = errors.New("latest private cleanup failure")
		process.mu.Lock()
		process.stopError = latest
		process.mu.Unlock()
		if err := m.RetryCleanup(context.Background()); err == nil {
			t.Fatal("failed cleanup retry accepted")
		}
	}
	m.mu.RLock()
	bounded := len(m.retained) == 1 && m.retained[0].cause == first && m.retained[0].latest == latest
	m.mu.RUnlock()
	if !bounded {
		t.Fatal("retries lost original cause or accumulated unbounded history")
	}
	process.mu.Lock()
	process.stopError = nil
	process.mu.Unlock()
	if err := m.RetryCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestManagerUnexpectedExitRestartsWithBoundedFreshGenerations(t *testing.T) {
	a := managerPackage(t, "alpha", func(m *Manifest) { m.Lifecycle.RestartLimit = 2 })
	first, second, third := managerReadyProcess(), managerReadyProcess(), managerReadyProcess()
	third.readyError = errors.New("private readiness failure")
	queue := []*managerTestProcess{first, second, third}
	var mu sync.Mutex
	driver := &managerTestDriver{start: func(context.Context, StartRequest) (OwnedInstance, error) {
		mu.Lock()
		defer mu.Unlock()
		if len(queue) == 0 {
			return nil, errors.New("unexpected extra start")
		}
		p := queue[0]
		queue = queue[1:]
		return p, nil
	}}
	m := managerForTest(t, context.Background(), driver)
	if _, err := m.Activate(context.Background(), managerRequest(a)); err != nil {
		t.Fatal(err)
	}
	old, _ := m.Resolve("tool", "inspect_alpha")
	first.exit(errors.New("private exit"))
	managerWait(t, func() bool {
		entry, err := m.Resolve("tool", "inspect_alpha")
		return err == nil && entry.Owner.Generation == 2
	})
	if m.CheckActive(old.Owner) == nil {
		t.Fatal("stale generation remains active")
	}
	second.exit(nil)
	managerWait(t, func() bool {
		s := m.Snapshot()
		return len(s.Instances) == 1 && s.Instances[0].Code == "plugin_restart_exhausted"
	})
	s := m.Snapshot().Instances[0]
	if driver.count() != 3 || s.RestartAttempts != 2 || s.Owner.Generation != 3 || s.State != "failed" {
		t.Fatal("restart budget not enforced")
	}
	if _, err := m.Resolve("tool", "inspect_alpha"); err == nil {
		t.Fatal("failed owner still dispatchable")
	}
}

func TestManagerRequiredDependencyHealthFencesDependentDispatch(t *testing.T) {
	a := managerPackage(t, "alpha", nil)
	b := managerPackage(t, "bravo", func(m *Manifest) {
		m.Dependencies = []Dependency{{PackageID: "alpha", MinimumVersion: "1.0.0", ExclusiveMaximumVersion: "2.0.0"}}
	})
	first := managerReadyProcess()
	replacement := &managerTestProcess{ready: make(chan struct{}), done: make(chan struct{})}
	restarting := make(chan struct{})
	var mu sync.Mutex
	alphaStarts := 0
	driver := &managerTestDriver{start: func(_ context.Context, r StartRequest) (OwnedInstance, error) {
		mu.Lock()
		defer mu.Unlock()
		if r.Owner.Pin.PackageID == "alpha" {
			alphaStarts++
			if alphaStarts == 1 {
				return first, nil
			}
			close(restarting)
			return replacement, nil
		}
		return managerReadyProcess(), nil
	}}
	m := managerForTest(t, context.Background(), driver)
	if _, err := m.Activate(context.Background(), managerRequest(a, b)); err != nil {
		t.Fatal(err)
	}
	old, _ := m.Resolve("tool", "inspect_bravo")
	first.exit(nil)
	managerSignal(t, restarting)
	if _, err := m.Resolve("tool", "inspect_bravo"); err == nil {
		t.Fatal("dependent dispatch ignored unavailable dependency")
	}
	close(replacement.ready)
	managerWait(t, func() bool {
		entry, err := m.Resolve("tool", "inspect_bravo")
		return err == nil && entry.Owner == old.Owner
	})
	if driver.count() != 3 {
		t.Fatal("dependent process restarted without an exit")
	}
}

func TestManagerCanceledActivationKeepsOriginalSetAndJoinsCandidate(t *testing.T) {
	a, b := managerPackage(t, "alpha", nil), managerPackage(t, "bravo", nil)
	started := make(chan struct{})
	pending := &managerTestProcess{ready: make(chan struct{}), done: make(chan struct{})}
	driver := &managerTestDriver{start: func(_ context.Context, r StartRequest) (OwnedInstance, error) {
		if r.Owner.Pin.PackageID == "bravo" {
			close(started)
			return pending, nil
		}
		return managerReadyProcess(), nil
	}}
	m := managerForTest(t, context.Background(), driver)
	if _, err := m.Activate(context.Background(), managerRequest(a)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := m.Activate(ctx, managerRequest(a, b)); result <- err }()
	managerSignal(t, started)
	cancel()
	if err := <-result; err == nil || !completed(pending.done) || pending.stopCount() != 1 {
		t.Fatal("canceled activation abandoned its original owner")
	}
	if _, err := m.Resolve("tool", "inspect_alpha"); err != nil {
		t.Fatal(err)
	}
}

func TestManagerCloseRetainsOriginalOwnerUntilCleanupProved(t *testing.T) {
	a := managerPackage(t, "alpha", nil)
	process := managerReadyProcess()
	process.stopError = errors.New("private cleanup failure")
	driver := &managerTestDriver{start: func(context.Context, StartRequest) (OwnedInstance, error) { return process, nil }}
	m := managerForTest(t, context.Background(), driver)
	if _, err := m.Activate(context.Background(), managerRequest(a)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if m.Close(ctx) == nil || completed(m.Done()) || m.Snapshot().Closed || m.Snapshot().RetainedCleanup != 1 {
		t.Fatal("close claimed false completion")
	}
	process.mu.Lock()
	process.stopError = nil
	process.mu.Unlock()
	if err := m.RetryCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if !completed(m.Done()) || !m.Snapshot().Closed || m.Snapshot().Instances[0].State != "stopped" || process.stopCount() != 2 {
		t.Fatal("original close owner was not rejoined")
	}
}

func TestManagerCloseCancelsSerializedActivationAndJoinsAllOwners(t *testing.T) {
	a, b, c := managerPackage(t, "alpha", nil), managerPackage(t, "bravo", nil), managerPackage(t, "charlie", nil)
	first := managerReadyProcess()
	pending := &managerTestProcess{ready: make(chan struct{}), done: make(chan struct{})}
	started := make(chan struct{})
	driver := &managerTestDriver{start: func(_ context.Context, r StartRequest) (OwnedInstance, error) {
		if r.Owner.Pin.PackageID == "alpha" {
			return first, nil
		}
		if r.Owner.Pin.PackageID == "bravo" {
			close(started)
			return pending, nil
		}
		return nil, errors.New("unexpected start")
	}}
	m := managerForTest(t, context.Background(), driver)
	if _, err := m.Activate(context.Background(), managerRequest(a)); err != nil {
		t.Fatal(err)
	}
	activation := make(chan error, 1)
	waiting := make(chan error, 1)
	go func() { _, err := m.Activate(context.Background(), managerRequest(a, b)); activation <- err }()
	managerSignal(t, started)
	go func() { _, err := m.Activate(context.Background(), managerRequest(a, b, c)); waiting <- err }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := m.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-activation; err == nil {
		t.Fatal("closing candidate was published")
	}
	if err := <-waiting; err == nil {
		t.Fatal("queued activation survived closure")
	}
	if driver.count() != 2 || first.stopCount() != 1 || pending.stopCount() != 1 || !completed(m.Done()) {
		t.Fatal("close lost original process ownership")
	}
}

func TestManagerCleanupRetryResumesOnlyAfterOriginalExitedOwnerJoins(t *testing.T) {
	a := managerPackage(t, "alpha", nil)
	first := managerReadyProcess()
	first.stopError = errors.New("private join failure")
	var mu sync.Mutex
	starts := 0
	driver := &managerTestDriver{start: func(context.Context, StartRequest) (OwnedInstance, error) {
		mu.Lock()
		defer mu.Unlock()
		starts++
		if starts == 1 {
			return first, nil
		}
		return managerReadyProcess(), nil
	}}
	m := managerForTest(t, context.Background(), driver)
	if _, err := m.Activate(context.Background(), managerRequest(a)); err != nil {
		t.Fatal(err)
	}
	first.exit(nil)
	managerWait(t, func() bool { return m.Snapshot().RetainedCleanup == 1 })
	if driver.count() != 1 {
		t.Fatal("restart raced uncertain original cleanup")
	}
	first.mu.Lock()
	first.stopError = nil
	first.mu.Unlock()
	if err := m.RetryCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	entry, err := m.Resolve("tool", "inspect_alpha")
	if err != nil || entry.Owner.Generation != 2 || driver.count() != 2 || first.stopCount() != 2 {
		t.Fatal("retained original owner did not gate restart")
	}
}

func TestManagerCleanupRetryResumesOtherExitedPackages(t *testing.T) {
	a, b := managerPackage(t, "alpha", nil), managerPackage(t, "bravo", nil)
	firstA, firstB := managerReadyProcess(), managerReadyProcess()
	firstA.stopError = errors.New("private cleanup uncertainty")
	var mu sync.Mutex
	counts := map[string]int{}
	driver := &managerTestDriver{start: func(_ context.Context, r StartRequest) (OwnedInstance, error) {
		mu.Lock()
		defer mu.Unlock()
		id := r.Owner.Pin.PackageID
		counts[id]++
		if counts[id] == 1 {
			if id == "alpha" {
				return firstA, nil
			}
			return firstB, nil
		}
		return managerReadyProcess(), nil
	}}
	m := managerForTest(t, context.Background(), driver)
	if _, err := m.Activate(context.Background(), managerRequest(a, b)); err != nil {
		t.Fatal(err)
	}
	firstA.exit(nil)
	managerWait(t, func() bool { return m.Snapshot().RetainedCleanup == 1 })
	firstB.exit(nil)
	managerWait(t, func() bool {
		for _, instance := range m.Snapshot().Instances {
			if instance.Owner.Pin.PackageID == "bravo" {
				return instance.Code == "plugin_cleanup_pending"
			}
		}
		return false
	})
	if driver.count() != 2 || firstB.stopCount() != 1 {
		t.Fatal("unresolved cleanup did not hold every restart")
	}
	firstA.mu.Lock()
	firstA.stopError = nil
	firstA.mu.Unlock()
	if err := m.RetryCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"alpha", "bravo"} {
		entry, err := m.Resolve("tool", "inspect_"+id)
		if err != nil || entry.Owner.Generation != 2 {
			t.Fatal("cleanup resolution left another exited package stranded")
		}
	}
	if driver.count() != 4 {
		t.Fatal("cleanup resolution used the wrong restart count")
	}
}

func TestManagerParentCancellationAndFreshEpoch(t *testing.T) {
	a := managerPackage(t, "alpha", nil)
	parent, cancel := context.WithCancel(context.Background())
	driver := &managerTestDriver{start: func(context.Context, StartRequest) (OwnedInstance, error) { return managerReadyProcess(), nil }}
	first := managerForTest(t, parent, driver)
	if _, err := first.Activate(context.Background(), managerRequest(a)); err != nil {
		t.Fatal(err)
	}
	old, _ := first.Resolve("tool", "inspect_alpha")
	cancel()
	managerSignal(t, first.Done())
	second := managerForTest(t, context.Background(), driver)
	if _, err := second.Activate(context.Background(), managerRequest(a)); err != nil {
		t.Fatal(err)
	}
	current, _ := second.Resolve("tool", "inspect_alpha")
	if current.Owner.Epoch == old.Owner.Epoch || current.Owner.Generation != 1 || second.CheckActive(old.Owner) == nil {
		t.Fatal("previous manager identity was reused")
	}
}

type managerTopologyDriver struct {
	*managerTestDriver
	preflight func(context.Context, InstanceTopology) error
}

func (d *managerTopologyDriver) PreflightInstances(ctx context.Context, topology InstanceTopology) error {
	return d.preflight(ctx, topology)
}

type managerWaitProcess struct {
	*managerTestProcess
	wait func(context.Context) error
}

func (p *managerWaitProcess) WaitReady(ctx context.Context) error { return p.wait(ctx) }

type managerLifetimeProcess struct {
	*managerTestProcess
	lifetime chan struct{}
	end      sync.Once
}

func managerLiveProcess() *managerLifetimeProcess {
	return &managerLifetimeProcess{managerTestProcess: managerReadyProcess(), lifetime: make(chan struct{})}
}
func (p *managerLifetimeProcess) LifetimeDone() <-chan struct{} { return p.lifetime }
func (p *managerLifetimeProcess) endLifetime()                  { p.end.Do(func() { close(p.lifetime) }) }
func (p *managerLifetimeProcess) Stop(ctx context.Context) error {
	p.endLifetime()
	return p.managerTestProcess.Stop(ctx)
}

func managerGraphRequest(packages []AdmittedPackage, topology InstanceTopologyInput) ActivationRequest {
	request := ActivationRequest{Catalog: packages, Topology: &topology, Contracts: []ContractBinding{{Kind: "tool", ContractRef: "urn:example:inspect"}}}
	for _, pkg := range packages {
		request.Selected = append(request.Selected, pkg.Pin())
	}
	for _, instance := range topology.Instances {
		request.InstanceConfigurations = append(request.InstanceConfigurations, InstanceConfigurationInput{InstanceID: instance.InstanceID, Pin: instance.Pin, Raw: []byte(`{}`)})
	}
	return request
}
func managerPrivatePair(t *testing.T) (AdmittedPackage, AdmittedPackage, InstanceTopologyInput) {
	t.Helper()
	parent := managerPackage(t, "parent", func(m *Manifest) {
		m.Children = []Child{{PackageID: "worker", Relationship: "private", Required: true}}
	})
	child := managerPackage(t, "worker", func(m *Manifest) { m.InstallationModes = []string{"private-child"} })
	input := InstanceTopologyInput{Instances: []InstanceSpec{
		{InstanceID: "parent", Pin: parent.Pin(), InstallationMode: "independent", Placement: Placement{Kind: "local-process"}},
		{InstanceID: "worker", Pin: child.Pin(), InstallationMode: "private-child", Placement: Placement{Kind: "local-process"}},
	}, Roots: []string{"parent"}, Children: []ChildBinding{{ParentID: "parent", ChildID: "worker", Relationship: "private"}}}
	return parent, child, input
}
func managerSnapshotInstance(snapshot ManagerSnapshot, id string) (InstanceSnapshot, bool) {
	for _, instance := range snapshot.Instances {
		if instance.Owner.InstanceID == id {
			return instance, true
		}
	}
	return InstanceSnapshot{}, false
}

func TestManagerTopologyPreflightAndAmbiguousBindingsHaveNoEffects(t *testing.T) {
	parent, child, topology := managerPrivatePair(t)
	base := &managerTestDriver{start: func(context.Context, StartRequest) (OwnedInstance, error) { return managerReadyProcess(), nil }}
	preflights := 0
	driver := &managerTopologyDriver{managerTestDriver: base, preflight: func(_ context.Context, plan InstanceTopology) error {
		preflights++
		if len(plan.Instances()) != 2 || plan.GroupID("worker") != "parent" {
			return pluginError("test_wrong_topology")
		}
		return pluginError("test_deployment_refused")
	}}
	m := managerForTest(t, context.Background(), driver)
	for _, mutate := range []func(*ActivationRequest){
		func(r *ActivationRequest) { r.Roots = []PackagePin{parent.Pin()} },
		func(r *ActivationRequest) { r.Instances = map[string]string{"parent": "parent"} },
		func(r *ActivationRequest) {
			r.Configurations = []ConfigurationInput{{Pin: parent.Pin(), Raw: []byte(`{}`)}}
		},
		func(r *ActivationRequest) { r.InstanceConfigurations[1].Pin = parent.Pin() },
		func(r *ActivationRequest) { r.InstanceConfigurations[1].Raw = []byte(`[]`) },
	} {
		r := managerGraphRequest([]AdmittedPackage{parent, child}, topology)
		mutate(&r)
		if _, err := m.Activate(context.Background(), r); err == nil {
			t.Fatal("invalid graph input admitted")
		}
	}
	if preflights != 0 || base.count() != 0 {
		t.Fatal("invalid input reached deployment admission")
	}
	if _, err := m.Activate(context.Background(), managerGraphRequest([]AdmittedPackage{parent, child}, topology)); err == nil || err.Error() != "test_deployment_refused" || preflights != 1 || base.count() != 0 {
		t.Fatal("whole topology was not admitted before effects")
	}
}

func TestManagerPrivateGroupStartsParentsBeforeDependencyReadiness(t *testing.T) {
	parent, child, topology := managerPrivatePair(t)
	var events []string
	processes := map[string]*managerWaitProcess{}
	var parentOwner OwnerReference
	driver := &managerTestDriver{start: func(_ context.Context, r StartRequest) (OwnedInstance, error) {
		id := r.Owner.InstanceID
		events = append(events, "start:"+id)
		if id == "parent" {
			if r.Parent != nil || r.ParentLifetime != nil {
				return nil, pluginError("test_independent_parent")
			}
			parentOwner = r.Owner
		} else if r.Parent == nil || *r.Parent != parentOwner || r.ParentLifetime != processes["parent"].Done() {
			return nil, pluginError("test_parent_binding")
		}
		p := &managerWaitProcess{managerTestProcess: managerReadyProcess()}
		p.wait = func(context.Context) error {
			if processes["parent"] == nil || processes["worker"] == nil {
				return pluginError("test_parent_waited_before_child_start")
			}
			events = append(events, "ready:"+id)
			return nil
		}
		processes[id] = p
		return p, nil
	}}
	m := managerForTest(t, context.Background(), driver)
	snapshot, err := m.Activate(context.Background(), managerGraphRequest([]AdmittedPackage{parent, child}, topology))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(events, ",") != "start:parent,start:worker,ready:worker,ready:parent" {
		t.Fatal("ownership and readiness order were conflated")
	}
	childState, ok := managerSnapshotInstance(snapshot, "worker")
	if !ok || childState.Parent == nil || *childState.Parent != parentOwner || childState.RootRetained {
		t.Fatal("private lifetime missing from snapshot")
	}
	childState.Parent.Generation++
	if _, err = m.ResolveFor(parentOwner, "worker", "tool", "inspect_worker"); err != nil {
		t.Fatal("snapshot caller changed stored parent")
	}
	if _, err = m.Resolve("tool", "inspect_worker"); err == nil {
		t.Fatal("private contribution escaped into global lookup")
	}
}

func TestManagerPrivateGroupSharesParentStartupDeadline(t *testing.T) {
	parent := managerPackage(t, "parent", func(m *Manifest) {
		m.Children = []Child{{PackageID: "worker", Relationship: "private", Required: true}}
		m.Lifecycle.StartDeadlineMS = 40
	})
	child := managerPackage(t, "worker", func(m *Manifest) { m.InstallationModes = []string{"private-child"}; m.Lifecycle.StartDeadlineMS = 1000 })
	topology := InstanceTopologyInput{Instances: []InstanceSpec{{"parent", parent.Pin(), "independent", Placement{"local-process"}}, {"worker", child.Pin(), "private-child", Placement{"local-process"}}}, Roots: []string{"parent"}, Children: []ChildBinding{{"parent", "worker", "private"}}}
	var parentDeadline time.Time
	var childProcess *managerWaitProcess
	driver := &managerTestDriver{start: func(ctx context.Context, r StartRequest) (OwnedInstance, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			return nil, pluginError("test_deadline_missing")
		}
		if r.Owner.InstanceID == "parent" {
			parentDeadline = deadline
			return managerReadyProcess(), nil
		}
		if deadline.After(parentDeadline) {
			return nil, pluginError("test_child_extended_parent_deadline")
		}
		childProcess = &managerWaitProcess{managerTestProcess: managerReadyProcess(), wait: func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }}
		return childProcess, nil
	}}
	m := managerForTest(t, context.Background(), driver)
	if _, err := m.Activate(context.Background(), managerGraphRequest([]AdmittedPackage{parent, child}, topology)); err == nil || err.Error() != "plugin_deadline_exceeded" {
		t.Fatal("parent startup deadline was extended")
	}
	if childProcess == nil || !completed(childProcess.Done()) || m.Snapshot().Revision != 0 {
		t.Fatal("deadline failure lost original child cleanup")
	}
}

func TestManagerSharedRetentionPrivateScopesAndInstanceConfigurations(t *testing.T) {
	a := managerPackage(t, "alpha", func(m *Manifest) {
		m.Children = []Child{{"worker", "private", true}, {"shared", "independent-reference", true}}
	})
	b := managerPackage(t, "bravo", func(m *Manifest) {
		m.Children = []Child{{"worker", "private", true}, {"shared", "independent-reference", true}}
	})
	child := managerPackage(t, "worker", func(m *Manifest) { m.InstallationModes = []string{"private-child"} })
	shared := managerPackage(t, "shared", nil)
	topology := InstanceTopologyInput{Instances: []InstanceSpec{
		{"a", a.Pin(), "independent", Placement{"local-process"}}, {"b", b.Pin(), "independent", Placement{"local-process"}},
		{"ac", child.Pin(), "private-child", Placement{"local-process"}}, {"bc", child.Pin(), "private-child", Placement{"local-process"}}, {"shared", shared.Pin(), "independent", Placement{"local-process"}},
	}, Roots: []string{"a", "b", "shared"}, Children: []ChildBinding{{"a", "ac", "private"}, {"b", "bc", "private"}, {"a", "shared", "independent-reference"}, {"b", "shared", "independent-reference"}}}
	var stops []string
	processes := map[string]*managerTestProcess{}
	driver := &managerTestDriver{start: func(_ context.Context, r StartRequest) (OwnedInstance, error) {
		p := managerReadyProcess()
		id := r.Owner.InstanceID
		p.onStop = func() { stops = append(stops, id) }
		processes[id] = p
		return p, nil
	}}
	m := managerForTest(t, context.Background(), driver)
	request := managerGraphRequest([]AdmittedPackage{a, b, child, shared}, topology)
	for i := range request.InstanceConfigurations {
		if request.InstanceConfigurations[i].InstanceID == "ac" {
			request.InstanceConfigurations[i].Raw = []byte(`{"project":"a"}`)
		}
		if request.InstanceConfigurations[i].InstanceID == "bc" {
			request.InstanceConfigurations[i].Raw = []byte(`{"project":"b"}`)
		}
	}
	snapshot, err := m.Activate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	as, _ := managerSnapshotInstance(snapshot, "a")
	bs, _ := managerSnapshotInstance(snapshot, "b")
	ss, _ := managerSnapshotInstance(snapshot, "shared")
	ac, err := m.ResolveFor(as.Owner, "ac", "tool", "inspect_worker")
	if err != nil {
		t.Fatal(err)
	}
	bc, err := m.ResolveFor(bs.Owner, "bc", "tool", "inspect_worker")
	if err != nil || ac.Owner.Pin != bc.Owner.Pin || ac.Owner.InstanceID == bc.Owner.InstanceID {
		t.Fatal("private copies lost exact package identity")
	}
	if _, err = m.ResolveFor(bs.Owner, "ac", "tool", "inspect_worker"); err == nil {
		t.Fatal("another parent gained private visibility")
	}
	if _, err = m.Resolve("tool", "inspect_worker"); err == nil {
		t.Fatal("private contribution globally visible")
	}
	seen := map[string]string{}
	for _, r := range driver.requested() {
		seen[r.Owner.InstanceID] = string(r.Configuration.Bytes())
		if r.Owner.InstanceID == "shared" && (r.Parent != nil || r.ParentLifetime != nil) {
			t.Fatal("shared reference acquired a borrower lifetime")
		}
	}
	if seen["ac"] != `{"project":"a"}` || seen["bc"] != `{"project":"b"}` {
		t.Fatal("instance configurations were conflated")
	}
	if _, err = m.ReleaseRoot(context.Background(), as.Owner); err != nil {
		t.Fatal(err)
	}
	if strings.Join(stops, ",") != "ac,a" || processes["shared"].stopCount() != 0 || m.CheckActive(ac.Owner) == nil {
		t.Fatal("parent release changed unrelated ownership")
	}
	if _, err = m.ResolveFor(as.Owner, "shared", "tool", "inspect_shared"); err == nil {
		t.Fatal("released borrower still dispatches")
	}
	if _, err = m.ResolveFor(bs.Owner, "shared", "tool", "inspect_shared"); err != nil {
		t.Fatal("remaining borrower lost shared instance")
	}
	if _, err = m.ReleaseRoot(context.Background(), ss.Owner); err != nil {
		t.Fatal(err)
	}
	current, _ := managerSnapshotInstance(m.Snapshot(), "shared")
	if current.RootRetained || len(current.Consumers) != 1 || current.Consumers[0] != "b" || processes["shared"].stopCount() != 0 {
		t.Fatal("released root was confused with its remaining consumer")
	}
	if _, err = m.ReleaseRoot(context.Background(), as.Owner); err == nil || err.Error() != "plugin_owner_stale" {
		t.Fatal("stale release accepted")
	}
	if _, err = m.ReleaseRoot(context.Background(), bs.Owner); err != nil {
		t.Fatal(err)
	}
	if len(m.Snapshot().Instances) != 0 || strings.Join(stops, ",") != "ac,a,bc,b,shared" {
		t.Fatal("last consumer did not release the unretained shared owner")
	}
	if driver.count() != 5 {
		t.Fatal("release cloned a shared or private instance")
	}
}

func TestManagerParentLifetimeRevokesSubtreeBeforeOriginalWaitAndRetriesCleanup(t *testing.T) {
	parent, child, topology := managerPrivatePair(t)
	firstParent, firstChild := managerLiveProcess(), managerLiveProcess()
	firstParent.stopError = errors.New("private original wait uncertainty")
	var mu sync.Mutex
	counts := map[string]int{}
	var stops []string
	firstParent.onStop = func() { mu.Lock(); stops = append(stops, "parent"); mu.Unlock() }
	firstChild.onStop = func() { mu.Lock(); stops = append(stops, "worker"); mu.Unlock() }
	driver := &managerTestDriver{start: func(_ context.Context, r StartRequest) (OwnedInstance, error) {
		mu.Lock()
		defer mu.Unlock()
		id := r.Owner.InstanceID
		counts[id]++
		if counts[id] == 1 {
			if id == "parent" {
				return firstParent, nil
			}
			return firstChild, nil
		}
		return managerLiveProcess(), nil
	}}
	m := managerForTest(t, context.Background(), driver)
	snapshot, err := m.Activate(context.Background(), managerGraphRequest([]AdmittedPackage{parent, child}, topology))
	if err != nil {
		t.Fatal(err)
	}
	oldParent, _ := managerSnapshotInstance(snapshot, "parent")
	oldChild, _ := managerSnapshotInstance(snapshot, "worker")
	firstParent.endLifetime()
	if completed(firstParent.Done()) {
		t.Fatal("lifetime end fabricated original process completion")
	}
	if m.CheckActive(oldChild.Owner) == nil || m.CheckActive(oldParent.Owner) == nil {
		t.Fatal("old private ancestry retained authority after lifetime loss")
	}
	managerWait(t, func() bool { return m.Snapshot().RetainedCleanup == 1 })
	mu.Lock()
	order := strings.Join(stops, ",")
	mu.Unlock()
	if order != "worker,parent" || driver.count() != 2 || !completed(firstChild.Done()) {
		t.Fatal("subtree was not cleaned deepest first before restart")
	}
	firstParent.mu.Lock()
	firstParent.stopError = nil
	firstParent.mu.Unlock()
	if err = m.RetryCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	currentParent, _ := managerSnapshotInstance(m.Snapshot(), "parent")
	currentChild, _ := managerSnapshotInstance(m.Snapshot(), "worker")
	if currentParent.Owner.Generation != 2 || currentChild.Owner.Generation != 2 || currentChild.Parent == nil || *currentChild.Parent != currentParent.Owner || currentParent.RestartAttempts != 1 || currentChild.RestartAttempts != 0 {
		t.Fatal("parent recovery did not bind fresh subtree generations and budgets")
	}
	if m.CheckActive(oldParent.Owner) == nil || m.CheckActive(oldChild.Owner) == nil || m.CheckActive(currentChild.Owner) != nil || !completed(firstParent.Done()) {
		t.Fatal("old owner survived recovery or original wait was abandoned")
	}
	requests := driver.requested()
	if len(requests) != 4 || requests[2].Owner.InstanceID != "parent" || requests[3].Owner.InstanceID != "worker" || requests[3].Parent == nil || *requests[3].Parent != requests[2].Owner || requests[3].ParentLifetime == firstParent.LifetimeDone() {
		t.Fatal("replacement reused the old parent lifetime")
	}
}

func TestManagerPrivateChildFailureDoesNotRestartParentOrSharedService(t *testing.T) {
	parent, child, topology := managerPrivatePair(t)
	shared := managerPackage(t, "shared", nil)
	topology.Instances = append(topology.Instances, InstanceSpec{"shared", shared.Pin(), "independent", Placement{"local-process"}})
	topology.Roots = append(topology.Roots, "shared")
	var mu sync.Mutex
	children := []*managerTestProcess{managerReadyProcess(), managerReadyProcess()}
	var parentProcess, sharedProcess *managerTestProcess
	starts := 0
	driver := &managerTestDriver{start: func(_ context.Context, r StartRequest) (OwnedInstance, error) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Owner.InstanceID {
		case "parent":
			parentProcess = managerReadyProcess()
			return parentProcess, nil
		case "shared":
			sharedProcess = managerReadyProcess()
			return sharedProcess, nil
		}
		if starts >= len(children) {
			return nil, pluginError("test_extra_child_restart")
		}
		p := children[starts]
		starts++
		return p, nil
	}}
	m := managerForTest(t, context.Background(), driver)
	snapshot, err := m.Activate(context.Background(), managerGraphRequest([]AdmittedPackage{parent, child, shared}, topology))
	if err != nil {
		t.Fatal(err)
	}
	originalParent, _ := managerSnapshotInstance(snapshot, "parent")
	children[0].exit(nil)
	managerWait(t, func() bool {
		s, ok := managerSnapshotInstance(m.Snapshot(), "worker")
		return ok && s.State == "ready" && s.Owner.Generation == 2
	})
	if m.CheckActive(originalParent.Owner) != nil || parentProcess.stopCount() != 0 || sharedProcess.stopCount() != 0 || driver.count() != 4 {
		t.Fatal("child recovery restarted an unrelated owner")
	}
	children[1].exit(nil)
	managerWait(t, func() bool {
		s, _ := managerSnapshotInstance(m.Snapshot(), "worker")
		return s.Code == "plugin_restart_exhausted"
	})
	if m.CheckActive(originalParent.Owner) == nil {
		t.Fatal("required failed child did not degrade parent dispatch")
	}
	if _, err = m.Resolve("tool", "inspect_shared"); err != nil || parentProcess.stopCount() != 0 || sharedProcess.stopCount() != 0 || driver.count() != 4 {
		t.Fatal("child exhaustion stopped unrelated processes")
	}
}

func TestManagerFailedPrivateAdditionPreservesPriorRegistryAndJoinsSubtree(t *testing.T) {
	old := managerPackage(t, "original", nil)
	parent, child, topology := managerPrivatePair(t)
	topology.Instances = append(topology.Instances, InstanceSpec{"original", old.Pin(), "independent", Placement{"local-process"}})
	topology.Roots = append(topology.Roots, "original")
	var stops []string
	driver := &managerTestDriver{start: func(_ context.Context, r StartRequest) (OwnedInstance, error) {
		p := managerReadyProcess()
		id := r.Owner.InstanceID
		p.onStop = func() { stops = append(stops, id) }
		if id == "worker" {
			p.readyError = pluginError("test_private_initialization_failed")
		}
		return p, nil
	}}
	m := managerForTest(t, context.Background(), driver)
	firstRequest := managerRequest(old)
	firstRequest.Instances["original"] = "original"
	first, err := m.Activate(context.Background(), firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	oldOwner := first.Instances[0].Owner
	if _, err = m.Activate(context.Background(), managerGraphRequest([]AdmittedPackage{old, parent, child}, topology)); err == nil || err.Error() != "test_private_initialization_failed" {
		t.Fatal("partial initialization accepted")
	}
	if m.CheckActive(oldOwner) != nil || len(m.Snapshot().Instances) != 1 || m.Snapshot().Revision != first.Revision || strings.Join(stops, ",") != "worker,parent" {
		t.Fatal("failed addition changed prior active set or lost cleanup")
	}
}

func TestManagerReleasedOwnerCleanupCannotRestoreAuthority(t *testing.T) {
	parent, child, topology := managerPrivatePair(t)
	childProcess := managerReadyProcess()
	childProcess.stopError = errors.New("private stop uncertainty")
	driver := &managerTestDriver{start: func(_ context.Context, r StartRequest) (OwnedInstance, error) {
		if r.Owner.InstanceID == "worker" {
			return childProcess, nil
		}
		return managerReadyProcess(), nil
	}}
	m := managerForTest(t, context.Background(), driver)
	request := managerGraphRequest([]AdmittedPackage{parent, child}, topology)
	snapshot, err := m.Activate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := managerSnapshotInstance(snapshot, "parent")
	after, err := m.ReleaseRoot(context.Background(), owner.Owner)
	if err == nil || err.Error() != "plugin_cleanup_incomplete" || len(after.Instances) != 0 || after.RetainedCleanup != 1 || m.CheckActive(owner.Owner) == nil {
		t.Fatal("uncertain release restored authority")
	}
	if _, err = m.Activate(context.Background(), request); err == nil || driver.count() != 2 {
		t.Fatal("unjoined released owner allowed a new start")
	}
	childProcess.mu.Lock()
	childProcess.stopError = nil
	childProcess.mu.Unlock()
	if err = m.RetryCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !completed(childProcess.Done()) || len(m.Snapshot().Instances) != 0 || driver.count() != 2 {
		t.Fatal("cleanup retry resurrected released subtree")
	}
}

func TestManagerReleaseDoesNotRetainUnboundOptionalPackage(t *testing.T) {
	a := managerPackage(t, "alpha", func(m *Manifest) {
		m.Dependencies = []Dependency{{PackageID: "bravo", MinimumVersion: "1.0.0", ExclusiveMaximumVersion: "2.0.0", Optional: true}}
	})
	b := managerPackage(t, "bravo", nil)
	topology := InstanceTopologyInput{Instances: []InstanceSpec{
		{"a", a.Pin(), "independent", Placement{"local-process"}},
		{"b", b.Pin(), "independent", Placement{"local-process"}},
	}, Roots: []string{"a", "b"}}
	processes := map[string]*managerTestProcess{}
	driver := &managerTestDriver{start: func(_ context.Context, request StartRequest) (OwnedInstance, error) {
		process := managerReadyProcess()
		processes[request.Owner.InstanceID] = process
		return process, nil
	}}
	m := managerForTest(t, context.Background(), driver)
	snapshot, err := m.Activate(context.Background(), managerGraphRequest([]AdmittedPackage{a, b}, topology))
	if err != nil {
		t.Fatal(err)
	}
	originalA, _ := managerSnapshotInstance(snapshot, "a")
	originalB, _ := managerSnapshotInstance(snapshot, "b")
	after, err := m.ReleaseRoot(context.Background(), originalB.Owner)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Instances) != 1 || m.CheckActive(originalA.Owner) != nil || processes["a"].stopCount() != 0 || processes["b"].stopCount() != 1 || len(after.InstanceUnavailable) != 1 {
		t.Fatal("package admission created an undeclared instance retention edge")
	}
}
