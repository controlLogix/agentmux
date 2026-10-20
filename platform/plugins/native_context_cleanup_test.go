package plugins

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// This owner double tests driver cleanup only. It does not authenticate a user
// or qualify the context services and their broker permissions.
type retainedContextOwner struct {
	owner  OwnerReference
	done   chan struct{}
	joined chan struct{}
	once   sync.Once
}

func (c *retainedContextOwner) Owner() OwnerReference       { return c.owner }
func (c *retainedContextOwner) Descriptor() []byte          { return nil }
func (c *retainedContextOwner) Bootstrap() ContextBootstrap { return ContextBootstrap{} }
func (c *retainedContextOwner) Done() <-chan struct{}       { return c.done }
func (c *retainedContextOwner) Invalidate()                 { c.once.Do(func() { close(c.done) }) }
func (c *retainedContextOwner) Dispatch(context.Context, []byte) ([]byte, error) {
	return nil, pluginError("context_unavailable")
}
func (c *retainedContextOwner) Close(ctx context.Context) error {
	if !completed(c.done) {
		return pluginError("context_still_active")
	}
	select {
	case <-c.joined:
		return nil
	case <-ctx.Done():
		return pluginError("context_cleanup_incomplete")
	}
}

func TestNativeContextCleanupRetainsOriginalOwnerAndStage(t *testing.T) {
	directory := privateTestDirectory(t)
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal("fixture root unavailable")
	}
	t.Cleanup(func() { _ = root.Close() })
	if root.Mkdir("stage", 0700) != nil {
		t.Fatal("fixture stage unavailable")
	}
	info, err := root.Lstat("stage")
	if err != nil {
		t.Fatal("fixture stage identity")
	}
	driver := &NativeDriver{root: root, owners: map[string]*nativeInstance{}}
	done := make(chan struct{})
	close(done)
	owner := OwnerReference{InstanceID: "instance"}
	lease := &retainedContextOwner{owner: owner, done: make(chan struct{}), joined: make(chan struct{})}
	p := &nativeInstance{driver: driver, owner: owner, drain: time.Second, stage: "stage", stageInfo: info, done: done, processDone: done, lifetimeDone: make(chan struct{}), stopToken: make(chan struct{}, 1), contextLease: lease, contextDone: lease.Done()}
	p.stopToken <- struct{}{}
	driver.owners[owner.InstanceID] = p
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	err = p.Stop(ctx)
	cancel()
	if err == nil || !completed(lease.done) || !completed(p.lifetimeDone) {
		t.Fatal("stop did not invalidate and retain unfinished context")
	}
	if driver.owners[owner.InstanceID] != p || p.cleaned {
		t.Fatal("original owner lost before context joined")
	}
	if _, err := root.Lstat("stage"); err != nil {
		t.Fatal("stage removed before context joined")
	}
	if _, err := driver.Dispatch(context.Background(), owner, []byte(`{}`)); err == nil {
		t.Fatal("stopped context admitted another call")
	}
	close(lease.joined)
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := p.Stop(ctx); err != nil {
		t.Fatal("same owner could not finish cleanup", err)
	}
	if len(driver.owners) != 0 || !p.cleaned {
		t.Fatal("joined context owner retained")
	}
	if _, err := root.Lstat("stage"); !os.IsNotExist(err) {
		t.Fatal("joined stage retained")
	}
}

func TestNativeContextConstructorRequiresProvider(t *testing.T) {
	var absent *blockingContextProvider
	for _, provider := range []ContextProvider{nil, absent} {
		if driver, err := NewNativeDriverWithContext(context.Background(), NativeDriverOptions{}, provider); err == nil || driver != nil {
			t.Fatal("missing context provider accepted")
		}
	}
}

type blockingContextProvider struct {
	entered chan time.Time
	release chan struct{}
	lease   *retainedContextOwner
}

func (p *blockingContextProvider) Open(ctx context.Context, binding ContextBinding) (ContextLease, error) {
	deadline, _ := ctx.Deadline()
	p.entered <- deadline
	<-ctx.Done()
	<-p.release
	return p.lease, pluginError("fixture_context_open_canceled")
}

func TestNativeContextStartCancellationRetainsLateLease(t *testing.T) {
	pkg := nativeFixturePackage(t, "contextstart")
	configuration, err := PrepareConfiguration(pkg, nil, []byte(`{"behavior":"normal"}`))
	if err != nil {
		t.Fatal("fixture configuration", err)
	}
	owner := OwnerReference{Pin: pkg.Pin(), InstanceID: "contextstart", Epoch: strings.Repeat("a", 64), Generation: 1}
	directory := privateTestDirectory(t)
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal("fixture root")
	}
	t.Cleanup(func() { _ = root.Close() })
	info, err := root.Stat(".")
	if err != nil {
		t.Fatal("fixture identity")
	}
	lease := &retainedContextOwner{owner: owner, done: make(chan struct{}), joined: make(chan struct{})}
	close(lease.joined)
	provider := &blockingContextProvider{entered: make(chan time.Time, 1), release: make(chan struct{}), lease: lease}
	driver := &NativeDriver{options: NativeDriverOptions{HubID: "fixture", StateDirectory: directory}, root: root, rootInfo: info, owners: map[string]*nativeInstance{}, bindings: map[string]admittedNativeBinding{owner.InstanceID: {binding: NativeBinding{Pin: pkg.Pin(), InstanceID: owner.InstanceID}}}, contexts: provider}
	result := make(chan error, 1)
	go func() {
		_, err := driver.Start(context.Background(), StartRequest{Owner: owner, Package: pkg, Configuration: configuration})
		result <- err
	}()
	defer func() {
		select {
		case <-provider.release:
		default:
			close(provider.release)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := driver.Close(ctx); err != nil {
			t.Errorf("late provider cleanup: %v", err)
		}
	}()
	select {
	case deadline := <-provider.entered:
		if deadline.IsZero() || time.Until(deadline) > 3*time.Second {
			t.Fatal("provider did not receive package startup deadline")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("provider did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err = driver.Close(ctx)
	cancel()
	if err == nil {
		t.Fatal("incomplete start incorrectly reported closed")
	}
	driver.mu.Lock()
	p := driver.owners[owner.InstanceID]
	retainedRoot := driver.root
	driver.mu.Unlock()
	if p == nil || retainedRoot != root || completed(p.startDone) {
		t.Fatal("in-flight start owner lost")
	}
	if _, err := root.Lstat(p.stage); err != nil {
		t.Fatal("in-flight stage removed")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	if _, err := driver.Dispatch(ctx, owner, []byte(`{}`)); err == nil {
		t.Fatal("starting owner accepted dispatch")
	}
	cancel()
	close(provider.release)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled startup succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("original start did not join")
	}
	if !completed(lease.done) {
		t.Fatal("late lease retained authority after stop")
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := driver.Close(ctx); err != nil {
		t.Fatal("original retained owner cleanup failed", err)
	}
	if len(driver.owners) != 0 || driver.root != nil {
		t.Fatal("joined owner or root retained")
	}
}
