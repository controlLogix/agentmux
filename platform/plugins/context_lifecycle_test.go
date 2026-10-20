package plugins

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"
)

func TestContextLifecycleTracksReadinessHealthAndDrain(t *testing.T) {
	owner := OwnerReference{InstanceID: "original", Generation: 1}
	source := newNativeContextLifecycle(owner)
	snapshot := source.Snapshot()
	if snapshot.Owner != owner || snapshot.State != "starting" || snapshot.Ready || snapshot.Health != "unknown" {
		t.Fatal("new owner invented readiness or health")
	}
	if err := source.ReportHealth("healthy"); err != nil {
		t.Fatal(err)
	}
	if source.Snapshot().Ready {
		t.Fatal("health report bypassed readiness acknowledgment")
	}
	if !source.markReady() || !source.Snapshot().Ready {
		t.Fatal("ready acknowledgment missing")
	}
	if err := source.ReportHealth("unhealthy"); err != nil || source.Snapshot().Ready {
		t.Fatal("unhealthy owner remained ready")
	}
	if err := source.ReportHealth("private-error-payload"); err == nil || source.Snapshot().Health != "unhealthy" {
		t.Fatal("arbitrary health payload accepted")
	}
	if err := source.ReportHealth("healthy"); err != nil || !source.Snapshot().Ready {
		t.Fatal("explicit health recovery ignored")
	}
	source.beginDrain()
	snapshot = source.Snapshot()
	if !completed(source.DrainDone()) || snapshot.State != "draining" || snapshot.Ready {
		t.Fatal("drain did not stop new readiness")
	}
	if source.markReady() || source.ReportHealth("healthy") == nil {
		t.Fatal("draining owner revived")
	}
	source.stop()
	source.stop()
	source.beginDrain()
	if source.Snapshot().State != "stopped" || source.ReportHealth("healthy") == nil {
		t.Fatal("stopped owner revived")
	}
}

func TestContextLifecycleConcurrentHealthCannotReverseDrain(t *testing.T) {
	source := newNativeContextLifecycle(OwnerReference{InstanceID: "original"})
	source.markReady()
	var workers sync.WaitGroup
	for range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 20 {
				_ = source.ReportHealth("healthy")
				_ = source.Snapshot()
			}
		}()
	}
	source.beginDrain()
	workers.Wait()
	snapshot := source.Snapshot()
	if snapshot.State != "draining" || snapshot.Ready {
		t.Fatal("health report reversed drain")
	}
}

func TestNativeContextStopDrainsBeforeCancelingAdmittedWork(t *testing.T) {
	directory := privateTestDirectory(t)
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal("fixture root")
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error("fixture root close")
		}
	})
	if err := root.Mkdir("stage", 0700); err != nil {
		t.Fatal("fixture stage")
	}
	info, err := root.Lstat("stage")
	if err != nil {
		t.Fatal("fixture stage identity")
	}
	owner := OwnerReference{InstanceID: "original"}
	source := newNativeContextLifecycle(owner)
	source.markReady()
	lease := &retainedContextOwner{owner: owner, done: make(chan struct{}), joined: make(chan struct{})}
	close(lease.joined)
	processDone := make(chan struct{})
	driver := &NativeDriver{root: root, owners: map[string]*nativeInstance{}}
	p := &nativeInstance{driver: driver, owner: owner, drain: 3 * time.Second, stage: "stage", stageInfo: info, done: processDone, lifetimeDone: make(chan struct{}), stopToken: make(chan struct{}, 1), contextLease: lease, contextDone: lease.Done(), lifecycle: source}
	p.stopToken <- struct{}{}
	driver.owners[owner.InstanceID] = p
	result := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		result <- p.Stop(ctx)
	}()
	var once sync.Once
	finish := func() { once.Do(func() { close(processDone) }) }
	defer func() {
		finish()
		select {
		case err := <-result:
			if err != nil {
				t.Error(err)
			}
			if !completed(p.lifetimeDone) || !completed(lease.Done()) || !p.cleaned || len(driver.owners) != 0 || source.Snapshot().State != "stopped" {
				t.Error("drained owner was not joined and released")
			}
			if _, err := root.Lstat("stage"); !os.IsNotExist(err) {
				t.Error("joined stage retained")
			}
		case <-time.After(4 * time.Second):
			t.Error("original stop did not join")
		}
	}()
	select {
	case <-source.DrainDone():
	case <-time.After(time.Second):
		t.Fatal("drain notification missing")
	}
	if completed(p.lifetimeDone) || completed(lease.Done()) {
		t.Fatal("graceful drain canceled admitted context work")
	}
	if source.Snapshot().State != "draining" || p.Available() {
		t.Fatal("draining owner accepted new work")
	}
	finish()
	// The deferred join verifies that the original process completion releases
	// context ownership and staging only after the graceful drain observation.
}
