package plugins

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeCompletedStageCloseFailureMovesOnlyAfterJoinedCleanup(t *testing.T) {
	directory := privateTestDirectory(t)
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal("fixture root unavailable")
	}
	t.Cleanup(func() { _ = root.Close() })
	if root.Mkdir("stage", 0700) != nil {
		t.Fatal("fixture stage unavailable")
	}
	stageInfo, err := root.Lstat("stage")
	if err != nil {
		t.Fatal("fixture stage identity")
	}
	consumed, err := os.CreateTemp(directory, "stage-file")
	if err != nil {
		t.Fatal("fixture descriptor")
	}
	if consumed.Close() != nil {
		t.Fatal("fixture descriptor close")
	}
	historical := closeAdmission(consumed, pluginError("native_stage_unavailable"))
	var original *AdmissionCleanupFailure
	if !errors.As(historical, &original) {
		t.Fatal("fixture historical failure")
	}
	workspace, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal("fixture workspace")
	}
	t.Cleanup(func() { _ = workspace.Close() })
	lock, err := os.OpenFile(filepath.Join(directory, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal("fixture lock")
	}
	t.Cleanup(func() { _ = lock.Close() })
	driver := &NativeDriver{root: root, lock: lock, owners: map[string]*nativeInstance{}, bindings: map[string]admittedNativeBinding{"example": {workspace: workspace}}}
	done := make(chan struct{})
	close(done)
	owner := OwnerReference{InstanceID: "instance"}
	instance := &nativeInstance{driver: driver, owner: owner, drain: time.Second, stage: "stage", stageInfo: stageInfo, done: done, processDone: done, stopToken: make(chan struct{}, 1), cleanupFailure: historical}
	instance.stopToken <- struct{}{}
	driver.owners[owner.InstanceID] = instance
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := instance.Stop(ctx); err != nil {
		t.Fatal("joined process retained historical descriptor as live cleanup")
	}
	if len(driver.owners) != 0 || !instance.cleaned {
		t.Fatal("joined instance retained")
	}
	if _, err := root.Lstat("stage"); !os.IsNotExist(err) {
		t.Fatal("stage cleanup not proved")
	}
	if !errors.Is(driver.closeFailure, historical) {
		t.Fatal("driver lost historical close cause")
	}
	err = driver.Close(ctx)
	var retained *AdmissionCleanupFailure
	if !errors.As(err, &retained) || retained != original {
		t.Fatal("driver historical result lost")
	}
	if driver.root != nil || driver.lock != nil || driver.bindings["example"].workspace != nil {
		t.Fatal("historical failure skipped remaining descriptor owners")
	}
	if _, err := lock.Stat(); err == nil {
		t.Fatal("lock descriptor not closed")
	}
	if _, err := workspace.Stat("."); err == nil {
		t.Fatal("workspace root not closed")
	}
	if err := instance.Stop(ctx); err != nil {
		t.Fatal("joined instance replayed consumed descriptor failure")
	}
	if !errors.As(driver.Close(ctx), &retained) || retained != original {
		t.Fatal("second driver close erased historical failure")
	}
}
