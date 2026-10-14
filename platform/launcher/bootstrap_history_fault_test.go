//go:build (linux || darwin) && historyfaultfixture

package launcher

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Only disposable copies carry the documented cancel/create and mode0500
// injections. These controls demonstrate real FS effects, not installed boot.
func TestBootstrapHistoryFaultExpiryAfterSchemaStartsNoMutation(t *testing.T) {
	if os.Getenv("AGENTMUX_HISTORY_FAULT_MODE") != "after_schema_cancel" {
		t.Fatal("explicit disposable injection required")
	}
	store, op, f, _, _ := historyFixture(t)
	if op.enter(op.startup, f.config, f.profile, op.attemptID) != nil {
		t.Fatal("component admission failed")
	}
	if store.Begin(op.startup) == nil {
		t.Fatal("actual canceled publication succeeded")
	}
	entries, err := os.ReadDir(f.profile.ProfileDirectory)
	if err != nil {
		t.Fatal("fixture inventory failed")
	}
	stageCount := 0
	marker := false
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".bootstrap-history_") {
			stageCount++
		}
		if entry.Name() == ".history-create-marker" {
			marker = true
		}
	}
	if marker || stageCount != 0 {
		t.Fatal("real create or stage remains after schema cancellation")
	}
}

func TestBootstrapHistoryFaultUnresolvedStageDoesNotBlockRetry(t *testing.T) {
	if os.Getenv("AGENTMUX_HISTORY_FAULT_MODE") != "unlink_eacces" {
		t.Fatal("explicit disposable injection required")
	}
	store, op, f, lease, binding := historyFixture(t)
	directory := f.profile.ProfileDirectory
	t.Cleanup(func() {
		if os.Chmod(directory, 0700) != nil {
			t.Error("fixture mode restoration failed")
		}
	})
	if op.enter(op.startup, f.config, f.profile, op.attemptID) != nil {
		t.Fatal("component admission failed")
	}
	failure := store.Begin(op.startup)
	if failure == nil || !errors.Is(failure, syscall.EACCES) {
		t.Fatal("actual staging unlink EACCES not demonstrated")
	}
	var retained interface{ Close(context.Context) error }
	if !errors.As(failure, &retained) {
		t.Fatal("exact staged cleanup owner lost")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal("stage enumeration failed")
	}
	var name string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".bootstrap-history_") {
			if name != "" {
				t.Fatal("unexpected extra stage")
			}
			name = entry.Name()
		}
	}
	if name == "" {
		t.Fatal("actual failed-unlink stage absent")
	}
	stagePath := filepath.Join(directory, name)
	original, err := os.Lstat(stagePath)
	if err != nil {
		t.Fatal("actual stage identity absent")
	}
	if store.Close(op.startup) == nil {
		t.Fatal("unresolved unlink falsely completed cleanup")
	}
	if lease.Close() != nil {
		t.Fatal("original component lease close failed")
	}
	// The history duplicate must have been released after publication joined,
	// while the exact root/temp cleanup capability remains available.
	nextCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	nextLease, err := AcquireBootstrapLock(nextCtx, directory, f.profile.InstanceID, "owner-status-service")
	cancel()
	if err != nil {
		t.Fatal("history cleanup blocked genuine next lock acquisition")
	}
	t.Cleanup(func() {
		if nextLease.Close() != nil {
			t.Error("next component lease cleanup failed")
		}
	})
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("write-mode restoration failed")
	}
	newer, err := newBootstrapOperation(op.startup, op.lifetime, op.server, nextLease, "attempt_"+strings.Repeat("b", 32))
	if err != nil {
		t.Fatal("new lease operation refused")
	}
	binding.ColdInvocationID = newer.attemptID
	nextStore, err := openBootstrapHistory(op.startup, newer, binding)
	if nextStore != nil {
		t.Cleanup(func() {
			if nextStore.Close(op.startup) != nil {
				t.Error("new store cleanup failed")
			}
		})
	}
	if err != nil || newer.enter(op.startup, f.config, f.profile, newer.attemptID) != nil || nextStore.Begin(op.startup) != nil || newer.complete(&Session{startupAttemptID: newer.attemptID}, nil) != nil || nextStore.RecordTerminal(op.startup) != nil {
		t.Fatal("new successful generation refused")
	}
	sharedPath := filepath.Join(directory, bootstrapHistoryName)
	shared, err := os.ReadFile(sharedPath)
	if err != nil {
		t.Fatal("new shared generation unavailable")
	}
	// A different inode at the old minted name must remain untouched.
	backup := stagePath + ".fixture-owned-backup"
	if os.Rename(stagePath, backup) != nil || os.WriteFile(stagePath, []byte("foreign fixture"), 0600) != nil {
		t.Fatal("foreign replacement setup failed")
	}
	foreign, err := os.Lstat(stagePath)
	if err != nil {
		t.Fatal("foreign identity unavailable")
	}
	if retained.Close(op.startup) == nil {
		t.Fatal("foreign stage replacement removed")
	}
	after, err := os.Lstat(stagePath)
	if err != nil || !os.SameFile(foreign, after) {
		t.Fatal("foreign replacement changed")
	}
	if os.Remove(stagePath) != nil || os.Rename(backup, stagePath) != nil {
		t.Fatal("exact original stage restoration failed")
	}
	restored, err := os.Lstat(stagePath)
	if err != nil || !os.SameFile(original, restored) {
		t.Fatal("original stage inode lost")
	}
	if retained.Close(op.startup) != nil {
		t.Fatal("same staged object cleanup retry failed")
	}
	if _, err := os.Lstat(stagePath); !os.IsNotExist(err) {
		t.Fatal("same stage was not removed")
	}
	final, err := os.ReadFile(sharedPath)
	if err != nil || !bytes.Equal(shared, final) {
		t.Fatal("old stage cleanup altered new successful generation")
	}
}

func TestBootstrapHistoryFaultFinalRootPrivacyRecheck(t *testing.T) {
	if os.Getenv("AGENTMUX_HISTORY_FAULT_MODE") != "reader_root_public" {
		t.Fatal("explicit disposable injection required")
	}
	store, op, f, lease, binding := historyFixture(t)
	t.Cleanup(func() {
		if os.Chmod(f.profile.ProfileDirectory, 0700) != nil {
			t.Error("fixture mode restoration failed")
		}
	})
	enterHistoryFixture(t, store, op, f)
	completeHistoryFailure(t, store, op)
	if store.Close(op.startup) != nil || lease.Close() != nil {
		t.Fatal("actual service lock release failed")
	}
	result, err := readBootstrapHistory(op.startup, f.owner, binding.RuntimeDigest)
	if result != nil || err == nil {
		t.Fatal("private root change after actual read escaped final check")
	}
}
