//go:build linux || darwin

package launcher

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestBootstrapHistoryConsumedCloseCauseModeRefusal(t *testing.T) {
	store, op, _, _, _ := historyFixture(t)
	name := ".bootstrap-history-cause-control"
	file, err := store.createStage(op.startup, name)
	if err != nil {
		t.Fatal("actual stage unavailable")
	}
	if err = file.Close(); err != nil {
		t.Fatal("fixture exact close failed")
	}
	if err = store.root.Chmod(name, 0644); err != nil {
		t.Fatal("fixture mode change failed")
	}
	failure := store.cleanupStage(op.startup)
	var retained *historyStageCleanupError
	causeRetained := errors.Is(failure, os.ErrClosed)
	ownerRetained := errors.As(failure, &retained) && retained.store == store
	_, exists := store.root.Lstat(name)
	if err = store.root.Chmod(name, 0600); err != nil {
		t.Fatal("fixture restore failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cleanupErr := store.Close(ctx)
	if cleanupErr != nil {
		t.Fatal("exact stage retry failed")
	}
	if !causeRetained || !ownerRetained || exists != nil {
		t.Fatal("consumed close cause or exact retained stage lost")
	}
}
