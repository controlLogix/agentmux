//go:build linux

package runtime

import (
	"context"
	"errors"
	"testing"
)

type rejectedStartImage struct {
	executable
	checked bool
	closed  bool
}

func (image *rejectedStartImage) validateForStart(ctx context.Context) error {
	image.checked = true
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New("fixture installation changed before spawn")
}

func (image *rejectedStartImage) close() error {
	image.closed = true
	return image.executable.close()
}

func TestStartValidationRejectsBeforeSpawnAndReapsEarlierChildren(t *testing.T) {
	root, raw, trust, opts := releaseFixture(t)
	p := prepared(t, root, raw, trust)
	rejected := &rejectedStartImage{executable: p.images[2]}
	p.images[2] = rejected
	group, err := p.Start(context.Background(), opts, budgets())
	if err == nil || group == nil || !rejected.checked || !rejected.closed {
		t.Fatal("pre-spawn validation or descriptor cleanup was bypassed")
	}
	states := group.Status()
	if len(states) != 2 {
		t.Fatal("rejected or later executable was spawned")
	}
	for _, state := range states {
		if !state.Exited {
			t.Fatal("earlier owned child was not reaped after refusal")
		}
	}
	if group.CleanupError() != nil {
		t.Fatal("refused start left owned descriptors open")
	}
	select {
	case <-group.Done():
	default:
		t.Fatal("refused start did not finish owned lifecycle")
	}
}
