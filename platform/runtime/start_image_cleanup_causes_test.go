package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

// Only actual owned files are closed. No command may be constructed or started.
type startCleanupImage struct {
	file  *os.File
	cause error
	calls int
}

func (*startCleanupImage) command([]string) *exec.Cmd {
	panic("pre-canceled startup must not construct a command")
}

func (image *startCleanupImage) close() error {
	image.calls++
	image.cause = image.file.Close()
	return image.cause
}

func assertStartImageCleanupSafe(t *testing.T, failure error) {
	t.Helper()
	if !errors.Is(failure, ErrStartupCleanup) {
		t.Fatal("image disposal failure lost the startup cleanup category")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		if fmt.Sprintf(format, failure) != "startup failed; owned cleanup incomplete" {
			t.Fatal("image cleanup presentation exposed private details")
		}
	}
	raw, err := json.Marshal(failure)
	if err != nil || string(raw) != `"startup failed; owned cleanup incomplete"` {
		t.Fatal("image cleanup JSON exposed private details")
	}
}

func TestStartImageCleanupCanceledAndExpired(t *testing.T) {
	for _, expired := range []bool{false, true} {
		for _, closeFault := range []bool{false, true} {
			t.Run(fmt.Sprintf("expired_%t_closeFault_%t", expired, closeFault), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				want := context.Canceled
				if expired {
					cancel()
					ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
					want = context.DeadlineExceeded
				} else {
					cancel()
				}
				defer cancel()
				roles := [4]string{"boot", "kernel-lifecycle", "internal-communication", "exported-status"}
				prepared := &Prepared{roles: roles}
				var images [4]*startCleanupImage
				var options [4]RoleOptions
				for i, role := range roles {
					file, err := os.CreateTemp(t.TempDir(), "private-start-image-")
					if err != nil {
						t.Fatal("owned image file unavailable")
					}
					images[i] = &startCleanupImage{file: file}
					prepared.images[i] = images[i]
					options[i] = RoleOptions{ID: role}
					if closeFault && file.Close() != nil {
						t.Fatal("actual owned close-fault setup failed")
					}
				}
				t.Cleanup(func() { prepared.Close() })
				group, failure := prepared.Start(ctx, options, Deadlines{StartTimeout: time.Second, StopGrace: time.Second, ReapTimeout: time.Second})
				if group == nil || !errors.Is(failure, want) || !prepared.consumed {
					t.Fatal("startup lost the original context or consumed group")
				}
				select {
				case <-group.Done():
				case <-time.After(time.Second):
					t.Fatal("child-free group did not complete")
				}
				check := func(failure error, contextCause error) {
					t.Helper()
					if contextCause != nil && !errors.Is(failure, contextCause) {
						t.Fatal("image failure replaced the original context error")
					}
					if closeFault {
						assertStartImageCleanupSafe(t, failure)
						for _, image := range images {
							if image.cause == nil || !errors.Is(failure, image.cause) || !errors.Is(failure, os.ErrClosed) {
								t.Fatal("an actual image close cause was discarded")
							}
						}
						var actual *os.PathError
						if !errors.As(failure, &actual) || actual != images[0].cause {
							t.Fatal("typed image close cause was not retained")
						}
					} else if errors.Is(failure, ErrStartupCleanup) || (contextCause == nil && failure != nil) {
						t.Fatal("successful disposal acquired a cleanup failure")
					}
				}
				check(failure, want)
				check(group.CleanupError(), nil)
				check(group.Stop(context.Background()), nil)
				check(group.Stop(ctx), want)
				for _, image := range images {
					if _, err := image.file.Stat(); !errors.Is(err, os.ErrClosed) {
						t.Fatal("image ownership was not consumed")
					}
				}
				var workers sync.WaitGroup
				observations := make(chan [3]error, 8)
				for range 8 {
					workers.Add(1)
					go func() {
						defer workers.Done()
						observations <- [3]error{prepared.Close(), group.CleanupError(), group.Stop(context.Background())}
					}()
				}
				workers.Wait()
				close(observations)
				for observation := range observations {
					if observation[0] != nil {
						t.Fatal("consumed image cleanup was retried")
					}
					check(observation[1], nil)
					check(observation[2], nil)
				}
				for i, image := range images {
					if image.calls != 1 || prepared.images[i] != nil {
						t.Fatal("image descriptor disposal was not exactly once")
					}
				}
			})
		}
	}
}

func TestStartImageCleanupRetainsOtherResourceCauses(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "private-start-history-")
	if err != nil || file.Close() != nil {
		t.Fatal("owned historical close-fault setup failed")
	}
	imageCause := file.Close()
	if !errors.Is(imageCause, os.ErrClosed) {
		t.Fatal("actual owned descriptor fault unavailable")
	}
	writerCause := &os.PathError{Op: "close", Path: "/private/writer-history", Err: errors.New("writer close fault")}
	automaticCause := errors.New("automatic cleanup fault")
	done := make(chan struct{})
	close(done)
	group := &Group{
		children: []*owned{{done: done, cleanupError: writerCause}}, allDone: done,
		stopToken: make(chan struct{}, 1), imageCleanupError: imageCause,
		contextCleanupError: automaticCause,
	}
	group.stopToken <- struct{}{}
	for _, failure := range []error{group.CleanupError(), group.Stop(context.Background())} {
		assertStartImageCleanupSafe(t, failure)
		for _, cause := range []error{imageCause, os.ErrClosed, writerCause} {
			if !errors.Is(failure, cause) {
				t.Fatal("image history displaced an existing resource cause")
			}
		}
	}
	if !errors.Is(group.CleanupError(), automaticCause) {
		t.Fatal("image history displaced automatic cleanup history")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	failure := group.Stop(canceled)
	assertStartImageCleanupSafe(t, failure)
	if !errors.Is(failure, context.Canceled) || !errors.Is(failure, imageCause) {
		t.Fatal("failed Stop lost context or image history")
	}
	var absent *Group
	if absent.Stop(canceled).Error() != "process group is not owned by this supervisor" ||
		group.Stop(nil).Error() != "stop context is required" {
		t.Fatal("image history changed ownership or nil-context validation")
	}
}
