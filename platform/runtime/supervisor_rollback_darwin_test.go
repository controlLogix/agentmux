//go:build darwin && cgo && agentmux_bootstrap_docker && agentmux_darwin_runtime_fixture

package runtime

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

// This distinct five-file image requires separately reviewed build/install
// evidence. These tests neither enroll a release nor replace a protected file.
func darwinRuntimeRollbackFixture(t *testing.T) (*Prepared, [4]RoleOptions, [4]*darwinRollbackImage) {
	t.Helper()
	path, want := os.Getenv("AGENTMUX_RUNTIME_FIXTURE_PATH"), os.Getenv("AGENTMUX_RUNTIME_FIXTURE_DIGEST")
	root := filepath.Dir(path)
	if os.Getenv("AGENTMUX_RUNTIME_FIXTURE_AUTHORIZED") != "1" || goruntime.GOARCH != "arm64" || os.Getuid() == 0 || os.Getuid() != os.Geteuid() ||
		filepath.Base(path) != "runtime-fixture" || filepath.Clean(path) != path || !darwinReleaseRoot(root) {
		t.Fatal("separately installed runtime fixture prerequisite refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	image, err := openDarwinProtected(ctx, path, want, 128*1024*1024)
	if err != nil {
		t.Fatal("actual protected runtime fixture admission failed")
	}
	if image.close() != nil {
		t.Fatal("protected runtime fixture admission cleanup failed")
	}
	p := &Prepared{roles: protocol.Roles()}
	t.Cleanup(func() {
		if p.Close() != nil {
			t.Error("owned rollback images cleanup failed")
		}
	})
	var options [4]RoleOptions
	var images [4]*darwinRollbackImage
	deadline := strconv.FormatInt(time.Now().Add(15*time.Second).UnixNano(), 10)
	for i, role := range p.roles {
		admitted, err := openDarwinProtected(ctx, filepath.Join(root, "bin", role), want, 128*1024*1024)
		if err != nil {
			t.Fatal("actual protected rollback role admission failed")
		}
		images[i] = &darwinRollbackImage{image: admitted, heldFiles: append([]*os.File(nil), admitted.files...)}
		p.images[i] = images[i]
		options[i] = RoleOptions{ID: role, Args: []string{"parent", role, deadline}}
	}
	return p, options, images
}

func darwinRuntimeRollbackBudgets() Deadlines {
	return Deadlines{StartTimeout: 3 * time.Second, StopGrace: 50 * time.Millisecond, ReapTimeout: 2 * time.Second}
}

type darwinRollbackReady struct {
	reader, writer         *os.File
	heldReader, heldWriter *os.File
	completed              bool
}

func newDarwinRollbackReady(t *testing.T) *darwinRollbackReady {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal("actual rollback readiness pipe unavailable")
	}
	ready := &darwinRollbackReady{reader: reader, writer: writer, heldReader: reader, heldWriter: writer}
	t.Cleanup(func() {
		for _, slot := range []**os.File{&ready.reader, &ready.writer} {
			if file := *slot; file != nil {
				*slot = nil
				if file.Close() != nil {
					t.Error("owned rollback readiness cleanup failed")
				}
			}
		}
	})
	return ready
}

func (r *darwinRollbackReady) wait(deadline time.Time) error {
	writer := r.writer
	r.writer = nil
	if err := writer.Close(); err != nil {
		return err
	}
	if err := r.reader.SetReadDeadline(deadline); err != nil {
		return err
	}
	var value [1]byte
	if n, err := io.ReadFull(r.reader, value[:]); err != nil || n != 1 || value[0] != 1 {
		return errors.New("actual rollback role readiness missing")
	}
	if n, err := r.reader.Read(value[:]); n != 0 || !errors.Is(err, io.EOF) {
		return errors.New("actual rollback readiness EOF missing")
	}
	reader := r.reader
	r.reader = nil
	err := reader.Close()
	r.completed = err == nil
	return err
}

// The existing private executable seam wraps only already admitted images.
// No command substitutes an unprotected path or adopts another process handle.
type darwinRollbackImage struct {
	image         *protectedDarwinExecutable
	heldFiles     []*os.File
	ready         *darwinRollbackReady
	beforeCommand func()
	beforeCheck   func() error
	checked       bool
	validationErr error
	closeCalls    int
}

func (e *darwinRollbackImage) command(args []string) *exec.Cmd {
	if e.beforeCommand != nil {
		e.beforeCommand()
	}
	cmd := e.image.command(args)
	if e.ready != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, e.ready.writer)
	}
	return cmd
}
func (e *darwinRollbackImage) validateForStart(ctx context.Context) error {
	e.checked = true
	if e.beforeCheck != nil {
		if err := e.beforeCheck(); err != nil {
			e.validationErr = err
			return err
		}
	}
	e.validationErr = e.image.validateForStart(ctx)
	return e.validationErr
}
func (e *darwinRollbackImage) close() error {
	e.closeCalls++
	return e.image.close()
}

func darwinRollbackCloseCounts(images [4]*darwinRollbackImage) (counts [4]int) {
	for i, image := range images {
		counts[i] = image.closeCalls
	}
	return counts
}

// Call immediately after Start returns, before any registered cleanup runs.
// Retained os.File objects are observed only, never closed through a new owner.
func assertDarwinRollbackImagesConsumed(t *testing.T, p *Prepared, images [4]*darwinRollbackImage, before [4]int) {
	t.Helper()
	if !p.consumed {
		t.Fatal("rollback did not consume prepared ownership")
	}
	for i, image := range images {
		if p.images[i] != nil || image.closeCalls != before[i]+1 || len(image.image.files) != 0 || len(image.heldFiles) == 0 {
			t.Fatal("Start did not consume and close every original image exactly once")
		}
		for _, file := range image.heldFiles {
			if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("Start returned with an original protected image descriptor open")
			}
		}
	}
}

func assertDarwinRollbackReadyConsumed(t *testing.T, ready *darwinRollbackReady) {
	t.Helper()
	if !ready.completed || ready.reader != nil || ready.writer != nil {
		t.Fatal("earlier-child readiness barrier did not run to completion")
	}
	for _, file := range []*os.File{ready.heldReader, ready.heldWriter} {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("readiness barrier left an original descriptor open")
		}
	}
}

func darwinRollbackGroupCleanup(t *testing.T, group *Group) {
	t.Helper()
	if group != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if group.Stop(ctx) != nil {
				t.Error("actual rollback group cleanup failed")
			}
		})
	}
}

func assertDarwinRollbackReaped(t *testing.T, group *Group, count int) {
	t.Helper()
	if group == nil || len(group.Status()) != count {
		t.Fatal("rollback started an unexpected number of actual children")
	}
	select {
	case <-group.Done():
	default:
		t.Fatal("rollback returned before actual owned children were reaped")
	}
	for _, status := range group.Status() {
		if !status.Exited {
			t.Fatal("actual rollback child is still running")
		}
		output, truncated := group.Output(status.Role)
		if truncated || !strings.Contains(string(output), `"ready":true`) {
			t.Fatal("actual rollback child never validated its parent lifetime")
		}
	}
}

func TestDarwinPartialStartFailureReapsEarlierChild(t *testing.T) {
	p, options, images := darwinRuntimeRollbackFixture(t)
	ready := newDarwinRollbackReady(t)
	images[0].ready = ready
	options[0].Args[0] = "parent-ready"
	if images[1].close() != nil {
		t.Fatal("exact second image close control failed")
	}
	var readiness error
	hookRan := false
	deadline := time.Now().Add(2 * time.Second)
	images[1].beforeCheck = func() error {
		hookRan = true
		readiness = ready.wait(deadline)
		return readiness
	}
	before := darwinRollbackCloseCounts(images)
	group, err := p.Start(context.Background(), options, darwinRuntimeRollbackBudgets())
	darwinRollbackGroupCleanup(t, group)
	assertDarwinRollbackImagesConsumed(t, p, images, before)
	assertDarwinRollbackReadyConsumed(t, ready)
	actual := images[1].validationErr
	if !hookRan || !images[1].checked || readiness != nil || actual == nil || actual.Error() != "protected_descriptor_closed" || !errors.Is(err, actual) {
		t.Fatal("partial start did not fail after actual earlier-child readiness")
	}
	assertDarwinRollbackReaped(t, group, 1)
}

func TestDarwinCancellationDuringPartialStartupReapsOwnedChildren(t *testing.T) {
	p, options, images := darwinRuntimeRollbackFixture(t)
	ready := newDarwinRollbackReady(t)
	images[0].ready = ready
	options[0].Args[0] = "parent-ready"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var readiness error
	hookRan := false
	deadline := time.Now().Add(2 * time.Second)
	images[1].beforeCommand = func() {
		hookRan = true
		readiness = ready.wait(deadline)
		cancel()
	}
	before := darwinRollbackCloseCounts(images)
	group, err := p.Start(ctx, options, darwinRuntimeRollbackBudgets())
	darwinRollbackGroupCleanup(t, group)
	assertDarwinRollbackImagesConsumed(t, p, images, before)
	assertDarwinRollbackReadyConsumed(t, ready)
	if !hookRan || !errors.Is(err, context.Canceled) || readiness != nil {
		t.Fatal("partial startup did not retain actual cancellation after readiness")
	}
	assertDarwinRollbackReaped(t, group, 1)
}

func TestDarwinStartValidationRejectsNextImageAndReapsEarlierChildren(t *testing.T) {
	p, options, images := darwinRuntimeRollbackFixture(t)
	var ready [2]*darwinRollbackReady
	for i := range ready {
		ready[i] = newDarwinRollbackReady(t)
		images[i].ready = ready[i]
		options[i].Args[0] = "parent-ready"
	}
	var readiness error
	deadline := time.Now().Add(2 * time.Second)
	refusal := errors.New("fixture installation changed before spawn")
	rejected := images[2]
	rejected.beforeCheck = func() error {
		for _, receipt := range ready {
			if err := receipt.wait(deadline); err != nil {
				readiness = err
				return err
			}
		}
		return refusal
	}
	before := darwinRollbackCloseCounts(images)
	group, err := p.Start(context.Background(), options, darwinRuntimeRollbackBudgets())
	darwinRollbackGroupCleanup(t, group)
	assertDarwinRollbackImagesConsumed(t, p, images, before)
	for _, receipt := range ready {
		assertDarwinRollbackReadyConsumed(t, receipt)
	}
	if !errors.Is(err, refusal) || readiness != nil || !rejected.checked || rejected.validationErr != refusal {
		t.Fatal("next-image validation or owned descriptor cleanup was bypassed")
	}
	assertDarwinRollbackReaped(t, group, 2)
	if group.CleanupError() != nil {
		t.Fatal("refused start left owned descriptors open")
	}
}
