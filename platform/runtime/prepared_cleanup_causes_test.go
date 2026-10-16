package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

// Use the existing private executable seam around an actual owned descriptor.
type preparedCleanupImage struct {
	file  *os.File
	cause error
	calls int
}

func (*preparedCleanupImage) command([]string) *exec.Cmd {
	panic("cleanup must not create a command")
}

func (e *preparedCleanupImage) close() error {
	e.calls++
	return errors.Join(e.file.Close(), e.cause)
}

func assertPreparedCleanupPresentation(t *testing.T, failure error) {
	t.Helper()
	if failure == nil {
		t.Fatal("cleanup failure was discarded")
	}
	if !errors.Is(failure, ErrStartupCleanup) {
		t.Fatal("cleanup failure lost its public error category")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		if got := fmt.Sprintf(format, failure); got != "startup failed; owned cleanup incomplete" {
			t.Fatal("cleanup presentation exposed private details")
		}
	}
	encoded, err := json.Marshal(failure)
	if err != nil || string(encoded) != `"startup failed; owned cleanup incomplete"` {
		t.Fatal("cleanup JSON exposed private details")
	}
}

func TestPreparedCleanupRetainsEveryCauseAndConsumesOnce(t *testing.T) {
	p := &Prepared{}
	t.Cleanup(func() { p.Close() })
	var images [4]*preparedCleanupImage
	for i := range images {
		file, err := os.CreateTemp(t.TempDir(), "private-cleanup-")
		if err != nil {
			t.Fatal("owned cleanup file unavailable")
		}
		images[i] = &preparedCleanupImage{file: file, cause: &os.PathError{
			Op: "close", Path: file.Name(), Err: errors.New("private-cleanup-cause"),
		}}
		p.images[i] = images[i]
	}
	failure := p.Close()
	assertPreparedCleanupPresentation(t, failure)
	for i, image := range images {
		if !errors.Is(failure, image.cause) || !errors.Is(failure, image.cause.(*os.PathError).Err) {
			t.Fatal("an exact cleanup cause was discarded")
		}
		if _, err := image.file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("owned descriptor was not closed")
		}
		if image.calls != 1 || p.images[i] != nil || !p.consumed {
			t.Fatal("image ownership was not consumed once")
		}
	}
	var actual *os.PathError
	if !errors.As(failure, &actual) || actual != images[0].cause {
		t.Fatal("exact typed cleanup cause was discarded")
	}
	if strings.Contains(failure.Error(), "private-cleanup") {
		t.Fatal("private cleanup details were published")
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := p.Close(); err != nil {
				t.Error("consumed cleanup was retried")
			}
		}()
	}
	workers.Wait()
	for _, image := range images {
		if image.calls != 1 {
			t.Fatal("owned descriptor close was retried")
		}
	}
}

func TestPreparedCleanupWithoutFailure(t *testing.T) {
	var absent *Prepared
	if absent.Close() != nil || (&Prepared{}).Close() != nil {
		t.Fatal("empty cleanup reported a failure")
	}
	file, err := os.CreateTemp(t.TempDir(), "owned-cleanup-")
	if err != nil {
		t.Fatal("owned cleanup file unavailable")
	}
	image := &preparedCleanupImage{file: file}
	p := &Prepared{images: [4]executable{image}}
	t.Cleanup(func() { p.Close() })
	if p.Close() != nil || p.Close() != nil || image.calls != 1 {
		t.Fatal("successful cleanup did not consume ownership once")
	}
}

func TestPreparedCleanupCategoryRetainsActualDescriptorAndStartupCauses(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "private-category-cleanup-")
	if err != nil {
		t.Fatal("owned cleanup file unavailable")
	}
	image := &preparedCleanupImage{file: file}
	p := &Prepared{images: [4]executable{image}}
	t.Cleanup(func() { p.Close() })
	// Close only the exact file this test owns; its owner reports the real fault.
	if err := file.Close(); err != nil {
		t.Fatal("owned descriptor fault setup failed")
	}
	cleanup := p.Close()
	assertPreparedCleanupPresentation(t, cleanup)
	var descriptorCause *os.PathError
	if !errors.As(cleanup, &descriptorCause) || descriptorCause.Path != file.Name() || !errors.Is(cleanup, os.ErrClosed) {
		t.Fatal("actual descriptor close cause was discarded")
	}
	startup := &os.PathError{Op: "start", Path: "/private/category-startup", Err: context.Canceled}
	failure := retainStartupCleanupCause(startup, cleanup)
	for _, value := range []error{failure, *failure.(*startupCleanupCause)} {
		assertPreparedCleanupPresentation(t, value)
		for _, cause := range []error{startup, context.Canceled, cleanup, descriptorCause, os.ErrClosed} {
			if !errors.Is(value, cause) {
				t.Fatal("category classification lost an original cause")
			}
		}
		var actual *os.PathError
		if !errors.As(value, &actual) || actual != startup {
			t.Fatal("category classification changed the exact typed startup cause")
		}
	}
	if errors.Is(startup, ErrStartupCleanup) || errors.Is(descriptorCause, ErrStartupCleanup) {
		t.Fatal("an unclassified error acquired the cleanup category")
	}
	if image.calls != 1 || p.images[0] != nil || p.Close() != nil || image.calls != 1 {
		t.Fatal("category control retried consumed cleanup")
	}
}
