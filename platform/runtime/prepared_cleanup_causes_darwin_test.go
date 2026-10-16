//go:build darwin && cgo

package runtime

import (
	"errors"
	"os"
	"testing"
)

func TestPreparedCleanupDarwinRetainsEveryDescriptorCause(t *testing.T) {
	image := &protectedDarwinExecutable{}
	p := &Prepared{images: [4]executable{image}}
	t.Cleanup(func() { p.Close() })
	var files []*os.File
	for range 3 {
		file, err := os.CreateTemp(t.TempDir(), "private-darwin-cleanup-")
		if err != nil {
			t.Fatal("owned Darwin cleanup file unavailable")
		}
		image.files = append(image.files, file)
		files = append(files, file)
	}
	// Fault only descriptors this test acquired, using their actual owners.
	for _, file := range files[:2] {
		if err := file.Close(); err != nil {
			t.Fatal("owned descriptor fault setup failed")
		}
	}
	failure := p.Close()
	assertPreparedCleanupPresentation(t, failure)
	if !errors.Is(failure, os.ErrClosed) {
		t.Fatal("actual descriptor close failure was discarded")
	}
	seen := map[string]bool{}
	var visit func(error)
	visit = func(err error) {
		if path, ok := err.(*os.PathError); ok {
			seen[path.Path] = true
		}
		switch cause := err.(type) {
		case interface{ Unwrap() []error }:
			for _, child := range cause.Unwrap() {
				visit(child)
			}
		case interface{ Unwrap() error }:
			visit(cause.Unwrap())
		}
	}
	visit(failure)
	if len(seen) != 2 || !seen[files[0].Name()] || !seen[files[1].Name()] {
		t.Fatal("an actual Darwin descriptor close cause was discarded")
	}
	if _, err := files[2].Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("later owned Darwin descriptor was not closed")
	}
	if len(image.files) != 0 || p.Close() != nil || image.close() != nil {
		t.Fatal("Darwin descriptor ownership was not consumed once")
	}
}
