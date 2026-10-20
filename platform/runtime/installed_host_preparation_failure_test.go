//go:build linux || darwin

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestInstalledHostPreparationRetainsCleanupAndSafePresentation(t *testing.T) {
	original := &os.PathError{Op: "close", Path: "/private/installed-host-marker", Err: context.DeadlineExceeded}
	for _, cleanup := range []bool{false, true} {
		var cause error = original
		if cleanup {
			cause = retainStartupCleanupCause(context.Canceled, original)
		}
		failure := installedHostPreparationFailure(cause)
		if errors.Is(failure, ErrStartupCleanup) != cleanup || !errors.Is(failure, context.DeadlineExceeded) {
			t.Fatal("protected installed-host admission lost original cleanup category")
		}
		var actual *os.PathError
		if !errors.As(failure, &actual) || actual != original {
			t.Fatal("exact original image cause was lost")
		}
		for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
			if fmt.Sprintf(format, failure) != "installed_host_protected_image_invalid" {
				t.Fatal("protected admission exposed its cause")
			}
		}
		raw, err := json.Marshal(failure)
		if err != nil || strings.Contains(string(raw), "private") || string(raw) != `"installed_host_protected_image_invalid"` {
			t.Fatal("protected admission JSON exposed its cause")
		}
	}
}

func TestInstalledHostImageCloseRetainsConsumedFailure(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "private-installed-image-")
	if err != nil {
		t.Fatal("owned close control unavailable")
	}
	if file.Close() != nil {
		t.Fatal("owned close control failed")
	}
	backend := &preparedCleanupImage{file: file}
	image := &InstalledHostImage{image: backend}
	failure := image.Close()
	var actual *os.PathError
	if !errors.Is(failure, ErrStartupCleanup) || !errors.Is(failure, os.ErrClosed) || !errors.As(failure, &actual) || actual.Path != file.Name() {
		t.Fatal("installed image close lost its actual consumed-descriptor cause")
	}
	if image.Close() != failure || backend.calls != 1 || image.image != nil || !image.consumed {
		t.Fatal("repeated close retried disposal or concealed the original failure")
	}
	for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
		if fmt.Sprintf(format, failure) != "installed_host_snapshot_close_failed" {
			t.Fatal("installed image close exposed private cause")
		}
	}
	raw, err := json.Marshal(failure)
	if err != nil || string(raw) != `"installed_host_snapshot_close_failed"` {
		t.Fatal("installed image close JSON exposed private cause")
	}
}
