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

func TestStartupCleanupRetainsOriginalCauseWithoutPublishingPrivatePath(t *testing.T) {
	startup := &os.PathError{Op: "start", Path: "/private/startup-cause-marker", Err: context.Canceled}
	failure := retainStartupCleanupCause(startup, context.DeadlineExceeded)
	if !errors.Is(failure, context.Canceled) || !errors.Is(failure, context.DeadlineExceeded) {
		t.Fatal("combined failure lost startup or cleanup cause")
	}
	var actual *os.PathError
	if !errors.As(failure, &actual) || actual != startup {
		t.Fatal("exact startup cause was not retained")
	}
	for _, value := range []any{failure, *failure.(*startupCleanupCause)} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if strings.Contains(fmt.Sprintf(format, value), "startup-cause-marker") {
				t.Fatal("combined failure published private startup details")
			}
		}
		raw, err := json.Marshal(value)
		if err != nil || strings.Contains(string(raw), "startup-cause-marker") {
			t.Fatal("combined failure JSON published private startup details")
		}
	}
}
