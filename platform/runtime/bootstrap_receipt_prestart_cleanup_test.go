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

// Faults pre-close concrete real pipe files. No production closer callback,
// injected authority or numeric descriptor retry is introduced.
func TestBootstrapReceiptPrestartCleanupRetainsBothCloseCauses(t *testing.T) {
	for _, fault := range []string{"none", "reader", "writer", "both"} {
		t.Run(fault, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal("real pipe unavailable")
			}
			// Cleanup owns only these os.File objects; repeated Close cannot adopt a
			// reused descriptor because os.File invalidates the object on first Close.
			t.Cleanup(func() { reader.Close(); writer.Close() })
			startup := errors.New("private original startup /fixture/path password")
			if fault == "reader" || fault == "both" {
				if reader.Close() != nil {
					t.Fatal("reader fault setup failed")
				}
			}
			if fault == "writer" || fault == "both" {
				if writer.Close() != nil {
					t.Fatal("writer fault setup failed")
				}
			}
			failure := closeReceiptBeforeStart(reader, writer, startup)
			if _, err := reader.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("reader close not attempted")
			}
			if _, err := writer.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("writer close not attempted")
			}
			if !errors.Is(failure, startup) {
				t.Fatal("original startup cause discarded")
			}
			if fault == "none" {
				if failure != startup {
					t.Fatal("successful closes changed original error identity")
				}
				return
			}
			if !errors.Is(failure, os.ErrClosed) {
				t.Fatal("actual pre-start close failure discarded")
			}
			joined, ok := errors.Unwrap(failure).(interface{ Unwrap() []error })
			if !ok {
				t.Fatal("concrete close ancestry absent")
			}
			closeCauses := map[string]bool{}
			for _, cause := range joined.Unwrap() {
				if e, ok := cause.(*os.PathError); ok && errors.Is(e, os.ErrClosed) {
					closeCauses[e.Path] = true
				}
			}
			expected := 1
			if fault == "both" {
				expected = 2
			}
			if len(closeCauses) != expected {
				t.Fatal("both distinct concrete close causes not retained")
			}
			for _, format := range []string{"%v", "%+v", "%#v"} {
				if got := fmt.Sprintf(format, failure); got != "bootstrap_receipt_cleanup_failed" {
					t.Fatal("private cause exposed in formatting")
				}
			}
			encoded, err := json.Marshal(failure)
			if err != nil || string(encoded) != `"bootstrap_receipt_cleanup_failed"` {
				t.Fatal("private cause exposed in JSON")
			}
		})
	}
}

func TestBootstrapReceiptPrestartCleanupSafeValueAndPointer(t *testing.T) {
	cause := errors.New("private path password")
	value := receiptPrestartCleanupCause{cause: cause}
	for _, e := range []error{value, &value} {
		if !errors.Is(e, cause) {
			t.Fatal("original cause missing")
		}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, e), "private") {
				t.Fatal("cause exposed")
			}
		}
		raw, err := json.Marshal(e)
		if err != nil || strings.Contains(string(raw), "private") {
			t.Fatal("cause serialized")
		}
	}
}

func TestBootstrapReceiptGenuinePrestartCancellationPreservesOriginalCode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	binding := receiptTestBinding()
	var image *InstalledHostImage
	child, err := image.StartHostWithBootstrapReceipt(ctx, HostInvocation{InvocationID: binding.ColdInvocationID}, binding)
	if child != nil || err == nil || err.Error() != "installed_host_start_cancelled" {
		t.Fatal("real pre-start cancellation changed")
	}
}
