//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestKernelStatusStageRetainsSafeCause(t *testing.T) {
	cause := &TransportCleanupError{cause: errKernelStatusAuthority, code: "kernel_status_owned_connection_cleanup_failed"}
	for _, value := range []error{kernelStatusStageError{"snapshot", cause}, &kernelStatusStageError{"snapshot", cause}} {
		if value.Error() != cause.Error() || !errors.Is(value, ErrTransportCleanup) || !IsKernelStatusAuthorityError(value) {
			t.Fatal("stage changed outward cause")
		}
		var retained *TransportCleanupError
		if !errors.As(value, &retained) || retained != cause {
			t.Fatal("concrete cleanup ownership lost")
		}
		var stage interface{ inspectionStage() string }
		if !errors.As(value, &stage) || stage.inspectionStage() != "snapshot" {
			t.Fatal("closed diagnostic stage unavailable")
		}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if fmt.Sprintf(format, value) != cause.Error() {
				t.Fatal("stage formatting exposed fields")
			}
		}
		raw, err := json.Marshal(value)
		if err != nil || string(raw) != `"kernel_status_owned_connection_cleanup_failed"` {
			t.Fatal("stage JSON exposed fields")
		}
	}
	unknown := kernelStatusStageError{"private/path", errors.New("password/private/path")}
	if unknown.Error() != "kernel_status_invalid" || unknown.inspectionStage() != "" || strings.Contains(fmt.Sprintf("%#v", unknown), "private") {
		t.Fatal("unknown diagnostic exposed private data")
	}
}

func TestKernelStatusStageActualSnapshotTimeout(t *testing.T) {
	f := newBridgeFixture(t)
	f.startBroker(t)
	// No protected actors publish snapshots. The broker still completes real
	// pinned TLS and authenticated ordinary-account subscription.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, proof, err := inspectLocalBrokerOperation(ctx, f.config)
	if err != nil {
		t.Fatal("actual private authority proof unavailable", err)
	}
	o := f.config.Kernel
	o.Timeout = 200 * time.Millisecond
	_, err = observeKernelWithProof(ctx, o, proof)
	var stage interface{ inspectionStage() string }
	if err == nil || !errors.As(err, &stage) || stage.inspectionStage() != "snapshot" || err.Error() != "kernel_status_unavailable" {
		t.Fatal("actual snapshot deadline stage incorrect", err)
	}
}

func TestKernelStatusStageAuthorityDenial(t *testing.T) {
	f := newBridgeFixture(t)
	o := f.config.Kernel
	o.Scope.HubID += "_other"
	_, err := ObserveKernel(context.Background(), o)
	var stage interface{ inspectionStage() string }
	if !IsKernelStatusAuthorityError(err) || !errors.As(err, &stage) || stage.inspectionStage() != "authority_inspection" {
		t.Fatal("authority stage lost hard denial", err)
	}
}
