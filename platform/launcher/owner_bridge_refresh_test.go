//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
)

func TestOwnerBridgeRefreshUsesOneActualBrokerInspection(t *testing.T) {
	f := newBridgeFixture(t)
	f.startBroker(t)
	f.startActors(t)
	if _, err := deployment.ProvisionAndProbe(context.Background(), f.config.Health); err != nil {
		t.Fatal("actual FILE health fixture unavailable", err)
	}
	server, err := LoadOwnerBridgeServer(f.config, f.owner, f.enrollment)
	if err != nil {
		t.Fatal("actual enrolled bridge unavailable", err)
	}
	audit := proofAudit(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	id := "attempt_0123456789abcdef0123456789abcdef"
	out, err := server.refresh(ctx, id, nil, nil)
	if err != nil || out.Disposition != "reused" || out.StartupAttemptID == nil || *out.StartupAttemptID != id {
		t.Fatal("fresh actual owner refresh unavailable", err)
	}
	count, err := os.ReadFile(audit)
	if err != nil || string(count) != "archive\narchive\narchive\n" {
		t.Fatal("owner refresh repeated complete broker inspection")
	}
	// A subsequent operation must inspect again rather than use any cached proof.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if _, err := server.refresh(ctx2, id, nil, nil); err != nil {
		t.Fatal("separate actual owner refresh unavailable", err)
	}
	count, err = os.ReadFile(audit)
	if err != nil || string(count) != "archive\narchive\narchive\narchive\narchive\narchive\n" {
		t.Fatal("owner refresh cached authority across operations")
	}
}

func TestOwnerBridgeObservationCleanupRetainsBothActualSocketOwners(t *testing.T) {
	healthDialer, healthSocket, healthPeer := actualCleanupSocket(t)
	kernelDialer, kernelSocket, kernelPeer := actualCleanupSocket(t)
	failExactSocketClose(t, healthSocket)
	failExactSocketClose(t, kernelSocket)
	if healthDialer.Close() == nil || kernelDialer.Close() == nil {
		t.Fatal("actual first socket close failure unavailable")
	}
	// Both concrete errors own independently opened real sockets. This is a
	// combined-cause helper control, not a forced public health/kernel fault.
	one := &TransportCleanupError{dialer: healthDialer, code: "kernel_status_owned_connection_cleanup_failed"}
	two := &TransportCleanupError{dialer: kernelDialer, cause: context.Canceled, code: "kernel_status_owned_connection_cleanup_failed"}
	failure := bridgeObservationCleanupFailure(one, two)
	var retained *TransportCleanupError
	if failure == nil || !errors.As(failure, &retained) || retained != one || !errors.Is(failure, two) || !errors.Is(failure, context.Canceled) {
		t.Fatal("observation cleanup discarded actual retry owners")
	}
	for _, value := range []any{failure, *failure.(*bridgeCompletionCause)} {
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			if fmt.Sprintf(verb, value) != "owner_bridge_owned_connection_cleanup_failed" {
				t.Fatal("observation cleanup presentation exposed causes")
			}
		}
		raw, err := json.Marshal(value)
		if err != nil || string(raw) != `"owner_bridge_owned_connection_cleanup_failed"` {
			t.Fatal("observation cleanup JSON exposed causes")
		}
	}
	for _, owner := range []*TransportCleanupError{one, two} {
		if owner.Close() != nil {
			t.Fatal("exact observation owner retry failed")
		}
	}
	for _, peer := range []<-chan error{healthPeer, kernelPeer} {
		select {
		case err := <-peer:
			if err != io.EOF {
				t.Fatal("actual cleanup peer EOF absent")
			}
		case <-time.After(time.Second):
			t.Fatal("actual cleanup peer did not join")
		}
	}
	if bridgeObservationCleanupFailure(context.DeadlineExceeded) != nil {
		t.Fatal("ordinary unavailable observation became fatal cleanup")
	}
}
