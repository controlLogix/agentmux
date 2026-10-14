//go:build linux || darwin

package launcher

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	protected "github.com/controlLogix/agentmux/platform/runtime"
	"golang.org/x/sys/unix"
)

func receiptPipeFixture(t *testing.T) (*os.File, func()) {
	t.Helper()
	reader, original, err := os.Pipe()
	if err != nil {
		t.Fatal("private receipt pipe unavailable")
	}
	fd, err := unix.FcntlInt(original.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	original.Close()
	if err != nil {
		reader.Close()
		t.Fatal("private writer duplication failed")
	}
	t.Setenv("AGENTMUX_BOOTSTRAP_RECEIPT_FD", strconv.Itoa(fd))
	owned := true
	t.Cleanup(func() {
		if owned {
			if err := unix.Close(fd); err != nil {
				t.Error("pre-adoption writer cleanup failed")
			}
		}
		reader.Close()
	})
	// Transfer only after successful adoption. Cleanup never closes a numeric
	// descriptor after the concrete writer has taken it (and may have closed it).
	return reader, func() { owned = false }
}
func receiptServerBinding(server *OwnerBridgeServer, id string) protected.BootstrapReceiptBinding {
	raw := mustStatusJSON(server.enrollment.Owner)
	sum := sha256.Sum256(raw)
	return protected.BootstrapReceiptBinding{Scope: server.config.Kernel.Scope, EnrollmentDigest: "sha256:" + hex.EncodeToString(sum[:]), ColdInvocationID: id, RuntimeDigest: "sha256:" + strings.Repeat("a", 64)}
}
func attachReceiptFixture(t *testing.T, server *OwnerBridgeServer, id string) *os.File {
	t.Helper()
	reader, transfer := receiptPipeFixture(t)
	binding := receiptServerBinding(server, id)
	writer, err := protected.OpenBootstrapReceiptWriter(binding)
	if err != nil {
		t.Fatal("actual inherited writer rejected")
	}
	transfer()
	server.receipt = &ownerBridgeReceiptState{writer: writer, binding: binding}
	t.Cleanup(func() {
		if writer.Close() != nil {
			t.Error("owned writer cleanup failed")
		}
	})
	return reader
}
func readReceiptFrame(t *testing.T, reader *os.File) protected.BootstrapControlReceipt {
	t.Helper()
	if reader.SetReadDeadline(time.Now().Add(time.Second)) != nil {
		t.Fatal("receipt read deadline unavailable")
	}
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		t.Fatal("actual control receipt missing")
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > 4092 {
		t.Fatal("control receipt length invalid")
	}
	raw := make([]byte, length)
	if _, err := io.ReadFull(reader, raw); err != nil {
		t.Fatal("control receipt truncated")
	}
	var frame protected.BootstrapControlReceipt
	if json.Unmarshal(raw, &frame) != nil || frame.Kind != "bootstrap-control-receipt" {
		t.Fatal("control receipt malformed")
	}
	return frame
}
func assertNoReceipt(t *testing.T, reader *os.File) {
	t.Helper()
	reader.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	var byte [1]byte
	if n, err := reader.Read(byte[:]); n != 0 || err == nil {
		t.Fatal("unqualified receipt emitted")
	}
	reader.SetReadDeadline(time.Time{})
}

func TestOwnerBridgeReceiptRequiresFreshEnteredOwner(t *testing.T) {
	for _, fault := range []string{"not_entered", "owner_revoked", "profile_changed", "binding"} {
		t.Run(fault, func(t *testing.T) {
			op, f, _, _, _ := pendingOperationFixture(t)
			reader := attachReceiptFixture(t, op.server, op.attemptID)
			if fault != "not_entered" && op.enter(op.startup, f.config, f.profile, op.attemptID) != nil {
				t.Fatal("actual component admission rejected")
			}
			switch fault {
			case "owner_revoked":
				owner := f.enrollment.Owner
				owner.Identity.Revision++
				writeOwnerFixture(t, f.profile.ProfileDirectory, mustStatusJSON(owner))
			case "profile_changed":
				profile := f.profile
				profile.DisplayName = "changed owner profile"
				releaseTestWrite(t, profile.ProfileDirectory, "profile.json", mustStatusJSON(profile))
			case "binding":
				op.server.receipt.binding.ColdInvocationID = "attempt_" + strings.Repeat("b", 32)
			}
			if err := op.emitBootstrapAccepted(op.startup); err == nil {
				t.Fatal("unqualified entry accepted")
			}
			assertNoReceipt(t, reader)
			op.server.receipt.mu.Lock()
			attempted := op.server.receipt.attempted
			op.server.receipt.mu.Unlock()
			if attempted {
				t.Fatal("admission refusal consumed an accepted frame")
			}
		})
	}
}

func TestOwnerBridgeReceiptAcceptedOnceThenEOF(t *testing.T) {
	op, f, _, _, _ := pendingOperationFixture(t)
	reader := attachReceiptFixture(t, op.server, op.attemptID)
	if op.enter(op.startup, f.config, f.profile, op.attemptID) != nil {
		t.Fatal("actual component admission rejected")
	}
	if op.emitBootstrapAccepted(op.startup) != nil {
		t.Fatal("qualified component receipt rejected")
	}
	frame := readReceiptFrame(t, reader)
	if frame.Outcome != "accepted" || frame.Binding != op.server.receipt.binding {
		t.Fatal("receipt binding or historical entry outcome changed")
	}
	if op.emitBootstrapAccepted(op.startup) != nil {
		t.Fatal("repeat hook changed bootstrap success")
	}
	cause := errors.New("actual_stop")
	if op.server.finishBootstrapReceipt(op.startup, cause) != cause {
		t.Fatal("receipt cleanup changed actual outcome")
	}
	if reader.SetReadDeadline(time.Now().Add(time.Second)) != nil {
		t.Fatal("EOF deadline unavailable")
	}
	var byte [1]byte
	if n, err := reader.Read(byte[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatal("one-shot writer emitted another frame or retained descriptor")
	}
}

func TestInstalledReceiptServerFactoryAndPreAdmissionFailure(t *testing.T) {
	selection, _ := installedBridgePolicyFixture(t)
	host, err := LoadEnrolledHostPolicy(selection)
	if err != nil {
		t.Fatal("actual installed policy rejected")
	}
	reader, transfer := receiptPipeFixture(t)
	id := "attempt_" + strings.Repeat("c", 32)
	server, _, err := host.BridgeServerForInvocation(id)
	if err == nil {
		transfer()
	}
	if err != nil || server.receipt == nil {
		t.Fatal("actual installed inherited factory rejected", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	cancel()
	if err := server.Run(ctx, ctx, id); err == nil {
		t.Fatal("cancelled bootstrap accepted")
	}
	frame := readReceiptFrame(t, reader)
	if frame.Outcome != "failed" || frame.Binding.ColdInvocationID != id {
		t.Fatal("actual pre-admission failure became acceptance or contention")
	}
	if n, err := reader.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatal("failed Run retained writer")
	}
}

func TestOwnerBridgeJoinedCompletionRetainsExactCleanupCause(t *testing.T) {
	op, _, _, _, cancelLifetime := pendingOperationFixture(t)
	dialer, socket, peer := actualCleanupSocket(t)
	failExactSocketClose(t, socket)
	actual, failed := closeOwnedTransport(dialer, nil, "owner_bridge_owned_connection_cleanup_failed")
	if !failed {
		t.Fatal("actual owned close negative did not fail")
	}
	if op.complete(nil, actual) != nil {
		t.Fatal("actual failed completion not retained")
	}
	cancelLifetime()
	session, result := joinedBridgeBootstrapResult(op, nil)
	if session != nil || result == nil || !errors.Is(result, ErrTransportCleanup) {
		t.Fatal("nil Session completion lost cleanup ownership")
	}
	var retained *TransportCleanupError
	if !errors.As(result, &retained) || retained.dialer != dialer {
		t.Fatal("joined completion changed exact cleanup handle")
	}
	for _, value := range []error{result, *result.(*bridgeCompletionCause)} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if fmt.Sprintf(format, value) != "owner_bridge_owned_connection_cleanup_failed" {
				t.Fatal("completion formatting exposed owner or cause")
			}
		}
		raw, err := json.Marshal(value)
		if err != nil || string(raw) != `"owner_bridge_owned_connection_cleanup_failed"` {
			t.Fatal("completion JSON exposed cause")
		}
	}
	_, withPrimary := joinedBridgeBootstrapResult(op, bridgeError("startup_failed"))
	if withPrimary.Error() != "owner_bridge_startup_failed" || !errors.As(withPrimary, &retained) {
		t.Fatal("primary code or completed ownership changed")
	}
	if retained.Close() != nil {
		t.Fatal("exact joined cleanup retry failed")
	}
	select {
	case err := <-peer:
		if !errors.Is(err, io.EOF) {
			t.Fatal("owned peer did not reach EOF")
		}
	case <-time.After(time.Second):
		t.Fatal("actual joined cleanup peer not closed")
	}
	unsafe := bridgeCompletionCause{code: "private/path/password", cause: errors.New("private cause")}
	if unsafe.Error() != "owner_bridge_startup_failed" || strings.Contains(fmt.Sprintf("%#v", unsafe), "private") {
		t.Fatal("plain completion disclosed details")
	}
}

func TestOwnerBridgeReceiptFixtureClosesBeforeAdoption(t *testing.T) {
	var fd int
	var before unix.Stat_t
	t.Run("factory_not_reached", func(t *testing.T) {
		_, _ = receiptPipeFixture(t)
		var err error
		fd, err = strconv.Atoi(os.Getenv("AGENTMUX_BOOTSTRAP_RECEIPT_FD"))
		if err != nil || unix.Fstat(fd, &before) != nil {
			t.Fatal("owned unadopted writer unavailable")
		}
		// The registered fixture cleanup must close this original descriptor even
		// when admission/Opening is never reached; no receiver owns it yet.
	})
	var after unix.Stat_t
	if unix.Fstat(fd, &after) == nil && after.Dev == before.Dev && after.Ino == before.Ino {
		t.Fatal("unadopted duplicate writer leaked")
	}
}
