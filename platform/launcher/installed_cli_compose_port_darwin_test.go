//go:build darwin && arm64 && cgo && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"golang.org/x/sys/unix"
)

// This file owns only the Mac ARM port scenario. Existing Darwin helpers own
// installation admission, exact creator/descendant proofs and process cleanup.
// SDK26.5 netinet/tcp_fsm.h defines TCPS_LISTEN as 1. Darwin does not
// support reading SO_ACCEPTCONN; TCP_CONNECTION_INFO reports socket state.
const darwinPortTCPListenState = 1

func darwinPortSocketHeld(raw syscall.RawConn, port int) bool {
	if raw == nil {
		return false
	}
	held := false
	// The descriptor comes directly from this live owned socket; it is never
	// stored, reconstructed, closed or used to control another resource.
	err := raw.Control(func(fd uintptr) {
		address, addressErr := unix.Getsockname(int(fd))
		info, stateErr := unix.GetsockoptTCPConnectionInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_CONNECTION_INFO)
		selected, ok := address.(*unix.SockaddrInet4)
		held = addressErr == nil && stateErr == nil && info != nil && info.State == darwinPortTCPListenState && ok && selected.Port == port && selected.Addr == [4]byte{127, 0, 0, 1}
	})
	return err == nil && held
}

func darwinPortAssertHeld(t *testing.T, listener *net.TCPListener, port int) {
	t.Helper()
	raw, err := listener.SyscallConn()
	if err != nil || !darwinPortSocketHeld(raw, port) {
		t.Fatal("actual fixture blocker no longer holds the selected endpoint")
	}
}

func TestDarwinPortSocketRequiresExactListeningEndpoint(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal("native fixture socket unavailable")
	}
	unix.CloseOnExec(fd)
	file := os.NewFile(uintptr(fd), "owned-port-state-control")
	if file == nil {
		if unix.Close(fd) != nil {
			t.Error("unwrapped native fixture socket did not close")
		}
		t.Fatal("native fixture socket owner unavailable")
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			closed = true
			if file.Close() != nil {
				t.Error("owned native fixture socket did not close")
			}
		}
	})
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal("owned native fixture socket descriptor unavailable")
	}
	port := 0
	var operationErr error
	if err := raw.Control(func(fd uintptr) {
		operationErr = unix.Bind(int(fd), &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}})
		if operationErr != nil {
			return
		}
		address, readErr := unix.Getsockname(int(fd))
		if readErr != nil {
			operationErr = readErr
			return
		}
		if selected, ok := address.(*unix.SockaddrInet4); ok {
			port = selected.Port
		}
	}); err != nil || operationErr != nil || port <= 0 {
		t.Fatal("owned native socket binding failed")
	}
	if darwinPortSocketHeld(raw, port) {
		t.Fatal("bound socket became a listening blocker")
	}
	if err := raw.Control(func(fd uintptr) { operationErr = unix.Listen(int(fd), 1) }); err != nil || operationErr != nil {
		t.Fatal("owned native socket did not listen")
	}
	if !darwinPortSocketHeld(raw, port) {
		t.Fatal("exact owned listening endpoint refused")
	}
	wrongPort := port + 1
	if wrongPort > 65535 {
		wrongPort = port - 1
	}
	if darwinPortSocketHeld(raw, wrongPort) {
		t.Fatal("wrong selected port admitted")
	}
	closed = true
	if file.Close() != nil {
		t.Fatal("owned native fixture socket close failed")
	}
	// RawConn refuses callbacks after its owner closes; no numeric descriptor
	// is reused or reconstructed to query a possibly unrelated socket.
	if darwinPortSocketHeld(raw, port) {
		t.Fatal("closed socket remained an owned blocker")
	}
}

func darwinPortNoFalseReadiness(t *testing.T, f *bootstrapDockerFixture, x *composeDarwinCLIFront, r hostPolicyRecord, raw []byte, success, allowReceipt bool, attempt, name string) {
	t.Helper()
	if !x.output.joined || !x.output.captured {
		t.Fatal("occupied-port assertions require joined private output capture")
	}
	if len(raw) == 0 {
		if success {
			t.Fatal("occupied-port request succeeded without a validated response")
		}
		return
	}
	var shape map[string]json.RawMessage
	if json.Unmarshal(raw, &shape) != nil {
		t.Fatal("occupied-port output is not bounded JSON")
	}
	if encoded, exists := shape["kind"]; exists {
		var kind string
		if json.Unmarshal(encoded, &kind) != nil {
			t.Fatal("occupied-port output kind is invalid")
		}
		switch kind {
		case "bootstrap-progress":
			if !allowReceipt {
				t.Fatal("status returned startup receipt instead of a failure observation")
			}
			x.observation(t, f, r, raw, name, true)
		case "bootstrap-terminal-history":
			history, code := composeCLIFailureHistoryCode(raw, attempt, time.Now())
			if code != "" || success {
				t.Fatal("port history does not match the failed creator-bound request")
			}
			f.WriteEvidence(t, name+"-history.json", history)
		default:
			t.Fatal("occupied-port output kind is not supported")
		}
		return
	}
	var out StartupStatusObservation
	if protocol.DecodeClosedJSON(raw, &out, 64*1024) != nil || out.Disposition == "started" || out.Disposition == "reused" || (out.Disposition == "starting" && !bridgeStartingUnknown(out)) {
		t.Fatal("occupied port became false current readiness")
	}
	if success && (out.Disposition == "failed" || out.Disposition == "unconfigured") {
		t.Fatal("failed or unconfigured status returned command success")
	}
	x.observation(t, f, r, raw, name, false)
}

func TestInstalledCLIDarwinRealComposeOccupiedSelectedPort(t *testing.T) {
	f, selection, record := composeDarwinCLIEnrolledFixture(t)
	if f.Profile.Docker.Backend != NativeUnix {
		t.Fatal("native occupied-port control requires the enrolled native engine")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	before, err := f.ObserveBroker(ctx)
	cancel()
	if err != nil || before.State != "absent" {
		t.Fatal("occupied-port cold broker is not absent")
	}
	port, err := urlPort(f.Profile.NATSEndpoint)
	if err != nil {
		t.Fatal("selected native endpoint is invalid")
	}
	blocker, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal("actual selected native port blocker unavailable")
	}
	blockerClosed := false
	// Registered before frontend cleanup: the blocker survives any assertion
	// until the exact owning frontend and host have been handled.
	t.Cleanup(func() {
		if !blockerClosed {
			if blocker.Close() != nil {
				f.RetainForRecovery(t)
				t.Error("exact fixture blocker cleanup failed")
			} else {
				blockerClosed = true
			}
		}
	})
	darwinPortAssertHeld(t, blocker, port)
	x := composeDarwinCLIPrepare(t, f, selection, record, "ensure")
	x.mustOwnHost = true
	darwinScenarioStart(t, f, x, darwinScenarioEnsureBudget)
	raw, succeeded := x.wait(t, f, "darwin-occupied-port", darwinScenarioEnsureBudget)
	darwinPortAssertHeld(t, blocker, port)
	if !x.creatorOwned() {
		f.RetainForRecovery(t)
		t.Fatal("occupied-port original host proof was not established")
	}
	attempt := x.lifetime.attempt
	darwinPortNoFalseReadiness(t, f, x, record, raw, succeeded, true, attempt, "darwin-occupied-port")
	// Exact host exit and every lease release share the original startup
	// deadline. A response or PID lookup never substitutes for that proof.
	deadline := x.output.started.Add(f.Config.StartupTimeout)
	ctx, cancel = context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if x.lifetime.host.WaitExit(ctx) != nil {
		f.RetainForRecovery(t)
		t.Fatal("actual occupied-port host did not exit within startup budget")
	}
	ids := append([]string{f.Profile.Docker.EngineID, "owner-status-service"}, bootstrapFixtureRoleLeaseIDs(f.Profile.Docker.EngineID)...)
	for _, id := range ids {
		lease, err := AcquireBootstrapLock(ctx, f.Profile.ProfileDirectory, f.Profile.InstanceID, id)
		if err != nil || lease == nil {
			f.RetainForRecovery(t)
			t.Fatal("occupied-port startup retained an actual owned lease")
		}
		if lease.Close() != nil {
			f.RetainForRecovery(t)
			t.Fatal("occupied-port released lease descriptor did not close")
		}
	}
	if ctx.Err() != nil || time.Now().After(deadline) {
		f.RetainForRecovery(t)
		t.Fatal("occupied-port exit and lease checks exceeded startup budget")
	}
	cancel()
	darwinPortAssertHeld(t, blocker, port)
	status := composeDarwinCLIPrepare(t, f, selection, record, "status")
	darwinScenarioStart(t, f, status, darwinScenarioRefusalBudget)
	statusRaw, statusSucceeded := status.wait(t, f, "darwin-occupied-port-status", darwinScenarioRefusalBudget)
	if status.creatorOwned() {
		f.RetainForRecovery(t)
		t.Fatal("occupied-port status created another owning host")
	}
	darwinPortNoFalseReadiness(t, f, status, record, statusRaw, statusSucceeded, false, attempt, "darwin-occupied-port-status")
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	broker, inspectErr := f.ObserveBroker(ctx)
	cancel()
	if inspectErr != nil || broker.State != "absent" {
		f.RetainForRecovery(t)
		t.Fatal("native port preflight did not leave the selected broker absent")
	}
	ledger := composeDarwinFailurePreservation(t, f, nil, "darwin-occupied-port-resource-ledger.json")
	darwinPortAssertHeld(t, blocker, port)
	now := time.Now()
	actionable := composeFailureActionable(x.stderr.Bytes(), "port") || composeFailureActionable(status.stderr.Bytes(), "port") ||
		(!succeeded && composeFailureHistoryActionable(raw, attempt, now, "port")) ||
		(!statusSucceeded && composeFailureHistoryActionable(statusRaw, attempt, now, "port"))
	f.WriteEvidence(t, "darwin-occupied-port-result.json", map[string]any{
		"actualSelectedPortHeld": true, "exactCreatorHostExited": true, "leasesReleased": true,
		"noFalseReadiness": true, "statusCreatedHost": false, "brokerAbsent": true,
		"allAddedResourcesQualified": ledger, "unrelatedPreserved": true, "actionablePublicDiagnostic": actionable,
		"bothFrontendWaitsJoined":      x.output.joined && status.output.joined,
		"bothOutputsPrivatelyCaptured": x.output.captured && status.output.captured,
	})
	if !ledger || !actionable {
		f.RetainForRecovery(t)
		t.Fatal("occupied-port refusal lacks preservation or exact actionable proof")
	}
	f.AssertBaselineUnchanged(t)
	// Correct only this owned listener, then retry the same enrollment. The
	// prior failed attempt stays historical and does not qualify the retry.
	if blocker.Close() != nil {
		f.RetainForRecovery(t)
		t.Fatal("exact fixture blocker could not be released for retry")
	}
	blockerClosed = true
	recovered := darwinScenarioCold(t, f, selection, record, "darwin-occupied-port-corrected-retry")
	if recovered.lifetime.attempt == attempt {
		t.Fatal("corrected retry reused the failed owning attempt")
	}
	stored := darwinScenarioStored(t, f)
	stored.assertPreserved(t, f, "darwin-occupied-port-retry-resource-ledger.json")
	f.WriteEvidence(t, "darwin-occupied-port-corrected-retry.json", map[string]any{
		"sameExplicitEnrollment": true, "fixtureBlockerReleased": true, "freshCreatorProvenHost": true,
		"authenticatedCompletion": true, "exactProtectedRoleCount": len(recovered.lifetime.roles),
		"originalFailureRemainsHistorical": true,
	})
}
