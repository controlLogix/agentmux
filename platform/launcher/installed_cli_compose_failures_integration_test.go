//go:build linux && agentmux_bootstrap_docker

package launcher

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"golang.org/x/sys/unix"
)

// These cases cover conflicting child environment selection and an occupied
// selected engine port. They do not qualify every wrong declared context.
func composeFailureWait(t *testing.T, f *bootstrapDockerFixture, x *composeCLIFront, s HostPolicySelection, r hostPolicyRecord) ([]byte, bool) {
	t.Helper()
	budget := 10 * time.Second
	if len(x.cmd.Args) > 1 && x.cmd.Args[1] == "status" {
		budget = 5 * time.Second
	}
	deadline := x.started.Add(budget)
	for {
		x.pinHost(s, r)
		select {
		case result := <-x.done:
			x.joined = true
			composeCLICaptureJoined(t, f, x)
			f.WriteEvidence(t, x.captureName+"-joined-diagnostic.json", composeCLIJoinedDiagnostic(x, result))
			if result.at.Sub(x.started) > budget {
				t.Fatal("negative frontend exceeded its original request budget")
			}
			return append([]byte(nil), x.stdout.Bytes()...), result.err == nil
		default:
		}
		if !time.Now().Before(deadline) {
			t.Fatal("negative frontend did not exit within its request budget")
		}
		time.Sleep(time.Millisecond)
	}
}

func composeFailureLeases(t *testing.T, f *bootstrapDockerFixture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ids := append([]string{f.Profile.Docker.EngineID, "owner-status-service"}, bootstrapFixtureRoleLeaseIDs(f.Profile.Docker.EngineID)...)
	for _, id := range ids {
		lease, err := AcquireBootstrapLock(ctx, f.Profile.ProfileDirectory, f.Profile.InstanceID, id)
		if err != nil {
			f.RetainForRecovery(t)
			t.Fatal("negative startup left an actual owned lease held")
		}
		if lease.Close() != nil {
			t.Fatal("negative startup lease control did not close")
		}
	}
}

func composeFailurePreservation(t *testing.T, f *bootstrapDockerFixture, qualified *OwnedBroker, name string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	containers, err := f.inventory(ctx)
	if err != nil {
		f.RetainForRecovery(t)
		t.Fatal("negative startup complete container roster unavailable")
	}
	networks, err := f.networkInventory(ctx)
	if err != nil {
		f.RetainForRecovery(t)
		t.Fatal("negative startup complete network roster unavailable")
	}
	containersUnchanged, networksUnchanged, allQualified, addedRunning := true, true, true, false
	for id, before := range f.baseline {
		after, present := containers[id]
		containersUnchanged = containersUnchanged && present && reflect.DeepEqual(before, after)
	}
	for id, before := range f.networkBaseline {
		after, present := networks[id]
		networksUnchanged = networksUnchanged && present && reflect.DeepEqual(before, after)
	}
	addedContainers, addedNetworks := []map[string]any{}, []map[string]any{}
	for id, current := range containers {
		if _, original := f.baseline[id]; original {
			continue
		}
		verified := qualified != nil && qualified.ContainerID == id && qualified.State == current.State
		allQualified = allQualified && verified
		addedRunning = addedRunning || current.State == "running"
		addedContainers = append(addedContainers, map[string]any{"containerId": id, "state": current.State, "qualifiedByFullBrokerInspection": verified})
	}
	for id, current := range networks {
		if _, original := f.networkBaseline[id]; original {
			continue
		}
		// This provenance is minted only by the fixture's full selected broker
		// inspection plus exact creation and attachment admission, not labels.
		pin := f.networkProvenance
		verified := qualified != nil && pin != nil && pin.containerID == qualified.ContainerID && pin.network.ID == id && sameBootstrapNetworkIdentity(pin.network, current) && validBootstrapCounterTransition(pin.network, current, qualified.ContainerID)
		if verified {
			attachments, attachmentErr := f.networkAttachments(ctx, qualified.ContainerID)
			if attachmentErr != nil {
				verified = false
			} else if qualified.State == "running" {
				attachment, present := attachments[current.Name]
				verified = len(current.Endpoints) == 1 && current.Endpoints[qualified.ContainerID] == pin.endpointID && pin.endpointID != "" && len(attachments) == 1 && present && attachment.NetworkID == id && attachment.EndpointID == pin.endpointID
			} else {
				verified = validBootstrapStoppedNetwork(pin, f.networkBaseline, f.Owner, qualified.ContainerID, qualified.State, current, attachments)
			}
		}
		allQualified = allQualified && verified
		addedNetworks = append(addedNetworks, map[string]any{"networkId": id, "digest": current.Digest, "liveEndpointCount": len(current.Endpoints), "qualifiedCreationRelation": verified})
	}
	f.WriteEvidence(t, name, map[string]any{"scope": "Complete container and network rosters; selected volume checked separately where present", "originalContainersUnchanged": containersUnchanged, "originalNetworksUnchanged": networksUnchanged, "addedContainers": addedContainers, "addedNetworks": addedNetworks, "allAddedResourcesQualified": allQualified, "anyAddedContainerRunning": addedRunning, "readOnlyLedger": true})
	if !allQualified || !containersUnchanged || !networksUnchanged {
		f.RetainForRecovery(t)
	}
	if !containersUnchanged || !networksUnchanged {
		t.Fatal("negative startup changed an original baseline resource")
	}
	return allQualified && (!addedRunning || (qualified != nil && qualified.State == "running"))
}

func TestInstalledCLIRealComposeConflictingChildSelection(t *testing.T) {
	for _, key := range []string{"DOCKER_CONTEXT", "DOCKER_HOST"} {
		t.Run(key, func(t *testing.T) {
			f := newBootstrapDockerFixtureWithHost(t, true)
			s, r := composeCLIPolicy(t, f)
			x := composeCLIPrepare(t, f, s, r, "ensure")
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "DOCKER_CONTEXT=") && !strings.HasPrefix(entry, "DOCKER_HOST=") {
					x.cmd.Env = append(x.cmd.Env, entry)
				}
			}
			value := "agentmux_unselected_" + bootstrapFixtureRandom(t, 4)
			if key == "DOCKER_HOST" {
				value = "unix:///agentmux-unselected-engine.sock"
			}
			x.cmd.Env = append(x.cmd.Env, key+"="+value)
			if x.launch() != nil {
				t.Fatal("actual negative frontend start failed")
			}
			raw, success := composeFailureWait(t, f, x, s, r)
			if success || x.hostFD >= 0 || len(raw) != 0 {
				t.Fatal("conflicting child selection started or attached a host")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			broker, err := f.ObserveBroker(ctx)
			cancel()
			if err != nil || broker.State != "absent" {
				t.Fatal("conflicting child selection created a stack")
			}
			composeFailureLeases(t, f)
			if !composeFailurePreservation(t, f, nil, "conflicting-selection-ledger.json") {
				t.Fatal("conflicting selection left unverified added resources")
			}
			actionable := composeFailureActionable(x.stderr.Bytes(), "selection")
			f.WriteEvidence(t, "conflicting-selection-result.json", map[string]any{"conflictingChildVariable": key, "frontendRefused": true, "createdHost": false, "brokerAbsent": true, "leasesReleased": true, "unrelatedPreserved": true, "actionablePublicDiagnostic": actionable})
			if !actionable {
				t.Fatal("actual conflicting-selection refusal lacks an actionable public diagnostic")
			}
		})
	}
}

// Occupy the actual selected engine host endpoint, not the WSL-only loopback.
// The Windows helper is our exact process, held by stdin lifetime and one Wait.
func composeFailureOccupyPort(t *testing.T, f *bootstrapDockerFixture) func() {
	t.Helper()
	port, err := urlPort(f.Profile.NATSEndpoint)
	if err != nil {
		t.Fatal("selected fixture port unavailable")
	}
	if f.Profile.Docker.Backend == NativeUnix {
		if bootstrapActualHost().WSL {
			t.Fatal("native loopback cannot prove selected WSL engine occupancy")
		}
		listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			t.Fatal("actual selected native port blocker unavailable")
		}
		t.Cleanup(func() {
			if listener.Close() != nil {
				t.Error("exact native blocker did not close")
			}
		})
		return func() {
			connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal("actual native blocker stopped holding selected port")
			}
			connection.Close()
		}
	}
	if f.Profile.Docker.Backend != WindowsInterop || !bootstrapActualHost().WSL {
		t.Fatal("selected engine port blocker is unsupported")
	}
	script := "$ErrorActionPreference='Stop'; $listener=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback," + strconv.Itoa(port) + "); try { $listener.Start(); [Console]::WriteLine('agentmux-port-held'); [Console]::Out.Flush(); [void][Console]::ReadLine() } finally { $listener.Stop() }"
	cmd := exec.Command("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal("exact blocker input unavailable")
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		t.Fatal("exact blocker output unavailable")
	}
	cmd.Stderr = io.Discard
	done := make(chan error, 1)
	exited := make(chan struct{})
	readerDone := make(chan struct{})
	ready := make(chan string, 1)
	started := false
	// Cleanup is registered before Start or any readiness assertion. It runs
	// before fixture cleanup because the blocker is constructed afterward.
	t.Cleanup(func() {
		stdin.Close()
		if started {
			select {
			case err := <-done:
				if err != nil {
					t.Error("exact Windows blocker exit failed")
				}
			case <-time.After(3 * time.Second):
				cmd.Process.Kill()
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					f.RetainForRecovery(t)
					t.Error("exact Windows blocker not joined")
				}
				t.Error("exact Windows blocker required forced cleanup")
			}
		}
		stdout.Close()
		if started {
			select {
			case <-readerDone:
			case <-time.After(time.Second):
				t.Error("blocker reader not joined")
			}
		}
	})
	if cmd.Start() != nil {
		t.Fatal("actual Windows blocker start failed")
	}
	started = true
	go func() { done <- cmd.Wait(); close(exited) }()
	go func() {
		defer close(readerDone)
		text, _ := bufio.NewReader(stdout).ReadString('\n')
		ready <- strings.TrimSpace(text)
	}()
	select {
	case text := <-ready:
		if text != "agentmux-port-held" {
			t.Fatal("actual Windows port was not held")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("actual Windows blocker readiness exceeded its bound")
	}
	assertHeld := func() {
		select {
		case <-exited:
			t.Fatal("exact Windows blocker exited before the negative completed")
		default:
		}
	}
	assertHeld()
	return assertHeld
}

func TestInstalledCLIRealComposeOccupiedSelectedPort(t *testing.T) {
	f := newBootstrapDockerFixtureWithHost(t, true)
	s, r := composeCLIPolicy(t, f)
	assertHeld := composeFailureOccupyPort(t, f)
	x := composeCLIPrepare(t, f, s, r, "ensure")
	x.mustOwnHost = true
	if x.launch() != nil {
		t.Fatal("actual occupied-port frontend start failed")
	}
	raw, succeeded := composeFailureWait(t, f, x, s, r)
	assertHeld()
	var shape map[string]json.RawMessage
	if len(raw) > 0 && json.Unmarshal(raw, &shape) != nil {
		t.Fatal("actual occupied-port output is not bounded JSON")
	}
	var kind string
	if encoded, exists := shape["kind"]; exists && json.Unmarshal(encoded, &kind) != nil {
		t.Fatal("occupied-port output kind is invalid")
	}
	if kind == "bootstrap-progress" {
		composeCLIObservation(t, f, x, r, raw, "occupied-port-control", true)
	} else if kind == "bootstrap-terminal-history" {
		out, code := composeCLIFailureHistoryCode(raw, x.hostAttempt, time.Now())
		if code != "" || succeeded || !x.joined || !x.captured {
			t.Fatal("occupied-port history does not match the failed creator")
		}
		f.WriteEvidence(t, "occupied-port-history.json", out)
	} else if kind != "" {
		t.Fatal("occupied-port output kind is not supported")
	} else if len(raw) > 0 {
		var out StartupStatusObservation
		if protocol.DecodeClosedJSON(raw, &out, 64*1024) != nil || out.Disposition == "started" || out.Disposition == "reused" || (out.Disposition == "starting" && !bridgeStartingUnknown(out)) {
			t.Fatal("occupied port became false current readiness")
		}
	}
	if x.hostFD < 0 {
		f.RetainForRecovery(t)
		t.Fatal("occupied-port exact owning child was not established")
	}
	remaining := time.Until(x.started.Add(f.Config.StartupTimeout))
	if remaining <= 0 {
		t.Fatal("occupied-port owner startup budget expired")
	}
	poll := []unix.PollFd{{Fd: int32(x.hostFD), Events: unix.POLLIN}}
	if n, e := unix.Poll(poll, int(remaining/time.Millisecond)); e != nil || n != 1 {
		f.RetainForRecovery(t)
		t.Fatal("actual occupied-port owner did not fail within its startup budget")
	}
	composeFailureLeases(t, f)
	assertHeld()
	status := composeCLIStart(t, f, s, r, "status")
	statusRaw, statusSucceeded := composeFailureWait(t, f, status, s, r)
	if len(statusRaw) > 0 {
		var statusShape map[string]json.RawMessage
		if json.Unmarshal(statusRaw, &statusShape) != nil {
			t.Fatal("occupied-port status is not JSON")
		}
		if encoded, exists := statusShape["kind"]; exists {
			var statusKind string
			if json.Unmarshal(encoded, &statusKind) != nil || statusKind != "bootstrap-terminal-history" {
				t.Fatal("occupied-port status kind is not supported")
			}
			out, code := composeCLIFailureHistoryCode(statusRaw, x.hostAttempt, time.Now())
			if code != "" || statusSucceeded || !status.joined || !status.captured {
				t.Fatal("occupied-port status history does not match the failed attempt")
			}
			f.WriteEvidence(t, "occupied-port-status-history.json", out)
		} else {
			var out StartupStatusObservation
			if protocol.DecodeClosedJSON(statusRaw, &out, 64*1024) != nil || out.Disposition == "started" || out.Disposition == "reused" {
				t.Fatal("occupied-port status overclaims running readiness")
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	broker, inspectErr := f.ObserveBroker(ctx)
	cancel()
	if inspectErr == nil && broker.State == "running" {
		t.Fatal("occupied port created a running shadow broker")
	}
	var qualified *OwnedBroker
	if inspectErr == nil {
		qualified = &broker
	}
	qualifiedLedger := composeFailurePreservation(t, f, qualified, "occupied-port-resource-ledger.json")
	assertHeld()
	// A partial owned container may be unverifiable; the existing fixture keeps
	// its data and refuses unsafe cleanup. Do not call that a zero-mutation pass.
	// Both frontends have joined and privately captured their outputs. History
	// is usable only for the exact original host attempt and failed requests;
	// it never converts a starting response or successful request into proof.
	now := time.Now()
	actionable := composeFailureActionable(x.stderr.Bytes(), "port") || composeFailureActionable(status.stderr.Bytes(), "port") ||
		(!succeeded && x.joined && x.captured && composeFailureHistoryActionable(raw, x.hostAttempt, now, "port")) ||
		(!statusSucceeded && status.joined && status.captured && composeFailureHistoryActionable(statusRaw, x.hostAttempt, now, "port"))
	f.WriteEvidence(t, "occupied-port-result.json", map[string]any{"actualSelectedPortHeld": true, "exactOwnerExited": true, "leasesReleased": true, "unrelatedPreserved": true, "noFalseReadiness": true, "actionablePublicDiagnostic": actionable, "partialOwnedInspectionVerified": inspectErr == nil, "allAddedResourcesQualified": qualifiedLedger, "partialOwnedDataRetained": true})
	if !qualifiedLedger {
		t.Fatal("occupied port left unverified partial resources; retained for recovery")
	}
	if !actionable {
		t.Fatal("actual occupied-port failure lacks an actionable public diagnostic")
	}
}

// FAIL55 covers a changed working directory with identical explicit enrollment.
// It does not qualify a different workspace, profile, host or organization.
func TestInstalledCLIRealComposeDifferentWorkingDirectoryReuse(t *testing.T) {
	f := newBootstrapDockerFixtureWithHost(t, true)
	s, r := composeCLIPolicy(t, f)
	x := composeCLIPrepare(t, f, s, r, "ensure")
	x.mustOwnHost = true
	if x.launch() != nil {
		t.Fatal("actual cwd control cold frontend unavailable")
	}
	composeCLIObservation(t, f, x, r, composeCLIWait(t, f, x, s, r, "cwd-cold"), "cwd-cold", true)
	composeCLIRefresh(t, f, x.started.Add(f.Config.StartupTimeout))
	composeCLIPinRoles(t, f, x)
	broker := bootstrapFixtureBroker(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	volume, err := f.volume(ctx)
	cancel()
	if err != nil {
		t.Fatal("cwd control owned volume unavailable")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	record, err := deployment.Observe(ctx, deployment.ObserveOptions{ProbeOptions: f.Config.Health, ReadExistingRecord: true})
	cancel()
	if err != nil || record.RecordSequence == 0 {
		t.Fatal("cwd control actual stored record unavailable")
	}
	original := bootstrapFixtureRecord(t, f.Config, record.RecordSequence)
	directory, err := os.MkdirTemp(f.EvidenceDirectory, "different-cwd-")
	if err != nil {
		t.Fatal("fresh owned working directory unavailable")
	}
	if err = os.Chmod(directory, 0700); err != nil {
		t.Fatal("fresh cwd permissions unavailable")
	}
	current, err := os.Getwd()
	if err != nil || filepath.Clean(current) == filepath.Clean(directory) {
		t.Fatal("cwd control did not change working directory")
	}
	for _, operation := range []string{"ensure", "status"} {
		warm := composeCLIPrepare(t, f, s, r, operation)
		warm.cmd.Dir = directory
		if warm.launch() != nil {
			t.Fatal("different-cwd frontend unavailable")
		}
		raw, success := composeFailureWait(t, f, warm, s, r)
		if !success {
			t.Fatal("different-cwd public operation failed")
		}
		out := composeCLIObservation(t, f, warm, r, raw, "different-cwd-"+operation, false)
		if out == nil || out.Disposition != "reused" || warm.hostFD >= 0 {
			t.Fatal("different cwd replaced host or failed genuine reuse")
		}
		for _, fd := range append(append([]int(nil), x.roleFDs...), x.hostFD) {
			poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			if n, e := unix.Poll(poll, 0); e != nil || n != 0 {
				t.Fatal("different cwd stopped an exact owned runtime process")
			}
		}
		if len(installedCLIChildren(x.hostPID)) != 4 {
			t.Fatal("different cwd changed protected child roster")
		}
	}
	afterBroker := bootstrapFixtureBroker(t, f)
	if afterBroker.ContainerID != broker.ContainerID {
		t.Fatal("different cwd created another broker")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	afterVolume, err := f.volume(ctx)
	cancel()
	if err != nil || !reflect.DeepEqual(volume, afterVolume) || bootstrapFixtureRecord(t, f.Config, record.RecordSequence) != original {
		t.Fatal("different cwd changed owned data or original record")
	}
	if !composeFailurePreservation(t, f, &afterBroker, "different-cwd-resource-ledger.json") {
		t.Fatal("different cwd left an unverified added resource")
	}
	f.WriteEvidence(t, "different-cwd-preservation.json", map[string]any{"workingDirectoryChanged": true, "sameExplicitEnrollment": true, "bothPublicOperationsReused": true, "sameExactHostAndRoles": true, "sameBroker": true, "sameVolume": true, "originalRecordRetained": true, "unrelatedPreserved": true})
}
