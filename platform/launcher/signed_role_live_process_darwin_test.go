//go:build darwin && cgo && agentmux_bootstrap_docker && !agentmux_darwin_identity_candidate && !agentmux_darwin_identity_protected_candidate

package launcher

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

// This carries the Linux real-process assertions, then explicitly tests recovery
// by retiring the entire old group and starting a newly prepared signed group.
// It does not claim selected-member replacement or mutate Group membership.
func TestSignedDarwinLiveRolesLateSnapshotDegradationAndWholeGroupRecovery(t *testing.T) {
	f := newDarwinLiveFixture(t)
	reader := f.reader(time.Now().Add(3 * time.Second))
	sub := f.subscribe(reader, f.wire.Snapshot)
	group := f.startGroup()
	initialPIDs := f.assertLive(group)
	first, _ := f.snapshot(sub, time.Now().Add(10*time.Second), darwinLiveReady(time.Time{}))
	late := f.reader(time.Now().Add(3 * time.Second))
	lateSub := f.subscribe(late, f.wire.Snapshot)
	updates := f.subscribe(late, f.wire.Update)
	next, _ := f.snapshot(lateSub, time.Now().Add(10*time.Second), darwinLiveReady(time.Time{}))
	if next.Incarnation != first.Incarnation || next.Revision <= first.Revision {
		t.Fatal("late actual-process snapshot lost source or revision continuity")
	}
	f.snapshot(updates, time.Now().Add(2*time.Second), func(protocol.Snapshot) bool { return true })
	if !reflect.DeepEqual(initialPIDs, f.assertLive(group)) {
		t.Fatal("signed child identities changed before the selected fault")
	}
	faultAt := time.Now()
	stop, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	err := group.StopRole(stop, "internal-communication")
	cancel()
	if err != nil {
		t.Fatal("exact owned internal-communication stop failed")
	}
	assertDarwinLiveSelectedExit(t, group, initialPIDs, "internal-communication")
	lost, _ := f.snapshot(sub, faultAt.Add(10*time.Second), func(frame protocol.Snapshot) bool {
		if !darwinLiveFrameAfter(frame, faultAt) {
			return false
		}
		for _, member := range frame.Members {
			if member.Role == "internal-communication" && member.State != "ready" && member.State != "unknown" {
				return true
			}
		}
		return false
	})
	if lost.KernelReadiness == "ready" || lost.Incarnation != first.Incarnation || lost.Revision <= first.Revision {
		t.Fatal("live failed protected member retained healthy or replayed kernel status")
	}
	f.snapshot(sub, faultAt.Add(10*time.Second), func(frame protocol.Snapshot) bool {
		if !darwinLiveFrameAfter(frame, faultAt) {
			return false
		}
		for _, member := range frame.Members {
			if member.Role == "internal-communication" && member.State == "stale" {
				return frame.KernelReadiness != "ready"
			}
		}
		return false
	})
	assertDarwinLiveSelectedExit(t, group, initialPIDs, "internal-communication")
	select {
	case <-group.Done():
		t.Fatal("single-member loss fabricated all-group completion")
	default:
	}
	if !f.stopGroup(group, true) {
		t.Fatal("old signed group did not shut down and reap cleanly")
	}
	reader.close(t)
	late.close(t)
	// The broker, scope, signed release, credentials, and endpoint are unchanged.
	// Every old child is reaped before any new start; actor incarnations may reset.
	recoveryReader := f.reader(time.Now().Add(3 * time.Second))
	recoverySub := f.subscribe(recoveryReader, f.wire.Snapshot)
	recoveryAt := time.Now()
	recoveredGroup := f.startGroup()
	recovered, _ := f.snapshot(recoverySub, recoveryAt.Add(10*time.Second), darwinLiveReady(recoveryAt))
	if recovered.Incarnation == first.Incarnation || recovered.Scope != first.Scope {
		t.Fatal("whole-group recovery reused old exporter identity or changed release scope")
	}
	oldMembers := darwinLiveMembers(first)
	for _, member := range recovered.Members {
		if member.Incarnation == oldMembers[member.Role].Incarnation {
			t.Fatal("whole-group recovery silently reused an old role incarnation")
		}
	}
	f.assertLive(recoveredGroup)
	if !f.stopGroup(recoveredGroup, true) {
		t.Fatal("recovered signed group did not shut down and reap cleanly")
	}
	f.checkReleaseUnchanged()
	darwinPrepareWrite(t, filepath.Join(f.directory, "whole-group-recovery.json"), mustStatusJSON(map[string]any{
		"fourSignedProcesses": true, "lateSnapshot": true, "liveUpdate": true,
		"selectedOwnedRoleReaped": true, "liveDegradation": true, "expiredRoleStale": true,
		"siblingsUnchangedUntilRetirement": true, "oldGroupReapedBeforeRecovery": true,
		"recoveryBoundary": "whole_group_reprepare_and_start", "selectedMemberRestartQualified": false,
		"sameReleaseScope": true, "allOwnedChildrenReaped": true, "cachedL04Used": false,
	}), 0600)
}

func assertDarwinLiveSelectedExit(t *testing.T, group *protected.Group, before map[string]int, selected string) {
	t.Helper()
	states := group.Status()
	if len(states) != 4 {
		t.Fatal("selected-role fault changed the protected roster")
	}
	for _, state := range states {
		if state.PID != before[state.Role] || state.Exited != (state.Role == selected) {
			t.Fatal("selected-role stop failed to reap its child or affected a sibling")
		}
	}
	if group.CleanupError() != nil {
		t.Fatal("selected-role failure hid descriptor cleanup failure")
	}
}

func TestSignedDarwinLiveTLSBrokerRecoveryPreservesOwnedRoles(t *testing.T) {
	f := newDarwinLiveFixture(t)
	reader := f.reader(time.Now().Add(3 * time.Second))
	sub := f.subscribe(reader, f.wire.Snapshot)
	group := f.startGroup()
	before, raw := f.snapshot(sub, time.Now().Add(10*time.Second), darwinLiveReady(time.Time{}))
	ownedBefore := f.assertLive(group)
	reader.close(t)
	if !f.stopBroker(f.brokers[0], true) {
		t.Fatal("planned exact broker loss did not join its owner and captures")
	}
	lostAt := time.Now()
	deadline := lostAt.Add(darwinLiveReconnectBound)
	// A short, actual outage exercises reconnect without assuming ten attempts
	// guarantee 24 seconds of survival. The 24 seconds bound observation only.
	restartedAt := time.Now()
	f.startBroker()
	reader = f.reader(deadline)
	sub = f.subscribe(reader, f.wire.Snapshot)
	after, _ := f.snapshot(sub, deadline, darwinLiveReady(restartedAt))
	assertDarwinLiveContinuity(t, before, after, true)
	for range 4 {
		next, _ := f.snapshot(sub, deadline, darwinLiveReady(restartedAt))
		assertDarwinLiveContinuity(t, after, next, false)
		after = next
	}
	// Expire the retained pre-loss frame independently, while the broker is
	// already restored. No fake clock or mandatory reconnect-exhausting outage.
	expiry := time.NewTimer(max(time.Duration(0), time.Until(lostAt.Add(darwinLiveFreshness))))
	remaining := time.NewTimer(max(time.Duration(0), time.Until(deadline)))
	select {
	case <-expiry.C:
	case <-remaining.C:
		expiry.Stop()
		t.Fatal("retained old-frame expiry exceeded the original recovery deadline")
	}
	expiry.Stop()
	remaining.Stop()
	if _, err := protocol.DecodeSnapshot(raw, f.scope, time.Now(), darwinLiveFreshness); err == nil {
		t.Fatal("pre-loss healthy frame remained admissible after actual expiry")
	}
	if !reflect.DeepEqual(ownedBefore, f.assertLive(group)) {
		t.Fatal("broker reconnect changed the exact owned protected processes")
	}
	if time.Now().After(deadline) {
		t.Fatal("live broker recovery exceeded the unchanged 24-second bound")
	}
	if !f.stopGroup(group, true) {
		t.Fatal("reconnected signed group did not shut down cleanly")
	}
	darwinPrepareWrite(t, filepath.Join(f.directory, "broker-recovery.json"), mustStatusJSON(map[string]any{
		"sameEnrolledTLSConnectionPolicy": true, "oldHealthyFrameExpired": true,
		"sameFourOwnedProcesses": true, "sameActorIncarnations": true,
		"everyMemberRevisionAdvanced": true, "subsequentConsistentSnapshots": 4,
		"reconnectObservationBoundSeconds": 24, "productionFreshnessSeconds": 3,
		"allOwnedChildrenReaped": true, "cachedL04Used": false,
	}), 0600)
}

func TestSignedDarwinLiveTLSBrokerReconnectExhaustionIsBounded(t *testing.T) {
	f := newDarwinLiveFixture(t)
	reader := f.reader(time.Now().Add(3 * time.Second))
	sub := f.subscribe(reader, f.wire.Snapshot)
	group := f.startGroup()
	_, raw := f.snapshot(sub, time.Now().Add(10*time.Second), darwinLiveReady(time.Time{}))
	ownedBefore := f.assertLive(group)
	reader.close(t)
	if !f.stopBroker(f.brokers[0], true) {
		t.Fatal("planned broker exhaustion fault did not join its owner and captures")
	}
	lostAt := time.Now()
	deadline := time.NewTimer(time.Until(lostAt.Add(darwinLiveReconnectBound)))
	defer deadline.Stop()
	select {
	case <-group.Done():
	case <-deadline.C:
		t.Fatal("actual protected roles outlived the existing reconnect observation bound")
	}
	completedAt := time.Now()
	if completedAt.After(lostAt.Add(darwinLiveReconnectBound)) {
		t.Fatal("actual protected reaping exceeded the original broker-loss deadline")
	}
	if group.CleanupError() != nil {
		t.Fatal("broker exhaustion hid owned descriptor cleanup failure")
	}
	states := group.Status()
	if len(states) != 4 {
		t.Fatal("broker exhaustion changed protected role membership")
	}
	for _, state := range states {
		if !state.Exited || state.PID != ownedBefore[state.Role] || state.ExitCode != 1 {
			t.Fatal("exact owned role did not terminate on bounded broker exhaustion")
		}
		output, truncated := group.Output(state.Role)
		if truncated || string(output) != "kernel_broker_unavailable\n" {
			t.Fatal("actual exhausted role omitted its exact bounded public failure code")
		}
	}
	if _, err := protocol.DecodeSnapshot(raw, f.scope, time.Now(), darwinLiveFreshness); err == nil {
		t.Fatal("exhausted protected roles retained admissible healthy status")
	}
	if !f.stopGroup(group, false) {
		t.Fatal("exhausted signed group retained unfinished shutdown or cleanup history")
	}
	darwinPrepareWrite(t, filepath.Join(f.directory, "broker-exhaustion.json"), mustStatusJSON(map[string]any{
		"sameFourOwnedProcessesReaped": true, "exactTerminalCode": "kernel_broker_unavailable",
		"lastHealthyFrameExpired": true, "reconnectObservationBoundSeconds": 24,
		"elapsedSeconds": completedAt.Sub(lostAt).Seconds(), "cachedL04Used": false,
	}), 0600)
}

func darwinLiveMembers(frame protocol.Snapshot) map[string]protocol.Member {
	members := map[string]protocol.Member{}
	for _, member := range frame.Members {
		members[member.Role] = member
	}
	return members
}

func darwinLiveFrameAfter(frame protocol.Snapshot, after time.Time) bool {
	observed, err := time.Parse(time.RFC3339Nano, frame.ObservedAt)
	return err == nil && !observed.Before(after)
}

func assertDarwinLiveContinuity(t *testing.T, previous, current protocol.Snapshot, requireEveryAdvance bool) {
	t.Helper()
	if previous.Scope != current.Scope || previous.Incarnation != current.Incarnation || current.Revision <= previous.Revision {
		t.Fatal("broker reconnect replaced exporter identity or replayed its revision")
	}
	old := darwinLiveMembers(previous)
	for _, member := range current.Members {
		before, found := old[member.Role]
		if !found || member.Incarnation != before.Incarnation || member.Revision < before.Revision ||
			(requireEveryAdvance && member.Revision <= before.Revision) || strings.TrimSpace(member.Incarnation) == "" {
			t.Fatal("broker reconnect replaced a protected actor or replayed its revision")
		}
	}
}
