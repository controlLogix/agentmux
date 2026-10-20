//go:build darwin && arm64 && cgo && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/internal/darwinfixtureidentity"
)

func composeHostPinTestArgs() []string {
	return []string{"/fixture/host", "host", "--host-policy", "/fixture/policy", "--invocation-id", "attempt_0123456789abcdef0123456789abcdef"}
}

func composeHostPinJoinedTestFront() *composeDarwinCLIFront {
	x := &composeDarwinCLIFront{proof: &darwinfixtureidentity.Proof{}}
	x.output.joined = true
	return x
}

func TestComposeDarwinHostPinEmptyExitedRosterIsFinalObservation(t *testing.T) {
	for _, mustOwn := range []bool{false, true} {
		x := composeHostPinJoinedTestFront()
		x.mustOwnHost = mustOwn
		calls := 0
		x.hostPinAttempt = func(context.Context) composeDarwinHostPinResult {
			calls++
			return composeDarwinHostPinResult{err: errors.New("original_exact_empty_roster"), noHost: true}
		}
		x.pinHost(context.Background())
		x.pinHost(context.Background())
		if calls != 1 || !x.hostPinNoHost || x.hostPinErr != nil || x.lifetime != nil || len(x.hostPinProofs) != 0 || x.creatorOwned() {
			t.Fatal("empty exited roster retried discovery, gained ownership or became readiness")
		}
	}
}

func TestComposeDarwinHostPinRetainsPartialFailureWithoutReplacement(t *testing.T) {
	for _, partialAbsence := range []bool{false, true} {
		proof := &darwinfixtureidentity.Proof{}
		original := errors.New("original_host_admission_failure")
		x := composeHostPinJoinedTestFront()
		calls := 0
		x.hostPinAttempt = func(context.Context) composeDarwinHostPinResult {
			calls++
			if calls == 1 {
				return composeDarwinHostPinResult{proof: proof, err: original, noHost: partialAbsence}
			}
			return composeDarwinHostPinResult{proof: &darwinfixtureidentity.Proof{}, args: composeHostPinTestArgs()}
		}
		x.pinHost(context.Background())
		wait, cancelWait := context.WithTimeout(context.Background(), time.Second)
		x.pinHost(wait)
		cancelWait()
		cleanup, cancelCleanup := context.WithTimeout(context.Background(), 3*time.Second)
		x.pinHost(cleanup)
		cancelCleanup()
		if calls != 1 || x.hostPinErr != original || x.lifetime != nil || len(x.hostPinProofs) != 1 || x.hostPinProofs[0] != proof {
			t.Fatal("wait or cleanup replaced a terminal failure or partial proof")
		}
	}
}

func TestComposeDarwinHostPinRetainsInvalidArgumentsAndCloseFailure(t *testing.T) {
	proof := &darwinfixtureidentity.Proof{}
	closeErr := errors.New("original_host_proof_close_failure")
	x := composeHostPinJoinedTestFront()
	calls, closes := 0, 0
	x.hostPinAttempt = func(context.Context) composeDarwinHostPinResult {
		calls++
		return composeDarwinHostPinResult{proof: proof, args: []string{"invalid"}, close: func() error {
			closes++
			if len(x.hostPinProofs) != 1 || x.hostPinProofs[0] != proof {
				t.Error("invalid host proof was not retained before its close attempt")
			}
			return closeErr
		}}
	}
	x.pinHost(context.Background())
	first := x.hostPinErr
	x.pinHost(context.Background())
	if calls != 1 || closes != 1 || first == nil || x.hostPinErr != first || !errors.Is(first, closeErr) || x.lifetime != nil || x.hostPinProofs[0] != proof {
		t.Fatal("invalid host arguments lost close failure or gained replacement authority")
	}
}

func TestComposeDarwinHostPinNativeFailureStaysTerminalThroughCleanup(t *testing.T) {
	x := &composeDarwinCLIFront{proof: &darwinfixtureidentity.Proof{}, hostExpected: darwinfixtureidentity.ExpectedHost{PolicyPath: "/fixture/policy", WorkspaceRoots: []string{"/fixture/workspace"}}}
	x.output.joined = true
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// A zero native proof refuses before any native scan. This exercises the
	// actual adapter rather than a caller-supplied absence classification.
	x.pinHost(ctx)
	first := x.hostPinErr
	if first == nil {
		t.Fatal("zero native proof was admitted")
	}
	f := &bootstrapDockerFixture{EvidenceDirectory: t.TempDir()}
	if !x.retainHostPinFailure(t, f) || !f.closed || !x.hostPinMarked {
		t.Fatal("terminal admission did not prevent fixture resource cleanup")
	}
	x.cleanup(t, f)
	x.pinHost(context.Background())
	if x.hostPinErr != first || !f.closed || x.lifetime != nil {
		t.Fatal("cleanup reset terminal admission or granted host authority")
	}
}

func TestComposeDarwinHostPinRejectsJoinedAbsenceAndEmptyResult(t *testing.T) {
	for _, result := range []composeDarwinHostPinResult{
		{err: errors.Join(errors.New("absence"), errors.New("cleanup_failure"))},
		{},
	} {
		x := composeHostPinJoinedTestFront()
		calls := 0
		x.hostPinAttempt = func(context.Context) composeDarwinHostPinResult { calls++; return result }
		x.pinHost(context.Background())
		x.pinHost(context.Background())
		if calls != 1 || x.hostPinErr == nil || x.lifetime != nil {
			t.Fatal("joined absence or malformed result permitted another admission attempt")
		}
	}
}

func TestComposeDarwinInstalledClientNeverUsesDirectHostDiscovery(t *testing.T) {
	for _, mustOwn := range []bool{false, true} {
		originalProof := &darwinfixtureidentity.Proof{}
		x := &composeDarwinCLIFront{proof: originalProof, installedClient: true, mustOwnHost: mustOwn}
		calls := 0
		x.hostPinAttempt = func(context.Context) composeDarwinHostPinResult {
			calls++
			return composeDarwinHostPinResult{err: errors.New("wrong_direct_parent_scan")}
		}
		x.pinHost(context.Background())
		x.output.joined = true
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		x.pinHost(ctx)
		cancel()
		if calls != 0 || x.hostPinErr != nil || len(x.hostPinProofs) != 0 || x.lifetime != nil || x.proof != originalProof {
			t.Fatal("installed client used direct discovery or acquired host authority")
		}
	}
}

func TestComposeDarwinDirectCLIStillDiscoversHostWithoutMustOwnFlag(t *testing.T) {
	proof := &darwinfixtureidentity.Proof{}
	x := &composeDarwinCLIFront{proof: &darwinfixtureidentity.Proof{}, mustOwnHost: false}
	x.output.joined = true
	calls := 0
	x.hostPinAttempt = func(context.Context) composeDarwinHostPinResult {
		calls++
		return composeDarwinHostPinResult{proof: proof, args: composeHostPinTestArgs()}
	}
	x.pinHost(context.Background())
	if calls != 1 || x.lifetime == nil || x.lifetime.host != proof || x.hostPinErr != nil {
		t.Fatal("indirect-client guard disabled ordinary direct CLI ownership discovery")
	}
}

func TestComposeDarwinHostPinWaitsForOriginalJoinAndClassifiesDuringFinished(t *testing.T) {
	proof := &darwinfixtureidentity.Proof{}
	x := &composeDarwinCLIFront{proof: &darwinfixtureidentity.Proof{}}
	calls := 0
	x.hostPinAttempt = func(context.Context) composeDarwinHostPinResult {
		calls++
		if !x.output.joined {
			t.Error("host classification preceded the original frontend/output join")
		}
		return composeDarwinHostPinResult{proof: proof, args: composeHostPinTestArgs()}
	}
	x.pinHost(context.Background())
	if calls != 0 || x.hostPinErr != nil {
		t.Fatal("live frontend triggered a surviving-child scan")
	}
	x.output.joined = true
	if !x.finished(context.Background()) || calls != 1 || x.lifetime == nil || x.lifetime.host != proof {
		t.Fatal("concurrent completion lost its original surviving host proof")
	}
}

func TestComposeDarwinHostPinFailedOriginalJoinCannotScan(t *testing.T) {
	original := &darwinfixtureidentity.Owned{}
	x := &composeDarwinCLIFront{proof: &darwinfixtureidentity.Proof{}, owned: original}
	calls := 0
	x.hostPinAttempt = func(context.Context) composeDarwinHostPinResult { calls++; return composeDarwinHostPinResult{} }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if x.finished(ctx) || calls != 0 || x.output.joined || x.owned != original || x.hostPinErr != nil {
		t.Fatal("unconfirmed original wait permitted child classification or lost its owner")
	}
}

func TestComposeDarwinHostPinLateCleanupJoinCannotRenewAdmissionBudget(t *testing.T) {
	original := &darwinfixtureidentity.Owned{}
	x := &composeDarwinCLIFront{proof: &darwinfixtureidentity.Proof{}, owned: original}
	deadline := time.Now().Add(-time.Second)
	request, stop := context.WithDeadline(context.Background(), deadline)
	defer stop()
	joins, scans := 0, 0
	x.joinAttempt = func(ctx context.Context) (darwinfixtureidentity.Completion, error) {
		joins++
		if joins == 1 {
			return darwinfixtureidentity.Completion{}, ctx.Err()
		}
		if ctx.Err() != nil {
			t.Fatal("original admission deadline shortened the separate cleanup join budget")
		}
		return darwinfixtureidentity.Completion{}, nil
	}
	x.hostPinAttempt = func(context.Context) composeDarwinHostPinResult {
		scans++
		return composeDarwinHostPinResult{proof: &darwinfixtureidentity.Proof{}, args: composeHostPinTestArgs()}
	}
	if x.finished(request) || x.output.joined || !errors.Is(x.hostPinErr, context.DeadlineExceeded) {
		t.Fatal("original join timeout lost its terminal admission failure")
	}
	failure := x.hostPinErr
	cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := x.join(cleanup); err != nil || !x.output.joined {
		t.Fatal("later original cleanup join did not complete")
	}
	x.pinHost(cleanup)
	f := &bootstrapDockerFixture{EvidenceDirectory: t.TempDir()}
	if !x.retainHostPinFailure(t, f) || !f.closed || !x.hostPinMarked || joins != 2 || scans != 0 || x.hostPinErr != failure || x.owned != original || x.lifetime != nil || len(x.hostPinProofs) != 0 || !x.hostPinDeadline.Equal(deadline) {
		t.Fatal("late cleanup join renewed admission, lost the original owner or failed to retain recovery")
	}
}

func TestComposeDarwinHostPinCleanupCannotScanAfterUnrecordedExpiry(t *testing.T) {
	x := composeHostPinJoinedTestFront()
	x.output.joined = false
	x.hostPinDeadline = time.Now().Add(-time.Second)
	x.hostPinAttempt = func(context.Context) composeDarwinHostPinResult {
		t.Fatal("fresh cleanup context permitted a scan after the original deadline")
		return composeDarwinHostPinResult{}
	}
	cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	f := &bootstrapDockerFixture{EvidenceDirectory: t.TempDir()}
	x.cleanup(t, f)
	if !f.closed || !x.hostPinMarked {
		t.Fatal("cleanup did not retain the original expired admission before reaping")
	}
	x.output.joined = true
	x.pinHost(cleanup)
	if !errors.Is(x.hostPinErr, context.DeadlineExceeded) || x.lifetime != nil || len(x.hostPinProofs) != 0 {
		t.Fatal("cleanup admitted a host after an unrecorded original expiry")
	}
}

func TestComposeDarwinHostPinClampsCleanupScanToOriginalDeadline(t *testing.T) {
	x := composeHostPinJoinedTestFront()
	x.hostPinDeadline = time.Now().Add(time.Second)
	deadline := x.hostPinDeadline
	x.hostPinAttempt = func(ctx context.Context) composeDarwinHostPinResult {
		if got, bounded := ctx.Deadline(); !bounded || !got.Equal(deadline) {
			t.Fatal("cleanup scan did not preserve the original admission deadline")
		}
		return composeDarwinHostPinResult{err: errors.New("native_host_observation_failed")}
	}
	cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	x.pinHost(cleanup)
	if x.hostPinErr == nil || !x.hostPinDeadline.Equal(deadline) {
		t.Fatal("cleanup scan replaced the original deadline or lost its failure")
	}
}

func TestComposeDarwinInstalledClientKeepsExistingFailureAndColdOwnership(t *testing.T) {
	original := errors.New("original_retained_admission_failure")
	partial, host := &darwinfixtureidentity.Proof{}, &darwinfixtureidentity.Proof{}
	lifetime := &composeDarwinCLILifetime{host: host, attempt: composeHostPinTestArgs()[5]}
	x := &composeDarwinCLIFront{proof: &darwinfixtureidentity.Proof{}, installedClient: true, hostPinErr: original,
		hostPinProofs: []*darwinfixtureidentity.Proof{partial}, lifetime: lifetime}
	x.hostPinAttempt = func(context.Context) composeDarwinHostPinResult {
		t.Error("installed client retried direct discovery")
		return composeDarwinHostPinResult{}
	}
	x.pinHost(context.Background())
	if x.hostPinErr != original || len(x.hostPinProofs) != 1 || x.hostPinProofs[0] != partial || x.lifetime != lifetime || x.lifetime.host != host {
		t.Fatal("indirect discovery marker reset retained failure or original cold ownership")
	}
}
