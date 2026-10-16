//go:build darwin && cgo && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/internal/darwinfixtureidentity"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

const (
	darwinScenarioEnsureBudget  = 10 * time.Second
	darwinScenarioRefusalBudget = 5 * time.Second
)

// Setup consumes the separately installed CLI and signed role prerequisites.
// These scenarios never stage an installation or request elevation. All process
// authority stays in the native helper's creator and opaque descendant proofs.
func darwinScenarioStart(t *testing.T, f *bootstrapDockerFixture, x *composeDarwinCLIFront, budget time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	err := x.start(ctx)
	cancel()
	if err != nil {
		t.Fatal("actual installed Darwin frontend start or admission failed")
	}
}

func darwinScenarioResponse(t *testing.T, f *bootstrapDockerFixture, x *composeDarwinCLIFront, r hostPolicyRecord, name string, budget time.Duration, receipt bool) *StartupStatusObservation {
	t.Helper()
	raw, success := x.wait(t, f, name, budget)
	if !success {
		t.Fatal("actual installed Darwin frontend failed")
	}
	return x.observation(t, f, r, raw, name, receipt)
}

func darwinScenarioCold(t *testing.T, f *bootstrapDockerFixture, s HostPolicySelection, r hostPolicyRecord, name string) *composeDarwinCLIFront {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	before, err := f.ObserveBroker(ctx)
	cancel()
	if err != nil || before.State != "absent" {
		t.Fatal("cold real broker is not absent")
	}
	x := composeDarwinCLIPrepare(t, f, s, r, "ensure")
	x.mustOwnHost = true
	darwinScenarioStart(t, f, x, darwinScenarioEnsureBudget)
	darwinScenarioResponse(t, f, x, r, name, darwinScenarioEnsureBudget, true)
	darwinScenarioReady(t, f, x, name+"-refresh.json")
	return x
}

func darwinScenarioReady(t *testing.T, f *bootstrapDockerFixture, x *composeDarwinCLIFront, name string) StartupStatusObservation {
	t.Helper()
	if !x.output.joined || !x.output.captured || !x.creatorOwned() {
		f.RetainForRecovery(t)
		t.Fatal("ready control needs a joined frontend and its exact creating host")
	}
	fresh, requested := darwinScenarioRefresh(t, f, x.output.started.Add(f.Config.StartupTimeout))
	if fresh.StartupAttemptID == nil || *fresh.StartupAttemptID != requested {
		t.Fatal("authenticated completion does not correlate the actual status request")
	}
	x.lifetime.pinRoles(t, f)
	x.lifetime.assertPinnedLive(t)
	bootstrapFixtureRoleLeases(t, f, true)
	f.WriteEvidence(t, name, fresh)
	return fresh
}

// Starting names the owning cold attempt; completed refresh names this status
// request. Keep its invocation alongside the observation instead of comparing
// it to the separately retained creator proof's cold attempt.
func darwinScenarioRefresh(t *testing.T, f *bootstrapDockerFixture, startupDeadline time.Time) (StartupStatusObservation, string) {
	t.Helper()
	client, err := LoadOwnerBridgeClient(f.Config, *f.BridgeEnrollment)
	if err != nil {
		t.Fatal("actual authenticated refresh client refused")
	}
	ctx, cancel := context.WithDeadline(context.Background(), startupDeadline)
	defer cancel()
	for ctx.Err() == nil {
		invocation := "attempt_" + bootstrapFixtureRandom(t, 16)
		request, stop := context.WithTimeout(ctx, 5*time.Second)
		out, requestErr := client.Request(request, "status", invocation)
		stop()
		code := "none"
		if requestErr != nil {
			switch requestErr.Error() {
			case "owner_bridge_connection_unavailable", "owner_bridge_reply_unavailable", "owner_bridge_deadline":
				code = requestErr.Error()
			default:
				code = "closed_unclassified_failure"
			}
		}
		f.WriteEvidence(t, "darwin-refresh-attempt-"+bootstrapFixtureRandom(t, 4)+".json", map[string]any{
			"errorCode": code, "deadlineExpired": ctx.Err() != nil, "disposition": out.Disposition,
			"requestedInvocationId": invocation,
		})
		// Request already checks the authenticated envelope's request nonce,
		// invocation, scope and freshness. Recheck the observation contract here
		// against the invocation actually supplied, including starting semantics.
		if requestErr == nil && !bridgeObservationBound(out, *f.BridgeEnrollment, invocation, time.Now()) {
			t.Fatal("actual refreshed observation lost owner or request correlation")
		}
		if requestErr == nil && (out.Disposition == "started" || out.Disposition == "reused") {
			if out.StartupAttemptID == nil || *out.StartupAttemptID != invocation ||
				out.Instance.RunningVersion == nil || out.Instance.Readiness != "degraded" ||
				out.Work.State != "unavailable" || out.Hubs.InventoryState != "unavailable" {
				t.Fatal("actual completed status lacks request correlation or current kernel evidence")
			}
			for _, role := range protocol.Roles() {
				found := false
				for _, service := range out.Instance.Services {
					if service.ServiceID == role && service.Readiness == "ready" && service.ObservedAt != nil && service.SourceRevision != nil {
						found = true
					}
				}
				if !found {
					t.Fatal("actual completed role lacks current readiness")
				}
			}
			return out, invocation
		}
		if requestErr != nil && code == "closed_unclassified_failure" {
			t.Fatal("actual refresh authority or runtime failed")
		}
		if requestErr == nil && out.Disposition != "starting" {
			t.Fatal("actual startup failed")
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("actual installed runtime did not complete within startup budget")
	return StartupStatusObservation{}, ""
}

type darwinScenarioStoredState struct {
	broker   OwnedBroker
	volume   bootstrapVolumeObservation
	sequence uint64
	record   string
}

func darwinScenarioStored(t *testing.T, f *bootstrapDockerFixture) darwinScenarioStoredState {
	t.Helper()
	broker := bootstrapFixtureBroker(t, f)
	if broker.State != "running" {
		t.Fatal("actual owned broker is not running")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	volume, err := f.volume(ctx)
	cancel()
	if err != nil {
		t.Fatal("actual owned volume identity unavailable")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	record, err := deployment.Observe(ctx, deployment.ObserveOptions{ProbeOptions: f.Config.Health, ReadExistingRecord: true})
	cancel()
	if err != nil || record.RecordSequence == 0 {
		t.Fatal("actual original persistence record unavailable")
	}
	return darwinScenarioStoredState{broker, volume, record.RecordSequence, bootstrapFixtureRecord(t, f.Config, record.RecordSequence)}
}

func (before darwinScenarioStoredState) assertPreserved(t *testing.T, f *bootstrapDockerFixture, name string) {
	t.Helper()
	after := bootstrapFixtureBroker(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	volume, err := f.volume(ctx)
	cancel()
	if err != nil || after.State != "running" || after.ContainerID != before.broker.ContainerID ||
		!reflect.DeepEqual(before.volume, volume) || bootstrapFixtureRecord(t, f.Config, before.sequence) != before.record {
		f.RetainForRecovery(t)
		t.Fatal("actual CLI operation changed broker, volume or original persistence record")
	}
	if !composeDarwinFailurePreservation(t, f, &after, name) {
		f.RetainForRecovery(t)
		t.Fatal("actual CLI operation left an unverified added resource")
	}
	f.AssertBaselineUnchanged(t)
}

func TestInstalledCLIDarwinRealComposeColdWarmAndRefresh(t *testing.T) {
	f, s, r := composeDarwinCLIEnrolledFixture(t)
	x := darwinScenarioCold(t, f, s, r, "darwin-cold")
	// The frontend's sole Wait and output copies have joined. These original
	// proofs, rather than a response or a process identifier, prove survival.
	x.lifetime.assertPinnedLive(t)
	before := darwinScenarioStored(t, f)
	f.AssertBaselineUnchanged(t)
	for _, operation := range []string{"ensure", "status"} {
		warm := composeDarwinCLIPrepare(t, f, s, r, operation)
		budget := darwinScenarioEnsureBudget
		if operation == "status" {
			budget = darwinScenarioRefusalBudget
		}
		darwinScenarioStart(t, f, warm, budget)
		out := darwinScenarioResponse(t, f, warm, r, "darwin-warm-"+operation, budget, false)
		if out == nil || out.Disposition != "reused" || warm.lifetime != nil {
			t.Fatal("warm installed CLI spawned a host or failed authenticated reuse")
		}
		x.lifetime.assertUnchanged(t, f)
	}
	before.assertPreserved(t, f, "darwin-warm-resource-ledger.json")
	f.WriteEvidence(t, "darwin-frontend-exit-survival.json", map[string]any{
		"frontendWaitJoined": true, "exactHostSurvived": true, "exactRoleCount": len(x.lifetime.roles),
		"bothPublicOperationsReused": true, "sameBrokerAndVolume": true, "originalRecordRetained": true,
	})
}

func TestInstalledCLIDarwinRealComposeConcurrentCold(t *testing.T) {
	f, s, r := composeDarwinCLIEnrolledFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	before, err := f.ObserveBroker(ctx)
	cancel()
	if err != nil || before.State != "absent" {
		t.Fatal("concurrent cold broker is not absent")
	}
	a := composeDarwinCLIPrepare(t, f, s, r, "ensure")
	b := composeDarwinCLIPrepare(t, f, s, r, "ensure")
	barrier, launched := make(chan struct{}), make(chan error, 2)
	for _, x := range []*composeDarwinCLIFront{a, b} {
		go func(x *composeDarwinCLIFront) {
			<-barrier
			ctx, cancel := context.WithTimeout(context.Background(), darwinScenarioEnsureBudget)
			defer cancel()
			launched <- x.start(ctx)
		}(x)
	}
	close(barrier)
	first, second := <-launched, <-launched
	if first != nil || second != nil {
		t.Fatal("concurrent actual installed frontend admission failed")
	}
	deadline := a.output.started.Add(darwinScenarioEnsureBudget)
	if other := b.output.started.Add(darwinScenarioEnsureBudget); other.Before(deadline) {
		deadline = other
	}
	ctx, cancel = context.WithDeadline(context.Background(), deadline)
	// Discover each actual direct host before polling its sole joined wait.
	// A fast frontend need not have a full proof; its completion cannot be
	// inferred from failed pinning. Retained anchors survive joining here.
	for ctx.Err() == nil {
		for _, x := range []*composeDarwinCLIFront{a, b} {
			poll, stop := context.WithTimeout(ctx, 10*time.Millisecond)
			x.pinHost(poll)
			stop()
		}
		aFinished, bFinished := a.finished(ctx), b.finished(ctx)
		if (a.lifetime != nil && b.lifetime != nil) || (aFinished && bFinished) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	darwinScenarioResponse(t, f, a, r, "darwin-concurrent-a", darwinScenarioEnsureBudget, true)
	darwinScenarioResponse(t, f, b, r, "darwin-concurrent-b", darwinScenarioEnsureBudget, true)
	fresh, requested := darwinScenarioRefresh(t, f, a.output.started.Add(f.Config.StartupTimeout))
	var retained []*composeDarwinCLIFront
	for _, x := range []*composeDarwinCLIFront{a, b} {
		if x.lifetime == nil {
			continue
		}
		state := x.lifetime.host.Live()
		if state == nil {
			retained = append(retained, x)
		} else if !errors.Is(state, darwinfixtureidentity.ErrExited) {
			f.RetainForRecovery(t)
			t.Fatal("concurrent host lifetime became unverifiable")
		}
	}
	if len(retained) != 1 {
		f.RetainForRecovery(t)
		t.Fatal("concurrent frontends did not converge on one exact retained host")
	}
	if fresh.StartupAttemptID == nil || *fresh.StartupAttemptID != requested {
		t.Fatal("concurrent authenticated completion does not correlate the actual status request")
	}
	owner := retained[0]
	owner.lifetime.pinRoles(t, f)
	owner.lifetime.assertUnchanged(t, f)
	bootstrapFixtureRoleLeases(t, f, true)
	stored := darwinScenarioStored(t, f)
	stored.assertPreserved(t, f, "darwin-concurrent-resource-ledger.json")
	f.WriteEvidence(t, "darwin-concurrent-refresh.json", fresh)
	f.WriteEvidence(t, "darwin-concurrent-owner.json", map[string]any{
		"joinedFrontends": 2, "retainedCreatorProvenHosts": len(retained), "exactProtectedRoles": len(owner.lifetime.roles),
	})
}

func TestInstalledCLIDarwinRealComposeAuthenticatedPending(t *testing.T) {
	f, s, r := composeDarwinCLIEnrolledFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	lease, err := AcquireBootstrapLock(ctx, f.Profile.ProfileDirectory, f.Profile.InstanceID, f.Profile.Docker.EngineID)
	cancel()
	if err != nil {
		t.Fatal("actual pending arbitration lease unavailable")
	}
	// Registered before the frontend cleanup so a failed assertion releases the
	// arbitration lease only after its exact owned frontend and host are handled.
	t.Cleanup(func() {
		if lease.Close() != nil {
			f.RetainForRecovery(t)
			t.Error("pending arbitration lease cleanup failed")
		}
	})
	owner := f.Owner
	owner.LockHeld = true
	ctx, cancel = context.WithTimeout(context.Background(), 60*time.Second)
	err = f.Driver.StartOwned(ctx, owner, f.Config.Compose)
	if err != nil {
		f.WriteEvidence(t, "darwin-pending-start-failure.json", map[string]any{
			"failureCode": bootstrapFixtureFailureCode(err), "failureStage": bootstrapFixtureFailureStage(err),
			"contextExpired": ctx.Err() != nil, "actualLeaseHeld": true,
		})
		cancel()
		t.Fatal("actual pending factory broker start failed")
	}
	cancel()
	x := composeDarwinCLIPrepare(t, f, s, r, "ensure")
	x.mustOwnHost = true
	darwinScenarioStart(t, f, x, darwinScenarioEnsureBudget)
	out := darwinScenarioResponse(t, f, x, r, "darwin-pending", darwinScenarioEnsureBudget, false)
	if !x.creatorOwned() || out == nil || out.Disposition != "starting" || !bridgeStartingUnknown(*out) ||
		out.StartupAttemptID == nil || *out.StartupAttemptID != x.lifetime.attempt {
		t.Fatal("actual pending response lacks authenticated unknown state and its owning attempt")
	}
	if lease.Close() != nil {
		f.RetainForRecovery(t)
		t.Fatal("pending arbitration release failed")
	}
	darwinScenarioReady(t, f, x, "darwin-pending-completion.json")
	stored := darwinScenarioStored(t, f)
	stored.assertPreserved(t, f, "darwin-pending-resource-ledger.json")
}

func TestInstalledCLIDarwinRealComposeAbruptHostRestart(t *testing.T) {
	f, s, r := composeDarwinCLIEnrolledFixture(t)
	original := darwinScenarioCold(t, f, s, r, "darwin-abrupt-cold")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	beforeKernel, err := ObserveKernel(ctx, f.Config.Kernel)
	cancel()
	if err != nil || beforeKernel.KernelReadiness != "ready" {
		t.Fatal("original genuine kernel incarnation unavailable")
	}
	stored := darwinScenarioStored(t, f)
	f.AssertBaselineUnchanged(t)
	killedAt := time.Now()
	deadline := killedAt.Add(f.Config.Deadlines.StopGrace + f.Config.Deadlines.ReapTimeout)
	if original.lifetime.host.Signal(syscall.SIGKILL) != nil {
		f.RetainForRecovery(t)
		t.Fatal("exact creator-proven host failure injection refused")
	}
	ctx, cancel = context.WithDeadline(context.Background(), deadline)
	defer cancel()
	for _, proof := range append([]*darwinfixtureidentity.Proof{original.lifetime.host}, original.lifetime.roles...) {
		if proof.WaitExit(ctx) != nil {
			f.RetainForRecovery(t)
			t.Fatal("abrupt host death did not establish all exact exits within the shared shutdown budget")
		}
	}
	// Include every role and service lease check in that same original deadline.
	ids := append(bootstrapFixtureRoleLeaseIDs(f.Profile.Docker.EngineID), "owner-status-service")
	for _, id := range ids {
		lease, err := AcquireBootstrapLock(ctx, f.Profile.ProfileDirectory, f.Profile.InstanceID, id)
		if err != nil || lease == nil {
			f.RetainForRecovery(t)
			t.Fatal("abrupt host retained an actual lifetime lease")
		}
		if lease.Close() != nil {
			f.RetainForRecovery(t)
			t.Fatal("released lifetime lease descriptor did not close")
		}
	}
	if ctx.Err() != nil || time.Now().After(deadline) {
		f.RetainForRecovery(t)
		t.Fatal("abrupt exit and lease release exceeded the shared shutdown budget")
	}
	cancel()
	f.WriteEvidence(t, "darwin-abrupt-exit.json", map[string]any{
		"injection": "SIGKILL through retained native host proof", "exactHostExited": true,
		"exactRoleExitCount": len(original.lifetime.roles), "roleLeasesReleased": 4, "serviceLeaseReleased": true,
		"sharedShutdownBudgetNanoseconds": int64(f.Config.Deadlines.StopGrace + f.Config.Deadlines.ReapTimeout),
		"elapsedNanoseconds":              time.Since(killedAt).Nanoseconds(),
	})
	stored.assertPreserved(t, f, "darwin-abrupt-before-restart-ledger.json")
	recovered := composeDarwinCLIPrepare(t, f, s, r, "ensure")
	recovered.mustOwnHost = true
	darwinScenarioStart(t, f, recovered, darwinScenarioEnsureBudget)
	darwinScenarioResponse(t, f, recovered, r, "darwin-abrupt-recovery", darwinScenarioEnsureBudget, true)
	darwinScenarioReady(t, f, recovered, "darwin-abrupt-recovery-status.json")
	if recovered.lifetime.attempt == original.lifetime.attempt ||
		!errors.Is(original.lifetime.host.Live(), darwinfixtureidentity.ErrExited) {
		t.Fatal("actual restart reused the dead creating host")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 60*time.Second)
	afterKernel, err := ObserveKernel(ctx, f.Config.Kernel)
	cancel()
	if err != nil || afterKernel.KernelReadiness != "ready" || afterKernel.Incarnation == beforeKernel.Incarnation {
		t.Fatal("actual restart did not establish a new genuine kernel incarnation")
	}
	stored.assertPreserved(t, f, "darwin-abrupt-recovery-ledger.json")
	f.WriteEvidence(t, "darwin-abrupt-recovery-preservation.json", map[string]any{
		"newCreatorProvenHost": true, "newKernelIncarnation": true, "sameBroker": true,
		"sameVolume": true, "originalRecordRetained": true, "newExactRoleCount": len(recovered.lifetime.roles),
	})
}

func TestInstalledCLIDarwinRealComposeDifferentWorkingDirectoryReuse(t *testing.T) {
	f, s, r := composeDarwinCLIEnrolledFixture(t)
	x := darwinScenarioCold(t, f, s, r, "darwin-cwd-cold")
	stored := darwinScenarioStored(t, f)
	directory, err := os.MkdirTemp(f.EvidenceDirectory, "different-cwd-")
	if err != nil || os.Chmod(directory, 0700) != nil {
		t.Fatal("fresh owned working directory unavailable")
	}
	current, err := os.Getwd()
	if err != nil || filepath.Clean(current) == filepath.Clean(directory) {
		t.Fatal("working directory control did not change directory")
	}
	for _, operation := range []string{"ensure", "status"} {
		warm := composeDarwinCLIPrepare(t, f, s, r, operation)
		warm.launch.Dir = directory
		budget := darwinScenarioEnsureBudget
		if operation == "status" {
			budget = darwinScenarioRefusalBudget
		}
		darwinScenarioStart(t, f, warm, budget)
		out := darwinScenarioResponse(t, f, warm, r, "darwin-different-cwd-"+operation, budget, false)
		if out == nil || out.Disposition != "reused" || warm.lifetime != nil {
			t.Fatal("different working directory replaced host or failed genuine reuse")
		}
		x.lifetime.assertUnchanged(t, f)
	}
	stored.assertPreserved(t, f, "darwin-different-cwd-resource-ledger.json")
	f.WriteEvidence(t, "darwin-different-cwd-preservation.json", map[string]any{
		"workingDirectoryChanged": true, "sameExplicitEnrollment": true, "bothPublicOperationsReused": true,
		"sameExactHostAndRoles": true, "sameBroker": true, "sameVolume": true, "originalRecordRetained": true,
	})
}

func TestInstalledCLIDarwinRealComposeConflictingChildSelection(t *testing.T) {
	for _, key := range []string{"DOCKER_CONTEXT", "DOCKER_HOST"} {
		t.Run(key, func(t *testing.T) {
			f, s, r := composeDarwinCLIEnrolledFixture(t)
			x := composeDarwinCLIPrepare(t, f, s, r, "ensure")
			x.launch.Env = nil
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "DOCKER_CONTEXT=") && !strings.HasPrefix(entry, "DOCKER_HOST=") {
					x.launch.Env = append(x.launch.Env, entry)
				}
			}
			value := "agentmux_unselected_" + bootstrapFixtureRandom(t, 4)
			if key == "DOCKER_HOST" {
				value = "unix:///agentmux-unselected-engine.sock"
			}
			x.launch.Env = append(x.launch.Env, key+"="+value)
			darwinScenarioStart(t, f, x, darwinScenarioRefusalBudget)
			raw, success := x.wait(t, f, "darwin-conflicting-selection", darwinScenarioRefusalBudget)
			if success || x.lifetime != nil || len(raw) != 0 {
				t.Fatal("conflicting child selection started or attached a host")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			broker, err := f.ObserveBroker(ctx)
			cancel()
			if err != nil || broker.State != "absent" {
				t.Fatal("conflicting child selection created a stack")
			}
			ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			ids := append([]string{f.Profile.Docker.EngineID, "owner-status-service"}, bootstrapFixtureRoleLeaseIDs(f.Profile.Docker.EngineID)...)
			for _, id := range ids {
				lease, err := AcquireBootstrapLock(ctx, f.Profile.ProfileDirectory, f.Profile.InstanceID, id)
				if err != nil || lease == nil {
					cancel()
					f.RetainForRecovery(t)
					t.Fatal("negative startup left an owned lease held")
				}
				if lease.Close() != nil {
					cancel()
					f.RetainForRecovery(t)
					t.Fatal("negative startup lease control did not close")
				}
			}
			cancel()
			if !composeDarwinFailurePreservation(t, f, nil, "darwin-conflicting-selection-ledger.json") {
				f.RetainForRecovery(t)
				t.Fatal("conflicting selection left unverified added resources")
			}
			var diagnostic RequestDiagnostic
			actionable := protocol.DecodeClosedJSON(x.stderr.Bytes(), &diagnostic, 4096) == nil && ValidRequestDiagnostic(diagnostic) &&
				diagnostic.Kind == "launcher-diagnostic" && diagnostic.Code == "docker_environment_conflict" && diagnostic.Action == "use_enrolled_selection"
			f.WriteEvidence(t, "darwin-conflicting-selection-result.json", map[string]any{
				"conflictingChildVariable": key, "frontendRefused": true, "createdHost": false,
				"brokerAbsent": true, "leasesReleased": true, "unrelatedPreserved": true, "actionablePublicDiagnostic": actionable,
			})
			if !actionable {
				t.Fatal("actual conflicting selection lacks the closed actionable public diagnostic")
			}
		})
	}
}
