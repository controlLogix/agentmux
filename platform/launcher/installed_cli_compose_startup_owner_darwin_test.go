//go:build darwin && cgo && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"errors"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/internal/darwinfixtureidentity"
)

// Keep exact uncertain owners reachable until the test process exits. Merely
// retaining Docker resources would not prevent a file finalizer opening the gate.
var darwinStartupOwnerRecovery struct {
	sync.Mutex
	owners []struct {
		gate     *BootstrapLock
		frontend *composeDarwinCLIFront
		fixture  *bootstrapDockerFixture
	}
}

func darwinStartupOwnerRetainGate(f *bootstrapDockerFixture, frontend *composeDarwinCLIFront, gate *BootstrapLock) {
	darwinStartupOwnerRecovery.Lock()
	defer darwinStartupOwnerRecovery.Unlock()
	darwinStartupOwnerRecovery.owners = append(darwinStartupOwnerRecovery.owners, struct {
		gate     *BootstrapLock
		frontend *composeDarwinCLIFront
		fixture  *bootstrapDockerFixture
	}{gate, frontend, f})
}

// Prepare persistent data without starting a kernel. The later launch is a
// cold protected-runtime launch against a preexisting broker, not a cold broker.
func darwinStartupOwnerStoredBroker(t *testing.T, f *bootstrapDockerFixture) darwinScenarioStoredState {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	before, err := f.ObserveBroker(ctx)
	if err != nil || before.State != "absent" {
		t.Fatal("startup owner fixture requires an absent selected broker")
	}
	lease, err := AcquireBootstrapLock(ctx, f.Profile.ProfileDirectory, f.Profile.InstanceID, f.Profile.Docker.EngineID)
	if err != nil || lease == nil {
		t.Fatal("stored broker setup bootstrap lease unavailable")
	}
	t.Cleanup(func() {
		if lease.Close() != nil {
			f.RetainForRecovery(t)
			t.Error("stored broker setup lease cleanup failed")
		}
	})
	owner := f.Owner
	owner.LockHeld = true
	if f.Driver.StartOwned(ctx, owner, f.Config.Compose) != nil {
		f.RetainForRecovery(t)
		t.Fatal("selected stored broker setup failed")
	}
	actual, err := f.ObserveBroker(ctx)
	if err != nil || actual.State != "running" {
		f.RetainForRecovery(t)
		t.Fatal("stored broker setup ownership unavailable")
	}
	if _, err := deployment.ProvisionAndProbe(ctx, f.Config.Health); err != nil {
		f.RetainForRecovery(t)
		t.Fatal("actual stored broker health record setup failed")
	}
	if lease.Close() != nil {
		f.RetainForRecovery(t)
		t.Fatal("stored broker setup bootstrap lease did not release")
	}
	return darwinScenarioStored(t, f)
}

// These OS-lock observations establish a startup phase, never process authority.
// Only a previously retained native creator proof permits signaling the host.
func darwinStartupOwnerLeasesFree(t *testing.T, f *bootstrapDockerFixture, ctx context.Context, ids []string) {
	t.Helper()
	for _, id := range ids {
		lease, err := AcquireBootstrapLock(ctx, f.Profile.ProfileDirectory, f.Profile.InstanceID, id)
		if err != nil || lease == nil {
			f.RetainForRecovery(t)
			t.Fatal("startup owner lifetime lease was not released")
		}
		if lease.Close() != nil {
			f.RetainForRecovery(t)
			t.Fatal("startup owner lease observation close failed")
		}
	}
}

func darwinStartupOwnerWaitPhase(t *testing.T, f *bootstrapDockerFixture, x *composeDarwinCLIFront, ids []string) {
	t.Helper()
	if !x.creatorOwned() || len(x.lifetime.roles) != 0 {
		t.Fatal("startup phase needs only the retained creating host proof")
	}
	ctx, cancel := context.WithDeadline(context.Background(), x.output.started.Add(f.Config.StartupTimeout))
	defer cancel()
	for ctx.Err() == nil {
		if x.lifetime.host.Live() != nil {
			f.RetainForRecovery(t)
			t.Fatal("startup owner exited before its blocked phase")
		}
		allHeld := true
		for _, id := range ids {
			probe, stop := context.WithTimeout(ctx, 20*time.Millisecond)
			lease, err := AcquireBootstrapLock(probe, f.Profile.ProfileDirectory, f.Profile.InstanceID, id)
			stop()
			if lease != nil {
				if lease.Close() != nil {
					f.RetainForRecovery(t)
					t.Fatal("startup phase probe lease close failed")
				}
				allHeld = false
			} else if !errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
				f.RetainForRecovery(t)
				t.Fatal("startup phase lease denial was not established")
			}
		}
		if allHeld && x.lifetime.host.Live() == nil {
			return
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
		}
		timer.Stop()
	}
	f.RetainForRecovery(t)
	t.Fatal("creating host did not reach the blocked startup phase within its original budget")
}

func TestInstalledCLIDarwinRealComposeStartupOwnerDeathBeforeRoles(t *testing.T) {
	f, selection, record := composeDarwinCLIEnrolledFixture(t)
	stored := darwinStartupOwnerStoredBroker(t, f)
	f.AssertBaselineUnchanged(t)
	// Bootstrap acquires every role lease before calling runtime.Prepared.Start.
	// Holding the last lease allows the first three to prove progress while
	// preventing all role launches. This does not cover death after partial spawn.
	allIDs := []string{"owner-status-service", f.Profile.Docker.EngineID}
	roleIDs := make([]string, 0, len(f.Config.Roles))
	for _, role := range f.Config.Roles {
		roleIDs = append(roleIDs, f.Profile.Docker.EngineID+":runtime:"+role.ID)
	}
	allIDs = append(allIDs, roleIDs...)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	darwinStartupOwnerLeasesFree(t, f, ctx, allIDs)
	barrier, err := AcquireBootstrapLock(ctx, f.Profile.ProfileDirectory, f.Profile.InstanceID, roleIDs[len(roleIDs)-1])
	cancel()
	if err != nil || barrier == nil {
		t.Fatal("exact last-role startup barrier lease unavailable")
	}
	var original *composeDarwinCLIFront
	launchAttempted, exactHostExitProven := false, false
	// Registered first: the original frontend's cleanup runs before this guard.
	// A closed or unavailable proof never counts as proof of host exit.
	t.Cleanup(func() {
		if barrier.file == nil {
			return
		}
		if launchAttempted && !exactHostExitProven {
			if original != nil && original.creatorOwned() {
				cleanup, stop := context.WithTimeout(context.Background(), f.Config.Deadlines.StopGrace+f.Config.Deadlines.ReapTimeout)
				exactHostExitProven = original.lifetime.host.WaitExit(cleanup) == nil
				stop()
			}
			if !exactHostExitProven {
				darwinStartupOwnerRetainGate(f, original, barrier)
				f.RetainForRecovery(t)
				t.Error("startup host exit unknown; exact last-role gate and fixture retained")
				return
			}
		}
		if barrier.Close() != nil {
			f.RetainForRecovery(t)
			t.Error("owned last-role barrier close failed")
		}
	})
	original = composeDarwinCLIPrepare(t, f, selection, record, "ensure")
	original.mustOwnHost = true
	launchAttempted = true
	darwinScenarioStart(t, f, original, darwinScenarioEnsureBudget)
	out := darwinScenarioResponse(t, f, original, record, "darwin-startup-owner-blocked", darwinScenarioEnsureBudget, false)
	if !original.creatorOwned() || out == nil || out.Disposition != "starting" || !bridgeStartingUnknown(*out) ||
		out.StartupAttemptID == nil || *out.StartupAttemptID != original.lifetime.attempt {
		t.Fatal("blocked startup lacks authenticated starting state and its creating attempt")
	}
	heldByHost := append([]string{"owner-status-service", f.Profile.Docker.EngineID}, roleIDs[:len(roleIDs)-1]...)
	darwinStartupOwnerWaitPhase(t, f, original, heldByHost)
	if barrier.file == nil {
		t.Fatal("owned last-role barrier was lost")
	}
	if _, err := barrier.file.Stat(); err != nil {
		t.Fatal("owned last-role barrier descriptor unavailable")
	}
	if original.lifetime.host.Live() != nil {
		f.RetainForRecovery(t)
		t.Fatal("exact startup host proof is no longer live")
	}
	killedAt := time.Now()
	deadline := killedAt.Add(f.Config.Deadlines.StopGrace + f.Config.Deadlines.ReapTimeout)
	if original.lifetime.host.Signal(syscall.SIGKILL) != nil {
		f.RetainForRecovery(t)
		t.Fatal("exact startup host failure injection refused")
	}
	ctx, cancel = context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if original.join(ctx) != nil || !original.output.joined || original.lifetime.host.WaitExit(ctx) != nil {
		f.RetainForRecovery(t)
		t.Fatal("startup owner or frontend did not complete within the shared shutdown budget")
	}
	exactHostExitProven = true
	// Keep our last-role lock held while proving release of the host's locks.
	darwinStartupOwnerLeasesFree(t, f, ctx, heldByHost)
	if _, err := barrier.file.Stat(); err != nil {
		f.RetainForRecovery(t)
		t.Fatal("last-role barrier disappeared during owner exit")
	}
	if barrier.Close() != nil {
		f.RetainForRecovery(t)
		t.Fatal("last-role barrier release failed")
	}
	darwinStartupOwnerLeasesFree(t, f, ctx, allIDs)
	if ctx.Err() != nil || time.Now().After(deadline) {
		f.RetainForRecovery(t)
		t.Fatal("startup owner exit and lease release exceeded their shared budget")
	}
	cancel()
	f.WriteEvidence(t, "darwin-startup-owner-before-roles-exit.json", map[string]any{
		"scenario":                     "cold protected-runtime startup with preexisting broker and record",
		"injection":                    "SIGKILL through retained creator-proven host",
		"authenticatedStartingAttempt": true, "frontendWaitJoined": true, "exactHostExited": true,
		"hostLeaseDenialsBeforeInjection": len(heldByHost), "hostLeasesReleasedWhileBarrierHeld": len(heldByHost),
		"ownLastRoleBarrierReleased": true, "allRoleLeasesReleased": len(roleIDs),
		"sharedShutdownBudgetNanoseconds": int64(f.Config.Deadlines.StopGrace + f.Config.Deadlines.ReapTimeout),
		"elapsedNanoseconds":              time.Since(killedAt).Nanoseconds(),
		"properSubsetChildExitClaimed":    false,
	})
	stored.assertPreserved(t, f, "darwin-startup-owner-before-retry-ledger.json")
	recovered := composeDarwinCLIPrepare(t, f, selection, record, "ensure")
	recovered.mustOwnHost = true
	darwinScenarioStart(t, f, recovered, darwinScenarioEnsureBudget)
	darwinScenarioResponse(t, f, recovered, record, "darwin-startup-owner-retry", darwinScenarioEnsureBudget, true)
	darwinScenarioReady(t, f, recovered, "darwin-startup-owner-retry-ready.json")
	if recovered.lifetime.attempt == original.lifetime.attempt || !errors.Is(original.lifetime.host.Live(), darwinfixtureidentity.ErrExited) {
		t.Fatal("startup owner recovery reused the dead creating host")
	}
	stored.assertPreserved(t, f, "darwin-startup-owner-retry-preservation.json")
	f.WriteEvidence(t, "darwin-startup-owner-retry-summary.json", map[string]any{
		"newCreatorProvenHost": true, "newStartupAttempt": true, "realReadyRoleCount": len(recovered.lifetime.roles),
		"sameBroker": true, "sameVolume": true, "originalRecordRetained": true,
		"partialSpawnOwnerDeathClaimed": false,
	})
}
