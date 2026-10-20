//go:build darwin && arm64 && cgo && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
)

// The callback runs inside the existing reverse copier. Only real daemon bytes
// reach it; the request copier has already forwarded the request unchanged.
type endpointReadinessGate struct {
	mu                sync.Mutex
	health            deployment.ProbeOptions
	sequence          uint64
	entered           chan struct{}
	release           chan struct{}
	latched, disabled bool
	failure           error
}

func (g *endpointReadinessGate) before(ctx context.Context) error {
	g.mu.Lock()
	latched, disabled := g.latched, g.disabled
	g.mu.Unlock()
	if disabled {
		return nil
	}
	if !latched {
		probe, cancel := context.WithTimeout(ctx, time.Second)
		observed, err := deployment.Observe(probe, deployment.ObserveOptions{ProbeOptions: g.health, ReadExistingRecord: true})
		cancel()
		if err != nil {
			code := ProjectRequestDiagnostic(err).Code
			if code == "owned_cleanup_incomplete" || code == "runtime_authority_rejected" {
				g.mu.Lock()
				g.failure = errors.Join(g.failure, err)
				g.mu.Unlock()
				return err
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil && (!observed.BrokerVerified || observed.PersistenceEvidence != deployment.PersistenceRecordSeen ||
			(observed.RecordSequence != g.sequence && observed.RecordSequence != g.sequence+1)) {
			err = errors.New("endpoint_readiness_health_marker_invalid")
		}
		if err != nil {
			g.mu.Lock()
			g.failure = errors.Join(g.failure, err)
			g.mu.Unlock()
			return err
		}
		if observed.RecordSequence == g.sequence {
			return nil
		}
		g.mu.Lock()
		if !g.latched {
			g.latched = true
			close(g.entered)
		}
		g.mu.Unlock()
	}
	select {
	case <-g.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (g *endpointReadinessGate) disarm() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.disabled {
		g.disabled = true
		close(g.release)
	}
}

func TestInstalledCLIDarwinActualReadinessInspectionTimeoutAndRetry(t *testing.T) {
	p := endpointProxyPrepare(t)
	f, selection, record := composeDarwinCLIEnrolledFixture(t)
	p.evidence = f
	stored := darwinStartupOwnerStoredBroker(t, f)
	p.checkSocket(t)
	roleIDs := bootstrapFixtureRoleLeaseIDs(f.Profile.Docker.EngineID)
	allIDs := append([]string{"owner-status-service", f.Profile.Docker.EngineID}, roleIDs...)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	darwinStartupOwnerLeasesFree(t, f, ctx, allIDs)
	barrier, err := AcquireBootstrapLock(ctx, f.Profile.ProfileDirectory, f.Profile.InstanceID, roleIDs[len(roleIDs)-1])
	cancel()
	endpointProxyRequire(t, err == nil && barrier != nil, "readiness_timeout_initial_role_barrier")
	gate := &endpointReadinessGate{health: f.Config.Health, sequence: stored.sequence, entered: make(chan struct{}), release: make(chan struct{})}
	var original *composeDarwinCLIFront
	launched, exited, proxyJoined := false, false, false
	// Registered before the frontend's cleanup. An uncertain creator retains
	// the original barrier; an uncertain stream retains the original proxy.
	t.Cleanup(func() {
		if launched && !exited && original != nil && original.creatorOwned() {
			cleanup, stop := context.WithTimeout(context.Background(), f.Config.Deadlines.StopGrace+f.Config.Deadlines.ReapTimeout)
			exited = original.lifetime.host.WaitExit(cleanup) == nil
			stop()
		}
		if barrier.file != nil {
			if launched && !exited {
				darwinStartupOwnerRetainGate(f, original, barrier)
				f.RetainForRecovery(t)
				t.Error("readiness timeout creator exit unknown; exact role barrier retained")
			} else if barrier.Close() != nil {
				f.RetainForRecovery(t)
				t.Error("readiness timeout role barrier cleanup failed")
			}
		}
		if !proxyJoined {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			err := p.server.pause(cleanup)
			stop()
			if err != nil {
				endpointProxyRetained.Lock()
				endpointProxyRetained.servers = append(endpointProxyRetained.servers, p.server)
				endpointProxyRetained.Unlock()
				f.RetainForRecovery(t)
				t.Error("readiness timeout original proxy workers did not join")
				return
			}
			gate.disarm()
			gate.mu.Lock()
			gateFailure := gate.failure
			gate.mu.Unlock()
			if gateFailure != nil {
				// The retained server's disabled callback keeps any exact probe
				// transport cleanup owner reachable after cancellation.
				endpointProxyRetained.Lock()
				endpointProxyRetained.servers = append(endpointProxyRetained.servers, p.server)
				endpointProxyRetained.Unlock()
				f.RetainForRecovery(t)
				t.Error("readiness timeout marker observation or cleanup failed")
			} else {
				p.server.mu.Lock()
				p.server.beforeResponse = nil
				p.server.mu.Unlock()
			}
			if err == nil && p.server.resume() != nil {
				f.RetainForRecovery(t)
				t.Error("readiness timeout proxy cleanup resume failed")
			}
		}
	})
	original = composeDarwinCLIPrepare(t, f, selection, record, "ensure")
	original.mustOwnHost = true
	launched = true
	darwinScenarioStart(t, f, original, darwinScenarioEnsureBudget)
	out := darwinScenarioResponse(t, f, original, record, "readiness-timeout-starting", darwinScenarioEnsureBudget, false)
	endpointProxyRequire(t, original.creatorOwned() && out != nil && out.Disposition == "starting" && bridgeStartingUnknown(*out) &&
		out.StartupAttemptID != nil && *out.StartupAttemptID == original.lifetime.attempt, "readiness_timeout_authenticated_starting_required")
	held := append([]string{"owner-status-service", f.Profile.Docker.EngineID}, roleIDs[:len(roleIDs)-1]...)
	darwinStartupOwnerWaitPhase(t, f, original, held)
	// The authenticated reply establishes the initial HOST connection before
	// arming; that connection's own Docker admission cannot trigger the gate.
	p.server.mu.Lock()
	p.server.beforeResponse = gate.before
	p.server.mu.Unlock()
	endpointProxyRequire(t, barrier.Close() == nil, "readiness_timeout_initial_barrier_release")
	deadline := original.output.started.Add(f.Config.StartupTimeout + f.Config.Deadlines.StopGrace + f.Config.Deadlines.ReapTimeout)
	ctx, cancel = context.WithDeadline(context.Background(), deadline)
	defer cancel()
	select {
	case <-gate.entered:
	case <-ctx.Done():
		f.RetainForRecovery(t)
		t.Fatal("actual post-provision daemon response gate was not entered")
	}
	if original.lifetime.host.WaitExit(ctx) != nil {
		f.RetainForRecovery(t)
		t.Fatal("readiness timeout original host did not complete within unchanged startup and cleanup budgets")
	}
	exited = true
	// Cancel and join the original response copier before release. This avoids
	// writing a withheld response to the Docker process that already timed out.
	join, stop := context.WithTimeout(context.Background(), 5*time.Second)
	err = p.server.pause(join)
	stop()
	if err != nil {
		f.RetainForRecovery(t)
		t.Fatal("readiness timeout original proxy copies did not join")
	}
	gate.mu.Lock()
	gateFailure := gate.failure
	latched := gate.latched
	gate.mu.Unlock()
	endpointProxyRequire(t, latched && gateFailure == nil, "readiness_timeout_authenticated_marker_or_cleanup_failed")
	gate.disarm()
	p.server.mu.Lock()
	p.server.beforeResponse = nil
	p.server.mu.Unlock()
	endpointProxyRequire(t, p.server.resume() == nil, "readiness_timeout_proxy_resume")
	proxyJoined = true
	p.checkSocket(t)
	darwinStartupOwnerLeasesFree(t, f, ctx, allIDs)
	hostPolicy, err := LoadEnrolledHostPolicy(selection)
	endpointProxyRequire(t, err == nil, "readiness_timeout_current_policy_admission")
	_, owner, err := hostPolicy.Load()
	endpointProxyRequire(t, err == nil, "readiness_timeout_current_owner_admission")
	history, err := readBootstrapHistory(ctx, owner, record.RuntimeExecutable.Digest)
	endpointProxyRequire(t, err == nil && history != nil && history.InvocationID == original.lifetime.attempt && history.DiagnosticStage != nil &&
		*history.DiagnosticStage == "readiness_inspection" && history.DiagnosticCode == "docker_command_timeout_outcome_unknown", "readiness_timeout_exact_boundary_required")
	status := composeDarwinCLIStart(t, f, selection, record, "status", false)
	raw, success := status.wait(t, f, "readiness-timeout-terminal", darwinScenarioRefusalBudget)
	terminal, code := composeCLIFailureHistoryCode(raw, original.lifetime.attempt, time.Now())
	endpointProxyRequire(t, !success && !status.creatorOwned() && code == "" && terminal.Diagnostic == requestDiagnostic("docker_command_timeout_outcome_unknown"), "readiness_timeout_owner_bound_terminal_failure")
	stored.assertPreserved(t, f, "readiness-timeout-negative-preservation.json")
	f.WriteEvidence(t, "readiness-timeout-result.json", map[string]any{
		"responseGateEnteredAfterAuthenticatedHealthWrite": true, "diagnosticStage": *history.DiagnosticStage, "diagnostic": terminal.Diagnostic,
		"unchangedStartupBudgetNanoseconds": int64(f.Config.StartupTimeout), "fullStartupBudgetExhaustionClaimed": false,
		"exactCreatorExited": true, "allRuntimeLeasesReleased": true, "originalProxyCopiesJoined": true,
	})
	retry := composeDarwinCLIStart(t, f, selection, record, "ensure", true)
	darwinScenarioResponse(t, f, retry, record, "readiness-timeout-retry", darwinScenarioEnsureBudget, true)
	darwinScenarioReady(t, f, retry, "readiness-timeout-retry-ready.json")
	endpointProxyRequire(t, retry.lifetime.attempt != original.lifetime.attempt, "readiness_timeout_corrected_attempt_not_fresh")
	stored.assertPreserved(t, f, "readiness-timeout-retry-preservation.json")
	profile, err := LoadProfile(f.Config.ProfilePolicy)
	endpointProxyRequire(t, err == nil && reflect.DeepEqual(profile.Declaration(), f.Profile), "readiness_timeout_profile_changed")
	currentPolicy, err := LoadEnrolledHostPolicy(selection)
	endpointProxyRequire(t, err == nil && reflect.DeepEqual(currentPolicy.record, record), "readiness_timeout_enrollment_changed")
}
