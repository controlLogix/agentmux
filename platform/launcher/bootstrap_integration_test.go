//go:build (linux || darwin) && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	protected "github.com/controlLogix/agentmux/platform/runtime"
	"github.com/nats-io/nats.go"
)

func bootstrapFixtureGroup(t *testing.T, session *Session) *protected.Group {
	t.Helper()
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.group == nil {
		t.Fatal("started session has no owned protected group")
	}
	return session.group
}

func bootstrapFixtureChildren(t *testing.T, group *protected.Group) []protected.ProcessStatus {
	t.Helper()
	states := group.Status()
	seen := map[int]bool{}
	if len(states) != 4 {
		t.Fatal("protected assembly did not start four children")
	}
	for _, state := range states {
		if state.Exited || state.PID <= 0 || seen[state.PID] {
			t.Fatal("protected child identities are not distinct and live")
		}
		seen[state.PID] = true
	}
	return states
}

func bootstrapFixtureSameChildren(t *testing.T, group *protected.Group, before []protected.ProcessStatus) {
	t.Helper()
	after := bootstrapFixtureChildren(t, group)
	for i, state := range after {
		if state.Role != before[i].Role || state.PID != before[i].PID {
			t.Fatal("reuse replaced an owned protected child")
		}
	}
}

func bootstrapFixtureRecord(t *testing.T, c BootstrapConfig, sequence uint64) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if c.Health.TLS == nil {
		t.Fatal("persistence reader lacks enrolled server trust")
	}
	dialer, err := c.Health.TLS.NewDialer(ctx, time.Second)
	if err != nil {
		t.Fatal("persistence reader trust unavailable")
	}
	defer dialer.Close()
	conn, err := nats.Connect(c.Health.Endpoint, nats.SetCustomDialer(dialer), nats.TLSHandshakeFirst(), nats.UserInfo(deployment.HealthUser, c.Health.Password), nats.NoReconnect(), nats.IgnoreDiscoveredServers(), nats.Timeout(time.Second))
	if err != nil {
		t.Fatal("persistence reader could not authenticate")
	}
	defer conn.Close()
	js, err := conn.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal("persistence reader unavailable")
	}
	message, err := js.GetMsg(deployment.HealthStream(c.Health.HubID), sequence)
	if err != nil || message.Sequence != sequence || message.Subject != deployment.HealthSubject(c.Health.HubID) || len(message.Data) == 0 || len(message.Data) > 512 {
		t.Fatal("original persistence record unavailable")
	}
	digest := sha256.Sum256(message.Data)
	return hex.EncodeToString(digest[:])
}

func bootstrapFixtureRoleLeases(t *testing.T, f *bootstrapDockerFixture, held bool) {
	t.Helper()
	for _, role := range f.Config.Roles {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		lease, err := AcquireBootstrapLock(ctx, f.Profile.ProfileDirectory, f.Profile.InstanceID, f.Profile.Docker.EngineID+":runtime:"+role.ID)
		cancel()
		if held {
			if lease != nil {
				lease.Close()
				t.Fatal("live role released its inherited lifetime lease")
			}
			var elsewhere *StartingElsewhereError
			if !errors.As(err, &elsewhere) {
				t.Fatal("role lease refusal was not an owned contention result")
			}
		} else {
			if err != nil || lease == nil {
				t.Fatal("reaped role retained its lifetime lease")
			}
			if lease.Close() != nil {
				t.Fatal("observed role lease cleanup failed")
			}
		}
	}
}

func bootstrapFixtureReaped(t *testing.T, group *protected.Group, budget time.Duration) {
	t.Helper()
	select {
	case <-group.Done():
	case <-time.After(budget):
		t.Fatal("owner lifetime did not reap protected children")
	}
	if group.CleanupError() != nil {
		t.Fatal("owned descriptor cleanup failed")
	}
	for _, state := range group.Status() {
		if !state.Exited {
			t.Fatal("owned child remains live after owner shutdown")
		}
	}
}

func bootstrapFixtureBroker(t *testing.T, f *bootstrapDockerFixture) OwnedBroker {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	broker, err := f.ObserveBroker(ctx)
	if err != nil {
		t.Fatal("actual owned broker observation failed")
	}
	return broker
}

// Only closed implementation codes may enter public fixture evidence. Unknown
// error text can contain paths, broker credentials or command output.
func bootstrapFixtureFailureCode(err error) string {
	if err == nil {
		return "none"
	}
	var waiting *StartingElsewhereError
	if errors.As(err, &waiting) {
		if errors.Is(err, context.DeadlineExceeded) {
			return "bootstrap_waiting_for_owner_deadline"
		}
		if errors.Is(err, context.Canceled) {
			return "bootstrap_waiting_for_owner_cancelled"
		}
		return "bootstrap_waiting_for_owner"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "context_deadline"
	}
	if errors.Is(err, context.Canceled) {
		return "context_cancelled"
	}
	approved := strings.Fields(`bootstrap_context_invalid bootstrap_probe_limits_invalid bootstrap_attempt_unavailable bootstrap_local_profile_required bootstrap_enrollment_binding_mismatch bootstrap_local_port_invalid bootstrap_broker_config_binding_invalid bootstrap_assembly_preparation_failed bootstrap_observation_deadline bootstrap_existing_runtime_not_ready bootstrap_owned_cleanup_incomplete bootstrap_broker_not_running bootstrap_protected_start_failed bootstrap_lifetime_cancelled bootstrap_protected_process_exited bootstrap_lease_close_failed bootstrap_readiness_deadline bootstrap_role_profile_invalid bootstrap_role_binding_invalid bootstrap_role_file_invalid bootstrap_role_credentials_invalid docker_command_timeout_outcome_unknown docker_command_failed docker_output_limit docker_invalid_observation docker_environment_conflict docker_config_binding_mismatch docker_unsupported_compose docker_unsupported_inline_config docker_nonprivate_port docker_unowned_compose_resource docker_unowned_compose_service docker_resource_owner_mismatch docker_ownership_preflight_missing kernel_status_authority_rejected kernel_status_deadline kernel_status_invalid kernel_status_cancelled kernel_status_unavailable kernel_status_owned_connection_cleanup_failed health_options_invalid health_endpoint_invalid health_tls_endpoint_mismatch health_context_invalid health_deadline health_tls_transport_invalid health_connection_cleanup_failed health_connect_failed health_broker_identity_mismatch health_context_failed health_domain_unavailable health_stream_unavailable health_stream_incompatible health_record_failed health_write_failed health_read_failed bootstrap_local_tls_required bootstrap_role_server_trust_invalid bootstrap_local_broker_authority_invalid bootstrap_local_broker_authority_unavailable`)
	for _, code := range approved {
		if err.Error() == code {
			return code
		}
	}
	return "unclassified_private_error"
}

func bootstrapFixtureFailureStage(err error) string {
	var waiting *StartingElsewhereError
	if errors.As(err, &waiting) {
		return "bootstrap_lease"
	}
	var staged interface{ inspectionStage() string }
	if errors.As(err, &staged) {
		switch stage := staged.inspectionStage(); stage {
		case "endpoint", "version", "engine", "compose_version", "roster", "authority_inspection", "tls_connect", "snapshot":
			return stage
		}
	}
	return "unknown"
}

func TestBootstrapFixtureFailureCodesDoNotExposePrivateText(t *testing.T) {
	for _, value := range []string{"fixture-private-password", "/private/profile/path", "docker_command_failed: fixture-private-password", "bootstrap_readiness_deadline\n/private/path"} {
		if bootstrapFixtureFailureCode(errors.New(value)) != "unclassified_private_error" {
			t.Fatal("private error text entered fixture evidence")
		}
	}
	if bootstrapFixtureFailureCode(errors.New("docker_command_failed")) != "docker_command_failed" || bootstrapFixtureFailureCode(context.DeadlineExceeded) != "context_deadline" {
		t.Fatal("safe failure classification lost")
	}
}

// This diagnostic performs identity reads only. It creates no project, volume,
// container, profile or protected process and cannot substitute for bootstrap.
func TestBootstrapRealDockerIdentityPreflight(t *testing.T) {
	if os.Getenv("AMX_BOOTSTRAP_DOCKER_AUTHORIZED") != "1" {
		t.Fatal("explicit Docker diagnostic authorization required")
	}
	selected, _ := loadBootstrapFixtureSelection(t)
	driver, err := NewDocker(selected.dockerConfig())
	if err != nil {
		t.Fatal("fixed diagnostic selection was refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	_, err = driver.Inspect(ctx)
	t.Logf("read-only identity diagnostic: elapsedMs=%d failureCode=%s stage=%s", time.Since(started).Milliseconds(), bootstrapFixtureFailureCode(err), bootstrapFixtureFailureStage(err))
	if err != nil {
		t.Fatal("read-only identity preflight failed")
	}
}

// This measures two simultaneous read-only inspections of an absent project.
// It never starts containers, creates a volume or prepares protected children.
func TestBootstrapRealDockerConcurrentAbsentInspection(t *testing.T) {
	if os.Getenv("AMX_BOOTSTRAP_DOCKER_AUTHORIZED") != "1" {
		t.Fatal("explicit Docker diagnostic authorization required")
	}
	selected, _ := loadBootstrapFixtureSelection(t)
	driver, err := NewDocker(selected.dockerConfig())
	if err != nil {
		t.Fatal("fixed diagnostic selection was refused")
	}
	owner := OwnershipPreflight{Project: "amx-p02-read-" + bootstrapFixtureRandom(t, 8), InstanceID: "instance_read", ProfileID: "profile_" + bootstrapFixtureRandom(t, 16), ReleaseDigest: "sha256:" + strings.Repeat("a", 64)}
	barrier := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer workers.Done()
			<-barrier
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			started := time.Now()
			broker, err := driver.InspectOwnedBroker(ctx, owner, selected.Image, 4222, sha256.Sum256([]byte("read-only absent diagnostic")))
			t.Logf("read-only concurrent absent inspection: elapsedMs=%d failureCode=%s stage=%s", time.Since(started).Milliseconds(), bootstrapFixtureFailureCode(err), bootstrapFixtureFailureStage(err))
			if err != nil || broker.State != "absent" || broker.ContainerID != "" {
				t.Error("concurrent read-only absent inspection failed")
			}
		}()
	}
	close(barrier)
	workers.Wait()
}

func bootstrapFixtureOwnerStatus(t *testing.T, f *bootstrapDockerFixture) *OwnerStatus {
	t.Helper()
	scope := f.Config.Kernel.Scope
	organization := f.Profile.OrganizationID
	if organization == "" {
		organization = "fixture_org"
	}
	var project *string
	if f.Profile.ProjectID != "" {
		value := f.Profile.ProjectID
		project = &value
	}
	enrollment := OwnerEnrollment{SchemaVersion: "1.0.0", OwnerUID: f.Profile.OwnerUID, PrincipalID: "fixture_owner", Identity: OwnerIdentityReference{ID: "fixture_owner_record", OwnerHubID: scope.HubID, Revision: 1}, Scope: OwnerScope{OrganizationID: organization, ProjectID: project}, InstanceID: scope.InstanceID, ProfileID: scope.ProfileID, ReleaseFingerprint: scope.ReleaseManifestDigest}
	if err := os.WriteFile(filepath.Join(f.Profile.ProfileDirectory, "status-owner.json"), mustStatusJSON(enrollment), 0600); err != nil {
		t.Fatal("explicit disposable owner enrollment failed")
	}
	owner, err := LoadOwnerStatus(OwnerPolicy{Profile: f.Config.ProfilePolicy, Enrollment: enrollment, KernelScope: scope, ServerName: f.Config.Health.ServerName, Domain: f.Config.Health.Domain, PublicEndpoint: f.Config.Health.Endpoint, PublicContextName: f.Profile.Docker.Context})
	if err != nil {
		t.Fatal("actual disposable owner enrollment was rejected")
	}
	return owner
}

func bootstrapFixturePublicStatus(t *testing.T, f *bootstrapDockerFixture, session *Session, owner *OwnerStatus, name, readiness string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := session.OwnerObservationContext(ctx, owner)
	proofAge := int64(-1)
	if session.healthProof != nil {
		proofAge = time.Since(session.healthProof.completedAt).Milliseconds()
	}
	t.Logf("actual status receipt: snapshotAgeMs=%d writeProofAgeMs=%d", time.Since(session.observedAt).Milliseconds(), proofAge)
	if err == nil {
		f.WriteEvidence(t, name, result)
	}
	if err != nil || result.Disposition != session.Status.Disposition || result.StartupAttemptID == nil || *result.StartupAttemptID != session.startupAttemptID || result.Persistence.Readiness != readiness || result.Instance.Readiness != "degraded" || result.Work.State != "unavailable" || result.Hubs.InventoryState != "unavailable" {
		t.Fatalf("actual bootstrap status mismatch: error=%t disposition=%s persistence=%s expectedPersistence=%s instance=%s work=%s hubs=%s", err != nil, result.Disposition, result.Persistence.Readiness, readiness, result.Instance.Readiness, result.Work.State, result.Hubs.InventoryState)
	}
}

// This selection requires an explicitly authorized, real disposable Compose
// project. Neither a fake CLI nor a native broker with altered listener/storage
// flags can substitute for the private factory configuration being inspected.
func TestBootstrapRealComposeConcurrentColdWarmAndOwnerRecovery(t *testing.T) {
	if os.Getenv("AMX_BOOTSTRAP_DOCKER_AUTHORIZED") != "1" {
		t.Fatal("explicit disposable Docker authorization required")
	}
	f := newBootstrapDockerFixture(t)
	statusOwner := bootstrapFixtureOwnerStatus(t, f)
	shutdownBudget := f.Config.Deadlines.StopGrace + f.Config.Deadlines.ReapTimeout + time.Second
	startup, cancelStartup := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelStartup()
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	defer cancelLifetime()
	before, err := f.ObserveBroker(startup)
	if err != nil || before.State != "absent" || before.ContainerID != "" {
		t.Fatal("fresh enrolled project was not absent")
	}
	type outcome struct {
		session *Session
		err     error
	}
	results := make(chan outcome, 2)
	barrier := make(chan struct{})
	var workers sync.WaitGroup
	var sessionsMu sync.Mutex
	var sessions []*Session
	var failureCodes []string
	var failureStages []string
	var elapsedMillis []int64
	var resultDispositions []string
	workersDone := make(chan struct{})
	// This hook runs before the fixture hook. Even a fatal assertion must join
	// both actual Bootstrap calls before inspecting or stopping their resources.
	t.Cleanup(func() {
		cancelStartup()
		cancelLifetime()
		select {
		case <-workersDone:
		case <-time.After(f.Config.StartupTimeout + shutdownBudget):
			// Retain private state rather than stopping a project while a bootstrap
			// call may still mutate it. This is an explicit failed cleanup result.
			f.RetainForRecovery(t)
			t.Error("concurrent bootstrap cleanup did not join; owned state retained")
			return
		}
		sessionsMu.Lock()
		owned := append([]*Session(nil), sessions...)
		codes := append([]string(nil), failureCodes...)
		stages := append([]string(nil), failureStages...)
		durations := append([]int64(nil), elapsedMillis...)
		dispositions := append([]string(nil), resultDispositions...)
		sessionsMu.Unlock()
		f.WriteEvidence(t, "bootstrap-call-results.json", map[string]any{"completedCalls": len(codes), "failureCodes": codes, "failureStages": stages, "elapsedMillis": durations, "resultDispositions": dispositions})
		for _, session := range owned {
			ctx, cancel := context.WithTimeout(context.Background(), shutdownBudget)
			err := session.Close(ctx)
			cancel()
			if err != nil {
				t.Error("joined bootstrap session cleanup failed")
			}
		}
	})
	for i := 0; i < 2; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-barrier
			attemptID := "attempt_" + bootstrapFixtureRandom(t, 16)
			callStarted := time.Now()
			session, err := BootstrapForInvocation(startup, lifetime, f.Config, attemptID)
			callDuration := time.Since(callStarted)
			if session != nil && session.startupAttemptID != attemptID {
				err = bootstrapError("invocation_invalid")
			}
			sessionsMu.Lock()
			failureCodes = append(failureCodes, bootstrapFixtureFailureCode(err))
			failureStages = append(failureStages, bootstrapFixtureFailureStage(err))
			elapsedMillis = append(elapsedMillis, callDuration.Milliseconds())
			disposition := "none"
			if session != nil {
				disposition = session.Status.Disposition
			}
			resultDispositions = append(resultDispositions, disposition)
			sessionsMu.Unlock()
			if session != nil {
				sessionsMu.Lock()
				sessions = append(sessions, session)
				sessionsMu.Unlock()
			}
			results <- outcome{session, err}
		}()
	}
	go func() { workers.Wait(); close(workersDone) }()
	close(barrier)
	var owner, reused *Session
	for i := 0; i < 2; i++ {
		select {
		case result := <-results:
			if result.err != nil || result.session == nil {
				t.Fatalf("concurrent actual bootstrap failed: %s stage=%s", bootstrapFixtureFailureCode(result.err), bootstrapFixtureFailureStage(result.err))
			}
			switch result.session.Status.Disposition {
			case "started":
				if owner != nil {
					t.Fatal("concurrent calls started duplicate protected groups")
				}
				owner = result.session
				bootstrapFixturePublicStatus(t, f, owner, statusOwner, "cold-owner-status.json", "ready")
			case "reused":
				if reused != nil {
					t.Fatal("concurrent calls did not identify one startup owner")
				}
				reused = result.session
				bootstrapFixturePublicStatus(t, f, reused, statusOwner, "concurrent-reuse-status.json", "unknown")
			default:
				t.Fatal("bootstrap disposition invalid")
			}
		case <-startup.Done():
			t.Fatal("concurrent actual bootstrap exceeded startup deadline")
		}
	}
	if owner == nil || reused == nil {
		t.Fatal("concurrent cold callers did not converge on one owner")
	}
	cancelStartup()
	group := bootstrapFixtureGroup(t, owner)
	initialChildren := bootstrapFixtureChildren(t, group)
	for _, session := range []*Session{owner, reused} {
		if session.Status.Kernel.KernelReadiness != "ready" || session.Status.Kernel.Scope != f.Config.Kernel.Scope || session.Status.Persistence.PersistenceEvidence != deployment.PersistenceRecordSeen || session.Status.Persistence.RecordSequence == 0 {
			t.Fatal("actual readiness or persistence evidence missing")
		}
	}
	if reused.group != nil || reused.lock != nil || reused.Status.Kernel.Incarnation != owner.Status.Kernel.Incarnation {
		t.Fatal("reuse took process ownership or observed a different runtime")
	}
	broker := bootstrapFixtureBroker(t, f)
	if broker.State != "running" || broker.ContainerID == "" {
		t.Fatal("actual owned container identity unavailable")
	}
	f.AssertBaselineUnchanged(t)
	sequence := owner.Status.Persistence.RecordSequence
	originalRecord := bootstrapFixtureRecord(t, f.Config, sequence)
	bootstrapFixtureRoleLeases(t, f, true)
	closeCtx, closeCancel := context.WithTimeout(context.Background(), time.Second)
	err = reused.Close(closeCtx)
	closeCancel()
	if err != nil {
		t.Fatal("reused session close failed")
	}
	bootstrapFixtureSameChildren(t, group, initialChildren)

	warmContext, cancelWarmContext := context.WithTimeout(context.Background(), 60*time.Second)
	warmStarted := time.Now()
	warm, err := Bootstrap(warmContext, context.Background(), f.Config)
	cancelWarmContext()
	if err != nil || warm == nil || warm.Status.Disposition != "reused" || warm.group != nil || warm.lock != nil {
		disposition := "no_session"
		ownsGroup, ownsLock := false, false
		if warm != nil {
			switch warm.Status.Disposition {
			case "started", "reused":
				disposition = warm.Status.Disposition
			default:
				disposition = "unclassified"
			}
			ownsGroup, ownsLock = warm.group != nil, warm.lock != nil
		}
		f.WriteEvidence(t, "warm-failure.json", map[string]any{"failureCode": bootstrapFixtureFailureCode(err), "failureStage": bootstrapFixtureFailureStage(err), "elapsedMillis": time.Since(warmStarted).Milliseconds(), "disposition": disposition, "ownsGroup": ownsGroup, "ownsLock": ownsLock})
		t.Fatalf("warm launch did not reuse without ownership: code=%s stage=%s elapsedMs=%d disposition=%s ownsGroup=%t ownsLock=%t", bootstrapFixtureFailureCode(err), bootstrapFixtureFailureStage(err), time.Since(warmStarted).Milliseconds(), disposition, ownsGroup, ownsLock)
	}
	if warm.Status.Kernel.Incarnation != owner.Status.Kernel.Incarnation || warm.Status.Persistence.RecordSequence != sequence {
		t.Fatal("warm reuse replaced runtime or persistence identity")
	}
	bootstrapFixturePublicStatus(t, f, warm, statusOwner, "warm-reuse-status.json", "unknown")
	closeCtx, closeCancel = context.WithTimeout(context.Background(), time.Second)
	err = warm.Close(closeCtx)
	closeCancel()
	if err != nil {
		t.Fatal("warm reuse close failed")
	}
	bootstrapFixtureSameChildren(t, group, initialChildren)
	warmBroker := bootstrapFixtureBroker(t, f)
	if warmBroker.ContainerID != broker.ContainerID {
		t.Fatal("warm reuse recreated broker")
	}
	if bootstrapFixtureRecord(t, f.Config, sequence) != originalRecord {
		t.Fatal("warm reuse changed stored evidence")
	}
	f.AssertBaselineUnchanged(t)
	f.WriteEvidence(t, "concurrent-warm.json", map[string]any{"scope": "Actual Compose plus signed protected processes; not native macOS or whole phase acceptance", "startedSessions": 1, "reusedConcurrentSessions": 1, "liveProtectedChildren": initialChildren, "sameContainerAfterWarm": true, "sameKernelIncarnationAfterWarm": true, "originalPersistenceRecordRetained": true, "retainedRoleLeases": 4, "composeUpCallCountObserved": false})

	cancelLifetime()
	bootstrapFixtureReaped(t, group, shutdownBudget)
	bootstrapFixtureRoleLeases(t, f, false)
	closeCtx, closeCancel = context.WithTimeout(context.Background(), shutdownBudget)
	err = owner.Close(closeCtx)
	closeCancel()
	if err != nil || owner.CleanupError() != nil {
		t.Fatal("owner session cleanup failed")
	}
	stillRunning := bootstrapFixtureBroker(t, f)
	if stillRunning.State != "running" || stillRunning.ContainerID != broker.ContainerID {
		t.Fatal("kernel owner cleanup modified broker ownership")
	}
	if bootstrapFixtureRecord(t, f.Config, sequence) != originalRecord {
		t.Fatal("owner cleanup removed persistence record")
	}
	f.AssertBaselineUnchanged(t)

	recoveryContext, cancelRecoveryContext := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelRecoveryContext()
	recoveryLifetime, cancelRecoveryLifetime := context.WithCancel(context.Background())
	defer cancelRecoveryLifetime()
	recoveryStarted := time.Now()
	recovered, err := Bootstrap(recoveryContext, recoveryLifetime, f.Config)
	if recovered != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), shutdownBudget)
			defer cancel()
			if recovered.Close(ctx) != nil {
				t.Error("recovery cleanup failed")
			}
		})
	}
	if err != nil || recovered == nil || recovered.Status.Disposition != "started" || recovered.Status.Kernel.KernelReadiness != "ready" {
		f.WriteEvidence(t, "recovery-failure.json", map[string]any{"failureCode": bootstrapFixtureFailureCode(err), "failureStage": bootstrapFixtureFailureStage(err), "elapsedMillis": time.Since(recoveryStarted).Milliseconds(), "hasSession": recovered != nil})
		t.Fatalf("owned runtime recovery failed: code=%s stage=%s elapsedMs=%d hasSession=%t", bootstrapFixtureFailureCode(err), bootstrapFixtureFailureStage(err), time.Since(recoveryStarted).Milliseconds(), recovered != nil)
	}
	bootstrapFixturePublicStatus(t, f, recovered, statusOwner, "recovered-owner-status.json", "ready")
	recoveredGroup := bootstrapFixtureGroup(t, recovered)
	if recoveredGroup == group {
		t.Fatal("recovery adopted the old protected group")
	}
	recoveredChildren := bootstrapFixtureChildren(t, recoveredGroup)
	if recovered.Status.Kernel.Incarnation == owner.Status.Kernel.Incarnation {
		t.Fatal("recovery reused a dead kernel incarnation")
	}
	recoveredBroker := bootstrapFixtureBroker(t, f)
	if recoveredBroker.ContainerID != broker.ContainerID {
		t.Fatal("runtime recovery recreated compatible broker")
	}
	if bootstrapFixtureRecord(t, f.Config, sequence) != originalRecord {
		t.Fatal("runtime recovery lost original persistence record")
	}
	bootstrapFixtureRoleLeases(t, f, true)
	cancelRecoveryLifetime()
	bootstrapFixtureReaped(t, recoveredGroup, shutdownBudget)
	bootstrapFixtureRoleLeases(t, f, false)
	f.AssertBaselineUnchanged(t)
	f.WriteEvidence(t, "recovery.json", map[string]any{"originalChildrenReaped": group.Status(), "recoveredLiveChildren": recoveredChildren, "recoveredChildrenReaped": recoveredGroup.Status(), "kernelIncarnationChanged": true, "sameContainerAfterRecovery": true, "originalPersistenceRecordRetained": true, "retainedRoleLeasesReleased": 4, "cleanupError": false, "trigger": "host lifetime context cancelled; abrupt host death is qualified separately"})
}

func TestBootstrapFixtureIdentifiesBoundedOwnerWait(t *testing.T) {
	err := &StartingElsewhereError{AttemptID: strings.Repeat("a", 32), Cause: context.DeadlineExceeded}
	if bootstrapFixtureFailureCode(err) != "bootstrap_waiting_for_owner_deadline" || bootstrapFixtureFailureStage(err) != "bootstrap_lease" {
		t.Fatal("owner wait hidden as an unrelated deadline")
	}
}
