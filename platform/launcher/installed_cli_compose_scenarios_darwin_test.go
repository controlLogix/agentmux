//go:build darwin && cgo && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/internal/darwinfixtureidentity"
	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/nats-io/nats.go"
)

// Only validated public observations enter this failure summary. The observer
// uses this test's existing protected credential and never publishes controls.
type darwinRecoveryObservation struct {
	CapturedAt   string                       `json:"capturedAt"`
	Owner        *StartupStatusObservation    `json:"lastValidatedOwnerReply"`
	OwnerCode    string                       `json:"lastOwnerDiagnostic"`
	Kernel       *protocol.Snapshot           `json:"lastValidatedKernelSnapshot"`
	KernelCode   string                       `json:"lastKernelDiagnostic"`
	Inventory    *protocol.LifecycleInventory `json:"lastValidatedLifecycleInventory"`
	Results      []protocol.LifecycleResult   `json:"lastValidatedLifecycleResults"`
	Events       map[string]protocol.Event    `json:"lastValidatedRoleEvents"`
	ObserverCode string                       `json:"observerDiagnostic"`
	drain        func()
}

func darwinScenarioLifecycleObservation(t *testing.T, f *bootstrapDockerFixture, ctx context.Context, observation *darwinRecoveryObservation) {
	t.Helper()
	dialer, err := f.Config.Kernel.TLS.NewDialer(ctx, time.Second)
	if err != nil {
		t.Fatal("recovery diagnostic enrolled TLS observer refused")
	}
	owned := &darwinSlowConsumerConnection{dialer: dialer, callbacksDone: make(chan struct{})}
	t.Cleanup(func() {
		if owned.close() != nil {
			f.RetainForRecovery(t)
			t.Error("recovery diagnostic exact observer cleanup failed")
		}
	})
	faults := make(chan error, 16)
	var overflow atomic.Bool
	owned.connection, err = nats.Connect(f.Config.Kernel.Endpoint,
		nats.UserInfo("kernel-lifecycle", f.Config.brokerUsers["kernel-lifecycle"]),
		nats.TLSHandshakeFirst(), nats.SetCustomDialer(dialer), nats.IgnoreDiscoveredServers(),
		nats.Timeout(time.Second), nats.MaxReconnects(120), nats.ReconnectWait(200*time.Millisecond), nats.ReconnectBufSize(0),
		nats.ClosedHandler(func(*nats.Conn) { close(owned.callbacksDone) }),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, failure error) {
			select {
			case faults <- failure:
			default:
				overflow.Store(true)
			}
		}))
	if err != nil || owned.connection == nil || owned.connection.ConnectedServerName() != f.Config.Health.ServerName || owned.connection.ConnectedServerVersion() != f.Config.Health.ServerVersion {
		t.Fatal("recovery diagnostic protected observer authentication refused")
	}
	wire, err := communication.Subjects(f.Config.Kernel.Scope.HubID)
	if err != nil {
		t.Fatal("recovery diagnostic protected subjects refused")
	}
	type received struct {
		message *nats.Msg
		at      time.Time
	}
	frames := make(chan received, 256)
	subjects := []string{wire.Commands["kernel-lifecycle"]}
	for _, role := range protocol.Roles() {
		subjects = append(subjects, wire.Events[role])
	}
	for _, subject := range subjects {
		sub, err := owned.connection.Subscribe(subject, func(message *nats.Msg) {
			if len(message.Data) > protocol.MaxPayload {
				overflow.Store(true)
				return
			}
			select {
			case frames <- received{message, time.Now()}:
			default:
				overflow.Store(true)
			}
		})
		if err != nil || sub.SetPendingLimits(128, 128*protocol.MaxPayload) != nil {
			t.Fatal("recovery diagnostic protected subscription refused")
		}
		t.Cleanup(func() {
			if sub.IsValid() && sub.Unsubscribe() != nil {
				t.Error("recovery diagnostic subscription cleanup failed")
			}
		})
	}
	if owned.connection.FlushWithContext(ctx) != nil {
		t.Fatal("recovery diagnostic protected subscription did not flush")
	}
	observation.Events = map[string]protocol.Event{}
	observation.drain = func() {
		for count := 0; count < cap(frames) && len(frames) > 0; count++ {
			frame := <-frames
			if frame.message.Reply != "" || len(frame.message.Header) != 0 {
				continue
			}
			if frame.message.Subject == wire.Commands["kernel-lifecycle"] {
				if value, err := protocol.DecodeLifecycleInventory(frame.message.Data, f.Config.Kernel.Scope, frame.at); err == nil {
					observation.Inventory = &value
				} else if value, err := protocol.DecodeLifecycleResult(frame.message.Data, f.Config.Kernel.Scope, frame.at); err == nil {
					if len(observation.Results) == 8 {
						observation.Results = observation.Results[1:]
					}
					observation.Results = append(observation.Results, value)
				}
				continue
			}
			for _, role := range protocol.Roles() {
				if frame.message.Subject == wire.Events[role] {
					if value, err := protocol.DecodeEvent(frame.message.Data, f.Config.Kernel.Scope, role, frame.at, 3*time.Second); err == nil {
						observation.Events[role] = value
					}
				}
			}
		}
		for count := 0; count < cap(faults) && len(faults) > 0; count++ {
			observation.ObserverCode = ProjectRequestDiagnostic(<-faults).Code
		}
		if overflow.Load() {
			observation.ObserverCode = "bounded_observer_overflow"
		}
	}
}

const (
	darwinScenarioEnsureBudget   = 10 * time.Second
	darwinScenarioRefusalBudget  = 5 * time.Second
	darwinScenarioRecoveryBudget = 30 * time.Second
)

// Recovery may truthfully report failed members while replacement is in flight.
// Only a fresh authenticated owner reply and genuine current kernel snapshot
// complete this wait. All retries share the caller's original deadline.
func darwinScenarioRecovered(t *testing.T, f *bootstrapDockerFixture, ctx context.Context, after time.Time, observed ...*darwinRecoveryObservation) protocol.Snapshot {
	t.Helper()
	observation := &darwinRecoveryObservation{}
	if len(observed) == 1 {
		observation = observed[0]
	}
	succeeded := false
	defer func() {
		if observation.drain != nil {
			observation.drain()
		}
		if !succeeded {
			observation.CapturedAt = time.Now().UTC().Format(time.RFC3339Nano)
			f.WriteEvidence(t, "darwin-recovery-last-observation.json", observation)
		}
	}()
	client, err := LoadOwnerBridgeClient(f.Config, *f.BridgeEnrollment)
	if err != nil {
		t.Fatal("authenticated recovery observer refused")
	}
	for ctx.Err() == nil {
		if observation.drain != nil {
			observation.drain()
		}
		invocation := "attempt_" + bootstrapFixtureRandom(t, 16)
		request, cancel := context.WithTimeout(ctx, 5*time.Second)
		out, requestErr := client.Request(request, "status", invocation)
		cancel()
		if requestErr != nil {
			observation.OwnerCode = ProjectRequestDiagnostic(requestErr).Code
			switch requestErr.Error() {
			case "owner_bridge_connection_unavailable", "owner_bridge_reply_unavailable", "owner_bridge_deadline":
			default:
				f.RetainForRecovery(t)
				t.Fatal("recovery status failed authentication or owned cleanup")
			}
		} else {
			if !bridgeObservationBound(out, *f.BridgeEnrollment, invocation, time.Now()) {
				t.Fatal("recovery reply lost its current owner, scope or invocation")
			}
			observation.Owner, observation.OwnerCode = &out, "validated"
			ready := out.Instance.RunningVersion != nil && (out.Disposition == "started" || out.Disposition == "reused")
			for _, role := range protocol.Roles() {
				found := false
				for _, service := range out.Instance.Services {
					if service.ServiceID == role && service.Readiness == "ready" && service.ObservedAt != nil && service.SourceRevision != nil {
						found = true
					}
				}
				ready = ready && found
			}
			{
				probe, cancel := context.WithTimeout(ctx, 5*time.Second)
				kernel, kernelErr := ObserveKernel(probe, f.Config.Kernel)
				cancel()
				observation.KernelCode = ProjectRequestDiagnostic(kernelErr).Code
				if kernelErr == nil {
					observation.Kernel, observation.KernelCode = &kernel, "validated"
				}
				if ProjectRequestDiagnostic(kernelErr).Code == "owned_cleanup_incomplete" {
					f.RetainForRecovery(t)
					t.Fatal("recovery observer owned cleanup is incomplete")
				}
				at, _ := time.Parse(time.RFC3339Nano, kernel.ObservedAt)
				if ready && kernelErr == nil && kernel.KernelReadiness == "ready" && !at.Before(after) {
					succeeded = true
					return kernel
				}
				if IsKernelStatusAuthorityError(kernelErr) {
					f.RetainForRecovery(t)
					t.Fatal("recovered kernel server authority rejected")
				}
			}
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	f.RetainForRecovery(t)
	t.Fatal("actual owned runtime did not recover within the one shared deadline")
	return protocol.Snapshot{}
}

// Keep the original roster, including any exited member, with its existing
// cleanup owner. Fresh creator-derived descendants have their own cleanup that
// first joins the exact host shutdown, then joins and closes those new proofs.
func darwinScenarioRecoveryRoster(t *testing.T, f *bootstrapDockerFixture, x *composeDarwinCLIFront, ctx context.Context) []*darwinfixtureidentity.Proof {
	t.Helper()
	var proofs []*darwinfixtureidentity.Proof
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), f.Config.Deadlines.StopGrace+f.Config.Deadlines.ReapTimeout)
		defer cancel()
		if state := x.lifetime.host.Live(); state == nil {
			if x.lifetime.host.Signal(syscall.SIGTERM) != nil {
				f.RetainForRecovery(t)
				t.Error("exact recovery host stop refused")
				return
			}
		} else if !errors.Is(state, darwinfixtureidentity.ErrExited) {
			f.RetainForRecovery(t)
			t.Error("exact recovery host identity unavailable")
			return
		}
		if x.lifetime.host.WaitExit(cleanup) != nil {
			f.RetainForRecovery(t)
			t.Error("exact recovery host shutdown did not join")
			return
		}
		for _, proof := range proofs {
			if proof.WaitExit(cleanup) != nil {
				f.RetainForRecovery(t)
				t.Error("fresh exact recovery descendant exit did not join")
				continue
			}
			if proof.Close() != nil {
				f.RetainForRecovery(t)
				t.Error("fresh descendant proof did not close")
			}
		}
	})
	args := map[string][]string{}
	for _, option := range f.Config.Roles {
		args[option.ID] = append([]string(nil), option.Args...)
	}
	var err error
	proofs, err = x.lifetime.pinRoster(ctx, f, args)
	if err != nil || len(proofs) != 4 {
		f.RetainForRecovery(t)
		t.Fatal("fresh signed creator-derived role roster refused")
	}
	for _, proof := range proofs {
		if proof.Live() != nil {
			f.RetainForRecovery(t)
			t.Fatal("fresh exact recovered descendant is not live")
		}
	}
	return proofs
}

func darwinScenarioRecoveryPreserved(t *testing.T, f *bootstrapDockerFixture, before darwinScenarioStoredState, ctx context.Context) {
	t.Helper()
	broker, brokerErr := f.ObserveBroker(ctx)
	volume, volumeErr := f.volume(ctx)
	record, recordErr := deployment.Observe(ctx, deployment.ObserveOptions{ProbeOptions: f.Config.Health, ReadExistingRecord: true})
	if brokerErr != nil || volumeErr != nil || recordErr != nil || ctx.Err() != nil || broker.State != "running" || broker.ContainerID != before.broker.ContainerID || !reflect.DeepEqual(volume, before.volume) || record.RecordSequence != before.sequence || record.RecordDigest != "sha256:"+before.record {
		diagnostic := func(failure error) string {
			if failure == nil {
				return "none"
			}
			var refused *dockerRefusalError
			if errors.As(failure, &refused) && refused != nil {
				return refused.Error()
			}
			if code := bootstrapFixtureFailureCode(failure); code != "unclassified_private_error" {
				return code
			}
			switch failure.Error() {
			case "fixture_network_admission_failed":
				return "fixture_network_admission_failed"
			case "fixture_network_inventory_failed":
				return "fixture_network_inventory_failed"
			}
			return ProjectRequestDiagnostic(failure).Code
		}
		f.WriteEvidence(t, "darwin-recovery-preservation-observation.json", map[string]any{
			"observedAt":                time.Now().UTC().Format(time.RFC3339Nano),
			"brokerInspectionSucceeded": brokerErr == nil, "volumeInspectionSucceeded": volumeErr == nil,
			"recordObservationSucceeded": recordErr == nil, "contextExpired": ctx.Err() != nil,
			"deadlineExceeded":      ctx.Err() == context.DeadlineExceeded,
			"brokerDiagnostic":      diagnostic(brokerErr),
			"brokerInspectionStage": bootstrapFixtureFailureStage(brokerErr),
			"brokerFailedRead":      bootstrapFailedReadFromError(brokerErr),
			"brokerNetworkStage":    bootstrapNetworkReadStage(brokerErr),
			"volumeDiagnostic":      diagnostic(volumeErr),
			"recordDiagnostic":      diagnostic(recordErr),
			"brokerState":           broker.State, "containerIdentityPreserved": broker.ContainerID == before.broker.ContainerID,
			"volumeNamePreserved":             volume.Name == before.volume.Name,
			"volumeCreationTimePreserved":     volume.CreatedAt == before.volume.CreatedAt,
			"volumeLabelsPreserved":           reflect.DeepEqual(volume.Labels, before.volume.Labels),
			"wholeVolumeObservationPreserved": reflect.DeepEqual(volume, before.volume),
			"recordObservationCode":           record.Code, "recordEvidence": record.PersistenceEvidence,
			"originalSequence": before.sequence, "observedLatestSequence": record.RecordSequence,
			"sequencePreserved":    record.RecordSequence == before.sequence,
			"originalRecordDigest": "sha256:" + before.record, "observedLatestRecordDigest": record.RecordDigest,
			"recordDigestPreserved": record.RecordDigest == "sha256:"+before.record,
		})
		f.RetainForRecovery(t)
		t.Fatal("recovery preservation was not verified; inspect the closed preservation observation")
	}
}

func TestInstalledCLIDarwinRealComposeOwnedMemberRecovery(t *testing.T) {
	f, s, r := composeDarwinCLIEnrolledFixture(t)
	x := darwinScenarioCold(t, f, s, r, "darwin-member-recovery-cold")
	probe, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	before, err := ObserveKernel(probe, f.Config.Kernel)
	cancel()
	if err != nil || before.KernelReadiness != "ready" {
		t.Fatal("original genuine kernel snapshot unavailable")
	}
	stored := darwinScenarioStored(t, f)
	var selected *darwinfixtureidentity.Proof
	for _, proof := range x.lifetime.roles {
		args := proof.LiteralArgs()
		if len(args) > 0 && args[0] == "agentmux-internal-communication" {
			selected = proof
		}
	}
	if selected == nil {
		t.Fatal("exact creator-derived member proof unavailable")
	}
	injected := time.Now()
	ctx, cancel := context.WithDeadline(context.Background(), injected.Add(darwinScenarioRecoveryBudget))
	defer cancel()
	if selected.Signal(syscall.SIGKILL) != nil || selected.WaitExit(ctx) != nil {
		f.RetainForRecovery(t)
		t.Fatal("exact selected member kill or exit proof failed")
	}
	after := darwinScenarioRecovered(t, f, ctx, injected)
	if x.lifetime.host.Live() != nil || !errors.Is(selected.Live(), darwinfixtureidentity.ErrExited) {
		t.Fatal("member recovery replaced its exact host or lost the exited member proof")
	}
	for _, proof := range x.lifetime.roles {
		if proof != selected && proof.Live() != nil {
			t.Fatal("member recovery replaced an unrelated protected sibling")
		}
	}
	darwinScenarioRecoveryRoster(t, f, x, ctx)
	if after.Incarnation != before.Incarnation || after.Revision <= before.Revision {
		t.Fatal("single-member recovery replaced the status actor or replayed its snapshot")
	}
	for _, old := range before.Members {
		matched := false
		for _, current := range after.Members {
			if current.Role == old.Role {
				matched = true
				if old.Role == "internal-communication" {
					if current.Incarnation == old.Incarnation {
						t.Fatal("recovered member reused its old incarnation")
					}
				} else if current.Incarnation != old.Incarnation {
					t.Fatal("member recovery changed a surviving sibling incarnation")
				}
			}
		}
		if !matched {
			t.Fatal("recovery snapshot omitted a protected role")
		}
	}
	darwinScenarioRecoveryPreserved(t, f, stored, ctx)
	recoveryElapsed := time.Since(injected)
	f.AssertBaselineUnchanged(t)
	f.WriteEvidence(t, "darwin-owned-member-recovery.json", map[string]any{"sameCreatorHost": true, "onlySelectedMemberReplaced": true, "newObservedMemberIncarnation": true, "sameBrokerVolumeAndRecord": true, "sharedBudgetNanoseconds": int64(darwinScenarioRecoveryBudget), "recoveryElapsedNanoseconds": recoveryElapsed.Nanoseconds()})
}

func TestInstalledCLIDarwinRealComposeOwnedBrokerRecovery(t *testing.T) {
	f, s, r := composeDarwinCLIEnrolledFixture(t)
	x := darwinScenarioCold(t, f, s, r, "darwin-broker-recovery-cold")
	stored := darwinScenarioStored(t, f)
	injected := time.Now()
	ctx, cancel := context.WithDeadline(context.Background(), injected.Add(darwinScenarioRecoveryBudget))
	defer cancel()
	observation := &darwinRecoveryObservation{}
	darwinScenarioLifecycleObservation(t, f, ctx, observation)
	if f.stopBrokerForRecovery(ctx, stored.broker.ContainerID) != nil {
		f.RetainForRecovery(t)
		t.Fatal("exact selected broker stop or lease cleanup failed")
	}
	darwinScenarioRecovered(t, f, ctx, injected, observation)
	if x.lifetime.host.Live() != nil {
		f.RetainForRecovery(t)
		t.Fatal("broker recovery replaced the creating host")
	}
	darwinScenarioRecoveryRoster(t, f, x, ctx)
	darwinScenarioRecoveryPreserved(t, f, stored, ctx)
	recoveryElapsed := time.Since(injected)
	f.AssertBaselineUnchanged(t)
	f.WriteEvidence(t, "darwin-owned-broker-recovery.json", map[string]any{"sameCreatorHost": true, "sameRestartedContainer": true, "sameVolumeAndOriginalRecord": true, "freshAuthenticatedReadiness": true, "sharedBudgetNanoseconds": int64(darwinScenarioRecoveryBudget), "recoveryElapsedNanoseconds": recoveryElapsed.Nanoseconds()})
}

func TestInstalledCLIDarwinRealComposeHOSTPrincipalIsolation(t *testing.T) {
	f, selection, record := composeDarwinCLIEnrolledFixture(t)
	original := darwinScenarioCold(t, f, selection, record, "darwin-host-permissions-cold")
	stored := darwinScenarioStored(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if !t.Run("existing-principal-matrix", func(t *testing.T) {
		matrix, finish := context.WithTimeout(ctx, 30*time.Second)
		defer finish()
		// Use the actual selected Compose broker and installed protected roles.
		// No controlled Docker process or alternate broker is installed here.
		ownerBridgePrincipalIsolation(t, bridgeFixture{config: f.Config, users: f.Config.brokerUsers}, matrix)
	}) {
		f.RetainForRecovery(t)
		t.Fatal("actual installed HOST permission matrix failed")
	}
	darwinScenarioRecovered(t, f, ctx, time.Now())
	original.lifetime.assertUnchanged(t, f)
	darwinScenarioRecoveryPreserved(t, f, stored, ctx)
	f.AssertBaselineUnchanged(t)
}

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
	type attemptDiagnostic struct {
		ErrorCode             string `json:"errorCode"`
		DeadlineExpired       bool   `json:"deadlineExpired"`
		Disposition           string `json:"disposition"`
		RequestedInvocationID string `json:"requestedInvocationId"`
	}
	summary := struct {
		Attempts        int                `json:"attemptCount"`
		FirstFailure    *attemptDiagnostic `json:"firstFailure"`
		LastFailure     *attemptDiagnostic `json:"lastFailure"`
		LastObservation *attemptDiagnostic `json:"lastObservation"`
		Completed       bool               `json:"completed"`
		DeadlineExpired bool               `json:"deadlineExpired"`
	}{}
	name := "darwin-refresh-summary-before-request.json"
	defer func() {
		summary.DeadlineExpired = !time.Now().Before(startupDeadline)
		f.WriteEvidence(t, name, summary)
	}()
	recordFailure := func(code string) {
		failure := attemptDiagnostic{ErrorCode: code}
		if summary.LastObservation != nil {
			failure = *summary.LastObservation
			failure.ErrorCode = code
		}
		if summary.FirstFailure == nil {
			summary.FirstFailure = &failure
		}
		summary.LastFailure = &failure
	}
	client, err := LoadOwnerBridgeClient(f.Config, *f.BridgeEnrollment)
	if err != nil {
		recordFailure("refresh_client_admission_refused")
		t.Fatal("actual authenticated refresh client refused")
	}
	ctx, cancel := context.WithDeadline(context.Background(), startupDeadline)
	defer cancel()
	for ctx.Err() == nil {
		invocation := "attempt_" + bootstrapFixtureRandom(t, 16)
		if summary.Attempts == 0 {
			name = "darwin-refresh-summary-" + invocation + ".json"
		}
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
		summary.Attempts++
		summary.LastObservation = &attemptDiagnostic{ErrorCode: code, DeadlineExpired: ctx.Err() != nil,
			Disposition: out.Disposition, RequestedInvocationID: invocation}
		if requestErr != nil {
			recordFailure(code)
		}
		// Request already checks the authenticated envelope's request nonce,
		// invocation, scope and freshness. Recheck the observation contract here
		// against the invocation actually supplied, including starting semantics.
		if requestErr == nil && !bridgeObservationBound(out, *f.BridgeEnrollment, invocation, time.Now()) {
			recordFailure("refresh_owner_or_request_correlation_invalid")
			t.Fatal("actual refreshed observation lost owner or request correlation")
		}
		if requestErr == nil && (out.Disposition == "started" || out.Disposition == "reused") {
			if out.StartupAttemptID == nil || *out.StartupAttemptID != invocation ||
				out.Instance.RunningVersion == nil || out.Instance.Readiness != "degraded" ||
				out.Work.State != "unavailable" || out.Hubs.InventoryState != "unavailable" {
				recordFailure("refresh_completed_observation_invalid")
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
					recordFailure("refresh_role_readiness_missing")
					t.Fatal("actual completed role lacks current readiness")
				}
			}
			summary.Completed = true
			return out, invocation
		}
		if requestErr != nil && code == "closed_unclassified_failure" {
			t.Fatal("actual refresh authority or runtime failed")
		}
		if requestErr == nil && out.Disposition != "starting" {
			recordFailure("refresh_runtime_failed")
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
	// Join each original frontend before inspecting its surviving direct host.
	// The retained native exit watch and creation-parent identity survive reaping.
	for ctx.Err() == nil {
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
	// Keep an ordinary permitted consumer connected to the unchanged broker
	// while the actual kernel processes exit and a new assembly starts.
	consumerCtx, finishConsumer := context.WithTimeout(context.Background(), f.Config.Deadlines.StopGrace+f.Config.Deadlines.ReapTimeout+f.Config.StartupTimeout+10*time.Second)
	defer finishConsumer()
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	consumer := darwinSlowConsumerConnect(t, f, consumerCtx, make(chan darwinSlowConsumerFault, 16))
	wire, err := communication.Subjects(f.Config.Kernel.Scope.HubID)
	if err != nil {
		t.Fatal("restart consumer scoped subjects unavailable")
	}
	subscriptions := make([]*nats.Subscription, 0, 2)
	for _, subject := range []string{wire.Snapshot, wire.Update} {
		sub, err := consumer.connection.SubscribeSync(subject)
		if err != nil {
			t.Fatal("restart consumer permitted subscription refused")
		}
		subscriptions = append(subscriptions, sub)
		t.Cleanup(func() {
			if sub.IsValid() && sub.Unsubscribe() != nil {
				t.Error("restart consumer subscription cleanup failed")
			}
		})
		if sub.SetPendingLimits(256, 256*protocol.MaxPayload) != nil {
			t.Fatal("restart consumer bounded subscription refused")
		}
	}
	if consumer.connection.FlushWithContext(ctx) != nil {
		t.Fatal("restart consumer subscriptions did not flush")
	}
	initial, err := subscriptions[0].NextMsgWithContext(ctx)
	initialReceived := time.Now()
	cancel()
	cursor := protocol.SnapshotCursor{}
	if err != nil || initial == nil {
		t.Fatal("restart consumer initial snapshot unavailable")
	}
	initialSnapshot, gap, err := cursor.Accept(initial.Data, f.Config.Kernel.Scope, initialReceived, 3*time.Second)
	if err != nil || gap || initialSnapshot.Incarnation != beforeKernel.Incarnation {
		t.Fatal("restart consumer initial snapshot or cursor refused")
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
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for index, subscription := range subscriptions {
		observed := false
		for ctx.Err() == nil {
			message, err := subscription.NextMsgWithContext(ctx)
			if err != nil || message == nil {
				break
			}
			current, decodeErr := protocol.DecodeSnapshot(message.Data, f.Config.Kernel.Scope, time.Now(), 3*time.Second)
			if decodeErr != nil || current.Incarnation != afterKernel.Incarnation || current.KernelReadiness != "ready" {
				continue
			}
			if index == 0 {
				if _, gap, err := cursor.Accept(message.Data, f.Config.Kernel.Scope, time.Now(), 3*time.Second); err != nil || !gap {
					t.Fatal("ordinary consumer did not resynchronize to the actual new kernel incarnation")
				}
			}
			observed = true
			break
		}
		if !observed {
			t.Fatal("ordinary consumer lost fresh snapshot or update publication across actual kernel restart")
		}
	}
	// Use the original receipt time so freshness alone cannot reject the old
	// wire frame; the cursor must remember that its incarnation was retired.
	if _, _, err := cursor.Accept(initial.Data, f.Config.Kernel.Scope, initialReceived, 3*time.Second); err == nil || err.Error() != "kernel_snapshot_incarnation_invalid" {
		t.Fatal("ordinary consumer accepted a replay from the retired actual kernel incarnation")
	}
	if !darwinSlowConsumerCheckFaults(t, consumer) || consumer.close() != nil || !darwinSlowConsumerCheckFaults(t, consumer) {
		f.RetainForRecovery(t)
		t.Fatal("restart consumer transport or owned cleanup failed")
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
