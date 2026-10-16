//go:build linux

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/nats-io/nats.go"
)

// The actual Bootstrap starts four separately signed real kernel executables.
// Only Docker inspection and its successful compose guard are controlled; no
// actual engine or container exists. The pause is confined to that test child.
func TestBootstrapBoundaryActualReadinessCallSites(t *testing.T) {
	kernelPath := filepath.Join(t.TempDir(), "kernel")
	installedCLIBuild(t, "./cmd/agentmux-kernel", kernelPath)
	kernel, e := os.ReadFile(kernelPath)
	if e != nil {
		t.Fatal("actual_kernel_fixture_unavailable")
	}
	for _, mode := range []string{"cold_readiness_failure", "cold_readiness_success"} {
		t.Run(mode, func(t *testing.T) {
			fixtureContext, stopFixture := context.WithTimeout(context.Background(), 45*time.Second)
			t.Cleanup(stopFixture)
			f := installedCLIRoleFixture(t, kernel)
			// This checked helper owns the actual TLS broker and its exact creator.
			bridgeDiagnosticOwnedBroker(t, fixtureContext, f)
			bridgeSpec := os.Getenv("AMX_OWNER_BRIDGE_DOCKER_FIXTURE")
			if bridgeSpec == "" {
				t.Fatal("controlled_identity_spec_unavailable")
			}
			t.Setenv("AMX_OWNER_BRIDGE_DOCKER_FIXTURE", "")
			dir := t.TempDir()
			spec := bootstrapBoundaryDockerSpec{Profile: f.profile, Mode: mode, Log: filepath.Join(dir, "commands.private"), ComposeSHA256: releaseDigest(f.config.Compose), BridgeSpec: bridgeSpec, Started: filepath.Join(dir, "started"), Pause: filepath.Join(dir, "paused"), Release: filepath.Join(dir, "release")}
			name := filepath.Join(dir, "spec.private")
			if os.WriteFile(name, mustStatusJSON(spec), 0600) != nil {
				t.Fatal("fixed_boundary_spec_unavailable")
			}
			t.Setenv("AMX_BOOTSTRAP_BOUNDARY_DOCKER_FIXTURE", name)
			t.Setenv("DOCKER_HOST", "")
			t.Setenv("DOCKER_CONTEXT", "")
			dialer, e := f.config.Health.TLS.NewDialer(fixtureContext, time.Second)
			if e != nil {
				t.Fatal("exact_health_dialer_unavailable")
			}
			var health *nats.Conn
			t.Cleanup(func() {
				if dialer.Close() != nil {
					t.Error("exact_health_dialer_cleanup_failed")
				}
				if health != nil {
					health.Close()
				}
			})
			health, e = nats.Connect(f.config.Health.Endpoint, nats.UserInfo(deployment.HealthUser, f.config.Health.Password), nats.TLSHandshakeFirst(), nats.SetCustomDialer(dialer), nats.NoReconnect(), nats.IgnoreDiscoveredServers(), nats.Timeout(time.Second), nats.ErrorHandler(ownerBridgeAsyncErrorHandler))
			if e != nil {
				t.Fatal("actual_health_account_unavailable")
			}
			startup, stopStartup := context.WithCancel(fixtureContext)
			type result struct {
				session *Session
				failure error
			}
			done := make(chan result, 1)
			joined := false
			var owned result
			go func() {
				s, e := BootstrapForInvocation(startup, fixtureContext, f.config, "attempt_"+strings.Repeat("d", 32))
				done <- result{s, e}
			}()
			defer func() {
				stopStartup()
				if !joined {
					owned = <-done
					joined = true
				}
				if !closeBootstrapBoundaryFailureOwners(fixtureContext, owned.session, owned.failure) {
					t.Error("actual_readiness_owner_cleanup_incomplete")
				}
				goruntime.KeepAlive(owned.failure)
			}()
			// The fifth endpoint inspect occurs after actual provisioning and group Start,
			// before the first readiness Observe. StartOwned also performs its own
			// warm guard inspection. The same startup budget stays live.
			for {
				if _, e := os.Stat(spec.Pause); e == nil {
					break
				}
				select {
				case owned = <-done:
					joined = true
					t.Fatal("actual_bootstrap_returned_before_readiness_boundary")
				case <-startup.Done():
					t.Fatal("original_startup_expired_before_readiness_boundary")
				case <-time.After(time.Millisecond):
				}
			}
			if mode == "cold_readiness_failure" {
				js, e := health.JetStream()
				if e != nil {
					t.Fatal("actual_health_stream_context_unavailable")
				}
				if _, e = js.Publish(deployment.HealthSubject(f.config.Health.HubID), []byte("invalid-isolated-health-record"), nats.Context(startup)); e != nil {
					t.Fatal("isolated_health_fault_not_persisted")
				}
			}
			if os.WriteFile(spec.Release, []byte("release"), 0600) != nil {
				t.Fatal("fixed_readiness_child_release_failed")
			}
			owned = <-done
			joined = true
			if !closeBootstrapBoundaryFailureOwners(fixtureContext, nil, owned.failure) {
				t.Fatal("actual_failure_controller_cleanup_incomplete")
			}
			if startup.Err() != nil || fixtureContext.Err() != nil {
				t.Fatal("original_context_exhausted")
			}
			if mode == "cold_readiness_failure" {
				stage := bootstrapDiagnosticStage(owned.failure)
				if owned.failure == nil || owned.failure.Error() != "observe_record_invalid" || stage == nil || *stage != "readiness_observation" {
					t.Fatal("actual_hard_observation_misattributed")
				}
			} else {
				if owned.failure != nil || owned.session == nil || owned.session.Status.Disposition != "started" || owned.session.Status.Kernel.KernelReadiness != "ready" {
					t.Fatal("actual_successful_finalization_changed")
				}
			}
			if owned.session != nil {
				if owned.session.Close(fixtureContext) != nil {
					t.Fatal("actual_session_close_failed")
				}
				owned.session = nil
			}
			for _, id := range append([]string{f.profile.Docker.EngineID}, bootstrapBoundaryRoleLeaseIDs(f.profile.Docker.EngineID)...) {
				bounded, cancel := context.WithTimeout(fixtureContext, 100*time.Millisecond)
				lease, e := AcquireBootstrapLock(bounded, f.profile.ProfileDirectory, f.profile.InstanceID, id)
				cancel()
				if e != nil {
					t.Fatal("actual_exclusion_not_released")
				}
				if lease.Close() != nil {
					t.Fatal("actual_contender_close_failed")
				}
			}
			ledger, e := os.ReadFile(spec.Log)
			if e != nil {
				t.Fatal("fixed_command_ledger_unavailable")
			}
			mutations := 0
			for _, line := range strings.Split(string(ledger), "\n") {
				var args []string
				if json.Unmarshal([]byte(line), &args) == nil && len(args) > 0 && args[0] == "compose" && strings.Contains(strings.Join(args, " "), " up ") {
					mutations++
				}
			}
			if mutations != 1 {
				t.Fatal("actual_original_mutation_guard_changed")
			}
		})
	}
}

// This test walks only the projector's exact reviewed wrappers. It never invokes
// unknown methods or adopts a resource. Original errors remain live in owned.
func closeBootstrapBoundaryFailureOwners(ctx context.Context, session *Session, failure error) bool {
	clean := true
	sessions := map[*Session]bool{}
	closeSession := func(s *Session) {
		if s != nil && !sessions[s] {
			sessions[s] = true
			if s.Close(ctx) != nil {
				clean = false
			}
		}
	}
	closeSession(session)
	pointers := map[error]bool{}
	queue := []error{failure}
	for visited := 0; len(queue) > 0; visited++ {
		if visited >= 64 {
			return false
		}
		current := queue[0]
		queue = queue[1:]
		if current == nil || (reflect.ValueOf(current).Kind() == reflect.Pointer && reflect.ValueOf(current).IsNil()) {
			continue
		}
		// Only actual pointer errors can be deduplicated without comparing an opaque
		// error field inside a value wrapper.
		if reflect.ValueOf(current).Kind() == reflect.Pointer {
			if pointers[current] {
				continue
			}
			pointers[current] = true
		}
		switch owner := current.(type) {
		case *TransportCleanupError:
			if owner.Close() != nil {
				clean = false
			}
		case TransportCleanupError:
			if (&owner).Close() != nil {
				clean = false
			}
		case *RuntimeCleanupError:
			if owner.Close(ctx) != nil {
				clean = false
			}
		case RuntimeCleanupError:
			if (&owner).Close(ctx) != nil {
				clean = false
			}
		case *deployment.ProbeCleanupError:
			if owner.Close() != nil {
				clean = false
			}
		case deployment.ProbeCleanupError:
			if (&owner).Close() != nil {
				clean = false
			}
		case *deployment.RawTransportCleanupError:
			if owner.Close(ctx) != nil {
				clean = false
			}
		case deployment.RawTransportCleanupError:
			if (&owner).Close(ctx) != nil {
				clean = false
			}
		case *protocol.CleanupError:
			if owner.Close() != nil {
				clean = false
			}
		case *bootstrapCleanupFailure:
			closeSession(owner.session)
		case bootstrapCleanupFailure:
			closeSession(owner.session)
		}
		if !diagnosticReviewedWrapper(current) {
			// These exact leaf layouts contain only text/code/context sentinel, no owner.
			switch current.(type) {
			case *dockerRefusalError, bridgeFailure, *bridgeFailure:
				continue
			}
			if current == context.Canceled || current == context.DeadlineExceeded || reflect.TypeOf(current) == reflect.TypeOf(errors.New("")) {
				continue
			}
			clean = false
			continue
		}
		switch known := current.(type) {
		case interface{ Unwrap() []error }:
			children := known.Unwrap()
			if len(children) > 63-visited-len(queue) {
				return false
			}
			queue = append(queue, children...)
		case interface{ Unwrap() error }:
			if len(queue) >= 63-visited {
				return false
			}
			queue = append(queue, known.Unwrap())
		}
	}
	return clean
}

// These zero-owner controls check dispatch/refusal only, not physical cleanup.
func TestBootstrapBoundaryFailureOwnerDispatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for name, failure := range map[string]error{
		"probe_pointer": &deployment.ProbeCleanupError{}, "probe_value": deployment.ProbeCleanupError{},
		"raw_pointer": &deployment.RawTransportCleanupError{}, "raw_value": deployment.RawTransportCleanupError{},
		"transport_pointer": &TransportCleanupError{}, "transport_value": TransportCleanupError{},
		"runtime_pointer": &RuntimeCleanupError{}, "runtime_value": RuntimeCleanupError{},
		"protocol_pointer": &protocol.CleanupError{},
		"nested":           errors.Join(&deployment.ProbeCleanupError{}, &TransportCleanupError{}),
	} {
		t.Run(name, func(t *testing.T) {
			if !closeBootstrapBoundaryFailureOwners(ctx, nil, failure) {
				t.Fatal("known_exact_cleanup_dispatch_failed")
			}
		})
	}
	if closeBootstrapBoundaryFailureOwners(ctx, nil, unknownBoundaryGraffiti{}) {
		t.Fatal("unknown_error_graph_claimed_closed")
	}
	large := make([]error, 65)
	for i := range large {
		large[i] = &deployment.ProbeCleanupError{}
	}
	if closeBootstrapBoundaryFailureOwners(ctx, nil, errors.Join(large...)) {
		t.Fatal("oversized_error_graph_claimed_closed")
	}
}
