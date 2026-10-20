//go:build darwin && cgo && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"strings"
	"testing"
	"time"
)

// This component check retains the exact source Session so a failed protected
// child can report its closed exit category. Installed CLI acceptance remains
// the separate TestInstalledCLIDarwinRealComposeOwnedBrokerRecovery scenario.
func TestDarwinRealComposeSourceSessionBrokerRecovery(t *testing.T) {
	f, _, _ := composeDarwinCLIEnrolledFixture(t)
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	defer cancelLifetime()
	startup, cancelStartup := context.WithTimeout(context.Background(), f.Config.StartupTimeout)
	session, err := Bootstrap(startup, lifetime, f.Config)
	cancelStartup()
	if session != nil {
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), f.Config.Deadlines.StopGrace+f.Config.Deadlines.ReapTimeout)
			defer cancel()
			if session.Close(cleanup) != nil {
				f.RetainForRecovery(t)
				t.Error("source session exact cleanup did not join")
			}
		})
	}
	if err != nil || session == nil || session.Status.Disposition != "started" {
		t.Fatalf("source session startup failed: %s stage=%s", bootstrapFixtureFailureCode(err), bootstrapFixtureFailureStage(err))
	}
	group := bootstrapFixtureGroup(t, session)
	bootstrapFixtureChildren(t, group)
	defer func() {
		for _, state := range group.Status() {
			output, truncated := group.Output(state.Role)
			code := "no_output"
			if len(output) != 0 {
				code = "unclassified_output"
			}
			switch strings.TrimSpace(string(output)) {
			case "kernel_parent_lifetime_invalid", "kernel_arguments_not_supported", "kernel_credentials_invalid",
				"kernel_server_trust_required", "kernel_server_trust_endpoint_invalid", "kernel_timing_invalid",
				"kernel_supervisor_identity_invalid", "kernel_credential_reference_invalid", "kernel_supervisor_context_mismatch",
				"kernel_credential_file_invalid", "kernel_credential_parent_invalid", "kernel_credential_platform_unqualified",
				"kernel_server_trust_reference_invalid", "kernel_server_trust_parent_invalid", "kernel_server_trust_platform_unqualified",
				"kernel_server_trust_binding_invalid", "kernel_server_trust_policy_invalid", "kernel_server_trust_file_invalid", "kernel_server_trust_record_invalid",
				"kernel_context_unavailable", "kernel_subjects_invalid", "kernel_incarnation_unavailable",
				"kernel_server_trust_unavailable", "kernel_broker_unavailable", "kernel_subscription_unavailable",
				"kernel_cleanup_failed", "kernel_broker_authentication_failed", "kernel_broker_authorization_failed",
				"kernel_server_authentication_failed", "kernel_broker_permission_or_delivery_failed",
				"kernel_revision_exhausted", "kernel_local_observation_invalid", "kernel_observation_unavailable",
				"kernel_lifecycle_publish_failed", "kernel_lifecycle_nonce_unavailable":
				code = strings.TrimSpace(string(output))
			}
			t.Logf("role=%s generation=%d exited=%t exitCode=%d diagnostic=%s outputTruncated=%t", state.Role, state.Generation, state.Exited, state.ExitCode, code, truncated)
		}
	}()
	stored := darwinScenarioStored(t, f)
	injected := time.Now()
	ctx, cancel := context.WithDeadline(context.Background(), injected.Add(darwinScenarioRecoveryBudget))
	defer cancel()
	if f.stopBrokerForRecovery(ctx, stored.broker.ContainerID) != nil {
		f.RetainForRecovery(t)
		t.Fatal("source session exact broker stop failed")
	}
	for ctx.Err() == nil {
		probe, probeCancel := context.WithTimeout(ctx, 5*time.Second)
		snapshot, observeErr := ObserveKernel(probe, f.Config.Kernel)
		probeCancel()
		at, _ := time.Parse(time.RFC3339Nano, snapshot.ObservedAt)
		if observeErr == nil && snapshot.KernelReadiness == "ready" && !at.Before(injected) && session.currentKernelSnapshot(snapshot) {
			darwinScenarioRecoveryPreserved(t, f, stored, ctx)
			t.Logf("source session fresh kernel recovery completed in %s", time.Since(injected))
			return
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	f.RetainForRecovery(t)
	t.Fatal("source session did not recover inside the unchanged deadline")
}
