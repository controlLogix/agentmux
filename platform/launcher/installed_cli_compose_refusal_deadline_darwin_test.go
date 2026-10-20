//go:build darwin && cgo && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"crypto/sha256"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/internal/darwinfixtureidentity"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

var darwinForeignCallerRetained struct {
	sync.Mutex
	commands []*exec.Cmd
	fixtures []*bootstrapDockerFixture
}

// Run waits for this exact foreground command and both bounded output readers.
// A timeout or incomplete reader join retains the original cleanup owner.
func darwinForeignCallerRun(t *testing.T, f *bootstrapDockerFixture, args ...string) ([]byte, []byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/sudo", append([]string{"-n", "-u", "nobody", "--"}, args...)...)
	command.Dir = "/private/tmp"
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/var/empty", "LANG=C"}
	command.WaitDelay = time.Second
	var stdout, stderr limitedOutput
	command.Stdout, command.Stderr = &stdout, &stderr
	started := time.Now()
	failure := command.Run()
	if ctx.Err() != nil || errors.Is(failure, exec.ErrWaitDelay) || command.ProcessState == nil || !command.ProcessState.Exited() ||
		stdout.exceeded || stderr.exceeded || time.Since(started) > 5*time.Second {
		darwinForeignCallerRetained.Lock()
		darwinForeignCallerRetained.commands = append(darwinForeignCallerRetained.commands, command)
		darwinForeignCallerRetained.fixtures = append(darwinForeignCallerRetained.fixtures, f)
		darwinForeignCallerRetained.Unlock()
		f.RetainForRecovery(t)
		t.Fatal("foreign caller foreground exit or output cleanup was not confirmed within five seconds")
	}
	return append([]byte(nil), stdout.Bytes()...), append([]byte(nil), stderr.Bytes()...), failure
}

// This checks a genuine foreign OS caller's access to the current owner's
// private policy. It does not enroll another account or share live writers.
func TestInstalledCLIDarwinRealComposeForeignOSCallerRefused(t *testing.T) {
	f, selection, record := composeDarwinCLIEnrolledFixture(t)
	original := darwinScenarioCold(t, f, selection, record, "darwin-foreign-caller-cold")
	stored := darwinScenarioStored(t, f)
	uidRaw, stderr, failure := darwinForeignCallerRun(t, f, "/usr/bin/id", "-u")
	uid, parseErr := strconv.ParseInt(strings.TrimSpace(string(uidRaw)), 10, 64)
	if failure != nil || len(stderr) != 0 || parseErr != nil || (uid != -2 && uid != 4294967294) || uint32(uid) == f.Profile.OwnerUID {
		t.Fatal("existing nobody account or noninteractive harness authorization was not established")
	}
	args := []string{record.RuntimeExecutable.Path, "status", "--host-policy", selection.Path}
	for _, root := range selection.WorkspaceRoots {
		args = append(args, "--workspace", root)
	}
	stdout, stderr, failure := darwinForeignCallerRun(t, f, args...)
	var diagnostic RequestDiagnostic
	if failure == nil || len(stdout) != 0 || protocol.DecodeClosedJSON(stderr, &diagnostic, 4096) != nil ||
		!ValidRequestDiagnostic(diagnostic) || diagnostic.Code != "host_policy_invalid" {
		t.Fatal("actual foreign OS caller did not receive the closed private-policy refusal")
	}
	original.lifetime.assertUnchanged(t, f)
	stored.assertPreserved(t, f, "darwin-foreign-caller-preservation.json")
	darwinScenarioRefresh(t, f, time.Now().Add(5*time.Second))
	f.WriteEvidence(t, "darwin-foreign-caller-result.json", map[string]any{
		"boundary": "foreign_os_caller_private_policy", "foreignUID": uid, "ownerUID": f.Profile.OwnerUID,
		"diagnostic": diagnostic, "foregroundWaitAndReadersJoined": true,
		"sameProtectedProcessesBrokerVolumeAndRecord": true, "alternateAccountEnrollmentClaimed": false,
	})
}

// The installed runtime creates the real compatible broker. Refusals below
// exercise the product's read-only preflight with different expectations;
// they do not represent another OS account or an alternate CLI enrollment.
func TestInstalledCLIDarwinRealComposeReadOnlyIdentityRefusal(t *testing.T) {
	f, selection, record := composeDarwinCLIEnrolledFixture(t)
	original := darwinScenarioCold(t, f, selection, record, "darwin-refusal-cold")
	stored := darwinScenarioStored(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	port, err := urlPort(f.Profile.NATSEndpoint)
	if err != nil {
		t.Fatal("real refusal fixture selected port unavailable")
	}
	for _, row := range []struct {
		name   string
		change func(*DockerConfig, *OwnershipPreflight)
		code   string
	}{
		{"foreign_instance", func(_ *DockerConfig, owner *OwnershipPreflight) {
			owner.InstanceID = "instance_" + bootstrapFixtureRandom(t, 16)
		}, "docker_resource_conflict"},
		{"foreign_profile", func(_ *DockerConfig, owner *OwnershipPreflight) {
			owner.ProfileID = "profile_" + bootstrapFixtureRandom(t, 16)
		}, "docker_resource_conflict"},
		{"incompatible_release", func(_ *DockerConfig, owner *OwnershipPreflight) {
			owner.ReleaseDigest = "sha256:" + strings.Repeat("0", 64)
		}, "docker_resource_conflict"},
		{"wrong_declared_context", func(config *DockerConfig, _ *OwnershipPreflight) {
			config.Context = "amx-unenrolled-" + bootstrapFixtureRandom(t, 8)
		}, "docker_command_failed"},
		{"wrong_declared_endpoint", func(config *DockerConfig, _ *OwnershipPreflight) {
			config.Endpoint = "unix:///private/tmp/amx-unselected-" + bootstrapFixtureRandom(t, 8) + ".sock"
		}, "docker_selection_mismatch"},
	} {
		t.Run(row.name, func(t *testing.T) {
			config, owner := f.Driver.config, f.Owner
			row.change(&config, &owner)
			driver, err := NewDocker(config)
			if err != nil {
				t.Fatal("real refusal expectation was invalid before inspection")
			}
			broker, failure := driver.InspectOwnedTLSBroker(ctx, owner, f.Config.BrokerImage, port, f.Config.BrokerConfigDigest,
				sha256.Sum256(f.Config.LocalTLS.ServerCertificatePEM()), sha256.Sum256(f.Config.LocalTLS.ServerKeyPEM()))
			diagnostic := ProjectRequestDiagnostic(failure)
			if failure == nil || broker != (OwnedBroker{}) || !ValidRequestDiagnostic(diagnostic) || diagnostic.Code != row.code || ctx.Err() != nil {
				t.Fatal("actual resource preflight did not produce the expected closed refusal")
			}
			darwinScenarioRecoveryPreserved(t, f, stored, ctx)
			original.lifetime.assertUnchanged(t, f)
			f.WriteEvidence(t, "darwin-read-only-refusal-"+row.name+".json", map[string]any{
				"boundary": "product_read_only_preflight", "diagnostic": diagnostic,
				"selectedContext": config.Context, "sameBrokerVolumeAndRecord": true,
				"originalProtectedProcessesLive": true, "otherOSAccountClaimed": false,
			})
		})
		if t.Failed() {
			f.RetainForRecovery(t)
			return
		}
	}
	deadline, _ := ctx.Deadline()
	darwinScenarioRefresh(t, f, deadline)
	stored.assertPreserved(t, f, "darwin-read-only-refusal-preservation.json")
}

// A preexisting, authenticated broker and durable record make this a partial
// stack. The last-role lease blocks all role spawns. The existing 30-second
// lease wait and 60-second startup limit remain unchanged.
func TestInstalledCLIDarwinRealComposeStartupLeaseDeadlineAndRetry(t *testing.T) {
	f, selection, record := composeDarwinCLIEnrolledFixture(t)
	stored := darwinStartupOwnerStoredBroker(t, f)
	roleIDs := bootstrapFixtureRoleLeaseIDs(f.Profile.Docker.EngineID)
	allIDs := append([]string{"owner-status-service", f.Profile.Docker.EngineID}, roleIDs...)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	darwinStartupOwnerLeasesFree(t, f, ctx, allIDs)
	gate, err := AcquireBootstrapLock(ctx, f.Profile.ProfileDirectory, f.Profile.InstanceID, roleIDs[len(roleIDs)-1])
	cancel()
	if err != nil || gate == nil {
		t.Fatal("startup deadline last-role lease unavailable")
	}
	var original *composeDarwinCLIFront
	launched, exited := false, false
	// The frontend cleanup is registered later and handles its exact owner
	// first. An uncertain owner keeps this gate and fixture reachable.
	t.Cleanup(func() {
		if gate.file == nil {
			return
		}
		if launched && !exited {
			if original != nil && original.creatorOwned() {
				cleanup, stop := context.WithTimeout(context.Background(), f.Config.Deadlines.StopGrace+f.Config.Deadlines.ReapTimeout)
				exited = original.lifetime.host.WaitExit(cleanup) == nil
				stop()
			}
			if !exited {
				darwinStartupOwnerRetainGate(f, original, gate)
				f.RetainForRecovery(t)
				t.Error("startup deadline exact owner exit unknown; original gate retained")
				return
			}
		}
		if gate.Close() != nil {
			f.RetainForRecovery(t)
			t.Error("startup deadline gate cleanup failed")
		}
	})
	original = composeDarwinCLIPrepare(t, f, selection, record, "ensure")
	original.mustOwnHost = true
	launched = true
	darwinScenarioStart(t, f, original, darwinScenarioEnsureBudget)
	out := darwinScenarioResponse(t, f, original, record, "darwin-startup-deadline-pending", darwinScenarioEnsureBudget, false)
	if !original.creatorOwned() || out == nil || out.Disposition != "starting" || !bridgeStartingUnknown(*out) ||
		out.StartupAttemptID == nil || *out.StartupAttemptID != original.lifetime.attempt {
		t.Fatal("startup deadline lacks authenticated unknown starting state")
	}
	held := append([]string{"owner-status-service", f.Profile.Docker.EngineID}, roleIDs[:len(roleIDs)-1]...)
	darwinStartupOwnerWaitPhase(t, f, original, held)
	deadline := original.output.started.Add(f.Config.StartupTimeout + f.Config.Deadlines.StopGrace + f.Config.Deadlines.ReapTimeout)
	ctx, cancel = context.WithDeadline(context.Background(), deadline)
	defer cancel()
	client, err := LoadOwnerBridgeClient(f.Config, *f.BridgeEnrollment)
	if err != nil {
		t.Fatal("startup deadline current observation client refused")
	}
	pendingObservations := 0
	for ctx.Err() == nil {
		poll, stop := context.WithTimeout(ctx, 20*time.Millisecond)
		waitErr := original.lifetime.host.WaitExit(poll)
		stop()
		if waitErr == nil {
			exited = true
			break
		}
		if !errors.Is(waitErr, context.DeadlineExceeded) {
			f.RetainForRecovery(t)
			t.Fatal("startup deadline exact host observation failed")
		}
		invocation := "attempt_" + bootstrapFixtureRandom(t, 16)
		request, stop := context.WithTimeout(ctx, 2*time.Second)
		current, requestErr := client.Request(request, "status", invocation)
		stop()
		if requestErr == nil {
			if !bridgeObservationBound(current, *f.BridgeEnrollment, invocation, time.Now()) ||
				(current.Disposition != "starting" && current.Disposition != "failed") ||
				(current.Disposition == "starting" && !bridgeStartingUnknown(current)) || current.Instance.RunningVersion != nil {
				f.RetainForRecovery(t)
				t.Fatal("blocked startup reported unbound or false current readiness")
			}
			pendingObservations++
		} else {
			switch requestErr.Error() {
			case "owner_bridge_connection_unavailable", "owner_bridge_reply_unavailable", "owner_bridge_deadline":
			default:
				f.RetainForRecovery(t)
				t.Fatal("startup deadline observation lost authentication or cleanup ownership")
			}
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
		}
		timer.Stop()
	}
	if !exited || ctx.Err() != nil {
		f.RetainForRecovery(t)
		t.Fatal("blocked startup did not tear down within its unchanged startup and cleanup budgets")
	}
	if _, err := gate.file.Stat(); err != nil || len(original.lifetime.roles) != 0 || time.Since(original.output.started) < 30*time.Second || pendingObservations == 0 {
		f.RetainForRecovery(t)
		t.Fatal("startup ended without retaining the role barrier through its existing lease deadline")
	}
	darwinStartupOwnerLeasesFree(t, f, ctx, held)
	status := composeDarwinCLIStart(t, f, selection, record, "status", false)
	raw, succeeded := status.wait(t, f, "darwin-startup-deadline-terminal", darwinScenarioRefusalBudget)
	history, code := composeCLIFailureHistoryCode(raw, original.lifetime.attempt, time.Now())
	if succeeded || status.creatorOwned() || code != "" || history.Diagnostic != requestDiagnostic("request_deadline") {
		f.RetainForRecovery(t)
		t.Fatal("installed status lacks the exact failed startup attempt and actionable deadline diagnostic")
	}
	f.WriteEvidence(t, "darwin-startup-deadline-result.json", map[string]any{
		"scenario": "partial_stack_role_lease_deadline", "history": history,
		"originalStartupBudgetNanoseconds": int64(f.Config.StartupTimeout), "existingRoleLeaseLimitNanoseconds": int64(30 * time.Second),
		"exactHostExited": true, "hostLeasesReleasedWhileGateHeld": true,
		"validatedPendingOrFailedObservations": pendingObservations,
		"fullReadinessBudgetExhaustionClaimed": false, "afterPartialSpawnFailureClaimed": false,
	})
	stored.assertPreserved(t, f, "darwin-startup-deadline-preservation.json")
	if gate.Close() != nil {
		f.RetainForRecovery(t)
		t.Fatal("startup deadline exact gate release failed")
	}
	darwinStartupOwnerLeasesFree(t, f, ctx, allIDs)
	cancel()
	retry := composeDarwinCLIPrepare(t, f, selection, record, "ensure")
	retry.mustOwnHost = true
	darwinScenarioStart(t, f, retry, darwinScenarioEnsureBudget)
	darwinScenarioResponse(t, f, retry, record, "darwin-startup-deadline-retry", darwinScenarioEnsureBudget, true)
	darwinScenarioReady(t, f, retry, "darwin-startup-deadline-retry-ready.json")
	if retry.lifetime.attempt == original.lifetime.attempt || !errors.Is(original.lifetime.host.Live(), darwinfixtureidentity.ErrExited) {
		t.Fatal("corrected startup did not use a new exact creating owner")
	}
	stored.assertPreserved(t, f, "darwin-startup-deadline-retry-preservation.json")
}
