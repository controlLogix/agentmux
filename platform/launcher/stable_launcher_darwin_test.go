//go:build darwin && arm64 && cgo && agentmux_bootstrap_docker

package launcher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/internal/darwinfixtureidentity"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

// This case changes only the frontend image. The existing fixture owns the
// enrolled host, role images, broker, volume and all original cleanup handles.
func stableFrontendStart(t *testing.T, f *bootstrapDockerFixture, s HostPolicySelection, r hostPolicyRecord, operation, pin string, mustOwn bool) *composeDarwinCLIFront {
	t.Helper()
	x := composeDarwinCLIPrepare(t, f, s, r, operation)
	x.launch.Path, x.launch.Digest = protected.StableFrontendPath, pin
	x.mustOwnHost = mustOwn
	if x.hostExpected.Path != r.RuntimeExecutable.Path || x.hostExpected.Digest != r.RuntimeExecutable.Digest {
		t.Fatal("stable frontend changed enrolled host expectation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), darwinScenarioEnsureBudget)
	defer cancel()
	var err error
	x.owned, err = x.creator.StartStableFrontend(ctx, x.launch)
	if x.owned != nil {
		x.output.started = x.owned.StartedAt()
	}
	if err != nil {
		t.Fatal("stable frontend admission or creation failed")
	}
	x.proof, x.pinErr = x.owned.Pin(ctx)
	return x
}

// The caller owns the input pipe. The native helper keeps the same child, wait
// and output owners across the frontend's direct exec into installed Python.
func stableInstalledClientStart(t *testing.T, f *bootstrapDockerFixture, s HostPolicySelection, r hostPolicyRecord, operation, pin, clientID, selection string, input *os.File, mustOwn bool, application *stableInstalledApplication, admission *stableInstalledClientColdAdmission) *composeDarwinCLIFront {
	t.Helper()
	if mustOwn && application != nil && admission == nil {
		t.Fatal("cold installed client requires its original admission owner before launch")
	}
	x := composeDarwinCLIPrepare(t, f, s, r, operation)
	x.launch.Path, x.launch.Digest = protected.StableFrontendPath, pin
	x.launch.Args = []string{operation, "--client-installation", clientID, "--selection", selection}
	x.installedClient = true
	x.launch.Stdin = input
	x.launch.Dir = filepath.Dir(selection)
	x.mustOwnHost = mustOwn
	if application != nil {
		expected := application.expected
		x.hostExpected.Application = &expected
	}
	ctx, cancel := context.WithTimeout(context.Background(), darwinScenarioEnsureBudget)
	defer cancel()
	var err error
	x.owned, err = x.creator.StartInstalledClient(ctx, x.launch, clientID, operation, selection)
	if admission != nil {
		admission.anchor = x
	}
	if x.owned != nil {
		x.output.started = x.owned.StartedAt()
	}
	if err != nil {
		if application != nil && mustOwn && x.owned != nil {
			admission.terminal(nil, err)
			admission.holdFailure(t, f, x)
		}
		t.Fatal("installed client admission or creation failed")
	}
	x.proof, x.pinErr = x.owned.Pin(ctx)
	return x
}

// Check the installed payload before the existing fixture can contact Docker.
func stableInstalledClientPrerequisites(t *testing.T) (string, string) {
	t.Helper()
	pin, clientID := os.Getenv("AMX_STABLE_FRONTEND_SHA256"), os.Getenv("AMX_INSTALLED_CLIENT_ID")
	if !digest.MatchString(pin) || !protected.ValidClientInstallationID(clientID) {
		t.Fatal("reviewed stable frontend digest and installed client ID required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	admitted, err := protected.PrepareInstalledClient(ctx, clientID)
	cancel()
	if err != nil {
		t.Fatal("installed client prerequisite refused")
	}
	if admitted.Close() != nil {
		t.Fatal("installed client prerequisite did not close")
	}
	return pin, clientID
}

func TestStableInstalledClientDarwinMCPPreservesEnrolledHost(t *testing.T) {
	pin, clientID := stableInstalledClientPrerequisites(t)
	f, s, r := stableInstalledClientFixture(t)
	stableInstalledClientScenario(t, f, s, r, pin, clientID, false, nil)
}

func TestStableInstalledClientDarwinColdMCPStartup(t *testing.T) {
	// A terminal admission failure cannot safely return through test cleanup.
	// The explicitly retained collector must outlive the failed observation.
	if os.Getenv("AMX_INSTALLED_CLIENT_COLD_FAILURE_HOLD") != "1" {
		t.Fatal("cold client requires an explicit collector failure hold")
	}
	if _, finite := t.Deadline(); finite {
		t.Fatal("cold collector failure hold requires test timeout disabled")
	}
	pin, clientID := stableInstalledClientPrerequisites(t)
	application := stableInstalledApplicationPrerequisites(t, clientID)
	f, s, r := stableInstalledClientFixture(t)
	stableInstalledClientScenario(t, f, s, r, pin, clientID, true, application)
}

// A retained run loads the approved host policy and takes fresh Docker
// baselines. Historical cleanup files never supply resource-removal authority.
func stableInstalledClientFixture(t *testing.T) (*bootstrapDockerFixture, HostPolicySelection, hostPolicyRecord) {
	t.Helper()
	path := os.Getenv("AMX_INSTALLED_CLIENT_HOST_POLICY")
	if path == "" {
		return composeDarwinCLIEnrolledFixture(t)
	}
	if os.Getenv("AMX_BOOTSTRAP_DOCKER_AUTHORIZED") != "1" {
		t.Fatal("actual Docker fixture authorization missing")
	}
	raw := bootstrapDarwinPrivatePrerequisite(t, "AMX_INSTALLED_CLIENT_HOST_POLICY", "AMX_INSTALLED_CLIENT_HOST_POLICY_SHA256")
	selected, _ := loadBootstrapFixtureSelection(t)
	s := HostPolicySelection{Path: path, OwnerUID: uint32(os.Geteuid()), WorkspaceRoots: []string{selected.WorkspaceRoot}}
	h, err := LoadEnrolledHostPolicy(s)
	if err != nil {
		t.Fatal("retained installed host policy refused")
	}
	c, _, err := h.Load()
	if err != nil || h.record.OwnerBridge == nil {
		t.Fatal("retained enrolled configuration unavailable")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("retained host policy changed during admission")
	}
	loaded, err := LoadProfile(c.ProfilePolicy)
	if err != nil {
		t.Fatal("retained profile refused")
	}
	profile := loaded.Declaration()
	if profile.Docker == nil || !reflect.DeepEqual(*profile.Docker, selected.Docker) || c.BrokerImage != selected.Image {
		t.Fatal("retained fixture does not match independently pinned engine and image")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	image, err := h.PrepareHost(ctx)
	if err != nil {
		t.Fatal("retained installed runtime image refused")
	}
	if image.Close() != nil {
		t.Fatal("retained runtime image descriptors did not close")
	}
	driver, err := NewDocker(selected.dockerConfig())
	if err != nil {
		t.Fatal("retained Docker selection refused")
	}
	if _, err := driver.Inspect(ctx); err != nil {
		t.Fatal("retained Docker engine or versions changed")
	}
	directory, err := os.MkdirTemp(filepath.Dir(path), "installed-client-live-")
	if err != nil {
		t.Fatal("private installed client run directory unavailable")
	}
	f := &bootstrapDockerFixture{Config: c, Profile: profile, Driver: driver, Project: profile.ComposeProject,
		EvidenceDirectory: directory, HostPolicy: h.policy, ownedIDs: map[string]bool{},
		BridgeEnrollment: &OwnerBridgeEnrollment{Owner: h.record.Owner, Credentials: *h.record.OwnerBridge},
		Owner: OwnershipPreflight{Project: profile.ComposeProject, InstanceID: profile.InstanceID, ProfileID: profile.ProfileID,
			ReleaseDigest: profile.ReleaseFingerprint, ConfigDigest: sha256.Sum256(c.Compose)}}
	f.baseline, err = f.inventory(ctx)
	if err != nil {
		t.Fatal("retained fixture fresh container baseline unavailable")
	}
	f.networkBaseline, err = f.networkInventory(ctx)
	if err != nil {
		t.Fatalf("retained fixture fresh network baseline unavailable: stage=%s code=%s", bootstrapNetworkReadStage(err), bootstrapFixtureFailureCode(err))
	}
	volume, err := f.volume(ctx)
	if err != nil || os.Getenv("AMX_INSTALLED_CLIENT_VOLUME_CREATED_AT") == "" || volume.CreatedAt != os.Getenv("AMX_INSTALLED_CLIENT_VOLUME_CREATED_AT") {
		t.Fatal("retained volume creation identity or ownership changed")
	}
	t.Cleanup(func() { f.Cleanup(t) })
	return f, s, h.record
}

func stableInstalledClientScenario(t *testing.T, f *bootstrapDockerFixture, s HostPolicySelection, r hostPolicyRecord, pin, clientID string, fromMCP bool, application *stableInstalledApplication) {
	t.Helper()
	selectionDirectory := filepath.Dir(s.Path)
	for _, root := range s.WorkspaceRoots {
		rel, err := filepath.Rel(root, selectionDirectory)
		if err != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
			t.Fatal("installed client working directory must be outside every workspace")
		}
	}
	value := map[string]any{"schemaVersion": "1.0.0", "hostPolicy": s.Path, "workspaces": s.WorkspaceRoots,
		"instanceId": r.InstanceID, "profileId": r.ProfileID, "hubId": r.Owner.Identity.OwnerHubID}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal("installed client selection could not be encoded")
	}
	var selection string
	enrollmentBytes := append(append([]byte(nil), raw...), '\n')
	if application != nil {
		if !fromMCP || application.selected.HostPolicy != s.Path || application.selected.InstanceID != r.InstanceID || application.selected.ProfileID != r.ProfileID {
			t.Fatal("selected application fixture does not match this cold host")
		}
		selection, enrollmentBytes = application.path, application.raw
	} else {
		file, err := os.CreateTemp(selectionDirectory, "installed-mcp-client-*.private.json")
		if err != nil {
			t.Fatal("private installed client selection could not be created")
		}
		selection = file.Name()
		_, writeErr := file.Write(enrollmentBytes)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatal("private installed client selection did not finish writing")
		}
	}
	policyBefore, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatal("enrolled host policy unavailable")
	}
	var cold *composeDarwinCLIFront
	defer func() {
		if t.Failed() && application != nil && cold != nil && cold.lifetime != nil && cold.lifetime.admissionFailure != nil {
			cold.lifetime.admissionFailure(fmt.Errorf("selected_service_scenario_failed"))
		}
	}()
	var before darwinScenarioStoredState
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	broker, brokerErr := f.ObserveBroker(ctx)
	cancel()
	if brokerErr != nil || broker.State != "absent" {
		t.Fatal("installed client cold scenario requires an absent owned broker")
	}
	if !fromMCP {
		cold = stableFrontendStart(t, f, s, r, "ensure", pin, true)
		darwinScenarioResponse(t, f, cold, r, "installed-client-cold-ensure", darwinScenarioEnsureBudget, true)
		darwinScenarioReady(t, f, cold, "installed-client-cold-ready.json")
		before = darwinScenarioStored(t, f)
	}
	mcp := stableInstalledMCPExchange(t, f, s, r, pin, clientID, selection, "installed-client-mcp-eof", fromMCP, application)
	if fromMCP {
		cold = mcp
		if application != nil {
			darwinScenarioRefresh(t, f, cold.output.started.Add(f.Config.StartupTimeout))
			stableInstalledMCPExchange(t, f, s, r, pin, clientID, selection, "installed-client-warm-mcp-eof", false, application)
		}
		darwinScenarioReady(t, f, cold, "installed-client-cold-mcp-ready.json")
		before = darwinScenarioStored(t, f)
		if application == nil {
			stableInstalledMCPExchange(t, f, s, r, pin, clientID, selection, "installed-client-warm-mcp-eof", false, nil)
		}
	}
	cold.lifetime.assertUnchanged(t, f)
	startup := stableInstalledClientStart(t, f, s, r, "startup", pin, clientID, selection, nil, false, application, nil)
	startupOutput, success := startup.wait(t, f, "installed-client-startup", darwinScenarioEnsureBudget)
	if !success || len(startupOutput) != 0 || !strings.Contains(startup.stderr.String(), "Instance "+r.InstanceID+":") {
		t.Fatal("installed startup did not complete through its human output channel")
	}
	for _, operation := range []string{"ensure", "status"} {
		warm := stableFrontendStart(t, f, s, r, operation, pin, false)
		budget := darwinScenarioEnsureBudget
		if operation == "status" {
			budget = darwinScenarioRefusalBudget
		}
		out := darwinScenarioResponse(t, f, warm, r, "installed-client-warm-"+operation, budget, false)
		if out == nil || out.Disposition != "reused" || warm.lifetime != nil {
			t.Fatal("installed client scenario failed reuse of the original host")
		}
		cold.lifetime.assertUnchanged(t, f)
	}
	policyAfter, err := os.ReadFile(s.Path)
	selectionAfter, selectionErr := os.ReadFile(selection)
	if err != nil || selectionErr != nil || !bytes.Equal(policyBefore, policyAfter) || !bytes.Equal(selectionAfter, enrollmentBytes) {
		t.Fatal("installed client changed host policy or client enrollment")
	}
	before.assertPreserved(t, f, "installed-client-resource-preservation.json")
	if application != nil {
		if application.serviceCheck != nil {
			application.serviceCheck(t, f, cold)
			cold.lifetime.assertUnchanged(t, f)
		}
		stableInstalledApplicationLoss(t, f, cold)
		lost := *application
		lost.expectUnavailable = true
		stableInstalledMCPExchange(t, f, s, r, pin, clientID, selection, "installed-client-service-loss-mcp-eof", false, &lost)
		cold.lifetime.assertUnchanged(t, f)
		before.assertPreserved(t, f, "installed-client-service-loss-resource-preservation.json")
	}
}

type stableInstalledClientColdAdmission struct {
	anchor                *composeDarwinCLIFront
	ensure                *darwinfixtureidentity.Proof
	ensureExited          bool
	partial               []*darwinfixtureidentity.Proof
	failure               error
	inputWriter           io.Closer
	inputCloseAttempted   bool
	inputCloseErr         error
	frontendJoinAttempted bool
}

func (s *stableInstalledClientColdAdmission) closeInput() error {
	if s.inputWriter != nil && !s.inputCloseAttempted {
		s.inputCloseAttempted = true
		s.inputCloseErr = s.inputWriter.Close()
	}
	return s.inputCloseErr
}

// EOF permits the original client to finish without signalling its detached
// host. Joining the client never releases host, fixture or admission ownership.
func (s *stableInstalledClientColdAdmission) settleFrontend(ctx context.Context, join func(context.Context) error) {
	if err := s.closeInput(); err != nil {
		s.failure = errors.Join(s.failure, errors.New("cold_client_input_eof_failed"), err)
	}
	if join == nil || s.frontendJoinAttempted {
		return
	}
	s.frontendJoinAttempted = true
	if err := join(ctx); err != nil {
		s.failure = errors.Join(s.failure, errors.New("cold_client_frontend_join_incomplete"), err)
	}
}

// Ensure owns short-lived inspection commands before starting its detached
// host. Wait for the original ensure exit, then inspect its surviving children.
// No intermediate image becomes a host or an accepted extra roster member.
func (s *stableInstalledClientColdAdmission) hostAfterEnsureExit(ctx context.Context, waitExit func(context.Context) error, pinHost func(context.Context) (*darwinfixtureidentity.Proof, error)) (*darwinfixtureidentity.Proof, error) {
	if s.failure != nil {
		return nil, s.failure
	}
	if ctx == nil {
		return nil, errors.New("cold_client_context_invalid")
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, errors.New("cold_client_deadline_required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !s.ensureExited {
		if err := waitExit(ctx); err != nil {
			return nil, err
		}
		s.ensureExited = true
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return pinHost(ctx)
}

func (s *stableInstalledClientColdAdmission) checkpoint(t *testing.T, f *bootstrapDockerFixture, client *composeDarwinCLIFront) {
	t.Helper()
	s.anchor = client
	live := client != nil && client.proof != nil && client.proof.Live() == nil
	f.WriteEvidence(t, "cold-child-admission-checkpoint.json", map[string]any{
		"categories":                        darwinfixtureidentity.FailureCategories(s.failure),
		"childComparisons":                  darwinfixtureidentity.ChildRosterDiagnostics(s.failure),
		"childScanComparisons":              darwinfixtureidentity.ChildScanDiagnostics(s.failure),
		"originalAnchorPresentAtCheckpoint": s.anchor != nil && s.anchor.owned != nil,
		"originalAnchorLive":                live,
		"originalFrontendJoined":            client != nil && client.output.joined,
		"originalEnsureExitObserved":        s.ensureExited,
		"checkpointBeforeFrontendCleanup":   true,
	})
}

func (s *stableInstalledClientColdAdmission) holdFailure(t *testing.T, f *bootstrapDockerFixture, client *composeDarwinCLIFront) {
	t.Helper()
	s.anchor = client
	// Reporting itself can call t.Fatal. Install the hold first, so even failed
	// evidence writes cannot unwind into frontend or fixture cleanup.
	stableInstalledClientHoldBeforeReporting(func() {
		s.checkpoint(t, f, client)
		f.RetainForRecovery(t)
		t.Error("cold client admission failed; original collector held for recovery; cleanup has not run")
	}, func() {
		// Reporting or settlement failure must still retain every original owner.
		defer s.keepCollector(f)
		deadline := time.Now().Add(2 * time.Second)
		var join func(context.Context) error
		if client != nil && client.owned != nil {
			// Preserve the original startup budget and add only bounded join time.
			deadline = client.output.started.Add(darwinScenarioEnsureBudget + 2*time.Second)
			join = client.join
		}
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		s.settleFrontend(ctx, join)
		joined := client != nil && client.output.joined
		f.WriteEvidence(t, "cold-client-frontend-settlement.json", map[string]any{
			"inputCloseAttempted":   s.inputCloseAttempted,
			"inputCloseSucceeded":   s.inputCloseAttempted && s.inputCloseErr == nil,
			"frontendJoinAttempted": s.frontendJoinAttempted,
			"frontendJoined":        joined,
			"stdoutCaptureComplete": joined && client.completion.Stdout.Err == nil && !client.completion.Stdout.Overflow,
			"stderrCaptureComplete": joined && client.completion.Stderr.Err == nil && !client.completion.Stderr.Overflow,
			"fixtureStillHeld":      true,
		})
	})
}

func stableInstalledClientHoldBeforeReporting(report, hold func()) {
	defer hold()
	report()
}

func (s *stableInstalledClientColdAdmission) keepCollector(f *bootstrapDockerFixture) {
	// Do not return through t.Cleanup, retry admission or convert a diagnostic
	// into signalling authority. There is deliberately no abandon command.
	// Recovery must finish through these original owners before this lifecycle
	// can gain a release path. A process restart cannot recover the anchor.
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		runtime.KeepAlive(s)
		runtime.KeepAlive(f)
	}
}

// Only exact pre-admission absence is safe to poll. Keep every terminal error
// and partial proof reachable through the original client's cleanup callback.
func (s *stableInstalledClientColdAdmission) terminal(proof *darwinfixtureidentity.Proof, err error) bool {
	if s.failure == nil && proof == nil && darwinfixtureidentity.ChildNotPresent(err) {
		return false
	}
	if proof != nil {
		s.partial = append(s.partial, proof)
	}
	if err == nil {
		err = fmt.Errorf("cold_client_admission_result_invalid")
	}
	s.failure = errors.Join(s.failure, err)
	return true
}

func stableInstalledMCPExchange(t *testing.T, f *bootstrapDockerFixture, s HostPolicySelection, r hostPolicyRecord, pin, clientID, selection, name string, cold bool, application *stableInstalledApplication) *composeDarwinCLIFront {
	t.Helper()
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal("installed MCP input pipe unavailable")
	}
	// Registered after the original fixture cleanup and before launching the
	// client. Every failure still closes both pipe owners before fixture cleanup.
	admission := &stableInstalledClientColdAdmission{inputWriter: writer}
	inputOpen := true
	t.Cleanup(func() {
		if admission.failure != nil {
			f.RetainForRecovery(t)
			t.Errorf("cold MCP admission retained a terminal failure: %v", darwinfixtureidentity.FailureCategories(admission.failure))
		}
		if admission.ensure != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if admission.ensure.WaitExit(ctx) != nil || admission.ensure.Close() != nil {
				f.RetainForRecovery(t)
				t.Error("installed MCP ensure child proof did not finish cleanup")
			}
		}
		if admission.closeInput() != nil {
			t.Error("installed MCP input writer cleanup failed")
		}
		if inputOpen && input.Close() != nil {
			t.Error("installed MCP input descriptor cleanup failed")
		}
	})
	mcp := stableInstalledClientStart(t, f, s, r, "mcp", pin, clientID, selection, input, cold, application, admission)
	defer func() {
		if t.Failed() && cold && application != nil {
			admission.terminal(nil, fmt.Errorf("selected_cold_mcp_failed"))
			admission.holdFailure(t, f, mcp)
		}
	}()
	inputOpen = false
	if input.Close() != nil {
		t.Fatal("installed MCP parent input descriptor did not close")
	}
	if mcp.proof == nil || mcp.pinErr != nil || mcp.proof.Live() != nil {
		if cold && application != nil {
			admission.terminal(nil, fmt.Errorf("selected_client_anchor_refused"))
			admission.holdFailure(t, f, mcp)
		}
		t.Fatal("installed MCP Python process proof unavailable")
	}
	if cold {
		stableInstalledClientPinColdHost(t, f, mcp, pin, admission)
	}
	requests := "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"agentmux-fixture\",\"version\":\"1\"}}}\n" +
		"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n" +
		"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n" +
		"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"agentmux_startup_status\",\"arguments\":{}}}\n"
	if writer.SetWriteDeadline(time.Now().Add(time.Second)) != nil {
		t.Fatal("installed MCP input deadline unavailable")
	}
	if n, err := writer.Write([]byte(requests)); err != nil || n != len(requests) {
		t.Fatal("installed MCP protocol requests did not finish writing")
	}
	if admission.closeInput() != nil {
		t.Fatal("installed MCP EOF could not be sent")
	}
	output, success := mcp.wait(t, f, name, darwinScenarioEnsureBudget)
	exitAccepted := success
	if application != nil && application.expectUnavailable {
		var exit *exec.ExitError
		exitAccepted = !success && errors.As(mcp.completion.Err, &exit) && exit.ExitCode() == 1
	}
	if !exitAccepted || validateInstalledMCPOutput(output, r, cold, application) != nil {
		t.Fatal("installed MCP initialize, tools or startup status response refused")
	}
	return mcp
}

func stableInstalledClientPinColdHost(t *testing.T, f *bootstrapDockerFixture, client *composeDarwinCLIFront, pin string, admission *stableInstalledClientColdAdmission) {
	t.Helper()
	ctx, cancel := context.WithDeadline(context.Background(), client.output.started.Add(darwinScenarioEnsureBudget))
	defer cancel()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for ctx.Err() == nil {
		if admission.ensure == nil {
			proof, err := client.proof.PinDirectClientEnsure(ctx, client.hostExpected, pin)
			if err == nil {
				admission.ensure = proof
			} else if admission.terminal(proof, err) {
				admission.holdFailure(t, f, client)
				return
			}
		}
		if admission.ensure != nil {
			ensure := admission.ensure
			proof, err := admission.hostAfterEnsureExit(ctx, ensure.WaitExit, func(ctx context.Context) (*darwinfixtureidentity.Proof, error) {
				return ensure.PinDirectHost(ctx, client.hostExpected)
			})
			if err == nil {
				args := proof.LiteralArgs()
				if len(args) >= 6 && ownerBridgeInvocation.MatchString(args[5]) {
					client.lifetime = &composeDarwinCLILifetime{host: proof, attempt: args[5], inspection: client.inspection}
					if application := client.hostExpected.Application; application != nil {
						client.lifetime.applicationInstallation = application.InstallationID
						client.lifetime.admissionFailure = func(err error) { admission.terminal(nil, err); admission.holdFailure(t, f, client) }
					}
					return
				}
				admission.terminal(proof, fmt.Errorf("cold_client_host_arguments_refused"))
				if closeErr := proof.Close(); closeErr != nil {
					admission.terminal(nil, closeErr)
				}
				admission.holdFailure(t, f, client)
				return
			} else if admission.terminal(proof, err) {
				admission.holdFailure(t, f, client)
				return
			}
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	admission.terminal(nil, ctx.Err())
	admission.holdFailure(t, f, client)
}

func validateInstalledMCPOutput(raw []byte, r hostPolicyRecord, cold bool, selectedApplication ...*stableInstalledApplication) error {
	refused := fmt.Errorf("installed_mcp_response_refused")
	var application *stableInstalledApplication
	if len(selectedApplication) == 1 {
		application = selectedApplication[0]
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte{'\n'})
	if len(lines) != 3 {
		return refused
	}
	results := make([]json.RawMessage, 3)
	for i, line := range lines {
		var response struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      int             `json:"id"`
			Result  json.RawMessage `json:"result"`
		}
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&response) != nil || response.JSONRPC != "2.0" || response.ID != i+1 || len(response.Result) == 0 {
			return refused
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return refused
		}
		results[i] = response.Result
	}
	var initialized struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name string `json:"name"`
		} `json:"serverInfo"`
		Instructions string `json:"instructions"`
	}
	var listed struct {
		Tools []struct {
			Name        string `json:"name"`
			InputSchema struct {
				AdditionalProperties *bool `json:"additionalProperties"`
			} `json:"inputSchema"`
		} `json:"tools"`
	}
	var status struct {
		IsError           bool `json:"isError"`
		StructuredContent struct {
			SchemaVersion      string `json:"schemaVersion"`
			Kind               string `json:"kind"`
			Operation          string `json:"operation"`
			Outcome            string `json:"outcome"`
			Code               any    `json:"code"`
			Readiness          string `json:"infrastructureReadiness"`
			Disposition        string `json:"disposition"`
			InstanceID         string `json:"instanceId"`
			ProfileID          string `json:"profileId"`
			OwnerHubID         string `json:"callerIdentityOwnerHubId"`
			ApplicationAccess  string `json:"applicationAccess"`
			Dashboard          any    `json:"dashboard"`
			ApplicationBinding any    `json:"applicationBinding"`
		} `json:"structuredContent"`
	}
	if json.Unmarshal(results[0], &initialized) != nil || initialized.ProtocolVersion != "2025-06-18" || initialized.ServerInfo.Name != "agentmux" || !strings.Contains(initialized.Instructions, "Application access is unavailable") ||
		json.Unmarshal(results[1], &listed) != nil || len(listed.Tools) == 0 || listed.Tools[0].Name != "agentmux_startup_status" || listed.Tools[0].InputSchema.AdditionalProperties == nil || *listed.Tools[0].InputSchema.AdditionalProperties ||
		json.Unmarshal(results[2], &status) != nil || status.IsError {
		return refused
	}
	expectedTools := 1
	if application != nil && application.allowQuery {
		expectedTools++
	}
	if len(listed.Tools) != expectedTools && !(application != nil && (cold || application.expectUnavailable) && len(listed.Tools) == 1) {
		return refused
	}
	if len(listed.Tools) == 2 && (listed.Tools[1].Name != "agentmux_integration_effect_query" || listed.Tools[1].InputSchema.AdditionalProperties == nil || *listed.Tools[1].InputSchema.AdditionalProperties) {
		return refused
	}
	s := status.StructuredContent
	if s.SchemaVersion != "1.0.0" || s.Kind != "client-startup" || s.Operation != "ensure" || s.ApplicationAccess != "unavailable" || s.Dashboard != nil {
		return refused
	}
	if application == nil && s.ApplicationBinding != nil {
		return refused
	}
	if application != nil && s.ApplicationBinding != nil {
		binding, ok := s.ApplicationBinding.(map[string]any)
		verified := !application.expectUnavailable && binding["state"] == "verified" && binding["hubId"] == r.Owner.Identity.OwnerHubID
		unavailable := (cold || application.expectUnavailable) && binding["state"] == "unavailable" && binding["hubId"] == nil
		if !ok || len(binding) != 2 || !(verified || unavailable) {
			return refused
		}
	}
	if application != nil && !cold && s.ApplicationBinding == nil {
		return refused
	}
	if cold && s.Outcome == "progress" {
		if s.Code != "observation_unavailable" || s.Readiness != "unknown" || s.Disposition != "" || s.InstanceID != "" || s.ProfileID != "" || s.OwnerHubID != "" {
			return refused
		}
		return nil
	}
	if s.Outcome != "observed" || s.Code != nil || s.InstanceID != r.InstanceID || s.ProfileID != r.ProfileID || s.OwnerHubID != r.Owner.Identity.OwnerHubID {
		return refused
	}
	if cold {
		if s.Disposition != "started" && s.Disposition != "starting" {
			return refused
		}
		if s.Disposition == "started" && s.Readiness != "degraded" || s.Disposition == "starting" && s.Readiness != "not_ready" && s.Readiness != "unknown" {
			return refused
		}
	} else if s.Readiness != "degraded" || s.Disposition != "reused" {
		return refused
	}
	return nil
}

func TestInstalledClientColdAdmissionRetainsTerminalOwners(t *testing.T) {
	state := &stableInstalledClientColdAdmission{}
	partial := &darwinfixtureidentity.Proof{}
	cleanup := errors.New("close_failed")
	if !state.terminal(partial, cleanup) || len(state.partial) != 1 || state.partial[0] != partial || !errors.Is(state.failure, cleanup) {
		t.Fatal("cold admission lost its terminal error or partial proof owner")
	}
	if !state.terminal(nil, context.Canceled) || !errors.Is(state.failure, cleanup) || !errors.Is(state.failure, context.Canceled) {
		t.Fatal("later failure replaced retained cleanup ownership")
	}
}

func TestInstalledClientColdHostWaitsForEnsureInspectionChildren(t *testing.T) {
	ensure, host := &darwinfixtureidentity.Proof{}, &darwinfixtureidentity.Proof{}
	state := &stableInstalledClientColdAdmission{ensure: ensure}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	inspectionLive, originalExited := true, false
	waits, scans := 0, 0
	proof, err := state.hostAfterEnsureExit(ctx, func(received context.Context) error {
		waits++
		if received != ctx || scans != 0 || state.ensure != ensure {
			t.Error("host scan preceded the original ensure exit wait")
		}
		// Model ensure's actual ordering: join its inspection commands before
		// exiting, while its detached host remains a surviving child.
		inspectionLive, originalExited = false, true
		return nil
	}, func(received context.Context) (*darwinfixtureidentity.Proof, error) {
		scans++
		if received != ctx || inspectionLive || !originalExited || !state.ensureExited || state.ensure != ensure {
			t.Error("survivor scan ran before inspection commands and ensure exited")
		}
		return host, nil
	})
	if err != nil || proof != host || waits != 1 || scans != 1 || state.ensure != ensure {
		t.Fatal("ordered discovery lost an original owner or changed its result")
	}
}

func TestInstalledClientColdHostExitRefusalPreventsScanAndRetry(t *testing.T) {
	ensure := &darwinfixtureidentity.Proof{}
	state := &stableInstalledClientColdAdmission{ensure: ensure}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	exitErr := errors.New("original_ensure_exit_unconfirmed")
	waits, scans := 0, 0
	wait := func(context.Context) error { waits++; return exitErr }
	scan := func(context.Context) (*darwinfixtureidentity.Proof, error) {
		scans++
		return &darwinfixtureidentity.Proof{}, nil
	}
	proof, err := state.hostAfterEnsureExit(ctx, wait, scan)
	if proof != nil || err != exitErr || state.ensureExited {
		t.Fatal("unconfirmed ensure exit granted survivor scan permission")
	}
	state.terminal(proof, err)
	_, again := state.hostAfterEnsureExit(ctx, wait, scan)
	if waits != 1 || scans != 0 || state.ensure != ensure || !errors.Is(again, exitErr) || !errors.Is(state.failure, exitErr) {
		t.Fatal("exit refusal lost its original owner or permitted another attempt")
	}
}

func TestInstalledClientColdHostPreservesUnexpectedSurvivorRefusal(t *testing.T) {
	ensure, partial := &darwinfixtureidentity.Proof{}, &darwinfixtureidentity.Proof{}
	state := &stableInstalledClientColdAdmission{ensure: ensure}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	rosterErr := errors.New("original_unexpected_surviving_child")
	waits, scans := 0, 0
	wait := func(context.Context) error { waits++; return nil }
	scan := func(context.Context) (*darwinfixtureidentity.Proof, error) { scans++; return partial, rosterErr }
	proof, err := state.hostAfterEnsureExit(ctx, wait, scan)
	if proof != partial || err != rosterErr || !state.ensureExited {
		t.Fatal("ensure exit hid an unexpected surviving child or partial proof")
	}
	state.terminal(proof, err)
	_, again := state.hostAfterEnsureExit(ctx, wait, scan)
	if waits != 1 || scans != 1 || state.ensure != ensure || len(state.partial) != 1 || state.partial[0] != partial || !errors.Is(again, rosterErr) {
		t.Fatal("survivor refusal lost original ownership or retried discovery")
	}
}

func TestInstalledClientColdHostKeepsOriginalStartupDeadline(t *testing.T) {
	state := &stableInstalledClientColdAdmission{ensure: &darwinfixtureidentity.Proof{}}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	called := false
	wait := func(context.Context) error { called = true; return nil }
	scan := func(context.Context) (*darwinfixtureidentity.Proof, error) { called = true; return nil, nil }
	proof, err := state.hostAfterEnsureExit(ctx, wait, scan)
	if called || proof != nil || !errors.Is(err, context.DeadlineExceeded) || state.ensureExited {
		t.Fatal("host discovery extended an expired original startup deadline")
	}
	if _, err := state.hostAfterEnsureExit(context.Background(), wait, scan); err == nil || called {
		t.Fatal("host discovery accepted an unbounded startup wait")
	}
}

func TestInstalledClientColdHostCancellationAfterExitPreventsScan(t *testing.T) {
	ensure := &darwinfixtureidentity.Proof{}
	state := &stableInstalledClientColdAdmission{ensure: ensure}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	scans := 0
	proof, err := state.hostAfterEnsureExit(ctx, func(context.Context) error {
		cancel()
		return nil
	}, func(context.Context) (*darwinfixtureidentity.Proof, error) {
		scans++
		return &darwinfixtureidentity.Proof{}, nil
	})
	if proof != nil || !errors.Is(err, context.Canceled) || !state.ensureExited || scans != 0 || state.ensure != ensure {
		t.Fatal("exit observation bypassed cancellation or replaced the original ensure proof")
	}
	state.terminal(proof, err)
	if !errors.Is(state.failure, context.Canceled) {
		t.Fatal("post-exit cancellation was not retained as terminal")
	}
}

type coldAdmissionInputClose struct {
	calls int
	err   error
}

func (c *coldAdmissionInputClose) Close() error {
	c.calls++
	return c.err
}

func TestInstalledClientColdAdmissionSendsOriginalEOFBeforeJoin(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal("input pipe unavailable")
	}
	defer reader.Close()
	defer writer.Close()
	if reader.SetReadDeadline(time.Now().Add(time.Second)) != nil {
		t.Fatal("input read deadline unavailable")
	}
	original := &composeDarwinCLIFront{owned: &darwinfixtureidentity.Owned{}}
	partial := &darwinfixtureidentity.Proof{}
	cause := errors.New("original_scan_refusal")
	state := &stableInstalledClientColdAdmission{anchor: original, inputWriter: writer, ensure: partial}
	state.terminal(partial, cause)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	calls := 0
	join := func(received context.Context) error {
		calls++
		if received != ctx {
			t.Error("join lost its original bounded context")
		}
		var buffer [1]byte
		if n, err := reader.Read(buffer[:]); n != 0 || err != io.EOF {
			t.Error("original input did not reach EOF before join")
		}
		// The original join owns both captures; settlement must retain them.
		original.completion = darwinfixtureidentity.Completion{
			Stdout: darwinfixtureidentity.Output{Bytes: []byte("original stdout")},
			Stderr: darwinfixtureidentity.Output{Bytes: []byte("original stderr")},
		}
		original.output.joined = true
		return nil
	}
	state.settleFrontend(ctx, join)
	state.settleFrontend(ctx, join)
	if calls != 1 || !state.inputCloseAttempted || state.inputCloseErr != nil || !original.output.joined {
		t.Fatal("settlement repeated input closure or the original join")
	}
	if state.anchor != original || state.anchor.owned == nil || state.ensure != partial || len(state.partial) != 1 || state.partial[0] != partial || !errors.Is(state.failure, cause) {
		t.Fatal("frontend join released an original admission or proof owner")
	}
	if string(original.completion.Stdout.Bytes) != "original stdout" || string(original.completion.Stderr.Bytes) != "original stderr" {
		t.Fatal("frontend settlement lost the original output captures")
	}
}

func TestInstalledClientColdAdmissionRetainsFailedEOFAndJoin(t *testing.T) {
	closeFailure := errors.New("original_input_close_failed")
	writer := &coldAdmissionInputClose{err: closeFailure}
	original := &composeDarwinCLIFront{owned: &darwinfixtureidentity.Owned{}}
	original.completion.Stdout = darwinfixtureidentity.Output{Bytes: []byte("retained output"), Err: io.ErrUnexpectedEOF}
	partial := &darwinfixtureidentity.Proof{}
	cause := errors.New("original_scan_refusal")
	state := &stableInstalledClientColdAdmission{anchor: original, inputWriter: writer, ensure: partial}
	state.terminal(partial, cause)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	join := func(received context.Context) error {
		calls++
		return received.Err()
	}
	state.settleFrontend(ctx, join)
	state.settleFrontend(ctx, join)
	if writer.calls != 1 || calls != 1 || state.inputWriter != writer || original.output.joined {
		t.Fatal("failed settlement replaced or retried an original owner")
	}
	if state.anchor != original || state.ensure != partial || len(state.partial) != 1 || state.partial[0] != partial {
		t.Fatal("failed settlement lost its original anchor or proof")
	}
	if string(original.completion.Stdout.Bytes) != "retained output" || original.completion.Stdout.Err != io.ErrUnexpectedEOF {
		t.Fatal("incomplete frontend join discarded an original output capture or reader failure")
	}
	for _, err := range []error{cause, closeFailure, context.Canceled} {
		if !errors.Is(state.failure, err) {
			t.Fatal("failed settlement lost a retained refusal or cleanup failure")
		}
	}
}

func TestInstalledClientColdAdmissionClosesInputBeforeChildAvailable(t *testing.T) {
	writer := &coldAdmissionInputClose{}
	cause := errors.New("original_launch_refusal")
	state := &stableInstalledClientColdAdmission{inputWriter: writer}
	state.terminal(nil, cause)
	state.settleFrontend(context.Background(), nil)
	if writer.calls != 1 || state.inputWriter != writer || state.frontendJoinAttempted || !errors.Is(state.failure, cause) {
		t.Fatal("early launch failure lost its original input or failure owner")
	}
}

func TestInstalledClientColdAdmissionHoldsBeforeFatalReportingCleanup(t *testing.T) {
	held, release, cleaned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	writer := &coldAdmissionInputClose{}
	state := &stableInstalledClientColdAdmission{inputWriter: writer}
	defer func() {
		close(release)
		select {
		case <-cleaned:
		case <-time.After(time.Second):
			t.Error("controlled hold test did not join its original goroutine")
		}
	}()
	go func() {
		defer close(cleaned)
		stableInstalledClientHoldBeforeReporting(runtime.Goexit, func() {
			state.settleFrontend(context.Background(), func(context.Context) error { return nil })
			close(held)
			<-release
		})
	}()
	select {
	case <-held:
	case <-time.After(time.Second):
		t.Fatal("fatal reporting did not enter the original collector hold")
	}
	if writer.calls != 1 || !state.frontendJoinAttempted {
		t.Fatal("fatal reporting skipped original input closure or frontend join")
	}
	select {
	case <-cleaned:
		t.Fatal("fatal reporting unwound cleanup before the collector hold")
	default:
	}
}

func TestInstalledMCPOutputRefusesNoiseScopeAndApplicationAccess(t *testing.T) {
	r := hostPolicyRecord{InstanceID: "fixture_instance", ProfileID: "fixture_profile"}
	r.Owner.Identity.OwnerHubID = "fixture_hub"
	status := map[string]any{"schemaVersion": "1.0.0", "kind": "client-startup", "operation": "ensure", "outcome": "observed", "code": nil,
		"infrastructureReadiness": "degraded", "disposition": "reused", "instanceId": r.InstanceID, "profileId": r.ProfileID,
		"callerIdentityOwnerHubId": r.Owner.Identity.OwnerHubID, "applicationAccess": "unavailable", "dashboard": nil}
	tools := []any{map[string]any{"name": "agentmux_startup_status", "inputSchema": map[string]any{"additionalProperties": false}}}
	encode := func() []byte {
		results := []any{
			map[string]any{"protocolVersion": "2025-06-18", "serverInfo": map[string]any{"name": "agentmux"}, "instructions": "Application access is unavailable"},
			map[string]any{"tools": tools},
			map[string]any{"isError": false, "structuredContent": status},
		}
		var output []byte
		for i, result := range results {
			line, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": i + 1, "result": result})
			if err != nil {
				t.Fatal("MCP control response could not be encoded")
			}
			output = append(output, append(line, '\n')...)
		}
		return output
	}
	valid := encode()
	if validateInstalledMCPOutput(valid, r, false) != nil {
		t.Fatal("valid infrastructure-only MCP response refused")
	}
	for _, changed := range [][]byte{append([]byte("human output\n"), valid...), append(append([]byte(nil), valid...), []byte("{}\n")...), bytes.Replace(valid, []byte("}\n"), []byte("} trailing\n"), 1)} {
		if validateInstalledMCPOutput(changed, r, false) == nil {
			t.Fatal("non-protocol output was accepted")
		}
	}
	for key, changed := range map[string]any{"instanceId": "other_instance", "applicationAccess": "available", "dashboard": "https://example.invalid", "outcome": "failed", "disposition": "started", "infrastructureReadiness": "ready"} {
		original := status[key]
		status[key] = changed
		if validateInstalledMCPOutput(encode(), r, false) == nil {
			t.Fatal("changed scope, outcome or application access was accepted")
		}
		status[key] = original
	}
	application := &stableInstalledApplication{}
	status["applicationBinding"] = map[string]any{"state": "verified", "hubId": r.Owner.Identity.OwnerHubID}
	if validateInstalledMCPOutput(encode(), r, false, application) != nil || validateInstalledMCPOutput(encode(), r, false) == nil {
		t.Fatal("verified application binding was not restricted to explicit selection")
	}
	for _, binding := range []any{nil, map[string]any{"state": "unavailable", "hubId": nil}, map[string]any{"state": "verified", "hubId": "foreign_hub"}, map[string]any{"state": "verified", "hubId": r.Owner.Identity.OwnerHubID, "grant": true}} {
		status["applicationBinding"] = binding
		if validateInstalledMCPOutput(encode(), r, false, application) == nil {
			t.Fatal("warm selected service case accepted missing, foreign or expanded binding")
		}
	}
	status["applicationBinding"] = map[string]any{"state": "verified", "hubId": r.Owner.Identity.OwnerHubID}
	application.allowQuery = true
	if validateInstalledMCPOutput(encode(), r, false, application) == nil {
		t.Fatal("enrolled integration query was omitted from the tool list")
	}
	tools = append(tools, map[string]any{"name": "agentmux_integration_effect_query", "inputSchema": map[string]any{"additionalProperties": false}})
	if validateInstalledMCPOutput(encode(), r, false, application) != nil {
		t.Fatal("explicit read-only integration query menu refused")
	}
	application.allowQuery = false
	if validateInstalledMCPOutput(encode(), r, false, application) == nil {
		t.Fatal("unenrolled integration query menu was accepted")
	}
	application.allowQuery = true
	application.expectUnavailable = true
	if validateInstalledMCPOutput(encode(), r, false, application) == nil {
		t.Fatal("service-loss case accepted a stale verified binding")
	}
	status["applicationBinding"] = map[string]any{"state": "unavailable", "hubId": nil}
	if validateInstalledMCPOutput(encode(), r, false, application) != nil {
		t.Fatal("service-loss case refused unavailable binding with enrolled query menu")
	}
	tools = tools[:1]
	if validateInstalledMCPOutput(encode(), r, false, application) != nil {
		t.Fatal("service-loss case refused unavailable binding with status-only menu")
	}
	for _, binding := range []any{nil, map[string]any{"state": "unavailable", "hubId": r.Owner.Identity.OwnerHubID}, map[string]any{"state": "unavailable", "hubId": nil, "grant": true}} {
		status["applicationBinding"] = binding
		if validateInstalledMCPOutput(encode(), r, false, application) == nil {
			t.Fatal("service-loss case accepted missing or expanded unavailable binding")
		}
	}
}

func TestStableLauncherDarwinColdWarmPreservesEnrolledHost(t *testing.T) {
	pin := os.Getenv("AMX_STABLE_FRONTEND_SHA256")
	if !digest.MatchString(pin) {
		t.Fatal("separately reviewed stable frontend digest required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	image, err := protected.PrepareProtectedInstalledFrontend(ctx, protected.StableFrontendPath, pin, 128*1024*1024)
	cancel()
	if err != nil {
		t.Fatal("installed stable frontend prerequisite refused")
	}
	if image.Close() != nil {
		t.Fatal("stable frontend prerequisite close failed")
	}
	f, s, r := composeDarwinCLIEnrolledFixture(t)
	beforePolicy, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatal("enrolled host policy unavailable")
	}
	cold := stableFrontendStart(t, f, s, r, "ensure", pin, true)
	darwinScenarioResponse(t, f, cold, r, "stable-cold", darwinScenarioEnsureBudget, true)
	darwinScenarioReady(t, f, cold, "stable-ready.json")
	before := darwinScenarioStored(t, f)
	f.AssertBaselineUnchanged(t)
	for _, operation := range []string{"ensure", "status"} {
		warm := stableFrontendStart(t, f, s, r, operation, pin, false)
		budget := darwinScenarioEnsureBudget
		if operation == "status" {
			budget = darwinScenarioRefusalBudget
		}
		out := darwinScenarioResponse(t, f, warm, r, "stable-warm-"+operation, budget, false)
		if out == nil || out.Disposition != "reused" || warm.lifetime != nil {
			t.Fatal("stable frontend did not reuse the enrolled host")
		}
		cold.lifetime.assertUnchanged(t, f)
	}
	afterPolicy, err := os.ReadFile(s.Path)
	if err != nil || !bytes.Equal(beforePolicy, afterPolicy) {
		t.Fatal("stable frontend changed host enrollment")
	}
	before.assertPreserved(t, f, "stable-resource-preservation.json")
}
