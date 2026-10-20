//go:build darwin && cgo && agentmux_bootstrap_docker

package launcher

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/internal/darwinfixtureidentity"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

func composeDarwinFailurePreservation(t *testing.T, f *bootstrapDockerFixture, qualified *OwnedBroker, name string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	containers, err := f.inventory(ctx)
	if err != nil {
		f.RetainForRecovery(t)
		t.Fatal("negative startup complete container roster unavailable")
	}
	networks, err := f.networkInventory(ctx)
	if err != nil {
		f.RetainForRecovery(t)
		t.Fatal("negative startup complete network roster unavailable")
	}
	containersUnchanged, networksUnchanged, allQualified, addedRunning := true, true, true, false
	for id, before := range f.baseline {
		after, present := containers[id]
		containersUnchanged = containersUnchanged && present && reflect.DeepEqual(before, after)
	}
	for id, before := range f.networkBaseline {
		after, present := networks[id]
		networksUnchanged = networksUnchanged && present && reflect.DeepEqual(before, after)
	}
	addedContainers, addedNetworks := []map[string]any{}, []map[string]any{}
	for id, current := range containers {
		if _, original := f.baseline[id]; original {
			continue
		}
		verified := qualified != nil && qualified.ContainerID == id && qualified.State == current.State
		allQualified = allQualified && verified
		addedRunning = addedRunning || current.State == "running"
		addedContainers = append(addedContainers, map[string]any{"containerId": id, "state": current.State, "qualifiedByFullBrokerInspection": verified})
	}
	for id, current := range networks {
		if _, original := f.networkBaseline[id]; original {
			continue
		}
		// This provenance is minted only by the fixture's full selected broker
		// inspection plus exact creation and attachment admission, not labels.
		pin := f.networkProvenance
		verified := qualified != nil && pin != nil && pin.containerID == qualified.ContainerID && pin.network.ID == id && sameBootstrapNetworkIdentity(pin.network, current) && validBootstrapCounterTransition(pin.network, current, qualified.ContainerID)
		if verified {
			attachments, attachmentErr := f.networkAttachments(ctx, qualified.ContainerID)
			if attachmentErr != nil {
				verified = false
			} else if qualified.State == "running" {
				attachment, present := attachments[current.Name]
				verified = len(current.Endpoints) == 1 && current.Endpoints[qualified.ContainerID] == pin.endpointID && pin.endpointID != "" && len(attachments) == 1 && present && attachment.NetworkID == id && attachment.EndpointID == pin.endpointID
			} else {
				verified = validBootstrapStoppedNetwork(pin, f.networkBaseline, f.Owner, qualified.ContainerID, qualified.State, current, attachments)
			}
		}
		allQualified = allQualified && verified
		addedNetworks = append(addedNetworks, map[string]any{"networkId": id, "digest": current.Digest, "liveEndpointCount": len(current.Endpoints), "qualifiedCreationRelation": verified})
	}
	f.WriteEvidence(t, name, map[string]any{"scope": "Complete container and network rosters; selected volume checked separately where present", "originalContainersUnchanged": containersUnchanged, "originalNetworksUnchanged": networksUnchanged, "addedContainers": addedContainers, "addedNetworks": addedNetworks, "allAddedResourcesQualified": allQualified, "anyAddedContainerRunning": addedRunning, "readOnlyLedger": true})
	if !allQualified || !containersUnchanged || !networksUnchanged {
		f.RetainForRecovery(t)
	}
	if !containersUnchanged || !networksUnchanged {
		t.Fatal("negative startup changed an original baseline resource")
	}
	return allQualified && (!addedRunning || (qualified != nil && qualified.State == "running"))
}

// Only the native helper owns the command, wait and process authority. Buffers
// are populated from its joined snapshots, never from live output sinks.
type composeDarwinCLIFront struct {
	creator         *darwinfixtureidentity.Creator
	launch          darwinfixtureidentity.Launch
	owned           *darwinfixtureidentity.Owned
	proof           *darwinfixtureidentity.Proof
	pinErr          error
	output          composeCLIOutput
	stdout, stderr  bytes.Buffer
	completion      darwinfixtureidentity.Completion
	lifetime        *composeDarwinCLILifetime
	hostExpected    darwinfixtureidentity.ExpectedHost
	mustOwnHost     bool
	installedClient bool
	hostPinErr      error
	hostPinNoHost   bool
	hostPinProofs   []*darwinfixtureidentity.Proof
	hostPinMarked   bool
	hostPinDeadline time.Time
	hostPinAttempt  func(context.Context) composeDarwinHostPinResult
	joinAttempt     func(context.Context) (darwinfixtureidentity.Completion, error)
	inspection      *darwinfixtureidentity.InspectionSelection
}

// The native path alone supplies the exact post-exit empty-roster result. The private
// operation seam lets offline tests exercise this caller without native scans.
type composeDarwinHostPinResult struct {
	proof  *darwinfixtureidentity.Proof
	args   []string
	close  func() error
	err    error
	noHost bool
}

// This state receives only creator-derived proofs. It never accepts a PID or
// reconstructs process authority from a response, file or serialized identity.
type composeDarwinCLILifetime struct {
	inspection              *darwinfixtureidentity.InspectionSelection
	host                    *darwinfixtureidentity.Proof
	roles                   []*darwinfixtureidentity.Proof
	attempt                 string
	applicationInstallation string
	applicationService      *darwinfixtureidentity.Proof
	applicationEnded        bool
	admissionFailure        func(error)
	partial                 []*darwinfixtureidentity.Proof
	cleanupOwners           []any
}

func (x *composeDarwinCLILifetime) pinRoster(ctx context.Context, f *bootstrapDockerFixture, args map[string][]string) ([]*darwinfixtureidentity.Proof, error) {
	input := darwinfixtureidentity.Assembly{Raw: f.Config.Assembly, PackageDir: f.Config.PackageDirectory, Trust: f.Config.ReleaseTrust}
	if x.applicationInstallation != "" && !x.applicationEnded {
		if x.inspection != nil {
			return x.host.PinDirectRolesWithApplicationService(ctx, input, args, x.applicationInstallation, x.inspection)
		}
		return x.host.PinDirectRolesWithApplicationService(ctx, input, args, x.applicationInstallation)
	}
	if x.inspection != nil {
		return x.host.PinDirectRoles(ctx, input, args, x.inspection)
	}
	return x.host.PinDirectRoles(ctx, input, args)
}

func (x *composeDarwinCLIFront) creatorOwned() bool {
	return x.lifetime != nil && x.lifetime.host != nil && ownerBridgeInvocation.MatchString(x.lifetime.attempt)
}

func (x *composeDarwinCLIFront) observation(t *testing.T, f *bootstrapDockerFixture, r hostPolicyRecord, raw []byte, name string, allowReceipt bool) *StartupStatusObservation {
	t.Helper()
	attempt := ""
	if x.creatorOwned() {
		attempt = x.lifetime.attempt
	}
	return composeCLIOutputObservation(t, f, &x.output, r, raw, name, allowReceipt, attempt, x.creatorOwned())
}

type composeDarwinRoleExpectation struct {
	Role           string
	Path           string
	LiteralArgv    []string
	CredentialFile string
}

// These are fixture expectations, not process authority. The helper must admit
// the signed assembly and bind its retained images to actual descendants.
func composeDarwinRoleExpectations(c BootstrapConfig, profileDirectory string) ([]composeDarwinRoleExpectation, error) {
	if !bootstrapFixtureAbsolute(c.PackageDirectory) || filepath.Dir(c.PackageDirectory) != bootstrapDarwinReleaseBase ||
		!fullID.MatchString(filepath.Base(c.PackageDirectory)) || !bootstrapFixtureAbsolute(profileDirectory) {
		return nil, errors.New("darwin_role_expectation_path_invalid")
	}
	var expected []composeDarwinRoleExpectation
	seen := map[string]bool{}
	for _, role := range protocol.Roles() {
		found := false
		for _, option := range c.Roles {
			if option.ID != role {
				continue
			}
			credential := filepath.Join(profileDirectory, role+".json")
			if seen[role] || len(option.Args) != 0 || option.Env["AGENTMUX_NATS_CREDS_FILE"] != credential {
				return nil, errors.New("darwin_role_expectation_binding_invalid")
			}
			seen[role], found = true, true
			expected = append(expected, composeDarwinRoleExpectation{Role: role, Path: filepath.Join(c.PackageDirectory, "bin", role), LiteralArgv: []string{"agentmux-" + role}, CredentialFile: credential})
		}
		if !found {
			return nil, errors.New("darwin_role_expectation_missing")
		}
	}
	return expected, nil
}

func (x *composeDarwinCLILifetime) pinRoles(t *testing.T, f *bootstrapDockerFixture) {
	t.Helper()
	if x.host == nil || len(x.roles) != 0 {
		t.Fatal("creator host proof missing or role roster already pinned")
	}
	expected, expectationErr := composeDarwinRoleExpectations(f.Config, f.Profile.ProfileDirectory)
	if expectationErr != nil {
		t.Fatal("actual role fixture expectations refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	started := time.Now()
	args := map[string][]string{}
	for _, option := range f.Config.Roles {
		args[option.ID] = append([]string(nil), option.Args...)
	}
	proofs, err := x.pinRoster(ctx, f, args)
	x.roles = proofs
	expired := ctx.Err() != nil
	cancel()
	expectedCount := 4
	if x.applicationInstallation != "" && !x.applicationEnded {
		expectedCount++
	}
	if err != nil || len(proofs) != expectedCount {
		if x.admissionFailure != nil {
			x.admissionFailure(errors.Join(err, errors.New("fixture_application_roster_refused")))
		}
		f.WriteEvidence(t, "darwin-role-admission-failure.json", map[string]any{
			"categories": darwinfixtureidentity.FailureCategories(err), "returnedProofCount": len(proofs),
			"contextExpired": expired, "elapsedNanoseconds": time.Since(started).Nanoseconds(),
		})
		f.RetainForRecovery(t)
		t.Fatal("actual signed assembly descendant admission refused")
	}
	// Native enumeration order is unspecified. Associate each opaque proof by
	// its exact admitted role alias, never by its index or a reported process ID.
	// PinDirectRoles independently binds each native image path and digest.
	seen := map[string]bool{}
	roles := make([]*darwinfixtureidentity.Proof, 0, 4)
	for _, proof := range proofs {
		literal := proof.LiteralArgs()
		if x.applicationInstallation != "" {
			root := filepath.Join(protected.InstalledClientBase, x.applicationInstallation)
			serviceArgs := []string{filepath.Join(root, protected.ClientInterpreter), "-I", "-S", filepath.Join(root, protected.ClientBootstrap), "application-services"}
			if slices.Equal(literal, serviceArgs) && x.applicationService == nil {
				x.applicationService = proof
				continue
			}
		}
		if len(literal) == 0 || seen[literal[0]] {
			f.RetainForRecovery(t)
			t.Fatal("actual role proof has missing or repeated image association")
		}
		matched := false
		for _, role := range expected {
			if slices.Equal(literal, append(append([]string(nil), role.LiteralArgv...), args[role.Role]...)) {
				matched = true
				break
			}
		}
		if !matched {
			f.RetainForRecovery(t)
			t.Fatal("actual role proof differs from enrolled path or literal arguments")
		}
		seen[literal[0]] = true
		roles = append(roles, proof)
	}
	if len(roles) != 4 || (x.applicationInstallation != "" && x.applicationService == nil) {
		if x.admissionFailure != nil {
			x.admissionFailure(errors.New("fixture_application_roster_association_refused"))
		}
		t.Fatal("actual complete host child roster could not be associated")
	}
	x.roles = roles
}

func (x *composeDarwinCLILifetime) assertUnchanged(t *testing.T, f *bootstrapDockerFixture) {
	t.Helper()
	x.assertPinnedLive(t)
	args := map[string][]string{}
	for _, option := range f.Config.Roles {
		args[option.ID] = append([]string(nil), option.Args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	proofs, err := x.pinRoster(ctx, f, args)
	cancel()
	for _, proof := range proofs {
		if closeErr := proof.Close(); closeErr != nil {
			x.partial = append(x.partial, proof)
			err = errors.Join(err, closeErr)
			if x.admissionFailure != nil {
				x.admissionFailure(err)
			}
			f.RetainForRecovery(t)
			t.Error("temporary role roster authority did not close")
		}
	}
	expectedCount := 4
	if x.applicationInstallation != "" && !x.applicationEnded {
		expectedCount++
	}
	if err != nil || len(proofs) != expectedCount {
		if x.admissionFailure != nil {
			x.admissionFailure(errors.Join(err, errors.New("fixture_application_roster_changed")))
		}
		t.Fatal("reuse added or removed a protected role")
	}
	x.assertPinnedLive(t)
}

func (x *composeDarwinCLILifetime) assertPinnedLive(t *testing.T) {
	t.Helper()
	if x.host == nil || len(x.roles) != 4 || x.host.Live() != nil {
		t.Fatal("reuse lost the exact owned host or protected role roster")
	}
	for _, proof := range x.roles {
		if proof.Live() != nil {
			t.Fatal("reuse replaced an exact owned protected role")
		}
	}
	if x.applicationInstallation != "" {
		if x.applicationService == nil {
			t.Fatal("reuse lost the installed application service proof")
		}
		state := x.applicationService.Live()
		if (!x.applicationEnded && state != nil) || (x.applicationEnded && !errors.Is(state, darwinfixtureidentity.ErrExited)) {
			t.Fatal("reuse changed the expected installed application service lifetime")
		}
	}
}

func (x *composeDarwinCLILifetime) cleanup(t *testing.T, f *bootstrapDockerFixture) {
	t.Helper()
	defer func() {
		if t.Failed() && x.admissionFailure != nil {
			x.admissionFailure(errors.New("selected_service_cleanup_failed"))
		}
	}()
	if x.host == nil {
		f.RetainForRecovery(t)
		t.Error("newly spawned host ownership was not established; fixture retained")
		return
	}
	deadline := time.Now().Add(f.Config.Deadlines.StopGrace + f.Config.Deadlines.ReapTimeout)
	if x.applicationInstallation != "" {
		deadline = deadline.Add(5 * time.Second)
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	state := x.host.Live()
	if state == nil {
		if err := x.host.Signal(syscall.SIGTERM); err != nil {
			if x.admissionFailure != nil {
				x.admissionFailure(err)
				return
			}
			f.RetainForRecovery(t)
			t.Error("exact installed host stop failed")
		}
	} else if !errors.Is(state, darwinfixtureidentity.ErrExited) {
		if x.admissionFailure != nil {
			x.admissionFailure(state)
		}
		f.RetainForRecovery(t)
		t.Error("exact installed host lifetime could not be observed")
		return
	}
	err := x.host.WaitExit(ctx)
	if err != nil {
		if x.admissionFailure != nil {
			x.admissionFailure(err)
		}
		f.RetainForRecovery(t)
		t.Error("exact installed host exceeded its shutdown budget")
		return
	}
	if x.applicationService != nil {
		if err := x.applicationService.WaitExit(ctx); err != nil {
			if x.admissionFailure != nil {
				x.admissionFailure(err)
			}
			f.RetainForRecovery(t)
			t.Error("owned application service exit was not established")
			return
		}
		if err := x.applicationService.Close(); err != nil {
			if x.admissionFailure != nil {
				x.admissionFailure(err)
			}
			f.RetainForRecovery(t)
			t.Error("owned application service exit or proof cleanup was not established")
			return
		}
	}
	for _, proof := range x.roles {
		err = proof.WaitExit(ctx)
		if err != nil {
			if x.admissionFailure != nil {
				x.admissionFailure(err)
				return
			}
			f.RetainForRecovery(t)
			t.Error("owned protected role exit was not established")
			continue
		}
		if err := proof.Close(); err != nil {
			if x.admissionFailure != nil {
				x.admissionFailure(err)
				return
			}
			f.RetainForRecovery(t)
			t.Error("owned protected role proof did not close")
		}
	}
	if x.applicationInstallation != "" {
		lease, err := AcquireBootstrapLock(ctx, f.Profile.ProfileDirectory, f.Profile.InstanceID, "application-services")
		if err != nil {
			if x.admissionFailure != nil {
				x.admissionFailure(err)
			}
			f.RetainForRecovery(t)
			t.Error("joined application service retained its lifetime lease")
			return
		}
		if err := lease.Close(); err != nil {
			x.cleanupOwners = append(x.cleanupOwners, lease)
			if x.admissionFailure != nil {
				x.admissionFailure(err)
			}
			f.RetainForRecovery(t)
			t.Error("application service lease check did not close")
			return
		}
	}
	if err := x.host.Close(); err != nil {
		if x.admissionFailure != nil {
			x.admissionFailure(err)
		}
		f.RetainForRecovery(t)
		t.Error("exact installed host proof did not close")
	}
}

func TestInstalledCLIDarwinRoleFixtureExpectations(t *testing.T) {
	c := BootstrapConfig{PackageDirectory: filepath.Join(bootstrapDarwinReleaseBase, strings.Repeat("a", 64))}
	profile := "/private/var/agentmux-fixture/profile"
	for i, role := range protocol.Roles() {
		c.Roles[i] = protected.RoleOptions{ID: role, Env: map[string]string{"AGENTMUX_NATS_CREDS_FILE": filepath.Join(profile, role+".json")}}
	}
	expected, err := composeDarwinRoleExpectations(c, profile)
	if err != nil || len(expected) != 4 {
		t.Fatal("complete role fixture expectations refused")
	}
	for i, role := range protocol.Roles() {
		got := expected[i]
		if got.Role != role || got.Path != filepath.Join(c.PackageDirectory, "bin", role) ||
			!reflect.DeepEqual(got.LiteralArgv, []string{"agentmux-" + role}) || got.CredentialFile != filepath.Join(profile, role+".json") {
			t.Fatal("role fixture expectation differs from production spawn")
		}
	}
	for _, change := range []func(*BootstrapConfig){
		func(c *BootstrapConfig) { c.Roles[0].Args = []string{"unexpected"} },
		func(c *BootstrapConfig) { c.Roles[0].ID = c.Roles[1].ID },
		func(c *BootstrapConfig) {
			c.Roles[0].Env = map[string]string{"AGENTMUX_NATS_CREDS_FILE": filepath.Join(profile, "other.json")}
		},
		func(c *BootstrapConfig) { c.PackageDirectory = "/tmp/user-owned-release" },
	} {
		bad := c
		change(&bad)
		if _, err := composeDarwinRoleExpectations(bad, profile); err == nil {
			t.Fatal("invalid role fixture expectation accepted")
		}
	}
}

func (x *composeDarwinCLILifetime) abruptExit(t *testing.T, f *bootstrapDockerFixture) {
	t.Helper()
	if x.host == nil || len(x.roles) != 4 {
		t.Fatal("abrupt injection requires a creator-proven host and four exact roles")
	}
	killedAt := time.Now()
	if x.host.Signal(syscall.SIGKILL) != nil {
		t.Fatal("exact owned host failure injection refused")
	}
	deadline := killedAt.Add(f.Config.Deadlines.StopGrace + f.Config.Deadlines.ReapTimeout)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	for _, proof := range append([]*darwinfixtureidentity.Proof{x.host}, x.roles...) {
		if proof.WaitExit(ctx) != nil {
			f.RetainForRecovery(t)
			t.Fatal("abrupt host death did not establish exact descendant exit within the shared shutdown budget")
		}
	}
	bootstrapFixtureRoleLeases(t, f, false)
	lease, err := AcquireBootstrapLock(ctx, f.Profile.ProfileDirectory, f.Profile.InstanceID, "owner-status-service")
	if err != nil {
		f.RetainForRecovery(t)
		t.Fatal("abrupt host did not release its actual service lease")
	}
	if lease.Close() != nil {
		f.RetainForRecovery(t)
		t.Fatal("released service lease cleanup failed")
	}
	f.WriteEvidence(t, "abrupt-exit.json", map[string]any{"injection": "SIGKILL through previously held creator-proven native host identity", "exactHostExited": true, "exactRoleExitCount": len(x.roles), "sharedShutdownBudgetNanoseconds": int64(f.Config.Deadlines.StopGrace + f.Config.Deadlines.ReapTimeout), "elapsedNanoseconds": time.Since(killedAt).Nanoseconds(), "roleLeasesReleased": 4, "serviceLeaseReleased": true})
}

func composeDarwinCLIPrepare(t *testing.T, f *bootstrapDockerFixture, s HostPolicySelection, r hostPolicyRecord, operation string) *composeDarwinCLIFront {
	t.Helper()
	creator, err := darwinfixtureidentity.NewCreator()
	if err != nil {
		t.Fatal("native installed CLI creator admission refused")
	}
	args := []string{operation, "--host-policy", s.Path}
	for _, root := range s.WorkspaceRoots {
		args = append(args, "--workspace", root)
	}
	x := &composeDarwinCLIFront{creator: creator, launch: darwinfixtureidentity.Launch{Path: r.RuntimeExecutable.Path, Digest: r.RuntimeExecutable.Digest, Args: args, Env: os.Environ()}}
	commands, err := composeDarwinInspectionCommands(f.Profile.Docker, f.Profile.ComposeProject, f.Config.BrokerImage)
	if err != nil {
		t.Fatal("selected Docker inspection grammar refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	x.inspection, err = darwinfixtureidentity.PrepareInspectionSelection(ctx, f.Profile.Docker.Executable, commands)
	cancel()
	if x.inspection != nil {
		t.Cleanup(func() {
			if err := x.inspection.Close(); err != nil {
				f.RetainForRecovery(t)
				t.Error("selected inspection image owner did not close")
			}
		})
	}
	if err != nil {
		t.Fatal("selected Docker inspection image refused")
	}
	x.hostExpected = darwinfixtureidentity.ExpectedHost{Path: r.RuntimeExecutable.Path, Digest: r.RuntimeExecutable.Digest, PolicyPath: s.Path, WorkspaceRoots: append([]string(nil), s.WorkspaceRoots...)}
	x.output.stdout, x.output.stderr = &x.stdout, &x.stderr
	t.Cleanup(func() { x.cleanup(t, f) })
	return x
}

func (x *composeDarwinCLIFront) rememberHostPinDeadline(ctx context.Context) {
	// Stop and reap may use fresh budgets; host admission may only shorten
	// the deadline retained from the original frontend request.
	if deadline, bounded := ctx.Deadline(); bounded && (x.hostPinDeadline.IsZero() || deadline.Before(x.hostPinDeadline)) {
		x.hostPinDeadline = deadline
	}
}

func (x *composeDarwinCLIFront) pinHost(ctx context.Context) {
	// Installed Python clients own an ensure child. Their cold host proof is
	// admitted through the explicit ensure-to-host path, never this direct scan.
	if x.installedClient || x.lifetime != nil || x.hostPinErr != nil || x.hostPinNoHost {
		return
	}
	x.rememberHostPinDeadline(ctx)
	if !x.hostPinDeadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, x.hostPinDeadline)
		defer cancel()
	}
	if err := ctx.Err(); err != nil {
		x.hostPinErr = errors.Join(errors.New("native_host_admission_budget_expired"), err)
		return
	}
	if !x.output.joined || x.proof == nil {
		return
	}
	var result composeDarwinHostPinResult
	if x.hostPinAttempt != nil {
		result = x.hostPinAttempt(ctx)
	} else {
		if result.err = x.proof.WaitExit(ctx); result.err == nil {
			if result.err = ctx.Err(); result.err == nil {
				result.proof, result.err = x.proof.PinDirectHostAfterExit(ctx, x.hostExpected)
			}
		}
		result.noHost = result.proof == nil && darwinfixtureidentity.NoSurvivingHost(result.err)
		if result.proof != nil {
			result.args, result.close = result.proof.LiteralArgs(), result.proof.Close
		}
	}
	if result.proof != nil {
		x.hostPinProofs = append(x.hostPinProofs, result.proof)
	}
	if err := ctx.Err(); err != nil {
		result.err = errors.Join(result.err, err)
		result.noHost = false
	}
	if result.proof == nil && result.err != nil && result.noHost {
		x.hostPinNoHost = true
		return
	}
	if result.err != nil {
		x.hostPinErr = result.err
		return
	}
	if result.proof == nil {
		x.hostPinErr = errors.New("native_host_admission_result_invalid")
		return
	}
	if len(result.args) < 6 || !ownerBridgeInvocation.MatchString(result.args[5]) {
		x.hostPinErr = errors.New("native_host_admission_arguments_invalid")
		if result.close != nil {
			x.hostPinErr = errors.Join(x.hostPinErr, result.close())
		}
		return
	}
	x.lifetime = &composeDarwinCLILifetime{host: result.proof, attempt: result.args[5], inspection: x.inspection}
}

func (x *composeDarwinCLIFront) retainHostPinFailure(t *testing.T, f *bootstrapDockerFixture) bool {
	t.Helper()
	if x.hostPinErr == nil {
		return false
	}
	if !x.hostPinMarked {
		x.hostPinMarked = true
		f.RetainForRecovery(t)
	}
	return true
}

func (x *composeDarwinCLIFront) start(ctx context.Context) error {
	x.rememberHostPinDeadline(ctx)
	var err error
	x.owned, err = x.creator.StartProtected(ctx, x.launch)
	// Successful creation retains ownership even when a fast frontend exits
	// before full pinning. Post-start pin refusal is separate from launch failure.
	if x.owned != nil {
		x.output.started = x.owned.StartedAt()
	}
	if err != nil {
		return err
	}
	x.proof, x.pinErr = x.owned.Pin(ctx)
	return nil
}

func (x *composeDarwinCLIFront) join(ctx context.Context) error {
	if x.output.joined {
		return nil
	}
	var completion darwinfixtureidentity.Completion
	var err error
	if x.joinAttempt != nil {
		completion, err = x.joinAttempt(ctx)
	} else {
		completion, err = x.owned.Join(ctx)
	}
	if err != nil {
		return err
	}
	x.completion = completion
	x.output.terminal = composeCLIExit{err: completion.Err, at: completion.At}
	x.stdout.Write(completion.Stdout.Bytes)
	x.stderr.Write(completion.Stderr.Bytes)
	x.output.joined = true
	return nil
}

// Concurrent callers join the original frontend before classifying surviving
// children. Neither a host proof nor an empty roster substitutes for that join.
func (x *composeDarwinCLIFront) finished(ctx context.Context) bool {
	x.rememberHostPinDeadline(ctx)
	if x.output.joined {
		x.pinHost(ctx)
		return true
	}
	if x.owned == nil {
		return false
	}
	poll, cancel := context.WithTimeout(ctx, time.Millisecond)
	err := x.join(poll)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			x.pinHost(ctx)
		}
		return false
	}
	x.pinHost(ctx)
	return true
}

func (x *composeDarwinCLIFront) wait(t *testing.T, f *bootstrapDockerFixture, name string, budget time.Duration) ([]byte, bool) {
	t.Helper()
	x.output.captureName = name
	ctx, cancel := context.WithDeadline(context.Background(), x.output.started.Add(budget))
	x.rememberHostPinDeadline(ctx)
	var err error
	for ctx.Err() == nil {
		request, stop := context.WithTimeout(ctx, time.Millisecond)
		err = x.join(request)
		stop()
		if err == nil || !errors.Is(err, context.DeadlineExceeded) {
			break
		}
	}
	if !x.output.joined && err == nil {
		err = context.DeadlineExceeded
	}
	x.pinHost(ctx)
	x.retainHostPinFailure(t, f)
	cancel()
	if err != nil {
		f.WriteEvidence(t, name+"-deadline-failure.json", map[string]any{"observedElapsedNanoseconds": time.Since(x.output.started).Nanoseconds(), "boundNanoseconds": int64(budget), "frontendWaitJoined": false, "outputCaptureAvailable": false})
		t.Fatal("actual installed frontend did not join within its original request budget")
	}
	x.output.writeCapture(t, f)
	f.WriteEvidence(t, name+"-joined-diagnostic.json", x.output.joinedDiagnostic(x.creatorOwned()))
	f.WriteEvidence(t, name+"-native-admission.json", map[string]any{"frontendWaitJoined": true, "frontendFullPinAvailable": x.proof != nil, "frontendFullPinRefused": x.pinErr != nil, "creatorHostProofAvailable": x.creatorOwned(),
		"hostAdmissionRefused": x.hostPinErr != nil, "hostAdmissionCategories": darwinfixtureidentity.FailureCategories(x.hostPinErr), "retainedHostProofCount": len(x.hostPinProofs), "noSurvivingCreatedHost": x.hostPinNoHost})
	elapsed := x.output.terminal.at.Sub(x.output.started)
	f.WriteEvidence(t, name+"-timing.json", map[string]any{"entryToExitNanoseconds": elapsed.Nanoseconds(), "boundNanoseconds": int64(budget), "exitSuccess": x.output.terminal.err == nil, "stdoutBytes": x.stdout.Len(), "stderrBytes": x.stderr.Len()})
	if !x.output.captured || x.completion.Stdout.Overflow || x.completion.Stderr.Overflow || x.completion.Stdout.Err != nil || x.completion.Stderr.Err != nil {
		t.Fatal("actual installed frontend output capture failed or exceeded its bounds")
	}
	if elapsed > budget {
		t.Fatal("actual installed frontend exceeded its original request budget")
	}
	if x.retainHostPinFailure(t, f) {
		t.Fatal("native host admission failed; original proof and failure owners retained")
	}
	if x.mustOwnHost && !x.creatorOwned() {
		f.RetainForRecovery(t)
		t.Fatal("cold frontend lacks its pinned creator and exact host proof")
	}
	return append([]byte(nil), x.stdout.Bytes()...), x.output.terminal.err == nil
}

func (x *composeDarwinCLIFront) cleanup(t *testing.T, f *bootstrapDockerFixture) {
	t.Helper()
	if !x.hostPinDeadline.IsZero() && !time.Now().Before(x.hostPinDeadline) {
		ctx, cancel := context.WithDeadline(context.Background(), x.hostPinDeadline)
		x.pinHost(ctx)
		cancel()
	}
	x.retainHostPinFailure(t, f)
	if x.owned == nil {
		return
	}
	defer func() {
		if x.lifetime != nil {
			x.lifetime.cleanup(t, f)
		} else if x.mustOwnHost {
			f.RetainForRecovery(t)
			t.Error("newly spawned host ownership was not established; fixture retained")
		}
	}()
	if x.output.joined {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		x.pinHost(ctx)
		x.retainHostPinFailure(t, f)
		cancel()
	}
	if !x.output.joined {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		// Owned.Signal is cleanup-only authority retained even when post-start
		// image or argument pinning fails. It still binds the native creator.
		if err := x.owned.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, darwinfixtureidentity.ErrExited) {
			f.RetainForRecovery(t)
			t.Error("exact native frontend cooperative stop refused")
		}
		err := x.join(ctx)
		if err == nil {
			x.pinHost(ctx)
			x.retainHostPinFailure(t, f)
		}
		cancel()
		if err != nil {
			if err := x.owned.Signal(syscall.SIGKILL); err != nil && !errors.Is(err, darwinfixtureidentity.ErrExited) {
				f.RetainForRecovery(t)
				t.Error("exact native frontend forced stop refused")
			}
			ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
			err = x.join(ctx)
			if err == nil {
				x.pinHost(ctx)
				x.retainHostPinFailure(t, f)
			}
			cancel()
			if err != nil {
				f.RetainForRecovery(t)
				t.Error("native frontend cleanup did not join; fixture retained")
				return
			}
			t.Error("native frontend exceeded cooperative cleanup budget")
		}
	}
	x.output.writeCapture(t, f)
	f.WriteEvidence(t, x.output.captureName+"-cleanup-joined-diagnostic.json", x.output.joinedDiagnostic(x.creatorOwned()))
	if x.completion.Stdout.Overflow || x.completion.Stderr.Overflow || x.completion.Stdout.Err != nil || x.completion.Stderr.Err != nil {
		t.Error("native frontend cleanup output exceeded capture bounds or failed")
	}
	if x.retainHostPinFailure(t, f) {
		t.Error("native host admission cleanup remains uncertain; original owners retained")
		return
	}
	if x.owned.Close() != nil {
		f.RetainForRecovery(t)
		t.Error("native frontend joined ownership did not close")
	}
}

// The CLI installation is an explicit prerequisite, checked before the shared
// fixture can build a kernel, install roles or contact the selected engine.
func composeDarwinCLIEnrolledFixture(t *testing.T) (*bootstrapDockerFixture, HostPolicySelection, hostPolicyRecord) {
	t.Helper()
	executable := bootstrapReadDarwinInstalledCLI(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	image, err := protected.PrepareProtectedInstalledHost(ctx, executable.Path, executable.Digest, 128*1024*1024)
	cancel()
	if err != nil {
		t.Fatal("separately installed native CLI prerequisite refused")
	}
	if image.Close() != nil {
		t.Fatal("installed CLI prerequisite descriptors did not close")
	}
	f := newBootstrapDockerFixtureWithHost(t, true)
	s, r := composeDarwinCLIPolicy(t, f, executable)
	return f, s, r
}

// Policy enrollment accepts only the separately installed protected CLI.
// Building and privileged setup remain separate from runtime execution.
func composeDarwinCLIPolicy(t *testing.T, f *bootstrapDockerFixture, executable hostPolicyExecutable) (HostPolicySelection, hostPolicyRecord) {
	t.Helper()
	if f.BridgeEnrollment == nil || f.Config.OwnerBridge == nil {
		t.Fatal("actual HOST enrollment missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	image, err := protected.PrepareProtectedInstalledHost(ctx, executable.Path, executable.Digest, 128*1024*1024)
	if err != nil {
		t.Fatal("actual installed CLI protected admission failed")
	}
	if image.Close() != nil {
		t.Fatal("actual installed CLI admission descriptors did not close")
	}
	bootstrapCheckNativeKernel(t, executable.Path, bootstrapActualHost().GOARCH)
	directory := filepath.Join(f.EvidenceDirectory, "installed")
	if os.Mkdir(directory, 0700) != nil {
		t.Fatal("private runtime policy directory unavailable")
	}
	p := f.HostPolicy.ExternalRelease
	r := hostPolicyRecord{SchemaVersion: protocol.Version, OwnerUID: f.Profile.OwnerUID, ProfileDirectory: f.Profile.ProfileDirectory, ProfileID: f.Profile.ProfileID, InstanceID: f.Profile.InstanceID, Owner: f.BridgeEnrollment.Owner, ServerName: f.Config.Health.ServerName, Domain: f.Config.Health.Domain, PublicEndpoint: f.Profile.NATSEndpoint, PublicContextName: f.Profile.Docker.Context, RuntimeExecutable: executable, Limits: hostPolicyLimits{60000, 3000, 10000, 2000, 3000}, OwnerBridge: &f.BridgeEnrollment.Credentials, Release: hostPolicyRelease{p.PackageDirectory, hex.EncodeToString(p.PublicKey), p.ReleaseManifestDigest, p.ReleaseAuthority, p.ReleaseVersion, p.KernelAPIMajor}}
	s := HostPolicySelection{Path: filepath.Join(directory, "host-policy.json"), OwnerUID: f.Profile.OwnerUID, WorkspaceRoots: append([]string(nil), f.HostPolicy.Profile.WorkspaceRoots...)}
	writeInstalledHostPolicy(t, s.Path, r)
	h, err := LoadEnrolledHostPolicy(s)
	if err != nil {
		t.Fatal("actual installed policy refused")
	}
	c, _, err := h.Load()
	if err != nil {
		t.Fatal("actual installed configuration refused")
	}
	loaded, err := LoadProfile(c.ProfilePolicy)
	if err != nil || loaded.Declaration().Docker.Executable != f.Profile.Docker.Executable {
		t.Fatal("actual Docker selection changed during installed admission")
	}
	return s, r
}

func composeDarwinCLIStart(t *testing.T, f *bootstrapDockerFixture, s HostPolicySelection, r hostPolicyRecord, operation string, mustOwn bool) *composeDarwinCLIFront {
	t.Helper()
	x := composeDarwinCLIPrepare(t, f, s, r, operation)
	x.mustOwnHost = mustOwn
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err := x.start(ctx)
	cancel()
	if err != nil {
		t.Fatal("actual installed frontend start failed")
	}
	return x
}

func composeDarwinCLIEnsure(t *testing.T, f *bootstrapDockerFixture, x *composeDarwinCLIFront, r hostPolicyRecord, name string, receipt bool) *StartupStatusObservation {
	t.Helper()
	raw, success := x.wait(t, f, name, 10*time.Second)
	if !success {
		t.Fatal("actual installed frontend failed")
	}
	return x.observation(t, f, r, raw, name, receipt)
}

func composeDarwinReady(t *testing.T, f *bootstrapDockerFixture, x *composeDarwinCLIFront, name string) StartupStatusObservation {
	t.Helper()
	fresh := composeCLIRefresh(t, f, x.output.started.Add(f.Config.StartupTimeout))
	if !x.creatorOwned() {
		f.RetainForRecovery(t)
		t.Fatal("actual creating frontend host proof missing")
	}
	x.lifetime.pinRoles(t, f)
	x.lifetime.assertPinnedLive(t)
	bootstrapFixtureRoleLeases(t, f, true)
	f.WriteEvidence(t, name, fresh)
	return fresh
}
