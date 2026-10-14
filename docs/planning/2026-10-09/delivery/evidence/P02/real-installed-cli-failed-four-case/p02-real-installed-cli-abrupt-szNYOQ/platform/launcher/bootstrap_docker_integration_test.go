//go:build (linux || darwin) && agentmux_bootstrap_docker

package launcher

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

const bootstrapFixtureDocker = "/mnt/c/Users/RyanHelms/AppData/Local/Programs/DockerDesktop/resources/bin/docker.exe"
const bootstrapFixtureImage = "docker.io/library/nats@sha256:fdae708d900cb150ce13f203359719bdd9cefd3dbbbc32a4c6224b23ea3e0b2c"
const bootstrapFixtureEngine = "e0f1f93d-abf1-44f2-b62a-5bfee21d2b5c"

type bootstrapContainerObservation struct {
	ID            string `json:"Id"`
	State         string
	DeclaredPorts map[string][]brokerPort
	ActivePorts   map[string][]brokerPort
}

type bootstrapDockerFixture struct {
	Config            BootstrapConfig
	Profile           Profile
	Driver            *Docker
	Owner             OwnershipPreflight
	Project           string
	EvidenceDirectory string
	baseline          map[string]bootstrapContainerObservation
	mu                sync.Mutex
	ownedIDs          map[string]bool
	closed            bool
	HostPolicy        HostPolicy
	BridgeEnrollment  *OwnerBridgeEnrollment
}

// This dedicated fixture never supplies a fake CLI, broker or readiness reply.
// Its private tree and named data volume remain available for local diagnosis.
func newBootstrapDockerFixture(t *testing.T) *bootstrapDockerFixture {
	return newBootstrapDockerFixtureWithHost(t, false)
}

func newBootstrapDockerFixtureWithHost(t *testing.T, withHost bool) *bootstrapDockerFixture {
	t.Helper()
	if os.Getenv("AMX_BOOTSTRAP_DOCKER_AUTHORIZED") != "1" {
		t.Fatal("actual Docker fixture authorization missing")
	}
	for _, name := range []string{"DOCKER_HOST", "DOCKER_CONTEXT", "AMX_BROKER_INSPECT_FIXTURE", "AMX_DOCKER_FIXTURE", "AMX_OWNER_BRIDGE_DOCKER_FIXTURE", "AGENTMUX_NATS_SERVER"} {
		if os.Getenv(name) != "" {
			t.Fatal("unexpected fixture or Docker environment override")
		}
	}
	selected, selectionPin := loadBootstrapFixtureSelection(t)
	driver, err := NewDocker(selected.dockerConfig())
	if err != nil {
		t.Fatal("actual Docker fixture configuration refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := driver.Inspect(ctx); err != nil {
		t.Fatalf("actual Docker identity unavailable or changed: %s stage=%s", bootstrapFixtureFailureCode(err), bootstrapFixtureFailureStage(err))
	}
	var imageID string
	if driver.read(ctx, &imageID, "image", "inspect", selected.Image, "--format", "{{json .Id}}") != nil || !digest.MatchString(imageID) {
		t.Fatal("pinned cached image unavailable")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal("native private fixture root unavailable")
	}
	cache := filepath.Join(home, ".cache", "agentmux-governance")
	if os.MkdirAll(cache, 0700) != nil {
		t.Fatal("native private fixture root unavailable")
	}
	directory, err := os.MkdirTemp(cache, "p02-bootstrap-private-")
	if err != nil {
		t.Fatal("private fixture directory unavailable")
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal("private fixture directory unavailable")
	}
	f := &bootstrapDockerFixture{Driver: driver, EvidenceDirectory: directory, ownedIDs: map[string]bool{}}
	baseline, err := f.inventory(ctx)
	if err != nil {
		t.Fatal("fresh Docker baseline unavailable")
	}
	f.baseline = baseline
	f.Project = "amx-p02-bootstrap-" + bootstrapFixtureRandom(t, 8)
	for _, filter := range []string{"label=com.docker.compose.project=" + f.Project, "name=" + f.Project + "_", "name=" + f.Project + "-"} {
		b, err := driver.run(ctx, nil, "ps", "--all", "--quiet", "--no-trunc", "--filter", filter)
		if err != nil || len(bytes.Fields(b)) != 0 {
			t.Fatal("fresh project collision or unverifiable absence")
		}
	}
	port := bootstrapSelectedPort(t, selected)
	for _, existing := range baseline {
		for _, bindings := range existing.DeclaredPorts {
			for _, binding := range bindings {
				if binding.HostPort == strconv.Itoa(port) {
					t.Fatal("selected port already claimed by Docker")
				}
			}
		}
	}
	connection, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 250*time.Millisecond)
	if err == nil {
		connection.Close()
		t.Fatal("selected loopback endpoint already occupied")
	}
	// The engine-read budget ends here. Native builds and protected staging have
	// their own bounded preparation budgets; they do not extend runtime limits.
	cancel()
	profileDirectory := filepath.Join(directory, "profile")
	packageDirectory := filepath.Join(directory, "release")
	for _, path := range []string{profileDirectory, packageDirectory, filepath.Join(packageDirectory, "bin")} {
		if os.Mkdir(path, 0700) != nil {
			t.Fatal("private fixture member directory unavailable")
		}
	}
	// Reuse the existing signature fixture, replacing every synthetic member with
	// the actual native kernel binary before signing its new source-bound hashes.
	release := signedReleaseFixture(t)
	release.policy.PackageDirectory = packageDirectory
	release.manifest.Broker.Image = selected.Image
	release.manifest.Broker.NATSVersion = selected.NATSVersion
	release.manifest.Broker.ComposeVersion = selected.Docker.ComposeVersion
	binary := filepath.Join(packageDirectory, "bin", "kernel-build")
	buildCtx, buildCancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer buildCancel()
	plan, err := bootstrapKernelBuild(selected, bootstrapActualHost(), runtime.GOROOT(), binary, os.Environ())
	if err != nil {
		t.Fatal("native kernel build selection refused")
	}
	build := exec.CommandContext(buildCtx, plan.Executable, plan.Args...)
	build.Dir = ".."
	build.WaitDelay = 2 * time.Second
	build.Env = plan.Env
	if build.Run() != nil {
		t.Fatal("actual native kernel build failed")
	}
	bootstrapCheckNativeKernel(t, binary, selected.GOARCH)
	binaryBytes, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal("actual native kernel bytes unavailable")
	}
	members, err := bootstrapCopyRoleMembers(packageDirectory, binaryBytes)
	if err != nil {
		t.Fatal("actual kernel member write failed")
	}
	if os.Remove(binary) != nil {
		t.Fatal("fixture build intermediate cleanup failed")
	}
	release.assembly["plugins"] = members
	release.refresh(t)
	// Darwin stages the exact signed bytes into its protected root-owned image
	// tree. Linux uses the existing sealed-image runtime without installation.
	bootstrapPrepareNativeRelease(t, release)
	workspace, err := filepath.EvalSymlinks(selected.WorkspaceRoot)
	if err != nil {
		t.Fatal("actual repository workspace unavailable")
	}
	workspace, err = filepath.Abs(workspace)
	if err != nil {
		t.Fatal("actual repository workspace unavailable")
	}
	dockerSelection := selected.Docker
	profile := Profile{SchemaVersion: "1.0.0", ProfileID: "profile_" + bootstrapFixtureRandom(t, 16), InstanceID: "instance_" + bootstrapFixtureRandom(t, 16), DisplayName: "Disposable bootstrap hub", OwnerUID: uint32(os.Geteuid()), ProfileDirectory: profileDirectory, Mode: "local", ReleaseFingerprint: release.policy.ReleaseManifestDigest, NATSEndpoint: "tls://127.0.0.1:" + strconv.Itoa(port), CredentialRef: "fixture_credentials", ComposeProject: f.Project, Docker: &dockerSelection}
	metadata := hostRuntimeMetadata{"1.0.0", "fixture_hub", "fixture_server", "fixture_domain", "/data/store", 1024 * 1024, 4 * 1024 * 1024}
	scope := protocol.Scope{HubID: metadata.HubID, InstanceID: profile.InstanceID, ProfileID: profile.ProfileID, AssemblyDigest: release.authorization.AssemblyDigest, ReleaseManifestDigest: profile.ReleaseFingerprint, ReleaseVersion: release.policy.ReleaseVersion}
	enrollCtx, enrollCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer enrollCancel()
	material, err := deployment.EnrollLocalTLS(enrollCtx, profile.ProfileID)
	if err != nil {
		t.Fatal("explicit disposable TLS enrollment failed")
	}
	trustRecord := protocol.ServerTrustRecord{SchemaVersion: protocol.Version, Endpoint: profile.NATSEndpoint, ServerName: material.ServerName(), RootsPEM: string(material.RootsPEM()), LeafCertificateSHA256: material.LeafCertificateSHA256(), Scope: scope}
	trustRaw, err := json.Marshal(trustRecord)
	if err != nil {
		t.Fatal("private server trust encoding failed")
	}
	trustDigest := sha256.Sum256(trustRaw)
	profile.ServerTrustRef = "nats-server-trust.json"
	profile.ServerTrustDigest = "sha256:" + hex.EncodeToString(trustDigest[:])
	releaseTestWrite(t, profileDirectory, profile.ServerTrustRef, trustRaw)
	releaseTestWrite(t, profileDirectory, "server-cert.pem", material.ServerCertificatePEM())
	releaseTestWrite(t, profileDirectory, "server-key.pem", material.ServerKeyPEM())
	credentials := communication.Credentials{}
	roles := protocol.Roles()
	for _, user := range append([]string{communication.Administrator, communication.OrdinaryPlugin}, roles[:]...) {
		credentials[user] = bootstrapFixtureRandom(t, 24)
	}
	health := bootstrapFixtureRandom(t, 24)
	storage := deployment.StorageProfile{HubID: metadata.HubID, ServerName: metadata.ServerName, Domain: metadata.Domain, StoreDirectory: metadata.StoreDirectory, MaxMemoryBytes: metadata.MaxMemoryBytes, MaxFileBytes: metadata.MaxFileBytes, Listener: communication.Listener{Mode: communication.ContainerInternal, Port: 4222}}
	var bridge *deployment.OwnerBridgeSettings
	var broker []byte
	if withHost {
		bridge = &deployment.OwnerBridgeSettings{Scope: scope, ServerPassword: bootstrapFixtureRandom(t, 24), ClientPassword: bootstrapFixtureRandom(t, 24)}
		broker, err = deployment.BuildSecureLocalConfigWithOwnerBridge(storage, credentials, health, *bridge, material)
	} else {
		broker, err = deployment.BuildSecureLocalConfig(storage, credentials, health, material)
	}
	if err != nil {
		t.Fatal("actual private broker factory failed")
	}
	compose, err := deployment.RenderSecureCompose(deployment.ComposeSpec{Project: f.Project, InstanceID: profile.InstanceID, ProfileID: profile.ProfileID, ReleaseDigest: profile.ReleaseFingerprint, Image: selected.Image, HostPort: port, BrokerConfig: broker}, material)
	if err != nil {
		t.Fatal("actual private Compose factory failed")
	}
	sum := sha256.Sum256(compose)
	profile.ConfigDigest = "sha256:" + hex.EncodeToString(sum[:])
	profilePolicy := ProfilePolicy{Directory: profileDirectory, WorkspaceRoots: []string{workspace}, OwnerUID: profile.OwnerUID, InstalledReleaseFingerprint: profile.ReleaseFingerprint}
	if EnrollProfile(profilePolicy, profile) != nil {
		t.Fatal("explicit fixture enrollment failed")
	}
	runtimeRaw, _ := json.Marshal(metadata)
	releaseTestWrite(t, profileDirectory, "runtime.json", runtimeRaw)
	releaseTestWrite(t, profileDirectory, "broker.json", broker)
	for _, role := range roles {
		raw, err := json.Marshal(protocol.Credentials{SchemaVersion: protocol.Version, Role: role, Username: role, Password: credentials[role], NATSURL: profile.NATSEndpoint, Scope: scope})
		if err != nil {
			t.Fatal("private role credential encoding failed")
		}
		releaseTestWrite(t, profileDirectory, role+".json", raw)
	}
	policy := HostPolicy{Profile: profilePolicy, ExternalRelease: release.policy, Deadlines: protected.Deadlines{StartTimeout: 10 * time.Second, StopGrace: 2 * time.Second, ReapTimeout: 3 * time.Second}, StartupTimeout: 60 * time.Second, ProbeTimeout: 3 * time.Second}
	policy.OwnerBridge = bridge
	if withHost {
		enrollment := OwnerBridgeEnrollment{Owner: OwnerEnrollment{SchemaVersion: protocol.Version, OwnerUID: profile.OwnerUID, PrincipalID: "fixture_owner", Identity: OwnerIdentityReference{ID: "fixture_owner_record", OwnerHubID: scope.HubID, Revision: 1}, Scope: OwnerScope{OrganizationID: "fixture_org"}, InstanceID: scope.InstanceID, ProfileID: scope.ProfileID, ReleaseFingerprint: scope.ReleaseManifestDigest}, Credentials: OwnerBridgeCredentialRefs{Server: "owner-host.json", Client: "owner-client.json"}}
		releaseTestWrite(t, profileDirectory, "status-owner.json", mustStatusJSON(enrollment.Owner))
		for _, item := range []struct{ name, role, password string }{{enrollment.Credentials.Server, deployment.OwnerBridgeServerUser, bridge.ServerPassword}, {enrollment.Credentials.Client, deployment.OwnerBridgeClientUser, bridge.ClientPassword}} {
			releaseTestWrite(t, profileDirectory, item.name, mustStatusJSON(OwnerBridgeCredential{SchemaVersion: protocol.Version, Role: item.role, Scope: scope, Owner: enrollment.Owner, Password: item.password}))
		}
		f.BridgeEnrollment = &enrollment
	}
	f.HostPolicy = policy
	f.Config, err = LoadBootstrapConfig(policy)
	if err != nil {
		t.Fatal("actual enrolled host loader refused fixture")
	}
	f.Profile = profile
	f.Owner = OwnershipPreflight{Project: f.Project, InstanceID: profile.InstanceID, ProfileID: profile.ProfileID, ReleaseDigest: profile.ReleaseFingerprint, ConfigDigest: sum}
	f.WriteEvidence(t, "baseline.json", baseline)
	f.WriteEvidence(t, "fixture.json", map[string]any{"project": f.Project, "profileId": profile.ProfileID, "instanceId": profile.InstanceID, "image": selected.Image, "cachedImageId": imageID, "hostPort": port, "engineId": selected.Docker.EngineID, "releaseDigest": profile.ReleaseFingerprint, "kernelBinaryDigest": releaseDigest(binaryBytes), "privateConfigRetained": true, "liveRunStarted": false,
		"target": selected.Target, "selectionPin": selectionPin, "actualGOOS": runtime.GOOS, "actualGOARCH": runtime.GOARCH, "actualWSL": bootstrapActualHost().WSL, "goVersion": runtime.Version(), "kernelCGOEnabled": selected.GOOS == "darwin", "dockerBackend": selected.Docker.Backend, "expectedVersions": selected.dockerConfig().Versions, "protectedInstallRetained": selected.GOOS == "darwin"})
	t.Cleanup(func() { f.Cleanup(t) })
	f.AssertBaselineUnchanged(t)
	return f
}

func bootstrapFixtureRandom(t *testing.T, count int) string {
	t.Helper()
	raw := make([]byte, count)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal("fixture randomness unavailable")
	}
	return hex.EncodeToString(raw)
}

// This selects once on the Windows host and refuses a conflict without retry.
func bootstrapWindowsPort(t *testing.T) int {
	t.Helper()
	const script = `$ErrorActionPreference='Stop'; $l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback,0); $l.Start(); $p=$l.LocalEndpoint.Port; $l.Stop(); $ranges=@(& netsh.exe interface ipv4 show excludedportrange protocol=tcp); if($LASTEXITCODE -ne 0){exit 2}; $count=0; foreach($line in $ranges){if($line -match '^\s*(\d+)\s+(\d+)\s*\*?\s*$'){$count++; if($p -ge [int]$Matches[1] -and $p -le [int]$Matches[2]){exit 3}}}; if($count -eq 0){exit 5}; if(@(Get-NetTCPConnection -ErrorAction Stop | Where-Object LocalPort -eq $p).Count -ne 0){exit 4}; [Console]::Write($p)`
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	command.WaitDelay = 2 * time.Second
	var output bytes.Buffer
	command.Stdout = &output
	if command.Run() != nil || output.Len() > 16 {
		t.Fatal("Windows host port preflight failed")
	}
	port, err := strconv.Atoi(strings.TrimSpace(output.String()))
	if err != nil || port < 1 || port > 65535 {
		t.Fatal("Windows host port response invalid")
	}
	return port
}

func (f *bootstrapDockerFixture) inventory(ctx context.Context) (map[string]bootstrapContainerObservation, error) {
	if _, err := f.Driver.Inspect(ctx); err != nil {
		return nil, err
	}
	b, err := f.Driver.run(ctx, nil, "ps", "--all", "--quiet", "--no-trunc")
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0)
	seen := map[string]bool{}
	for _, raw := range bytes.Fields(b) {
		id := string(raw)
		if !fullID.MatchString(id) || seen[id] {
			return nil, errors.New("fixture_inventory_id_invalid")
		}
		seen[id] = true
		ids = append(ids, id)
	}
	result := map[string]bootstrapContainerObservation{}
	if len(ids) == 0 {
		return result, nil
	}
	const format = `{"Id":{{json .Id}},"State":{{json .State.Status}},"DeclaredPorts":{{json .HostConfig.PortBindings}},"ActivePorts":{{json .NetworkSettings.Ports}}}`
	args := append([]string{"container", "inspect", "--format", format}, ids...)
	raw, err := f.Driver.run(ctx, nil, args...)
	if err != nil {
		return nil, err
	}
	return decodeBootstrapInventory(raw, ids)
}

// Batch the exact roster into one read. Every declared identity must appear
// exactly once; missing, extra and malformed observations remain failures.

// JSON shape checking alone does not require fields. Preserve complete state
// and port projections even when Docker explicitly reports a nullable map.
func completeBootstrapInventoryProjection(raw []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 4 {
		return false
	}
	for _, key := range []string{"Id", "State", "DeclaredPorts", "ActivePorts"} {
		if _, ok := fields[key]; !ok {
			return false
		}
	}
	var state string
	if json.Unmarshal(fields["State"], &state) != nil {
		return false
	}
	switch state {
	case "created", "restarting", "running", "removing", "paused", "exited", "dead":
	default:
		return false
	}
	for _, key := range []string{"DeclaredPorts", "ActivePorts"} {
		if bytes.Equal(bytes.TrimSpace(fields[key]), []byte("null")) {
			continue
		}
		var ports map[string]json.RawMessage
		if json.Unmarshal(fields[key], &ports) != nil || ports == nil {
			return false
		}
		for _, encoded := range ports {
			if bytes.Equal(bytes.TrimSpace(encoded), []byte("null")) {
				continue
			}
			var bindings []json.RawMessage
			if json.Unmarshal(encoded, &bindings) != nil || bindings == nil {
				return false
			}
			for _, entry := range bindings {
				var binding map[string]json.RawMessage
				if json.Unmarshal(entry, &binding) != nil || len(binding) != 2 {
					return false
				}
				for _, field := range []string{"HostIp", "HostPort"} {
					value, ok := binding[field]
					if !ok || len(bytes.TrimSpace(value)) == 0 || bytes.TrimSpace(value)[0] != '"' {
						return false
					}
				}
			}
		}
	}
	return true
}

func decodeBootstrapInventory(raw []byte, ids []string) (map[string]bootstrapContainerObservation, error) {
	expected := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !fullID.MatchString(id) || expected[id] {
			return nil, errors.New("fixture_inventory_id_invalid")
		}
		expected[id] = true
	}
	result := make(map[string]bootstrapContainerObservation, len(ids))
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	for range ids {
		var encoded json.RawMessage
		var item bootstrapContainerObservation
		if err := decoder.Decode(&encoded); err != nil || protocol.DecodeClosedJSON(encoded, &item, 64*1024) != nil || !completeBootstrapInventoryProjection(encoded) || !expected[item.ID] {
			return nil, errors.New("fixture_inventory_identity_mismatch")
		}
		if _, duplicate := result[item.ID]; duplicate {
			return nil, errors.New("fixture_inventory_identity_mismatch")
		}
		result[item.ID] = item
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, errors.New("fixture_inventory_extra_observation")
	}

	return result, nil
}

func (f *bootstrapDockerFixture) ObserveBroker(ctx context.Context) (OwnedBroker, error) {
	u, err := urlPort(f.Profile.NATSEndpoint)
	if err != nil {
		return OwnedBroker{}, err
	}
	b, err := f.Driver.InspectOwnedTLSBroker(ctx, f.Owner, f.Config.BrokerImage, u, f.Config.BrokerConfigDigest, sha256.Sum256(f.Config.LocalTLS.ServerCertificatePEM()), sha256.Sum256(f.Config.LocalTLS.ServerKeyPEM()))
	if err != nil {
		if discoveryErr := f.captureCreatedIDs(ctx); discoveryErr != nil {
			return OwnedBroker{}, discoveryErr
		}
		return b, err
	}
	if err == nil && b.ContainerID != "" {
		f.mu.Lock()
		f.ownedIDs[b.ContainerID] = true
		f.mu.Unlock()
	}
	return b, err
}

// Record identities even when a failed startup left an owned but incomplete
// container that the strict broker inspector correctly refuses to classify.
func (f *bootstrapDockerFixture) captureCreatedIDs(ctx context.Context) error {
	if _, err := f.Driver.Inspect(ctx); err != nil {
		return err
	}
	for _, filter := range []string{"label=com.docker.compose.project=" + f.Project, "name=" + f.Project + "_", "name=" + f.Project + "-"} {
		b, err := f.Driver.run(ctx, nil, "ps", "--all", "--quiet", "--no-trunc", "--filter", filter)
		if err != nil {
			return err
		}
		for _, raw := range bytes.Fields(b) {
			id := string(raw)
			if !fullID.MatchString(id) {
				return errors.New("fixture_discovery_id_invalid")
			}
			if _, existed := f.baseline[id]; existed {
				return errors.New("fixture_discovery_existing_collision")
			}
			var labels map[string]string
			const format = `{"agentmux.instance.id":{{json (index .Config.Labels "agentmux.instance.id")}},"agentmux.profile.id":{{json (index .Config.Labels "agentmux.profile.id")}},"agentmux.release.digest":{{json (index .Config.Labels "agentmux.release.digest")}},"com.docker.compose.project":{{json (index .Config.Labels "com.docker.compose.project")}}}`
			if err := f.Driver.read(ctx, &labels, "container", "inspect", id, "--format", format); err != nil {
				return err
			}
			if !f.Owner.matches(labels) {
				return errors.New("fixture_discovery_foreign_identity")
			}
			f.mu.Lock()
			f.ownedIDs[id] = true
			f.mu.Unlock()
		}
	}
	return nil
}

type bootstrapVolumeObservation struct {
	Name, CreatedAt string
	Labels          map[string]string
}

const bootstrapFixtureVolumeFormat = `{"Name":{{json .Name}},"CreatedAt":{{json .CreatedAt}},"Labels":{"agentmux.instance.id":{{json (index .Labels "agentmux.instance.id")}},"agentmux.profile.id":{{json (index .Labels "agentmux.profile.id")}},"agentmux.release.digest":{{json (index .Labels "agentmux.release.digest")}},"com.docker.compose.project":{{json (index .Labels "com.docker.compose.project")}}}}`

func (f *bootstrapDockerFixture) volume(ctx context.Context) (bootstrapVolumeObservation, error) {
	var result bootstrapVolumeObservation
	if err := f.Driver.read(ctx, &result, "volume", "inspect", f.Project+"_data", "--format", bootstrapFixtureVolumeFormat); err != nil {
		return result, err
	}
	if result.Name != f.Project+"_data" || result.CreatedAt == "" || !f.Owner.matches(result.Labels) {
		return bootstrapVolumeObservation{}, errors.New("fixture_volume_identity_invalid")
	}
	return result, nil
}

// A caller that cannot join startup workers must retain the fixture instead of
// stopping infrastructure still used by a possible live protected process.
func (f *bootstrapDockerFixture) RetainForRecovery(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	f.closed = true
	ids := make(map[string]bool, len(f.ownedIDs))
	for id := range f.ownedIDs {
		ids[id] = true
	}
	f.mu.Unlock()
	f.WriteEvidence(t, "incomplete-bootstrap-cleanup.json", map[string]any{"at": time.Now().UTC(), "ownedStopRefused": true, "manualRecoveryRequired": true, "reason": "startup_workers_not_joined", "knownOwnedIDs": ids})
}

func (f *bootstrapDockerFixture) cleanupGap(t *testing.T, reason string) {
	t.Helper()
	f.mu.Lock()
	ids := make(map[string]bool, len(f.ownedIDs))
	for id := range f.ownedIDs {
		ids[id] = true
	}
	f.mu.Unlock()
	f.WriteEvidence(t, "cleanup-unverified.json", map[string]any{"at": time.Now().UTC(), "manualRecoveryRequired": true, "reason": reason, "knownOwnedIDs": ids})
}

func urlPort(endpoint string) (int, error) {
	selected, err := url.Parse(endpoint)
	if err != nil || (selected.Scheme != "tls" && selected.Scheme != "nats") || selected.User != nil || selected.Path != "" || selected.RawQuery != "" || selected.Fragment != "" {
		return 0, errors.New("fixture_port_invalid")
	}
	_, port, err := net.SplitHostPort(selected.Host)
	if err != nil {
		return 0, errors.New("fixture_port_invalid")
	}
	value, err := strconv.Atoi(port)
	return value, err
}

func (f *bootstrapDockerFixture) AssertBaselineUnchanged(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	actual, err := f.inventory(ctx)
	if err != nil {
		t.Fatalf("fixture preservation inventory unavailable: %s stage=%s", bootstrapFixtureFailureCode(err), bootstrapFixtureFailureStage(err))
	}
	broker, err := f.ObserveBroker(ctx)
	if err != nil {
		t.Fatal("fixture preservation owned broker unverifiable")
	}
	if broker.ContainerID != "" {
		delete(actual, broker.ContainerID)
	}
	unchanged := reflect.DeepEqual(actual, f.baseline)
	f.WriteEvidence(t, "baseline-guard-"+bootstrapFixtureRandom(t, 4)+".json", map[string]any{"at": time.Now().UTC(), "unchanged": unchanged, "existingContainerCount": len(f.baseline)})
	if !unchanged {
		// These are the same bounded public state/port projections compared by
		// the guard. Never include arbitrary Docker labels, env or config bytes.
		f.WriteEvidence(t, "baseline-difference.json", map[string]any{"at": time.Now().UTC(), "before": f.baseline, "after": actual})
		t.Fatal("existing Docker container state or port changed during fixture")
	}
}

// Callers may pass only deliberate safe fields, never BootstrapConfig, broker
// bytes, credentials, arbitrary inspected labels or private filesystem paths.
func (f *bootstrapDockerFixture) WriteEvidence(t *testing.T, name string, safe any) {
	t.Helper()
	if filepath.Base(name) != name {
		t.Fatal("fixture evidence name invalid")
	}
	raw, err := json.MarshalIndent(safe, "", "  ")
	if err != nil {
		t.Fatal("safe fixture evidence encoding failed")
	}
	if os.WriteFile(filepath.Join(f.EvidenceDirectory, name), append(raw, '\n'), 0600) != nil {
		t.Fatal("safe fixture evidence write failed")
	}
}

func (f *bootstrapDockerFixture) Cleanup(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	f.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// Real leases must be free after orchestration cleanup. A boolean alone is
	// never sufficient permission to stop a broker while protected roles survive.
	var leases []*BootstrapLock
	defer func() {
		for _, lease := range leases {
			lease.Close()
		}
	}()
	engineID := f.Profile.Docker.EngineID
	for _, identity := range append([]string{engineID}, bootstrapFixtureRoleLeaseIDs(engineID)...) {
		lease, err := AcquireBootstrapLock(ctx, f.Profile.ProfileDirectory, f.Profile.InstanceID, identity)
		if err != nil {
			f.cleanupGap(t, "protected_or_bootstrap_lease_unavailable")
			t.Error("fixture cleanup lease unavailable; owned stop refused")
			return
		}
		leases = append(leases, lease)
	}
	broker, err := f.ObserveBroker(ctx)
	if err != nil {
		f.cleanupGap(t, "partial_or_unverifiable_owned_state_stop_refused")
		t.Error("fixture cleanup ownership unverifiable; stop refused")
		return
	}
	if broker.ContainerID != "" {
		beforeVolume, err := f.volume(ctx)
		if err != nil {
			f.cleanupGap(t, "owned_volume_unverifiable_stop_refused")
			t.Error("fixture owned volume unverifiable; stop refused")
			return
		}
		owner := f.Owner
		owner.LockHeld = true
		if f.Driver.StopOwned(ctx, owner, broker.ContainerID) != nil {
			f.cleanupGap(t, "exact_owned_stop_failed")
			t.Error("fixture exact owned stop failed")
			return
		}
		stopped, err := f.ObserveBroker(ctx)
		if err != nil || stopped.ContainerID != broker.ContainerID || stopped.State != "stopped" {
			f.cleanupGap(t, "exact_stopped_state_unverifiable")
			t.Error("fixture exact stopped state unverifiable")
			return
		}
		afterVolume, err := f.volume(ctx)
		if err != nil || !reflect.DeepEqual(beforeVolume, afterVolume) {
			f.cleanupGap(t, "owned_volume_retention_unverifiable")
			t.Error("fixture owned volume retention unverifiable")
			return
		}
		f.WriteEvidence(t, "cleanup.json", map[string]any{"at": time.Now().UTC(), "containerId": broker.ContainerID, "state": stopped.State, "volumeRetained": true, "volume": afterVolume, "ownedIDs": f.ownedIDs})
	}
	f.AssertBaselineUnchanged(t)
}

func bootstrapFixtureRoleLeaseIDs(engineID string) []string {
	var identities []string
	for _, role := range protocol.Roles() {
		identities = append(identities, engineID+":runtime:"+role)
	}
	return identities
}

// Execute the actual Docker Go-template literal before a live fixture may use it.
func TestBootstrapVolumeTemplateProducesCompleteJSON(t *testing.T) {
	input := bootstrapVolumeObservation{Name: "fixture_data", CreatedAt: "2026-10-13T23:13:02Z", Labels: map[string]string{"agentmux.instance.id": "instance", "agentmux.profile.id": "profile", "agentmux.release.digest": "release", "com.docker.compose.project": "fixture", "unrecognized": "must-not-be-captured"}}
	formatter, err := template.New("volume").Funcs(template.FuncMap{"json": func(v any) (string, error) { raw, err := json.Marshal(v); return string(raw), err }}).Parse(bootstrapFixtureVolumeFormat)
	if err != nil {
		t.Fatal("volume template parse failed")
	}
	var output bytes.Buffer
	if formatter.Execute(&output, input) != nil {
		t.Fatal("volume template execution failed")
	}
	var actual bootstrapVolumeObservation
	if json.Unmarshal(output.Bytes(), &actual) != nil {
		t.Fatal("volume template did not produce complete JSON")
	}
	delete(input.Labels, "unrecognized")
	if !reflect.DeepEqual(actual, input) || bytes.Contains(output.Bytes(), []byte("must-not-be-captured")) {
		t.Fatal("volume template identity or privacy changed")
	}
}

func TestBootstrapInventoryBatchRequiresCompleteExactRoster(t *testing.T) {
	first, second := strings.Repeat("a", 64), strings.Repeat("b", 64)
	one := `{"Id":"` + first + `","State":"running","DeclaredPorts":null,"ActivePorts":null}`
	two := `{"Id":"` + second + `","State":"exited","DeclaredPorts":{},"ActivePorts":{}}`
	if got, err := decodeBootstrapInventory([]byte(one+"\n"+two), []string{first, second}); err != nil || len(got) != 2 {
		t.Fatal("complete roster refused")
	}
	for name, raw := range map[string]string{"missing": one, "duplicate": one + "\n" + one, "extra": one + "\n" + two + "\n" + one, "unknown": strings.Replace(two, second, strings.Repeat("c", 64), 1) + "\n" + one, "truncated": one + "\n" + two[:len(two)-1], "unknown-field": strings.Replace(one, `"State":`, `"Unexpected":true,"State":`, 1) + "\n" + two, "duplicate-field": strings.Replace(one, `"State":`, `"State":"stopped","State":`, 1) + "\n" + two, "wrong-field-case": strings.Replace(one, `"Id":`, `"id":`, 1) + "\n" + two, "trailing": one + "\n" + two + "garbage"} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeBootstrapInventory([]byte(raw), []string{first, second}); err == nil {
				t.Fatal("incomplete or foreign inventory accepted")
			}
		})
	}
}

// Read-only engine check: no profile, project, process or volume is created.
func TestBootstrapRealDockerBatchedPreservationInventory(t *testing.T) {
	if os.Getenv("AMX_BOOTSTRAP_DOCKER_AUTHORIZED") != "1" {
		t.Fatal("actual Docker fixture authorization missing")
	}
	for _, name := range []string{"DOCKER_HOST", "DOCKER_CONTEXT", "AMX_DOCKER_FIXTURE", "AMX_BROKER_INSPECT_FIXTURE"} {
		if os.Getenv(name) != "" {
			t.Fatal("unexpected fixture or Docker override")
		}
	}
	selected, _ := loadBootstrapFixtureSelection(t)
	driver, err := NewDocker(selected.dockerConfig())
	if err != nil {
		t.Fatal("selected engine configuration refused")
	}
	f := &bootstrapDockerFixture{Driver: driver}
	var baseline map[string]bootstrapContainerObservation
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		start := time.Now()
		actual, err := f.inventory(ctx)
		elapsed := time.Since(start)
		cancel()
		if err != nil {
			t.Fatalf("batched preservation inventory failed: %s stage=%s", bootstrapFixtureFailureCode(err), bootstrapFixtureFailureStage(err))
		}
		t.Logf("read=%d containerCount=%d elapsedMs=%d", i+1, len(actual), elapsed.Milliseconds())
		if i == 0 {
			baseline = actual
		} else if !reflect.DeepEqual(baseline, actual) {
			t.Fatal("read-only inventory changed between observations")
		}
	}
}

func TestBootstrapInventoryRequiresCompleteStateAndPortFields(t *testing.T) {
	id := strings.Repeat("a", 64)
	valid := `{"Id":"` + id + `","State":"running","DeclaredPorts":null,"ActivePorts":null}`
	for name, raw := range map[string]string{
		"missing-state":     strings.Replace(valid, `"State":"running",`, "", 1),
		"missing-declared":  strings.Replace(valid, `"DeclaredPorts":null,`, "", 1),
		"missing-active":    strings.Replace(valid, `,"ActivePorts":null`, "", 1),
		"null-state":        strings.Replace(valid, `"State":"running"`, `"State":null`, 1),
		"unknown-state":     strings.Replace(valid, `"State":"running"`, `"State":"unknown"`, 1),
		"missing-host-port": strings.Replace(valid, `"ActivePorts":null`, `"ActivePorts":{"4222/tcp":[{"HostIp":"127.0.0.1"}]}`, 1),
		"null-host-ip":      strings.Replace(valid, `"ActivePorts":null`, `"ActivePorts":{"4222/tcp":[{"HostIp":null,"HostPort":"4222"}]}`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeBootstrapInventory([]byte(raw), []string{id}); err == nil {
				t.Fatal("incomplete preservation projection accepted")
			}
		})
	}
	complete := strings.Replace(valid, `"ActivePorts":null`, `"ActivePorts":{"4222/tcp":[{"HostIp":"","HostPort":""}],"8222/tcp":null}`, 1)
	if _, err := decodeBootstrapInventory([]byte(complete), []string{id}); err != nil {
		t.Fatal("explicit nullable map and complete default bindings refused")
	}
}
