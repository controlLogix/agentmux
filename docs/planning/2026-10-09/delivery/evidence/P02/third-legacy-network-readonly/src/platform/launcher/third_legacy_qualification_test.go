//go:build linux && agentmux_bootstrap_docker

package launcher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestThirdHistoricalFixtureReadOnlyQualification(t *testing.T) {
	if os.Getenv("AMX_BOOTSTRAP_DOCKER_AUTHORIZED") != "1" {
		t.Fatal("explicit readonly qualification missing")
	}
	out := os.Getenv("AMX_LEGACY_QUALIFICATION_OUTPUT")
	root := "/home/ryan/.cache/agentmux-governance/p02-bootstrap-private-3411499751"
	cid := "066bd3c2cd6698d5a6eae5e650b71acd7ff0754c3f9871c343b30f558387c306"
	rows := map[string]any{"mutationExecuted": false, "directory": "p02-bootstrap-private-3411499751", "containerId": cid, "qualified": false}
	var leases []*BootstrapLock
	archive := func(name string, value any) {
		b, e := json.MarshalIndent(value, "", "  ")
		if e != nil || os.WriteFile(filepath.Join(out, name), append(b, '\n'), 0600) != nil {
			t.Fatal("private qualification archive failed")
		}
	}
	defer func() {
		errors := []string{}
		for _, lease := range leases {
			if e := lease.Close(); e != nil {
				errors = append(errors, bootstrapFixtureFailureCode(e))
			}
		}
		rows["actualLeasesReleased"] = len(leases)
		rows["leaseCloseCodes"] = errors
		archive("qualification.json", rows)
	}()
	guard := func(stage string, e error) {
		rows["stage"] = stage
		rows["failureCode"] = bootstrapFixtureFailureCode(e)
		var staged *bootstrapNetworkReadFailure
		if errors.As(e, &staged) {
			rows["networkReadStage"] = bootstrapNetworkReadStage(e)
			rows["nestedFailureCode"] = bootstrapFixtureFailureCode(staged.cause)
		}
		if e != nil {
			t.Fatal("fixed readonly qualification stage failed")
		}
	}
	historical, e := os.ReadFile("/home/ryan/.cache/agentmux-governance/p02-real-installed-cli-pending-SY2CkI/review.json")
	guard("historical_review", e)
	if fmt.Sprintf("%x", sha256.Sum256(historical)) != "e46eacaaf577f4acafaff8e6f891699e912ab279097033549925f18842d12932" {
		t.Fatal("original historical record changed")
	}
	var original struct {
		TestExit int `json:"testExit"`
		Tests    []struct {
			Name    string `json:"name"`
			Started string `json:"started"`
			Ended   string `json:"ended"`
		} `json:"tests"`
		Outputs []struct {
			Test      string `json:"test"`
			Directory string `json:"privateCacheDirectoryName"`
			Cleanup   struct {
				ContainerID    string                     `json:"containerId"`
				State          string                     `json:"state"`
				VolumeRetained bool                       `json:"volumeRetained"`
				Volume         bootstrapVolumeObservation `json:"volume"`
			} `json:"cleanup"`
		} `json:"actualFixtureOutputs"`
	}
	guard("historical_shape", json.Unmarshal(historical, &original))
	var started, ended time.Time
	var oldVolume bootstrapVolumeObservation
	found := false
	for _, x := range original.Outputs {
		if x.Test == "TestInstalledCLIRealComposeAuthenticatedPending" && x.Directory == filepath.Base(root) && x.Cleanup.ContainerID == cid && x.Cleanup.State == "stopped" && x.Cleanup.VolumeRetained {
			oldVolume = x.Cleanup.Volume
			found = true
		}
	}
	for _, x := range original.Tests {
		if x.Name == "TestInstalledCLIRealComposeAuthenticatedPending" {
			started, e = time.Parse(time.RFC3339Nano, x.Started)
			guard("historical_start", e)
			ended, e = time.Parse(time.RFC3339Nano, x.Ended)
			guard("historical_end", e)
		}
	}
	if original.TestExit != 0 || !found || started.IsZero() || ended.IsZero() {
		t.Fatal("historical named creator relation missing")
	}
	rows["historicalNamedCreatorBound"] = true
	selected, pin := loadBootstrapFixtureSelection(t)
	workspace, e := filepath.EvalSymlinks(selected.WorkspaceRoot)
	guard("workspace", e)
	h, e := LoadEnrolledHostPolicy(HostPolicySelection{Path: filepath.Join(root, "installed/host-policy.json"), OwnerUID: uint32(os.Geteuid()), WorkspaceRoots: []string{workspace}})
	guard("private_signed_policy", e)
	c, status, e := h.Load()
	guard("private_full_admission", e)
	if status == nil {
		t.Fatal("actual enrolled owner missing")
	}
	p, e := LoadProfile(c.ProfilePolicy)
	guard("private_profile", e)
	decl := p.Declaration()
	if decl.Docker.EngineID != selected.Docker.EngineID || decl.Docker.Executable != selected.Docker.Executable || decl.Docker.Context != selected.Docker.Context || decl.Docker.Endpoint != selected.Docker.Endpoint {
		t.Fatal("actual selected engine changed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ids := append([]string{decl.Docker.EngineID, "owner-status-service"}, bootstrapFixtureRoleLeaseIDs(decl.Docker.EngineID)...)
	for _, id := range ids {
		lease, e := AcquireBootstrapLock(ctx, decl.ProfileDirectory, decl.InstanceID, id)
		guard("actual_lease_acquisition", e)
		leases = append(leases, lease)
	}
	if len(leases) != 6 {
		t.Fatal("six actual leases not held")
	}
	rows["actualLeasesHeld"] = len(leases)
	d, e := NewDocker(selected.dockerConfig())
	guard("exact_selected_driver", e)
	_, e = d.Inspect(ctx)
	guard("actual_engine", e)
	owner := OwnershipPreflight{Project: decl.ComposeProject, InstanceID: decl.InstanceID, ProfileID: decl.ProfileID, ReleaseDigest: decl.ReleaseFingerprint, ConfigDigest: sha256.Sum256(c.Compose)}
	f := &bootstrapDockerFixture{Driver: d, Profile: decl, Config: c, Owner: owner, Project: decl.ComposeProject, EvidenceDirectory: out, ownedIDs: map[string]bool{}}
	beforeContainers, e := f.inventory(ctx)
	guard("complete_container_before", e)
	networkBeforeStarted := time.Now()
	beforeNetworks, e := f.networkInventory(ctx)
	rows["networkBeforeElapsedNanoseconds"] = time.Since(networkBeforeStarted).Nanoseconds()
	guard("complete_network_before", e)
	port, e := urlPort(decl.NATSEndpoint)
	guard("enrolled_port", e)
	broker, e := d.InspectOwnedTLSBroker(ctx, owner, c.BrokerImage, port, c.BrokerConfigDigest, sha256.Sum256(c.LocalTLS.ServerCertificatePEM()), sha256.Sum256(c.LocalTLS.ServerKeyPEM()))
	guard("full_actual_broker", e)
	if broker.ContainerID != cid || broker.State != "stopped" {
		t.Fatal("exact historical stopped broker mismatch")
	}
	rows["fullStoppedBrokerIdentityQualified"] = true
	attachments, e := f.networkAttachments(ctx, cid)
	guard("exact_retained_network_relation", e)
	if len(attachments) != 1 {
		t.Fatal("historical exact sole network relation absent")
	}
	a, present := attachments[decl.ComposeProject+"_default"]
	if !present || !fullID.MatchString(a.NetworkID) || a.EndpointID != "" {
		t.Fatal("historical stopped attachment mismatch")
	}
	n, e := f.networkByID(ctx, a.NetworkID)
	guard("exact_current_network", e)
	if n.ID != a.NetworkID || n.Name != decl.ComposeProject+"_default" || !owner.matches(n.Labels) || n.Driver != "bridge" || n.Scope != "local" || n.Internal || n.Ingress || n.ConfigOnly || len(n.Endpoints) != 0 {
		t.Fatal("historical empty sole network identity refused")
	}
	networkCreated, e := time.Parse(time.RFC3339Nano, n.Created)
	guard("network_created", e)
	raw, e := d.run(ctx, nil, "container", "inspect", cid, "--format", `{"Id":{{json .Id}},"Created":{{json .Created}},"State":{{json .State.Status}},"Networks":{{json .NetworkSettings.Networks}}}`)
	guard("exact_container_created", e)
	if os.WriteFile(filepath.Join(out, "private-container.json"), raw, 0600) != nil {
		t.Fatal("private raw container capture failed")
	}
	var container struct {
		ID       string         `json:"Id"`
		Created  string         `json:"Created"`
		State    string         `json:"State"`
		Networks map[string]any `json:"Networks"`
	}
	guard("container_projection", protocol.DecodeClosedJSON(bytes.TrimSpace(raw), &container, 65536))
	networkValue, networkPresent := container.Networks[decl.ComposeProject+"_default"]
	networkFields, networkObject := networkValue.(map[string]any)
	if len(container.Networks) != 1 || !networkPresent || !networkObject || networkFields["NetworkID"] != a.NetworkID || networkFields["EndpointID"] != "" {
		t.Fatal("same exact raw stopped container network relation refused")
	}
	containerCreated, e := time.Parse(time.RFC3339Nano, container.Created)
	guard("container_created", e)
	if container.ID != cid || container.State != "exited" || networkCreated.Before(started) || networkCreated.After(ended) || containerCreated.Before(networkCreated) || containerCreated.After(ended) {
		t.Fatal("historical named creation time relation refused")
	}
	volume, e := f.volume(ctx)
	guard("full_selected_volume", e)
	if !reflect.DeepEqual(oldVolume, volume) {
		t.Fatal("historical selected volume changed")
	}
	fullNetwork, e := d.run(ctx, nil, "network", "inspect", a.NetworkID)
	guard("private_network_projection", e)
	if os.WriteFile(filepath.Join(out, "private-network.json"), fullNetwork, 0600) != nil {
		t.Fatal("private network archive failed")
	}
	if os.WriteFile(filepath.Join(out, "private-container.json"), raw, 0600) != nil {
		t.Fatal("private container archive failed")
	}
	archive("private-volume.json", volume)
	afterContainers, e := f.inventory(ctx)
	guard("complete_container_after", e)
	networkAfterStarted := time.Now()
	afterNetworks, e := f.networkInventory(ctx)
	rows["networkAfterElapsedNanoseconds"] = time.Since(networkAfterStarted).Nanoseconds()
	guard("complete_network_after", e)
	if !reflect.DeepEqual(beforeContainers, afterContainers) || !sameBootstrapNetworkBaseline(beforeNetworks, afterNetworks) {
		t.Fatal("complete read-only baseline changed")
	}
	rows["networkId"] = n.ID
	rows["networkCreated"] = n.Created
	rows["containerCreated"] = container.Created
	rows["project"] = decl.ComposeProject
	rows["profileId"] = decl.ProfileID
	rows["instanceId"] = decl.InstanceID
	rows["engineId"] = decl.Docker.EngineID
	rows["selectionPin"] = pin
	rows["emptyLiveEndpointCount"] = len(n.Endpoints)
	rows["stoppedAttachmentEndpointEmpty"] = a.EndpointID == ""
	rows["retainedSoleNetworkIdMatches"] = true
	rows["historicalVolumeRetained"] = true
	rows["completeContainerBaselineUnchanged"] = true
	rows["completeNetworkBaselineUnchanged"] = true
	rows["containerBaselineCount"] = len(beforeContainers)
	rows["networkBaselineCount"] = len(beforeNetworks)
	rows["networkFullDigest"] = n.Digest
	rows["networkImmutableDigest"] = n.ImmutableDigest
	rows["qualified"] = true
	rows["stage"] = "all_readonly_qualification_complete"
	_ = strings.TrimSpace
}
