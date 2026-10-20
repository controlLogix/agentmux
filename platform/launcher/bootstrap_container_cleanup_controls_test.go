//go:build (linux || darwin) && agentmux_bootstrap_docker

package launcher

import (
	"strings"
	"testing"
)

func TestBootstrapStoppedContainerRemovalRequiresCompletedOwnership(t *testing.T) {
	for _, name := range []string{"complete", "missing_lease", "foreign_project", "foreign_instance", "foreign_profile", "foreign_release", "different_config", "short_id", "different_broker", "running", "unknown_state", "unknown_baseline", "existing_container", "unknown_owner", "network_retained", "missing_creation", "different_creation", "restart_pending", "unknown_attachments", "attached_network"} {
		t.Run(name, func(t *testing.T) {
			_, owner, id, network, _ := bootstrapNetworkPolicyFixture()
			fixture := &bootstrapDockerFixture{
				Owner: owner, baseline: map[string]bootstrapContainerObservation{},
				ownedIDs: map[string]bool{id: true}, networkRemoved: true,
				networkProvenance: &bootstrapNetworkProvenance{network: network, containerID: id},
			}
			owner.LockHeld = true
			broker := OwnedBroker{ContainerID: id, State: "stopped"}
			attachments := map[string]bootstrapNetworkAttachment{}
			switch name {
			case "missing_lease":
				owner.LockHeld = false
			case "foreign_project":
				owner.Project = "other_project"
			case "foreign_instance":
				owner.InstanceID = "other_instance"
			case "foreign_profile":
				owner.ProfileID = "other_profile"
			case "foreign_release":
				owner.ReleaseDigest = "sha256:" + strings.Repeat("f", 64)
			case "different_config":
				owner.ConfigDigest[0] = 1
			case "short_id":
				id = id[:12]
				broker.ContainerID = id
			case "different_broker":
				broker.ContainerID = strings.Repeat("f", 64)
			case "running":
				broker.State = "running"
			case "unknown_state":
				broker.State = ""
			case "unknown_baseline":
				fixture.baseline = nil
			case "existing_container":
				fixture.baseline[id] = bootstrapContainerObservation{ID: id, State: "exited"}
			case "unknown_owner":
				delete(fixture.ownedIDs, id)
			case "network_retained":
				fixture.networkRemoved = false
			case "missing_creation":
				fixture.networkProvenance = nil
			case "different_creation":
				fixture.networkProvenance.containerID = strings.Repeat("f", 64)
			case "restart_pending":
				fixture.networkRestart = &bootstrapNetworkRestart{}
			case "unknown_attachments":
				attachments = nil
			case "attached_network":
				attachments[network.Name] = bootstrapNetworkAttachment{NetworkID: network.ID}
			}
			if got := fixture.allowStoppedContainerRemoval(owner, id, broker, attachments); got != (name == "complete") {
				t.Fatal("stopped container cleanup accepted incomplete ownership or refused the complete owner")
			}
		})
	}
}

func TestBootstrapContainerRemovalRequiresExactResponse(t *testing.T) {
	id := strings.Repeat("b", 64)
	if !validBootstrapContainerRemovalOutput(id, []byte(id+"\n")) {
		t.Fatal("exact removed container response refused")
	}
	for _, raw := range []string{"", id[:12], strings.Repeat("c", 64), id + "\n" + strings.Repeat("c", 64), "warning\n" + id} {
		if validBootstrapContainerRemovalOutput(id, []byte(raw)) {
			t.Fatal("missing, partial or ambiguous container removal response accepted")
		}
	}
	if validBootstrapContainerRemovalOutput(id[:12], []byte(id[:12])) {
		t.Fatal("partial requested container identity accepted")
	}
}
