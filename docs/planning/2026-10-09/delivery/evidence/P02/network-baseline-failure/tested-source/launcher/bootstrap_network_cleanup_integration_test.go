//go:build (linux || darwin) && agentmux_bootstrap_docker

package launcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

// Full private projections are hashed for preservation. Unknown Docker fields
// grant no ownership; unchanged values remain part of the cleanup guard.
// Arbitrary labels are never published.
type bootstrapNetworkObservation struct {
	ID, Name, Created, Driver, Scope string
	Internal, Ingress, ConfigOnly    bool
	Labels                           map[string]string
	Endpoints                        map[string]string
	Digest                           string
	ImmutableDigest                  string
}

type bootstrapNetworkAttachment struct{ NetworkID, EndpointID string }

type bootstrapNetworkProvenance struct {
	network     bootstrapNetworkObservation
	containerID string
	endpointID  string
}

func bootstrapNetworkError() error { return errors.New("fixture_network_admission_failed") }

func decodeBootstrapNetwork(raw []byte) (bootstrapNetworkObservation, error) {
	var empty bootstrapNetworkObservation
	var fields map[string]any
	if protocol.DecodeClosedJSON(raw, &fields, 64*1024) != nil || fields == nil {
		return empty, bootstrapNetworkError()
	}
	// The strict guard checks duplicates, shape and bounds. This second decode
	// preserves exact private JSON numbers rather than rounding them to float64.
	precise := json.NewDecoder(bytes.NewReader(raw))
	precise.UseNumber()
	if precise.Decode(&fields) != nil {
		return empty, bootstrapNetworkError()
	}
	keys := []string{"Id", "Name", "Created", "Driver", "Scope", "Internal", "Ingress", "ConfigOnly", "Labels", "Containers"}
	for _, required := range keys {
		if _, ok := fields[required]; !ok {
			return empty, bootstrapNetworkError()
		}
		for key := range fields {
			if key != required && strings.EqualFold(key, required) {
				return empty, bootstrapNetworkError()
			}
		}
	}
	stringField := func(key string) string { value, _ := fields[key].(string); return value }
	x := bootstrapNetworkObservation{ID: stringField("Id"), Name: stringField("Name"), Created: stringField("Created"), Driver: stringField("Driver"), Scope: stringField("Scope"), Labels: map[string]string{}, Endpoints: map[string]string{}}
	if !fullID.MatchString(x.ID) || !statusText(x.Name, 128) || !statusText(x.Driver, 64) || !statusText(x.Scope, 64) {
		return empty, bootstrapNetworkError()
	}
	if _, err := time.Parse(time.RFC3339Nano, x.Created); err != nil {
		return empty, bootstrapNetworkError()
	}
	for key, target := range map[string]*bool{"Internal": &x.Internal, "Ingress": &x.Ingress, "ConfigOnly": &x.ConfigOnly} {
		value, ok := fields[key].(bool)
		if !ok {
			return empty, bootstrapNetworkError()
		}
		*target = value
	}
	labels, ok := fields["Labels"].(map[string]any)
	// Built-in networks may explicitly have null labels. They never grant fixture
	// authority, but their complete null projection still belongs in the baseline.
	if !ok && fields["Labels"] != nil {
		return empty, bootstrapNetworkError()
	}
	for key, value := range labels {
		text, ok := value.(string)
		if !ok {
			return empty, bootstrapNetworkError()
		}
		x.Labels[key] = text
	}
	containers, ok := fields["Containers"].(map[string]any)
	if !ok {
		return empty, bootstrapNetworkError()
	}
	for id, value := range containers {
		entry, ok := value.(map[string]any)
		if !ok || !fullID.MatchString(id) {
			return empty, bootstrapNetworkError()
		}
		endpoint, ok := entry["EndpointID"].(string)
		if !ok || !fullID.MatchString(endpoint) {
			return empty, bootstrapNetworkError()
		}
		for key := range entry {
			if key != "EndpointID" && strings.EqualFold(key, "EndpointID") {
				return empty, bootstrapNetworkError()
			}
		}
		x.Endpoints[id] = endpoint
	}
	canonical, err := json.Marshal(fields)
	if err != nil {
		return empty, bootstrapNetworkError()
	}
	x.Digest = releaseDigest(canonical)
	immutable := make(map[string]any, len(fields)-1)
	for key, value := range fields {
		if key != "Containers" {
			immutable[key] = value
		}
	}
	canonical, err = json.Marshal(immutable)
	if err != nil {
		return empty, bootstrapNetworkError()
	}
	x.ImmutableDigest = releaseDigest(canonical)
	return x, nil
}

func decodeBootstrapNetworks(raw []byte, ids []string) (map[string]bootstrapNetworkObservation, error) {
	if len(raw) > 1024*1024 {
		return nil, bootstrapNetworkError()
	}
	expected := map[string]bool{}
	for _, id := range ids {
		if !fullID.MatchString(id) || expected[id] {
			return nil, bootstrapNetworkError()
		}
		expected[id] = true
	}
	var rows []json.RawMessage
	if json.Unmarshal(raw, &rows) != nil || rows == nil || len(rows) != len(ids) {
		return nil, bootstrapNetworkError()
	}
	result := map[string]bootstrapNetworkObservation{}
	for _, raw := range rows {
		row, err := decodeBootstrapNetwork(raw)
		if err != nil || !expected[row.ID] || result[row.ID].ID != "" {
			return nil, bootstrapNetworkError()
		}
		result[row.ID] = row
	}
	return result, nil
}

func (f *bootstrapDockerFixture) networkInventory(ctx context.Context) (map[string]bootstrapNetworkObservation, error) {
	if _, err := f.Driver.Inspect(ctx); err != nil {
		return nil, err
	}
	raw, err := f.Driver.run(ctx, nil, "network", "ls", "--quiet", "--no-trunc")
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, word := range bytes.Fields(raw) {
		ids = append(ids, string(word))
	}
	if len(ids) == 0 {
		return map[string]bootstrapNetworkObservation{}, nil
	}
	raw, err = f.Driver.run(ctx, nil, append([]string{"network", "inspect"}, ids...)...)
	if err != nil {
		return nil, err
	}
	return decodeBootstrapNetworks(raw, ids)
}

func (f *bootstrapDockerFixture) networkByID(ctx context.Context, id string) (bootstrapNetworkObservation, error) {
	if !fullID.MatchString(id) {
		return bootstrapNetworkObservation{}, bootstrapNetworkError()
	}
	raw, err := f.Driver.run(ctx, nil, "network", "inspect", id)
	if err != nil {
		return bootstrapNetworkObservation{}, err
	}
	rows, err := decodeBootstrapNetworks(raw, []string{id})
	if err != nil {
		return bootstrapNetworkObservation{}, err
	}
	return rows[id], nil
}

func (f *bootstrapDockerFixture) networkAttachments(ctx context.Context, id string) (map[string]bootstrapNetworkAttachment, error) {
	if !fullID.MatchString(id) {
		return nil, bootstrapNetworkError()
	}
	raw, err := f.Driver.run(ctx, nil, "container", "inspect", id, "--format", "{{json .NetworkSettings.Networks}}")
	if err != nil {
		return nil, err
	}
	var fields map[string]any
	if protocol.DecodeClosedJSON(raw, &fields, 64*1024) != nil || fields == nil {
		return nil, bootstrapNetworkError()
	}
	result := map[string]bootstrapNetworkAttachment{}
	for name, value := range fields {
		entry, ok := value.(map[string]any)
		if !ok {
			return nil, bootstrapNetworkError()
		}
		for _, required := range []string{"NetworkID", "EndpointID"} {
			for key := range entry {
				if key != required && strings.EqualFold(key, required) {
					return nil, bootstrapNetworkError()
				}
			}
		}
		netID, ok := entry["NetworkID"].(string)
		if !ok || !fullID.MatchString(netID) {
			return nil, bootstrapNetworkError()
		}
		endpoint, ok := entry["EndpointID"].(string)
		if !ok || (endpoint != "" && !fullID.MatchString(endpoint)) {
			return nil, bootstrapNetworkError()
		}
		result[name] = bootstrapNetworkAttachment{netID, endpoint}
	}
	return result, nil
}

func validBootstrapNetworkCreation(baseline map[string]bootstrapNetworkObservation, owner OwnershipPreflight, containerID string, network bootstrapNetworkObservation, attachments map[string]bootstrapNetworkAttachment) bool {
	if !fullID.MatchString(containerID) || !fullID.MatchString(network.ID) || baseline == nil || baseline[network.ID].ID != "" || network.Name != owner.Project+"_default" || network.Driver != "bridge" || network.Scope != "local" || network.Internal || network.Ingress || network.ConfigOnly || !owner.matches(network.Labels) || len(attachments) != 1 || len(network.Endpoints) != 1 {
		return false
	}
	for _, old := range baseline {
		if old.Name == network.Name {
			return false
		}
	}
	attachment, ok := attachments[network.Name]
	return ok && attachment.NetworkID == network.ID && fullID.MatchString(attachment.EndpointID) && network.Endpoints[containerID] == attachment.EndpointID
}

func sameBootstrapNetworkIdentity(a, b bootstrapNetworkObservation) bool {
	return a.ID == b.ID && a.Name == b.Name && a.Created == b.Created && a.Driver == b.Driver && a.Scope == b.Scope && a.Internal == b.Internal && a.Ingress == b.Ingress && a.ConfigOnly == b.ConfigOnly && reflect.DeepEqual(a.Labels, b.Labels) && a.ImmutableDigest == b.ImmutableDigest
}

func validBootstrapStoppedNetwork(pin *bootstrapNetworkProvenance, baseline map[string]bootstrapNetworkObservation, owner OwnershipPreflight, containerID, state string, current bootstrapNetworkObservation, attachments map[string]bootstrapNetworkAttachment) bool {
	if pin == nil || baseline == nil || state != "stopped" || containerID != pin.containerID || !sameBootstrapNetworkIdentity(pin.network, current) || baseline[current.ID].ID != "" || !owner.matches(current.Labels) || len(attachments) != 1 || len(current.Endpoints) > 1 {
		return false
	}
	for _, old := range baseline {
		if old.Name == current.Name {
			return false
		}
	}
	attachment, ok := attachments[current.Name]
	if !ok || attachment.NetworkID != current.ID || (attachment.EndpointID != "" && attachment.EndpointID != pin.endpointID) {
		return false
	}
	for id, endpoint := range current.Endpoints {
		if id != containerID || endpoint != pin.endpointID {
			return false
		}
	}
	return true
}

func (f *bootstrapDockerFixture) observeCreatedNetwork(ctx context.Context, broker OwnedBroker) error {
	f.mu.Lock()
	removed := f.networkRemoved
	pin := f.networkProvenance
	f.mu.Unlock()
	if removed {
		return nil
	}
	if broker.State != "running" {
		return nil
	}
	attachments, err := f.networkAttachments(ctx, broker.ContainerID)
	if err != nil {
		return err
	}
	attachment, ok := attachments[f.Project+"_default"]
	if !ok {
		return bootstrapNetworkError()
	}
	network, err := f.networkByID(ctx, attachment.NetworkID)
	if err != nil {
		return err
	}
	if !validBootstrapNetworkCreation(f.networkBaseline, f.Owner, broker.ContainerID, network, attachments) {
		return bootstrapNetworkError()
	}
	if pin != nil {
		if !sameBootstrapNetworkIdentity(pin.network, network) || pin.containerID != broker.ContainerID || pin.endpointID != attachment.EndpointID {
			return bootstrapNetworkError()
		}
		return nil
	}
	f.mu.Lock()
	if f.networkProvenance == nil {
		f.networkProvenance = &bootstrapNetworkProvenance{network, broker.ContainerID, attachment.EndpointID}
	}
	f.mu.Unlock()
	return f.writeNetworkEvidence("network-provenance.json", map[string]any{"networkId": network.ID, "name": network.Name, "created": network.Created, "containerId": broker.ContainerID, "endpointId": attachment.EndpointID, "baselineExcluded": true, "scope": f.Config.Kernel.Scope})
}

// Error-returning evidence keeps read helpers usable without a testing callback.
func (f *bootstrapDockerFixture) writeNetworkEvidence(name string, value any) error {
	if strings.ContainsAny(name, "/\\") {
		return bootstrapNetworkError()
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(f.EvidenceDirectory, name), append(raw, '\n'), 0600)
}

func (f *bootstrapDockerFixture) cleanupCreatedNetwork(ctx context.Context, containerID string) error {
	f.mu.Lock()
	pin := f.networkProvenance
	f.mu.Unlock()
	if pin == nil {
		return bootstrapNetworkError()
	}
	current, err := f.networkByID(ctx, pin.network.ID)
	if err != nil {
		return err
	}
	attachments, err := f.networkAttachments(ctx, containerID)
	if err != nil {
		return err
	}
	broker, err := f.ObserveBroker(ctx)
	if err != nil {
		return err
	}
	if !validBootstrapStoppedNetwork(pin, f.networkBaseline, f.Owner, containerID, broker.State, current, attachments) {
		return bootstrapNetworkError()
	}
	beforeDetach := map[string]any{"networkId": current.ID, "created": current.Created, "immutableDigest": current.ImmutableDigest, "liveEndpointCount": len(current.Endpoints), "containerNetworkId": attachments[current.Name].NetworkID, "containerEndpointId": attachments[current.Name].EndpointID, "containerState": broker.State}
	if _, err = f.Driver.Inspect(ctx); err != nil {
		return err
	}
	if _, err = f.Driver.run(ctx, nil, "network", "disconnect", "--force", pin.network.ID, containerID); err != nil {
		return err
	}
	current, err = f.networkByID(ctx, pin.network.ID)
	if err != nil {
		return err
	}
	attachments, err = f.networkAttachments(ctx, containerID)
	if err != nil {
		return err
	}
	broker, err = f.ObserveBroker(ctx)
	if err != nil {
		return err
	}
	if !sameBootstrapNetworkIdentity(pin.network, current) || len(current.Endpoints) != 0 || len(attachments) != 0 || broker.ContainerID != containerID || broker.State != "stopped" {
		return bootstrapNetworkError()
	}
	afterDetach := map[string]any{"networkId": current.ID, "created": current.Created, "immutableDigest": current.ImmutableDigest, "liveEndpointCount": len(current.Endpoints), "containerAttachmentCount": len(attachments), "containerState": broker.State}
	if _, err = f.Driver.Inspect(ctx); err != nil {
		return err
	}
	removed, rmErr := f.Driver.run(ctx, nil, "network", "rm", pin.network.ID)
	if rmErr != nil {
		return rmErr
	}
	if !validBootstrapNetworkRemovalOutput(pin.network.ID, removed) {
		return bootstrapNetworkError()
	}
	baseline, err := f.networkInventory(ctx)
	if err != nil {
		return err
	}
	if baseline[pin.network.ID].ID != "" || !sameBootstrapNetworkBaseline(f.networkBaseline, baseline) {
		return bootstrapNetworkError()
	}
	f.mu.Lock()
	f.networkRemoved = true
	f.mu.Unlock()
	return f.writeNetworkEvidence("network-cleanup.json", map[string]any{"networkId": pin.network.ID, "containerId": containerID, "forcedStoppedEndpointDetach": true, "beforeDetach": beforeDetach, "afterDetach": afterDetach, "exactRemovedId": string(bytes.TrimSpace(removed)), "baselineNetworkCount": len(f.networkBaseline), "afterRemovalNetworkCount": len(baseline), "emptyBeforeRemoval": true, "networkRemoved": true, "unrelatedNetworkBaselineUnchanged": true, "stoppedContainerRetained": true})
}

func validBootstrapNetworkRemovalOutput(id string, raw []byte) bool {
	return fullID.MatchString(id) && string(bytes.TrimSpace(raw)) == id
}

func sameBootstrapNetworkBaseline(a, b map[string]bootstrapNetworkObservation) bool {
	if len(a) != len(b) {
		return false
	}
	for id, old := range a {
		if next, ok := b[id]; !ok || old.Digest != next.Digest {
			return false
		}
	}
	return true
}

func bootstrapNetworkPolicyFixture() (map[string]bootstrapNetworkObservation, OwnershipPreflight, string, bootstrapNetworkObservation, map[string]bootstrapNetworkAttachment) {
	id, cid, endpoint := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	owner := OwnershipPreflight{Project: "fixture_project", InstanceID: "instance_fixture", ProfileID: "profile_fixture", ReleaseDigest: "sha256:" + strings.Repeat("d", 64)}
	network := bootstrapNetworkObservation{ID: id, Name: owner.Project + "_default", Created: "2026-10-14T00:00:00Z", Driver: "bridge", Scope: "local", Labels: map[string]string{"com.docker.compose.project": owner.Project, "agentmux.instance.id": owner.InstanceID, "agentmux.profile.id": owner.ProfileID, "agentmux.release.digest": owner.ReleaseDigest}, Endpoints: map[string]string{cid: endpoint}, Digest: "sha256:" + strings.Repeat("e", 64), ImmutableDigest: "sha256:" + strings.Repeat("1", 64)}
	return map[string]bootstrapNetworkObservation{}, owner, cid, network, map[string]bootstrapNetworkAttachment{network.Name: {id, endpoint}}
}

func TestBootstrapNetworkCreationAndStoppedPolicy(t *testing.T) {
	baseline, owner, cid, network, attachments := bootstrapNetworkPolicyFixture()
	if !validBootstrapNetworkCreation(baseline, owner, cid, network, attachments) {
		t.Fatal("matching complete network creation rejected")
	}
	pin := &bootstrapNetworkProvenance{network, cid, attachments[network.Name].EndpointID}
	if !validBootstrapStoppedNetwork(pin, baseline, owner, cid, "stopped", network, attachments) {
		t.Fatal("matching stopped endpoint rejected")
	}
	empty := network
	empty.Endpoints = map[string]string{}
	cleared := map[string]bootstrapNetworkAttachment{network.Name: {network.ID, ""}}
	if !validBootstrapStoppedNetwork(pin, baseline, owner, cid, "stopped", empty, cleared) {
		t.Fatal("documented stop-cleared live endpoint rejected")
	}
	for _, name := range []string{"baseline_id", "baseline_name", "wrong_owner", "extra_endpoint", "extra_network", "wrong_endpoint", "wrong_network", "internal_network", "changed_creation", "running_broker", "missing_pin"} {
		t.Run(name, func(t *testing.T) {
			base, o, container, n, a := bootstrapNetworkPolicyFixture()
			p := &bootstrapNetworkProvenance{n, container, a[n.Name].EndpointID}
			state := "stopped"
			switch name {
			case "baseline_id":
				base[n.ID] = n
			case "baseline_name":
				old := n
				old.ID = strings.Repeat("f", 64)
				base[old.ID] = old
			case "wrong_owner":
				o.InstanceID = "other_instance"
			case "extra_endpoint":
				n.Endpoints[strings.Repeat("f", 64)] = strings.Repeat("1", 64)
			case "extra_network":
				a["other_network"] = bootstrapNetworkAttachment{strings.Repeat("f", 64), strings.Repeat("1", 64)}
			case "wrong_endpoint":
				a[n.Name] = bootstrapNetworkAttachment{n.ID, strings.Repeat("f", 64)}
			case "wrong_network":
				a[n.Name] = bootstrapNetworkAttachment{strings.Repeat("f", 64), a[n.Name].EndpointID}
			case "internal_network":
				n.Internal = true
			case "changed_creation":
				n.Created = "2026-10-14T01:00:00Z"
			case "running_broker":
				state = "running"
			case "missing_pin":
				p = nil
			}
			if name != "changed_creation" && name != "running_broker" && name != "missing_pin" && validBootstrapNetworkCreation(base, o, container, n, a) {
				t.Fatal("unsafe creation admitted")
			}
			if validBootstrapStoppedNetwork(p, base, o, container, state, n, a) {
				t.Fatal("unsafe stopped network cleanup admitted")
			}
		})
	}
}

func TestBootstrapNetworkProjectionRequiresCompleteExactRoster(t *testing.T) {
	_, _, cid, network, _ := bootstrapNetworkPolicyFixture()
	fields := map[string]any{"Id": network.ID, "Name": network.Name, "Created": network.Created, "Driver": network.Driver, "Scope": network.Scope, "Internal": false, "Ingress": false, "ConfigOnly": false, "Labels": network.Labels, "Containers": map[string]any{cid: map[string]any{"EndpointID": network.Endpoints[cid]}}, "unknownDockerField": "hash-preservation-only"}
	raw, _ := json.Marshal(fields)
	decoded, err := decodeBootstrapNetworks(append(append([]byte{'['}, raw...), ']'), []string{network.ID})
	if err != nil || decoded[network.ID].ID != network.ID {
		t.Fatal("complete bounded network projection rejected")
	}
	for _, name := range []string{"missing_id", "wrong_case", "duplicate_key", "null_endpoints", "missing_endpoint", "duplicate_roster", "missing_roster", "extra_roster", "trailing_json"} {
		t.Run(name, func(t *testing.T) {
			copyFields := map[string]any{}
			for key, value := range fields {
				copyFields[key] = value
			}
			ids := []string{network.ID}
			switch name {
			case "missing_id":
				delete(copyFields, "Id")
			case "wrong_case":
				delete(copyFields, "Id")
				copyFields["ID"] = network.ID
			case "null_endpoints":
				copyFields["Containers"] = nil
			case "missing_endpoint":
				copyFields["Containers"] = map[string]any{cid: map[string]any{}}
			case "missing_roster":
				ids = append(ids, strings.Repeat("f", 64))
			case "duplicate_roster":
				ids = append(ids, network.ID)
			}
			row, _ := json.Marshal(copyFields)
			if name == "duplicate_key" {
				row = bytes.Replace(row, []byte(`"Id":`), []byte(`"Id":"`+network.ID+`","Id":`), 1)
			}
			body := append(append([]byte{'['}, row...), ']')
			if name == "extra_roster" {
				body = append(append(append(append([]byte{'['}, row...), ','), row...), ']')
			}
			if name == "trailing_json" {
				body = append(body, []byte(` {}`)...)
			}
			if _, err := decodeBootstrapNetworks(body, ids); err == nil {
				t.Fatal("incomplete or ambiguous network projection admitted")
			}
		})
	}
	changed := map[string]any{}
	for key, value := range fields {
		changed[key] = value
	}
	changed["unknownDockerField"] = "changed"
	changedRaw, _ := json.Marshal(changed)
	other, err := decodeBootstrapNetwork(changedRaw)
	if err != nil || other.Digest == decoded[network.ID].Digest {
		t.Fatal("unknown baseline field drift was discarded")
	}
}

func TestBootstrapNetworkProjectionPreservesExactUnknownNumbers(t *testing.T) {
	_, _, cid, network, _ := bootstrapNetworkPolicyFixture()
	fields := map[string]any{"Id": network.ID, "Name": network.Name, "Created": network.Created, "Driver": network.Driver, "Scope": network.Scope, "Internal": false, "Ingress": false, "ConfigOnly": false, "Labels": network.Labels, "Containers": map[string]any{cid: map[string]any{"EndpointID": network.Endpoints[cid]}}, "unknownInteger": json.Number("9007199254740992")}
	one, _ := json.Marshal(fields)
	fields["unknownInteger"] = json.Number("9007199254740993")
	two, _ := json.Marshal(fields)
	a, ae := decodeBootstrapNetwork(one)
	b, be := decodeBootstrapNetwork(two)
	if ae != nil || be != nil || a.Digest == b.Digest {
		t.Fatal("distinct actual unknown integers collapsed in network preservation digest")
	}
}

func TestBootstrapNetworkImmutableProjectionAndRemovalOutput(t *testing.T) {
	base, owner, cid, n, attachments := bootstrapNetworkPolicyFixture()
	fields := map[string]any{"Id": n.ID, "Name": n.Name, "Created": n.Created, "Driver": n.Driver, "Scope": n.Scope, "Internal": false, "Ingress": false, "ConfigOnly": false, "Labels": n.Labels, "Containers": map[string]any{cid: map[string]any{"EndpointID": n.Endpoints[cid]}}, "IPAM": map[string]any{"Driver": "default", "Subnet": "192.0.2.0/24"}, "Options": map[string]any{"example": "original"}, "unknownDockerField": "original"}
	raw, _ := json.Marshal(fields)
	original, err := decodeBootstrapNetwork(raw)
	if err != nil {
		t.Fatal("original complete immutable projection rejected")
	}
	pin := &bootstrapNetworkProvenance{original, cid, n.Endpoints[cid]}
	for _, field := range []string{"IPAM", "Options", "unknownDockerField", "Containers"} {
		t.Run(field, func(t *testing.T) {
			copyFields := map[string]any{}
			for key, value := range fields {
				copyFields[key] = value
			}
			copyFields[field] = map[string]any{"changed": "value"}
			if field == "Containers" {
				copyFields[field] = map[string]any{}
			}
			raw, _ := json.Marshal(copyFields)
			changed, err := decodeBootstrapNetwork(raw)
			if err != nil {
				t.Fatal("otherwise valid changed projection rejected before identity check")
			}
			if field == "Containers" {
				cleared := map[string]bootstrapNetworkAttachment{n.Name: {n.ID, ""}}
				if !sameBootstrapNetworkIdentity(original, changed) || !validBootstrapStoppedNetwork(pin, base, owner, cid, "stopped", changed, cleared) {
					t.Fatal("actual stop transition changed immutable authority")
				}
			} else if sameBootstrapNetworkIdentity(original, changed) || validBootstrapStoppedNetwork(pin, base, owner, cid, "stopped", changed, attachments) {
				t.Fatal("otherwise valid immutable projection drift admitted")
			}
		})
	}
	if !validBootstrapNetworkRemovalOutput(n.ID, []byte(n.ID+"\n")) {
		t.Fatal("exact full network removal result rejected")
	}
	for _, raw := range []string{"", n.Name, strings.Repeat("f", 64), n.ID + "\n" + n.ID, n.ID[:12]} {
		if validBootstrapNetworkRemovalOutput(n.ID, []byte(raw)) {
			t.Fatal("wrong or ambiguous network removal result admitted")
		}
	}
}
