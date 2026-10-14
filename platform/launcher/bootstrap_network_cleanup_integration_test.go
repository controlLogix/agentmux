//go:build (linux || darwin) && agentmux_bootstrap_docker

package launcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/netip"
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
	allocations                      map[string]bootstrapAllocationCounters
	endpointSubnets                  map[string][]string
}

type bootstrapNetworkAttachment struct{ NetworkID, EndpointID string }

type bootstrapNetworkProvenance struct {
	network     bootstrapNetworkObservation
	containerID string
	endpointID  string
}

func bootstrapNetworkError() error { return errors.New("fixture_network_admission_failed") }

type bootstrapNetworkReadFailure struct {
	stage string
	cause error
}

func (e *bootstrapNetworkReadFailure) Error() string { return "fixture_network_inventory_failed" }
func (e *bootstrapNetworkReadFailure) Unwrap() error { return e.cause }
func bootstrapNetworkReadStage(err error) string {
	var staged *bootstrapNetworkReadFailure
	if errors.As(err, &staged) {
		switch staged.stage {
		case "engine", "network_roster", "network_inspect", "network_decode":
			return staged.stage
		}
	}
	return "unknown"
}

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
	if !normalizeBootstrapNetworkCounters(immutable, containers, &x) {
		return empty, bootstrapNetworkError()
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
		return nil, &bootstrapNetworkReadFailure{"engine", err}
	}
	raw, err := f.Driver.run(ctx, nil, "network", "ls", "--quiet", "--no-trunc")
	if err != nil {
		return nil, &bootstrapNetworkReadFailure{"network_roster", err}
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
		return nil, &bootstrapNetworkReadFailure{"network_inspect", err}
	}
	result, err := decodeBootstrapNetworks(raw, ids)
	if err != nil {
		return nil, &bootstrapNetworkReadFailure{"network_decode", err}
	}
	return result, nil
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
	return validBootstrapCounterTransition(pin.network, current, pin.containerID)
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
		if !sameBootstrapNetworkIdentity(pin.network, network) || !validBootstrapCounterTransition(pin.network, network, pin.containerID) || pin.containerID != broker.ContainerID || pin.endpointID != attachment.EndpointID {
			return bootstrapNetworkError()
		}
		return nil
	}
	f.mu.Lock()
	if f.networkProvenance == nil {
		f.networkProvenance = &bootstrapNetworkProvenance{network, broker.ContainerID, attachment.EndpointID}
	}
	f.mu.Unlock()
	return f.writeNetworkEvidence("network-provenance.json", map[string]any{"networkId": network.ID, "name": network.Name, "created": network.Created, "containerId": broker.ContainerID, "endpointId": attachment.EndpointID, "baselineExcluded": true, "immutableDigest": network.ImmutableDigest, "scope": f.Config.Kernel.Scope})
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

func (f *bootstrapDockerFixture) cleanupCreatedNetwork(ctx context.Context, containerID string) (failure error) {
	started := time.Now()
	stage := "creation_pin"
	defer func() {
		_ = f.writeNetworkEvidence("network-cleanup-stage.json", bootstrapNetworkCleanupDiagnostic(stage, failure, ctx, time.Since(started)))
	}()
	f.mu.Lock()
	pin := f.networkProvenance
	f.mu.Unlock()
	if pin == nil {
		return bootstrapNetworkError()
	}
	stage = "network_before"
	current, err := f.networkByID(ctx, pin.network.ID)
	if err != nil {
		return err
	}
	stage = "attachment_before"
	attachments, err := f.networkAttachments(ctx, containerID)
	if err != nil {
		return err
	}
	stage = "broker_before"
	broker, err := f.ObserveBroker(ctx)
	if err != nil {
		return err
	}
	stage = "stopped_guard"
	if !validBootstrapStoppedNetwork(pin, f.networkBaseline, f.Owner, containerID, broker.State, current, attachments) {
		return bootstrapNetworkError()
	}
	beforeDetach := map[string]any{"networkId": current.ID, "created": current.Created, "immutableDigest": current.ImmutableDigest, "liveEndpointCount": len(current.Endpoints), "containerNetworkId": attachments[current.Name].NetworkID, "containerEndpointId": attachments[current.Name].EndpointID, "containerState": broker.State}
	stage = "engine_before_detach"
	if _, err = f.Driver.Inspect(ctx); err != nil {
		return err
	}
	stage = "detach"
	if _, err = f.Driver.run(ctx, nil, "network", "disconnect", "--force", pin.network.ID, containerID); err != nil {
		return err
	}
	stage = "network_after"
	current, err = f.networkByID(ctx, pin.network.ID)
	if err != nil {
		return err
	}
	stage = "attachment_after"
	attachments, err = f.networkAttachments(ctx, containerID)
	if err != nil {
		return err
	}
	stage = "broker_after"
	broker, err = f.ObserveBroker(ctx)
	if err != nil {
		return err
	}
	stage = "detached_guard"
	if !sameBootstrapNetworkIdentity(pin.network, current) || !validBootstrapCounterTransition(pin.network, current, pin.containerID) || len(current.Endpoints) != 0 || len(attachments) != 0 || broker.ContainerID != containerID || broker.State != "stopped" {
		return bootstrapNetworkError()
	}
	afterDetach := map[string]any{"networkId": current.ID, "created": current.Created, "immutableDigest": current.ImmutableDigest, "liveEndpointCount": len(current.Endpoints), "containerAttachmentCount": len(attachments), "containerState": broker.State}
	stage = "engine_before_remove"
	if _, err = f.Driver.Inspect(ctx); err != nil {
		return err
	}
	stage = "remove"
	removed, rmErr := f.Driver.run(ctx, nil, "network", "rm", pin.network.ID)
	if evidenceErr := writeBootstrapNetworkRemovalEvidence(f.EvidenceDirectory, pin.network.ID, removed); evidenceErr != nil {
		return errors.Join(rmErr, evidenceErr)
	}
	if rmErr != nil {
		return rmErr
	}
	stage = "remove_result"
	if !validBootstrapNetworkRemovalOutput(pin.network.ID, removed) {
		return bootstrapNetworkError()
	}
	stage = "baseline_read"
	baseline, err := f.networkInventory(ctx)
	if err != nil {
		return err
	}
	stage = "baseline_guard"
	if baseline[pin.network.ID].ID != "" || !sameBootstrapNetworkBaseline(f.networkBaseline, baseline) {
		return bootstrapNetworkError()
	}
	f.mu.Lock()
	f.networkRemoved = true
	f.mu.Unlock()
	stage = "complete"
	return f.writeNetworkEvidence("network-cleanup.json", map[string]any{"networkId": pin.network.ID, "containerId": containerID, "forcedStoppedEndpointDetach": true, "beforeDetach": beforeDetach, "afterDetach": afterDetach, "exactRemovedId": string(bytes.TrimSpace(removed)), "baselineNetworkCount": len(f.networkBaseline), "afterRemovalNetworkCount": len(baseline), "emptyBeforeRemoval": true, "networkRemoved": true, "unrelatedNetworkBaselineUnchanged": true, "stoppedContainerRetained": true})
}

func validBootstrapNetworkRemovalOutput(id string, raw []byte) bool {
	return fullID.MatchString(id) && string(bytes.TrimSpace(raw)) == id
}

// Save the actual response before a later inventory read can fail. The public
// summary contains only fixed fields; the response itself stays private.
func writeBootstrapNetworkRemovalEvidence(directory, id string, raw []byte) error {
	if len(raw) > 1024*1024 {
		return errors.New("fixture_removal_evidence_bound")
	}
	file, err := os.OpenFile(filepath.Join(directory, "network-removal-stdout.private"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("fixture_removal_evidence_unavailable")
	}
	_, writeErr := file.Write(raw)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("fixture_removal_evidence_unavailable")
	}
	summary, err := json.Marshal(map[string]any{"bytes": len(raw), "sha256": releaseDigest(raw), "exactRemovedID": validBootstrapNetworkRemovalOutput(id, raw)})
	if err != nil {
		return errors.New("fixture_removal_evidence_unavailable")
	}
	summaryFile, err := os.OpenFile(filepath.Join(directory, "network-removal-output.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("fixture_removal_evidence_unavailable")
	}
	_, writeErr = summaryFile.Write(append(summary, '\n'))
	closeErr = summaryFile.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("fixture_removal_evidence_unavailable")
	}
	return nil
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

// Read the admitted engine without TLS enrollment, builds or fixture mutation.
// This isolates a failing bounded baseline command before repeating startup.
func TestBootstrapRealBaselineReadOnlyDiagnostic(t *testing.T) {
	if os.Getenv("AMX_BOOTSTRAP_DOCKER_AUTHORIZED") != "1" {
		t.Fatal("actual read-only engine authorization missing")
	}
	for _, key := range []string{"DOCKER_HOST", "DOCKER_CONTEXT", "AMX_DOCKER_FIXTURE", "AMX_BROKER_INSPECT_FIXTURE", "AMX_OWNER_BRIDGE_DOCKER_FIXTURE"} {
		if os.Getenv(key) != "" {
			t.Fatal("baseline diagnostic override refused")
		}
	}
	selected, pin := loadBootstrapFixtureSelection(t)
	driver, err := NewDocker(selected.dockerConfig())
	if err != nil {
		t.Fatal("baseline diagnostic selection refused")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal("native diagnostic root unavailable")
	}
	directory, err := os.MkdirTemp(filepath.Join(home, ".cache", "agentmux-governance"), "p02-readonly-baseline-")
	if err != nil {
		t.Fatal("private baseline diagnostic directory unavailable")
	}
	f := &bootstrapDockerFixture{Driver: driver, EvidenceDirectory: directory}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	results := []map[string]any{}
	defer func() {
		f.WriteEvidence(t, "read-only-baseline.json", map[string]any{"target": selected.Target, "selectionPin": pin, "engineId": selected.Docker.EngineID, "noMutation": true, "observations": results})
	}()
	started := time.Now()
	_, err = driver.Inspect(ctx)
	results = append(results, map[string]any{"stage": "engine_identity", "elapsedNanoseconds": time.Since(started).Nanoseconds(), "failureCode": bootstrapFixtureFailureCode(err), "contextExpired": ctx.Err() != nil})
	if err != nil {
		t.Fatal("read-only baseline engine identity failed")
	}
	read := func(stage string, args ...string) []byte {
		started := time.Now()
		raw, e := driver.run(ctx, nil, args...)
		results = append(results, map[string]any{"stage": stage, "elapsedNanoseconds": time.Since(started).Nanoseconds(), "outputBytes": len(raw), "failureCode": bootstrapFixtureFailureCode(e), "contextExpired": ctx.Err() != nil})
		if e != nil {
			t.Fatal("bounded read-only baseline command failed")
		}
		return raw
	}
	netRoster := read("network_roster", "network", "ls", "--quiet", "--no-trunc")
	var netIDs []string
	for _, word := range bytes.Fields(netRoster) {
		netIDs = append(netIDs, string(word))
	}
	if len(netIDs) > 0 {
		raw := read("network_inspect", append([]string{"network", "inspect"}, netIDs...)...)
		_, err = decodeBootstrapNetworks(raw, netIDs)
		results = append(results, map[string]any{"stage": "network_decode", "accepted": err == nil, "declaredCount": len(netIDs)})
		if err != nil {
			t.Fatal("read-only baseline network decode failed")
		}
	}
	containerRoster := read("container_roster", "ps", "--all", "--quiet", "--no-trunc")
	var containerIDs []string
	for _, word := range bytes.Fields(containerRoster) {
		containerIDs = append(containerIDs, string(word))
	}
	if len(containerIDs) > 0 {
		const format = `{"Id":{{json .Id}},"State":{{json .State.Status}},"DeclaredPorts":{{json .HostConfig.PortBindings}},"ActivePorts":{{json .NetworkSettings.Ports}}}`
		raw := read("container_inspect", append([]string{"container", "inspect", "--format", format}, containerIDs...)...)
		_, err = decodeBootstrapInventory(raw, containerIDs)
		results = append(results, map[string]any{"stage": "container_decode", "accepted": err == nil, "declaredCount": len(containerIDs)})
		if err != nil {
			t.Fatal("read-only baseline container decode failed")
		}
	}
}

// Diagnostic fields grant no ownership or cleanup authority.
func bootstrapNetworkCleanupDiagnostic(stage string, err error, ctx context.Context, elapsed time.Duration) map[string]any {
	switch stage {
	case "creation_pin", "network_before", "attachment_before", "broker_before", "stopped_guard", "engine_before_detach", "detach", "network_after", "attachment_after", "broker_after", "detached_guard", "engine_before_remove", "remove", "remove_result", "baseline_read", "baseline_guard", "complete":
	default:
		stage = "unknown"
	}
	readStage := "not_applicable"
	if stage == "baseline_read" {
		readStage = bootstrapNetworkReadStage(err)
	}
	return map[string]any{"stage": stage, "readStage": readStage, "failureCode": bootstrapFixtureFailureCode(err), "contextExpired": ctx != nil && ctx.Err() != nil, "elapsedNanoseconds": elapsed.Nanoseconds(), "cleanupVerified": err == nil && stage == "complete"}
}
func TestBootstrapNetworkCleanupDiagnosticIsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	row := bootstrapNetworkCleanupDiagnostic("secret-path", errors.New("secret-password"), ctx, time.Millisecond)
	raw, err := json.Marshal(row)
	if err != nil || bytes.Contains(raw, []byte("secret")) || row["stage"] != "unknown" || row["contextExpired"] != true || row["cleanupVerified"] != false {
		t.Fatal("cleanup diagnostic leaked or fabricated authority")
	}
	if bootstrapNetworkCleanupDiagnostic("complete", nil, context.Background(), time.Millisecond)["cleanupVerified"] != true {
		t.Fatal("completed diagnostic rejected")
	}
	if bootstrapNetworkCleanupDiagnostic("remove", nil, context.Background(), time.Millisecond)["cleanupVerified"] != false {
		t.Fatal("partial cleanup reported complete")
	}
}

func TestBootstrapNetworkCleanupPreservesNestedReadFailure(t *testing.T) {
	for _, stage := range []string{"engine", "network_roster", "network_inspect", "network_decode", "private-path"} {
		row := bootstrapNetworkCleanupDiagnostic("baseline_read", &bootstrapNetworkReadFailure{stage, errors.New("private-password")}, context.Background(), time.Millisecond)
		expected := stage
		if stage == "private-path" {
			expected = "unknown"
		}
		raw, err := json.Marshal(row)
		if err != nil || row["readStage"] != expected || bytes.Contains(raw, []byte("private-password")) || bytes.Contains(raw, []byte("private-path")) {
			t.Fatal("nested read failure was lost or exposed private text")
		}
	}
}

func TestBootstrapNetworkRemovalEvidenceRetainsPrivateResponse(t *testing.T) {
	id := strings.Repeat("a", 64)
	for _, response := range []string{id + "\n", "private-password\n", ""} {
		directory := t.TempDir()
		if err := writeBootstrapNetworkRemovalEvidence(directory, id, []byte(response)); err != nil {
			t.Fatal("actual removal response was not preserved")
		}
		path := filepath.Join(directory, "network-removal-stdout.private")
		raw, err := os.ReadFile(path)
		info, statErr := os.Stat(path)
		if err != nil || statErr != nil || string(raw) != response || info.Mode().Perm() != 0600 {
			t.Fatal("private response differs or is readable outside its owner")
		}
		summary, err := os.ReadFile(filepath.Join(directory, "network-removal-output.json"))
		var row map[string]any
		if err != nil || json.Unmarshal(summary, &row) != nil || len(row) != 3 || row["sha256"] != releaseDigest(raw) || row["exactRemovedID"] != (response == id+"\n") || bytes.Contains(summary, []byte("private-password")) {
			t.Fatal("safe summary lost the result or exposed arbitrary output")
		}
		if writeBootstrapNetworkRemovalEvidence(directory, id, []byte("replacement")) == nil {
			t.Fatal("original response was overwritten")
		}
		still, err := os.ReadFile(path)
		if err != nil || string(still) != response {
			t.Fatal("refused overwrite changed original response")
		}
	}
}

func TestBootstrapNetworkRemovalEvidenceRejectsUnsafeSinkAndBounds(t *testing.T) {
	directory := t.TempDir()
	id := strings.Repeat("a", 64)
	if writeBootstrapNetworkRemovalEvidence(directory, id, make([]byte, 1024*1024+1)) == nil {
		t.Fatal("oversized response was admitted")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatal("oversized response created evidence")
	}
	target := filepath.Join(t.TempDir(), "original")
	if os.WriteFile(target, []byte("original"), 0600) != nil || os.Symlink(target, filepath.Join(directory, "network-removal-stdout.private")) != nil {
		t.Fatal("owned unsafe-sink fixture unavailable")
	}
	if writeBootstrapNetworkRemovalEvidence(directory, id, []byte(id)) == nil {
		t.Fatal("response followed a replacement sink")
	}
	unchanged, err := os.ReadFile(target)
	if err != nil || string(unchanged) != "original" {
		t.Fatal("refused sink modified unrelated bytes")
	}
}

func TestBootstrapNetworkRemovalSummaryRefusesExistingSink(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		directory := t.TempDir()
		path := filepath.Join(directory, "network-removal-output.json")
		target := path
		if symlink {
			target = filepath.Join(t.TempDir(), "unrelated")
		}
		if os.WriteFile(target, []byte("original"), 0600) != nil {
			t.Fatal("owned summary fixture unavailable")
		}
		if symlink && os.Symlink(target, path) != nil {
			t.Fatal("owned summary symlink unavailable")
		}
		response := strings.Repeat("a", 64) + "\n"
		if writeBootstrapNetworkRemovalEvidence(directory, strings.Repeat("a", 64), []byte(response)) == nil {
			t.Fatal("pre-existing summary was admitted")
		}
		unchanged, err := os.ReadFile(target)
		if err != nil || string(unchanged) != "original" {
			t.Fatal("refused summary changed original bytes")
		}
		raw, err := os.ReadFile(filepath.Join(directory, "network-removal-stdout.private"))
		if err != nil || string(raw) != response {
			t.Fatal("summary refusal lost the actual response")
		}
	}
}

func bootstrapCounterFields() map[string]any {
	_, _, cid, n, _ := bootstrapNetworkPolicyFixture()
	return map[string]any{"Id": n.ID, "Name": n.Name, "Created": n.Created, "Driver": n.Driver, "Scope": n.Scope, "Internal": false, "Ingress": false, "ConfigOnly": false, "Labels": n.Labels, "Containers": map[string]any{cid: map[string]any{"EndpointID": n.Endpoints[cid], "IPv4Address": "192.0.2.2/24", "IPv6Address": ""}}, "IPAM": map[string]any{"Driver": "default", "Config": []any{map[string]any{"Subnet": "192.0.2.0/24", "Gateway": "192.0.2.1"}}, "unknownStatic": json.Number("9007199254740993")}, "Status": map[string]any{"IPAM": map[string]any{"Subnets": map[string]any{"192.0.2.0/24": map[string]any{"IPsInUse": 4, "DynamicIPsAvailable": 252, "unknownCounterNeighbor": "original"}}}, "unknownStatus": "original"}}
}
func bootstrapCounterDecode(t *testing.T, fields map[string]any) bootstrapNetworkObservation {
	t.Helper()
	raw, e := json.Marshal(fields)
	if e != nil {
		t.Fatal("counter fixture encode failed")
	}
	n, e := decodeBootstrapNetwork(raw)
	if e != nil {
		t.Fatal("otherwise valid counter fixture rejected")
	}
	return n
}
func bootstrapCounterValues(fields map[string]any) map[string]any {
	return fields["Status"].(map[string]any)["IPAM"].(map[string]any)["Subnets"].(map[string]any)["192.0.2.0/24"].(map[string]any)
}
func TestBootstrapNetworkCounterOneEndpointRelease(t *testing.T) {
	base, owner, cid, _, _ := bootstrapNetworkPolicyFixture()
	running := bootstrapCounterDecode(t, bootstrapCounterFields())
	fields := bootstrapCounterFields()
	fields["Containers"] = map[string]any{}
	counters := bootstrapCounterValues(fields)
	counters["IPsInUse"] = 3
	counters["DynamicIPsAvailable"] = 253
	stopped := bootstrapCounterDecode(t, fields)
	pin := &bootstrapNetworkProvenance{running, cid, running.Endpoints[cid]}
	attachments := map[string]bootstrapNetworkAttachment{running.Name: {running.ID, ""}}
	if !validBootstrapStoppedNetwork(pin, base, owner, cid, "stopped", stopped, attachments) {
		t.Fatal("actual one-endpoint allocation release rejected")
	}
	if running.Digest == stopped.Digest || sameBootstrapNetworkBaseline(map[string]bootstrapNetworkObservation{running.ID: running}, map[string]bootstrapNetworkObservation{stopped.ID: stopped}) {
		t.Fatal("foreign complete baseline normalized allocation counters")
	}
}
func TestBootstrapNetworkCounterMalformedAndAmbiguous(t *testing.T) {
	for _, name := range []string{"fraction", "negative", "exponent", "string", "null", "missing", "overflow", "wrong_total", "status_subnet", "duplicate_static", "overlap_static", "noncanonical_static", "endpoint_foreign", "endpoint_prefix", "endpoint_absent", "unknown_address_family"} {
		t.Run(name, func(t *testing.T) {
			f := bootstrapCounterFields()
			c := bootstrapCounterValues(f)
			cid := strings.Repeat("b", 64)
			entry := f["Containers"].(map[string]any)[cid].(map[string]any)
			static := f["IPAM"].(map[string]any)
			switch name {
			case "fraction":
				c["IPsInUse"] = json.Number("3.5")
			case "negative":
				c["IPsInUse"] = -1
			case "exponent":
				c["IPsInUse"] = json.Number("4e0")
			case "string":
				c["IPsInUse"] = "4"
			case "null":
				c["IPsInUse"] = nil
			case "missing":
				delete(c, "IPsInUse")
			case "overflow":
				c["IPsInUse"] = json.Number("340282366920938463463374607431768211457")
			case "wrong_total":
				c["DynamicIPsAvailable"] = 251
			case "status_subnet":
				f["Status"].(map[string]any)["IPAM"].(map[string]any)["Subnets"] = map[string]any{"192.0.3.0/24": c}
			case "duplicate_static":
				static["Config"] = []any{map[string]any{"Subnet": "192.0.2.0/24"}, map[string]any{"Subnet": "192.0.2.0/24"}}
			case "overlap_static":
				static["Config"] = []any{map[string]any{"Subnet": "192.0.2.0/24"}, map[string]any{"Subnet": "192.0.2.0/25"}}
			case "noncanonical_static":
				static["Config"] = []any{map[string]any{"Subnet": "192.0.2.1/24"}}
			case "endpoint_foreign":
				entry["IPv4Address"] = "192.0.3.2/24"
			case "endpoint_prefix":
				entry["IPv4Address"] = "192.0.2.2/25"
			case "endpoint_absent":
				entry["IPv4Address"] = ""
			case "unknown_address_family":
				entry["IPv6Address"] = "192.0.2.3/24"
			}
			raw, _ := json.Marshal(f)
			if _, e := decodeBootstrapNetwork(raw); e == nil {
				t.Fatal("malformed or ambiguous allocation admitted")
			}
		})
	}
}
func TestBootstrapNetworkCounterRejectsWrongTransitionAndUnknownDrift(t *testing.T) {
	for _, name := range []string{"two_release", "inverse_release", "unchanged_endpoint_counter_drift", "removed_without_release", "unknown_status", "unknown_subnet", "unknown_static", "foreign_endpoint", "absent_status", "unknown_large_integer"} {
		t.Run(name, func(t *testing.T) {
			base, owner, cid, _, _ := bootstrapNetworkPolicyFixture()
			running := bootstrapCounterDecode(t, bootstrapCounterFields())
			f := bootstrapCounterFields()
			f["Containers"] = map[string]any{}
			c := bootstrapCounterValues(f)
			c["IPsInUse"] = 3
			c["DynamicIPsAvailable"] = 253
			switch name {
			case "two_release":
				c["IPsInUse"] = 2
				c["DynamicIPsAvailable"] = 254
			case "inverse_release":
				c["IPsInUse"] = 5
				c["DynamicIPsAvailable"] = 251
			case "unchanged_endpoint_counter_drift":
				f["Containers"] = bootstrapCounterFields()["Containers"]
			case "removed_without_release":
				c["IPsInUse"] = 4
				c["DynamicIPsAvailable"] = 252
			case "unknown_status":
				f["Status"].(map[string]any)["unknownStatus"] = "changed"
			case "unknown_subnet":
				c["unknownCounterNeighbor"] = "changed"
			case "unknown_static":
				f["IPAM"].(map[string]any)["unknownStatic"] = json.Number("9007199254740992")
			case "foreign_endpoint":
				f["Containers"] = map[string]any{strings.Repeat("f", 64): bootstrapCounterFields()["Containers"].(map[string]any)[cid]}
			case "absent_status":
				delete(f, "Status")
			case "unknown_large_integer":
				f["Status"].(map[string]any)["unknownStatus"] = json.Number("9007199254740993")
			}
			current := bootstrapCounterDecode(t, f)
			pin := &bootstrapNetworkProvenance{running, cid, running.Endpoints[cid]}
			a := map[string]bootstrapNetworkAttachment{running.Name: {running.ID, ""}}
			if validBootstrapStoppedNetwork(pin, base, owner, cid, "stopped", current, a) {
				t.Fatal("wrong allocation or unknown immutable drift admitted")
			}
		})
	}
}

type bootstrapAllocationCounters struct{ used, available string }

func bootstrapExactCounter(v any) (*big.Int, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return nil, false
	}
	s := n.String()
	if len(s) == 0 || len(s) > 39 || (len(s) > 1 && s[0] == '0') {
		return nil, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return nil, false
		}
	}
	value, ok := new(big.Int).SetString(s, 10)
	return value, ok
}
func bootstrapExactKey(m map[string]any, key string) bool {
	for k := range m {
		if k != key && strings.EqualFold(k, key) {
			return false
		}
	}
	return true
}

// Only known, validated allocation values change the identity projection. All
// unknown keys and values remain in that projection and in the full baseline.
func normalizeBootstrapNetworkCounters(fields, containers map[string]any, n *bootstrapNetworkObservation) bool {
	if !bootstrapExactKey(fields, "Status") || !bootstrapExactKey(fields, "IPAM") {
		return false
	}
	value, present := fields["Status"]
	if !present {
		return true
	}
	status, ok := value.(map[string]any)
	if !ok {
		return false
	}
	if !bootstrapExactKey(status, "IPAM") {
		return false
	}
	value, present = status["IPAM"]
	if !present {
		return true
	}
	ipamStatus, ok := value.(map[string]any)
	if !ok || !bootstrapExactKey(ipamStatus, "Subnets") {
		return false
	}
	value, present = ipamStatus["Subnets"]
	if !present {
		return true
	}
	subnets, ok := value.(map[string]any)
	if !ok {
		return false
	}
	if len(subnets) == 0 {
		return true
	}
	if len(subnets) > 16 {
		return false
	}
	static, ok := fields["IPAM"].(map[string]any)
	if !ok || !bootstrapExactKey(static, "Config") {
		return false
	}
	config, ok := static["Config"].([]any)
	if !ok || len(config) != len(subnets) {
		return false
	}
	prefixes := map[string]netip.Prefix{}
	for _, v := range config {
		row, ok := v.(map[string]any)
		if !ok || !bootstrapExactKey(row, "Subnet") {
			return false
		}
		text, ok := row["Subnet"].(string)
		if !ok {
			return false
		}
		prefix, e := netip.ParsePrefix(text)
		if e != nil || prefix.Masked().String() != text || prefix.Addr().Is4In6() {
			return false
		}
		if _, exists := prefixes[text]; exists {
			return false
		}
		for _, old := range prefixes {
			if old.Overlaps(prefix) {
				return false
			}
		}
		prefixes[text] = prefix
	}
	n.allocations = map[string]bootstrapAllocationCounters{}
	n.endpointSubnets = map[string][]string{}
	for text, value := range subnets {
		prefix, exists := prefixes[text]
		row, ok := value.(map[string]any)
		if !exists || !ok || !bootstrapExactKey(row, "IPsInUse") || !bootstrapExactKey(row, "DynamicIPsAvailable") {
			return false
		}
		used, uok := bootstrapExactCounter(row["IPsInUse"])
		available, aok := bootstrapExactCounter(row["DynamicIPsAvailable"])
		if !uok || !aok {
			return false
		}
		capacity := new(big.Int).Lsh(big.NewInt(1), uint(prefix.Addr().BitLen()-prefix.Bits()))
		if used.Cmp(capacity) > 0 || available.Cmp(capacity) > 0 || new(big.Int).Add(used, available).Cmp(capacity) != 0 {
			return false
		}
		n.allocations[text] = bootstrapAllocationCounters{used.String(), available.String()}
	}
	assigned := map[string]int{}
	for id, value := range containers {
		row, ok := value.(map[string]any)
		if !ok {
			return false
		}
		families := 0
		for _, key := range []string{"IPv4Address", "IPv6Address"} {
			if !bootstrapExactKey(row, key) {
				return false
			}
			value, present := row[key]
			if !present {
				continue
			}
			text, ok := value.(string)
			if !ok {
				return false
			}
			if text == "" {
				continue
			}
			address, e := netip.ParsePrefix(text)
			if e != nil || address.String() != text || address.Addr().Is4In6() || (key == "IPv4Address") != address.Addr().Is4() {
				return false
			}
			match := ""
			for subnet, prefix := range prefixes {
				if prefix.Contains(address.Addr()) {
					if match != "" || address.Bits() != prefix.Bits() {
						return false
					}
					match = subnet
				}
			}
			if match == "" {
				return false
			}
			n.endpointSubnets[id] = append(n.endpointSubnets[id], match)
			assigned[match]++
			families++
		}
		if families == 0 {
			return false
		}
	}
	for subnet, count := range assigned {
		used, _ := new(big.Int).SetString(n.allocations[subnet].used, 10)
		if used.Cmp(big.NewInt(int64(count))) < 0 {
			return false
		}
	}
	for _, value := range subnets {
		row := value.(map[string]any)
		row["IPsInUse"] = "validated-endpoint-counter"
		row["DynamicIPsAvailable"] = "validated-endpoint-counter"
	}
	return true
}

// A retained original pin authorizes at most one exact endpoint release. It
// cannot bless a foreign allocation or a second release after detach.
func validBootstrapCounterTransition(original, current bootstrapNetworkObservation, containerID string) bool {
	if len(original.allocations) != len(current.allocations) {
		return false
	}
	if len(original.allocations) == 0 {
		return true
	}
	_, wasPresent := original.Endpoints[containerID]
	_, isPresent := current.Endpoints[containerID]
	if !wasPresent {
		return false
	}
	if isPresent && !reflect.DeepEqual(original.endpointSubnets, current.endpointSubnets) {
		return false
	}
	release := map[string]bool{}
	if !isPresent {
		for _, subnet := range original.endpointSubnets[containerID] {
			if release[subnet] {
				return false
			}
			release[subnet] = true
		}
		if len(release) == 0 {
			return false
		}
	}
	for subnet, before := range original.allocations {
		after, ok := current.allocations[subnet]
		if !ok {
			return false
		}
		u, ok := new(big.Int).SetString(before.used, 10)
		if !ok {
			return false
		}
		a, ok := new(big.Int).SetString(before.available, 10)
		if !ok {
			return false
		}
		if release[subnet] {
			if u.Sign() == 0 {
				return false
			}
			u.Sub(u, big.NewInt(1))
			a.Add(a, big.NewInt(1))
		}
		if after.used != u.String() || after.available != a.String() {
			return false
		}
	}
	return true
}

func TestBootstrapNetworkCounterPreservesAbsentAndExactUnknownStatus(t *testing.T) {
	base, owner, cid, n, a := bootstrapNetworkPolicyFixture()
	pin := &bootstrapNetworkProvenance{n, cid, n.Endpoints[cid]}
	if !validBootstrapStoppedNetwork(pin, base, owner, cid, "stopped", n, a) {
		t.Fatal("unchanged absent status rejected")
	}
	fields := bootstrapCounterFields()
	fields["Status"].(map[string]any)["unknownStatus"] = json.Number("9007199254740993")
	running := bootstrapCounterDecode(t, fields)
	fields = bootstrapCounterFields()
	fields["Containers"] = map[string]any{}
	values := bootstrapCounterValues(fields)
	values["IPsInUse"] = 3
	values["DynamicIPsAvailable"] = 253
	fields["Status"].(map[string]any)["unknownStatus"] = json.Number("9007199254740992")
	current := bootstrapCounterDecode(t, fields)
	pinned := &bootstrapNetworkProvenance{running, cid, running.Endpoints[cid]}
	cleared := map[string]bootstrapNetworkAttachment{running.Name: {running.ID, ""}}
	if validBootstrapStoppedNetwork(pinned, base, owner, cid, "stopped", current, cleared) {
		t.Fatal("exact unknown status integer drift collapsed")
	}
	// The original pin remains the authority after a release; another release is
	// not accepted by treating the last observation as a new pin.
	fields = bootstrapCounterFields()
	fields["Containers"] = map[string]any{}
	values = bootstrapCounterValues(fields)
	values["IPsInUse"] = 2
	values["DynamicIPsAvailable"] = 254
	if validBootstrapStoppedNetwork(pinned, base, owner, cid, "stopped", bootstrapCounterDecode(t, fields), cleared) {
		t.Fatal("second release accepted")
	}
}
func TestBootstrapNetworkCounterAllowsExactUnchangedAndIPv6Allocation(t *testing.T) {
	base, owner, cid, _, _ := bootstrapNetworkPolicyFixture()
	n := bootstrapCounterDecode(t, bootstrapCounterFields())
	p := &bootstrapNetworkProvenance{n, cid, n.Endpoints[cid]}
	a := map[string]bootstrapNetworkAttachment{n.Name: {n.ID, n.Endpoints[cid]}}
	if !validBootstrapStoppedNetwork(p, base, owner, cid, "stopped", n, a) {
		t.Fatal("unchanged endpoint allocation rejected")
	}
	fields := bootstrapCounterFields()
	fields["IPAM"].(map[string]any)["Config"] = []any{map[string]any{"Subnet": "2001:db8::/64"}}
	fields["Status"].(map[string]any)["IPAM"].(map[string]any)["Subnets"] = map[string]any{"2001:db8::/64": map[string]any{"IPsInUse": json.Number("4"), "DynamicIPsAvailable": json.Number("18446744073709551612")}}
	entry := fields["Containers"].(map[string]any)[cid].(map[string]any)
	entry["IPv4Address"] = ""
	entry["IPv6Address"] = "2001:db8::2/64"
	running := bootstrapCounterDecode(t, fields)
	fields["Containers"] = map[string]any{}
	v := fields["Status"].(map[string]any)["IPAM"].(map[string]any)["Subnets"].(map[string]any)["2001:db8::/64"].(map[string]any)
	v["IPsInUse"] = json.Number("3")
	v["DynamicIPsAvailable"] = json.Number("18446744073709551613")
	stopped := bootstrapCounterDecode(t, fields)
	p = &bootstrapNetworkProvenance{running, cid, running.Endpoints[cid]}
	a = map[string]bootstrapNetworkAttachment{running.Name: {running.ID, ""}}
	if !validBootstrapStoppedNetwork(p, base, owner, cid, "stopped", stopped, a) {
		t.Fatal("exact IPv6 allocation arithmetic rejected")
	}
}
