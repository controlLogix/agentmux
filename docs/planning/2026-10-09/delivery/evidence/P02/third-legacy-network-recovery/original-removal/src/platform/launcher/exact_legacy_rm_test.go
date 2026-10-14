package launcher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestExactThirdLegacyEmptyNetworkRemoval(t *testing.T) {
	out := os.Getenv("AMX_EXACT_RM_OUTPUT")
	if out == "" || os.Getenv("AMX_EXACT_RM_AUTHORIZED") != "1" {
		t.Fatal("exact removal authorization missing")
	}
	const cid = "066bd3c2cd6698d5a6eae5e650b71acd7ff0754c3f9871c343b30f558387c306"
	const nid = "d6696c0a7b1e8bf34fc308b63c8162521f6c17d879aa700af554a699325ec621"
	const expectedDigest = "sha256:b20d02d53f5b03526b589f873665a6d0c8e72ed9dcfc8f478ffdf09242c7b630"
	const root = "/home/ryan/.cache/agentmux-governance/p02-bootstrap-private-3411499751"
	result := map[string]any{"networkId": nid, "containerId": cid, "mutationAttempted": false, "mutationSucceeded": false}
	var leases []*BootstrapLock
	archive := func(name string, b []byte) {
		if os.WriteFile(filepath.Join(out, name), b, 0600) != nil {
			t.Fatal("private exact recovery archive failed")
		}
	}
	defer func() {
		codes := []string{}
		for _, l := range leases {
			if l.Close() != nil {
				codes = append(codes, "lease_close_failed")
			}
		}
		result["leaseCountReleased"] = len(leases)
		result["leaseCloseCodes"] = codes
		b, _ := json.MarshalIndent(result, "", "  ")
		archive("result.json", append(b, '\n'))
	}()
	guard := func(stage string, e error) {
		result["stage"] = stage
		if e != nil {
			result["failureCode"] = "fixed_recovery_stage_failed"
			t.Fatal("fixed exact recovery stage failed")
		}
		result["failureCode"] = "none"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	h, e := LoadEnrolledHostPolicy(HostPolicySelection{Path: filepath.Join(root, "installed/host-policy.json"), OwnerUID: uint32(os.Geteuid()), WorkspaceRoots: []string{"/mnt/c/Users/RyanHelms/GitHub/agentmux"}})
	guard("private_signed_admission", e)
	c, status, e := h.Load()
	guard("private_full_config", e)
	if status == nil {
		t.Fatal("actual owner absent")
	}
	p, e := LoadProfile(c.ProfilePolicy)
	guard("private_profile", e)
	decl := p.Declaration()
	sel, local := p.LocalDocker()
	if !local || sel.EngineID != "e0f1f93d-abf1-44f2-b62a-5bfee21d2b5c" {
		t.Fatal("exact selected engine mismatch")
	}
	ids := []string{sel.EngineID, "owner-status-service"}
	for _, role := range protocol.Roles() {
		ids = append(ids, sel.EngineID+":runtime:"+role)
	}
	for _, id := range ids {
		l, e := AcquireBootstrapLock(ctx, decl.ProfileDirectory, decl.InstanceID, id)
		guard("actual_six_leases", e)
		leases = append(leases, l)
	}
	if len(leases) != 6 {
		t.Fatal("actual six leases absent")
	}
	result["leaseCountHeld"] = 6
	d, e := NewDocker(DockerConfig{Executable: sel.Executable, Context: sel.Context, Endpoint: sel.Endpoint, EngineID: sel.EngineID, Versions: DockerVersions{sel.ClientVersion, sel.ServerVersion, sel.ComposeVersion}, Timeout: 4 * time.Second, Backend: sel.Backend})
	guard("literal_selected_driver", e)
	read := func(stage string, args ...string) []byte {
		started := time.Now()
		raw, e := d.run(ctx, nil, args...)
		result[stage+"ElapsedNanoseconds"] = time.Since(started).Nanoseconds()
		guard(stage, e)
		return raw
	}
	precise := func(raw []byte) map[string]any {
		var fields map[string]any
		guard("strict_private_json", protocol.DecodeClosedJSON(raw, &fields, 65536))
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		guard("precise_private_json", dec.Decode(&fields))
		return fields
	}
	hash := func(fields map[string]any) string {
		b, e := json.Marshal(fields)
		guard("canonical_private_hash", e)
		return fmt.Sprintf("sha256:%x", sha256.Sum256(b))
	}
	roster := func(kind, phase string) map[string]string {
		var ids []string
		var raw []byte
		if kind == "network" {
			raw = read("network_roster", "network", "ls", "--quiet", "--no-trunc")
		} else {
			raw = read("container_roster", "ps", "--all", "--quiet", "--no-trunc")
		}
		for _, word := range bytes.Fields(raw) {
			id := string(word)
			if len(id) != 64 || strings.Trim(id, "0123456789abcdef") != "" {
				t.Fatal("complete roster ID refused")
			}
			ids = append(ids, id)
		}
		args := []string{kind, "inspect"}
		args = append(args, ids...)
		raw = read(kind+"_full_roster", args...)
		archive("private-"+kind+"-"+phase+".json", raw)
		var rows []json.RawMessage
		guard("complete_full_roster_json", json.Unmarshal(raw, &rows))
		if len(rows) != len(ids) {
			t.Fatal("complete roster size mismatch")
		}
		expected := map[string]bool{}
		for _, id := range ids {
			if expected[id] {
				t.Fatal("duplicate declared ID")
			}
			expected[id] = true
		}
		hashes := map[string]string{}
		for _, row := range rows {
			fields := precise(row)
			id, ok := fields["Id"].(string)
			if !ok || !expected[id] || hashes[id] != "" {
				t.Fatal("full roster exact identity refused")
			}
			for key := range fields {
				if key != "Id" && strings.EqualFold(key, "Id") {
					t.Fatal("full roster alias identity refused")
				}
			}
			hashes[id] = hash(fields)
		}
		return hashes
	}
	_, e = d.Inspect(ctx)
	guard("selected_engine", e)
	portText := strings.TrimPrefix(decl.NATSEndpoint, "tls://127.0.0.1:")
	var port int
	if _, e = fmt.Sscanf(portText, "%d", &port); e != nil || port <= 0 || port > 65535 {
		t.Fatal("exact enrolled port refused")
	}
	owner := OwnershipPreflight{Project: decl.ComposeProject, InstanceID: decl.InstanceID, ProfileID: decl.ProfileID, ReleaseDigest: decl.ReleaseFingerprint, ConfigDigest: sha256.Sum256(c.Compose)}
	broker := func() {
		b, e := d.InspectOwnedTLSBroker(ctx, owner, c.BrokerImage, port, c.BrokerConfigDigest, sha256.Sum256(c.LocalTLS.ServerCertificatePEM()), sha256.Sum256(c.LocalTLS.ServerKeyPEM()))
		guard("full_same_stopped_broker", e)
		if b.ContainerID != cid || b.State != "stopped" {
			t.Fatal("full same stopped identity refused")
		}
	}
	broker()
	networkRaw := read("exact_network_before", "network", "inspect", nid)
	archive("private-exact-network-before.json", networkRaw)
	var networkRows []json.RawMessage
	guard("exact_network_array", json.Unmarshal(networkRaw, &networkRows))
	if len(networkRows) != 1 {
		t.Fatal("exact network count refused")
	}
	network := precise(networkRows[0])
	live, ok := network["Containers"].(map[string]any)
	if !ok || len(live) != 0 || network["Id"] != nid || network["Name"] != decl.ComposeProject+"_default" || network["Created"] != "2026-10-14T08:36:23.711423596Z" || hash(network) != expectedDigest {
		t.Fatal("fresh exact empty full network drift")
	}
	relationRaw := read("exact_relation_before", "container", "inspect", cid, "--format", `{"Id":{{json .Id}},"Created":{{json .Created}},"State":{{json .State.Status}},"Networks":{{json .NetworkSettings.Networks}}}`)
	archive("private-relation-before.json", relationRaw)
	relation := precise(bytes.TrimSpace(relationRaw))
	networks, ok := relation["Networks"].(map[string]any)
	entry, entryOK := networks[decl.ComposeProject+"_default"].(map[string]any)
	if !ok || len(networks) != 1 || !entryOK || entry["NetworkID"] != nid || entry["EndpointID"] != "" || relation["Id"] != cid || relation["State"] != "exited" || relation["Created"] != "2026-10-14T08:36:23.762217381Z" {
		t.Fatal("fresh exact stopped sole relation drift")
	}
	volumeRaw := read("exact_volume_before", "volume", "inspect", decl.ComposeProject+"_data")
	archive("private-volume-before.json", volumeRaw)
	beforeContainers := roster("container", "before")
	beforeNetworks := roster("network", "before")
	result["containerBeforeCount"] = len(beforeContainers)
	result["networkBeforeCount"] = len(beforeNetworks)
	_, e = d.Inspect(ctx)
	guard("fresh_engine_before_removal", e)
	result["mutationAttempted"] = true
	removed := read("literal_exact_network_rm", "network", "rm", nid)
	if string(bytes.TrimSpace(removed)) != nid {
		t.Fatal("exact network removal response mismatch")
	}
	result["returnedExactNetworkId"] = true
	afterContainers := roster("container", "after")
	afterNetworks := roster("network", "after")
	if afterNetworks[nid] != "" {
		t.Fatal("exact removed network still present")
	}
	delete(beforeNetworks, nid)
	result["completeOtherNetworksUnchanged"] = reflect.DeepEqual(beforeNetworks, afterNetworks)
	result["completeContainersUnchanged"] = reflect.DeepEqual(beforeContainers, afterContainers)
	if result["completeOtherNetworksUnchanged"] != true || result["completeContainersUnchanged"] != true {
		t.Fatal("complete exact recovery baseline changed")
	}
	broker()
	afterRelation := read("exact_relation_after", "container", "inspect", cid, "--format", `{"Id":{{json .Id}},"Created":{{json .Created}},"State":{{json .State.Status}},"Networks":{{json .NetworkSettings.Networks}}}`)
	archive("private-relation-after.json", afterRelation)
	if !reflect.DeepEqual(relation, precise(bytes.TrimSpace(afterRelation))) {
		t.Fatal("retained exact stopped relation changed")
	}
	afterVolume := read("exact_volume_after", "volume", "inspect", decl.ComposeProject+"_data")
	archive("private-volume-after.json", afterVolume)
	var vb, va []json.RawMessage
	guard("volume_before_array", json.Unmarshal(volumeRaw, &vb))
	guard("volume_after_array", json.Unmarshal(afterVolume, &va))
	if len(vb) != 1 || len(va) != 1 || hash(precise(vb[0])) != hash(precise(va[0])) {
		t.Fatal("full retained volume changed")
	}
	result["sameStoppedBrokerRetained"] = true
	result["fullVolumeRetained"] = true
	result["danglingStoppedNetworkReferenceRetained"] = true
	result["networkAfterCount"] = len(afterNetworks)
	result["containerAfterCount"] = len(afterContainers)
	result["mutationSucceeded"] = true
	result["stage"] = "exact_removal_and_preservation_complete"
}
