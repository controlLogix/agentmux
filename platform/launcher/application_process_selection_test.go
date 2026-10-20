//go:build (darwin && arm64) || ((linux || darwin) && agentmux_application_services)

package launcher

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

func TestApplicationProcessSelectionBindsExactPinAndKeepsHeaderClosed(t *testing.T) {
	host := HostPolicySelection{Path: "/private/host-policy", OwnerUID: 501, WorkspaceRoots: []string{"/workspace"}}
	scope := protocol.Scope{HubID: "hub", InstanceID: "instance", ProfileID: "profile"}
	header := applicationServiceSelectionHeader{SchemaVersion: protocol.Version, HostPolicy: host.Path, OwnerUID: host.OwnerUID,
		Workspaces: host.WorkspaceRoots, KernelScope: scope, AuthorityID: "authority", OrganizationID: "organization",
		AuthoritySwitch: map[string]any{"custodyDirectory": "/private/authority-switch", "binding": nil},
		Identity:        map[string]any{"selected": true}, Definitions: map[string]any{"selected": true}}
	encode := func(value any) []byte {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	pin := func(raw []byte) ApplicationServiceProcessSelection {
		sum := sha256.Sum256(raw)
		return ApplicationServiceProcessSelection{SHA256: "sha256:" + hex.EncodeToString(sum[:])}
	}
	baseline := encode(header)
	if bytes.Contains(baseline, []byte(`"process"`)) || bindApplicationServiceSelection(baseline, pin(baseline), host, scope, nil) != nil {
		t.Fatal("omitted Process changed existing service admission")
	}
	// Native admission binds the selected bytes. Python validates the complete
	// nested Process schema before opening providers or declaring readiness.
	header.Process = map[string]any{
		"executorRef":       map[string]any{"id": "executor", "ownerHubId": "hub", "revision": float64(2)},
		"run":               map[string]any{"namespace": "process_one", "stream": "AMX_PROCESS_PROCESS_ONE", "inventoryRoot": "/private/process"},
		"pluginIdentityRef": map[string]any{"id": "plugin", "ownerHubId": "hub", "revision": float64(1)},
	}
	raw := encode(header)
	if bindApplicationServiceSelection(raw, pin(raw), host, scope, nil) != nil {
		t.Fatal("declared Process header refused")
	}
	if bindApplicationServiceSelection(raw, pin(baseline), host, scope, nil) == nil {
		t.Fatal("Process bypassed the independently selected byte digest")
	}
	var decoded applicationServiceSelectionHeader
	if protocol.DecodeClosedJSON(raw, &decoded, 65536) != nil || !reflect.DeepEqual(decoded.Process, header.Process) {
		t.Fatal("Process pins changed during native header decoding")
	}
	changed := decoded
	changed.Process = map[string]any{"executorRef": map[string]any{"id": "other_executor", "ownerHubId": "hub", "revision": 2}}
	if bindApplicationServiceSelection(encode(changed), pin(raw), host, scope, nil) == nil {
		t.Fatal("changed Process pins passed the original independent digest")
	}
	for _, malformed := range []string{`[]`, `true`, `42`, `"process"`} {
		var value map[string]json.RawMessage
		if json.Unmarshal(raw, &value) != nil {
			t.Fatal("fixture selection invalid")
		}
		value["process"] = json.RawMessage(malformed)
		bad := encode(value)
		if bindApplicationServiceSelection(bad, pin(bad), host, scope, nil) == nil {
			t.Fatalf("malformed Process header accepted: %s", malformed)
		}
	}
	var value map[string]json.RawMessage
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("fixture selection invalid")
	}
	value["processOverride"] = json.RawMessage(`{}`)
	unknown := encode(value)
	if bindApplicationServiceSelection(unknown, pin(unknown), host, scope, nil) == nil {
		t.Fatal("Process opened the outer selection to unknown fields")
	}
}
