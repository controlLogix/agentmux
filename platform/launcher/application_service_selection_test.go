//go:build (darwin && arm64) || ((linux || darwin) && agentmux_application_services)

package launcher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/nats-io/nkeys"
)

func TestApplicationServiceSelectionBindsIndependentHostScopeAndExactBytes(t *testing.T) {
	host := HostPolicySelection{Path: "/private/host-policy", OwnerUID: 501, WorkspaceRoots: []string{"/workspace"}}
	scope := protocol.Scope{HubID: "hub", InstanceID: "instance", ProfileID: "profile"}
	header := applicationServiceSelectionHeader{SchemaVersion: protocol.Version, HostPolicy: host.Path, OwnerUID: host.OwnerUID, Workspaces: append([]string(nil), host.WorkspaceRoots...), KernelScope: scope,
		AuthorityID: "authority", OrganizationID: "organization", AuthoritySwitch: map[string]any{"custodyDirectory": "/private/authority-switch", "binding": nil}, Identity: map[string]any{"selected": true}, Definitions: map[string]any{"selected": true}}
	header.Policy = map[string]any{"selected": true}
	encode := func(h applicationServiceSelectionHeader) ([]byte, ApplicationServiceProcessSelection) {
		raw, err := json.Marshal(h)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		return raw, ApplicationServiceProcessSelection{SHA256: "sha256:" + hex.EncodeToString(sum[:])}
	}
	raw, selected := encode(header)
	if bindApplicationServiceSelection(raw, selected, host, scope, nil) != nil {
		t.Fatal("exact independently selected host binding refused")
	}
	for _, change := range []func(*applicationServiceSelectionHeader){
		func(h *applicationServiceSelectionHeader) { h.HostPolicy = "/private/other-policy" },
		func(h *applicationServiceSelectionHeader) { h.OwnerUID++ },
		func(h *applicationServiceSelectionHeader) { h.Workspaces = []string{"/other-workspace"} },
		func(h *applicationServiceSelectionHeader) { h.KernelScope.ProfileID = "other-profile" },
		func(h *applicationServiceSelectionHeader) { h.KernelScope.InstanceID = "other-instance" },
		func(h *applicationServiceSelectionHeader) { h.KernelScope.HubID = "other-hub" },
		func(h *applicationServiceSelectionHeader) { h.Identity = nil },
		func(h *applicationServiceSelectionHeader) { h.Definitions = nil },
	} {
		changed := header
		change(&changed)
		body, pin := encode(changed)
		if bindApplicationServiceSelection(body, pin, host, scope, nil) == nil {
			t.Fatal("matching digest concealed a changed host or scope binding")
		}
	}
	if bindApplicationServiceSelection(append(raw, ' '), selected, host, scope, nil) == nil {
		t.Fatal("changed selection bytes passed the original independent digest")
	}
	for _, stale := range []string{"protectedHostAccount", "hostAccountPublicKey"} {
		var override map[string]any
		json.Unmarshal(raw, &override)
		override[stale] = map[string]any{"kind": "named-password", "account": "HOST"}
		body, _ := json.Marshal(override)
		sum := sha256.Sum256(body)
		pin := selected
		pin.SHA256 = "sha256:" + hex.EncodeToString(sum[:])
		if bindApplicationServiceSelection(body, pin, host, scope, nil) == nil {
			t.Fatal("service selection overrode native HOST admission")
		}
	}
}

func TestIntegrationOperatorSelectionDoesNotRequireLongLivedAuthoritySwitch(t *testing.T) {
	host := HostPolicySelection{Path: "/private/host-policy", OwnerUID: 501, WorkspaceRoots: []string{"/workspace"}}
	scope := protocol.Scope{HubID: "hub", InstanceID: "instance", ProfileID: "profile"}
	header := applicationServiceSelectionHeader{SchemaVersion: protocol.Version, HostPolicy: host.Path, OwnerUID: host.OwnerUID, Workspaces: host.WorkspaceRoots, KernelScope: scope,
		AuthorityID: "authority", OrganizationID: "organization", Identity: map[string]any{"selected": true}, Definitions: map[string]any{"selected": true}}
	raw, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	selected := ApplicationServiceProcessSelection{SHA256: "sha256:" + hex.EncodeToString(sum[:])}
	if bindApplicationServiceSelection(raw, selected, host, scope, nil) == nil {
		t.Fatal("long-lived service accepted a missing authority switch")
	}
	if bindSelectedApplicationService(raw, selected, host, scope, nil, false) != nil {
		t.Fatal("short-lived integration operator required a long-lived authority switch")
	}
}

func TestApplicationServiceSelectionAdmitsOptionalConfigurationForNativeActivation(t *testing.T) {
	host := HostPolicySelection{Path: "/private/host-policy", OwnerUID: 501, WorkspaceRoots: []string{"/workspace"}}
	scope := protocol.Scope{HubID: "hub", InstanceID: "instance", ProfileID: "profile"}
	header := applicationServiceSelectionHeader{SchemaVersion: protocol.Version, HostPolicy: host.Path, OwnerUID: host.OwnerUID, Workspaces: host.WorkspaceRoots, KernelScope: scope, AuthorityID: "authority", OrganizationID: "organization", AuthoritySwitch: map[string]any{"custodyDirectory": "/private/authority-switch", "binding": nil}, Identity: map[string]any{"selected": true}, Definitions: map[string]any{"selected": true}}
	pin := func(raw []byte) ApplicationServiceProcessSelection {
		sum := sha256.Sum256(raw)
		return ApplicationServiceProcessSelection{SHA256: "sha256:" + hex.EncodeToString(sum[:])}
	}
	baseline, _ := json.Marshal(header)
	if bytes.Contains(baseline, []byte(`"configuration"`)) || bindApplicationServiceSelection(baseline, pin(baseline), host, scope, nil) != nil {
		t.Fatal("omitted configuration changed existing service admission")
	}
	// The Python selection owner validates the full existing configuration
	// descriptor before readiness; native admission binds its exact bytes.
	header.Configuration = map[string]any{"selected": true}
	selected, _ := json.Marshal(header)
	if bindApplicationServiceSelection(selected, pin(selected), host, scope, nil) != nil || bindApplicationServiceSelection(selected, pin(baseline), host, scope, nil) == nil {
		t.Fatal("configuration did not require its independently selected digest")
	}
	for _, malformed := range []string{`[]`, `true`, `42`, `"configuration"`} {
		var value map[string]json.RawMessage
		_ = json.Unmarshal(baseline, &value)
		value["configuration"] = json.RawMessage(malformed)
		raw, _ := json.Marshal(value)
		if bindApplicationServiceSelection(raw, pin(raw), host, scope, nil) == nil {
			t.Fatal("malformed configuration header accepted")
		}
	}
}

func TestApplicationServiceSelectionBindsOptionalDomainPolicies(t *testing.T) {
	host := HostPolicySelection{Path: "/private/host-policy", OwnerUID: 501, WorkspaceRoots: []string{"/workspace"}}
	scope := protocol.Scope{HubID: "hub", InstanceID: "instance", ProfileID: "profile"}
	header := applicationServiceSelectionHeader{SchemaVersion: protocol.Version, HostPolicy: host.Path, OwnerUID: host.OwnerUID, Workspaces: host.WorkspaceRoots, KernelScope: scope, AuthorityID: "authority", OrganizationID: "organization", AuthoritySwitch: map[string]any{"custodyDirectory": "/private/authority-switch", "binding": nil}, Identity: map[string]any{"selected": true}, Definitions: map[string]any{"selected": true}}
	pin := func(raw []byte) ApplicationServiceProcessSelection {
		sum := sha256.Sum256(raw)
		return ApplicationServiceProcessSelection{SHA256: "sha256:" + hex.EncodeToString(sum[:])}
	}
	baseline, _ := json.Marshal(header)
	if bytes.Contains(baseline, []byte(`"dashboard"`)) || bytes.Contains(baseline, []byte(`"orchestration"`)) || bindApplicationServiceSelection(baseline, pin(baseline), host, scope, nil) != nil {
		t.Fatal("omitted domain policies changed existing service admission")
	}
	header.Dashboard = map[string]any{"resourceRef": map[string]any{"id": "dashboard-one"}}
	header.Orchestration = map[string]any{"resourceRef": map[string]any{"id": "orchestration-one"}}
	header.Task = map[string]any{"ledger": map[string]any{"entityId": "task-one"}}
	header.Workspace = map[string]any{"resourceRef": map[string]any{"id": "task-one"}}
	header.Artifact = map[string]any{"resourceRef": map[string]any{"id": "task-one"}}
	header.FederationPolicy = map[string]any{"target": map[string]any{"source": map[string]any{}}}
	header.PeerControl = map[string]any{"routes": []any{}}
	header.CoreWorkTransport = map[string]any{"routes": []any{}}
	selected, _ := json.Marshal(header)
	if bindApplicationServiceSelection(selected, pin(selected), host, scope, nil) != nil || bindApplicationServiceSelection(selected, pin(baseline), host, scope, nil) == nil {
		t.Fatal("domain policies did not require their independently selected digest")
	}
	for _, field := range []string{"dashboard", "orchestration", "task", "workspace", "artifact", "federationPolicy", "peerControl", "coreWorkTransport"} {
		for _, malformed := range []string{`[]`, `true`, `42`, `"policy"`} {
			var value map[string]json.RawMessage
			_ = json.Unmarshal(baseline, &value)
			value[field] = json.RawMessage(malformed)
			raw, _ := json.Marshal(value)
			if bindApplicationServiceSelection(raw, pin(raw), host, scope, nil) == nil {
				t.Fatalf("malformed %s header accepted", field)
			}
		}
	}
}

func TestApplicationServiceSelectionBindsOptionalOIDCBrowserConfiguration(t *testing.T) {
	host := HostPolicySelection{Path: "/private/host-policy", OwnerUID: 501, WorkspaceRoots: []string{"/workspace"}}
	scope := protocol.Scope{HubID: "hub", InstanceID: "instance", ProfileID: "profile"}
	header := applicationServiceSelectionHeader{SchemaVersion: protocol.Version, HostPolicy: host.Path, OwnerUID: host.OwnerUID, Workspaces: host.WorkspaceRoots, KernelScope: scope, AuthorityID: "authority", OrganizationID: "organization", AuthoritySwitch: map[string]any{"custodyDirectory": "/private/authority-switch", "binding": nil}, Identity: map[string]any{"selected": true}, Definitions: map[string]any{"selected": true}}
	pin := func(raw []byte) ApplicationServiceProcessSelection {
		sum := sha256.Sum256(raw)
		return ApplicationServiceProcessSelection{SHA256: "sha256:" + hex.EncodeToString(sum[:])}
	}
	baseline, _ := json.Marshal(header)
	if bytes.Contains(baseline, []byte(`"oidcBrowser"`)) || bindApplicationServiceSelection(baseline, pin(baseline), host, scope, nil) != nil {
		t.Fatal("omitted OIDC browser configuration changed existing service admission")
	}
	header.OIDCBrowser = map[string]any{"issuer": "https://identity.example/realms/team", "audience": "agentmux"}
	selected, _ := json.Marshal(header)
	if bindApplicationServiceSelection(selected, pin(selected), host, scope, nil) != nil || bindApplicationServiceSelection(selected, pin(baseline), host, scope, nil) == nil {
		t.Fatal("OIDC browser configuration did not require its independently selected digest")
	}
	for _, malformed := range []string{`[]`, `true`, `42`, `"oidc"`} {
		var value map[string]json.RawMessage
		_ = json.Unmarshal(baseline, &value)
		value["oidcBrowser"] = json.RawMessage(malformed)
		raw, _ := json.Marshal(value)
		if bindApplicationServiceSelection(raw, pin(raw), host, scope, nil) == nil {
			t.Fatal("malformed OIDC browser header accepted")
		}
	}
}

func TestApplicationServiceSelectionKeepsOptionalStorageHeaderClosed(t *testing.T) {
	host := HostPolicySelection{Path: "/private/host-policy", OwnerUID: 501, WorkspaceRoots: []string{"/workspace"}}
	scope := protocol.Scope{HubID: "hub", InstanceID: "instance", ProfileID: "profile"}
	header := applicationServiceSelectionHeader{SchemaVersion: protocol.Version, HostPolicy: host.Path, OwnerUID: host.OwnerUID, Workspaces: host.WorkspaceRoots, KernelScope: scope, AuthorityID: "authority", OrganizationID: "organization", AuthoritySwitch: map[string]any{"custodyDirectory": "/private/authority-switch", "binding": nil}, Identity: map[string]any{"selected": true}, Definitions: map[string]any{"selected": true}}
	pin := func(raw []byte) ApplicationServiceProcessSelection {
		sum := sha256.Sum256(raw)
		return ApplicationServiceProcessSelection{SHA256: "sha256:" + hex.EncodeToString(sum[:])}
	}
	baseline, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(baseline, []byte(`"storage"`)) || bindApplicationServiceSelection(baseline, pin(baseline), host, scope, nil) != nil {
		t.Fatal("omitted storage changed the existing native selection")
	}
	// These are header shapes only. Python separately validates every nested
	// receiver, provider, credential and retained resource before readiness.
	header.Storage = &applicationServiceStorageHeader{Scope: json.RawMessage(`{"organizationId":"organization","projectId":null,"workspaceId":null}`), Receivers: json.RawMessage(`{"storage":{},"outcome":{}}`), PrivateStorage: json.RawMessage(`{"publisher":{},"ledger":{}}`)}
	selected, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	if bindApplicationServiceSelection(selected, pin(selected), host, scope, nil) != nil {
		t.Fatal("declared optional storage header refused")
	}
	if bindApplicationServiceSelection(selected, pin(baseline), host, scope, nil) == nil {
		t.Fatal("storage changed without replacing the exact selected digest")
	}
	// Work can borrow the already selected domain source and participate in its
	// protected policy projection. Native admission still binds the full bytes.
	for _, domain := range []string{"messages", "knowledge", "code", "work"} {
		var value map[string]json.RawMessage
		_ = json.Unmarshal(selected, &value)
		var storage map[string]json.RawMessage
		_ = json.Unmarshal(value["storage"], &storage)
		storage[domain] = json.RawMessage(`{"source":{"database":{"path":"/private/work.db"}},"repository":{"localName":"falcon"},"localPeer":null}`)
		value["storage"], _ = json.Marshal(storage)
		raw, _ := json.Marshal(value)
		if bindApplicationServiceSelection(raw, pin(raw), host, scope, nil) != nil {
			t.Fatalf("selected %s storage header refused", domain)
		}
		if bindApplicationServiceSelection(raw, pin(selected), host, scope, nil) == nil {
			t.Fatalf("selected %s storage bypassed its exact digest", domain)
		}
		for _, malformed := range []string{`[]`, `true`, `42`, `"storage"`} {
			storage[domain] = json.RawMessage(malformed)
			value["storage"], _ = json.Marshal(storage)
			bad, _ := json.Marshal(value)
			if bindApplicationServiceSelection(bad, pin(bad), host, scope, nil) == nil {
				t.Fatalf("malformed %s storage header accepted", domain)
			}
		}
	}
	for _, storage := range []string{`[]`, `"storage"`, `42`, `true`, `{"scope":{},"receivers":{},"privateStorage":{},"ambientCredentials":true}`} {
		var value map[string]json.RawMessage
		if json.Unmarshal(baseline, &value) != nil {
			t.Fatal("header fixture invalid")
		}
		value["storage"] = json.RawMessage(storage)
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if bindApplicationServiceSelection(raw, pin(raw), host, scope, nil) == nil {
			t.Fatal("wrong storage type or undeclared storage field accepted")
		}
	}
	var value map[string]json.RawMessage
	_ = json.Unmarshal(selected, &value)
	value["storageOverride"] = json.RawMessage(`{}`)
	raw, _ := json.Marshal(value)
	if bindApplicationServiceSelection(raw, pin(raw), host, scope, nil) == nil {
		t.Fatal("optional storage opened the outer native selection")
	}
	if bindApplicationServiceSelection(append(selected, bytes.Repeat([]byte(" "), 65536)...), pin(append(selected, bytes.Repeat([]byte(" "), 65536)...)), host, scope, nil) == nil {
		t.Fatal("storage bypassed the existing selection size bound")
	}
}

func TestApplicationServiceIdentityRequiresAccountAndTLSBindingWithSeparateUsers(t *testing.T) {
	_, attestor := applicationHostCompositionSelection(t)
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal("identity service user unavailable")
	}
	defer user.Wipe()
	public, _ := user.PublicKey()
	makeHeader := func() applicationServiceSelectionHeader {
		c := attestor.Connection
		return applicationServiceSelectionHeader{KernelScope: attestor.Signer.KernelScope, AuthorityID: attestor.Signer.AuthorityID, OrganizationID: attestor.Signer.Scope.OrganizationID,
			Identity: map[string]any{"connection": map[string]any{"endpoint": c.Endpoint, "serverName": c.ServerName, "rootsPEM": c.RootsPEM, "leafCertificateSHA256": c.LeafCertificateSHA256, "jetstreamDomain": nil},
				"credentials": map[string]any{"accountPublicKey": attestor.AccountPublicKey, "userPublicKey": public, "replyPrefix": "_INBOX.identity_receiver_0001"}}}
	}
	if bindApplicationServiceIdentity(makeHeader(), attestor) != nil {
		t.Fatal("separate users in the shared application account were refused")
	}
	for _, fault := range []string{"endpoint", "serverName", "rootsPEM", "leafCertificateSHA256", "account", "same-user", "same-inbox", "authority", "organization", "kernel", "missing-connection"} {
		t.Run(fault, func(t *testing.T) {
			h := makeHeader()
			connection := h.Identity["connection"].(map[string]any)
			credentials := h.Identity["credentials"].(map[string]any)
			switch fault {
			case "endpoint":
				connection[fault] = "tls://127.0.0.1:44223"
			case "serverName":
				connection[fault] = "foreign.agentmux.invalid"
			case "rootsPEM":
				connection[fault] = "missing CA"
			case "leafCertificateSHA256":
				connection[fault] = "sha256:" + string(make([]byte, 64))
			case "account":
				other, _ := nkeys.CreateAccount()
				defer other.Wipe()
				credentials["accountPublicKey"], _ = other.PublicKey()
			case "same-user":
				credentials["userPublicKey"] = attestor.UserPublicKey
			case "same-inbox":
				credentials["replyPrefix"] = attestor.Signer.ReplyPrefix
			case "authority":
				h.AuthorityID = "foreign_authority"
			case "organization":
				h.OrganizationID = "foreign_organization"
			case "kernel":
				h.KernelScope.InstanceID = "foreign_instance"
			case "missing-connection":
				delete(h.Identity, "connection")
			}
			if bindApplicationServiceIdentity(h, attestor) == nil {
				t.Fatal("incompatible identity receiver passed connection admission")
			}
		})
	}
}

func TestApplicationServiceProtectedHostDescriptorRequiresCompleteFactory(t *testing.T) {
	selection, _ := installedBridgePolicyFixture(t)
	host, err := LoadEnrolledHostPolicy(selection)
	if err != nil {
		t.Fatal("admitted host fixture unavailable")
	}
	config, _, err := host.Load()
	if err != nil {
		t.Fatal("admitted host configuration unavailable")
	}
	descriptor, err := admitApplicationServiceProtectedHost(config)
	if err != nil || descriptor.Kind != "named-password" || descriptor.Account != "HOST" || descriptor.Broker.Endpoint != config.Kernel.Endpoint || descriptor.Broker.ServerName != config.Health.ServerName || descriptor.Broker.ConfigSHA256 != "sha256:"+hex.EncodeToString(config.BrokerConfigDigest[:]) {
		t.Fatal("actual HOST account description was not derived from admitted configuration")
	}
	packet := applicationServiceStart{ProtectedHostAccount: descriptor}
	encoded, _ := json.Marshal(packet)
	if bytes.Contains(encoded, []byte(config.OwnerBridge.ServerPassword)) || bytes.Contains(encoded, []byte(config.OwnerBridge.ClientPassword)) || bytes.Contains(encoded, []byte("hostAccountPublicKey")) {
		t.Fatal("private start descriptor contains a password or stale HOST key")
	}
	for _, fault := range []string{"missing-bridge", "scope", "extra-user", "nkey", "imports", "jetstream", "digest"} {
		t.Run(fault, func(t *testing.T) {
			changed := config
			if fault == "missing-bridge" {
				changed.OwnerBridge = nil
			} else if fault == "scope" {
				bridge := *config.OwnerBridge
				bridge.Scope.ProfileID = "foreign_profile"
				changed.OwnerBridge = &bridge
			} else if fault == "digest" {
				changed.BrokerConfigDigest[0] ^= 1
			} else {
				raw, err := bootstrapComposeBrokerBytes(config)
				if err != nil {
					t.Fatal("original inline broker unavailable")
				}
				defer clear(raw)
				var broker map[string]any
				if json.Unmarshal(raw, &broker) != nil {
					t.Fatal("broker fixture decode failed")
				}
				account := broker["accounts"].(map[string]any)["HOST"].(map[string]any)
				switch fault {
				case "extra-user":
					account["users"] = append(account["users"].([]any), map[string]any{"user": "injected", "password": strings.Repeat("z", 48)})
				case "nkey":
					account["nkey"] = strings.Repeat("A", 56)
				case "imports":
					account["imports"] = []any{map[string]any{"stream": map[string]any{"account": "APPLICATION", "subject": ">"}}}
				case "jetstream":
					account["jetstream"] = "enabled"
				}
				altered, _ := json.Marshal(broker)
				defer clear(altered)
				var document composeDocument
				if json.Unmarshal(config.Compose, &document) != nil {
					t.Fatal("compose fixture decode failed")
				}
				entry := document.Configs["broker_config"]
				entry.Content = strings.ReplaceAll(string(altered), "$", "$$")
				document.Configs["broker_config"] = entry
				changed.Compose, _ = json.Marshal(document)
				changed.BrokerConfigDigest = sha256.Sum256(altered)
			}
			if got, err := admitApplicationServiceProtectedHost(changed); err == nil || got != (applicationProtectedHostAccount{}) {
				t.Fatal("altered HOST boundary produced an admitted descriptor")
			}
		})
	}
}

func TestApplicationServiceStartEntriesRefuseMissingHostAdmissionAndStaleKey(t *testing.T) {
	selection, _ := installedHostPolicyFixture(t)
	host, err := LoadEnrolledHostPolicy(selection)
	if err != nil {
		t.Fatal("unbridged host fixture unavailable")
	}
	selected := ApplicationServiceProcessSelection{InstallationID: strings.Repeat("c", 64), Path: filepath.Join(filepath.Dir(selection.Path), "services.json"), SHA256: "sha256:" + strings.Repeat("d", 64)}
	owner, err := host.StartApplicationServices(context.Background(), selected, make(chan struct{}))
	var failure *serviceProcessFailure
	if owner != nil || !errors.As(err, &failure) || failure.code != "protected_host_unadmitted" {
		t.Fatal("direct service start bypassed actual HOST admission")
	}
	composedHost, attestor := applicationHostCompositionSelection(t)
	prepared, err := prepareApplicationAttestorHost(context.Background(), composedHost, attestor)
	if err != nil {
		t.Fatal("valid attestor control failed before the negative boundary")
	}
	if prepared.close() != nil {
		t.Fatal("valid attestor control did not close")
	}
	unbridged := *composedHost
	unbridged.record.OwnerBridge = nil
	err = unbridged.RunWithApplicationServices(context.Background(), "attempt_"+strings.Repeat("a", 32), attestor, selected)
	var applicationFailure *applicationEvidenceFailure
	if !errors.As(err, &applicationFailure) || applicationFailure.code != "host_admission_failed" {
		t.Fatal("composed service start did not refuse the missing HOST admission")
	}
	selected.HostAccountPublicKey = strings.Repeat("A", 56)
	owner, err = host.StartApplicationServices(context.Background(), selected, make(chan struct{}))
	if owner != nil || !errors.As(err, &failure) || failure.code != "selection_invalid" {
		t.Fatal("direct service start accepted a stale HOST key")
	}
	err = composedHost.RunWithApplicationServices(context.Background(), "attempt_"+strings.Repeat("a", 32), attestor, selected)
	if !errors.As(err, &failure) || failure.code != "selection_invalid" {
		t.Fatal("composed service start did not refuse the stale HOST key")
	}
}
