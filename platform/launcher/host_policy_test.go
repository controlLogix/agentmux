//go:build linux || darwin

package launcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func installedHostPolicyFixture(t *testing.T) (HostPolicySelection, hostPolicyRecord) {
	t.Helper()
	fixture := hostConfigFixture(t)
	e := OwnerEnrollment{SchemaVersion: "1.0.0", OwnerUID: fixture.profile.OwnerUID, PrincipalID: "fixture_owner", Identity: OwnerIdentityReference{ID: "fixture_owner_ref", OwnerHubID: fixture.metadata.HubID, Revision: 1}, Scope: OwnerScope{OrganizationID: "fixture_org"}, InstanceID: fixture.profile.InstanceID, ProfileID: fixture.profile.ProfileID, ReleaseFingerprint: fixture.profile.ReleaseFingerprint}
	writeOwnerFixture(t, fixture.profile.ProfileDirectory, mustStatusJSON(e))
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("private host policy fixture root unavailable")
	}
	if os.Chmod(root, 0700) != nil {
		t.Fatal("private host policy root mode unavailable")
	}
	installed := filepath.Join(root, "agentmux-runtime")
	content := []byte("contained source fixture; execution is tested separately")
	if os.WriteFile(installed, content, 0700) != nil {
		t.Fatal("private installed source fixture write failed")
	}
	sum := sha256.Sum256(content)
	r := hostPolicyRecord{SchemaVersion: "1.0.0", OwnerUID: fixture.profile.OwnerUID, ProfileDirectory: fixture.profile.ProfileDirectory, ProfileID: fixture.profile.ProfileID, InstanceID: fixture.profile.InstanceID, Owner: e, ServerName: fixture.metadata.ServerName, Domain: fixture.metadata.Domain, PublicEndpoint: fixture.profile.NATSEndpoint, PublicContextName: fixture.profile.Docker.Context, RuntimeExecutable: hostPolicyExecutable{Path: installed, Digest: "sha256:" + hex.EncodeToString(sum[:])}, Limits: hostPolicyLimits{StartupMilliseconds: 10000, ProbeMilliseconds: 1000, RoleStartMilliseconds: 2000, StopGraceMilliseconds: 1000, ReapMilliseconds: 1000}}
	p := fixture.policy.ExternalRelease
	r.Release = hostPolicyRelease{PackageDirectory: p.PackageDirectory, PublicKeyHex: hex.EncodeToString(p.PublicKey), ReleaseManifestDigest: p.ReleaseManifestDigest, ReleaseAuthority: p.ReleaseAuthority, ReleaseVersion: p.ReleaseVersion, KernelAPIMajor: p.KernelAPIMajor}
	s := HostPolicySelection{Path: filepath.Join(root, "host-policy.json"), OwnerUID: fixture.profile.OwnerUID, WorkspaceRoots: append([]string(nil), fixture.policy.Profile.WorkspaceRoots...)}
	writeInstalledHostPolicy(t, s.Path, r)
	return s, r
}

func installedBridgePolicyFixture(t *testing.T) (HostPolicySelection, hostPolicyRecord) {
	t.Helper()
	s, r := installedHostPolicyFixture(t)
	h, err := LoadEnrolledHostPolicy(s)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := h.Load()
	if err != nil {
		t.Fatal(err)
	}
	settings := deployment.OwnerBridgeSettings{Scope: c.Kernel.Scope, ServerPassword: strings.Repeat("a", 48), ClientPassword: strings.Repeat("b", 48)}
	r.OwnerBridge = &OwnerBridgeCredentialRefs{Server: "owner-host.json", Client: "owner-client.json"}
	var document composeDocument
	if json.Unmarshal(c.Compose, &document) != nil {
		t.Fatal("fixture compose unavailable")
	}
	entry, ok := document.Configs["broker_config"]
	if !ok {
		t.Fatal("secure fixture broker configuration unavailable")
	}
	broker := []byte(strings.ReplaceAll(entry.Content, "$$", "$"))
	credentials, err := bootstrapBrokerCredentials(broker, c)
	if err != nil {
		t.Fatal(err)
	}
	// The existing fixture enrolls this explicit small disposable local store.
	raw, err := deployment.BuildSecureLocalConfigWithOwnerBridge(deployment.StorageProfile{HubID: c.Kernel.Scope.HubID, ServerName: r.ServerName, Domain: r.Domain, StoreDirectory: "/data/store", MaxMemoryBytes: 1024 * 1024, MaxFileBytes: 4 * 1024 * 1024, Listener: communication.Listener{Mode: communication.ContainerInternal, Port: 4222}}, credentials, c.Health.Password, settings, c.LocalTLS)
	if err != nil {
		t.Fatal(err)
	}
	p, err := LoadProfile(h.policy.Profile)
	if err != nil {
		t.Fatal(err)
	}
	declaration := p.Declaration()
	compose, err := deployment.RenderSecureCompose(deployment.ComposeSpec{Project: declaration.ComposeProject, InstanceID: r.InstanceID, ProfileID: r.ProfileID, ReleaseDigest: r.Release.ReleaseManifestDigest, Image: c.BrokerImage, HostPort: 4222, BrokerConfig: raw}, c.LocalTLS)
	if err != nil {
		t.Fatal(err)
	}
	declaration.ConfigDigest = releaseDigest(compose)
	releaseTestWrite(t, r.ProfileDirectory, "profile.json", mustStatusJSON(declaration))
	releaseTestWrite(t, r.ProfileDirectory, "broker.json", raw)
	for _, item := range []struct{ name, role, password string }{{r.OwnerBridge.Server, deployment.OwnerBridgeServerUser, settings.ServerPassword}, {r.OwnerBridge.Client, deployment.OwnerBridgeClientUser, settings.ClientPassword}} {
		releaseTestWrite(t, r.ProfileDirectory, item.name, mustStatusJSON(OwnerBridgeCredential{SchemaVersion: protocol.Version, Role: item.role, Scope: settings.Scope, Owner: r.Owner, Password: item.password}))
	}
	writeInstalledHostPolicy(t, s.Path, r)
	return s, r
}

func TestInstalledHostPolicyBridgeBindingsBeforeFactoryLoad(t *testing.T) {
	s, r := installedBridgePolicyFixture(t)
	h, err := LoadEnrolledHostPolicy(s)
	if err != nil {
		t.Fatal("valid enrolled bridge rejected:", err)
	}
	if _, err := h.BridgeClient(); err != nil {
		t.Fatal("bound client unavailable:", err)
	}
	if _, _, err := h.BridgeServer(); err != nil {
		t.Fatal("bound server unavailable:", err)
	}
	for _, change := range []string{"password", "role", "scope", "owner", "nested-missing", "nested-alias", "public-file", "null-scope"} {
		t.Run(change, func(t *testing.T) {
			s, r = installedBridgePolicyFixture(t)
			path := filepath.Join(r.ProfileDirectory, r.OwnerBridge.Client)
			raw, _ := os.ReadFile(path)
			text := string(raw)
			switch change {
			case "password":
				text = strings.Replace(text, strings.Repeat("b", 48), strings.Repeat("c", 48), 1)
			case "role":
				text = strings.Replace(text, `"role":"runtime-client"`, `"role":"runtime-host"`, 1)
			case "scope":
				text = strings.Replace(text, `"hubId":"fixture_hub"`, `"hubId":"foreign_hub"`, 1)
			case "owner":
				text = strings.Replace(text, `"principalId":"fixture_owner"`, `"principalId":"foreign_owner"`, 1)
			case "nested-missing":
				text = strings.Replace(text, `,"workspaceId":null`, "", 1)
			case "nested-alias":
				text = strings.Replace(text, `"organizationId":`, `"OrganizationId":`, 1)
			case "null-scope":
				var object map[string]json.RawMessage
				json.Unmarshal(raw, &object)
				object["scope"] = json.RawMessage("null")
				encoded, _ := json.Marshal(object)
				text = string(encoded)
			case "public-file":
				os.Chmod(path, 0644)
			}
			if change != "public-file" {
				os.WriteFile(path, []byte(text), 0600)
			}
			if loaded, err := LoadEnrolledHostPolicy(s); err == nil || loaded != nil {
				t.Fatal("invalid private bridge declaration accepted")
			}
		})
	}
}
func writeInstalledHostPolicy(t *testing.T, path string, record hostPolicyRecord) {
	t.Helper()
	raw, e := json.Marshal(record)
	if e != nil || os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("private host policy fixture write failed")
	}
}

func TestInstalledHostPolicyNullableOwnerAndBoundFiles(t *testing.T) {
	selection, record := installedHostPolicyFixture(t)
	h, e := LoadEnrolledHostPolicy(selection)
	if e != nil {
		t.Fatal("valid private host policy with nullable owner scope rejected:", e)
	}
	config, owner, e := h.Load()
	if e != nil || owner == nil || config.Kernel.Scope.ProfileID != record.ProfileID || config.Kernel.Scope.InstanceID != record.InstanceID || config.ReleaseTrust.ReleaseManifestDigest != record.Release.ReleaseManifestDigest {
		t.Fatal("external host enrollment bindings lost")
	}
	selection.WorkspaceRoots[0] = "/tampered-caller-copy"
	if h.Invocation().WorkspaceRoots[0] == selection.WorkspaceRoots[0] {
		t.Fatal("policy retained mutable caller roots")
	}
	invocation, e := h.BeginEnsure()
	if e != nil || !kernelStatusID.MatchString(invocation.id) {
		t.Fatal("actual ensure invocation not identified")
	}
	if _, e := invocation.Observe(nil); e == nil {
		t.Fatal("nil observation context accepted")
	}
	if _, e := h.ObserveStatus(nil); e == nil {
		t.Fatal("nil status context accepted")
	}
	if _, e := h.PrepareHost(context.Background()); e == nil {
		t.Fatal("contained non-ELF fixture became an installed executable")
	}
}

func TestInstalledHostPolicyRejectsPrivateBoundaryAndDeclarations(t *testing.T) {
	for _, mode := range []string{"writable-ancestor", "public-file", "symlink", "hardlink", "inside-workspace", "owner", "profile", "instance", "release-key", "endpoint", "context", "deadline", "unknown-field", "duplicate-field", "nested-alias", "missing-field", "oversize", "invalid-utf8", "surrogate"} {
		t.Run(mode, func(t *testing.T) {
			s, r := installedHostPolicyFixture(t)
			switch mode {
			case "writable-ancestor":
				ancestor := filepath.Join(filepath.Dir(s.Path), "unsafe")
				if os.Mkdir(ancestor, 0700) != nil || os.Chmod(ancestor, 0777) != nil {
					t.Fatal("unsafe ancestor fixture failed")
				}
				child := filepath.Join(ancestor, "private")
				if os.Mkdir(child, 0700) != nil {
					t.Fatal("private leaf fixture failed")
				}
				s.Path = filepath.Join(child, "host-policy.json")
				writeInstalledHostPolicy(t, s.Path, r)
			case "public-file":
				os.Chmod(s.Path, 0644)
			case "symlink":
				target := s.Path + "-target"
				os.Rename(s.Path, target)
				os.Symlink(target, s.Path)
			case "hardlink":
				os.Link(s.Path, s.Path+"-alias")
			case "inside-workspace":
				s.WorkspaceRoots = append(s.WorkspaceRoots, filepath.Dir(s.Path))
			case "owner":
				s.OwnerUID++
			case "profile":
				r.ProfileID = "profile_" + strings.Repeat("e", 32)
				writeInstalledHostPolicy(t, s.Path, r)
			case "instance":
				r.InstanceID = "instance_" + strings.Repeat("e", 32)
				writeInstalledHostPolicy(t, s.Path, r)
			case "release-key":
				r.Release.PublicKeyHex = strings.Repeat("e", 64)
				writeInstalledHostPolicy(t, s.Path, r)
			case "endpoint":
				r.PublicEndpoint = "nats://127.0.0.1:65535"
				writeInstalledHostPolicy(t, s.Path, r)
			case "context":
				r.PublicContextName = "foreign-context"
				writeInstalledHostPolicy(t, s.Path, r)
			case "deadline":
				r.Limits.StartupMilliseconds = 60001
				writeInstalledHostPolicy(t, s.Path, r)
			default:
				raw, _ := os.ReadFile(s.Path)
				text := string(raw)
				switch mode {
				case "unknown-field":
					text = strings.Replace(text, `"schemaVersion":`, `"unexpected":true,"schemaVersion":`, 1)
				case "duplicate-field":
					text = strings.Replace(text, `"schemaVersion":`, `"schemaVersion":"1.0.0","schemaVersion":`, 1)
				case "nested-alias":
					text = strings.Replace(text, `"organizationId":`, `"OrganizationId":`, 1)
				case "missing-field":
					text = strings.Replace(text, `"workspaceId":null,`, "", 1)
					text = strings.Replace(text, `,"workspaceId":null`, "", 1)
				case "oversize":
					text = strings.Repeat(" ", 65537)
				case "invalid-utf8":
					text = string([]byte{0xff})
				case "surrogate":
					text = strings.Replace(text, `"fixture_org"`, `"\ud800"`, 1)
				}
				os.WriteFile(s.Path, []byte(text), 0600)
			}
			if h, e := LoadEnrolledHostPolicy(s); e == nil || h != nil {
				t.Fatal("untrusted host policy accepted")
			}
		})
	}
}
