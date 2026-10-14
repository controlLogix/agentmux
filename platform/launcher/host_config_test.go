//go:build linux || darwin

package launcher

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/assembly"
	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

type hostTestFixture struct {
	policy      HostPolicy
	profile     Profile
	metadata    hostRuntimeMetadata
	broker      []byte
	credentials communication.Credentials
	health      string
	material    *deployment.LocalTLSMaterial
}

func TestHostPrivateReadRejectsSameSizeRewriteDuringOpen(t *testing.T) {
	for _, restore := range []bool{false, true} {
		t.Run(map[bool]string{false: "rewrite", true: "restore-mtime"}[restore], func(t *testing.T) {
			policy, _ := profileFixture(t)
			path := filepath.Join(policy.Directory, "read-control")
			if os.WriteFile(path, []byte("original"), 0600) != nil {
				t.Fatal("read control fixture unavailable")
			}
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal("read control metadata unavailable")
			}
			root, err := openProfileDirectory(policy)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			injected := false
			open := func(root *os.Root, name string) (*os.File, error) {
				file, err := assembly.OpenMember(root, name)
				if err != nil {
					return nil, err
				}
				time.Sleep(time.Millisecond)
				if os.WriteFile(path, []byte("rewritten"[:8]), 0600) != nil {
					file.Close()
					t.Fatal("same-size rewrite control failed")
				}
				if restore && os.Chtimes(path, before.ModTime(), before.ModTime()) != nil {
					file.Close()
					t.Fatal("mtime restore control failed")
				}
				injected = true
				return file, nil
			}
			raw, err := hostPrivateReadWithOpen(root, "read-control", policy.OwnerUID, 64, open)
			if !injected {
				t.Fatal("same-size rewrite control did not execute")
			}
			if err == nil || raw != nil {
				t.Fatal("changed private contents were accepted")
			}
		})
	}
}

func hostConfigFixture(t *testing.T) *hostTestFixture {
	t.Helper()
	release := signedReleaseFixture(t)
	profilePolicy, profile := profileFixture(t)
	profilePolicy.InstalledReleaseFingerprint = release.policy.ReleaseManifestDigest
	profile.ReleaseFingerprint = release.policy.ReleaseManifestDigest
	profile.Docker.ComposeVersion = "5.5.1"
	profile.NATSEndpoint = "tls://127.0.0.1:4222"
	material, err := deployment.EnrollLocalTLS(context.Background(), profile.ProfileID)
	if err != nil {
		t.Fatal("host fixture TLS enrollment failed")
	}
	scope := protocol.Scope{HubID: "fixture_hub", InstanceID: profile.InstanceID, ProfileID: profile.ProfileID, AssemblyDigest: release.authorization.AssemblyDigest, ReleaseManifestDigest: release.policy.ReleaseManifestDigest, ReleaseVersion: release.policy.ReleaseVersion}
	record := protocol.ServerTrustRecord{SchemaVersion: protocol.Version, Endpoint: profile.NATSEndpoint, ServerName: material.ServerName(), RootsPEM: string(material.RootsPEM()), LeafCertificateSHA256: material.LeafCertificateSHA256(), Scope: scope}
	trustRaw, err := json.Marshal(record)
	if err != nil {
		t.Fatal("host fixture server trust encoding failed")
	}
	profile.ServerTrustRef = localServerTrustFile
	profile.ServerTrustDigest = releaseDigest(trustRaw)
	releaseTestWrite(t, profile.ProfileDirectory, localServerTrustFile, trustRaw)
	releaseTestWrite(t, profile.ProfileDirectory, localServerCertificateFile, material.ServerCertificatePEM())
	releaseTestWrite(t, profile.ProfileDirectory, localServerKeyFile, material.ServerKeyPEM())
	metadata := hostRuntimeMetadata{"1.0.0", "fixture_hub", "fixture_server", "fixture_domain", "/data/store", 1024 * 1024, 4 * 1024 * 1024}
	random := func() string {
		var value [24]byte
		if _, err := rand.Read(value[:]); err != nil {
			t.Fatal("fixture secret unavailable")
		}
		return hex.EncodeToString(value[:])
	}
	credentials := communication.Credentials{}
	roles := protocol.Roles()
	for _, user := range append([]string{communication.Administrator, communication.OrdinaryPlugin}, roles[:]...) {
		credentials[user] = random()
	}
	health := random()
	broker, err := deployment.BuildSecureLocalConfig(deployment.StorageProfile{HubID: metadata.HubID, ServerName: metadata.ServerName,
		Domain: metadata.Domain, StoreDirectory: metadata.StoreDirectory, MaxMemoryBytes: metadata.MaxMemoryBytes,
		MaxFileBytes: metadata.MaxFileBytes, Listener: communication.Listener{Mode: communication.ContainerInternal, Port: 4222}}, credentials, health, material)
	if err != nil {
		t.Fatal(err)
	}
	compose, err := deployment.RenderSecureCompose(deployment.ComposeSpec{Project: profile.ComposeProject, InstanceID: profile.InstanceID,
		ProfileID: profile.ProfileID, ReleaseDigest: profile.ReleaseFingerprint, Image: release.manifest.Broker.Image, HostPort: 4222, BrokerConfig: broker}, material)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(compose)
	profile.ConfigDigest = "sha256:" + hex.EncodeToString(sum[:])
	if err := EnrollProfile(profilePolicy, profile); err != nil {
		t.Fatal(err)
	}
	policy := HostPolicy{Profile: profilePolicy, ExternalRelease: release.policy,
		Deadlines:      protected.Deadlines{StartTimeout: 2 * time.Second, StopGrace: time.Second, ReapTimeout: time.Second},
		StartupTimeout: 10 * time.Second, ProbeTimeout: time.Second}
	runtimeRaw, _ := json.Marshal(metadata)
	releaseTestWrite(t, profile.ProfileDirectory, "runtime.json", runtimeRaw)
	releaseTestWrite(t, profile.ProfileDirectory, "broker.json", broker)
	for _, role := range protocol.Roles() {
		raw, _ := json.Marshal(protocol.Credentials{SchemaVersion: protocol.Version, Role: role, Username: role, Password: credentials[role],
			NATSURL: profile.NATSEndpoint, Scope: scope})
		releaseTestWrite(t, profile.ProfileDirectory, role+".json", raw)
	}
	return &hostTestFixture{policy, profile, metadata, broker, credentials, health, material}
}

func hostConfigRefused(t *testing.T, f *hostTestFixture) {
	t.Helper()
	config, err := LoadBootstrapConfig(f.policy)
	if err == nil || !reflect.DeepEqual(config, BootstrapConfig{}) {
		t.Fatal("invalid private host configuration accepted or partially exposed")
	}
	for _, private := range []string{f.profile.ProfileDirectory, f.health, f.credentials["boot"], f.profile.NATSEndpoint} {
		if strings.Contains(err.Error(), private) {
			t.Fatal("host loader error exposed private input")
		}
	}
	if !strings.HasPrefix(err.Error(), "host_config_") {
		t.Fatal("unsafe underlying loader error returned")
	}
}

func TestHostConfigActualSignedFilesAreLoadedWithoutSideEffects(t *testing.T) {
	f := hostConfigFixture(t)
	before := map[string]string{}
	entries, err := os.ReadDir(f.profile.ProfileDirectory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		raw, _ := os.ReadFile(filepath.Join(f.profile.ProfileDirectory, entry.Name()))
		before[entry.Name()] = releaseDigest(raw)
	}
	t.Setenv("DOCKER_CONTEXT", "not-the-enrolled-context")
	config, err := LoadBootstrapConfig(f.policy)
	if err != nil {
		t.Fatal(err)
	}
	if config.ReleaseTrust.ReleaseManifestDigest != f.profile.ReleaseFingerprint || config.Kernel.Scope.ProfileID != f.profile.ProfileID ||
		config.Health.Password != f.health || config.Kernel.Password != f.credentials[communication.OrdinaryPlugin] || config.BrokerConfigDigest != sha256.Sum256(f.broker) ||
		config.Deadlines != f.policy.Deadlines || config.StartupTimeout != f.policy.StartupTimeout || config.Health.Timeout != f.policy.ProbeTimeout {
		t.Fatal("host configuration lost enrolled release, credential or deadline bindings")
	}
	for index, role := range protocol.Roles() {
		option := config.Roles[index]
		if option.ID != role || len(option.Args) != 0 || option.LifetimeLease != nil || len(option.Env) != 5 ||
			option.Env["AGENTMUX_NATS_CREDS_FILE"] != filepath.Join(f.profile.ProfileDirectory, role+".json") || option.Env["AGENTMUX_NATS_SERVER_TRUST_FILE"] != filepath.Join(f.profile.ProfileDirectory, localServerTrustFile) {
			t.Fatal("untrusted role arguments or lease introduced")
		}
	}
	after, _ := os.ReadDir(f.profile.ProfileDirectory)
	if len(after) != len(entries) {
		t.Fatal("loader created profile state or enrollment files")
	}
	for name, expected := range before {
		raw, _ := os.ReadFile(filepath.Join(f.profile.ProfileDirectory, name))
		if releaseDigest(raw) != expected {
			t.Fatal("loader modified private user files")
		}
	}
}

func TestHostConfigTLSAuthorityAndRetainedPolicy(t *testing.T) {
	f := hostConfigFixture(t)
	c, err := LoadBootstrapConfig(f.policy)
	if err != nil {
		t.Fatal("enrolled TLS host configuration rejected")
	}
	if c.Kernel.TLS == nil || c.Health.TLS == nil || c.LocalTLS == nil || c.admissionPolicy == nil || c.Kernel.authority == nil || c.Kernel.TLS != c.Health.TLS {
		t.Fatal("installed configuration omitted authenticated broker authority")
	}
	if c.Kernel.TLS.Policy().Endpoint != f.profile.NATSEndpoint || c.Kernel.TLS.Policy().LeafCertificateSHA256 != f.material.LeafCertificateSHA256() {
		t.Fatal("installed TLS identity lost profile binding")
	}
	if c.Kernel.authority.config.Kernel.authority != nil {
		t.Fatal("private broker binding recursively retained itself")
	}
	key := append([]byte(nil), f.policy.ExternalRelease.PublicKey...)
	workspace := f.policy.Profile.WorkspaceRoots[0]
	f.policy.ExternalRelease.PublicKey[0] ^= 0xff
	f.policy.Profile.WorkspaceRoots[0] = "/changed-caller-root"
	if string(c.admissionPolicy.ExternalRelease.PublicKey) != string(key) || c.admissionPolicy.Profile.WorkspaceRoots[0] != workspace || c.ProfilePolicy.WorkspaceRoots[0] != workspace {
		t.Fatal("caller mutation changed retained host admission policy")
	}
}

func TestHostConfigRejectsMissingTrustWithoutEnrollment(t *testing.T) {
	for _, kind := range []string{"reference", "digest", "artifact", "certificate", "key", "plaintext"} {
		t.Run(kind, func(t *testing.T) {
			f := hostConfigFixture(t)
			switch kind {
			case "reference":
				f.profile.ServerTrustRef = ""
			case "digest":
				f.profile.ServerTrustDigest = ""
			case "artifact":
				os.Remove(filepath.Join(f.profile.ProfileDirectory, localServerTrustFile))
			case "certificate":
				os.Remove(filepath.Join(f.profile.ProfileDirectory, localServerCertificateFile))
			case "key":
				os.Remove(filepath.Join(f.profile.ProfileDirectory, localServerKeyFile))
			case "plaintext":
				f.profile.ServerTrustRef = ""
				f.profile.ServerTrustDigest = ""
				f.profile.NATSEndpoint = "nats://127.0.0.1:4222"
			}
			releaseTestWrite(t, f.profile.ProfileDirectory, "profile.json", mustStatusJSON(f.profile))
			entries, _ := os.ReadDir(f.profile.ProfileDirectory)
			hostConfigRefused(t, f)
			after, _ := os.ReadDir(f.profile.ProfileDirectory)
			if len(after) != len(entries) {
				t.Fatal("failed trust load enrolled or regenerated private files")
			}
		})
	}
}

func TestHostConfigPolicyAndEnrolledDigestRefusals(t *testing.T) {
	for _, kind := range []string{"release-policy", "startup", "probe", "start", "grace", "reap", "config-digest", "compose-version", "remote", "ipv6", "plaintext"} {
		t.Run(kind, func(t *testing.T) {
			f := hostConfigFixture(t)
			switch kind {
			case "release-policy":
				f.policy.ExternalRelease.ReleaseManifestDigest = "sha256:" + strings.Repeat("a", 64)
			case "startup":
				f.policy.StartupTimeout = 61 * time.Second
			case "probe":
				f.policy.ProbeTimeout = 6 * time.Second
			case "start":
				f.policy.Deadlines.StartTimeout = 31 * time.Second
			case "grace":
				f.policy.Deadlines.StopGrace = 11 * time.Second
			case "reap":
				f.policy.Deadlines.ReapTimeout = 11 * time.Second
			default:
				switch kind {
				case "config-digest":
					f.profile.ConfigDigest = "sha256:" + strings.Repeat("a", 64)
				case "compose-version":
					f.profile.Docker.ComposeVersion = "5.5.2"
				case "remote":
					f.profile.Mode = "remote"
					f.profile.Docker = nil
					f.profile.ComposeProject = ""
					f.profile.NATSEndpoint = "tls://127.0.0.1:4222"
				case "ipv6":
					f.profile.NATSEndpoint = "tls://[::1]:4222"
				case "plaintext":
					f.profile.NATSEndpoint = "nats://127.0.0.1:4222"
					f.profile.ServerTrustRef = ""
					f.profile.ServerTrustDigest = ""
				}
				raw, _ := json.Marshal(f.profile)
				releaseTestWrite(t, f.profile.ProfileDirectory, "profile.json", raw)
			}
			hostConfigRefused(t, f)
		})
	}
}

func TestHostConfigRuntimeMetadataCannotSupplyAuthorityOrDeadlines(t *testing.T) {
	for _, kind := range []string{"authority", "deadline", "duplicate", "null", "missing", "trailing", "storage", "memory", "mismatch"} {
		t.Run(kind, func(t *testing.T) {
			f := hostConfigFixture(t)
			raw, _ := json.Marshal(f.metadata)
			switch kind {
			case "authority":
				raw = append([]byte(`{"publicKey":"self-trust-is-refused",`), raw[1:]...)
			case "deadline":
				raw = append([]byte(`{"startupTimeout":999999,`), raw[1:]...)
			case "duplicate":
				raw = append([]byte(`{"hubId":"fixture_hub",`), raw[1:]...)
			case "null":
				raw = []byte(`null`)
			case "missing":
				raw = []byte(`{"schemaVersion":"1.0.0"}`)
			case "trailing":
				raw = append(raw, []byte(`{}`)...)
			case "storage":
				f.metadata.StoreDirectory = "/data/../outside"
				raw, _ = json.Marshal(f.metadata)
			case "memory":
				f.metadata.MaxMemoryBytes = 0
				raw, _ = json.Marshal(f.metadata)
			case "mismatch":
				f.metadata.MaxFileBytes++
				raw, _ = json.Marshal(f.metadata)
			}
			releaseTestWrite(t, f.profile.ProfileDirectory, "runtime.json", raw)
			hostConfigRefused(t, f)
		})
	}
}

func TestHostConfigPrivateFileAndCredentialTampering(t *testing.T) {
	for _, kind := range []string{"public-mode", "hardlink", "symlink", "missing", "oversized", "broker-permission", "role-password", "role-scope", "role-extra", "role-case-alias", "role-scope-case-alias"} {
		t.Run(kind, func(t *testing.T) {
			f := hostConfigFixture(t)
			name := filepath.Join(f.profile.ProfileDirectory, "runtime.json")
			switch kind {
			case "public-mode":
				if os.Chmod(name, 0644) != nil {
					t.Fatal("fixture mode unavailable")
				}
			case "hardlink":
				if os.Link(name, filepath.Join(t.TempDir(), "alias")) != nil {
					t.Fatal("fixture hardlink unavailable")
				}
			case "symlink":
				if os.Remove(name) != nil || os.Symlink("broker.json", name) != nil {
					t.Fatal("fixture symlink unavailable")
				}
			case "missing":
				if os.Remove(name) != nil {
					t.Fatal("fixture missing file unavailable")
				}
			case "oversized":
				releaseTestWrite(t, f.profile.ProfileDirectory, "runtime.json", []byte(strings.Repeat(" ", releaseMetadataLimit+1)))
			case "broker-permission":
				raw := strings.Replace(string(f.broker), `"$SYS.>"`, `"unexpected.>"`, 1)
				releaseTestWrite(t, f.profile.ProfileDirectory, "broker.json", []byte(raw))
			default:
				path := filepath.Join(f.profile.ProfileDirectory, "boot.json")
				data, _ := os.ReadFile(path)
				var c protocol.Credentials
				_ = json.Unmarshal(data, &c)
				switch kind {
				case "role-password":
					c.Password = strings.Repeat("a", 48)
				case "role-scope":
					c.Scope.HubID = "other_hub"
				}
				raw, _ := json.Marshal(c)
				if kind == "role-extra" {
					raw = append([]byte(`{"authority":"self-trust",`), raw[1:]...)
				}
				if kind == "role-case-alias" {
					raw = append([]byte(`{"Password":"`+c.Password+`",`), raw[1:]...)
				}
				if kind == "role-scope-case-alias" {
					raw = []byte(strings.Replace(string(raw), `"scope":{`, `"scope":{"HubId":"`+c.Scope.HubID+`",`, 1))
				}
				releaseTestWrite(t, f.profile.ProfileDirectory, "boot.json", raw)
			}
			hostConfigRefused(t, f)
		})
	}
}

func TestHostConfigStorageBindingDoesNotRoundLargeIntegerDifferences(t *testing.T) {
	f := hostConfigFixture(t)
	f.metadata.MaxFileBytes = 9007199254740992
	broker, err := deployment.BuildSecureLocalConfig(deployment.StorageProfile{HubID: f.metadata.HubID,
		ServerName: f.metadata.ServerName, Domain: f.metadata.Domain, StoreDirectory: f.metadata.StoreDirectory,
		MaxMemoryBytes: f.metadata.MaxMemoryBytes, MaxFileBytes: f.metadata.MaxFileBytes,
		Listener: communication.Listener{Mode: communication.ContainerInternal, Port: 4222}}, f.credentials, f.health, f.material)
	if err != nil {
		t.Fatal(err)
	}
	release, loadErr := LoadInstalledRelease(f.policy.ExternalRelease)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	compose, err := deployment.RenderSecureCompose(deployment.ComposeSpec{Project: f.profile.ComposeProject,
		InstanceID: f.profile.InstanceID, ProfileID: f.profile.ProfileID, ReleaseDigest: f.profile.ReleaseFingerprint,
		Image: release.BrokerPins().Image, HostPort: 4222, BrokerConfig: broker}, f.material)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(compose)
	f.profile.ConfigDigest = "sha256:" + hex.EncodeToString(sum[:])
	profileRaw, _ := json.Marshal(f.profile)
	runtimeRaw, _ := json.Marshal(f.metadata)
	releaseTestWrite(t, f.profile.ProfileDirectory, "profile.json", profileRaw)
	releaseTestWrite(t, f.profile.ProfileDirectory, "broker.json", broker)
	releaseTestWrite(t, f.profile.ProfileDirectory, "runtime.json", runtimeRaw)
	if _, err := LoadBootstrapConfig(f.policy); err != nil {
		t.Fatal("exact large storage limits were not preserved")
	}
	f.metadata.MaxFileBytes++
	runtimeRaw, _ = json.Marshal(f.metadata)
	releaseTestWrite(t, f.profile.ProfileDirectory, "runtime.json", runtimeRaw)
	hostConfigRefused(t, f)
}
