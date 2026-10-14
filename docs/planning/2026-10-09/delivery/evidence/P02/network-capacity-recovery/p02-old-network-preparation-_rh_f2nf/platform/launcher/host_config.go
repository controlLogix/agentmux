//go:build linux || darwin

package launcher

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/assembly"
	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/privatefs"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

// HostPolicy is separately enrolled local host policy, not runtime metadata or
// package-supplied authority. All deadlines are selected here, not from files.
type HostPolicy struct {
	Profile         ProfilePolicy
	ExternalRelease ReleasePolicy
	Deadlines       protected.Deadlines
	StartupTimeout  time.Duration
	ProbeTimeout    time.Duration
	// Only separately enrolled host policy may enable the owner-status account.
	OwnerBridge *deployment.OwnerBridgeSettings
}

type hostRuntimeMetadata struct {
	SchemaVersion  string `json:"schemaVersion"`
	HubID          string `json:"hubId"`
	ServerName     string `json:"serverName"`
	Domain         string `json:"domain"`
	StoreDirectory string `json:"storeDirectory"`
	MaxMemoryBytes int64  `json:"maxMemoryBytes"`
	MaxFileBytes   int64  `json:"maxFileBytes"`
}

func hostConfigError(code string) error { return errors.New("host_config_" + code) }

func hostPrivateRead(root *os.Root, name string, uid uint32, limit int64) ([]byte, error) {
	return hostPrivateReadWithOpen(root, name, uid, limit, assembly.OpenMember)
}

func hostPrivateReadWithOpen(root *os.Root, name string, uid uint32, limit int64, open func(*os.Root, string) (*os.File, error)) ([]byte, error) {
	before, err := root.Lstat(name)
	if err != nil || !privateProfileInfo(before, uid, false) || before.Size() < 0 || before.Size() > limit {
		return nil, hostConfigError("private_file_invalid")
	}
	file, err := open(root, name)
	if err != nil {
		return nil, hostConfigError("private_file_unavailable")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !hostReadMetadataEqual(before, opened) || !privateProfileInfo(opened, uid, false) || privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil {
		return nil, hostConfigError("private_file_changed")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	after, afterErr := root.Lstat(name)
	final, statErr := file.Stat()
	if err != nil || afterErr != nil || statErr != nil || privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil || int64(len(raw)) > limit ||
		!privateProfileInfo(after, uid, false) || !privateProfileInfo(final, uid, false) ||
		!hostReadMetadataEqual(opened, after) || !hostReadMetadataEqual(opened, final) || before.Size() != int64(len(raw)) || final.Size() != int64(len(raw)) {
		return nil, hostConfigError("private_file_changed")
	}
	return raw, nil
}

// Access time may change during a read. Modification and inode-change times
// must remain stable, including when a same-size writer restores modification
// time. Darwin and Linux expose the change time under different stat fields.
func hostReadMetadataEqual(a, b os.FileInfo) bool {
	if a == nil || b == nil || !os.SameFile(a, b) || a.Size() != b.Size() || a.Mode() != b.Mode() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	av, bv := reflect.ValueOf(a.Sys()), reflect.ValueOf(b.Sys())
	if av.Kind() != reflect.Pointer || bv.Kind() != reflect.Pointer || av.IsNil() || bv.IsNil() {
		return false
	}
	av, bv = av.Elem(), bv.Elem()
	if av.Kind() != reflect.Struct || bv.Kind() != reflect.Struct {
		return false
	}
	for _, name := range []string{"Ctim", "Ctimespec"} {
		ac, bc := av.FieldByName(name), bv.FieldByName(name)
		if ac.IsValid() && bc.IsValid() && ac.CanInterface() && bc.CanInterface() {
			return reflect.DeepEqual(ac.Interface(), bc.Interface())
		}
	}
	return false
}

func hostRuntimeDecode(raw []byte) (hostRuntimeMetadata, error) {
	var metadata hostRuntimeMetadata
	if releaseJSON(raw) != nil {
		return metadata, hostConfigError("runtime_metadata_invalid")
	}
	if _, err := releaseFields(raw, "schemaVersion", "hubId", "serverName", "domain", "storeDirectory", "maxMemoryBytes", "maxFileBytes"); err != nil {
		return metadata, hostConfigError("runtime_metadata_invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&metadata) != nil || metadata.SchemaVersion != "1.0.0" ||
		!releaseIdentifier.MatchString(metadata.HubID) || !releaseIdentifier.MatchString(metadata.ServerName) ||
		!releaseIdentifier.MatchString(metadata.Domain) || !strings.HasPrefix(metadata.StoreDirectory, "/data/") ||
		filepath.Clean(metadata.StoreDirectory) != metadata.StoreDirectory || metadata.MaxMemoryBytes < 1024*1024 ||
		metadata.MaxFileBytes < 1024*1024 {
		return hostRuntimeMetadata{}, hostConfigError("runtime_metadata_invalid")
	}
	return metadata, nil
}

func hostBrokerSecrets(raw []byte) (string, string, error) {
	if releaseJSON(raw) != nil {
		return "", "", hostConfigError("broker_json_invalid")
	}
	var broker struct {
		Accounts map[string]struct {
			Users []struct {
				User, Password string
			} `json:"users"`
		} `json:"accounts"`
	}
	if json.Unmarshal(raw, &broker) != nil {
		return "", "", hostConfigError("broker_json_invalid")
	}
	find := func(account, username string) (string, bool) {
		users := broker.Accounts[account].Users
		if len(users) != 1 || users[0].User != username {
			return "", false
		}
		return users[0].Password, true
	}
	health, healthOK := find(deployment.HealthAccount, deployment.HealthUser)
	observer, observerOK := find("APPLICATION", communication.OrdinaryPlugin)
	if !healthOK || !observerOK || !kernelStatusPassword.MatchString(health) || !kernelStatusPassword.MatchString(observer) {
		return "", "", hostConfigError("broker_credentials_invalid")
	}
	return health, observer, nil
}

// LoadBootstrapConfig reads and validates actual private files and a signed
// installed release. It creates no profile, files, leases, processes or network
// connections. The returned configuration contains secrets for trusted bootstrap
// code only and must never be serialized or printed for a user.
func LoadBootstrapConfig(policy HostPolicy) (BootstrapConfig, error) {
	if policy.StartupTimeout <= 0 || policy.StartupTimeout > 60*time.Second ||
		policy.ProbeTimeout <= 0 || policy.ProbeTimeout > 5*time.Second ||
		policy.Deadlines.StartTimeout <= 0 || policy.Deadlines.StartTimeout > 30*time.Second ||
		policy.Deadlines.StopGrace <= 0 || policy.Deadlines.StopGrace > 10*time.Second ||
		policy.Deadlines.ReapTimeout <= 0 || policy.Deadlines.ReapTimeout > 10*time.Second ||
		policy.Profile.InstalledReleaseFingerprint != policy.ExternalRelease.ReleaseManifestDigest {
		return BootstrapConfig{}, hostConfigError("host_policy_invalid")
	}
	loadedProfile, err := LoadProfile(policy.Profile)
	if err != nil {
		return BootstrapConfig{}, hostConfigError("profile_invalid")
	}
	profile := loadedProfile.Declaration()
	if profile.Mode != "local" || profile.Docker == nil {
		return BootstrapConfig{}, hostConfigError("local_profile_required")
	}
	endpoint, err := url.Parse(profile.NATSEndpoint)
	if err != nil {
		return BootstrapConfig{}, hostConfigError("local_endpoint_unsupported")
	}
	host, portText, err := net.SplitHostPort(endpoint.Host)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || host != "127.0.0.1" || endpoint.Scheme != "tls" || port <= 0 || port > 65535 {
		return BootstrapConfig{}, hostConfigError("local_endpoint_unsupported")
	}
	release, err := LoadInstalledRelease(policy.ExternalRelease)
	if err != nil {
		return BootstrapConfig{}, hostConfigError("installed_release_invalid")
	}
	pins := release.BrokerPins()
	if profile.Docker.ComposeVersion != pins.ComposeVersion {
		return BootstrapConfig{}, hostConfigError("compose_version_mismatch")
	}
	root, err := openProfileDirectory(policy.Profile)
	if err != nil {
		return BootstrapConfig{}, hostConfigError("profile_root_invalid")
	}
	defer root.Close()
	openedRoot, err := root.Stat(".")
	if err != nil {
		return BootstrapConfig{}, hostConfigError("profile_root_invalid")
	}
	runtimeRaw, err := hostPrivateRead(root, "runtime.json", profile.OwnerUID, releaseMetadataLimit)
	if err != nil {
		return BootstrapConfig{}, err
	}
	metadata, err := hostRuntimeDecode(runtimeRaw)
	if err != nil {
		return BootstrapConfig{}, err
	}
	brokerRaw, err := hostPrivateRead(root, "broker.json", profile.OwnerUID, deployment.MaxPrivateConfigBytes)
	if err != nil {
		return BootstrapConfig{}, err
	}
	healthPassword, observerPassword, err := hostBrokerSecrets(brokerRaw)
	if err != nil {
		return BootstrapConfig{}, err
	}
	trust := release.Trust()
	scope := protocol.Scope{HubID: metadata.HubID, InstanceID: profile.InstanceID, ProfileID: profile.ProfileID,
		AssemblyDigest: trust.AssemblyDigest, ReleaseManifestDigest: trust.ReleaseManifestDigest, ReleaseVersion: trust.ReleaseVersion}
	config := BootstrapConfig{ProfilePolicy: policy.Profile, Assembly: release.Assembly(), PackageDirectory: release.PackageDirectory(),
		ReleaseTrust: trust, BrokerImage: pins.Image, BrokerConfigDigest: sha256.Sum256(brokerRaw), Deadlines: policy.Deadlines,
		StartupTimeout: policy.StartupTimeout,
		Health: deployment.ProbeOptions{Endpoint: profile.NATSEndpoint, Password: healthPassword, HubID: metadata.HubID,
			ServerName: metadata.ServerName, Domain: metadata.Domain, ServerVersion: pins.NATSVersion, Timeout: policy.ProbeTimeout},
		Kernel: KernelStatusOptions{Endpoint: profile.NATSEndpoint, Password: observerPassword, Scope: scope, Timeout: policy.ProbeTimeout}}
	config.ProfilePolicy.WorkspaceRoots = append([]string(nil), policy.Profile.WorkspaceRoots...)
	serverTrust, material, err := loadLocalServerTrust(root, profile, scope)
	if err != nil {
		return BootstrapConfig{}, err
	}
	config.LocalTLS = material
	config.Kernel.TLS = serverTrust
	config.Health.TLS = serverTrust
	if policy.OwnerBridge != nil {
		settings := *policy.OwnerBridge
		if settings.Scope != scope {
			return BootstrapConfig{}, hostConfigError("owner_bridge_scope_invalid")
		}
		config.OwnerBridge = &settings
	}
	credentials, err := bootstrapBrokerCredentials(brokerRaw, config)
	if err != nil {
		return BootstrapConfig{}, hostConfigError("broker_policy_invalid")
	}
	// Rebuild from runtime.json as well: a valid factory file for different storage
	// settings must not silently override the enrolled runtime metadata.
	storage := deployment.StorageProfile{HubID: metadata.HubID,
		ServerName: metadata.ServerName, Domain: metadata.Domain, StoreDirectory: metadata.StoreDirectory,
		MaxMemoryBytes: metadata.MaxMemoryBytes, MaxFileBytes: metadata.MaxFileBytes,
		Listener: communication.Listener{Mode: communication.ContainerInternal, Port: 4222}}
	var expectedBroker []byte
	if config.OwnerBridge != nil {
		expectedBroker, err = deployment.BuildSecureLocalConfigWithOwnerBridge(storage, credentials, healthPassword, *config.OwnerBridge, material)
	} else {
		expectedBroker, err = deployment.BuildSecureLocalConfig(storage, credentials, healthPassword, material)
	}
	decodeObject := func(raw []byte) (any, error) {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var object any
		err := decoder.Decode(&object)
		return object, err
	}
	actualObject, actualErr := decodeObject(brokerRaw)
	expectedObject, expectedErr := decodeObject(expectedBroker)
	if err != nil || actualErr != nil || expectedErr != nil ||
		!reflect.DeepEqual(actualObject, expectedObject) {
		return BootstrapConfig{}, hostConfigError("runtime_broker_mismatch")
	}
	config.brokerUsers = credentials
	compose, err := deployment.RenderSecureCompose(deployment.ComposeSpec{Project: profile.ComposeProject, InstanceID: profile.InstanceID,
		ProfileID: profile.ProfileID, ReleaseDigest: trust.ReleaseManifestDigest, Image: pins.Image, HostPort: port, BrokerConfig: brokerRaw}, material)
	if err != nil {
		return BootstrapConfig{}, hostConfigError("compose_invalid")
	}
	composeHash := sha256.Sum256(compose)
	if profile.ConfigDigest != "sha256:"+hex.EncodeToString(composeHash[:]) {
		return BootstrapConfig{}, hostConfigError("enrolled_config_digest_mismatch")
	}
	config.Compose = compose
	for index, role := range protocol.Roles() {
		name := role + ".json"
		data, err := hostPrivateRead(root, name, profile.OwnerUID, protocol.MaxPayload)
		if err != nil {
			return BootstrapConfig{}, err
		}
		var roleCredentials protocol.Credentials
		fields, fieldsErr := releaseFields(data, "schemaVersion", "role", "username", "password", "natsUrl", "scope")
		var scopeErr error
		if fieldsErr == nil {
			_, scopeErr = releaseFields(fields["scope"], "hubId", "instanceId", "profileId", "assemblyDigest", "releaseManifestDigest", "releaseVersion")
		}
		if fieldsErr != nil || scopeErr != nil || releaseJSON(data) != nil || protocol.StrictJSON(data, &roleCredentials) != nil ||
			roleCredentials.SchemaVersion != protocol.Version || roleCredentials.Role != role || roleCredentials.Username != role ||
			roleCredentials.NATSURL != profile.NATSEndpoint || roleCredentials.Scope != scope || roleCredentials.Password != credentials[role] {
			return BootstrapConfig{}, hostConfigError("role_credentials_invalid")
		}
		config.Roles[index] = protected.RoleOptions{ID: role, Env: map[string]string{
			"AGENTMUX_NATS_SERVER_TRUST_FILE": filepath.Join(profile.ProfileDirectory, localServerTrustFile),
			"AGENTMUX_NATS_URL":               profile.NATSEndpoint, "AGENTMUX_INSTANCE_ID": profile.InstanceID,
			"AGENTMUX_PROFILE_ID": profile.ProfileID, "AGENTMUX_NATS_CREDS_FILE": filepath.Join(profile.ProfileDirectory, name)}}
	}
	if validateBootstrapRoles(config, profile) != nil {
		return BootstrapConfig{}, hostConfigError("role_binding_invalid")
	}
	afterRoot, err := os.Lstat(profile.ProfileDirectory)
	if err != nil || !privateProfileInfo(afterRoot, profile.OwnerUID, true) || !os.SameFile(openedRoot, afterRoot) || checkPrivateProfileRoot(root) != nil {
		return BootstrapConfig{}, hostConfigError("profile_root_changed")
	}
	config.admissionPolicy = cloneHostAdmissionPolicy(policy)
	if attachLocalBrokerAuthority(&config) != nil {
		return BootstrapConfig{}, hostConfigError("local_broker_authority_invalid")
	}
	return config, nil
}
