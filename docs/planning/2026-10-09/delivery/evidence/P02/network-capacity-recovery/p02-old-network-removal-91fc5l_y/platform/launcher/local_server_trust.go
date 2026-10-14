//go:build linux || darwin

package launcher

import (
	"bytes"
	"os"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/localtls"
	"github.com/controlLogix/agentmux/platform/privatefs"
	"golang.org/x/sys/unix"
)

const localServerTrustFile = "nats-server-trust.json"
const localServerCertificateFile = "server-cert.pem"
const localServerKeyFile = "server-key.pem"

// Revalidation retains the externally selected policy, without sharing mutable
// caller slices or bridge settings. This copy grants no network authority.
func cloneHostAdmissionPolicy(policy HostPolicy) *HostPolicy {
	copy := policy
	copy.Profile.WorkspaceRoots = append([]string(nil), policy.Profile.WorkspaceRoots...)
	copy.ExternalRelease.PublicKey = bytes.Clone(policy.ExternalRelease.PublicKey)
	if policy.OwnerBridge != nil {
		settings := *policy.OwnerBridge
		copy.OwnerBridge = &settings
	}
	return &copy
}

// The selected profile's digest binds the artifact; the full kernel scope binds
// its identity. All reads use the same already-held private profile directory.
// This function never writes, renews certificates or contacts a server.
func loadLocalServerTrust(root *os.Root, profile Profile, scope protocol.Scope) (*localtls.ClientTrust, *deployment.LocalTLSMaterial, error) {
	refusal := func(code string) (*localtls.ClientTrust, *deployment.LocalTLSMaterial, error) {
		return nil, nil, hostConfigError("server_trust_" + code)
	}
	if root == nil || profile.ServerTrustRef != localServerTrustFile || !digest.MatchString(profile.ServerTrustDigest) || scope.InstanceID != profile.InstanceID || scope.ProfileID != profile.ProfileID || scope.ReleaseManifestDigest != profile.ReleaseFingerprint {
		return refusal("enrollment_invalid")
	}
	raw, err := hostPrivateRead(root, localServerTrustFile, profile.OwnerUID, protocol.MaxPayload)
	if err != nil || releaseDigest(raw) != profile.ServerTrustDigest || !releaseEscapesValid(raw) {
		return refusal("artifact_invalid")
	}
	fields, err := releaseFields(raw, "schemaVersion", "endpoint", "serverName", "rootsPem", "leafCertificateSha256", "scope")
	if err != nil {
		return refusal("fields_invalid")
	}
	if _, err = releaseFields(fields["scope"], "hubId", "instanceId", "profileId", "assemblyDigest", "releaseManifestDigest", "releaseVersion"); err != nil {
		return refusal("fields_invalid")
	}
	var record protocol.ServerTrustRecord
	if protocol.DecodeClosedJSON(raw, &record, protocol.MaxPayload) != nil {
		return refusal("record_invalid")
	}
	trust, err := protocol.ValidateServerTrustRecord(record, scope, profile.NATSEndpoint)
	if err != nil {
		return refusal("binding_invalid")
	}
	certificate, err := hostPrivateRead(root, localServerCertificateFile, profile.OwnerUID, 16*1024)
	if err != nil {
		return refusal("certificate_invalid")
	}
	key, err := hostPrivateRead(root, localServerKeyFile, profile.OwnerUID, 8*1024)
	if err != nil {
		return refusal("key_invalid")
	}
	material, err := deployment.NewLocalTLSMaterial(profile.ProfileID, []byte(record.RootsPEM), certificate, key)
	if err != nil {
		return refusal("material_invalid")
	}
	policy := trust.Policy()
	if policy.ServerName != material.ServerName() || policy.LeafCertificateSHA256 != material.LeafCertificateSHA256() || !bytes.Equal(policy.RootsPEM, material.RootsPEM()) {
		return refusal("material_binding_invalid")
	}
	return trust, material, nil
}

func checkPrivateProfileRoot(root *os.Root) error {
	if root == nil {
		return hostConfigError("profile_root_invalid")
	}
	file, err := root.OpenFile(".", os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return hostConfigError("profile_root_invalid")
	}
	defer file.Close()
	if privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil {
		return hostConfigError("profile_root_access_denied")
	}
	return nil
}
