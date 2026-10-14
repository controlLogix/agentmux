//go:build linux || darwin

package launcher

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

type localTrustFixture struct {
	policy   ProfilePolicy
	profile  Profile
	scope    protocol.Scope
	material *deployment.LocalTLSMaterial
	record   protocol.ServerTrustRecord
}

func newLocalTrustFixture(t *testing.T) localTrustFixture {
	t.Helper()
	policy, p := profileFixture(t)
	p.NATSEndpoint = "tls://127.0.0.1:4222"
	scope := protocol.Scope{HubID: "trust_hub", InstanceID: p.InstanceID, ProfileID: p.ProfileID, AssemblyDigest: "sha256:" + strings.Repeat("c", 64), ReleaseManifestDigest: p.ReleaseFingerprint, ReleaseVersion: "1.0.0"}
	material, err := deployment.EnrollLocalTLS(context.Background(), p.ProfileID)
	if err != nil {
		t.Fatal("disposable TLS enrollment fixture failed")
	}
	record := protocol.ServerTrustRecord{SchemaVersion: protocol.Version, Endpoint: p.NATSEndpoint, ServerName: material.ServerName(), RootsPEM: string(material.RootsPEM()), LeafCertificateSHA256: material.LeafCertificateSHA256(), Scope: scope}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal("disposable trust fixture encoding failed")
	}
	p.ServerTrustRef = localServerTrustFile
	p.ServerTrustDigest = releaseDigest(raw)
	releaseTestWrite(t, policy.Directory, localServerTrustFile, raw)
	releaseTestWrite(t, policy.Directory, localServerCertificateFile, material.ServerCertificatePEM())
	releaseTestWrite(t, policy.Directory, localServerKeyFile, material.ServerKeyPEM())
	if EnrollProfile(policy, p) != nil {
		t.Fatal("disposable TLS profile enrollment failed")
	}
	return localTrustFixture{policy, p, scope, material, record}
}

func TestLocalServerTrustAdmissionPolicyCopies(t *testing.T) {
	policy := HostPolicy{Profile: ProfilePolicy{WorkspaceRoots: []string{"/workspace"}}, ExternalRelease: ReleasePolicy{PublicKey: []byte{1, 2, 3}}, OwnerBridge: &deployment.OwnerBridgeSettings{ServerPassword: "original-server", ClientPassword: "original-client"}}
	copy := cloneHostAdmissionPolicy(policy)
	policy.Profile.WorkspaceRoots[0] = "/changed"
	policy.ExternalRelease.PublicKey[0] = 9
	policy.OwnerBridge.ServerPassword = "changed"
	if copy.Profile.WorkspaceRoots[0] != "/workspace" || copy.ExternalRelease.PublicKey[0] != 1 || copy.OwnerBridge.ServerPassword != "original-server" {
		t.Fatal("caller mutation changed retained admission policy")
	}
	copy.ExternalRelease.PublicKey[1] = 7
	if policy.ExternalRelease.PublicKey[1] == 7 {
		t.Fatal("admission policy copy changed the original policy")
	}
}
func TestLocalServerTrustReadOnlyBoundMaterial(t *testing.T) {
	f := newLocalTrustFixture(t)
	before := map[string]string{}
	entries, err := os.ReadDir(f.policy.Directory)
	if err != nil {
		t.Fatal("private trust fixture inventory failed")
	}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(f.policy.Directory, entry.Name()))
		if err != nil {
			t.Fatal("private trust fixture read failed")
		}
		before[entry.Name()] = releaseDigest(raw)
	}
	root, err := openProfileDirectory(f.policy)
	if err != nil {
		t.Fatal("private trust root unavailable")
	}
	defer root.Close()
	trust, material, err := loadLocalServerTrust(root, f.profile, f.scope)
	if err != nil || trust == nil || material == nil || trust.Policy().LeafCertificateSHA256 != f.material.LeafCertificateSHA256() {
		t.Fatal("correct enrolled TLS identity rejected")
	}
	public := trust.Policy()
	public.RootsPEM[0] = '!'
	privateCopy := material.ServerKeyPEM()
	privateCopy[0] = '!'
	if !bytes.Equal(trust.Policy().RootsPEM, f.material.RootsPEM()) || !bytes.Equal(material.ServerKeyPEM(), f.material.ServerKeyPEM()) {
		t.Fatal("TLS material retained mutable getter data")
	}
	for name, digest := range before {
		raw, err := os.ReadFile(filepath.Join(f.policy.Directory, name))
		if err != nil || releaseDigest(raw) != digest {
			t.Fatal("warm trust loading changed enrolled files")
		}
	}
	after, err := os.ReadDir(f.policy.Directory)
	if err != nil || len(after) != len(entries) {
		t.Fatal("trust loading created or removed files")
	}
}

func TestLocalServerTrustRejectsArtifactsAndMaterial(t *testing.T) {
	for _, mode := range []string{"missing", "digest", "public-trust", "trust-symlink", "trust-hardlink", "scope", "endpoint", "name", "pin", "ca", "missing-scope-field", "alias", "duplicate", "unknown", "null", "oversize", "missing-cert", "public-cert", "cert-symlink", "cert-hardlink", "missing-key", "public-key", "key-symlink", "key-hardlink", "wrong-key", "wrong-leaf"} {
		t.Run(mode, func(t *testing.T) {
			f := newLocalTrustFixture(t)
			trustPath := filepath.Join(f.policy.Directory, localServerTrustFile)
			certPath := filepath.Join(f.policy.Directory, localServerCertificateFile)
			keyPath := filepath.Join(f.policy.Directory, localServerKeyFile)
			writeRecord := false
			switch mode {
			case "missing":
				os.Remove(trustPath)
			case "digest":
				f.profile.ServerTrustDigest = "sha256:" + strings.Repeat("0", 64)
			case "public-trust":
				os.Chmod(trustPath, 0644)
			case "trust-symlink", "trust-hardlink", "cert-symlink", "cert-hardlink", "key-symlink", "key-hardlink":
				path := trustPath
				if strings.HasPrefix(mode, "cert-") {
					path = certPath
				}
				if strings.HasPrefix(mode, "key-") {
					path = keyPath
				}
				if strings.HasSuffix(mode, "symlink") {
					if os.Rename(path, path+"-target") != nil || os.Symlink(path+"-target", path) != nil {
						t.Fatal("symlink control failed")
					}
				} else if os.Link(path, path+"-alias") != nil {
					t.Fatal("hardlink control failed")
				}
			case "scope":
				f.record.Scope.HubID = "foreign_hub"
				writeRecord = true
			case "endpoint":
				f.record.Endpoint = "tls://127.0.0.1:4223"
				writeRecord = true
			case "name":
				f.record.ServerName = "foreign.agentmux.invalid"
				writeRecord = true
			case "pin":
				f.record.LeafCertificateSHA256 = "sha256:" + strings.Repeat("0", 64)
				writeRecord = true
			case "ca":
				other, err := deployment.EnrollLocalTLS(context.Background(), f.profile.ProfileID)
				if err != nil {
					t.Fatal("alternate CA control failed")
				}
				f.record.RootsPEM = string(other.RootsPEM())
				writeRecord = true
			case "missing-cert":
				os.Remove(certPath)
			case "public-cert":
				os.Chmod(certPath, 0644)
			case "missing-key":
				os.Remove(keyPath)
			case "public-key":
				os.Chmod(keyPath, 0644)
			case "wrong-key", "wrong-leaf":
				other, err := deployment.EnrollLocalTLS(context.Background(), f.profile.ProfileID)
				if err != nil {
					t.Fatal("alternate material control failed")
				}
				if mode == "wrong-key" {
					releaseTestWrite(t, f.policy.Directory, localServerKeyFile, other.ServerKeyPEM())
				} else {
					releaseTestWrite(t, f.policy.Directory, localServerCertificateFile, other.ServerCertificatePEM())
					releaseTestWrite(t, f.policy.Directory, localServerKeyFile, other.ServerKeyPEM())
				}
			default:
				raw, _ := json.Marshal(f.record)
				text := string(raw)
				switch mode {
				case "missing-scope-field":
					text = strings.Replace(text, `"hubId":"trust_hub",`, "", 1)
				case "alias":
					text = strings.Replace(text, `"scope":`, `"Scope":`, 1)
				case "duplicate":
					text = strings.Replace(text, `"schemaVersion":`, `"schemaVersion":"1.0.0","schemaVersion":`, 1)
				case "unknown":
					text = strings.Replace(text, `"endpoint":`, `"unexpected":true,"endpoint":`, 1)
				case "null":
					var fields map[string]json.RawMessage
					json.Unmarshal(raw, &fields)
					fields["scope"] = json.RawMessage("null")
					encoded, _ := json.Marshal(fields)
					text = string(encoded)
				case "oversize":
					text = strings.Repeat(" ", protocol.MaxPayload+1)
				}
				releaseTestWrite(t, f.policy.Directory, localServerTrustFile, []byte(text))
				f.profile.ServerTrustDigest = releaseDigest([]byte(text))
			}
			if writeRecord {
				raw, _ := json.Marshal(f.record)
				releaseTestWrite(t, f.policy.Directory, localServerTrustFile, raw)
				f.profile.ServerTrustDigest = releaseDigest(raw)
			}
			root, err := openProfileDirectory(f.policy)
			if err != nil {
				t.Fatal("negative fixture private root unavailable")
			}
			defer root.Close()
			trust, material, err := loadLocalServerTrust(root, f.profile, f.scope)
			if err == nil || trust != nil || material != nil {
				t.Fatal("invalid enrolled TLS identity accepted")
			}
			if strings.Contains(err.Error(), f.policy.Directory) || strings.Contains(err.Error(), string(f.material.ServerKeyPEM())) {
				t.Fatal("TLS admission error exposed private input")
			}
		})
	}
}
