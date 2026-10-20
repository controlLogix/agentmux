//go:build linux || darwin

package launcher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"
)

// Reuse the enrolled-host fixture; no server, Docker command or child starts.
func applicationHostCompositionSelection(t *testing.T) (*EnrolledHostPolicy, ApplicationAttestorHostSelection) {
	t.Helper()
	hostSelection, _ := installedBridgePolicyFixture(t)
	host, err := LoadEnrolledHostPolicy(hostSelection)
	if err != nil {
		t.Fatal(err)
	}
	server, _, err := host.BridgeServer()
	if err != nil {
		t.Fatal(err)
	}
	applicationTLS, err := deployment.EnrollLocalTLS(context.Background(), server.config.Kernel.Scope.ProfileID)
	if err != nil {
		t.Fatal("application TLS enrollment unavailable")
	}
	connection := ApplicationAttestorConnectionSelection{Endpoint: "tls://127.0.0.1:44222", ServerName: applicationTLS.ServerName(), RootsPEM: string(applicationTLS.RootsPEM()), LeafCertificateSHA256: applicationTLS.LeafCertificateSHA256()}
	selection, material, _ := applicationSignerTestSelection(time.Now())
	selection.KernelScope = server.config.Kernel.Scope
	selection.OwnerUID = hostSelection.OwnerUID
	selection.WorkspaceRoots = append([]string(nil), hostSelection.WorkspaceRoots...)
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if os.Chmod(base, 0700) != nil {
		t.Fatal("private composition directory unavailable")
	}
	selection.KeyPath = filepath.Join(base, "application-attestor.json")
	var record map[string]any
	json.Unmarshal(material, &record)
	record["hubId"] = selection.KernelScope.HubID
	record["profileId"] = selection.KernelScope.ProfileID
	record["instanceId"] = selection.KernelScope.InstanceID
	material, _ = json.Marshal(record)
	if os.WriteFile(selection.KeyPath, material, 0600) != nil {
		t.Fatal("explicit attestor key unavailable")
	}
	account, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	defer account.Wipe()
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer user.Wipe()
	accountPublic, _ := account.PublicKey()
	userPublic, _ := user.PublicKey()
	seed, _ := user.Seed()
	defer clear(seed)
	subject := "amx.v1.h." + selection.KernelScope.HubID + ".o." + selection.Scope.OrganizationID + ".identity." + selection.AuthorityID + ".command"
	claims, _ := json.Marshal(map[string]any{"iss": accountPublic, "sub": userPublic, "exp": time.Now().Add(time.Minute).Unix(), "nats": map[string]any{"type": "user", "version": 2, "pub": map[string]any{"allow": []string{subject}}, "sub": map[string]any{"allow": []string{selection.ReplyPrefix + ".>"}}}})
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"ed25519-nkey"}`))
	body := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	signature, err := account.Sign([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	credential := []byte("-----BEGIN NATS USER JWT-----\n" + body + "." + base64.RawURLEncoding.EncodeToString(signature) + "\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n" + string(seed) + "\n------END USER NKEY SEED------\n")
	path := filepath.Join(base, "application-attestor.creds")
	if os.WriteFile(path, credential, 0600) != nil {
		t.Fatal("private broker credential unavailable")
	}
	sum := sha256.Sum256(credential)
	return host, ApplicationAttestorHostSelection{Signer: selection, CredentialsPath: path, CredentialsSHA256: "sha256:" + hex.EncodeToString(sum[:]), AccountPublicKey: accountPublic, UserPublicKey: userPublic, InitialGeneration: 1, Connection: connection}
}

func TestApplicationHostCompositionAdmitsExplicitHostAndOwnsKeyCleanup(t *testing.T) {
	host, selection := applicationHostCompositionSelection(t)
	prepared, err := prepareApplicationAttestorHost(context.Background(), host, selection)
	if err != nil {
		t.Fatal("explicit application host selection refused", err)
	}
	if prepared.enrollment.Scope != selection.Signer.KernelScope || prepared.enrollment.ReplyPrefix != selection.Signer.ReplyPrefix || prepared.enrollment.Signer != prepared.signer || prepared.signer.closed {
		t.Fatal("host composition lost its admitted bindings")
	}
	original := bytes.Clone(prepared.enrollment.Credentials)
	if err = prepared.close(); err != nil {
		t.Fatal(err)
	}
	if !prepared.signer.closed || len(prepared.signer.private) != 0 || bytes.Equal(original, prepared.enrollment.Credentials) {
		t.Fatal("composition did not clear its signing key and credential snapshot")
	}
	if err = prepared.close(); err != nil {
		t.Fatal("repeated close changed cleanup", err)
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, selection), selection.CredentialsPath) {
			t.Fatal("private host selection exposed")
		}
	}
}

func TestApplicationHostCompositionUsesExplicitApplicationBrokerWithoutKernelFallback(t *testing.T) {
	host, selection := applicationHostCompositionSelection(t)
	prepared, err := prepareApplicationAttestorHost(context.Background(), host, selection)
	if err != nil {
		t.Fatal("separately enrolled application transport refused", err)
	}
	defer prepared.close()
	server, _, err := host.BridgeServer()
	if err != nil {
		t.Fatal(err)
	}
	policy := prepared.enrollment.Trust.Policy()
	if policy.Endpoint != selection.Connection.Endpoint || policy.ServerName != selection.Connection.ServerName || string(policy.RootsPEM) != selection.Connection.RootsPEM || policy.LeafCertificateSHA256 != selection.Connection.LeafCertificateSHA256 || policy.Endpoint == server.config.Kernel.Endpoint || bytes.Equal(policy.RootsPEM, server.config.Kernel.TLS.Policy().RootsPEM) {
		t.Fatal("application transport inherited or rewrote kernel broker enrollment")
	}
	configured, err := server.WithApplicationAttestor(prepared.enrollment)
	if err != nil || configured.application == nil {
		t.Fatal("host rejected independently admitted application transport")
	}
	clear(configured.application.enrollment.Credentials)
	infrastructure := prepared.enrollment
	infrastructure.Trust = server.config.Kernel.TLS
	infrastructure.ServerName = server.config.Kernel.TLS.Policy().ServerName
	if _, err := server.WithApplicationAttestor(infrastructure); err == nil {
		t.Fatal("direct attestor configuration accepted the infrastructure listener")
	}
	selection.Connection.Endpoint = server.config.Kernel.Endpoint
	if same, err := prepareApplicationAttestorHost(context.Background(), host, selection); err == nil || same != nil {
		t.Fatal("application transport accepted the password-based infrastructure listener")
	}
	selection.Connection = ApplicationAttestorConnectionSelection{}
	if missing, err := prepareApplicationAttestorHost(context.Background(), host, selection); err == nil || missing != nil {
		t.Fatal("missing application connection fell back to the kernel listener")
	}
}

func TestApplicationHostCompositionRefusesMismatchBeforeReceiptAdoption(t *testing.T) {
	for _, fault := range []string{"credential-digest", "scope", "workspaces", "uid", "generation", "public-credential", "account", "prefix"} {
		t.Run(fault, func(t *testing.T) {
			host, selection := applicationHostCompositionSelection(t)
			_, _ = receiptPipeFixture(t)
			fd, err := strconv.Atoi(os.Getenv("AGENTMUX_BOOTSTRAP_RECEIPT_FD"))
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "credential-digest":
				selection.CredentialsSHA256 = "sha256:" + strings.Repeat("0", 64)
			case "scope":
				selection.Signer.KernelScope.InstanceID = "foreign_instance"
			case "workspaces":
				selection.Signer.WorkspaceRoots = nil
			case "uid":
				selection.Signer.OwnerUID++
			case "generation":
				selection.InitialGeneration = 0
			case "public-credential":
				if os.Chmod(selection.CredentialsPath, 0644) != nil {
					t.Fatal("mode control failed")
				}
			case "account":
				other, _ := nkeys.CreateAccount()
				defer other.Wipe()
				selection.AccountPublicKey, _ = other.PublicKey()
			case "prefix":
				selection.Signer.ReplyPrefix = "_INBOX.OTHERPRINCIPAL000"
			}
			if err = host.RunWithApplicationAttestor(context.Background(), "attempt_"+strings.Repeat("a", 32), selection); err == nil {
				t.Fatal("mismatched application selection started a host")
			}
			if _, err = unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
				t.Fatal("pre-admission failure consumed the inherited writer")
			}
		})
	}
}

func applicationHostSelectionRecordForTest(host *EnrolledHostPolicy, s ApplicationAttestorHostSelection) applicationHostSelectionRecord {
	return applicationHostSelectionRecord{SchemaVersion: "1.0.0", HostPolicy: host.selection.Path, OwnerUID: s.Signer.OwnerUID, Workspaces: append([]string(nil), s.Signer.WorkspaceRoots...), KernelScope: s.Signer.KernelScope, KeyPath: s.Signer.KeyPath, Credentials: applicationHostCredentialRecord{Path: s.CredentialsPath, SHA256: s.CredentialsSHA256, AccountPublicKey: s.AccountPublicKey, UserPublicKey: s.UserPublicKey, ReplyPrefix: s.Signer.ReplyPrefix}, Application: applicationHostBindingRecord{AuthorityID: s.Signer.AuthorityID, IdentityRef: s.Signer.IdentityRef, IssuerRef: s.Signer.IssuerRef, TransportRef: s.Signer.TransportRef, PolicyRef: s.Signer.PolicyRef, WorkspaceRef: s.Signer.WorkspaceRef, Scope: s.Signer.Scope}, ReceiptTrust: applicationHostReceiptTrustRecord{IssuerRef: s.Signer.ReceiptTrust.Issuer, PublicKey: base64.RawURLEncoding.EncodeToString(s.Signer.ReceiptTrust.PublicKey), NotBefore: bridgeTime(s.Signer.ReceiptTrust.NotBefore), ExpiresAt: bridgeTime(s.Signer.ReceiptTrust.ExpiresAt), MinimumAuthorityRevision: s.Signer.ReceiptTrust.MinimumAuthorityRevision}, InitialGeneration: s.InitialGeneration, Connection: s.Connection}
}

func TestApplicationHostClosedSelectionReaderPinsExactRecordAndHost(t *testing.T) {
	host, original := applicationHostCompositionSelection(t)
	record := applicationHostSelectionRecordForTest(host, original)
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(original.Signer.KeyPath), "application-host-selection.json")
	write := func(raw []byte) string {
		if os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("private selection unavailable")
		}
		sum := sha256.Sum256(raw)
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	pin := write(raw)
	selected, err := host.ReadApplicationAttestorHostSelection(context.Background(), path, pin)
	if err != nil {
		t.Fatal("closed application selection rejected", err)
	}
	if selected.Connection != original.Connection || selected.CredentialsPath != original.CredentialsPath || selected.CredentialsSHA256 != original.CredentialsSHA256 || selected.Signer.KernelScope != original.Signer.KernelScope || selected.Signer.PolicyRef != original.Signer.PolicyRef || !bytes.Equal(selected.Signer.ReceiptTrust.PublicKey, original.Signer.ReceiptTrust.PublicKey) {
		t.Fatal("record changed expected application binding")
	}
	prepared, err := prepareApplicationAttestorHost(context.Background(), host, selected)
	if err != nil {
		t.Fatal("read selection did not compose", err)
	}
	prepared.close()
	if _, err := host.ReadApplicationAttestorHostSelection(context.Background(), path, "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("selection digest mismatch admitted")
	}
	for _, fault := range []string{"extra", "host-policy", "kernel-scope", "workspaces", "null-application-scope", "missing-reference-revision", "alias", "prefix", "receipt-key", "missing-connection", "partial-connection", "extra-connection", "insecure-connection", "invalid-connection-root", "invalid-leaf-pin"} {
		t.Run(fault, func(t *testing.T) {
			var changed map[string]any
			json.Unmarshal(raw, &changed)
			switch fault {
			case "extra":
				changed["ignored"] = true
			case "host-policy":
				changed["hostPolicy"] = "/private/foreign-policy.json"
			case "kernel-scope":
				changed["kernelScope"].(map[string]any)["instanceId"] = "foreign_instance"
			case "workspaces":
				changed["workspaces"] = []string{"/foreign_workspace"}
			case "null-application-scope":
				changed["application"].(map[string]any)["scope"] = nil
			case "missing-reference-revision":
				delete(changed["application"].(map[string]any)["policyRef"].(map[string]any), "revision")
			case "alias":
				changed["OwnerUid"] = changed["ownerUid"]
				delete(changed, "ownerUid")
			case "prefix":
				changed["credentials"].(map[string]any)["replyPrefix"] = "_INBOX"
			case "receipt-key":
				changed["receiptTrust"].(map[string]any)["publicKey"] = "invalid"
			case "missing-connection":
				delete(changed, "connection")
			case "partial-connection":
				delete(changed["connection"].(map[string]any), "leafCertificateSHA256")
			case "extra-connection":
				changed["connection"].(map[string]any)["fallback"] = true
			case "insecure-connection":
				changed["connection"].(map[string]any)["endpoint"] = "nats://127.0.0.1:4222"
			case "invalid-connection-root":
				changed["connection"].(map[string]any)["rootsPEM"] = "missing CA"
			case "invalid-leaf-pin":
				changed["connection"].(map[string]any)["leafCertificateSHA256"] = "sha256:invalid"
			}
			body, _ := json.Marshal(changed)
			if _, err := host.ReadApplicationAttestorHostSelection(context.Background(), path, write(body)); err == nil {
				t.Fatal("unbound or incomplete application selection admitted")
			}
		})
	}
}
