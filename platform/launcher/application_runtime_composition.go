//go:build linux || darwin

package launcher

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/localtls"
	"github.com/nats-io/nkeys"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// ApplicationAttestorHostSelection is supplied by explicit application setup.
// Expected references, key/credential paths, the credential digest and broker
// account/user keys precede admission; no request or broker reply selects them.
// AMUX-47 owns the persisted enrollment format that supplies these values.
type ApplicationAttestorHostSelection struct {
	Signer                             ApplicationSignerSelection
	CredentialsPath, CredentialsSHA256 string
	AccountPublicKey, UserPublicKey    string
	InitialGeneration                  uint64
	Connection                         ApplicationAttestorConnectionSelection
}

// ApplicationAttestorConnectionSelection pins an already enrolled application
// broker. It neither selects the kernel listener nor provisions another broker.
type ApplicationAttestorConnectionSelection struct {
	Endpoint              string `json:"endpoint"`
	ServerName            string `json:"serverName"`
	RootsPEM              string `json:"rootsPEM"`
	LeafCertificateSHA256 string `json:"leafCertificateSHA256"`
}

func (c ApplicationAttestorConnectionSelection) clientTrust() (*localtls.ClientTrust, error) {
	trust, err := localtls.NewClientTrust(localtls.Policy{Endpoint: c.Endpoint, ServerName: c.ServerName, RootsPEM: []byte(c.RootsPEM), LeafCertificateSHA256: c.LeafCertificateSHA256})
	if err != nil {
		return nil, applicationEvidenceError("connection_invalid", err)
	}
	return trust, nil
}

func (ApplicationAttestorHostSelection) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "[private application host selection]")
}
func (ApplicationAttestorHostSelection) MarshalJSON() ([]byte, error) {
	return nil, applicationEvidenceError("serialization_forbidden", nil)
}

type preparedApplicationAttestorHost struct {
	enrollment ApplicationAttestorNATSEnrollment
	signer     *EnrolledApplicationObservationSigner
}

func (p *preparedApplicationAttestorHost) close() error {
	if p == nil {
		return nil
	}
	clear(p.enrollment.Credentials)
	if p.signer != nil {
		return p.signer.Close()
	}
	return nil
}

func prepareApplicationAttestorHost(parent context.Context, host *EnrolledHostPolicy, selection ApplicationAttestorHostSelection) (prepared *preparedApplicationAttestorHost, failure error) {
	if parent == nil || parent.Err() != nil || host == nil || selection.Signer.OwnerUID != host.selection.OwnerUID || !reflect.DeepEqual(selection.Signer.WorkspaceRoots, host.selection.WorkspaceRoots) || !filepath.IsAbs(selection.CredentialsPath) || filepath.Clean(selection.CredentialsPath) != selection.CredentialsPath || !kernelStatusDigest.MatchString(selection.CredentialsSHA256) || selection.InitialGeneration == 0 || selection.InitialGeneration > applicationMaxGeneration {
		return nil, applicationEvidenceError("host_selection_invalid", nil)
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	server, _, err := host.BridgeServer()
	if err != nil {
		return nil, applicationEvidenceError("host_admission_failed", err)
	}
	if server.config.Kernel.TLS == nil || selection.Signer.KernelScope != server.config.Kernel.Scope {
		return nil, applicationEvidenceError("host_selection_invalid", nil)
	}
	applicationTrust, err := selection.Connection.clientTrust()
	if err != nil {
		return nil, err
	}
	if applicationTrust.Policy().Endpoint == server.config.Kernel.Endpoint {
		return nil, applicationEvidenceError("connection_is_infrastructure", nil)
	}
	signer, err := LoadApplicationObservationSigner(ctx, selection.Signer)
	if err != nil {
		return nil, err
	}
	owned := &preparedApplicationAttestorHost{signer: signer}
	defer func() {
		if failure != nil {
			failure = errors.Join(failure, owned.close())
			prepared = nil
		}
	}()
	root, err := openPrivateHostRoot(filepath.Dir(selection.CredentialsPath), selection.Signer.OwnerUID, selection.Signer.WorkspaceRoots)
	if err != nil {
		return nil, applicationEvidenceError("credential_store_invalid", err)
	}
	// Close this root before returning prepared ownership. No inherited receipt
	// writer has been adopted and no process or network connection exists yet.
	raw, readErr := readApplicationPrivateFile(ctx, root, filepath.Base(selection.CredentialsPath), selection.Signer.OwnerUID, 65536)
	closeErr := root.Close()
	if readErr != nil || closeErr != nil {
		clear(raw)
		return nil, applicationEvidenceError("credential_store_invalid", errors.Join(readErr, closeErr))
	}
	owned.enrollment.Credentials = raw
	sum := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != selection.CredentialsSHA256 {
		return nil, applicationEvidenceError("credential_binding_invalid", nil)
	}
	owned.enrollment = ApplicationAttestorNATSEnrollment{Scope: server.config.Kernel.Scope, OrganizationID: selection.Signer.Scope.OrganizationID, AuthorityID: selection.Signer.AuthorityID, UserPublicKey: selection.UserPublicKey, AccountPublicKey: selection.AccountPublicKey, ReplyPrefix: selection.Signer.ReplyPrefix, Credentials: raw, Trust: applicationTrust, ServerName: selection.Connection.ServerName, InitialGeneration: selection.InitialGeneration, Signer: signer}
	if _, err := admitApplicationAttestorCredential(owned.enrollment); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, applicationEvidenceError("deadline", ctx.Err())
	}
	return owned, nil
}

// RunWithApplicationAttestor composes and runs the installed host from an
// explicit application selection. This is the production host-route entry.
// It owns the admitted signing key through the host/application join and closes
// it on every return. Admission never enrolls a key or changes HOST permissions.
func (host *EnrolledHostPolicy) RunWithApplicationAttestor(parent context.Context, invocationID string, selection ApplicationAttestorHostSelection) (failure error) {
	return host.runWithApplicationAttestor(parent, invocationID, selection, nil)
}

func (host *EnrolledHostPolicy) runWithApplicationAttestor(parent context.Context, invocationID string, selection ApplicationAttestorHostSelection, configure func(*OwnerBridgeServer) error) (failure error) {
	if !ownerBridgeInvocation.MatchString(invocationID) {
		return applicationEvidenceError("invocation_invalid", nil)
	}
	prepared, err := prepareApplicationAttestorHost(parent, host, selection)
	if err != nil {
		return err
	}
	defer func() { failure = errors.Join(failure, prepared.close()) }()
	// The standard factory remains the sole inherited-writer admission path.
	// It runs only after all new private-key and credential checks succeed.
	server, budget, err := host.BridgeServerForInvocation(invocationID)
	if err != nil {
		return err
	}
	configured, err := server.WithApplicationAttestor(prepared.enrollment)
	if err != nil {
		return server.finishBootstrapReceipt(parent, err)
	}
	defer clear(configured.application.enrollment.Credentials)
	if configure != nil {
		if err := configure(configured); err != nil {
			return server.finishBootstrapReceipt(parent, err)
		}
	}
	startup, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	return configured.Run(startup, parent, invocationID)
}

// Keep private selection rendering closed even when nested in other diagnostic
// values. Public results may report only fixed admission/freshness categories.
var _ json.Marshaler = ApplicationAttestorHostSelection{}

// Closed product enrollment record; its schema and writer belong to AMUX-47.
// Paths and pins are local setup declarations, never application request data.
type applicationHostSelectionRecord struct {
	SchemaVersion     string                                 `json:"schemaVersion"`
	HostPolicy        string                                 `json:"hostPolicy"`
	OwnerUID          uint32                                 `json:"ownerUid"`
	Workspaces        []string                               `json:"workspaces"`
	KernelScope       protocol.Scope                         `json:"kernelScope"`
	KeyPath           string                                 `json:"keyPath"`
	Credentials       applicationHostCredentialRecord        `json:"credentials"`
	Application       applicationHostBindingRecord           `json:"application"`
	ReceiptTrust      applicationHostReceiptTrustRecord      `json:"receiptTrust"`
	InitialGeneration uint64                                 `json:"initialGeneration"`
	Connection        ApplicationAttestorConnectionSelection `json:"connection"`
}

type applicationHostCredentialRecord struct {
	Path             string `json:"path"`
	SHA256           string `json:"sha256"`
	AccountPublicKey string `json:"accountPublicKey"`
	UserPublicKey    string `json:"userPublicKey"`
	ReplyPrefix      string `json:"replyPrefix"`
}

type applicationHostBindingRecord struct {
	AuthorityID  string                  `json:"authorityId"`
	IdentityRef  OwnerIdentityReference  `json:"identityRef"`
	IssuerRef    OwnerIdentityReference  `json:"issuerRef"`
	TransportRef OwnerIdentityReference  `json:"transportRef"`
	PolicyRef    OwnerIdentityReference  `json:"policyRef"`
	WorkspaceRef *OwnerIdentityReference `json:"workspaceRef"`
	Scope        OwnerScope              `json:"scope"`
}

type applicationHostReceiptTrustRecord struct {
	IssuerRef                OwnerIdentityReference `json:"issuerRef"`
	PublicKey                string                 `json:"publicKey"`
	NotBefore                string                 `json:"notBefore"`
	ExpiresAt                string                 `json:"expiresAt"`
	MinimumAuthorityRevision uint64                 `json:"minimumAuthorityRevision"`
}

func applicationHostRecordFields(raw []byte) error {
	fields, err := applicationSignerObject(raw, 65536, "schemaVersion", "hostPolicy", "ownerUid", "workspaces", "kernelScope", "keyPath", "credentials", "application", "receiptTrust", "initialGeneration", "connection")
	if err != nil {
		return err
	}
	for _, check := range []struct {
		raw    []byte
		fields []string
	}{
		{fields["connection"], []string{"endpoint", "serverName", "rootsPEM", "leafCertificateSHA256"}},
		{fields["kernelScope"], []string{"hubId", "instanceId", "profileId", "assemblyDigest", "releaseManifestDigest", "releaseVersion"}},
		{fields["credentials"], []string{"path", "sha256", "accountPublicKey", "userPublicKey", "replyPrefix"}},
		{fields["application"], []string{"authorityId", "identityRef", "issuerRef", "transportRef", "policyRef", "workspaceRef", "scope"}},
		{fields["receiptTrust"], []string{"issuerRef", "publicKey", "notBefore", "expiresAt", "minimumAuthorityRevision"}},
	} {
		if _, err := applicationSignerObject(check.raw, 65536, check.fields...); err != nil {
			return err
		}
	}
	var application, trust map[string]json.RawMessage
	json.Unmarshal(fields["application"], &application)
	json.Unmarshal(fields["receiptTrust"], &trust)
	for _, ref := range []json.RawMessage{application["identityRef"], application["issuerRef"], application["transportRef"], application["policyRef"], trust["issuerRef"]} {
		if _, err := applicationSignerObject(ref, 65536, "id", "ownerHubId", "revision"); err != nil {
			return err
		}
	}
	if !bytes.Equal(bytes.TrimSpace(application["workspaceRef"]), []byte("null")) {
		if _, err := applicationSignerObject(application["workspaceRef"], 65536, "id", "ownerHubId", "revision"); err != nil {
			return err
		}
	}
	if _, err := applicationSignerObject(application["scope"], 65536, "organizationId", "projectId", "workspaceId"); err != nil {
		return err
	}
	return nil
}

// ReadApplicationAttestorHostSelection admits the exact private record selected
// by the native host route. The digest is retained separately by setup. The
// approved host policy and workspace roots remain external admission inputs.
func (host *EnrolledHostPolicy) ReadApplicationAttestorHostSelection(parent context.Context, path, expectedDigest string) (selected ApplicationAttestorHostSelection, failure error) {
	if host == nil || parent == nil || parent.Err() != nil || !applicationFileReference(path) || !kernelStatusDigest.MatchString(expectedDigest) {
		return selected, applicationEvidenceError("host_selection_invalid", nil)
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	root, err := openPrivateHostRoot(filepath.Dir(path), host.selection.OwnerUID, host.selection.WorkspaceRoots)
	if err != nil {
		return selected, applicationEvidenceError("host_selection_invalid", err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			selected = ApplicationAttestorHostSelection{}
			failure = applicationEvidenceError("selection_cleanup_failed", errors.Join(failure, err))
		}
	}()
	raw, err := readApplicationPrivateFile(ctx, root, filepath.Base(path), host.selection.OwnerUID, 65536)
	if err != nil {
		return selected, applicationEvidenceError("host_selection_invalid", err)
	}
	defer clear(raw)
	sum := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != expectedDigest || applicationHostRecordFields(raw) != nil {
		return selected, applicationEvidenceError("host_selection_invalid", nil)
	}
	var record applicationHostSelectionRecord
	if protocol.DecodeClosedJSON(raw, &record, 65536) != nil || record.SchemaVersion != "1.0.0" || record.HostPolicy != host.selection.Path || record.OwnerUID != host.selection.OwnerUID || !reflect.DeepEqual(record.Workspaces, host.selection.WorkspaceRoots) || !applicationFileReference(record.KeyPath) || !applicationFileReference(record.Credentials.Path) || !kernelStatusDigest.MatchString(record.Credentials.SHA256) || !nkeys.IsValidPublicAccountKey(record.Credentials.AccountPublicKey) || !nkeys.IsValidPublicUserKey(record.Credentials.UserPublicKey) || !applicationReplyPrefix.MatchString(record.Credentials.ReplyPrefix) || record.InitialGeneration == 0 || record.InitialGeneration > applicationMaxGeneration {
		return selected, applicationEvidenceError("host_selection_invalid", nil)
	}
	config, _, err := host.Load()
	if err != nil || record.KernelScope != config.Kernel.Scope {
		return selected, applicationEvidenceError("host_selection_binding_invalid", err)
	}
	if _, err := record.Connection.clientTrust(); err != nil {
		return selected, err
	}
	public, err := base64.RawURLEncoding.DecodeString(record.ReceiptTrust.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(public) != record.ReceiptTrust.PublicKey || !ownerBridgeTimestamp.MatchString(record.ReceiptTrust.NotBefore) || !ownerBridgeTimestamp.MatchString(record.ReceiptTrust.ExpiresAt) {
		return selected, applicationEvidenceError("receipt_trust_unavailable", err)
	}
	before, e1 := time.Parse(time.RFC3339Nano, record.ReceiptTrust.NotBefore)
	expiry, e2 := time.Parse(time.RFC3339Nano, record.ReceiptTrust.ExpiresAt)
	if e1 != nil || e2 != nil {
		return selected, applicationEvidenceError("receipt_trust_unavailable", errors.Join(e1, e2))
	}
	signer := ApplicationSignerSelection{KeyPath: record.KeyPath, OwnerUID: host.selection.OwnerUID, WorkspaceRoots: append([]string(nil), host.selection.WorkspaceRoots...), KernelScope: record.KernelScope, AuthorityID: record.Application.AuthorityID, IdentityRef: record.Application.IdentityRef, IssuerRef: record.Application.IssuerRef, TransportRef: record.Application.TransportRef, PolicyRef: record.Application.PolicyRef, WorkspaceRef: record.Application.WorkspaceRef, Scope: record.Application.Scope, ReplyPrefix: record.Credentials.ReplyPrefix, ReceiptTrust: ApplicationReceiptTrust{Issuer: record.ReceiptTrust.IssuerRef, PublicKey: public, NotBefore: before, ExpiresAt: expiry, MinimumAuthorityRevision: record.ReceiptTrust.MinimumAuthorityRevision}}
	if err := validateApplicationSignerSelection(signer, time.Now()); err != nil {
		return selected, err
	}
	if ctx.Err() != nil {
		return selected, applicationEvidenceError("deadline", ctx.Err())
	}
	return ApplicationAttestorHostSelection{Signer: signer, CredentialsPath: record.Credentials.Path, CredentialsSHA256: record.Credentials.SHA256, AccountPublicKey: record.Credentials.AccountPublicKey, UserPublicKey: record.Credentials.UserPublicKey, InitialGeneration: record.InitialGeneration, Connection: record.Connection}, nil
}

func applicationFileReference(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && len(path) <= 4096 && strings.IndexFunc(path, func(r rune) bool { return r < 32 || r == 127 }) < 0
}
