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
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/controlLogix/agentmux/platform/internal/wirejson"
	"github.com/controlLogix/agentmux/platform/kernel/assembly"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/privatefs"
)

// ApplicationReceiptTrust is independently enrolled issuer trust. No key or
// issuer reference is learned from an update, receipt or unsigned broker read.
type ApplicationReceiptTrust struct {
	Issuer                   OwnerIdentityReference
	PublicKey                ed25519.PublicKey
	NotBefore, ExpiresAt     time.Time
	MinimumAuthorityRevision uint64
}

// ApplicationSignerSelection supplies expected bindings separately from the key
// file being admitted. It does not create grants or enroll an application.
type ApplicationSignerSelection struct {
	KeyPath                              string
	OwnerUID                             uint32
	WorkspaceRoots                       []string
	KernelScope                          protocol.Scope
	AuthorityID                          string
	IdentityRef, IssuerRef, TransportRef OwnerIdentityReference
	PolicyRef                            OwnerIdentityReference
	WorkspaceRef                         *OwnerIdentityReference
	Scope                                OwnerScope
	ReplyPrefix                          string
	ReceiptTrust                         ApplicationReceiptTrust
}

type applicationAttestorKeyMaterial struct {
	Purpose      string                 `json:"purpose"`
	Seed         string                 `json:"seed"`
	HubID        string                 `json:"hubId"`
	ProfileID    string                 `json:"profileId"`
	AuthorityID  string                 `json:"authorityId"`
	InstanceID   string                 `json:"instanceId"`
	IdentityRef  OwnerIdentityReference `json:"identityRef"`
	IssuerRef    OwnerIdentityReference `json:"issuerRef"`
	TransportRef OwnerIdentityReference `json:"transportRef"`
}

type signedApplicationObservation struct {
	generation uint64
	lifetimeID string
	raw        []byte
	ended      bool
}

// EnrolledApplicationObservationSigner owns one admitted application key. The
// setup owner must Close it after the host Run and its application worker join.
type EnrolledApplicationObservationSigner struct {
	mu                sync.Mutex
	selection         ApplicationSignerSelection
	private           ed25519.PrivateKey
	last              *signedApplicationObservation
	authorityRevision uint64
	pendingRequest    []byte
	closed            bool
}

func (*EnrolledApplicationObservationSigner) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "[private enrolled application signer]")
}
func (*EnrolledApplicationObservationSigner) MarshalJSON() ([]byte, error) {
	return nil, applicationEvidenceError("serialization_forbidden", nil)
}

func applicationReferenceValid(ref OwnerIdentityReference, hub string) bool {
	return kernelStatusID.MatchString(ref.ID) && ref.OwnerHubID == hub && ref.Revision <= protocol.MaxRevision
}

func validateApplicationSignerSelection(s ApplicationSignerSelection, now time.Time) error {
	k := s.KernelScope
	if !kernelStatusID.MatchString(k.HubID) || !kernelStatusID.MatchString(k.ProfileID) || !kernelStatusID.MatchString(k.InstanceID) || !kernelStatusDigest.MatchString(k.AssemblyDigest) || !kernelStatusDigest.MatchString(k.ReleaseManifestDigest) || !kernelStatusVersion.MatchString(k.ReleaseVersion) || !kernelStatusID.MatchString(s.AuthorityID) || !applicationReplyPrefix.MatchString(s.ReplyPrefix) || !kernelStatusID.MatchString(s.Scope.OrganizationID) || !optionalStatusID(s.Scope.ProjectID) || !optionalStatusID(s.Scope.WorkspaceID) || !applicationReferenceValid(s.PolicyRef, k.HubID) || (s.WorkspaceRef != nil && !applicationReferenceValid(*s.WorkspaceRef, k.HubID)) {
		return applicationEvidenceError("signer_selection_invalid", nil)
	}
	for _, ref := range []OwnerIdentityReference{s.IdentityRef, s.IssuerRef, s.TransportRef, s.ReceiptTrust.Issuer} {
		if !applicationReferenceValid(ref, k.HubID) {
			return applicationEvidenceError("signer_selection_invalid", nil)
		}
	}
	trust := s.ReceiptTrust
	if len(trust.PublicKey) != ed25519.PublicKeySize || trust.NotBefore.IsZero() || trust.ExpiresAt.IsZero() || now.Before(trust.NotBefore) || !now.Before(trust.ExpiresAt) || trust.MinimumAuthorityRevision > protocol.MaxRevision {
		return applicationEvidenceError("receipt_trust_unavailable", nil)
	}
	return nil
}

// LoadApplicationObservationSigner reads AMUX-47's closed protected-store
// format. Loading never creates a key, grants membership or rotates enrollment.
func LoadApplicationObservationSigner(parent context.Context, s ApplicationSignerSelection) (signer *EnrolledApplicationObservationSigner, failure error) {
	if parent == nil || parent.Err() != nil {
		return nil, applicationEvidenceError("context_invalid", nil)
	}
	ctx, cancel := context.WithTimeout(parent, time.Second)
	defer cancel()
	if err := validateApplicationSignerSelection(s, time.Now()); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(s.KeyPath) || filepath.Clean(s.KeyPath) != s.KeyPath {
		return nil, applicationEvidenceError("key_store_invalid", nil)
	}
	root, err := openPrivateHostRoot(filepath.Dir(s.KeyPath), s.OwnerUID, s.WorkspaceRoots)
	if err != nil {
		return nil, applicationEvidenceError("key_store_invalid", err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			if signer != nil {
				signer.Close()
				signer = nil
			}
			failure = applicationEvidenceError("key_cleanup_failed", errors.Join(failure, err))
		}
	}()
	if ctx.Err() != nil {
		return nil, applicationEvidenceError("deadline", ctx.Err())
	}
	raw, err := readApplicationAttestorKey(ctx, root, filepath.Base(s.KeyPath), s.OwnerUID)
	if err != nil {
		return nil, applicationEvidenceError("key_store_invalid", err)
	}
	defer clear(raw)
	if ctx.Err() != nil {
		return nil, applicationEvidenceError("deadline", ctx.Err())
	}
	signer, failure = applicationSignerFromMaterial(raw, s, time.Now())
	if ctx.Err() != nil {
		if signer != nil {
			signer.Close()
			signer = nil
		}
		return nil, applicationEvidenceError("deadline", ctx.Err())
	}
	return signer, failure
}

func readApplicationAttestorKey(ctx context.Context, root *os.Root, name string, uid uint32) (raw []byte, failure error) {
	return readApplicationPrivateFile(ctx, root, name, uid, 4096)
}

func readApplicationPrivateFile(ctx context.Context, root *os.Root, name string, uid uint32, limit int64) (raw []byte, failure error) {
	if ctx == nil || ctx.Err() != nil || root == nil || limit < 1 || limit > 65536 {
		return nil, applicationEvidenceError("private_store_invalid", nil)
	}
	before, err := root.Lstat(name)
	if err != nil || !privateProfileInfo(before, uid, false) || before.Size() < 1 || before.Size() > limit {
		return nil, applicationEvidenceError("key_store_invalid", err)
	}
	file, err := assembly.OpenMember(root, name)
	if err != nil {
		return nil, applicationEvidenceError("key_store_invalid", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			clear(raw)
			raw = nil
			failure = applicationEvidenceError("key_cleanup_failed", errors.Join(failure, err))
		}
	}()
	opened, err := file.Stat()
	if err != nil || !privateProfileInfo(opened, uid, false) || !hostReadMetadataEqual(before, opened) || privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil || ctx.Err() != nil {
		return nil, applicationEvidenceError("key_store_invalid", err)
	}
	raw, err = io.ReadAll(io.LimitReader(file, limit+1))
	after, pathErr := root.Lstat(name)
	final, statErr := file.Stat()
	if err != nil || pathErr != nil || statErr != nil || int64(len(raw)) > limit || int64(len(raw)) != before.Size() || !privateProfileInfo(after, uid, false) || !privateProfileInfo(final, uid, false) || !hostReadMetadataEqual(opened, after) || !hostReadMetadataEqual(opened, final) || privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil || ctx.Err() != nil {
		clear(raw)
		return nil, applicationEvidenceError("key_store_changed", errors.Join(err, pathErr, statErr, ctx.Err()))
	}
	return raw, nil
}

// Only the admitted loader calls this decoder in production. It accepts no
// client observation or inferred reference as a signing binding.
func applicationSignerFromMaterial(raw []byte, s ApplicationSignerSelection, now time.Time) (*EnrolledApplicationObservationSigner, error) {
	if err := validateApplicationSignerSelection(s, now); err != nil {
		return nil, err
	}
	if _, err := applicationSignerObject(raw, 4096, "purpose", "seed", "hubId", "profileId", "authorityId", "instanceId", "identityRef", "issuerRef", "transportRef"); err != nil {
		return nil, err
	}
	var keyFields map[string]json.RawMessage
	json.Unmarshal(raw, &keyFields)
	for _, name := range []string{"identityRef", "issuerRef", "transportRef"} {
		if _, err := applicationSignerObject(keyFields[name], 4096, "id", "ownerHubId", "revision"); err != nil {
			return nil, err
		}
	}
	var material applicationAttestorKeyMaterial
	if protocol.DecodeClosedJSON(raw, &material, 4096) != nil || material.Purpose != "agentmux-application-attestor-key-v1" || material.HubID != s.KernelScope.HubID || material.ProfileID != s.KernelScope.ProfileID || material.InstanceID != s.KernelScope.InstanceID || material.AuthorityID != s.AuthorityID || material.IdentityRef != s.IdentityRef || material.IssuerRef != s.IssuerRef || material.TransportRef != s.TransportRef {
		return nil, applicationEvidenceError("key_binding_invalid", nil)
	}
	seed, err := base64.StdEncoding.DecodeString(material.Seed)
	if err != nil || len(seed) != ed25519.SeedSize || base64.StdEncoding.EncodeToString(seed) != material.Seed {
		clear(seed)
		return nil, applicationEvidenceError("key_store_invalid", nil)
	}
	defer clear(seed)
	s.WorkspaceRoots = append([]string(nil), s.WorkspaceRoots...)
	s.Scope = copyOwnerScope(s.Scope)
	if s.WorkspaceRef != nil {
		copyRef := *s.WorkspaceRef
		s.WorkspaceRef = &copyRef
	}
	s.ReceiptTrust.PublicKey = bytes.Clone(s.ReceiptTrust.PublicKey)
	return &EnrolledApplicationObservationSigner{selection: s, private: ed25519.NewKeyFromSeed(seed), authorityRevision: s.ReceiptTrust.MinimumAuthorityRevision}, nil
}

func applicationSignerObject(raw []byte, limit int, fields ...string) (map[string]json.RawMessage, error) {
	if wirejson.Validate(raw, limit) != nil {
		return nil, applicationEvidenceError("signer_wire_invalid", nil)
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil || len(object) != len(fields) {
		return nil, applicationEvidenceError("signer_wire_invalid", nil)
	}
	for _, field := range fields {
		if _, ok := object[field]; !ok {
			return nil, applicationEvidenceError("signer_wire_invalid", nil)
		}
	}
	return object, nil
}

func applicationSignedWrapper(claims any, key ed25519.PrivateKey) ([]byte, error) {
	raw, err := json.Marshal(claims)
	if err != nil {
		return nil, applicationEvidenceError("signer_wire_invalid", err)
	}
	canonical, err := wirejson.Canonical(raw, 65536)
	if err != nil {
		return nil, applicationEvidenceError("signer_wire_invalid", err)
	}
	wrapped, err := json.Marshal(map[string]any{"schemaVersion": "1.0.0", "algorithm": "Ed25519", "canonicalization": "RFC8785-JCS-UTF8", "claims": json.RawMessage(raw), "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, canonical))})
	if err != nil {
		return nil, applicationEvidenceError("signer_wire_invalid", err)
	}
	canonical, err = wirejson.Canonical(wrapped, 65536)
	if err != nil {
		return nil, applicationEvidenceError("signer_wire_invalid", err)
	}
	return canonical, nil
}

func applicationVerifyWrapper(raw []byte, key ed25519.PublicKey) ([]byte, error) {
	fields, err := applicationSignerObject(raw, 65536, "schemaVersion", "algorithm", "canonicalization", "claims", "signature")
	if err != nil {
		return nil, err
	}
	for field, want := range map[string]string{"schemaVersion": "1.0.0", "algorithm": "Ed25519", "canonicalization": "RFC8785-JCS-UTF8"} {
		var got string
		if json.Unmarshal(fields[field], &got) != nil || got != want {
			return nil, applicationEvidenceError("signature_invalid", nil)
		}
	}
	var text string
	if json.Unmarshal(fields["signature"], &text) != nil {
		return nil, applicationEvidenceError("signature_invalid", nil)
	}
	signature, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != text {
		return nil, applicationEvidenceError("signature_invalid", nil)
	}
	canonical, err := wirejson.Canonical(fields["claims"], 65536)
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, canonical, signature) {
		return nil, applicationEvidenceError("signature_invalid", err)
	}
	return fields["claims"], nil
}

func (s *EnrolledApplicationObservationSigner) usable(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || s.closed || len(s.private) != ed25519.PrivateKeySize {
		return applicationEvidenceError("signer_unavailable", nil)
	}
	return validateApplicationSignerSelection(s.selection, time.Now())
}

func (s *EnrolledApplicationObservationSigner) Refresh(ctx context.Context, e *ApplicationRuntimeEvidence, requestID, reply string) ([]byte, error) {
	if s == nil || !s.mu.TryLock() {
		return nil, applicationEvidenceError("signer_busy", nil)
	}
	defer s.mu.Unlock()
	if err := s.usable(ctx); err != nil {
		return nil, err
	}
	scope, generation, lifetime, issued, expires, err := e.Facts(ctx)
	if err != nil {
		return nil, err
	}
	if scope != s.selection.KernelScope || !kernelStatusID.MatchString(requestID) || !validApplicationReplySubject(s.selection.ReplyPrefix, reply) {
		return nil, applicationEvidenceError("signing_binding_invalid", nil)
	}
	if s.last != nil && (s.last.lifetimeID != lifetime || s.last.generation != generation) && !s.last.ended {
		return nil, applicationEvidenceError("generation_not_ended", nil)
	}
	if s.last != nil && s.last.lifetimeID == lifetime && s.last.ended {
		return nil, applicationEvidenceError("lifetime_ended", nil)
	}
	observation, err := s.signObservation(scope, generation, lifetime, issued, expires)
	if err != nil {
		return nil, err
	}
	request, err := s.update(ctx, "refresh", generation, lifetime, observation, requestID, reply, expires)
	if err != nil {
		return nil, err
	}
	if err = e.Recheck(ctx); err != nil {
		return nil, err
	}
	if s.last != nil {
		clear(s.last.raw)
	}
	s.last = &signedApplicationObservation{generation: generation, lifetimeID: lifetime, raw: observation}
	return request, nil
}

func (s *EnrolledApplicationObservationSigner) signObservation(scope protocol.Scope, generation uint64, lifetime string, issued, expires time.Time) ([]byte, error) {
	claims := map[string]any{"purpose": "agentmux-application-runtime-observation-v1", "hubId": scope.HubID, "profileId": scope.ProfileID, "instanceId": scope.InstanceID, "generation": generation, "lifetimeId": lifetime, "releaseDigest": scope.ReleaseManifestDigest, "policyRef": s.selection.PolicyRef, "workspaceRef": s.selection.WorkspaceRef, "scope": s.selection.Scope, "signingKeyRef": s.selection.IssuerRef, "issuedAt": bridgeTime(issued), "expiresAt": bridgeTime(expires)}
	return applicationSignedWrapper(claims, s.private)
}

func (s *EnrolledApplicationObservationSigner) End(ctx context.Context, e *ApplicationRuntimeEvidence, requestID, reply string) ([]byte, error) {
	if s == nil || !s.mu.TryLock() {
		return nil, applicationEvidenceError("signer_busy", nil)
	}
	defer s.mu.Unlock()
	if err := s.usable(ctx); err != nil {
		return nil, err
	}
	scope, generation, lifetime, err := e.Lifetime()
	if err != nil {
		return nil, err
	}
	if scope != s.selection.KernelScope || s.last == nil || s.last.generation != generation || s.last.lifetimeID != lifetime || s.last.ended {
		return nil, applicationEvidenceError("end_binding_invalid", nil)
	}
	request, err := s.update(ctx, "end", generation, lifetime, s.last.raw, requestID, reply, time.Now().Add(3*time.Second))
	if err == nil {
		s.last.ended = true
	}
	return request, err
}

func (s *EnrolledApplicationObservationSigner) update(ctx context.Context, action string, generation uint64, lifetime string, observation []byte, requestID, reply string, expiry time.Time) ([]byte, error) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	if !kernelStatusID.MatchString(requestID) || !validApplicationReplySubject(s.selection.ReplyPrefix, reply) || !now.Before(expiry) || expiry.Sub(now) > 5*time.Second {
		return nil, applicationEvidenceError("signing_binding_invalid", nil)
	}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expiry) {
		expiry = deadline
	}
	if !now.Before(expiry) {
		return nil, applicationEvidenceError("deadline", nil)
	}
	claims := map[string]any{"purpose": "agentmux-application-observation-update-v1", "requestId": requestID, "hubId": s.selection.KernelScope.HubID, "profileId": s.selection.KernelScope.ProfileID, "authorityId": s.selection.AuthorityID, "action": action, "generation": generation, "lifetimeId": lifetime, "transportRef": s.selection.TransportRef, "observationBytes": base64.StdEncoding.EncodeToString(observation), "replySubject": reply, "issuedAt": bridgeTime(now), "expiresAt": bridgeTime(expiry)}
	raw, err := applicationSignedWrapper(claims, s.private)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil || !time.Now().Before(expiry) {
		return nil, applicationEvidenceError("deadline", ctx.Err())
	}
	clear(s.pendingRequest)
	s.pendingRequest = bytes.Clone(raw)
	return raw, nil
}

func (s *EnrolledApplicationObservationSigner) VerifyReceipt(ctx context.Context, response, request []byte) error {
	if s == nil || !s.mu.TryLock() {
		return applicationEvidenceError("signer_busy", nil)
	}
	defer s.mu.Unlock()
	if err := s.usable(ctx); err != nil {
		return err
	}
	if len(s.pendingRequest) == 0 || !bytes.Equal(s.pendingRequest, request) {
		return applicationEvidenceError("receipt_binding_invalid", nil)
	}
	requestClaims, err := applicationVerifyWrapper(request, s.private.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}
	wanted, err := applicationSignerObject(requestClaims, 65536, "purpose", "requestId", "hubId", "profileId", "authorityId", "action", "generation", "lifetimeId", "transportRef", "observationBytes", "replySubject", "issuedAt", "expiresAt")
	if err != nil {
		return err
	}
	claimsRaw, err := applicationVerifyWrapper(response, s.selection.ReceiptTrust.PublicKey)
	if err != nil {
		return err
	}
	claims, err := applicationSignerObject(claimsRaw, 65536, "purpose", "requestId", "hubId", "profileId", "authorityId", "requestDigest", "action", "generation", "lifetimeId", "signingKeyRef", "authorityRef", "issuedAt", "validUntil")
	if err != nil {
		return err
	}
	for _, raw := range []json.RawMessage{claims["signingKeyRef"], claims["authorityRef"], wanted["transportRef"]} {
		if _, err := applicationSignerObject(raw, 65536, "id", "ownerHubId", "revision"); err != nil {
			return err
		}
	}
	for _, field := range []string{"requestId", "hubId", "profileId", "authorityId", "action", "generation", "lifetimeId"} {
		left, e1 := wirejson.Canonical(claims[field], 65536)
		right, e2 := wirejson.Canonical(wanted[field], 65536)
		if e1 != nil || e2 != nil || !bytes.Equal(left, right) {
			return applicationEvidenceError("receipt_binding_invalid", nil)
		}
	}
	var purpose, digest, reply, hub, profile, authority string
	var issuer, authorityRef, transport OwnerIdentityReference
	if json.Unmarshal(claims["purpose"], &purpose) != nil || purpose != "agentmux-application-observation-receipt-v1" || json.Unmarshal(claims["requestDigest"], &digest) != nil || protocol.DecodeClosedJSON(claims["signingKeyRef"], &issuer, 65536) != nil || issuer != s.selection.ReceiptTrust.Issuer || protocol.DecodeClosedJSON(claims["authorityRef"], &authorityRef, 65536) != nil || !applicationReferenceValid(authorityRef, s.selection.KernelScope.HubID) || authorityRef.ID != s.selection.AuthorityID || authorityRef.Revision < s.authorityRevision || json.Unmarshal(wanted["replySubject"], &reply) != nil || !validApplicationReplySubject(s.selection.ReplyPrefix, reply) || json.Unmarshal(wanted["hubId"], &hub) != nil || hub != s.selection.KernelScope.HubID || json.Unmarshal(wanted["profileId"], &profile) != nil || profile != s.selection.KernelScope.ProfileID || json.Unmarshal(wanted["authorityId"], &authority) != nil || authority != s.selection.AuthorityID || protocol.DecodeClosedJSON(wanted["transportRef"], &transport, 65536) != nil || transport != s.selection.TransportRef {
		return applicationEvidenceError("receipt_binding_invalid", nil)
	}
	canonical, err := wirejson.Canonical(request, 65536)
	sum := sha256.Sum256(canonical)
	if err != nil || digest != "sha256:"+hex.EncodeToString(sum[:]) {
		return applicationEvidenceError("receipt_digest_invalid", err)
	}
	var requestIssued, requestExpiry, issued, expiry string
	for field, destination := range map[string]*string{"issuedAt": &issued, "validUntil": &expiry} {
		if json.Unmarshal(claims[field], destination) != nil {
			return applicationEvidenceError("receipt_time_invalid", nil)
		}
	}
	if json.Unmarshal(wanted["issuedAt"], &requestIssued) != nil || json.Unmarshal(wanted["expiresAt"], &requestExpiry) != nil {
		return applicationEvidenceError("receipt_time_invalid", nil)
	}
	from, e1 := time.Parse(time.RFC3339Nano, requestIssued)
	until, e2 := time.Parse(time.RFC3339Nano, requestExpiry)
	at, e3 := time.Parse(time.RFC3339Nano, issued)
	end, e4 := time.Parse(time.RFC3339Nano, expiry)
	now := time.Now().UTC()
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || !ownerBridgeTimestamp.MatchString(requestIssued) || !ownerBridgeTimestamp.MatchString(requestExpiry) || !ownerBridgeTimestamp.MatchString(issued) || !ownerBridgeTimestamp.MatchString(expiry) || at.Before(from) || at.After(now) || !now.Before(end) || end.After(until) || until.Sub(from) > 5*time.Second || at.Before(s.selection.ReceiptTrust.NotBefore) || end.After(s.selection.ReceiptTrust.ExpiresAt) || ctx.Err() != nil {
		return applicationEvidenceError("receipt_time_invalid", nil)
	}
	s.authorityRevision = authorityRef.Revision
	clear(s.pendingRequest)
	s.pendingRequest = nil
	return nil
}

func (s *EnrolledApplicationObservationSigner) Close() error {
	if s == nil {
		return nil
	}
	if !s.mu.TryLock() {
		return applicationEvidenceError("signer_busy", nil)
	}
	defer s.mu.Unlock()
	if !s.closed {
		clear(s.private)
		s.private = nil
		clear(s.pendingRequest)
		s.pendingRequest = nil
		if s.last != nil {
			clear(s.last.raw)
			s.last = nil
		}
		s.closed = true
	}
	return nil
}
