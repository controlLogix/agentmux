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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/internal/wirejson"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

func applicationSignerTestSelection(now time.Time) (ApplicationSignerSelection, []byte, ed25519.PrivateKey) {
	ref := func(id string) OwnerIdentityReference {
		return OwnerIdentityReference{ID: id, OwnerHubID: "fixture_hub", Revision: 1}
	}
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	receiptSeed := make([]byte, 32)
	for i := range receiptSeed {
		receiptSeed[i] = byte(31 - i)
	}
	receipt := ed25519.NewKeyFromSeed(receiptSeed)
	s := ApplicationSignerSelection{OwnerUID: uint32(os.Geteuid()), KernelScope: protocol.Scope{HubID: "fixture_hub", ProfileID: "fixture_profile", InstanceID: "fixture_instance", AssemblyDigest: "sha256:" + strings.Repeat("a", 64), ReleaseManifestDigest: "sha256:" + strings.Repeat("b", 64), ReleaseVersion: "1.0.0"}, AuthorityID: "fixture_authority", IdentityRef: ref("attestor_identity"), IssuerRef: ref("attestor_issuer"), TransportRef: ref("attestor_transport"), PolicyRef: ref("application_policy"), Scope: OwnerScope{OrganizationID: "fixture_org"}, ReplyPrefix: "_INBOX.abcdefghijklmnop", ReceiptTrust: ApplicationReceiptTrust{Issuer: ref("identity_issuer"), PublicKey: receipt.Public().(ed25519.PublicKey), NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), MinimumAuthorityRevision: 1}}
	raw, _ := json.Marshal(applicationAttestorKeyMaterial{Purpose: "agentmux-application-attestor-key-v1", Seed: base64.StdEncoding.EncodeToString(seed), HubID: s.KernelScope.HubID, ProfileID: s.KernelScope.ProfileID, AuthorityID: s.AuthorityID, InstanceID: s.KernelScope.InstanceID, IdentityRef: s.IdentityRef, IssuerRef: s.IssuerRef, TransportRef: s.TransportRef})
	return s, raw, receipt
}

func applicationSignerTestRequest(t *testing.T) (*EnrolledApplicationObservationSigner, []byte, ed25519.PrivateKey, map[string]any) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	selection, material, receiptKey := applicationSignerTestSelection(now)
	signer, err := applicationSignerFromMaterial(material, selection, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { signer.Close() })
	observation, err := signer.signObservation(selection.KernelScope, 2, strings.Repeat("d", 64), now, now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	request, err := signer.update(context.Background(), "refresh", 2, strings.Repeat("d", 64), observation, "fixture_request", selection.ReplyPrefix+".fixture_reply", now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ := wirejson.Canonical(request, 65536)
	digest := sha256.Sum256(canonical)
	receipt := map[string]any{"purpose": "agentmux-application-observation-receipt-v1", "requestId": "fixture_request", "hubId": selection.KernelScope.HubID, "profileId": selection.KernelScope.ProfileID, "authorityId": selection.AuthorityID, "requestDigest": "sha256:" + hex.EncodeToString(digest[:]), "action": "refresh", "generation": 2, "lifetimeId": strings.Repeat("d", 64), "signingKeyRef": selection.ReceiptTrust.Issuer, "authorityRef": OwnerIdentityReference{ID: selection.AuthorityID, OwnerHubID: selection.KernelScope.HubID, Revision: 2}, "issuedAt": bridgeTime(time.Now()), "validUntil": bridgeTime(now.Add(2 * time.Second))}
	return signer, request, receiptKey, receipt
}

func TestApplicationSignerReceiptBindingAndReplay(t *testing.T) {
	signer, request, key, claims := applicationSignerTestRequest(t)
	receipt, err := applicationSignedWrapper(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	if err = signer.VerifyReceipt(context.Background(), receipt, request); err != nil {
		t.Fatal(err)
	}
	if err = signer.VerifyReceipt(context.Background(), receipt, request); err == nil {
		t.Fatal("receipt replay admitted")
	}
	for _, fault := range []string{"requestId", "hubId", "profileId", "authorityId", "requestDigest", "action", "generation", "lifetimeId", "signingKeyRef", "authorityRef", "issuedAt", "validUntil", "extra", "wrong-key", "changed-request"} {
		t.Run(fault, func(t *testing.T) {
			signer, request, key, claims := applicationSignerTestRequest(t)
			switch fault {
			case "generation":
				claims[fault] = 3
			case "signingKeyRef":
				claims[fault] = OwnerIdentityReference{ID: "other_issuer", OwnerHubID: "fixture_hub", Revision: 1}
			case "authorityRef":
				claims[fault] = OwnerIdentityReference{ID: "fixture_authority", OwnerHubID: "fixture_hub", Revision: 0}
			case "issuedAt":
				claims[fault] = bridgeTime(time.Now().Add(time.Minute))
			case "validUntil":
				claims[fault] = bridgeTime(time.Now().Add(-time.Minute))
			case "extra":
				claims[fault] = "PRIVATE_SENTINEL"
			case "wrong-key":
				key = ed25519.NewKeyFromSeed(make([]byte, 32))
			case "changed-request":
				request = append(bytes.Clone(request), ' ')
			default:
				claims[fault] = "changed"
			}
			receipt, err := applicationSignedWrapper(claims, key)
			if err != nil {
				t.Fatal(err)
			}
			if err = signer.VerifyReceipt(context.Background(), receipt, request); err == nil {
				t.Fatal("incorrect receipt admitted")
			}
		})
	}
}

func TestApplicationSignerClosedStoreAndExpectedBinding(t *testing.T) {
	now := time.Now()
	selection, raw, _ := applicationSignerTestSelection(now)
	for _, fault := range []string{"seed", "purpose", "hubId", "profileId", "authorityId", "instanceId", "identityRef", "issuerRef", "transportRef", "unknown", "missing-ref-field"} {
		t.Run(fault, func(t *testing.T) {
			var material map[string]any
			json.Unmarshal(raw, &material)
			switch fault {
			case "identityRef", "issuerRef", "transportRef":
				material[fault] = OwnerIdentityReference{ID: "other_ref", OwnerHubID: "fixture_hub", Revision: 1}
			case "missing-ref-field":
				delete(material["issuerRef"].(map[string]any), "revision")
			default:
				material[fault] = "changed"
			}
			changed, _ := json.Marshal(material)
			if signer, err := applicationSignerFromMaterial(changed, selection, now); err == nil {
				signer.Close()
				t.Fatal("unadmitted store binding accepted")
			}
		})
	}
	signer, err := applicationSignerFromMaterial(raw, selection, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, signer), "seed") || strings.Contains(fmt.Sprintf(format, signer), base64.StdEncoding.EncodeToString(signer.private.Seed())) {
			t.Fatal("private signer exposed")
		}
	}
	if _, err := json.Marshal(signer); err == nil {
		t.Fatal("signer serialized")
	}
	if _, err := signer.Refresh(context.Background(), &ApplicationRuntimeEvidence{}, "fixture_request", selection.ReplyPrefix+".reply"); err == nil {
		t.Fatal("request fields manufactured live evidence")
	}
	signer.Close()
	signer.Close()
	if len(signer.private) != 0 || !signer.closed {
		t.Fatal("signing key not consumed")
	}
}

func TestApplicationSignerEndKeepsExactExpiredObservation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	selection, raw, _ := applicationSignerTestSelection(now)
	signer, err := applicationSignerFromMaterial(raw, selection, now)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	old, err := signer.signObservation(selection.KernelScope, 2, strings.Repeat("d", 64), now.Add(-10*time.Second), now.Add(-7*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	signer.last = &signedApplicationObservation{generation: 2, lifetimeID: strings.Repeat("d", 64), raw: old}
	evidence := &ApplicationRuntimeEvidence{producer: &applicationRuntimeProducer{}, scope: selection.KernelScope, generation: 2, lifetimeID: strings.Repeat("d", 64), issuedAt: now.Add(-10 * time.Second), expiresAt: now.Add(-7 * time.Second)}
	request, err := signer.End(context.Background(), evidence, "fixture_end", selection.ReplyPrefix+".end_reply")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := applicationVerifyWrapper(request, signer.private.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	json.Unmarshal(claims, &fields)
	var text string
	json.Unmarshal(fields["observationBytes"], &text)
	nested, _ := base64.StdEncoding.DecodeString(text)
	if !bytes.Equal(nested, old) {
		t.Fatal("end replaced or refreshed expired evidence")
	}
	if _, err = signer.End(context.Background(), evidence, "duplicate_end", selection.ReplyPrefix+".end_reply"); err == nil {
		t.Fatal("end was silently retried")
	}
}

func TestApplicationSignerProtectedFileLoad(t *testing.T) {
	now := time.Now()
	selection, raw, _ := applicationSignerTestSelection(now)
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(base, "keys")
	workspace := filepath.Join(base, "workspace")
	if os.Mkdir(directory, 0700) != nil || os.Mkdir(workspace, 0700) != nil {
		t.Fatal("private directories unavailable")
	}
	selection.KeyPath = filepath.Join(directory, "attestor.json")
	selection.WorkspaceRoots = []string{workspace}
	if os.WriteFile(selection.KeyPath, raw, 0600) != nil {
		t.Fatal("private key unavailable")
	}
	signer, err := LoadApplicationObservationSigner(context.Background(), selection)
	if err != nil {
		t.Fatal("native key admission failed", err)
	}
	signer.Close()
	if os.Chmod(selection.KeyPath, 0644) != nil {
		t.Fatal("mode control unavailable")
	}
	if signer, err = LoadApplicationObservationSigner(context.Background(), selection); err == nil {
		signer.Close()
		t.Fatal("readable key admitted")
	}
}

func TestApplicationSignerPythonSDKVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/application-attestor-jcs.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		SeedHex string
		Vectors []struct {
			Claims json.RawMessage
			Signed string
		}
	}
	if json.Unmarshal(raw, &corpus) != nil || len(corpus.Vectors) != 3 {
		t.Fatal("application SDK vectors invalid")
	}
	seed, err := hex.DecodeString(corpus.SeedHex)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	for index, vector := range corpus.Vectors {
		result, err := applicationSignedWrapper(vector.Claims, key)
		if err != nil || string(result) != vector.Signed {
			t.Fatalf("Python SDK application signature %d differs: %v", index, err)
		}
		if _, err = applicationVerifyWrapper(result, key.Public().(ed25519.PublicKey)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestApplicationSignerTrustExpiryCancellationAndCopiedBindings(t *testing.T) {
	signer, request, key, claims := applicationSignerTestRequest(t)
	receipt, err := applicationSignedWrapper(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if signer.VerifyReceipt(cancelled, receipt, request) == nil {
		t.Fatal("cancelled verification admitted")
	}
	if len(signer.pendingRequest) == 0 {
		t.Fatal("cancellation consumed the outstanding request")
	}
	signer.selection.ReceiptTrust.ExpiresAt = time.Now().Add(-time.Second)
	if signer.VerifyReceipt(context.Background(), receipt, request) == nil {
		t.Fatal("expired issuer trust admitted")
	}
	now := time.Now()
	selection, material, _ := applicationSignerTestSelection(now)
	project := "fixture_project"
	selection.Scope.ProjectID = &project
	workspace := OwnerIdentityReference{ID: "fixture_workspace", OwnerHubID: "fixture_hub", Revision: 1}
	selection.WorkspaceRef = &workspace
	copied, err := applicationSignerFromMaterial(material, selection, now)
	if err != nil {
		t.Fatal(err)
	}
	defer copied.Close()
	selection.ReceiptTrust.PublicKey[0] ^= 255
	project = "changed_project"
	workspace.Revision = 2
	if *copied.selection.Scope.ProjectID != "fixture_project" || copied.selection.WorkspaceRef.Revision != 1 || bytes.Equal(copied.selection.ReceiptTrust.PublicKey, selection.ReceiptTrust.PublicKey) {
		t.Fatal("caller mutation changed admitted signer binding")
	}
}

func TestApplicationSignerRejectsAuthorityRevisionRollback(t *testing.T) {
	signer, request, key, claims := applicationSignerTestRequest(t)
	receipt, err := applicationSignedWrapper(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	if err = signer.VerifyReceipt(context.Background(), receipt, request); err != nil {
		t.Fatal(err)
	}
	oldClaims, err := applicationVerifyWrapper(request, signer.private.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	var old map[string]json.RawMessage
	json.Unmarshal(oldClaims, &old)
	var encoded string
	json.Unmarshal(old["observationBytes"], &encoded)
	observation, _ := base64.StdEncoding.DecodeString(encoded)
	now := time.Now().UTC().Truncate(time.Microsecond)
	later, err := signer.update(context.Background(), "refresh", 2, strings.Repeat("d", 64), observation, "later_request", signer.selection.ReplyPrefix+".later_reply", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ := wirejson.Canonical(later, 65536)
	digest := sha256.Sum256(canonical)
	claims["requestId"] = "later_request"
	claims["requestDigest"] = "sha256:" + hex.EncodeToString(digest[:])
	claims["authorityRef"] = OwnerIdentityReference{ID: signer.selection.AuthorityID, OwnerHubID: "fixture_hub", Revision: 1}
	claims["issuedAt"] = bridgeTime(time.Now())
	claims["validUntil"] = bridgeTime(now.Add(500 * time.Millisecond))
	receipt, err = applicationSignedWrapper(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	if signer.VerifyReceipt(context.Background(), receipt, later) == nil {
		t.Fatal("older authority revision admitted after a newer signed receipt")
	}
}
