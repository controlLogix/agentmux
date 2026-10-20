package plugins

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type nativeConfigurationWatchWireExchange struct {
	*nativeConfigurationTestExchange
	close func(context.Context, string, []byte) ([]byte, error)
}

func TestNativeConfigurationWatchCleanupAdmissionSizeBoundary(t *testing.T) {
	w, _, _ := configurationWatchCleanupFixture(t)
	original := w.original
	withVersion := func(size int) nativeConfigurationWatchCloseClaims {
		c := original
		c.Owner.Pin.Version = strings.Repeat("1", size) + ".0.0"
		return c
	}
	low, high := 1, nativeAuthorityLimit
	for low+1 < high {
		middle := (low + high) / 2
		if nativeConfigurationWatchRepresentable(withVersion(middle)) {
			low = middle
		} else {
			high = middle
		}
	}
	for _, size := range []int{low - 1, low, high} {
		c := withVersion(size)
		if nativeAuthoritySchema("owner", contextJSON(c.Owner)) != nil {
			t.Fatal("boundary fixture is not an admitted owner shape")
		}
		if nativeConfigurationWatchRepresentable(c) != (size <= low) {
			t.Fatal("watch cleanup representability boundary was not enforced")
		}
	}
	if low < 1000 {
		t.Fatal("ordinary owner shape was unnecessarily restricted")
	}
}

func TestNativeConfigurationWatchCleanupSizePythonParity(t *testing.T) {
	python := os.Getenv("AGENTMUX_NATIVE_AUTHORITY_PYTHON")
	if python == "" {
		t.Skip("prepared Python required for configuration watch sizing parity")
	}
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	vectorRaw, err := os.ReadFile(filepath.Join(repo, "tests", "contracts", "vectors", "configuration-watch-close-sizing.json"))
	if err != nil {
		t.Fatal("shared watch sizing vector unavailable")
	}
	var vector struct {
		Binding              nativeConfigurationWatchCloseClaims `json:"binding"`
		MaximumVersionDigits int                                 `json:"maximumVersionDigits"`
		ProofLimit           int                                 `json:"proofLimit"`
		ConfirmationLimit    int                                 `json:"confirmationLimit"`
	}
	if json.Unmarshal(vectorRaw, &vector) != nil || vector.MaximumVersionDigits < 2 || vector.ProofLimit != nativeConfigurationJoinedProofLimit || vector.ConfirmationLimit != nativeAuthorityLimit {
		t.Fatal("shared watch sizing vector invalid")
	}
	inputs := make([]nativeConfigurationWatchCloseClaims, 0, 4)
	for _, size := range []int{1, vector.MaximumVersionDigits - 1, vector.MaximumVersionDigits, vector.MaximumVersionDigits + 1} {
		c := vector.Binding
		c.Purpose = "agentmux-configuration-watch-close-v1"
		c.Owner.Pin.Version = strings.Repeat("1", size) + ".0.0"
		inputs = append(inputs, c)
	}
	const script = `import base64,json,sys
from state_owner.configuration_watch_control import _sizing_frames
results=[]
for binding in json.load(sys.stdin):
    proof,confirmation=_sizing_frames(binding)
    results.append({'proofBytes':len(proof),'confirmationBytes':len(confirmation),'accepted':len(proof)<=12288 and len(base64.b64encode(proof))<=16384 and len(confirmation)<=65536})
print(json.dumps(results))
`
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-c", script)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(repo, "sdk", "python")+string(os.PathListSeparator)+repo, "PYTHONDONTWRITEBYTECODE=1")
	cmd.Stdin = bytes.NewReader(contextJSON(inputs))
	raw, err := cmd.Output()
	if err != nil || len(raw) > 4096 {
		t.Fatal("Python watch sizing parity did not return bounded results")
	}
	var results []struct {
		ProofBytes        int  `json:"proofBytes"`
		ConfirmationBytes int  `json:"confirmationBytes"`
		Accepted          bool `json:"accepted"`
	}
	if json.Unmarshal(raw, &results) != nil || len(results) != len(inputs) {
		t.Fatal("Python watch sizing parity returned invalid results")
	}
	for i, c := range inputs {
		proof, confirmation, err := nativeConfigurationWatchSizingFrames(c)
		if err != nil || len(proof) != results[i].ProofBytes || len(confirmation) != results[i].ConfirmationBytes || nativeConfigurationWatchRepresentable(c) != results[i].Accepted {
			t.Fatal("Go and Python watch cleanup size admission disagree")
		}
		if results[i].Accepted != (i < 3) || i == 2 && len(proof) != vector.ProofLimit {
			t.Fatal("shared exact watch cleanup size boundary changed")
		}
	}
}

func (e *nativeConfigurationWatchWireExchange) ExchangeConfigurationWatchClose(ctx context.Context, reply string, raw []byte) ([]byte, error) {
	return e.close(ctx, reply, raw)
}

func configurationWatchCleanupFixture(t *testing.T) (*nativeConfigurationWatchClose, *nativeConfigurationWireFixture, *nativeConfigurationWatchWireExchange) {
	t.Helper()
	f := configurationWireFixture(t)
	a := f.authority.authority
	a.client.options.ReplyPrefix = "_INBOX.configurationfixture"
	raw := f.request(t, "configuration-watch", f.revision)
	var envelope map[string]any
	json.Unmarshal(raw, &envelope)
	claims := envelope["ingressAttestation"].(map[string]any)["claims"].(map[string]any)
	claims["authenticatedTransportRef"] = a.client.options.RequestSigningRef
	signed, err := nativeAuthoritySign(contextJSON(claims), f.authority.response)
	if err != nil {
		t.Fatal(err)
	}
	envelope["ingressAttestation"] = json.RawMessage(signed)
	exchange := &nativeConfigurationWatchWireExchange{nativeConfigurationTestExchange: &nativeConfigurationTestExchange{}}
	input := NativeConfigurationClientBinding{Binding: f.binding, Exchange: exchange, ReplyPrefix: a.client.options.ReplyPrefix}
	cleanup, err := a.prepareConfigurationWatchCleanup(context.Background(), contextJSON(envelope), input, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	return cleanup.(*nativeConfigurationWatchClose), f, exchange
}

func watchCleanupReply(t *testing.T, w *nativeConfigurationWatchClose, f *nativeConfigurationWireFixture, request []byte, change func(map[string]any)) []byte {
	t.Helper()
	var wanted nativeConfigurationWatchCloseClaims
	if json.Unmarshal(fieldsForClaim(request, "claims"), &wanted) != nil {
		t.Fatal("bad cleanup request")
	}
	claims := map[string]any{"purpose": "agentmux-configuration-watch-close-response-v1", "requestId": wanted.RequestID, "profileId": wanted.ProfileID, "hubId": wanted.HubID, "authorityId": wanted.AuthorityID, "replySubject": wanted.ReplySubject, "owner": wanted.Owner, "configurationRef": wanted.ConfigurationRef, "operationId": wanted.OperationID, "cancellationRef": wanted.CancellationRef, "watchRequestDigest": wanted.WatchRequestDigest, "requestDigest": nativeAuthorityDigestMustCanonical(request), "requestSigningKeyRef": wanted.SigningKeyRef, "requestPublicKey": base64.RawURLEncoding.EncodeToString(w.publicKey), "watchExpiresAt": nativeAuthorityStamp(w.watchExpiresAt), "signingKeyRef": f.binding.Service.SigningKeyRef, "authorityRef": ContextReference{"native_authority", "context_hub", 7}, "issuedAt": nativeAuthorityStamp(time.Now()), "validUntil": wanted.ExpiresAt, "joined": true, "receiptConfirmed": wanted.JoinedResponseBytes != ""}
	if change != nil {
		change(claims)
	}
	raw, err := nativeAuthoritySign(contextJSON(claims), f.authority.response)
	if err != nil {
		t.Fatal(err)
	}
	if change == nil && nativeAuthoritySchema("configuration-watch-close-response", raw) != nil {
		t.Fatal("cleanup response fixture does not match canonical schema")
	}
	canonical, err := nativeAuthorityCanonical(raw)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func TestNativeConfigurationWatchCleanupRetriesLostRepliesWithOriginalProof(t *testing.T) {
	for _, lost := range []string{"first", "confirmation"} {
		t.Run(lost, func(t *testing.T) {
			w, f, exchange := configurationWatchCleanupFixture(t)
			calls := 0
			var proof []byte
			exchange.close = func(_ context.Context, reply string, raw []byte) ([]byte, error) {
				calls++
				var wanted nativeConfigurationWatchCloseClaims
				json.Unmarshal(fieldsForClaim(raw, "claims"), &wanted)
				if wanted.ReplySubject != reply || wanted.WatchRequestDigest != w.original.WatchRequestDigest {
					t.Fatal("cleanup changed original request or reply binding")
				}
				if wanted.JoinedResponseBytes != "" {
					got, err := base64.StdEncoding.Strict().DecodeString(wanted.JoinedResponseBytes)
					if err != nil || !bytes.Equal(got, proof) {
						t.Fatal("confirmation did not retain exact verified original proof")
					}
				}
				response := watchCleanupReply(t, w, f, raw, nil)
				if wanted.JoinedResponseBytes == "" {
					proof = bytes.Clone(response)
				}
				if lost == "first" && calls == 1 || lost == "confirmation" && calls == 2 {
					return nil, errors.New("original reply lost")
				}
				return response, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if w.Close(ctx) == nil {
				t.Fatal("lost reply reported joined")
			}
			// Cleanup uses the original admitted key after business authority ends.
			f.authority.keys.revoked = true
			if err := w.Close(ctx); err != nil {
				t.Fatal("original cleanup could not recover after lost reply and revocation")
			}
			if calls != 3 {
				t.Fatal("cleanup did not resume the original handshake")
			}
		})
	}
}

func TestNativeConfigurationWatchCleanupRejectsInvalidJoinProof(t *testing.T) {
	for _, change := range []string{"joined", "owner", "digest", "host-key", "expiry", "signer", "receipt"} {
		t.Run(change, func(t *testing.T) {
			w, f, exchange := configurationWatchCleanupFixture(t)
			exchange.close = func(_ context.Context, _ string, raw []byte) ([]byte, error) {
				response := watchCleanupReply(t, w, f, raw, func(c map[string]any) {
					switch change {
					case "joined":
						c["joined"] = false
					case "owner":
						owner := w.original.Owner
						owner.Generation++
						c["owner"] = owner
					case "digest":
						c["watchRequestDigest"] = "sha256:" + string(bytes.Repeat([]byte("a"), 64))
					case "host-key":
						c["requestPublicKey"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
					case "expiry":
						c["watchExpiresAt"] = nativeAuthorityStamp(w.watchExpiresAt.Add(time.Second))
					case "receipt":
						c["receiptConfirmed"] = true
					}
				})
				if change == "signer" {
					var err error
					response, err = nativeAuthoritySign(fieldsForClaim(response, "claims"), ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)))
					if err != nil {
						t.Fatal(err)
					}
					response, err = nativeAuthorityCanonical(response)
					if err != nil {
						t.Fatal(err)
					}
				}
				return response, nil
			}
			if w.Close(context.Background()) == nil || len(w.proof) != 0 {
				t.Fatal("invalid join proof accepted or retained")
			}
		})
	}
}
