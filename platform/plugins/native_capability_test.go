package plugins

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type nativeCapabilityTestKeys func(context.Context, NativeCapabilityServiceBinding) (NativeAuthorityKey, error)

func (f nativeCapabilityTestKeys) CurrentServiceKey(ctx context.Context, binding NativeCapabilityServiceBinding) (NativeAuthorityKey, error) {
	return f(ctx, binding)
}

type nativeCapabilityTestExchange func(context.Context, string, []byte) ([]byte, error)

func (f nativeCapabilityTestExchange) ExchangeCapability(ctx context.Context, reply string, raw []byte) ([]byte, error) {
	return f(ctx, reply, raw)
}

type nativeCapabilityFixture struct {
	authority  *nativeAuthorityFixture
	gateway    *NativeCapabilityGateway
	approved   ContextApprovedEnvelope
	serviceKey ed25519.PrivateKey
	service    NativeCapabilityServiceBinding
	mutate     func(map[string]any)
}

func newNativeCapabilityFixture(t *testing.T, changes ...func(*nativeAuthorityFixture)) *nativeCapabilityFixture {
	t.Helper()
	f := &nativeCapabilityFixture{authority: newNativeAuthorityFixture(t), serviceKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))}
	a := f.authority
	for _, change := range changes {
		change(a)
	}
	if _, err := a.authority.BindInstance(context.Background(), a.binding); err != nil {
		t.Fatal(err)
	}
	var op map[string]any
	_ = json.Unmarshal(fieldsForClaim(contextTestEnvelope("a"), "operation"), &op)
	op["deadline"] = nativeAuthorityStamp(time.Now().Add(time.Minute))
	payload := map[string]any{"resourceRef": ContextReference{"fixture_resource", "context_hub", 1}, "input": map[string]any{}}
	original := a.envelope(t, op, payload, "capability-storage-read")
	admitted, err := a.authority.AdmitOperation(context.Background(), a.binding.Owner, original)
	if err != nil {
		t.Fatal(err)
	}
	f.approved, err = a.authority.PrepareDomainCall(context.Background(), a.binding.Owner, admitted, ContextDomainCall{RequestID: "request_" + strings.Repeat("e", 64), BindingID: "owner", ContractID: "capability-storage-read", Payload: contextJSON(payload)})
	if err != nil {
		t.Fatal(err)
	}
	f.service = NativeCapabilityServiceBinding{ProfileID: "profile", HubID: "context_hub", ServiceID: "storage-owner", ServiceInstanceID: "storage_instance", ServiceIdentityRef: ContextReference{"storage_identity", "context_hub", 1}, SigningKeyRef: ContextReference{"storage_signer", "context_hub", 1}}
	route := NativeCapabilityRoute{BindingID: "owner", RequestContractID: "capability-storage-read", ReplyContractID: "capability-content-reply", Service: f.service}
	route.Keys = nativeCapabilityTestKeys(func(_ context.Context, binding NativeCapabilityServiceBinding) (NativeAuthorityKey, error) {
		if binding != f.service {
			t.Fatal("service key lookup lost enrolled association")
		}
		return NativeAuthorityKey{PublicKey: f.serviceKey.Public().(ed25519.PublicKey), NotBefore: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(time.Hour)}, nil
	})
	route.Exchange = nativeCapabilityTestExchange(func(_ context.Context, reply string, request []byte) ([]byte, error) {
		if nativeCapabilitySchema("capability-service-request", request) != nil {
			t.Fatal("service request schema invalid")
		}
		var claims map[string]any
		_ = json.Unmarshal(fieldsForClaim(request, "claims"), &claims)
		if claims["replySubject"] != reply {
			t.Fatal("service request redirected")
		}
		var sigText string
		_ = json.Unmarshal(fieldsForClaim(request, "signature"), &sigText)
		sig, _ := base64.RawURLEncoding.DecodeString(sigText)
		signed, _ := nativeAuthorityCanonicalLimit(fieldsForClaim(request, "claims"), nativeCapabilityRequestLimit)
		if !ed25519.Verify(a.response.Public().(ed25519.PublicKey), signed, sig) {
			t.Fatal("gateway replaced issuer preparation")
		}
		requestCanonical, _ := nativeAuthorityCanonicalLimit(request, nativeCapabilityRequestLimit)
		envelope, _ := base64.StdEncoding.DecodeString(claims["envelopeBytes"].(string))
		result := map[string]any{"purpose": "agentmux-capability-service-response-v1", "serviceIdentityRef": f.service.ServiceIdentityRef, "serviceInstanceId": f.service.ServiceInstanceID, "requestDigest": nativeAuthorityDigest(requestCanonical), "envelopeDigest": nativeAuthorityDigest(envelope), "signingKeyRef": f.service.SigningKeyRef, "authorityRef": a.authorityRef, "issuedAt": nativeAuthorityStamp(time.Now()), "validUntil": claims["validUntil"], "payload": map[string]any{"resourceRef": claims["resourceRef"], "data": base64.StdEncoding.EncodeToString([]byte("private owner content"))}}
		for _, name := range []string{"requestId", "profileId", "hubId", "authorityId", "serviceId", "requestContractId", "replyContractId", "operationId", "owner", "resourceRef", "scope", "replySubject"} {
			result[name] = claims[name]
		}
		if f.mutate != nil {
			f.mutate(result)
		}
		return nativeAuthoritySign(contextJSON(result), f.serviceKey)
	})
	f.gateway, err = NewNativeCapabilityGateway(a.authority, []NativeCapabilityRoute{route})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if f.gateway.Close(ctx) != nil {
			t.Error("capability gateway did not join")
		}
	})
	return f
}
func TestNativeCapabilityAuthenticatedReplyAndClone(t *testing.T) {
	f := newNativeCapabilityFixture(t)
	clone := f.approved.Clone()
	clone.Envelope[0] = ' '
	if f.approved.Envelope[0] == ' ' {
		t.Fatal("clone aliased original envelope")
	}
	clone = f.approved.Clone()
	clone.delivery.serviceRequest[0] = ' '
	if f.approved.delivery.serviceRequest[0] == ' ' {
		t.Fatal("clone aliased private delivery")
	}
	reply, err := f.gateway.Domain(context.Background(), f.approved.Clone())
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Data []byte `json:"data"`
	}
	if json.Unmarshal(reply, &payload) != nil || string(payload.Data) != "private owner content" {
		t.Fatal("authenticated content missing")
	}
	if _, err = f.gateway.Domain(context.Background(), ContextApprovedEnvelope{BindingID: f.approved.BindingID, Envelope: bytes.Clone(f.approved.Envelope)}); err == nil {
		t.Fatal("unprepared reconstructed envelope admitted")
	}
}
func TestNativeCapabilityRejectsReplyBindingChanges(t *testing.T) {
	changes := map[string]func(map[string]any){
		"request": func(c map[string]any) { c["requestId"] = "other" }, "profile": func(c map[string]any) { c["profileId"] = "other" }, "hub": func(c map[string]any) { c["hubId"] = "other" }, "authority": func(c map[string]any) { c["authorityId"] = "other" },
		"service": func(c map[string]any) { c["serviceId"] = "artifact-owner" }, "contract": func(c map[string]any) { c["requestContractId"] = "capability-artifact-read" }, "reply-contract": func(c map[string]any) { c["replyContractId"] = "capability-storage-write-reply" },
		"operation": func(c map[string]any) { c["operationId"] = "other" }, "owner": func(c map[string]any) { c["owner"].(map[string]any)["generation"] = 2 }, "resource": func(c map[string]any) { c["resourceRef"].(map[string]any)["id"] = "other" }, "scope": func(c map[string]any) { c["scope"].(map[string]any)["organizationId"] = "other" },
		"reply-route": func(c map[string]any) { c["replySubject"] = "_INBOX." + strings.Repeat("x", 32) }, "digest": func(c map[string]any) { c["requestDigest"] = "sha256:" + strings.Repeat("a", 64) }, "envelope": func(c map[string]any) { c["envelopeDigest"] = "sha256:" + strings.Repeat("a", 64) },
		"service-identity": func(c map[string]any) { c["serviceIdentityRef"] = ContextReference{"other", "context_hub", 1} }, "service-instance": func(c map[string]any) { c["serviceInstanceId"] = "other" }, "key": func(c map[string]any) { c["signingKeyRef"] = ContextReference{"other", "context_hub", 1} },
		"expired": func(c map[string]any) { c["validUntil"] = nativeAuthorityStamp(time.Now().Add(-time.Second)) }, "extended": func(c map[string]any) { c["validUntil"] = nativeAuthorityStamp(time.Now().Add(time.Minute)) }, "payload-schema": func(c map[string]any) { c["payload"] = map[string]any{"data": "private"} },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			f := newNativeCapabilityFixture(t)
			f.mutate = change
			if raw, err := f.gateway.Domain(context.Background(), f.approved); err == nil || raw != nil {
				t.Fatal("changed signed reply disclosed payload")
			}
		})
	}
}
func TestNativeCapabilityCloseRetainsOriginalCall(t *testing.T) {
	f := newNativeCapabilityFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	route := f.gateway.routes["owner"]
	route.Exchange = nativeCapabilityTestExchange(func(context.Context, string, []byte) ([]byte, error) {
		close(entered)
		<-release
		return nil, pluginError("fixture_unknown_outcome")
	})
	f.gateway.routes["owner"] = route
	result := make(chan error, 1)
	go func() { _, err := f.gateway.Domain(context.Background(), f.approved); result <- err }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if f.gateway.Close(ctx) == nil {
		t.Fatal("unfinished original call was released")
	}
	close(release)
	if <-result == nil {
		t.Fatal("canceled effect became success")
	}
	joined, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if f.gateway.Close(joined) != nil {
		t.Fatal("original call did not join")
	}
}
func TestNativeCapabilityReplyExpiresDuringKeyLookup(t *testing.T) {
	f := newNativeCapabilityFixture(t)
	f.mutate = func(c map[string]any) { c["validUntil"] = nativeAuthorityStamp(time.Now().Add(time.Second)) }
	route := f.gateway.routes["owner"]
	original := route.Keys
	route.Keys = nativeCapabilityTestKeys(func(ctx context.Context, binding NativeCapabilityServiceBinding) (NativeAuthorityKey, error) {
		key, err := original.CurrentServiceKey(ctx, binding)
		f.authority.authority.client.now = func() time.Time { return time.Now().Add(2 * time.Second) }
		return key, err
	})
	f.gateway.routes["owner"] = route
	if raw, err := f.gateway.Domain(context.Background(), f.approved); err == nil || raw != nil {
		t.Fatal("reply expired during service trust lookup")
	}
}
func TestNativeCapabilitySchemaCopiesAndFrameLimit(t *testing.T) {
	for _, name := range nativeCapabilitySchemaNames {
		original, err := os.ReadFile(filepath.Join("../../contracts/v1/schemas", name+".schema.json"))
		if err != nil {
			t.Fatal(err)
		}
		copy, err := nativeCapabilityResources.ReadFile("schemas/" + name + ".schema.json")
		if err != nil || !bytes.Equal(original, copy) {
			t.Fatal("capability shared schema copy drift", name)
		}
	}
	large := contextJSON(map[string]string{"frame": strings.Repeat("x", 70*1024)})
	if _, err := nativeAuthorityCanonical(large); err == nil {
		t.Fatal("authority frame limit expanded")
	}
	if _, err := nativeAuthorityCanonicalLimit(large, nativeCapabilityRequestLimit); err != nil {
		t.Fatal("bounded capability transport frame refused")
	}
	oversized := contextJSON(map[string]string{"frame": strings.Repeat("x", nativeCapabilityRequestLimit)})
	if _, err := nativeAuthorityCanonicalLimit(oversized, nativeCapabilityRequestLimit); err == nil {
		t.Fatal("oversized capability frame admitted")
	}
}

func TestNativeCapabilityRefreshesServiceTrustAfterAuthorityWait(t *testing.T) {
	f := newNativeCapabilityFixture(t)
	route := f.gateway.routes["owner"]
	original := route.Keys
	lookups := 0
	route.Keys = nativeCapabilityTestKeys(func(ctx context.Context, binding NativeCapabilityServiceBinding) (NativeAuthorityKey, error) {
		lookups++
		if lookups > 1 {
			return NativeAuthorityKey{}, pluginError("fixture_service_revoked")
		}
		return original.CurrentServiceKey(ctx, binding)
	})
	f.gateway.routes["owner"] = route
	if raw, err := f.gateway.Domain(context.Background(), f.approved); err == nil || raw != nil {
		t.Fatal("service trust was reused after an awaited authority check")
	}
}

func TestNativeCapabilityEnvelopeDigestUsesExactBytes(t *testing.T) {
	for _, variant := range []string{"whitespace", "numeric-token"} {
		t.Run(variant, func(t *testing.T) {
			f := newNativeCapabilityFixture(t, func(a *nativeAuthorityFixture) {
				a.envelopeTransform = func(raw []byte) []byte {
					if variant == "whitespace" {
						return append([]byte(" \n\t"), raw...)
					}
					return bytes.ReplaceAll(raw, []byte(`"contractMajor":1`), []byte(`"contractMajor":1.000`))
				}
			})
			canonical, err := nativeAuthorityCanonical(f.approved.Envelope)
			if err != nil || bytes.Equal(canonical, f.approved.Envelope) {
				t.Fatal("lexical variant missing")
			}
			if f.approved.delivery.envelopeDigest == nativeAuthorityDigest(canonical) {
				t.Fatal("exact envelope identity was replaced by canonical identity")
			}
			if _, err = f.gateway.Domain(context.Background(), f.approved); err != nil {
				t.Fatal("exact-byte signed receiver reply refused")
			}
		})
	}
}

func TestNativeCapabilityFencesNewerAuthorityDuringServiceKeyRead(t *testing.T) {
	for _, stage := range []string{"unchanged", "first-key", "final-key"} {
		t.Run(stage, func(t *testing.T) {
			f := newNativeCapabilityFixture(t)
			route := f.gateway.routes["owner"]
			original := route.Keys
			lookups := 0
			route.Keys = nativeCapabilityTestKeys(func(ctx context.Context, binding NativeCapabilityServiceBinding) (NativeAuthorityKey, error) {
				lookups++
				key, err := original.CurrentServiceKey(ctx, binding)
				key.AuthoritySequence = 3
				if (stage == "first-key" && lookups == 1) || (stage == "final-key" && lookups == 2) {
					key.AuthoritySequence = 4
				}
				return key, err
			})
			f.gateway.routes["owner"] = route
			raw, err := f.gateway.Domain(context.Background(), f.approved.Clone())
			if stage == "unchanged" {
				if err != nil || len(raw) == 0 || lookups != 2 {
					t.Fatal("unchanged current authority refused")
				}
				return
			}
			if err == nil || raw != nil {
				t.Fatal("private bytes disclosed after a newer authority read")
			}
			expected := 1
			if stage == "final-key" {
				expected = 2
			}
			if lookups != expected {
				t.Fatal("test did not reach the expected service trust boundary")
			}
		})
	}
}
