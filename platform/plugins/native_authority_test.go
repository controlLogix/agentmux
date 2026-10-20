package plugins

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type nativeAuthorityTestKeys struct {
	request, response ed25519.PublicKey
	revoked           bool
}

func (k *nativeAuthorityTestKeys) Current(_ context.Context, _ string, _ string, _ ContextReference, purpose string) (NativeAuthorityKey, error) {
	if k.revoked {
		return NativeAuthorityKey{}, pluginError("fixture_revoked")
	}
	public := k.response
	if purpose == "agentmux-native-authority-request-v1" {
		public = k.request
	}
	return NativeAuthorityKey{PublicKey: public, NotBefore: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(time.Hour)}, nil
}

type nativeAuthorityTestExchange func(context.Context, string, []byte) ([]byte, error)

func (f nativeAuthorityTestExchange) Exchange(ctx context.Context, reply string, raw []byte) ([]byte, error) {
	return f(ctx, reply, raw)
}

type nativeAuthorityFixture struct {
	envelopeTransform         func([]byte) []byte
	authority                 *NativeContextAuthority
	binding                   ContextBinding
	facts                     map[string]any
	keys                      *nativeAuthorityTestKeys
	response                  ed25519.PrivateKey
	responseRef, authorityRef ContextReference
	mutate                    func(map[string]any)
	exchangeCount             int
	original                  []byte
}

func newNativeAuthorityFixture(t *testing.T) *nativeAuthorityFixture {
	t.Helper()
	contextFixture := newContextTestFixture(t, nil)
	f := &nativeAuthorityFixture{binding: contextFixture.lease.binding, responseRef: ContextReference{"native_signer", "context_hub", 1}, authorityRef: ContextReference{"native_authority", "context_hub", 1}}
	manifest := fixtureManifest("native_authority_package")
	manifest.RequestedCapabilities = []Capability{{Action: "read", ResourceClass: "storage", Required: true}}
	pkg := fixturePackage(t, manifest, map[string][]byte{"schemas/config.json": []byte(`{"type":"object"}`)})
	configuration, configErr := PrepareConfiguration(pkg, nil, []byte(`{}`))
	if configErr != nil {
		t.Fatal(configErr)
	}
	f.binding.Package = pkg
	f.binding.Configuration = configuration
	f.binding.Owner.Pin = pkg.Pin()
	requestSeed := bytes.Repeat([]byte{1}, 32)
	responseSeed := bytes.Repeat([]byte{2}, 32)
	f.response = ed25519.NewKeyFromSeed(responseSeed)
	f.keys = &nativeAuthorityTestKeys{request: ed25519.NewKeyFromSeed(requestSeed).Public().(ed25519.PublicKey), response: f.response.Public().(ed25519.PublicKey)}
	var grant map[string]any
	_ = json.Unmarshal(contextFixture.authority.instance.EffectiveGrant, &grant)
	grant["parentGrantRef"] = nil
	grant["actions"] = []string{"read"}
	ref := contextFixture.authority.instance.ScopeRef
	f.facts = map[string]any{"grant": grant, "policy": map[string]any{"reference": ref, "subjectInstanceId": f.binding.Owner.InstanceID, "scope": grant["scope"], "issuedAt": grant["issuedAt"], "expiresAt": grant["expiresAt"], "decisions": []any{map[string]any{"access": map[string]string{"action": "read", "resourceClass": "storage", "resourceId": "fixture_resource"}, "outcome": "allow"}}}, "parentGrant": nil, "parentAccess": []any{}, "scopeRef": ref, "configurationRevision": 7, "secretReferences": []any{}, "domainBindings": []any{map[string]any{"id": "owner", "contractId": "capability-storage-read", "action": "read", "resourceClass": "storage", "resourceIds": []string{"fixture_resource"}}}}
	options := NativeAuthorityClientOptions{ProfileID: "profile", HubID: "context_hub", AuthorityID: "native_authority", RequestSigningRef: ContextReference{"host_signer", "context_hub", 1}, ResponseSigningRef: f.responseRef, RequestSigningSeed: requestSeed, Keys: f.keys}
	options.Exchange = nativeAuthorityTestExchange(func(ctx context.Context, reply string, raw []byte) ([]byte, error) {
		f.exchangeCount++
		if nativeAuthoritySchema("request", raw) != nil {
			t.Fatal("request did not match shared schema")
		}
		var wire struct {
			Claims    json.RawMessage `json:"claims"`
			Signature string          `json:"signature"`
		}
		_ = json.Unmarshal(raw, &wire)
		canonical, _ := nativeAuthorityCanonical(wire.Claims)
		signature, _ := base64.RawURLEncoding.DecodeString(wire.Signature)
		if !ed25519.Verify(f.keys.request, canonical, signature) {
			t.Fatal("request signature invalid")
		}
		var request map[string]any
		_ = json.Unmarshal(wire.Claims, &request)
		if request["replySubject"] != reply {
			t.Fatal("unsigned reply route")
		}
		input := request["input"].(map[string]any)
		var result any = f.facts
		switch request["method"] {
		case "admit-operation":
			original, _ := base64.StdEncoding.DecodeString(input["envelopeBytes"].(string))
			f.original = bytes.Clone(original)
			result = map[string]any{"operation": json.RawMessage(fieldsForClaim(original, "operation")), "authorityRef": f.authorityRef}
		case "recheck":
			fields := map[string]any{}
			for k, v := range f.facts {
				fields[k] = v
			}
			fields["operationAuthorityRef"] = input["operationAuthorityRef"]
			result = fields
			if input["operation"] != nil {
				original, _ := base64.StdEncoding.DecodeString(input["originalEnvelopeBytes"].(string))
				if !bytes.Equal(original, f.original) {
					t.Fatal("original envelope was rewritten")
				}
			}
		case "prepare-domain-call":
			original, _ := base64.StdEncoding.DecodeString(input["originalEnvelopeBytes"].(string))
			if !bytes.Equal(original, f.original) {
				t.Fatal("downstream original envelope changed")
			}
			operation := input["operation"].(map[string]any)
			source := operation["operationId"].(string)
			id, _ := ContextDownstreamOperationID(source, input["serviceRequestId"].(string))
			operation["operationId"] = id
			operation["causationId"] = source
			envelope := f.envelope(t, operation, input["payload"], input["contractId"].(string))
			if f.envelopeTransform != nil {
				envelope = f.envelopeTransform(envelope)
			}
			serviceClaims := map[string]any{"purpose": "agentmux-capability-service-request-v1", "requestId": input["serviceRequestId"], "profileId": request["profileId"], "hubId": request["hubId"], "authorityId": request["authorityId"], "owner": request["owner"], "serviceId": "storage-owner", "requestContractId": input["contractId"], "replyContractId": "capability-content-reply", "operationId": operation["operationId"], "resourceRef": input["payload"].(map[string]any)["resourceRef"], "scope": operation["scope"], "replySubject": input["serviceReplySubject"], "issuedAt": nativeAuthorityStamp(time.Now()), "validUntil": request["expiresAt"], "signingKeyRef": f.responseRef, "hostTransportRef": request["signingKeyRef"], "nativeFactsDigest": nativeAuthorityDigestMustCanonical(contextJSON(f.facts)), "envelopeBytes": base64.StdEncoding.EncodeToString(envelope)}
			serviceRequest, err := nativeAuthoritySignLimit(contextJSON(serviceClaims), f.response, nativeCapabilityRequestLimit)
			if err != nil {
				t.Fatal(err)
			}
			result = map[string]any{"bindingId": input["bindingId"], "envelopeBytes": base64.StdEncoding.EncodeToString(envelope), "serviceRequestBytes": base64.StdEncoding.EncodeToString(serviceRequest)}
		}
		claims := map[string]any{"purpose": "agentmux-native-authority-response-v1", "requestId": request["requestId"], "method": request["method"], "profileId": request["profileId"], "hubId": request["hubId"], "authorityId": request["authorityId"], "owner": request["owner"], "requestDigest": nativeAuthorityDigest(canonical), "signingKeyRef": f.responseRef, "authorityRef": f.authorityRef, "authoritySequence": 3, "issuedAt": nativeAuthorityStamp(time.Now()), "validUntil": request["expiresAt"], "outcome": "allowed", "result": result}
		if f.mutate != nil {
			f.mutate(claims)
		}
		return nativeAuthoritySign(contextJSON(claims), f.response)
	})
	var err error
	f.authority, err = NewNativeContextAuthority(options, map[string]string{f.binding.Owner.InstanceID: "storage-owner"})
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func TestNativeAuthorityClientAllowsConfigurationPreparation(t *testing.T) {
	f := newNativeAuthorityFixture(t)
	wanted := map[string]any{"envelopeBytes": base64.StdEncoding.EncodeToString([]byte(`{}`))}
	f.mutate = func(claims map[string]any) { claims["result"] = wanted }
	input := map[string]any{"configurationRef": ContextReference{"configuration_one", "context_hub", 1}, "contractId": "configuration-read", "cancellationRef": ContextReference{"configuration_cancel", "context_hub", 1}}
	result, _, _, err := f.authority.client.callWithSequence(context.Background(), f.binding.Owner, "prepare-configuration-request", input)
	if err != nil || f.exchangeCount != 1 || !nativeCapabilityEqual(result, contextJSON(wanted)) {
		t.Fatal("configuration preparation did not complete the signed native exchange", err)
	}
}

func TestNativeAuthorityCurrentFactsAndOriginalEnvelope(t *testing.T) {
	f := newNativeAuthorityFixture(t)
	admission, err := f.authority.BindInstance(context.Background(), f.binding)
	if err != nil {
		t.Fatal(err)
	}
	var originalOperation map[string]any
	_ = json.Unmarshal(fieldsForClaim(contextTestEnvelope("a"), "operation"), &originalOperation)
	originalOperation["deadline"] = nativeAuthorityStamp(time.Now().Add(time.Minute))
	original := append([]byte(" \n"), f.envelope(t, originalOperation, map[string]any{"private": "payload-secret"}, "capability-storage-read")...)
	operation, err := f.authority.AdmitOperation(context.Background(), f.binding.Owner, original)
	if err != nil {
		t.Fatal(err)
	}
	original[0] = '\t'
	if err = f.authority.Recheck(context.Background(), f.binding.Owner, admission, &operation); err != nil {
		t.Fatal(err)
	}
	call := ContextDomainCall{RequestID: "request_" + strings.Repeat("a", 64), BindingID: "owner", ContractID: "capability-storage-read", Payload: []byte(`{"resourceRef":{"id":"fixture_resource","ownerHubId":"context_hub","revision":1},"input":{}}`)}
	if _, err = f.authority.PrepareDomainCall(context.Background(), f.binding.Owner, operation, call); err != nil {
		t.Fatal(err)
	}
	before := f.exchangeCount
	f.keys.revoked = true
	if f.authority.Recheck(context.Background(), f.binding.Owner, admission, &operation) == nil {
		t.Fatal("revoked signing trust reused")
	}
	if f.exchangeCount != before {
		t.Fatal("revoked request key reached transport")
	}
}
func TestNativeAuthorityRejectsResponseBindings(t *testing.T) {
	changes := map[string]func(map[string]any){
		"request": func(c map[string]any) { c["requestId"] = "request_other" }, "method": func(c map[string]any) { c["method"] = "recheck" },
		"profile": func(c map[string]any) { c["profileId"] = "other" }, "hub": func(c map[string]any) { c["hubId"] = "other" }, "authority": func(c map[string]any) { c["authorityId"] = "other" },
		"digest": func(c map[string]any) { c["requestDigest"] = "sha256:" + strings.Repeat("a", 64) }, "key": func(c map[string]any) { c["signingKeyRef"] = ContextReference{"other", "context_hub", 1} },
		"owner": func(c map[string]any) { c["owner"].(map[string]any)["generation"] = 2 }, "extra": func(c map[string]any) { c["untrusted"] = true },
		"expired": func(c map[string]any) { c["validUntil"] = nativeAuthorityStamp(time.Now().Add(-time.Second)) }, "future": func(c map[string]any) { c["issuedAt"] = nativeAuthorityStamp(time.Now().Add(time.Second)) },
		"extended": func(c map[string]any) { c["validUntil"] = nativeAuthorityStamp(time.Now().Add(time.Minute)) }, "denied": func(c map[string]any) { c["outcome"] = "denied"; c["result"] = nil },
		"ungranted-resource": func(c map[string]any) {
			c["result"].(map[string]any)["domainBindings"].([]any)[0].(map[string]any)["resourceIds"] = []string{"other"}
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			f := newNativeAuthorityFixture(t)
			f.mutate = change
			if _, err := f.authority.BindInstance(context.Background(), f.binding); err == nil {
				t.Fatal("changed signed response admitted")
			}
		})
	}
}
func TestNativeAuthorityRechecksChangedPolicy(t *testing.T) {
	f := newNativeAuthorityFixture(t)
	admission, err := f.authority.BindInstance(context.Background(), f.binding)
	if err != nil {
		t.Fatal(err)
	}
	f.facts["policy"].(map[string]any)["decisions"].([]any)[0].(map[string]any)["outcome"] = "deny"
	if f.authority.Recheck(context.Background(), f.binding.Owner, admission, nil) == nil {
		t.Fatal("old allow survived current denial")
	}
}
func TestNativeAuthorityPythonCanonicalVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/native-authority-jcs.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		SeedHex, PublicKeyHex string
		Vectors               []struct{ Raw, Canonical, Signature string }
	}
	if json.Unmarshal(raw, &file) != nil || len(file.Vectors) < 4 {
		t.Fatal("vectors missing")
	}
	seed, _ := hex.DecodeString(file.SeedHex)
	public, _ := hex.DecodeString(file.PublicKeyHex)
	for i, v := range file.Vectors {
		canonical, e := nativeAuthorityCanonical([]byte(v.Raw))
		if e != nil || string(canonical) != v.Canonical {
			t.Fatalf("Python canonical vector %d differs: %v", i, e)
		}
		signature := ed25519.Sign(ed25519.NewKeyFromSeed(seed), canonical)
		if base64.RawURLEncoding.EncodeToString(signature) != v.Signature || !ed25519.Verify(public, canonical, signature) {
			t.Fatalf("Python signature vector %d differs", i)
		}
		wire, err := nativeAuthoritySign([]byte(v.Raw), ed25519.NewKeyFromSeed(seed))
		if err != nil || strictDocument(wire) != nil {
			t.Fatalf("signed vector %d cannot be read by strict peer", i)
		}
		recovered, err := nativeAuthorityCanonical(fieldsForClaim(wire, "claims"))
		if err != nil || !bytes.Equal(recovered, canonical) {
			t.Fatalf("signed vector %d changed canonical claims", i)
		}
	}
	for _, bad := range []string{`{"a":1,"a":2}`, `"\ud800"`, `9007199254740992`, `1e999`, `{"a":1} {}`, strings.Repeat(" ", 65537), `"` + string([]byte{255}) + `"`} {
		if _, e := nativeAuthorityCanonical([]byte(bad)); e == nil {
			t.Fatal("invalid canonical input admitted")
		}
	}
}
func TestNativeAuthoritySchemaCopies(t *testing.T) {
	for _, name := range []string{"native-authority-request", "native-authority-response", "native-authority-facts", "message-envelope", "ingress-attestation", "owner-record", "identity-authority-state", "identity-native-instance", "configuration-set", "configuration-change", "configuration-change-subscribe", "configuration-change-subscribe-reply"} {
		original, e := os.ReadFile(filepath.Join("../../contracts/v1/schemas", name+".schema.json"))
		if e != nil {
			t.Fatal(e)
		}
		embedded, e := nativeAuthorityResources.ReadFile("schemas/" + name + ".schema.json")
		if e != nil || !bytes.Equal(original, embedded) {
			t.Fatal("shared schema copy drift", name)
		}
	}
}

// This signer is an offline protocol fixture, not enrolled identity authority.
func (f *nativeAuthorityFixture) envelope(t *testing.T, operation map[string]any, payload any, contract string) []byte {
	t.Helper()
	operation["scope"] = f.facts["grant"].(map[string]any)["scope"]
	payloadCanonical, err := nativeAuthorityCanonical(contextJSON(payload))
	if err != nil {
		t.Fatal(err)
	}
	operation["payloadDigest"] = nativeAuthorityDigest(payloadCanonical)
	issued := nativeAuthorityStamp(time.Now().Add(-time.Second))
	envelope := map[string]any{"schemaVersion": "1.0.0", "messageId": "fixture_message", "kind": "command", "contractId": contract, "contractMajor": 1, "sourceHubId": "context_hub", "sourceInstanceId": "fixture_issuer", "destinationHubId": "context_hub", "destinationServiceId": "storage-owner", "sentAt": issued, "correlationId": operation["operationId"], "operation": operation, "payload": payload}
	claims := map[string]any{"purpose": "agentmux-ingress-v1", "issuerHubId": "context_hub", "signingKeyRef": f.responseRef, "authenticationMethod": "nats-credential-mapping", "authenticatedTransportRef": ContextReference{"fixture_transport", "context_hub", 1}, "audience": map[string]string{"hubId": "context_hub", "serviceId": "storage-owner"}, "issuedAt": issued, "expiresAt": operation["deadline"]}
	for _, key := range []string{"messageId", "kind", "contractId", "contractMajor", "sourceHubId", "sourceInstanceId", "sentAt", "correlationId", "operation"} {
		claims[key] = envelope[key]
	}
	attestation, err := nativeAuthoritySign(contextJSON(claims), f.response)
	if err != nil {
		t.Fatal(err)
	}
	envelope["ingressAttestation"] = json.RawMessage(attestation)
	return contextJSON(envelope)
}

func TestNativeAuthorityRejectsSignatureAndReplay(t *testing.T) {
	for _, mode := range []string{"signature", "padding", "missing", "key", "replay"} {
		t.Run(mode, func(t *testing.T) {
			f := newNativeAuthorityFixture(t)
			original := f.authority.client.options.Exchange
			var first []byte
			f.authority.client.options.Exchange = nativeAuthorityTestExchange(func(ctx context.Context, subject string, raw []byte) ([]byte, error) {
				reply, err := original.Exchange(ctx, subject, raw)
				if err != nil {
					return nil, err
				}
				if mode == "replay" {
					if first == nil {
						first = bytes.Clone(reply)
						return reply, nil
					}
					return first, nil
				}
				if mode == "key" {
					f.keys.response = bytes.Repeat([]byte{3}, 32)
					return reply, nil
				}
				var fields map[string]any
				_ = json.Unmarshal(reply, &fields)
				switch mode {
				case "signature":
					fields["signature"] = strings.Repeat("A", 86)
				case "padding":
					fields["signature"] = fields["signature"].(string) + "=="
				case "missing":
					delete(fields["claims"].(map[string]any), "owner")
				}
				return contextJSON(fields), nil
			})
			admission, err := f.authority.BindInstance(context.Background(), f.binding)
			if mode == "replay" {
				if err != nil {
					t.Fatal(err)
				}
				if f.authority.Recheck(context.Background(), f.binding.Owner, admission, nil) == nil {
					t.Fatal("old signed response replayed")
				}
			} else if err == nil {
				t.Fatal("invalid signature or closed fields admitted")
			}
		})
	}
}
func TestNativeAuthorityLifetimeAndCancellation(t *testing.T) {
	f := newNativeAuthorityFixture(t)
	admission, err := f.authority.BindInstance(context.Background(), f.binding)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	joined := make(chan struct{})
	f.authority.client.options.Exchange = nativeAuthorityTestExchange(func(ctx context.Context, _ string, _ []byte) ([]byte, error) {
		close(entered)
		defer close(joined)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	result := make(chan error, 1)
	go func() { result <- f.authority.Recheck(ctx, f.binding.Owner, admission, nil) }()
	<-entered
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled exchange succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("exchange did not join")
	}
	if !completed(joined) {
		t.Fatal("authority released unfinished exchange")
	}
}
func TestNativeAuthorityRecheckAcceptsFreshAuthorityRevision(t *testing.T) {
	f := newNativeAuthorityFixture(t)
	admission, err := f.authority.BindInstance(context.Background(), f.binding)
	if err != nil {
		t.Fatal(err)
	}
	var operation map[string]any
	_ = json.Unmarshal(fieldsForClaim(contextTestEnvelope("a"), "operation"), &operation)
	operation["deadline"] = nativeAuthorityStamp(time.Now().Add(time.Minute))
	admitted, err := f.authority.AdmitOperation(context.Background(), f.binding.Owner, f.envelope(t, operation, map[string]any{"taskId": "fixture_resource"}, "capability-storage-read"))
	if err != nil {
		t.Fatal(err)
	}
	f.mutate = func(claims map[string]any) {
		if claims["method"] == "recheck" {
			claims["result"].(map[string]any)["operationAuthorityRef"] = ContextReference{f.authorityRef.ID, f.authorityRef.OwnerHubID, f.authorityRef.Revision + 1}
		}
	}
	if f.authority.Recheck(context.Background(), f.binding.Owner, admission, &admitted) != nil {
		t.Fatal("fresh read of unchanged admitted authority refused")
	}
	f.mutate = func(claims map[string]any) {
		if claims["method"] == "recheck" {
			claims["result"].(map[string]any)["operationAuthorityRef"] = ContextReference{f.authorityRef.ID, f.authorityRef.OwnerHubID, 0}
		}
	}
	if f.authority.Recheck(context.Background(), f.binding.Owner, admission, &admitted) == nil {
		t.Fatal("authority revision regressed")
	}
}
func TestNativeAuthorityTransportRejectsUntrustedConfiguration(t *testing.T) {
	for _, options := range []NativeAuthorityNATSOptions{{}, {ServerURL: "nats://127.0.0.1:4222", Subject: "authority"}, {ServerURL: "tls://127.0.0.1:4222", Subject: "authority.*"}} {
		if owner, err := NewNativeAuthorityNATSExchange(context.Background(), options); err == nil || owner != nil {
			t.Fatal("untrusted transport configuration admitted")
		}
	}
}

type nativeAuthorityTestKeySource func(context.Context, string, string, ContextReference, string) (NativeAuthorityKey, error)

func (f nativeAuthorityTestKeySource) Current(ctx context.Context, profile, hub string, ref ContextReference, purpose string) (NativeAuthorityKey, error) {
	return f(ctx, profile, hub, ref, purpose)
}
func TestNativeAuthorityExpiryDuringKeyLookup(t *testing.T) {
	for _, stage := range []string{"request-key", "request-deadline", "response-key", "response-reply"} {
		t.Run(stage, func(t *testing.T) {
			f := newNativeAuthorityFixture(t)
			offset := time.Duration(0)
			f.authority.client.now = func() time.Time { return time.Now().Add(offset) }
			originalKeys := f.keys
			f.authority.client.options.Keys = nativeAuthorityTestKeySource(func(ctx context.Context, profile, hub string, ref ContextReference, purpose string) (NativeAuthorityKey, error) {
				key, err := originalKeys.Current(ctx, profile, hub, ref, purpose)
				request := purpose == "agentmux-native-authority-request-v1"
				if (stage == "request-key" && request) || (stage == "response-key" && !request) {
					key.ExpiresAt = time.Now().Add(time.Second)
					offset = 2 * time.Second
				}
				if stage == "request-deadline" && request {
					offset = 6 * time.Second
				}
				if stage == "response-reply" && !request {
					offset = 2 * time.Second
				}
				return key, err
			})
			if stage == "response-reply" {
				f.mutate = func(claims map[string]any) { claims["validUntil"] = nativeAuthorityStamp(time.Now().Add(time.Second)) }
			}
			// Exercise the client's return boundary directly as well as the public
			// consumer's final fact check. The request context is still live here.
			input := map[string]any{"manifestDigest": f.binding.Package.manifest.Checksum(), "relationship": "independent", "parentOwner": nil, "configurationChecksum": f.binding.Configuration.Checksum()}
			if _, _, err := f.authority.client.call(context.Background(), f.binding.Owner, "bind-instance", input); err == nil {
				t.Fatal("lookup reused a time captured before expiry")
			}
			if strings.HasPrefix(stage, "request-") && f.exchangeCount != 0 {
				t.Fatal("expired request reached transport")
			}
		})
	}
}

func TestNativeAuthorityRefusesReplyOlderThanCurrentKeyRead(t *testing.T) {
	for _, newer := range []bool{false, true} {
		t.Run(fmt.Sprint(newer), func(t *testing.T) {
			f := newNativeAuthorityFixture(t)
			admission, err := f.authority.BindInstance(context.Background(), f.binding)
			if err != nil {
				t.Fatal(err)
			}
			original := f.authority.client.options.Keys
			f.authority.client.options.Keys = nativeAuthorityTestKeySource(func(ctx context.Context, profile, hub string, ref ContextReference, purpose string) (NativeAuthorityKey, error) {
				key, err := original.Current(ctx, profile, hub, ref, purpose)
				key.AuthoritySequence = 3
				if newer && purpose == "agentmux-native-authority-response-v1" {
					key.AuthoritySequence = 4
				}
				return key, err
			})
			err = f.authority.Recheck(context.Background(), f.binding.Owner, admission, nil)
			if (err != nil) != newer {
				t.Fatal("signed allow did not respect the current key-read sequence")
			}
		})
	}
}
func TestNativeAuthorityRetainsVerifiedReplySequence(t *testing.T) {
	f := newNativeAuthorityFixture(t)
	admission, err := f.authority.BindInstance(context.Background(), f.binding)
	if err != nil {
		t.Fatal(err)
	}
	f.mutate = func(claims map[string]any) { claims["authoritySequence"] = 2 }
	if f.authority.Recheck(context.Background(), f.binding.Owner, admission, nil) == nil {
		t.Fatal("older signed authority replaced a verified newer response")
	}
	f.mutate = func(claims map[string]any) { claims["authoritySequence"] = 4 }
	if err := f.authority.Recheck(context.Background(), f.binding.Owner, admission, nil); err != nil {
		t.Fatal("fresh compatible authority was refused", err)
	}
}
