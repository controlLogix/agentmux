package plugins

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

// This fixture runs the real registered provider, signed native client and
// configuration reply verifier. Controlled transport/key reads do not qualify
// broker delivery or enrollment. The existing Manager allocates both owners.
type nativeRestartSequence struct {
	mu                        sync.Mutex
	t                         *testing.T
	wire                      *nativeConfigurationWireFixture
	provider                  *nativeRegisteredContextProvider
	version, revision         uint64
	lastRecord                ContextReference
	nativeCalls, sets, opened int
	mode                      string
	cancel                    context.CancelFunc
}

func (s *nativeRestartSequence) currentWithSequence(context.Context) ([]byte, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return nil, s.version, nil
}
func (*nativeRestartSequence) activationHostIdentity() ContextReference {
	return ContextReference{"host_identity", "context_hub", 1}
}
func (s *nativeRestartSequence) CurrentConfigurationKey(ctx context.Context, b NativeConfigurationServiceBinding) (NativeAuthorityKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return NativeAuthorityKey{PublicKey: s.wire.keys.public, NotBefore: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(time.Hour), AuthoritySequence: s.version}, nil
}
func (s *nativeRestartSequence) ExchangeConfiguration(ctx context.Context, _ string, raw []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sets++
	var payload struct {
		ConfigurationRef ContextReference `json:"configurationRef"`
		Owner            OwnerReference   `json:"owner"`
	}
	if json.Unmarshal(fieldsForClaim(raw, "payload"), &payload) != nil || payload.ConfigurationRef.Revision != s.revision {
		return nil, errors.New("configuration CAS refused")
	}
	if s.mode == "refused" {
		return nil, errors.New("configuration refused")
	}
	s.revision++
	s.wire.revision = s.revision
	reply := s.wire.reply(s.t, raw, func(claims map[string]any) {
		claims["authorityRef"] = ContextReference{"native_authority", "context_hub", s.version}
		var deadline string
		if json.Unmarshal(fieldsForClaim(fieldsForClaim(raw, "operation"), "deadline"), &deadline) != nil {
			s.t.Fatal("initialization fixture lacks original deadline")
		}
		claims["validUntil"] = deadline
		if s.mode == "invalid" {
			claims["configurationRef"] = ContextReference{"wrong_configuration", "context_hub", s.revision}
		}
	})
	if s.mode == "uncertain" {
		return nil, errors.New("committed reply lost")
	}
	if s.mode == "canceled" {
		s.cancel()
		return nil, ctx.Err()
	}
	return reply, nil
}
func (*nativeRestartSequence) ConfigurationReusable() bool { return true }
func (*nativeRestartSequence) Close(context.Context) error { return nil }
func (s *nativeRestartSequence) Open(_ context.Context, binding ContextBinding) (ContextLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.opened++
	if s.provider.configurations[binding.Owner.InstanceID].Binding.ConfigurationRef.Revision != s.revision {
		s.t.Fatal("context opened before verified configuration revision propagated")
	}
	lease := &retainedContextOwner{owner: binding.Owner, done: make(chan struct{}), joined: make(chan struct{})}
	close(lease.joined)
	return lease, nil
}
func nativeRestartSequenceFixture(t *testing.T, required ...bool) *nativeRestartSequence {
	t.Helper()
	f := configurationWireFixture(t)
	// Revision tests use an optional declaration; required-capability tests
	// exercise the same signed activation and configuration boundary.
	manifest := f.authority.binding.Package.Manifest()
	manifest.RequestedCapabilities[0].Required = len(required) == 1 && required[0]
	pkg := fixturePackage(t, manifest, map[string][]byte{"schemas/config.json": []byte(`{"type":"object"}`)})
	configuration, err := PrepareConfiguration(pkg, nil, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	f.authority.binding.Package, f.authority.binding.Configuration = pkg, configuration
	f.authority.binding.Owner.Pin = pkg.Pin()
	f.binding.ConfigurationRef.Revision = 6
	f.authority.binding.Lifecycle = newNativeContextLifecycle(f.authority.binding.Owner)
	metadata := "Development"
	profile := NativeContextProfile{ProfileID: "profile", InstanceID: "host_one", HubID: "context_hub", Context: &ProfileContext{Environment: &metadata}}
	instance := f.authority.binding.Owner.InstanceID
	declaration := NativeActivationDeclaration{RecordRef: ContextReference{"native_record", "context_hub", 1}, IdentityRef: ContextReference{"plugin_identity", "context_hub", 1}, Pin: f.authority.binding.Owner.Pin, ManifestDigest: f.authority.binding.Package.manifest.Checksum(), ConfigurationChecksum: f.authority.binding.Configuration.Checksum(), Facts: contextJSON(f.authority.facts)}
	s := &nativeRestartSequence{t: t, wire: f, version: 3, revision: 6}
	input := NativeConfigurationClientBinding{Binding: f.binding, Exchange: s, ReplyPrefix: "_INBOX.configurationcaller123456"}
	owner := &NativeConfigurationOwner{bindings: map[string]NativeConfigurationClientBinding{instance: input}, leases: map[*nativeConfigurationLease]bool{}}
	s.provider = &nativeRegisteredContextProvider{profileOwner: &nativeCompositionTestProfile{profile: profile}, profile: profile, provider: s, authority: f.authority.authority, activationKeys: s, configurationOwner: owner, configurations: map[string]NativeConfigurationClientBinding{instance: input}, declarations: map[string]NativeActivationDeclaration{instance: declaration}, activating: map[string]bool{}, activationFailed: map[string]bool{}}
	original := f.authority.authority.client.options.Exchange
	var result any
	f.authority.mutate = func(claims map[string]any) {
		claims["result"] = result
		claims["authorityRef"] = ContextReference{"native_authority", "context_hub", s.version}
		claims["authoritySequence"] = s.version
	}
	f.authority.authority.client.options.Exchange = nativeAuthorityTestExchange(func(ctx context.Context, reply string, raw []byte) ([]byte, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.nativeCalls++
		claims := fieldsForClaim(raw, "claims")
		input := fieldsForClaim(claims, "input")
		switch string(fieldsForClaim(claims, "method")) {
		case `"activate-instance"`:
			var record struct {
				Ref   ContextReference `json:"ref"`
				Owner OwnerReference   `json:"owner"`
				Facts json.RawMessage  `json:"facts"`
			}
			if json.Unmarshal(fieldsForClaim(input, "record"), &record) != nil || string(fieldsForClaim(input, "expectedVersion")) != string(contextJSON(s.version)) || string(fieldsForClaim(record.Facts, "configurationRevision")) != string(contextJSON(s.revision+1)) {
				return nil, errors.New("activation CAS refused")
			}
			if record.Ref.Revision != s.lastRecord.Revision+1 {
				return nil, errors.New("activation record revision refused")
			}
			if s.lastRecord.Revision == 0 {
				if string(fieldsForClaim(input, "previousRef")) != "null" {
					return nil, errors.New("initial activation previous reference refused")
				}
			} else if !nativeCapabilityEqual(fieldsForClaim(input, "previousRef"), contextJSON(s.lastRecord)) {
				return nil, errors.New("activation previous reference refused")
			}
			s.lastRecord = record.Ref
			f.authority.binding.Owner = record.Owner
			json.Unmarshal(record.Facts, &f.authority.facts)
			s.version++
			result = map[string]any{"enrollmentRef": record.Ref, "facts": json.RawMessage(record.Facts)}
		case `"prepare-configuration-initialization"`:
			var payload map[string]any
			json.Unmarshal(fieldsForClaim(input, "payload"), &payload)
			var operation map[string]any
			json.Unmarshal(fieldsForClaim(contextTestEnvelope("configuration"), "operation"), &operation)
			operation["deadline"] = json.RawMessage(fieldsForClaim(claims, "expiresAt"))
			operation["cancellationRef"] = json.RawMessage(fieldsForClaim(input, "cancellationRef"))
			operation["expectedVersion"] = s.revision
			envelope := f.authority.envelope(t, operation, payload, "configuration-set")
			var body map[string]any
			json.Unmarshal(envelope, &body)
			body["destinationServiceId"] = "configuration-owner"
			attestation := body["ingressAttestation"].(map[string]any)
			signedClaims := attestation["claims"].(map[string]any)
			signedClaims["audience"].(map[string]any)["serviceId"] = "configuration-owner"
			attested, err := nativeAuthoritySign(contextJSON(signedClaims), f.authority.response)
			if err != nil {
				t.Fatal(err)
			}
			body["ingressAttestation"] = json.RawMessage(attested)
			result = map[string]any{"envelopeBytes": base64.StdEncoding.EncodeToString(contextJSON(body))}
		default:
			return nil, errors.New("unexpected native method")
		}
		return original.Exchange(ctx, reply, raw)
	})
	return s
}

func TestNativeRegisteredProviderRetainsConfigurationAcrossManagerGenerations(t *testing.T) {
	s := nativeRestartSequenceFixture(t)
	driver := &managerTestDriver{}
	driver.start = func(ctx context.Context, request StartRequest) (OwnedInstance, error) {
		process := managerReadyProcess()
		binding := ContextBinding{ProfileContext: cloneProfileContext(s.provider.profile.Context), Owner: request.Owner, Package: request.Package, Configuration: request.Configuration, LifetimeDone: process.done, Lifecycle: newNativeContextLifecycle(request.Owner)}
		lease, err := s.provider.Open(ctx, binding)
		process.onStop = func() {
			if lease != nil {
				lease.Invalidate()
				if err := lease.Close(context.Background()); err != nil {
					t.Error(err)
				}
			}
		}
		return process, err
	}
	manager := managerForTest(t, context.Background(), driver)
	request := managerRequest(s.wire.authority.binding.Package)
	instance := s.wire.authority.binding.Owner.InstanceID
	request.Instances[s.wire.authority.binding.Owner.Pin.PackageID] = instance
	for generation := uint64(1); generation <= 2; generation++ {
		snapshot, err := manager.Activate(context.Background(), request)
		if err != nil {
			t.Fatal("manager generation failed", generation, err, "native calls", s.nativeCalls, "sets", s.sets, "opens", s.opened)
		}
		if len(snapshot.Instances) != 1 || snapshot.Instances[0].Owner.Generation != generation {
			t.Fatal("manager did not allocate actual next generation")
		}
		s.mu.Lock()
		revision, opened := s.revision, s.opened
		s.mu.Unlock()
		s.provider.activationMu.Lock()
		reference := s.provider.configurations[instance].Binding.ConfigurationRef
		facts := append([]byte(nil), s.provider.declarations[instance].Facts...)
		failed := s.provider.activationFailed[instance]
		s.provider.activationMu.Unlock()
		if revision != 6+generation || reference.Revision != revision || string(fieldsForClaim(facts, "configurationRevision")) != string(contextJSON(revision+1)) || opened != int(generation) || failed {
			t.Fatal("verified revision was not retained for next generation")
		}
		if _, err := manager.ReleaseRoot(context.Background(), snapshot.Instances[0].Owner); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNativeRegisteredProviderInitializationFailureDoesNotAdvanceConfiguration(t *testing.T) {
	for _, mode := range []string{"refused", "uncertain", "canceled", "invalid", "stale-declaration"} {
		t.Run(mode, func(t *testing.T) {
			s := nativeRestartSequenceFixture(t)
			s.mode = mode
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s.cancel = cancel
			binding := cloneContextBinding(s.wire.authority.binding)
			binding.ProfileContext = cloneProfileContext(s.provider.profile.Context)
			instance := binding.Owner.InstanceID
			if mode == "stale-declaration" {
				d := s.provider.declarations[instance]
				var facts map[string]any
				json.Unmarshal(d.Facts, &facts)
				facts["configurationRevision"] = uint64(8)
				d.Facts = contextJSON(facts)
				s.provider.declarations[instance] = d
			}
			original := append([]byte(nil), s.provider.declarations[instance].Facts...)
			if lease, err := s.provider.Open(ctx, binding); err == nil || lease != nil {
				t.Fatal("failed initialization opened context")
			}
			if s.provider.configurations[instance].Binding.ConfigurationRef.Revision != 6 || s.provider.configurationOwner.bindings[instance].Binding.ConfigurationRef.Revision != 6 || !nativeCapabilityEqual(s.provider.declarations[instance].Facts, original) || !s.provider.activationFailed[instance] || s.opened != 0 {
				t.Fatal("failed initialization advanced configuration or lost fence")
			}
			calls, sets := s.nativeCalls, s.sets
			if mode == "stale-declaration" && (calls != 0 || sets != 0) {
				t.Fatal("known stale declaration committed identity")
			}
			if _, err := s.provider.Open(context.Background(), binding); err == nil || s.nativeCalls != calls || s.sets != sets {
				t.Fatal("uncertain initialization retried automatically")
			}
		})
	}
}
