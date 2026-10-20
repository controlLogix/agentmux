package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/localtls"
)

type nativeSubscriptionLiveSource struct {
	Source NativeConfigurationEventSource `json:"source"`
	Cursor NativeConfigurationEventCursor `json:"cursor"`
}

type nativeSubscriptionLiveReady struct {
	LeafCertificateSHA256 string                            `json:"leafCertificateSha256"`
	AccountPublicKey      string                            `json:"accountPublicKey"`
	ReplyPrefix           string                            `json:"replyPrefix"`
	PublishSubjects       []string                          `json:"publishSubjects"`
	ServerURL             string                            `json:"serverUrl"`
	AuthoritySubject      string                            `json:"authoritySubject"`
	ConfigurationSubject  string                            `json:"configurationSubject"`
	CredentialsFile       string                            `json:"credentialsFile"`
	CAFile                string                            `json:"caFile"`
	TLSName               string                            `json:"tlsName"`
	HostSigningSeedFile   string                            `json:"hostSigningSeedFile"`
	OriginalEnvelopeFile  string                            `json:"originalEnvelopeFile"`
	Enrollment            NativeEnrolledKeyOptions          `json:"enrollment"`
	Service               NativeConfigurationServiceBinding `json:"service"`
	Source                NativeConfigurationEventSource    `json:"source"`
	Cursor                NativeConfigurationEventCursor    `json:"cursor"`
	BindingID             string                            `json:"bindingId"`
	Revoked               bool                              `json:"revoked"`
}

// The existing Python TLS fixture owns its broker, retained source, signing
// authority and this test process. This test introduces no broker fixture.
func TestNativeConfigurationSubscriptionTLSIntegration(t *testing.T) {
	directory := os.Getenv("AMX_NATIVE_CONFIGURATION_SUBSCRIPTION_LIVE_DIR")
	if directory == "" {
		t.Skip("coordinated configuration subscription TLS fixture required")
	}
	if os.Getenv("AMX_CONFIGURATION_SUBSCRIPTION_LIVE") != "1" || runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Fatal("coordinated native macOS ARM64 slot required")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !filepath.IsAbs(directory) {
		t.Fatal("private fixture directory required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	manifest := fixtureManifest("native_tls_subscription_test")
	manifest.ConfigurationSchemaRef = "config.json"
	manifest.RequestedCapabilities = []Capability{{Action: "subscribe", ResourceClass: "configuration", Required: true}}
	pkg := fixturePackage(t, manifest, map[string][]byte{"config.json": []byte(`{"type":"object"}`)})
	configuration, err := PrepareConfiguration(pkg, nil, []byte(`{}`))
	if err != nil {
		t.Fatal("configuration preparation failed")
	}
	lifetime := make(chan struct{})
	defer close(lifetime)
	nonce, err := randomControlID()
	if err != nil {
		t.Fatal("instance identity allocation failed")
	}
	binding := ContextBinding{Owner: OwnerReference{Pin: pkg.Pin(), InstanceID: "plugin-one", Epoch: nonce, Generation: 1}, Package: pkg, Configuration: configuration, LifetimeDone: lifetime}
	var source nativeSubscriptionLiveSource
	nativeLiveWait(t, ctx, directory, "source-ready.json", func(raw []byte) bool {
		if nativeLiveDecode(raw, &source) != nil {
			t.Fatal("source ready document invalid")
		}
		return true
	})
	if !contextReferenceValid(source.Source.ConfigurationRef) || source.Source.ConfigurationRef.Revision != 0 || source.Source.SchemaRef != pkg.Manifest().ConfigurationSchemaRef || source.Cursor.Sequence != 0 || source.Cursor.SourceDigest != source.Source.SourceDigest || source.Cursor.StreamCreated != source.Source.StreamCreated {
		t.Fatal("initial empty source pin invalid")
	}
	binding.ConfigurationEventSources = []NativeConfigurationEventSource{source.Source}
	nativeLiveWrite(t, directory, "go-declaration.json", map[string]any{"owner": binding.Owner, "manifestDigest": pkg.manifest.Checksum(), "configurationChecksum": configuration.Checksum()})
	var ready nativeSubscriptionLiveReady
	nativeLiveWait(t, ctx, directory, "fixture-ready.json", func(raw []byte) bool {
		if nativeLiveDecode(raw, &ready) != nil {
			t.Fatal("fixture ready document invalid")
		}
		return !ready.Revoked
	})
	if ready.Source != source.Source || ready.Cursor.Sequence != 1 || ready.Cursor.SourceDigest != source.Cursor.SourceDigest || ready.Cursor.StreamCreated != source.Cursor.StreamCreated || ready.BindingID == "" {
		t.Fatal("fixture replaced the original source pin")
	}
	ca, err := ReadOwnerPrivateFile(ready.CAFile, nativeAuthorityLimit)
	if err != nil {
		t.Fatal("fixture CA unavailable")
	}
	trust, err := localtls.NewClientTrust(localtls.Policy{Endpoint: ready.ServerURL, ServerName: ready.TLSName, RootsPEM: ca, LeafCertificateSHA256: ready.LeafCertificateSHA256})
	if err != nil {
		t.Fatal("fixture local TLS enrollment invalid")
	}
	seed, err := ReadOwnerPrivateFile(ready.HostSigningSeedFile, 32)
	if err != nil || len(seed) != 32 {
		t.Fatal("fixture host signing seed invalid")
	}
	defer clear(seed)
	original, err := ReadOwnerPrivateFile(ready.OriginalEnvelopeFile, nativeAuthorityLimit)
	if err != nil {
		t.Fatal("fixture original envelope unavailable")
	}
	var authorityTransport, subscriptionTransport *NativeAuthorityNATSExchange
	var subscriptions *NativeConfigurationSubscriptions
	var lease ContextSubscriptionLease
	verified := false

	defer func() {
		closedTransports := map[*NativeAuthorityNATSExchange]bool{}
		attempt := uint64(0)
		for {
			work, closeCancel := context.WithTimeout(context.Background(), 3*time.Second)
			joined := true
			if lease != nil {
				joined = lease.Close(work) == nil && completed(lease.Done())
			}
			if joined && subscriptions != nil {
				joined = subscriptions.Close(work) == nil
			}
			if joined {
				for _, transport := range []*NativeAuthorityNATSExchange{subscriptionTransport, authorityTransport} {
					if transport != nil && !closedTransports[transport] {
						if transport.Close(work) != nil {
							joined = false
						} else {
							closedTransports[transport] = true
						}
					}
				}
			}
			closeCancel()
			if joined {
				nativeSubscriptionLiveCleanupState(directory, map[string]any{"phase": "cleanup-complete", "attempt": attempt})
				if verified {
					nativeLiveWrite(t, directory, "go-result.json", map[string]any{"phase": "complete", "event": true, "revocation": true, "cleanup": true})
				}
				return
			}
			// Never return from this defer with an unjoined allocation or transport.
			// The Python supervisor keeps this exact process and its services alive.
			t.Log("original subscription cleanup is retained for cooperative recovery")
			nativeSubscriptionLiveCleanupState(directory, map[string]any{"phase": "cleanup-required", "attempt": attempt})
			for {
				raw, err := ReadOwnerPrivateFile(filepath.Join(directory, "fixture-cleanup.json"), 8192)
				var request struct {
					Attempt uint64 `json:"attempt"`
				}
				if err == nil && nativeLiveDecode(raw, &request) == nil && request.Attempt > attempt {
					attempt = request.Attempt
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	options := NativeAuthorityNATSOptions{ServerURL: ready.ServerURL, Subject: ready.AuthoritySubject, CredentialsFile: ready.CredentialsFile, Trust: trust, AccountPublicKey: ready.AccountPublicKey, ReplyPrefix: ready.ReplyPrefix, PublishSubjects: ready.PublishSubjects}
	authorityTransport, err = NewNativeAuthorityNATSExchange(ctx, options)
	if err != nil {
		t.Fatal("authority TLS connection refused")
	}
	options.Subject = ready.ConfigurationSubject
	subscriptionTransport, err = NewNativeAuthorityNATSExchange(ctx, options)
	if err != nil {
		t.Fatal("subscription TLS connection refused")
	}
	keys, err := NewNativeEnrolledKeys(authorityTransport, ready.Enrollment)
	if err != nil {
		t.Fatal("enrolled key source refused")
	}
	authority, err := NewNativeContextAuthority(NativeAuthorityClientOptions{ProfileID: ready.Enrollment.ProfileID, HubID: ready.Enrollment.HubID, AuthorityID: ready.Enrollment.AuthorityID, RequestSigningRef: ready.Enrollment.HostTransportRef, ResponseSigningRef: ready.Enrollment.IssuerRef, RequestSigningSeed: seed, ReplyPrefix: ready.ReplyPrefix, Keys: keys, Exchange: authorityTransport}, map[string]string{binding.Owner.InstanceID: "configuration-owner"})
	if err != nil {
		t.Fatal("native authority construction refused")
	}
	if _, err = authority.BindInstance(ctx, binding); err != nil {
		t.Fatal("current retained native admission refused")
	}
	operation, err := authority.AdmitOperation(ctx, binding.Owner, original)
	if err != nil {
		t.Fatal("original signed subscription operation refused")
	}
	filter := nativeConfigurationSubscription{ResourceRef: ready.Source.ConfigurationRef, EventContractID: "configuration-change", Cursor: ready.Cursor}
	filter.Filter.Owner = binding.Owner
	filter.Filter.SchemaRef = ready.Source.SchemaRef
	filter.FilterDigest = nativeAuthorityDigestMustCanonical(contextJSON(map[string]any{"resourceRef": filter.ResourceRef, "eventContractId": filter.EventContractID, "filter": filter.Filter}))
	approved, err := authority.PrepareDomainCall(ctx, binding.Owner, operation, ContextDomainCall{RequestID: "request_" + strings.Repeat("e", 64), BindingID: ready.BindingID, ContractID: "configuration-change-subscribe", Payload: contextJSON(filter)})
	if err != nil {
		t.Fatal("issuer subscription preparation refused")
	}
	subscriptions, err = NewNativeConfigurationSubscriptions(authority, keys, []NativeConfigurationSubscriptionRoute{{BindingID: ready.BindingID, Source: ready.Source, Service: ready.Service, Exchange: subscriptionTransport}})
	if err != nil {
		t.Fatal("native subscription owner construction refused")
	}
	lease, err = subscriptions.Subscribe(ctx, approved.Clone())
	if err != nil {
		t.Fatal("signed TLS subscription open refused")
	}
	remote, ok := lease.(*nativeRemoteSubscription)
	if !ok {
		t.Fatal("original native allocation missing")
	}
	remote.mu.Lock()
	openID, leaseID, allocationUntil := remote.openID, remote.leaseID, remote.until
	remote.mu.Unlock()
	if openID == "" || leaseID == nil || *leaseID == "" {
		t.Fatal("original source allocation identity missing")
	}
	nativeLiveWrite(t, directory, "go-result.json", map[string]any{"phase": "opened"})
	var expected struct {
		EventEnvelopeBytes []byte `json:"eventEnvelopeBytes"`
	}
	nativeLiveWait(t, ctx, directory, "expected-event.json", func(raw []byte) bool {
		if nativeLiveDecode(raw, &expected) != nil || len(expected.EventEnvelopeBytes) == 0 {
			t.Fatal("expected retained event invalid")
		}
		return true
	})
	event, err := lease.Next(ctx)
	if err != nil || !bytes.Equal(event, expected.EventEnvelopeBytes) {
		t.Fatal("original retained event changed or was refused")
	}
	payload, err := authority.AdmitDomainEvent(ctx, binding.Owner, operation, approved.Clone(), event)
	if err != nil || !nativeCapabilityEqual(payload, fieldsForClaim(event, "payload")) {
		t.Fatal("current signed event admission failed")
	}
	var changed struct {
		ConfigurationRef      ContextReference `json:"configurationRef"`
		Owner                 OwnerReference   `json:"owner"`
		SchemaRef             string           `json:"schemaRef"`
		ConfigurationChecksum string           `json:"configurationChecksum"`
	}
	if json.Unmarshal(payload, &changed) != nil || changed.ConfigurationRef.ID != ready.Source.ConfigurationRef.ID || changed.ConfigurationRef.OwnerHubID != ready.Source.ConfigurationRef.OwnerHubID || changed.ConfigurationRef.Revision != 2 || changed.Owner != binding.Owner || changed.SchemaRef != ready.Source.SchemaRef || changed.ConfigurationChecksum != configuration.Checksum() {
		t.Fatal("committed event owner, revision or bytes changed")
	}
	remote.mu.Lock()
	cursor := remote.cursor
	same := remote.openID == openID && remote.leaseID == leaseID
	remote.mu.Unlock()
	if !same || cursor.Sequence != 2 || cursor.SourceDigest != ready.Cursor.SourceDigest || cursor.StreamCreated != ready.Cursor.StreamCreated {
		t.Fatal("event replaced the original allocation or source cursor")
	}
	nativeLiveWrite(t, directory, "go-result.json", map[string]any{"phase": "event-complete"})
	nativeLiveWait(t, ctx, directory, "fixture-ready.json", func(raw []byte) bool {
		var next nativeSubscriptionLiveReady
		if nativeLiveDecode(raw, &next) != nil {
			t.Fatal("fixture revocation document invalid")
		}
		return next.Revoked
	})
	deadline, err := nativeSubscriptionEnvelopeDeadline(approved.Envelope)
	if err != nil || (!time.Now().Add(100*time.Millisecond).Before(deadline) || !time.Now().Add(100*time.Millisecond).Before(allocationUntil)) {
		t.Fatal("revocation was not observed before subscription expiry")
	}
	if data, err := authority.AdmitDomainEvent(ctx, binding.Owner, operation, approved.Clone(), event); err == nil || data != nil {
		t.Fatal("revoked source disclosed event payload")
	}
	// Python has already proved source refusal over TLS at the prior
	// unacknowledged cursor while the exact retained event is available.
	if data, err := lease.Next(ctx); err == nil || data != nil {
		t.Fatal("revoked source continued its allocation")
	}
	if lease.Close(ctx) != nil || !completed(lease.Done()) {
		t.Fatal("revoked original source allocation did not join")
	}
	remote.mu.Lock()
	same = remote.openID == openID && remote.leaseID == leaseID && remote.cursor == cursor
	remote.mu.Unlock()
	if !same {
		t.Fatal("revoked cleanup replaced the original allocation or cursor")
	}
	verified = true
}

// A failed handoff write must not terminate the process that retains cleanup.
func nativeSubscriptionLiveCleanupState(directory string, value any) {
	raw, err := json.Marshal(value)
	if err != nil {
		return
	}
	file, err := os.CreateTemp(directory, ".go-cleanup-")
	if err != nil {
		return
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	_, writeErr := file.Write(raw)
	closeErr := file.Close()
	if writeErr == nil && closeErr == nil {
		_ = os.Rename(temporary, filepath.Join(directory, "go-cleanup.json"))
	}
}

// Check the actual Python fixture's facts against the exact subscribing manifest
// before spending the shared live slot. No broker or identity service is started.
func TestNativeConfigurationSubscriptionFixtureFactsMatchManifest(t *testing.T) {
	python := os.Getenv("AGENTMUX_NATIVE_AUTHORITY_PYTHON")
	if python == "" {
		t.Skip("prepared identity Python is not selected")
	}
	repository, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(python, "-c", `import sys
from agentmux_contracts import canonical_bytes
from state_owner.test_configuration_live import LiveConfigurationSubscriptionTests
fixture=LiveConfigurationSubscriptionTests('test_tls_subscription_delivery_revocation_and_cleanup')
fixture.scope={'organizationId':'org-one','projectId':None,'workspaceId':None}
fixture.initial_authority()
sys.stdout.buffer.write(canonical_bytes(fixture.row['facts']))
`)
	command.Dir = repository
	command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1", "PYTHONPATH="+filepath.Join(repository, "sdk/python")+":"+repository)
	facts, err := command.Output()
	if err != nil {
		t.Fatal("existing Python subscription fixture facts unavailable")
	}
	manifest := fixtureManifest("native_tls_subscription_test")
	manifest.ConfigurationSchemaRef = "config.json"
	manifest.RequestedCapabilities = []Capability{{Action: "subscribe", ResourceClass: "configuration", Required: true}}
	pkg := fixturePackage(t, manifest, map[string][]byte{"config.json": []byte(`{"type":"object"}`)})
	binding := ContextBinding{Owner: OwnerReference{Pin: pkg.Pin(), InstanceID: "plugin-one", Epoch: strings.Repeat("a", 64), Generation: 1}, Package: pkg}
	if _, err := decodeNativeAuthorityFacts(facts, binding, time.Now()); err != nil {
		t.Fatal("Python fixture facts exceed the subscribing manifest's capabilities")
	}
	var expanded map[string]any
	if json.Unmarshal(facts, &expanded) != nil {
		t.Fatal("Python fixture facts invalid")
	}
	grant := expanded["grant"].(map[string]any)
	grant["actions"] = append(grant["actions"].([]any), "inspect")
	grant["resourceIds"] = append(grant["resourceIds"].([]any), "task-one")
	policy := expanded["policy"].(map[string]any)
	policy["decisions"] = append(policy["decisions"].([]any), map[string]any{"access": map[string]string{"action": "inspect", "resourceClass": "task", "resourceId": "task-one"}, "outcome": "allow"})
	expanded["domainBindings"] = append(expanded["domainBindings"].([]any), map[string]any{"id": "inspect-binding", "contractId": "task-inspect", "action": "inspect", "resourceClass": "task", "resourceIds": []string{"task-one"}})
	if _, err := decodeNativeAuthorityFacts(contextJSON(expanded), binding, time.Now()); err == nil {
		t.Fatal("unrelated fixture domain binding exceeded the subscribing manifest")
	}
}
