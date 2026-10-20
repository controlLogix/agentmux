package plugins

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/localtls"
)

type nativeCompositionTestProfile struct {
	profile NativeContextProfile
	err     error
}

func (p *nativeCompositionTestProfile) NativeContextProfile(context.Context) (NativeContextProfile, error) {
	return p.profile, p.err
}
func compositionTestTrust(t *testing.T) *localtls.ClientTrust {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "context test CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := localtls.NewClientTrust(localtls.Policy{Endpoint: "tls://127.0.0.1:4222", ServerName: "context.test", RootsPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), LeafCertificateSHA256: "sha256:" + strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	return trust
}
func compositionTestOptions(t *testing.T) (NativeContextProfile, NativeContextCompositionOptions) {
	t.Helper()
	fixture := newContextTestFixture(t, nil)
	ports := fixture.lease.ports
	activation := newNativeAuthorityFixture(t)
	declaration := NativeActivationDeclaration{RecordRef: ContextReference{"native_record", "context_hub", 1}, IdentityRef: ContextReference{"plugin_identity", "context_hub", 1}, Pin: activation.binding.Owner.Pin, ManifestDigest: activation.binding.Package.manifest.Checksum(), ConfigurationChecksum: activation.binding.Configuration.Checksum(), Facts: contextJSON(activation.facts)}
	destination, err := os.OpenFile(filepath.Join(privateTestDirectory(t), "observations.jsonl"), os.O_CREATE|os.O_EXCL|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	observability, err := NewNativeObservability(context.Background(), destination, NativeObservabilityOptions{HubID: "context_hub", Bindings: map[string]PackagePin{"plugin_one": declaration.Pin}, EventCodes: ports.EventCodes, SpanCodes: ports.SpanCodes, MetricCodes: ports.MetricCodes, MaxBytes: 65536})
	destination.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { observability.Close(context.Background()) })
	ports.Log, ports.Trace, ports.Metric = nil, nil, nil
	ports.EventCodes, ports.SpanCodes, ports.MetricCodes = nil, nil, nil
	ports.Authority = nil
	ports.SubscriptionAuthority = nil
	ports.Subscribe = nil
	ports.Configuration = nil
	ports.Domain = nil
	ports.Now = nil
	environment := "Development"
	profile := NativeContextProfile{ProfileID: "profile_one", InstanceID: "host_one", HubID: "context_hub", Context: &ProfileContext{Environment: &environment}}
	hostRef := ContextReference{"host_transport", "context_hub", 1}
	issuerRef := ContextReference{"issuer", "context_hub", 1}
	source := NativeConfigurationEventSource{ConfigurationRef: ContextReference{"configuration_one", "context_hub", 1}, SchemaRef: activation.binding.Configuration.SchemaRef(), SourceDigest: nativeAuthorityDigest([]byte("selected-source")), StreamCreated: nativeAuthorityStamp(time.Now().Add(-time.Hour))}
	subscription := NativeContextSubscriptionInput{BindingID: "configuration_events", Source: source, Service: NativeConfigurationServiceBinding{ProfileID: "profile_one", HubID: "context_hub", ServiceInstanceID: "configuration_instance", ServiceIdentityRef: ContextReference{"configuration_identity", "context_hub", 1}, SigningKeyRef: ContextReference{"configuration_signer", "context_hub", 1}}}

	return profile, NativeContextCompositionOptions{Driver: NativeDriverOptions{HubID: "context_hub", Bindings: []NativeBinding{{InstanceID: "plugin_one", Pin: declaration.Pin}}}, ContextTransport: NATSContextOptions{HubID: "context_hub", Bindings: []ContextTransportBinding{{InstanceID: "plugin_one"}}}, ContextTrust: compositionTestTrust(t), LifecycleTrust: compositionTestTrust(t), Enrollment: NativeEnrolledKeyOptions{ProfileID: profile.ProfileID, HubID: profile.HubID, AuthorityID: "authority", HostTransportRef: hostRef, IssuerRef: issuerRef}, Authority: NativeAuthorityClientOptions{ProfileID: profile.ProfileID, HubID: profile.HubID, AuthorityID: "authority", RequestSigningRef: hostRef, ResponseSigningRef: issuerRef}, Destinations: map[string]string{"plugin_one": "definition-owner"}, ActivationDeclarations: map[string]NativeActivationDeclaration{"plugin_one": declaration}, Observability: observability, Subscriptions: []NativeContextSubscriptionInput{subscription}, Services: []NativeContextServiceRoute{{BindingID: "definitions"}}, Configurations: map[string]NativeContextConfigurationInput{"plugin_one": {}}, Ports: ports}
}
func TestNativeContextCompositionRejectsMissingOrSubstitutedOwners(t *testing.T) {
	for _, kind := range []string{"configuration", "subscription", "subscription-authority", "log", "trace", "metric", "authority", "domain", "clock", "profile", "hub", "signer", "destinations", "instances", "display-context", "reply-prefix", "configuration-reply-prefix", "injected-configuration", "activation-declaration", "activation-facts", "activation-instance", "observability"} {
		t.Run(kind, func(t *testing.T) {
			profile, options := compositionTestOptions(t)
			if !nativeContextCompositionValid(profile, options) {
				t.Fatal("unchanged composition inputs failed dependency validation")
			}
			switch kind {
			case "activation-declaration":
				options.ActivationDeclarations = nil
			case "activation-facts":
				declaration := options.ActivationDeclarations["plugin_one"]
				declaration.Facts = nil
				options.ActivationDeclarations["plugin_one"] = declaration
			case "activation-instance":
				options.ActivationDeclarations["another_instance"] = options.ActivationDeclarations["plugin_one"]
				delete(options.ActivationDeclarations, "plugin_one")
			case "configuration":
				options.Configurations = nil
			case "subscription":
				options.Subscriptions = nil
			case "subscription-authority":
				options.Ports.SubscriptionAuthority = &contextTestAuthority{}
			case "observability":
				options.Observability = nil
			case "log":
				options.Ports.Log = func(context.Context, ContextLogRecord) error { return nil }
			case "trace":
				options.Ports.Trace = func(context.Context, ContextTraceRecord) error { return nil }
			case "metric":
				options.Ports.Metric = func(context.Context, ContextMetricRecord) error { return nil }
			case "authority":
				options.Ports.Authority = &contextTestAuthority{}
			case "domain":
				options.Ports.Domain = func(context.Context, ContextApprovedEnvelope) ([]byte, error) { return nil, nil }
			case "clock":
				options.Ports.Now = time.Now
			case "profile":
				options.Enrollment.ProfileID = "another_profile"
			case "hub":
				options.ContextTransport.HubID = "another_hub"
			case "signer":
				options.Authority.RequestSigningRef.ID = "another_signer"
			case "destinations":
				options.Destinations["unbound_instance"] = "definition-owner"
			case "instances":
				options.ContextTransport.Bindings[0].InstanceID = "unbound_instance"
			case "injected-configuration":
				options.Ports.Configuration = newContextMemoryConfigurationOwner()
			case "reply-prefix":
				options.Services[0].Transport.ReplyPrefix = "_INBOX.differentprefix123456"
			case "configuration-reply-prefix":
				input := options.Configurations["plugin_one"]
				input.Transport.ReplyPrefix = "_INBOX.differentprefix123456"
				options.Configurations["plugin_one"] = input
			case "display-context":
				options.Driver.ProfileContext = &ProfileContext{Project: profile.Context.Environment}
			}
			owner, err := NewNativeContextComposition(context.Background(), &nativeCompositionTestProfile{profile: profile}, options)
			if owner != nil || err == nil || err.Error() != "context_host_binding_invalid" {
				t.Fatal("unadmitted dependency reached transport or driver construction")
			}
		})
	}
}
func TestNativeContextCompositionKeepsOpaqueAdmissionFailure(t *testing.T) {
	cause := errors.New("private retained admission owner")
	owner := &NativeContextComposition{failure: cause}
	first := owner.Close(context.Background())
	if !errors.Is(first, cause) || owner.Close(context.Background()) != first {
		t.Fatal("opaque admission owner was lost or cleanup was reported complete")
	}
	if _, err := owner.Driver(); err == nil {
		t.Fatal("failed composition disclosed a driver")
	}
}
func TestNativeContextCompositionProfileErrorPreservesCause(t *testing.T) {
	cause := errors.New("private original profile admission")
	owner, err := NewNativeContextComposition(context.Background(), &nativeCompositionTestProfile{err: cause}, NativeContextCompositionOptions{})
	if owner != nil || !errors.Is(err, cause) || strings.Contains(err.Error(), "private") {
		t.Fatal("profile admission failure was discarded or exposed")
	}
}
func TestPinnedContextProviderRequiresAdmittedEndpoint(t *testing.T) {
	trust := compositionTestTrust(t)
	for _, endpoint := range []string{"nats://127.0.0.1:4222", "tls://127.0.0.1:4333", "tls://other.test:4222"} {
		owner, err := NewPinnedNATSContextProvider(context.Background(), NATSContextOptions{ServerURL: endpoint}, trust, ContextPorts{})
		if owner != nil || err == nil || err.Error() != "context_transport_options_invalid" {
			t.Fatal("unpinned endpoint reached context credential admission")
		}
	}
}

type nativeAdmissionTestCloser struct{ calls int }

func (c *nativeAdmissionTestCloser) Close() error {
	c.calls++
	return errors.New("private consumed close failure")
}
func TestNativeAuthorityCredentialErrorRetainsCleanupOwner(t *testing.T) {
	original := &nativeAdmissionTestCloser{}
	admission := closeAdmission(original, errors.New("private credential admission"))
	trust := compositionTestTrust(t)
	options := NativeAuthorityNATSOptions{ServerURL: trust.Policy().Endpoint, Subject: "fixture.authority", PublishSubjects: []string{"fixture.authority"}, ReplyPrefix: "_INBOX.fixtureprefix123456", Trust: trust}
	transport, err := newNativeAuthorityNATSExchange(context.Background(), options, func(string, string, []string, []string, bool) (lifecycleCredential, error) {
		return lifecycleCredential{}, admission
	})
	var actual *AdmissionCleanupFailure
	if transport != nil || !errors.As(err, &actual) || actual != admission || actual.owner != original || original.calls != 1 {
		t.Fatal("nil transport result lost or retried original credential cleanup owner")
	}
	if strings.Contains(err.Error(), "private") {
		t.Fatal("credential failure exposed private cause")
	}
}

func TestPinnedLifecycleTrustMustMatchAdmittedEndpointAndCA(t *testing.T) {
	trust := compositionTestTrust(t)
	for _, kind := range []string{"endpoint", "ca"} {
		t.Run(kind, func(t *testing.T) {
			directory := privateTestDirectory(t)
			ca := trust.Policy().RootsPEM
			endpoint := trust.Policy().Endpoint
			if kind == "endpoint" {
				endpoint = "tls://127.0.0.1:4333"
			} else {
				ca = compositionTestTrust(t).Policy().RootsPEM
			}
			path := filepath.Join(directory, "ca.pem")
			if err := os.WriteFile(path, ca, 0600); err != nil {
				t.Fatal(err)
			}
			driver, err := NewNativeDriver(context.Background(), NativeDriverOptions{LifecycleTrust: trust, HubID: "context_hub", ServerURL: endpoint, CAFile: path, Bindings: []NativeBinding{{InstanceID: "plugin_one"}}})
			if driver != nil || err == nil || err.Error() != "lifecycle_tls_binding_invalid" {
				t.Fatal("mismatched lifecycle trust reached credential or process admission")
			}
		})
	}
}
