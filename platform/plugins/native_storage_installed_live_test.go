package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/localtls"
)

type installedStoragePin struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type installedStorageSigner struct {
	IdentityRef  ContextReference    `json:"identityRef"`
	TransportRef ContextReference    `json:"transportRef"`
	KeyFile      installedStoragePin `json:"keyFile"`
	PublicKey    string              `json:"publicKey"`
}

type installedStoragePackageMaterial struct {
	SchemaVersion         string         `json:"schemaVersion"`
	Owner                 OwnerReference `json:"owner"`
	ManifestDigest        string         `json:"manifestDigest"`
	ConfigurationChecksum string         `json:"configurationChecksum"`
	SchemaRef             string         `json:"schemaRef"`
	SchemaBytes           []byte         `json:"schemaBytes"`
}

func installedStoragePackage(t *testing.T, directory string) (AdmittedPackage, ValidatedConfiguration) {
	t.Helper()
	pkg := nativeFixturePackage(t, "installed_storage_package", func(manifest *Manifest) {
		manifest.RequestedCapabilities = []Capability{{Action: "read", ResourceClass: "storage", Required: true}, {Action: "write", ResourceClass: "storage", Required: true}, {Action: "inspect", ResourceClass: "outcome", Required: true}, {Action: "subscribe", ResourceClass: "configuration", Required: true}}
		manifest.Runtime.Args = []string{"-test.run=^TestNativeChild$", "-test.timeout=0"}
		manifest.Lifecycle.DrainDeadlineMS = 8000
	})
	// The preparation and installed child admit identical source provenance.
	// Temporary extraction directories must not change the enrolled package pin.
	provenance := pkg.Provenance()
	pkg, err := AdmitPackage(context.Background(), PackageInput{Directory: filepath.Dir(provenance.Path), ManifestPath: "manifest.json", SourceID: provenance.SourceID, SourcePath: filepath.Join(directory, "installed-storage-source.md"), Scope: provenance.Scope, Source: provenance.Source(), SourceChecksum: provenance.Checksum})
	if err != nil {
		t.Fatal("storage package provenance refused")
	}
	configuration, err := PrepareConfiguration(pkg, nil, contextJSON(map[string]string{"behavior": "storage-contract", "fixtureDirectory": directory}))
	if err != nil {
		t.Fatal("storage package configuration refused")
	}
	return pkg, configuration
}

func TestInstalledStoragePackagePreparationIdentity(t *testing.T) {
	directory := t.TempDir()
	prepared, initial := installedStoragePackage(t, directory)
	started, current := installedStoragePackage(t, directory)
	if prepared.Pin() != started.Pin() || initial.Checksum() != current.Checksum() {
		t.Fatal("preparation and startup changed the selected package or configuration")
	}
	other, changed := installedStoragePackage(t, t.TempDir())
	if other.Pin() == prepared.Pin() || changed.Checksum() == initial.Checksum() {
		t.Fatal("another enrollment directory reused the original package or configuration")
	}
}

func TestInstalledStorageDeclarationConfigurationWatch(t *testing.T) {
	pkg, configuration := installedStoragePackage(t, t.TempDir())
	now := time.Now()
	m := installedStorageMaterial{
		InstanceID:   "installed_storage_plugin",
		ProjectScope: contextJSON(map[string]any{"organizationId": "fixture_org", "projectId": "fixture_project", "workspaceId": nil}),
		Interval:     map[string]string{"issuedAt": nativeAuthorityStamp(now.Add(-time.Minute)), "expiresAt": nativeAuthorityStamp(now.Add(time.Hour))},
		Resources:    map[string]ContextReference{"private": {"private_resource", "fixture_hub", 1}, "card": {"card_resource", "fixture_hub", 1}},
	}
	m.Enrollment.HubID = "fixture_hub"
	m.Configuration.Reference = ContextReference{"configuration_resource", "fixture_hub", 0}
	m.Configuration.EventSource.ConfigurationRef = m.Configuration.Reference
	declaration := installedStorageDeclaration(m, pkg, configuration)
	facts, err := decodeNativeAuthorityFacts(declaration.Facts, ContextBinding{Owner: OwnerReference{Pin: pkg.Pin(), InstanceID: m.InstanceID}, Package: pkg, Configuration: configuration}, now)
	if err != nil {
		t.Fatal("storage activation facts do not match the requested capabilities")
	}
	for _, domain := range facts.admission.DomainBindings {
		if domain.ID == "configuration_watch" && domain.ContractID == "configuration-change-subscribe" && domain.Action == "subscribe" && domain.ResourceClass == "configuration" {
			resources := facts.resources[domain.ID]
			if len(resources) == 1 && resources[0] == declaration.ConfigurationEventSources[0].ConfigurationRef.ID {
				return
			}
		}
	}
	t.Fatal("selected configuration event source has no admitted subscription binding")
}

// Preparation fixes the package and requested owner before service enrollment.
// It starts no process or broker connection and creates no identity activation.
func TestPrepareNativeInstalledStoragePackage(t *testing.T) {
	output, directory := os.Getenv("AMX_INSTALLED_STORAGE_PACKAGE_OUTPUT"), os.Getenv("AMX_INSTALLED_STORAGE_PREPARATION_DIRECTORY")
	if output == "" && directory == "" {
		t.Skip("explicit installed storage package preparation required")
	}
	if !filepath.IsAbs(output) || filepath.Clean(output) != output || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		t.Fatal("private package preparation paths required")
	}
	pkg, configuration := installedStoragePackage(t, directory)
	epoch, err := randomControlID()
	if err != nil {
		t.Fatal("storage owner identity unavailable")
	}
	schema, err := pkg.File(configuration.SchemaRef())
	if err != nil {
		t.Fatal("storage configuration schema unavailable")
	}
	material := installedStoragePackageMaterial{SchemaVersion: "1.0.0", Owner: OwnerReference{Pin: pkg.Pin(), InstanceID: "installed_storage_plugin", Epoch: epoch, Generation: 1}, ManifestDigest: pkg.manifest.Checksum(), ConfigurationChecksum: configuration.Checksum(), SchemaRef: configuration.SchemaRef(), SchemaBytes: schema}
	raw, err := json.Marshal(material)
	if err != nil {
		t.Fatal("storage package material encoding failed")
	}
	file, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("storage package output unavailable")
	}
	_, writeErr := file.Write(raw)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("storage package output incomplete")
	}
}

type installedStorageMaterial struct {
	SchemaVersion    string                            `json:"schemaVersion"`
	ServiceSelection installedStoragePin               `json:"serviceSelection"`
	NativeSigners    map[string]installedStorageSigner `json:"nativeSigners"`
	NativePackage    installedStoragePackageMaterial   `json:"nativePackage"`
	Configuration    struct {
		Reference      ContextReference                  `json:"reference"`
		AuthorityRef   ContextReference                  `json:"authorityRef"`
		Service        NativeConfigurationServiceBinding `json:"service"`
		CommandSubject string                            `json:"commandSubject"`
		EventSource    NativeConfigurationEventSource    `json:"eventSource"`
	} `json:"configuration"`
	NativeBroker struct {
		Credentials map[string]struct {
			Path          string `json:"path"`
			SHA256        string `json:"sha256"`
			UserPublicKey string `json:"userPublicKey"`
		} `json:"credentials"`
		ReplyPrefix      string              `json:"replyPrefix"`
		PublishSubjects  []string            `json:"publishSubjects"`
		AuthoritySubject string              `json:"authoritySubject"`
		CAFile           installedStoragePin `json:"caFile"`
		StateDirectory   string              `json:"stateDirectory"`
	} `json:"nativeBroker"`
	Connection struct {
		Endpoint   string `json:"endpoint"`
		ServerName string `json:"serverName"`
		RootsPEM   string `json:"rootsPEM"`
		Leaf       string `json:"leafCertificateSHA256"`
		Domain     string `json:"jetstreamDomain"`
	} `json:"connection"`
	Interval             map[string]string                         `json:"interval"`
	AccountPublicKey     string                                    `json:"accountPublicKey"`
	Enrollment           NativeEnrolledKeyOptions                  `json:"enrollment"`
	Resources            map[string]ContextReference               `json:"resources"`
	PrivateBindingDigest string                                    `json:"privateBindingDigest"`
	Services             map[string]NativeCapabilityServiceBinding `json:"services"`
	InstanceID           string                                    `json:"instanceId"`
	PackageID            string                                    `json:"packageId"`
	ProjectScope         json.RawMessage                           `json:"projectScope"`
	OperationGrants      map[string]map[string]ContextReference    `json:"operationGrants"`
}

func installedStorageRead(t *testing.T, pin installedStoragePin, limit int) []byte {
	t.Helper()
	raw, err := ReadOwnerPrivateFile(pin.Path, int64(limit))
	if err != nil || nativeAuthorityDigest(raw) != pin.SHA256 {
		t.Fatal("installed storage pinned material refused")
	}
	return raw
}

func installedStorageDeclaration(m installedStorageMaterial, pkg AdmittedPackage, config ValidatedConfiguration) NativeActivationDeclaration {
	ref := func(id string) ContextReference {
		return ContextReference{ID: id, OwnerHubID: m.Enrollment.HubID, Revision: 1}
	}
	ids := []string{m.Resources["private"].ID, m.Resources["card"].ID}
	var decisions []any
	var bindings []any
	for _, spec := range []struct{ id, contract, action, class string }{
		{"storage_read", "capability-storage-read", "read", "storage"},
		{"storage_write", "capability-storage-write", "write", "storage"},
		{"storage_outcome", "capability-outcome-query", "inspect", "outcome"},
	} {
		bindings = append(bindings, map[string]any{"id": spec.id, "contractId": spec.contract, "action": spec.action, "resourceClass": spec.class, "resourceIds": ids})
		for _, id := range ids {
			decisions = append(decisions, map[string]any{"access": map[string]string{"action": spec.action, "resourceClass": spec.class, "resourceId": id}, "outcome": "allow"})
		}
	}
	// The selected event source must have the same explicit capability and
	// resource binding as the configuration subscription it exposes.
	configurationID := m.Configuration.EventSource.ConfigurationRef.ID
	bindings = append(bindings, map[string]any{"id": "configuration_watch", "contractId": "configuration-change-subscribe", "action": "subscribe", "resourceClass": "configuration", "resourceIds": []string{configurationID}})
	decisions = append(decisions, map[string]any{"access": map[string]string{"action": "subscribe", "resourceClass": "configuration", "resourceId": configurationID}, "outcome": "allow"})
	grantResources := append(append([]string{}, ids...), configurationID)
	policy := ref("installed_storage_policy")
	facts := contextJSON(map[string]any{
		"grant":       map[string]any{"grantId": "installed_storage_grant", "issuerHubId": m.Enrollment.HubID, "subjectInstanceId": m.InstanceID, "scope": m.ProjectScope, "actions": []string{"read", "write", "inspect", "subscribe"}, "resourceIds": grantResources, "issuedAt": m.Interval["issuedAt"], "expiresAt": m.Interval["expiresAt"], "policyRef": policy, "parentGrantRef": nil, "revision": 1},
		"policy":      map[string]any{"reference": policy, "subjectInstanceId": m.InstanceID, "scope": m.ProjectScope, "issuedAt": m.Interval["issuedAt"], "expiresAt": m.Interval["expiresAt"], "decisions": decisions},
		"parentGrant": nil, "parentAccess": []any{}, "scopeRef": ref("installed_storage_scope"), "configurationRevision": m.Configuration.Reference.Revision + 1, "secretReferences": []any{}, "domainBindings": bindings})
	return NativeActivationDeclaration{RecordRef: ref("installed_storage_instance"), IdentityRef: m.NativeSigners["storage_plugin"].IdentityRef,
		Pin: pkg.Pin(), ManifestDigest: pkg.manifest.Checksum(), ConfigurationChecksum: config.Checksum(), Facts: facts,
		ConfigurationEventSources: []NativeConfigurationEventSource{m.Configuration.EventSource},
		PrivateStorageResources:   []NativePrivateStorageResource{{ResourceID: ids[0], Scope: m.ProjectScope, BindingDigest: m.PrivateBindingDigest}}}
}

// The launcher collector retains the installed host while this fixed child
// owns the real native plugin, its transports and each typed storage operation.
func RunNativeInstalledStorageProviders(t *testing.T, profileOwner NativeContextProfileOwner) {
	path := os.Getenv("AMX_INSTALLED_STORAGE_CONTRACT_MATERIAL")
	if path == "" {
		t.Skip("installed storage collector required")
	}
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" || os.Getenv("AMX_INSTALLED_STORAGE_AUTHORIZED") != "1" {
		t.Fatal("native installed storage authorization required")
	}
	pin := installedStoragePin{path, os.Getenv("AMX_INSTALLED_STORAGE_CONTRACT_MATERIAL_SHA256")}
	var m installedStorageMaterial
	if nativeLiveDecode(installedStorageRead(t, pin, 16384), &m) != nil || m.SchemaVersion != "1.0.0" {
		t.Fatal("storage contract material invalid")
	}
	installedStorageRead(t, m.ServiceSelection, 65536)
	for _, credential := range m.NativeBroker.Credentials {
		installedStorageRead(t, installedStoragePin{credential.Path, credential.SHA256}, 65536)
	}
	ca := installedStorageRead(t, m.NativeBroker.CAFile, 16384)
	seed := installedStorageRead(t, m.NativeSigners["native_host"].KeyFile, 32)
	defer clear(seed)
	trust, err := localtls.NewClientTrust(localtls.Policy{Endpoint: m.Connection.Endpoint, ServerName: m.Connection.ServerName, RootsPEM: ca, LeafCertificateSHA256: m.Connection.Leaf})
	if err != nil {
		t.Fatal("storage TLS selection refused")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var composition *NativeContextComposition
	var observation *NativeObservability
	var handles []*CapabilityHandles
	defer func() {
		for attempt := uint64(0); ; attempt++ {
			closeCtx, stop := context.WithTimeout(context.Background(), 8*time.Second)
			joined := true
			for _, handle := range handles {
				if handle.Close(closeCtx) != nil {
					joined = false
				}
			}
			if joined && composition != nil {
				closeErr := composition.Close(closeCtx)
				joined = composition.CleanupComplete()
				if closeErr != nil && joined {
					t.Error("storage composition failed; original owners joined")
				}
			} else if joined && observation != nil {
				closeErr := observation.Close(closeCtx)
				joined = observation.CleanupComplete()
				if closeErr != nil && joined {
					t.Error("storage observation failed; original writer joined")
				}
			}
			stop()
			if joined {
				return
			}
			nativeSubscriptionLiveCleanupState(filepath.Dir(path), map[string]any{"phase": "cleanup-required", "attempt": attempt})
			for {
				raw, e := ReadOwnerPrivateFile(filepath.Join(filepath.Dir(path), "fixture-cleanup.json"), 8192)
				var recovery struct {
					Attempt uint64 `json:"attempt"`
				}
				if e == nil && nativeLiveDecode(raw, &recovery) == nil && recovery.Attempt > attempt {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
	}()
	transportOptions := func(subject string) NativeAuthorityNATSOptions {
		return NativeAuthorityNATSOptions{ServerURL: m.Connection.Endpoint, Subject: subject, CredentialsFile: m.NativeBroker.Credentials["host"].Path, AccountPublicKey: m.AccountPublicKey, ReplyPrefix: m.NativeBroker.ReplyPrefix, PublishSubjects: m.NativeBroker.PublishSubjects, Trust: trust}
	}
	pkg, configuration := installedStoragePackage(t, filepath.Dir(path))
	planned := m.NativePackage
	if planned.SchemaVersion != "1.0.0" || planned.Owner.Pin != pkg.Pin() || planned.Owner.InstanceID != m.InstanceID || planned.Owner.Generation != 1 || !contextOwnerValid(planned.Owner) || planned.ManifestDigest != pkg.manifest.Checksum() || planned.ConfigurationChecksum != configuration.Checksum() || planned.SchemaRef != configuration.SchemaRef() {
		t.Fatal("storage package differs from the enrolled preparation")
	}
	schema, err := pkg.File(configuration.SchemaRef())
	if err != nil || !bytes.Equal(schema, planned.SchemaBytes) {
		t.Fatal("storage configuration schema changed")
	}
	var routes []NativeContextServiceRoute
	for _, spec := range []struct{ id, contract, reply, service string }{{"storage_read", "capability-storage-read", "capability-content-reply", "storage"}, {"storage_write", "capability-storage-write", "capability-storage-write-reply", "storage"}, {"storage_outcome", "capability-outcome-query", "capability-outcome-query-reply", "outcome"}} {
		service := m.Services[spec.service]
		subject := "amx.v1.h." + m.Enrollment.HubID + ".o." + m.Enrollment.OrganizationID + ".p."
		var scope struct {
			ProjectID string `json:"projectId"`
		}
		if json.Unmarshal(m.ProjectScope, &scope) != nil {
			t.Fatal("storage scope invalid")
		}
		subject += scope.ProjectID + ".w._.capability." + service.ServiceID + ".command"
		routes = append(routes, NativeContextServiceRoute{BindingID: spec.id, RequestContractID: spec.contract, ReplyContractID: spec.reply, Service: service, Transport: transportOptions(subject)})
	}
	observationID, err := randomControlID()
	if err != nil {
		t.Fatal("storage observation identity unavailable")
	}
	file, err := os.OpenFile(filepath.Join(filepath.Dir(path), "storage-observations-"+observationID+".private.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal("storage observation file unavailable")
	}
	observation, err = NewNativeObservability(ctx, file, NativeObservabilityOptions{HubID: m.Enrollment.HubID, Bindings: map[string]PackagePin{m.InstanceID: pkg.Pin()}, EventCodes: []string{"operation_started"}, SpanCodes: []string{"domain_request"}, MetricCodes: []string{"calls"}, MaxBytes: 65536})
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatal("storage observation owner unavailable")
	}
	composition, err = NewNativeContextComposition(ctx, profileOwner, NativeContextCompositionOptions{
		Driver:           NativeDriverOptions{HubID: m.Enrollment.HubID, AccountPublicKey: m.AccountPublicKey, ServerURL: m.Connection.Endpoint, CAFile: m.NativeBroker.CAFile.Path, StateDirectory: m.NativeBroker.StateDirectory, ControllerCredentialsFile: m.NativeBroker.Credentials["controller"].Path, Bindings: []NativeBinding{{Pin: pkg.Pin(), InstanceID: m.InstanceID, CredentialsFile: m.NativeBroker.Credentials["plugin"].Path}}},
		ContextTransport: NATSContextOptions{HubID: m.Enrollment.HubID, AccountPublicKey: m.AccountPublicKey, ServerURL: m.Connection.Endpoint, CAFile: m.NativeBroker.CAFile.Path, ServerCredentialsFile: m.NativeBroker.Credentials["context"].Path, Bindings: []ContextTransportBinding{{InstanceID: m.InstanceID, ClientCredentialsFile: m.NativeBroker.Credentials["context_client"].Path}}},
		ContextTrust:     trust, LifecycleTrust: trust, Enrollment: m.Enrollment,
		Authority:              NativeAuthorityClientOptions{ProfileID: m.Enrollment.ProfileID, HubID: m.Enrollment.HubID, AuthorityID: m.Enrollment.AuthorityID, RequestSigningRef: m.Enrollment.HostTransportRef, ResponseSigningRef: m.Enrollment.IssuerRef, RequestSigningSeed: seed, ReplyPrefix: m.NativeBroker.ReplyPrefix},
		AuthorityTransport:     transportOptions(m.NativeBroker.AuthoritySubject),
		Destinations:           map[string]string{m.InstanceID: "storage-owner"},
		ActivationDeclarations: map[string]NativeActivationDeclaration{m.InstanceID: installedStorageDeclaration(m, pkg, configuration)},
		Observability:          observation, Services: routes,
		Configurations: map[string]NativeContextConfigurationInput{m.InstanceID: {Binding: NativeConfigurationBinding{ConfigurationRef: m.Configuration.Reference, Service: m.Configuration.Service, AuthorityRef: m.Configuration.AuthorityRef}, Transport: transportOptions(m.Configuration.CommandSubject)}},
		Subscriptions:  []NativeContextSubscriptionInput{{BindingID: "configuration_watch", Source: m.Configuration.EventSource, Service: m.Configuration.Service, Transport: transportOptions(m.Configuration.CommandSubject)}},
	})
	if err != nil {
		t.Fatal("registered storage composition refused")
	}
	driver, authority, gateway := composition.driver, composition.authority, composition.gateway
	owner := planned.Owner
	start, stop := context.WithTimeout(ctx, time.Duration(pkg.Manifest().Lifecycle.StartDeadlineMS)*time.Millisecond)
	process, err := driver.Start(start, StartRequest{Owner: owner, Package: pkg, Configuration: configuration})
	if err == nil {
		err = process.WaitReady(start)
	}
	stop()
	if err != nil {
		var failure *Error
		if errors.As(err, &failure) {
			t.Fatalf("installed storage native startup failed: %s", failure.Code())
		}
		t.Fatal("installed storage native startup failed")
	}
	// Borrow the actual process lease. The authority deliberately retains a
	// reduced binding without a lifecycle or package files.
	native, ok := process.(*nativeInstance)
	if !ok {
		t.Fatal("actual storage process unavailable")
	}
	native.mu.Lock()
	pinned, ok := native.contextLease.(*pinnedContextLease)
	native.mu.Unlock()
	if !ok {
		t.Fatal("actual storage context lease unavailable")
	}
	lease, ok := pinned.ContextLease.(*contextLease)
	if !ok {
		t.Fatal("actual storage context binding unavailable")
	}
	binding, instance := cloneContextBinding(lease.binding), cloneInstanceAdmission(lease.admission)
	if binding.Owner != owner || binding.Lifecycle == nil || !binding.Lifecycle.Snapshot().Ready {
		t.Fatal("actual storage process binding unavailable")
	}
	type pendingRecovery struct {
		provider                          string
		path                              string
		before, committed, later, receipt ContextReference
		value                             []byte
	}
	var pending []pendingRecovery
	for _, name := range []string{"private", "card"} {
		resource := m.Resources[name]
		value := []byte(`{"installed":true}`)
		if name == "card" {
			value = []byte(`{"command":"move","status":"doing"}`)
		}
		original := installedStorageOperation(t, pin, name, "capability-storage-write", resource, value)
		operation, e := authority.AdmitOperation(ctx, owner, original)
		if e != nil {
			t.Fatal("fresh storage operation refused")
		}
		domainCalls := 0
		domain := func(call context.Context, approved ContextApprovedEnvelope) ([]byte, error) {
			domainCalls++
			return gateway.Domain(call, approved)
		}
		handle, e := OpenCapabilityHandles(ctx, binding, instance, operation, CapabilityHandlePorts{Authority: authority, Domain: domain, Now: time.Now})
		if e != nil {
			t.Fatal(e)
		}
		handles = append(handles, handle)
		// The common interface is closed: an undeclared operation must never
		// dispatch to either selected provider, even with an admitted context.
		var unsupportedReply any
		unsupported := handle.session.call(ctx, "capability-storage-delete", resource, struct{}{}, &unsupportedReply, nil, false)
		var refusal *Error
		if !errors.As(unsupported, &refusal) || refusal.Code() != "capability_access_refused" || domainCalls != 0 {
			t.Fatalf("%s undeclared storage operation was not refused before dispatch", name)
		}
		mutation, e := handle.Storage.PrepareCompareAndSwap(ctx, resource, value)
		if e != nil {
			t.Fatal(e)
		}
		recovery, e := mutation.RecoveryBytes()
		if e != nil {
			t.Fatal(e)
		}
		nativeLiveWrite(t, filepath.Dir(path), "storage-"+name+"-mutation.json", json.RawMessage(recovery))
		result, e := handle.Storage.CompareAndSwap(ctx, mutation, resource, value)
		if e != nil || result.Outcome() != "applied" {
			t.Fatal("installed storage mutation failed")
		}
		updated, present := result.ResourceReference()
		if !present || updated.ID != resource.ID || updated.Revision <= resource.Revision || result.Reference() == updated {
			t.Fatal("storage resource and receipt revisions were not distinct")
		}
		replay, e := handle.Storage.CompareAndSwap(ctx, mutation, resource, value)
		if e != nil {
			if failure, ok := e.(*Error); ok {
				t.Fatalf("installed storage replay refused: %s", failure.Code())
			}
			t.Fatal("installed storage replay failed")
		}
		if replay.Reference() != result.Reference() {
			t.Fatal("installed storage replay changed receipt")
		}
		if _, e := handle.Storage.CompareAndSwap(ctx, mutation, resource, []byte(`{"changed":true}`)); e == nil {
			t.Fatal("original storage mutation accepted changed bytes")
		}
		read := func(target ContextReference) []byte {
			envelope := installedStorageOperation(t, pin, name, "capability-storage-read", target, nil)
			op, err := authority.AdmitOperation(ctx, owner, envelope)
			if err != nil {
				t.Fatal("fresh storage read operation refused")
			}
			h, err := OpenCapabilityHandles(ctx, binding, instance, op, CapabilityHandlePorts{Authority: authority, Domain: gateway.Domain, Now: time.Now})
			if err != nil {
				t.Fatal("storage read handle unavailable")
			}
			handles = append(handles, h)
			content, err := h.Storage.Read(ctx, target)
			if err != nil {
				t.Fatal("installed storage read failed")
			}
			return content.Bytes()
		}
		beforeConflict := read(updated)
		if name == "private" && !nativeCapabilityEqual(beforeConflict, value) {
			t.Fatal("private storage read differs from the committed value")
		}
		fresh := func(target ContextReference, desired []byte, domain func(context.Context, ContextApprovedEnvelope) ([]byte, error)) (*CapabilityHandles, *CapabilityMutation) {
			envelope := installedStorageOperation(t, pin, name, "capability-storage-write", target, desired)
			op, err := authority.AdmitOperation(ctx, owner, envelope)
			if err != nil {
				t.Fatal("fresh follow-up storage operation refused")
			}
			if domain == nil {
				domain = gateway.Domain
			}
			h, err := OpenCapabilityHandles(ctx, binding, instance, op, CapabilityHandlePorts{Authority: authority, Domain: domain, Now: time.Now})
			if err != nil {
				t.Fatal(err)
			}
			handles = append(handles, h)
			m, err := h.Storage.PrepareCompareAndSwap(ctx, target, desired)
			if err != nil {
				t.Fatal(err)
			}
			return h, m
		}
		if name == "card" {
			unsupportedValue := []byte(`{"command":"add"}`)
			unsupportedHandle, unsupportedMutation := fresh(updated, unsupportedValue, nil)
			_, err := unsupportedHandle.Storage.CompareAndSwap(ctx, unsupportedMutation, updated, unsupportedValue)
			var refusal *Error
			if !errors.As(err, &refusal) || refusal.Code() != "capability_outcome_unavailable" {
				t.Fatal("board storage did not explicitly refuse an unsupported command")
			}
			if !bytes.Equal(read(updated), beforeConflict) {
				t.Fatal("unsupported board command changed the stored card")
			}
		}
		staleValue := []byte(`{"mustNotApply":true}`)
		if name == "card" {
			staleValue = []byte(`{"command":"move","status":"todo"}`)
		}
		conflictHandle, conflictMutation := fresh(resource, staleValue, nil)
		conflict, e := conflictHandle.Storage.CompareAndSwap(ctx, conflictMutation, resource, staleValue)
		observed, exists := conflict.ResourceReference()
		expectedConflict := updated
		if name == "private" {
			// Private storage retains a rejected owner record at a new revision;
			// the board retains its conflict in a separate publisher journal.
			expectedConflict.Revision++
		}
		if e != nil || conflict.Outcome() != "conflict" || !exists || observed != expectedConflict {
			t.Fatal("stale storage write returned an unexpected resource revision")
		}
		if !bytes.Equal(read(observed), beforeConflict) {
			t.Fatal("stale storage write changed the stored value")
		}
		latest := observed
		// Lose a real authenticated reply after the owner has executed. The
		// caller sees uncertainty; the test observes the dropped reply only to
		// check the durable result after another write and process restart.
		var dropped []byte
		dispatches := 0
		loseReply := func(call context.Context, approved ContextApprovedEnvelope) ([]byte, error) {
			dispatches++
			if dispatches != 1 {
				return nil, errors.New("fixture_effect_retry_refused")
			}
			reply, err := gateway.Domain(call, approved)
			if err != nil {
				return nil, err
			}
			dropped = append([]byte(nil), reply...)
			return nil, errors.New("fixture_reply_discarded")
		}
		lostHandle, lostMutation := fresh(latest, value, loseReply)
		saved, err := lostMutation.RecoveryBytes()
		if err != nil {
			t.Fatal("lost-reply recovery material unavailable")
		}
		nameOnDisk := "storage-" + name + "-lost-mutation.json"
		nativeLiveWrite(t, filepath.Dir(path), nameOnDisk, json.RawMessage(saved))
		if _, err := lostHandle.Storage.CompareAndSwap(ctx, lostMutation, latest, value); err == nil || dispatches != 1 {
			t.Fatal("lost write reply was accepted or automatically retried")
		}
		var committed struct {
			Receipt  ContextReference `json:"receiptRef"`
			Resource ContextReference `json:"resourceRef"`
			Outcome  string           `json:"outcome"`
		}
		if json.Unmarshal(dropped, &committed) != nil || committed.Outcome != "applied" || committed.Resource.Revision <= latest.Revision || !contextReferenceValid(committed.Receipt) {
			t.Fatal("lost reply did not follow a committed owner write")
		}
		following, followingMutation := fresh(committed.Resource, value, nil)
		result, err = following.Storage.CompareAndSwap(ctx, followingMutation, committed.Resource, value)
		after, exists := result.ResourceReference()
		if err != nil {
			var failure *Error
			if errors.As(err, &failure) {
				t.Fatalf("%s write after lost reply refused: %s", name, failure.Code())
			}
			t.Fatalf("%s write after lost reply failed", name)
		}
		if err != nil || result.Outcome() != "applied" || !exists || after.Revision <= committed.Resource.Revision {
			t.Fatalf("%s write after lost reply returned an unexpected outcome or revision", name)
		}
		pending = append(pending, pendingRecovery{name, filepath.Join(filepath.Dir(path), nameOnDisk), latest, committed.Resource, after, committed.Receipt, append([]byte(nil), value...)})
	}
	// Stop consumes the original child's wait and readers before the next
	// generation starts. The installed owner services retain their ledgers.
	oldPID := native.cmd.Process.Pid
	closeCtx, closeCancel := context.WithTimeout(ctx, 8*time.Second)
	for _, handle := range handles {
		if err := handle.Close(closeCtx); err != nil {
			closeCancel()
			t.Fatal("storage handle cleanup before restart failed")
		}
	}
	handles = nil
	err = process.Stop(closeCtx)
	closeCancel()
	if err != nil || !completed(process.Done()) {
		t.Fatal("original storage plugin did not join before restart")
	}
	owner.Generation++
	start, stop = context.WithTimeout(ctx, time.Duration(pkg.Manifest().Lifecycle.StartDeadlineMS)*time.Millisecond)
	process, err = driver.Start(start, StartRequest{Owner: owner, Package: pkg, Configuration: configuration})
	if err == nil {
		err = process.WaitReady(start)
	}
	stop()
	if err != nil {
		t.Fatal("next storage plugin generation failed")
	}
	native, ok = process.(*nativeInstance)
	if !ok || native.cmd.Process.Pid == oldPID {
		t.Fatal("storage restart did not create a new native process")
	}
	native.mu.Lock()
	pinned, ok = native.contextLease.(*pinnedContextLease)
	native.mu.Unlock()
	if !ok {
		t.Fatal("restarted storage context unavailable")
	}
	lease, ok = pinned.ContextLease.(*contextLease)
	if !ok {
		t.Fatal("restarted storage binding unavailable")
	}
	binding, instance = cloneContextBinding(lease.binding), cloneInstanceAdmission(lease.admission)
	if binding.Owner != owner || !binding.Lifecycle.Snapshot().Ready {
		t.Fatal("restarted storage owner was not admitted")
	}
	for _, item := range pending {
		saved, err := ReadOwnerPrivateFile(item.path, 65536)
		if err != nil {
			t.Fatal("saved lost-write mutation unavailable after restart")
		}
		mutation, err := RestoreCapabilityMutation(saved)
		if err != nil {
			t.Fatal("saved lost-write mutation refused after restart")
		}
		envelope := installedStorageOperation(t, pin, item.provider, "capability-storage-write", item.before, item.value)
		op, err := authority.AdmitOperation(ctx, owner, envelope)
		if err != nil {
			t.Fatal("fresh recovery operation refused after restart")
		}
		handle, err := OpenCapabilityHandles(ctx, binding, instance, op, CapabilityHandlePorts{Authority: authority, Domain: gateway.Domain, Now: time.Now})
		if err != nil {
			t.Fatal("recovery handle unavailable after restart")
		}
		handles = append(handles, handle)
		outcome, err := handle.Reconcile(ctx, mutation)
		resource, exists := outcome.ResourceReference()
		receipt, recorded := outcome.Record()
		if err != nil || outcome.Outcome() != "committed" || !exists || resource != item.committed || resource == item.later || !recorded || receipt != item.receipt {
			t.Fatal("restart recovery lost the original write result")
		}
	}
}

func installedStorageOperation(t *testing.T, pin installedStoragePin, provider, contract string, resource ContextReference, value []byte) []byte {
	t.Helper()
	python, root := os.Getenv("AGENTMUX_NATS_CREDENTIAL_PYTHON"), os.Getenv("AMX_INSTALLED_STORAGE_REPOSITORY")
	if !filepath.IsAbs(python) || !filepath.IsAbs(root) {
		t.Fatal("prepared storage operation helper required")
	}
	nonce, err := randomControlID()
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]any{}
	if contract == "capability-storage-write" {
		input["value"] = json.RawMessage(value)
	} else if contract != "capability-storage-read" {
		t.Fatal("unsupported installed storage operation")
	}
	request := contextJSON(map[string]any{"contractMaterial": pin, "provider": provider, "contractId": contract, "operationId": "storage_" + nonce, "expectedVersion": resource.Revision, "resourceRef": resource, "input": input})
	output, err := os.CreateTemp(filepath.Dir(pin.Path), "storage-operation-*.private.json")
	if err != nil {
		t.Fatal("storage operation output unavailable")
	}
	diagnostic, err := os.CreateTemp(filepath.Dir(pin.Path), "storage-operation-*.private.log")
	if err != nil {
		output.Close()
		t.Fatal("storage operation diagnostic unavailable")
	}
	command := exec.Command(python, "-B", filepath.Join(root, "platform/launcher/testdata/installed_storage_operation.py"))
	command.Dir = root
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "PYTHONDONTWRITEBYTECODE=1", "PYTHONPATH=" + filepath.Join(root, "sdk/python") + string(os.PathListSeparator) + root}
	command.Stdin = bytes.NewReader(request)
	command.Stdout = output
	command.Stderr = diagnostic
	err = command.Run()
	outErr, diagErr := output.Close(), diagnostic.Close()
	if err != nil || outErr != nil || diagErr != nil {
		t.Fatal("fresh installed storage operation admission failed")
	}
	raw, err := ReadOwnerPrivateFile(output.Name(), 65536)
	if err != nil {
		t.Fatal("fresh storage envelope unavailable")
	}
	return bytes.TrimSpace(raw)
}
