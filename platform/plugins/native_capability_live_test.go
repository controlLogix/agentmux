package plugins

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/controlLogix/agentmux/platform/localtls"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The existing Python capability fixture owns the broker, enrollment, resource
// records and this Go process. Only fixed results cross back to its supervisor.
func TestNativeCapabilityTLSIntegration(t *testing.T) {
	directory := os.Getenv("AMX_NATIVE_CAPABILITY_LIVE_DIR")
	if directory == "" {
		t.Skip("coordinated capability TLS fixture required")
	}
	if os.Getenv("AMX_CAPABILITY_LIVE") != "1" || runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Fatal("coordinated native macOS ARM64 slot required")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !filepath.IsAbs(directory) {
		t.Fatal("private fixture directory required")
	}
	processMode := os.Getenv("AMX_NATIVE_CAPABILITY_PROCESS") == "1"
	budget := 25 * time.Second
	if processMode {
		budget = 75 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	privateChild := os.Getenv("AMX_NATIVE_CAPABILITY_PRIVATE") == "1"
	manifest := fixtureManifest("native_tls_capability_test")
	if privateChild {
		manifest.InstallationModes = []string{"private-child"}
	}
	resourceClass := os.Getenv("AMX_NATIVE_CAPABILITY_CLASS")
	if resourceClass == "" {
		resourceClass = "storage"
	}
	action := os.Getenv("AMX_NATIVE_CAPABILITY_ACTION")
	if action == "" {
		action = "read"
	}
	manifest.RequestedCapabilities = []Capability{{Action: action, ResourceClass: resourceClass, Required: true}}
	if os.Getenv("AMX_NATIVE_CAPABILITY_RECOVERY") == "1" {
		manifest.RequestedCapabilities = append(manifest.RequestedCapabilities, Capability{Action: "inspect", ResourceClass: "outcome", Required: true})
	}
	if resourceClass == "outcome" {
		manifest.RequestedCapabilities = append(manifest.RequestedCapabilities, Capability{Action: "write", ResourceClass: "storage"})
	}
	if processMode {
		manifest.RequestedCapabilities = []Capability{{Action: "start", ResourceClass: "process", Required: true},
			{Action: "cancel", ResourceClass: "process", Required: true}, {Action: "inspect", ResourceClass: "outcome", Required: true}}
	}
	pkg := fixturePackage(t, manifest, map[string][]byte{"schemas/config.json": []byte(`{"type":"object"}`)})
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
	declaration := map[string]any{"owner": binding.Owner, "manifestDigest": pkg.manifest.Checksum(), "configurationChecksum": configuration.Checksum()}
	var parentBinding *ContextBinding
	if privateChild {
		parentManifest := fixtureManifest("native_tls_capability_parent")
		parentManifest.RequestedCapabilities = manifest.RequestedCapabilities
		parentPkg := fixturePackage(t, parentManifest, map[string][]byte{"schemas/config.json": []byte(`{"type":"object"}`)})
		parentConfiguration, prepareErr := PrepareConfiguration(parentPkg, nil, []byte(`{}`))
		if prepareErr != nil {
			t.Fatal("parent configuration preparation failed")
		}
		parentLifetime := make(chan struct{})
		defer close(parentLifetime)
		parentNonce, nonceErr := randomControlID()
		if nonceErr != nil {
			t.Fatal("parent identity allocation failed")
		}
		parentBinding = &ContextBinding{Owner: OwnerReference{Pin: parentPkg.Pin(), InstanceID: "parent-one", Epoch: parentNonce, Generation: 1}, Package: parentPkg, Configuration: parentConfiguration, LifetimeDone: parentLifetime}
		binding.Parent = copyParent(&parentBinding.Owner)
		binding.ParentLifetime = parentLifetime
		declaration["parent"] = map[string]any{"owner": parentBinding.Owner, "manifestDigest": parentPkg.manifest.Checksum(), "configurationChecksum": parentConfiguration.Checksum()}
	}
	nativeLiveWrite(t, directory, "go-declaration.json", declaration)
	var ready nativeCapabilityLiveReady
	nativeLiveWait(t, ctx, directory, "fixture-ready.json", func(raw []byte) bool {
		if nativeLiveDecode(raw, &ready) != nil {
			t.Fatal("fixture ready document invalid")
		}
		return !ready.Revoked
	})
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
	original, err := ReadOwnerPrivateFile(ready.OriginalEnvelopeFile, nativeAuthorityLimit)
	if err != nil {
		t.Fatal("fixture original envelope unavailable")
	}
	var authorityTransport, capabilityTransport, outcomeTransport *NativeAuthorityNATSExchange
	var gateway *NativeCapabilityGateway
	var policyHandles, storageHandles, processHandles *CapabilityHandles
	var storageMutation *CapabilityMutation
	var storageValue []byte
	var secretConsumer, secretPurpose ContextReference
	joined := false
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer closeCancel()
		good := true
		if policyHandles != nil && policyHandles.Close(closeCtx) != nil {
			good = false
		}
		if storageHandles != nil && storageHandles.Close(closeCtx) != nil {
			good = false
		}
		if processHandles != nil && processHandles.Close(closeCtx) != nil {
			good = false
		}
		if gateway != nil && gateway.Close(closeCtx) != nil {
			good = false
		}
		for _, transport := range []*NativeAuthorityNATSExchange{outcomeTransport, capabilityTransport, authorityTransport} {
			if transport != nil && transport.Close(closeCtx) != nil {
				good = false
			}
		}
		if !good {
			t.Error("original Go transport work did not join")
		}
		if joined && good {
			if processMode {
				nativeLiveWrite(t, directory, "go-result.json", map[string]any{"phase": "complete", "process": true, "recovery": true, "revocation": true, "cleanup": true})
			} else {
				nativeLiveWrite(t, directory, "go-result.json", map[string]any{"phase": "complete", "read": true, "revocation": true, "cleanup": true})
			}
		}
	}()
	options := NativeAuthorityNATSOptions{ServerURL: ready.ServerURL, Subject: ready.AuthoritySubject, CredentialsFile: ready.CredentialsFile, Trust: trust, AccountPublicKey: ready.AccountPublicKey, ReplyPrefix: ready.ReplyPrefix, PublishSubjects: ready.PublishSubjects}
	authorityTransport, err = NewNativeAuthorityNATSExchange(ctx, options)
	if err != nil {
		t.Fatal("authority TLS connection refused")
	}
	options.Subject = ready.CapabilitySubject
	capabilityTransport, err = NewNativeAuthorityNATSExchange(ctx, options)
	if err != nil {
		t.Fatal("capability TLS connection refused")
	}
	keys, err := NewNativeEnrolledKeys(authorityTransport, ready.Enrollment)
	if err != nil {
		t.Fatal("enrolled key source refused")
	}
	if ready.RequestContractID == "capability-secret-use" {
		payload, _ := json.Marshal(map[string]string{"last_by_subj": keys.subject()})
		raw, readErr := keys.request(ctx, keys.api()+"STREAM.MSG.GET."+ready.Enrollment.Stream, payload)
		var retained struct {
			Message struct {
				Data string `json:"data"`
			} `json:"message"`
		}
		if readErr != nil || json.Unmarshal(raw, &retained) != nil {
			t.Fatal("secret retained authority read refused")
		}
		record, decodeErr := base64.StdEncoding.DecodeString(retained.Message.Data)
		var owner struct {
			State json.RawMessage `json:"state"`
		}
		if decodeErr != nil || json.Unmarshal(record, &owner) != nil {
			t.Fatal("secret retained authority decode refused")
		}
		if nativeAuthoritySchema("record", record) != nil {
			t.Fatal("secret retained authority record schema refused")
		}
		if nativeAuthoritySchema("state", owner.State) != nil {
			t.Fatal("secret retained authority state schema refused")
		}
	}
	destinations := map[string]string{binding.Owner.InstanceID: ready.Service.ServiceID}
	if parentBinding != nil {
		destinations[parentBinding.Owner.InstanceID] = ready.Service.ServiceID
	}
	authority, err := NewNativeContextAuthority(NativeAuthorityClientOptions{ProfileID: ready.Enrollment.ProfileID, HubID: ready.Enrollment.HubID, AuthorityID: ready.Enrollment.AuthorityID, RequestSigningRef: ready.Enrollment.HostTransportRef, ResponseSigningRef: ready.Enrollment.IssuerRef, RequestSigningSeed: seed, ReplyPrefix: ready.ReplyPrefix, Keys: keys, Exchange: authorityTransport}, destinations)
	if err != nil {
		t.Fatal("native authority construction refused")
	}
	if parentBinding != nil {
		if _, err = authority.BindInstance(ctx, *parentBinding); err != nil {
			t.Fatal("current retained parent admission refused", err)
		}
	}
	admission, err := authority.BindInstance(ctx, binding)
	if err != nil {
		t.Fatal("current retained native admission refused")
	}
	operation, err := authority.AdmitOperation(ctx, binding.Owner, original)
	if err != nil {
		t.Fatal("original signed operation refused")
	}
	payload, _ := json.Marshal(map[string]any{"resourceRef": ready.ResourceRef, "input": ready.RequestInput})
	var approved ContextApprovedEnvelope
	if !processMode && ready.RequestContractID != "capability-secret-use" {
		approved, err = authority.PrepareDomainCall(ctx, binding.Owner, operation, ContextDomainCall{RequestID: "request_" + strings.Repeat("d", 64), BindingID: ready.BindingID, ContractID: ready.RequestContractID, Payload: payload})
		if err != nil {
			t.Fatal("issuer capability preparation refused")
		}
	}
	routes := []NativeCapabilityRoute{{BindingID: ready.BindingID, RequestContractID: ready.RequestContractID, ReplyContractID: ready.ReplyContractID, Service: ready.Service, Keys: keys, Exchange: capabilityTransport}}
	if processMode {
		if ready.RequestContractID != "capability-process-start" || ready.ReplyContractID != "capability-process-start-reply" || ready.OutcomeService == nil {
			t.Fatal("Process fixture route selection invalid")
		}
		startBinding := nativeProcessBinding(t, admission, "capability-process-start")
		if startBinding != ready.BindingID {
			t.Fatal("Process start route differs from admitted native facts")
		}
		routes = append(routes, NativeCapabilityRoute{BindingID: nativeProcessBinding(t, admission, "capability-process-cancel"), RequestContractID: "capability-process-cancel", ReplyContractID: "capability-process-cancel-reply", Service: ready.Service, Keys: keys, Exchange: capabilityTransport})
	}
	if ready.OutcomeService != nil {
		options.Subject = ready.OutcomeSubject
		outcomeTransport, err = NewNativeAuthorityNATSExchange(ctx, options)
		if err != nil {
			t.Fatal("outcome TLS connection refused")
		}
		outcomeBinding := "messages-outcome"
		if processMode {
			outcomeBinding = nativeProcessBinding(t, admission, "capability-outcome-query")
		}
		routes = append(routes, NativeCapabilityRoute{BindingID: outcomeBinding, RequestContractID: "capability-outcome-query", ReplyContractID: "capability-outcome-query-reply", Service: *ready.OutcomeService, Keys: keys, Exchange: outcomeTransport})
	}
	gateway, err = NewNativeCapabilityGateway(authority, routes)
	if err != nil {
		t.Fatal("native capability gateway construction refused")
	}
	if processMode {
		nativeProcessCapabilityFlow(t, ctx, directory, ready, binding, admission, operation, authority, gateway, &processHandles)
		joined = true
		return
	}
	var reply []byte
	if ready.RequestContractID != "capability-storage-write" && ready.RequestContractID != "capability-secret-use" {
		reply, err = gateway.Domain(ctx, approved.Clone())
		if err != nil {
			t.Fatal("signed TLS capability read refused")
		}
	}
	var content struct {
		Data []byte `json:"data"`
	}
	if ready.RequestContractID == "capability-secret-use" {
		var input struct {
			Consumer ContextReference `json:"consumerRef"`
			Purpose  ContextReference `json:"purposeRef"`
		}
		if json.Unmarshal(ready.RequestInput, &input) != nil {
			t.Fatal("secret consumer references invalid")
		}
		secretConsumer, secretPurpose = input.Consumer, input.Purpose
		storageHandles, err = OpenCapabilityHandles(ctx, binding, admission, operation, CapabilityHandlePorts{Authority: authority, Domain: gateway.Domain, Now: time.Now})
		if err != nil {
			t.Fatal("typed secret handle construction refused")
		}
		storageMutation, err = storageHandles.Secret.PrepareUse(ctx, ready.ResourceRef, secretConsumer, secretPurpose)
		if err != nil {
			t.Fatal("typed secret preparation refused")
		}
		recovery, saveErr := storageMutation.RecoveryBytes()
		if saveErr != nil {
			t.Fatal("original secret recovery unavailable")
		}
		nativeLiveWrite(t, directory, "secret-mutation.json", json.RawMessage(recovery))
		result, useErr := storageHandles.Secret.Use(ctx, storageMutation, ready.ResourceRef, secretConsumer, secretPurpose)
		if useErr != nil || result.Outcome() != "accepted" || !contextReferenceValid(result.Reference()) {
			t.Fatal("typed secret use refused", useErr, result.Outcome())
		}
		if ready.OutcomeService != nil {
			recovered, recoveryErr := storageHandles.Reconcile(ctx, storageMutation)
			record, present := recovered.Record()
			if recoveryErr != nil || recovered.Outcome() != "committed" || !present || record != result.Reference() {
				t.Fatal("typed secret recovery lost original receipt")
			}
		}
	} else if ready.RequestContractID == "capability-storage-write" {
		var input struct {
			Value json.RawMessage `json:"value"`
		}
		encoded, _ := json.Marshal(ready.RequestInput)
		if json.Unmarshal(encoded, &input) != nil || len(input.Value) == 0 {
			t.Fatal("storage command input invalid")
		}
		storageValue = input.Value
		storageHandles, err = OpenCapabilityHandles(ctx, binding, admission, operation, CapabilityHandlePorts{Authority: authority, Domain: gateway.Domain, Now: time.Now})
		if err != nil {
			t.Fatal("typed storage handle construction refused")
		}
		storageMutation, err = storageHandles.Storage.PrepareCompareAndSwap(ctx, ready.ResourceRef, storageValue)
		if err != nil {
			t.Fatal("typed storage preparation refused")
		}
		recovery, saveErr := storageMutation.RecoveryBytes()
		if saveErr != nil {
			t.Fatal("original storage recovery unavailable")
		}
		nativeLiveWrite(t, directory, "storage-mutation.json", json.RawMessage(recovery))
		if ready.OutcomeService != nil {
			absent, absentErr := storageHandles.Reconcile(ctx, storageMutation)
			_, hasRecord := absent.Record()
			_, hasResource := absent.ResourceReference()
			if absentErr != nil || absent.Outcome() != "absent" || hasRecord || hasResource {
				t.Fatal("prepared undispatched storage write could not reconcile as absent")
			}
		}
		result, callErr := storageHandles.Storage.CompareAndSwap(ctx, storageMutation, ready.ResourceRef, storageValue)
		updated, present := result.ResourceReference()
		if callErr != nil || result.Outcome() != "applied" || !present || updated.Revision <= ready.ResourceRef.Revision {
			t.Fatal("typed storage effect refused")
		}
		if ready.OutcomeService != nil {
			committed, outcomeErr := storageHandles.Reconcile(ctx, storageMutation)
			record, hasRecord := committed.Record()
			if outcomeErr != nil || committed.Outcome() != "committed" || !hasRecord || record != result.Reference() {
				t.Fatal("committed storage write lost original recovery result")
			}
		}
		replayed, replayErr := storageHandles.Storage.CompareAndSwap(ctx, storageMutation, ready.ResourceRef, storageValue)
		if replayErr != nil || replayed.Reference() != result.Reference() {
			t.Fatal("typed storage replay changed original result")
		}
	} else if ready.RequestContractID == "capability-policy-evaluate" {
		var decision struct {
			Receipt ContextReference `json:"receiptRef"`
			Outcome string           `json:"outcome"`
		}
		if nativeCapabilitySchema(ready.ReplyContractID, reply) != nil || json.Unmarshal(reply, &decision) != nil || decision.Outcome != "allow" || !contextReferenceValid(decision.Receipt) || decision.Receipt.OwnerHubID != ready.ResourceRef.OwnerHubID {
			t.Fatal("retained policy decision refused")
		}
		handles, openErr := OpenCapabilityHandles(ctx, binding, admission, operation, CapabilityHandlePorts{Authority: authority, Domain: gateway.Domain, Now: time.Now})
		if openErr != nil {
			t.Fatal("typed policy handle construction refused")
		}
		policyHandles = handles
		var access CapabilityAccess
		encoded, _ := json.Marshal(ready.RequestInput)
		if json.Unmarshal(encoded, &access) != nil {
			t.Fatal("policy access input invalid")
		}
		result, callErr := handles.Policy.Evaluate(ctx, ready.ResourceRef, access)
		if callErr != nil || result.Outcome() != "allow" || !contextReferenceValid(result.Reference()) {
			t.Fatal("actual typed policy evaluation or original cleanup refused")
		}
	} else if ready.ReplyPayloadDigest != "" {
		if nativeAuthorityDigest(reply) != ready.ReplyPayloadDigest {
			t.Fatal("original owner reply changed across native delivery")
		}
	} else if json.Unmarshal(reply, &content) != nil || nativeAuthorityDigest(content.Data) != ready.ResourceDigest {
		t.Fatal("retained record changed across native delivery")
	}
	if ready.OutcomeService != nil {
		// Recovery checks use several bounded requests. Prepare an unused delivery
		// now so revocation is tested inside its original five-second validity.
		approved, err = authority.PrepareDomainCall(ctx, binding.Owner, operation, ContextDomainCall{RequestID: "request_" + strings.Repeat("d", 64), BindingID: ready.BindingID, ContractID: ready.RequestContractID, Payload: payload})
		if err != nil {
			t.Fatal("fresh revocation delivery preparation refused")
		}
	}
	if privateChild {
		nativeLiveWrite(t, directory, "go-prepared.json", map[string]any{"request": approved.delivery.serviceRequest})
	}
	nativeLiveWrite(t, directory, "go-result.json", map[string]any{"phase": "read-complete"})
	nativeLiveWait(t, ctx, directory, "fixture-ready.json", func(raw []byte) bool {
		var next nativeCapabilityLiveReady
		if nativeLiveDecode(raw, &next) != nil {
			t.Fatal("fixture revocation document invalid")
		}
		return next.Revoked
	})
	var signed struct {
		Claims struct {
			ValidUntil string `json:"validUntil"`
		} `json:"claims"`
	}
	if json.Unmarshal(approved.delivery.serviceRequest, &signed) != nil {
		t.Fatal("prepared deadline missing")
	}
	expiry, err := nativeAuthorityTime(signed.Claims.ValidUntil)
	if err != nil || !time.Now().Add(100*time.Millisecond).Before(expiry) {
		t.Fatal("revocation was not observed before prepared delivery expiry")
	}
	if authority.Recheck(ctx, binding.Owner, admission, &operation) == nil {
		t.Fatal("persisted revocation did not refuse source authority")
	}
	if raw, err := gateway.Domain(ctx, approved.Clone()); err == nil || raw != nil {
		t.Fatal("revoked owner disclosed retained bytes")
	}
	if policyHandles != nil {
		var access CapabilityAccess
		encoded, _ := json.Marshal(ready.RequestInput)
		if json.Unmarshal(encoded, &access) != nil {
			t.Fatal("policy access input invalid")
		}
		if _, err := policyHandles.Policy.Evaluate(ctx, ready.ResourceRef, access); err == nil {
			t.Fatal("revoked typed policy handle remained usable")
		}
	}
	if storageHandles != nil {
		if ready.RequestContractID == "capability-secret-use" {
			if _, err := storageHandles.Secret.Use(ctx, storageMutation, ready.ResourceRef, secretConsumer, secretPurpose); err == nil {
				t.Fatal("revoked typed secret handle remained usable")
			}
		} else if _, err := storageHandles.Storage.CompareAndSwap(ctx, storageMutation, ready.ResourceRef, storageValue); err == nil {
			t.Fatal("revoked typed storage handle remained usable")
		}
	}
	joined = true
}

type nativeCapabilityLiveReady struct {
	LeafCertificateSHA256 string                          `json:"leafCertificateSha256"`
	AccountPublicKey      string                          `json:"accountPublicKey"`
	ReplyPrefix           string                          `json:"replyPrefix"`
	PublishSubjects       []string                        `json:"publishSubjects"`
	ServerURL             string                          `json:"serverUrl"`
	AuthoritySubject      string                          `json:"authoritySubject"`
	CapabilitySubject     string                          `json:"capabilitySubject"`
	CredentialsFile       string                          `json:"credentialsFile"`
	CAFile                string                          `json:"caFile"`
	TLSName               string                          `json:"tlsName"`
	HostSigningSeedFile   string                          `json:"hostSigningSeedFile"`
	OriginalEnvelopeFile  string                          `json:"originalEnvelopeFile"`
	Enrollment            NativeEnrolledKeyOptions        `json:"enrollment"`
	Service               NativeCapabilityServiceBinding  `json:"service"`
	OutcomeService        *NativeCapabilityServiceBinding `json:"outcomeService,omitempty"`
	OutcomeSubject        string                          `json:"outcomeSubject,omitempty"`
	BindingID             string                          `json:"bindingId"`
	ResourceRef           ContextReference                `json:"resourceRef"`
	RequestContractID     string                          `json:"requestContractId"`
	ReplyContractID       string                          `json:"replyContractId"`
	RequestInput          json.RawMessage                 `json:"requestInput"`
	ReplyPayloadDigest    string                          `json:"replyPayloadDigest"`
	ResourceDigest        string                          `json:"resourceDigest"`
	Revoked               bool                            `json:"revoked"`
}

func nativeLiveDecode(raw []byte, value any) error {
	if strictDocument(raw) != nil {
		return pluginError("native_live_document_invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}
func nativeLiveWrite(t *testing.T, directory, name string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal("fixture result encoding failed")
	}
	file, err := os.CreateTemp(directory, ".go-handoff-")
	if err != nil {
		t.Fatal("fixture result creation failed")
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if _, err = file.Write(raw); err != nil {
		_ = file.Close()
		t.Fatal("fixture result write failed")
	}
	if file.Close() != nil || os.Rename(temporary, filepath.Join(directory, name)) != nil {
		t.Fatal("fixture result publication failed")
	}
}
func nativeLiveWait(t *testing.T, ctx context.Context, directory, name string, accept func([]byte) bool) {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		raw, err := ReadOwnerPrivateFile(filepath.Join(directory, name), nativeAuthorityLimit)
		if err == nil && accept(raw) {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("fixture handoff deadline elapsed")
		case <-ticker.C:
		}
	}
}
