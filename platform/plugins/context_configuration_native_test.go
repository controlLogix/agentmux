package plugins

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type nativeConfigurationTestKeys struct {
	public      ed25519.PublicKey
	calls       atomic.Int32
	revokeAfter int32
	verified    chan struct{}
	once        sync.Once
}

func TestNativeConfigurationOwnerRequiresEnrolledCallerReplyPrefix(t *testing.T) {
	f := configurationWireFixture(t)
	authority := f.authority.authority
	const caller = "_INBOX.enrolledcaller123456"
	authority.client.options.ReplyPrefix = caller
	for _, prefix := range []string{caller, "_INBOX.serviceoutbound123456", "", caller + "\n"} {
		owner, err := NewNativeConfigurationOwner(authority, &NativeEnrolledKeys{}, map[string]NativeConfigurationClientBinding{
			f.authority.binding.Owner.InstanceID: {Binding: f.binding, Exchange: &nativeConfigurationTestExchange{}, ReplyPrefix: prefix},
		})
		if prefix == caller {
			if err != nil || owner == nil {
				t.Fatal("enrolled caller prefix refused")
			}
			if err := owner.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		} else if owner != nil || err == nil {
			t.Fatal("unbound configuration reply prefix admitted")
		}
	}
	if owner, err := NewNativeConfigurationOwner(&NativeContextAuthority{}, &NativeEnrolledKeys{}, nil); owner != nil || err == nil {
		t.Fatal("uninitialized authority admitted")
	}
}

func (k *nativeConfigurationTestKeys) CurrentConfigurationKey(context.Context, NativeConfigurationServiceBinding) (NativeAuthorityKey, error) {
	count := k.calls.Add(1)
	if count >= 4 && k.verified != nil {
		k.once.Do(func() { close(k.verified) })
	}
	if k.revokeAfter > 0 && count > k.revokeAfter {
		return NativeAuthorityKey{}, errors.New("fixture signer revoked")
	}
	return NativeAuthorityKey{PublicKey: k.public, NotBefore: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(time.Hour), AuthoritySequence: 7}, nil
}

type nativeConfigurationWireFixture struct {
	authority *nativeAuthorityFixture
	binding   NativeConfigurationBinding
	keys      *nativeConfigurationTestKeys
	revision  uint64
}

func configurationWireFixture(t *testing.T) *nativeConfigurationWireFixture {
	t.Helper()
	a := newNativeAuthorityFixture(t)
	return &nativeConfigurationWireFixture{authority: a, revision: 7, keys: &nativeConfigurationTestKeys{public: a.response.Public().(ed25519.PublicKey)}, binding: NativeConfigurationBinding{ConfigurationRef: ContextReference{"configuration_one", "context_hub", 7}, Service: NativeConfigurationServiceBinding{ProfileID: "profile", HubID: "context_hub", ServiceInstanceID: "configuration_instance", ServiceIdentityRef: ContextReference{"configuration_identity", "context_hub", 1}, SigningKeyRef: a.responseRef}, AuthorityRef: ContextReference{"native_authority", "context_hub", 1}}}
}
func (f *nativeConfigurationWireFixture) request(t *testing.T, contract string, after uint64) []byte {
	t.Helper()
	var operation map[string]any
	json.Unmarshal(fieldsForClaim(contextTestEnvelope("configuration"), "operation"), &operation)
	operation["deadline"] = nativeAuthorityStamp(time.Now().Add(4 * time.Second))
	payload := map[string]any{"configurationRef": f.binding.ConfigurationRef, "owner": f.authority.binding.Owner}
	if contract == "configuration-set" {
		payload["schemaRef"] = f.authority.binding.Configuration.SchemaRef()
		payload["configurationBytes"] = base64.StdEncoding.EncodeToString(f.authority.binding.Configuration.Bytes())
		payload["secretReferences"] = []ContextReference{}
	}
	if contract == "configuration-watch" {
		payload["afterRevision"] = after
	}
	raw := f.authority.envelope(t, operation, payload, contract)
	var envelope map[string]any
	json.Unmarshal(raw, &envelope)
	envelope["destinationServiceId"] = "configuration-owner"
	attestation := envelope["ingressAttestation"].(map[string]any)
	claims := attestation["claims"].(map[string]any)
	claims["audience"].(map[string]any)["serviceId"] = "configuration-owner"
	signed, err := nativeAuthoritySign(contextJSON(claims), f.authority.response)
	if err != nil {
		t.Fatal(err)
	}
	envelope["ingressAttestation"] = json.RawMessage(signed)
	raw = contextJSON(envelope)
	if nativeAuthoritySchema("envelope", raw) != nil {
		t.Fatal("configuration request fixture does not match envelope schema")
	}
	return raw
}
func (f *nativeConfigurationWireFixture) reply(t *testing.T, request []byte, change func(map[string]any)) []byte {
	t.Helper()
	configuration := f.authority.binding.Configuration
	claims := map[string]any{"purpose": "agentmux-configuration-response-v1", "requestDigest": nativeAuthorityDigestMustCanonical(request), "configurationRef": ContextReference{f.binding.ConfigurationRef.ID, "context_hub", f.revision}, "owner": f.authority.binding.Owner, "authorityRef": ContextReference{"native_authority", "context_hub", 7}, "signingKeyRef": f.binding.Service.SigningKeyRef, "issuedAt": nativeAuthorityStamp(time.Now().Add(-time.Millisecond)), "validUntil": nativeAuthorityStamp(time.Now().Add(3 * time.Second)), "state": map[string]any{"format": "amx-configuration-v1", "owner": f.authority.binding.Owner, "schemaRef": configuration.SchemaRef(), "configurationBytes": base64.StdEncoding.EncodeToString(configuration.Bytes()), "secretReferences": []ContextReference{}, "configurationChecksum": configuration.Checksum(), "revision": f.revision}}
	if change != nil {
		change(claims)
	}
	canonical, err := nativeAuthorityCanonical(contextJSON(claims))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := nativeAuthorityCanonical(contextJSON(map[string]any{"claims": claims, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.authority.response, canonical))}))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestNativeConfigurationReplyRequiresCurrentSignerAndExactBindings(t *testing.T) {
	f := configurationWireFixture(t)
	request := f.request(t, "configuration-read", 0)
	raw := f.reply(t, request, nil)
	snapshot, _, err := verifyNativeConfigurationResponse(context.Background(), raw, request, f.authority.binding, f.binding, f.keys)
	if err != nil || snapshot.Revision != 7 || !bytes.Equal(snapshot.Configuration.Bytes(), f.authority.binding.Configuration.Bytes()) || f.keys.calls.Load() != 2 {
		t.Fatal("valid signed configuration reply refused or final signer was not checked", err)
	}
	for _, kind := range []string{"purpose", "request", "owner", "reference", "checksum", "schema", "expiry", "signer-revoked", "signature"} {
		t.Run(kind, func(t *testing.T) {
			f := configurationWireFixture(t)
			request := f.request(t, "configuration-read", 0)
			raw := f.reply(t, request, func(claims map[string]any) {
				state := claims["state"].(map[string]any)
				switch kind {
				case "purpose":
					claims["purpose"] = "agentmux-capability-service-response-v1"
				case "request":
					claims["requestDigest"] = "sha256:" + string(bytes.Repeat([]byte{'b'}, 64))
				case "owner":
					owner := f.authority.binding.Owner
					owner.Generation++
					claims["owner"] = owner
					state["owner"] = owner
				case "reference":
					claims["configurationRef"] = ContextReference{"another_configuration", "context_hub", 7}
				case "checksum":
					state["configurationChecksum"] = "sha256:" + string(bytes.Repeat([]byte{'b'}, 64))
				case "schema":
					state["schemaRef"] = "schemas/other.json"
				case "expiry":
					claims["validUntil"] = nativeAuthorityStamp(time.Now().Add(-time.Second))
				}
			})
			if kind == "signer-revoked" {
				f.keys.revokeAfter = 1
			}
			if kind == "signature" {
				var value map[string]any
				json.Unmarshal(raw, &value)
				value["signature"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, ed25519.SignatureSize))
				raw, _ = nativeAuthorityCanonical(contextJSON(value))
			}
			if _, _, err := verifyNativeConfigurationResponse(context.Background(), raw, request, f.authority.binding, f.binding, f.keys); err == nil {
				t.Fatal("invalid configuration reply was released")
			}
		})
	}
}

type nativeConfigurationTestPreparer struct {
	fixture *nativeConfigurationWireFixture
	t       *testing.T
}

func (p nativeConfigurationTestPreparer) PrepareConfigurationRequest(_ context.Context, _ OwnerReference, _ ContextReference, contract string, after uint64, cancellation ContextReference) ([]byte, error) {
	request := p.fixture.request(p.t, contract, after)
	var envelope map[string]any
	json.Unmarshal(request, &envelope)
	operation := envelope["operation"].(map[string]any)
	operation["cancellationRef"] = cancellation
	// The offline fixture signs a new matching ingress attestation; production
	// uses the enrolled authority method, never this fixture preparer.
	claims := envelope["ingressAttestation"].(map[string]any)["claims"].(map[string]any)
	claims["operation"] = operation
	signed, err := nativeAuthoritySign(contextJSON(claims), p.fixture.authority.response)
	if err != nil {
		p.t.Fatal(err)
	}
	envelope["ingressAttestation"] = json.RawMessage(signed)
	return contextJSON(envelope), nil
}

type nativeConfigurationTestExchange struct {
	fixture              *nativeConfigurationWireFixture
	t                    *testing.T
	mu                   sync.Mutex
	watches, reads       int
	activeWatch          bool
	rearmed              chan struct{}
	once                 sync.Once
	unjoined             atomic.Bool
	closeCalls           atomic.Int32
	nextRevision         atomic.Uint64
	changedSecret        atomic.Bool
	refusedRead          atomic.Bool
	assertRearm          bool
	remoteCleanupBlocked atomic.Bool
	remoteCloseCalls     atomic.Int32
	watchEntered         chan struct{}
	watchEnteredOnce     sync.Once
	watchFailure         chan struct{}
	watchCatchUp         bool
	watchAfter           []uint64
	watchChanged         chan struct{}
}

type nativeConfigurationTestWatchCleanup struct {
	exchange *nativeConfigurationTestExchange
}

func (w *nativeConfigurationTestWatchCleanup) Close(ctx context.Context) error {
	w.exchange.remoteCloseCalls.Add(1)
	if ctx.Err() != nil || w.exchange.remoteCleanupBlocked.Load() {
		return errors.New("original remote watch not joined")
	}
	return nil
}
func (e *nativeConfigurationTestExchange) testWatchCleanup() nativeConfigurationWatchCleanup {
	return &nativeConfigurationTestWatchCleanup{e}
}
func (p nativeConfigurationTestPreparer) prepareConfigurationWatchCleanup(_ context.Context, _ []byte, input NativeConfigurationClientBinding, _ NativeConfigurationKeySource) (nativeConfigurationWatchCleanup, error) {
	exchange, ok := input.Exchange.(interface {
		testWatchCleanup() nativeConfigurationWatchCleanup
	})
	if !ok {
		return nil, errors.New("fixture watch cleanup unavailable")
	}
	return exchange.testWatchCleanup(), nil
}

func TestNativeConfigurationRemoteWatchJoinRequiredBeforeDoneOrRearm(t *testing.T) {
	f := configurationWireFixture(t)
	exchange := &nativeConfigurationTestExchange{fixture: f, t: t, rearmed: make(chan struct{})}
	exchange.remoteCleanupBlocked.Store(true)
	owner := &NativeConfigurationOwner{authority: nativeConfigurationTestPreparer{f, t}, keys: f.keys, bindings: map[string]NativeConfigurationClientBinding{f.authority.binding.Owner.InstanceID: {Binding: f.binding, Exchange: exchange, ReplyPrefix: "_INBOX.configurationfixture"}}, leases: map[*nativeConfigurationLease]bool{}, watchBudget: 20 * time.Millisecond}
	lease, err := owner.Open(context.Background(), f.authority.binding)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	select {
	case <-lease.(*nativeConfigurationLease).workerDone:
	case <-ctx.Done():
		t.Fatal("original worker did not finish its failed cleanup attempt")
	}
	if err := owner.Close(ctx); err == nil || completed(lease.Done()) {
		t.Fatal("unconfirmed remote watch reported joined")
	}
	exchange.mu.Lock()
	reads, watches := exchange.reads, exchange.watches
	exchange.mu.Unlock()
	owner.mu.Lock()
	retained := len(owner.leases)
	owner.mu.Unlock()
	if reads != 1 || watches != 1 || retained != 1 {
		t.Fatal("uncertain watch was discarded or configuration tracking rearmed")
	}
	exchange.remoteCleanupBlocked.Store(false)
	if err := owner.Close(ctx); err != nil || !completed(lease.Done()) {
		t.Fatal("same original remote cleanup could not finish")
	}
	owner.mu.Lock()
	retained = len(owner.leases)
	owner.mu.Unlock()
	if retained != 0 || exchange.remoteCloseCalls.Load() < 3 {
		t.Fatal("original remote cleanup was not retained through retries")
	}
}

func TestNativeConfigurationFailureInvalidatesActualContextBeforeRemoteJoin(t *testing.T) {
	wire := configurationWireFixture(t)
	exchange := &nativeConfigurationTestExchange{fixture: wire, t: t, rearmed: make(chan struct{}), watchEntered: make(chan struct{}), watchFailure: make(chan struct{})}
	exchange.remoteCleanupBlocked.Store(true)
	var owner *NativeConfigurationOwner
	f := newContextTestFixture(t, func(binding *ContextBinding, ports *ContextPorts) {
		wire.authority.binding = cloneContextBinding(*binding)
		owner = &NativeConfigurationOwner{authority: nativeConfigurationTestPreparer{wire, t}, keys: wire.keys, bindings: map[string]NativeConfigurationClientBinding{binding.Owner.InstanceID: {Binding: wire.binding, Exchange: exchange, ReplyPrefix: "_INBOX.configurationfixture"}}, leases: map[*nativeConfigurationLease]bool{}}
		ports.Configuration = owner
	})
	defer func() {
		exchange.remoteCleanupBlocked.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := owner.Close(ctx); err != nil {
			t.Error("original remote configuration cleanup did not recover")
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	select {
	case <-exchange.watchEntered:
	case <-ctx.Done():
		t.Fatal("original native watch did not start")
	}
	result := make(chan contextDispatchResult, 1)
	go func() {
		raw, err := f.lease.Dispatch(ctx, contextTestEnvelope("a"))
		result <- contextDispatchResult{raw, err}
	}()
	select {
	case <-f.connection.invokes:
	case r := <-result:
		t.Fatalf("operation refused before configuration failure: %v", r.err)
	case <-ctx.Done():
		t.Fatal("operation did not start before configuration failure")
	}
	lease := f.lease.configurationLease.(*nativeConfigurationLease)
	close(exchange.watchFailure)
	select {
	case <-f.lease.Done():
	case <-ctx.Done():
		t.Fatal("terminal configuration failure did not invalidate actual context")
	}
	select {
	case r := <-result:
		if r.err == nil {
			t.Fatal("active operation survived terminal configuration failure")
		}
	case <-ctx.Done():
		t.Fatal("active operation was not canceled")
	}
	if _, err := f.lease.Dispatch(ctx, contextTestEnvelope("b")); err == nil {
		t.Fatal("new operation admitted after terminal configuration failure")
	}
	var request contextServiceRequest
	if json.Unmarshal(f.request("log", "write", nil, map[string]any{"eventCode": "operation_started"}), &request) != nil {
		t.Fatal("invalid service request fixture")
	}
	if _, code := f.lease.serve(request); code != "context_owner_stale" {
		t.Fatal("non-configuration service remained available")
	}
	if completed(lease.Done()) || f.lease.Close(ctx) == nil {
		t.Fatal("unjoined remote owner reported cleanup complete")
	}
	owner.mu.Lock()
	retained := len(owner.leases)
	owner.mu.Unlock()
	if retained != 1 {
		t.Fatal("actual provider discarded original remote owner")
	}
	exchange.remoteCleanupBlocked.Store(false)
	if err := f.lease.Close(ctx); err != nil || !completed(lease.Done()) {
		t.Fatal("actual provider could not join the same original owner")
	}
	exchange.mu.Lock()
	watches := exchange.watches
	exchange.mu.Unlock()
	if watches != 1 || exchange.remoteCloseCalls.Load() < 2 {
		t.Fatal("cleanup retry replaced original watch")
	}
}

func nativeConfigurationStartingContext(t *testing.T, generic ...bool) (*contextTestFixture, *NativeConfigurationOwner, *nativeConfigurationTestExchange, *nativeContextLifecycle) {
	t.Helper()
	wire := configurationWireFixture(t)
	exchange := &nativeConfigurationTestExchange{fixture: wire, t: t, rearmed: make(chan struct{}), watchEntered: make(chan struct{}), watchCatchUp: true, watchChanged: make(chan struct{}, 1)}
	var owner *NativeConfigurationOwner
	var lifecycle *nativeContextLifecycle
	f := newContextTestFixture(t, func(binding *ContextBinding, ports *ContextPorts) {
		lifecycle = newNativeContextLifecycle(binding.Owner)
		binding.Lifecycle = lifecycle
		wire.authority.binding = cloneContextBinding(*binding)
		owner = &NativeConfigurationOwner{authority: nativeConfigurationTestPreparer{wire, t}, keys: wire.keys, bindings: map[string]NativeConfigurationClientBinding{binding.Owner.InstanceID: {Binding: wire.binding, Exchange: exchange, ReplyPrefix: "_INBOX.configurationfixture"}}, leases: map[*nativeConfigurationLease]bool{}}
		ports.Configuration = owner
		if len(generic) > 0 && generic[0] {
			ports.Configuration = struct{ ContextConfigurationOwner }{owner}
		}
	})
	return f, owner, exchange, lifecycle
}

func TestNativeConfigurationWatchWaitsForTrustedReadyAndReconcilesStartupGap(t *testing.T) {
	f, _, exchange, lifecycle := nativeConfigurationStartingContext(t)
	lease := f.lease.configurationLease.(*nativeConfigurationLease)
	exchange.mu.Lock()
	reads, watches := exchange.reads, exchange.watches
	exchange.mu.Unlock()
	if reads != 1 || watches != 0 {
		t.Fatal("private opening did not reuse its verified initial read before background work")
	}
	if lifecycle.ReportHealth("healthy") != nil || completed(lifecycle.nativeReadyDone()) {
		t.Fatal("plugin health report advanced trusted readiness")
	}
	lease.mu.Lock()
	changed := lease.changed
	lease.mu.Unlock()
	// A committed revision during the gap must be requested from the original
	// snapshot revision; no notification or revision may be skipped.
	exchange.nextRevision.Store(8)
	if !lifecycle.markReady() {
		t.Fatal("trusted native readiness refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	select {
	case <-changed:
	case <-ctx.Done():
		t.Fatal("first watch did not reconcile the startup gap")
	}
	exchange.mu.Lock()
	after := append([]uint64(nil), exchange.watchAfter...)
	exchange.mu.Unlock()
	if len(after) == 0 || after[0] != 7 {
		t.Fatal("first watch skipped the admitted snapshot revision")
	}
	snapshot, err := f.lease.configuration.Read(ctx)
	if err != nil || snapshot.Revision != 8 {
		t.Fatal("actual context did not disclose the fresh reconciled revision")
	}
	if err := f.lease.Close(ctx); err != nil || !completed(lease.Done()) {
		t.Fatal("original gated watch did not join")
	}
}

func TestNativeConfigurationWatchWaitingForReadyJoinsFailedStartup(t *testing.T) {
	for _, stop := range []string{"close", "drain", "lifetime"} {
		t.Run(stop, func(t *testing.T) {
			f, owner, exchange, lifecycle := nativeConfigurationStartingContext(t)
			lease := f.lease.configurationLease.(*nativeConfigurationLease)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			switch stop {
			case "drain":
				lifecycle.beginDrain()
				lease.requestConfigurationWatch()
				if completed(lease.watchDemand) {
					t.Fatal("failed-start drain admitted new watch demand")
				}
			case "lifetime":
				close(f.lifetime)
			}
			if stop != "close" {
				select {
				case <-lease.Done():
				case <-ctx.Done():
					t.Fatal("failed native start did not release the waiting watch worker")
				}
			}
			if err := f.lease.Close(ctx); err != nil || !completed(lease.Done()) {
				t.Fatal("failed startup did not join its original waiting worker")
			}
			exchange.mu.Lock()
			reads, watches := exchange.reads, exchange.watches
			exchange.mu.Unlock()
			owner.mu.Lock()
			retained := len(owner.leases)
			owner.mu.Unlock()
			if reads != 1 || watches != 0 || retained != 0 || exchange.remoteCloseCalls.Load() != 0 {
				t.Fatal("failed startup allocated a watch or abandoned its original owner")
			}
		})
	}
}

func TestNativeConfigurationReadyBeforeDrainKeepsOwnedWatchLive(t *testing.T) {
	f, _, exchange, lifecycle := nativeConfigurationStartingContext(t)
	if !lifecycle.markReady() {
		t.Fatal("native readiness refused")
	}
	lifecycle.beginDrain()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	select {
	case <-exchange.watchEntered:
	case <-ctx.Done():
		t.Fatal("running owner's configuration watch was lost during drain")
	}
	lease := f.lease.configurationLease.(*nativeConfigurationLease)
	if completed(lease.Done()) || completed(f.lease.Done()) {
		t.Fatal("graceful drain invalidated original configuration context")
	}
	if _, err := f.lease.configuration.Read(ctx); err != nil {
		t.Fatal("admitted configuration read failed during graceful drain")
	}
	if err := f.lease.Close(ctx); err != nil || !completed(lease.Done()) {
		t.Fatal("running original watch did not join after drain")
	}
}

func TestNativeConfigurationPreReadyNextStartsOwnedWatchOnDemand(t *testing.T) {
	f, _, exchange, lifecycle := nativeConfigurationStartingContext(t)
	lease := f.lease.configurationLease.(*nativeConfigurationLease)
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := f.lease.configuration.Next(canceled, 7); err == nil || completed(lease.watchDemand) {
		t.Fatal("canceled request started background work")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	type result struct {
		snapshot ContextConfigurationSnapshot
		err      error
	}
	done := make(chan result, 1)
	go func() { snapshot, err := f.lease.configuration.Next(ctx, 7); done <- result{snapshot, err} }()
	select {
	case <-exchange.watchEntered:
	case <-ctx.Done():
		t.Fatal("pre-ready configuration wait did not start its original watch")
	}
	exchange.nextRevision.Store(8)
	exchange.watchChanged <- struct{}{}
	select {
	case got := <-done:
		if got.err != nil || got.snapshot.Revision != 8 {
			t.Fatal("pre-ready configuration wait missed current revision")
		}
	case <-ctx.Done():
		t.Fatal("pre-ready configuration wait deadlocked readiness")
	}
	if completed(lifecycle.nativeReadyDone()) || lifecycle.Snapshot().Ready {
		t.Fatal("configuration demand invented native readiness")
	}
	if err := f.lease.Close(ctx); err != nil || !completed(lease.Done()) {
		t.Fatal("pre-ready demand lost its original watch cleanup")
	}
}

func (e *nativeConfigurationTestExchange) ConfigurationReusable() bool {
	return !e.unjoined.Load()
}

func (e *nativeConfigurationTestExchange) Close(context.Context) error {
	e.closeCalls.Add(1)
	if e.unjoined.Load() {
		return errors.New("original subscription cleanup unresolved")
	}
	return nil
}

func (e *nativeConfigurationTestExchange) ExchangeConfiguration(ctx context.Context, _ string, request []byte) ([]byte, error) {
	var input struct {
		ContractID string `json:"contractId"`
		Payload    struct {
			AfterRevision uint64 `json:"afterRevision"`
		} `json:"payload"`
	}
	json.Unmarshal(request, &input)
	if input.ContractID == "configuration-watch" {
		e.mu.Lock()
		if e.activeWatch {
			e.mu.Unlock()
			return nil, errors.New("overlapping watch")
		}
		e.activeWatch = true
		e.watches++
		e.watchAfter = append(e.watchAfter, input.Payload.AfterRevision)
		e.mu.Unlock()
		if e.watchEntered != nil {
			e.watchEnteredOnce.Do(func() { close(e.watchEntered) })
		}
		if revision := e.nextRevision.Load(); e.watchCatchUp && revision > input.Payload.AfterRevision {
			e.mu.Lock()
			e.activeWatch = false
			e.mu.Unlock()
			return e.fixture.reply(e.t, request, func(claims map[string]any) {
				claims["configurationRef"] = ContextReference{e.fixture.binding.ConfigurationRef.ID, "context_hub", revision}
				claims["state"].(map[string]any)["revision"] = revision
			}), nil
		}
		select {
		case <-ctx.Done():
		case <-e.watchFailure:
		case <-e.watchChanged:
		}
		// The original request is joined before the rearm read may begin.
		e.mu.Lock()
		e.activeWatch = false
		e.mu.Unlock()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if revision := e.nextRevision.Load(); e.watchCatchUp && revision > input.Payload.AfterRevision {
			return e.fixture.reply(e.t, request, func(claims map[string]any) {
				claims["configurationRef"] = ContextReference{e.fixture.binding.ConfigurationRef.ID, "context_hub", revision}
				claims["state"].(map[string]any)["revision"] = revision
			}), nil
		}
		return nil, errors.New("original remote configuration watch failed")
	}
	e.mu.Lock()
	e.reads++
	reads, active := e.reads, e.activeWatch
	e.mu.Unlock()
	if e.assertRearm && active && reads == 2 {
		return nil, errors.New("read before original watch joined")
	}
	if reads > 1 {
		e.once.Do(func() { close(e.rearmed) })
	}
	if e.refusedRead.Load() {
		return nil, errors.New("configuration read refused")
	}
	return e.fixture.reply(e.t, request, func(claims map[string]any) {
		if revision := e.nextRevision.Load(); revision != 0 {
			claims["configurationRef"] = ContextReference{e.fixture.binding.ConfigurationRef.ID, "context_hub", revision}
			claims["state"].(map[string]any)["revision"] = revision
		}
		if e.changedSecret.Load() {
			claims["state"].(map[string]any)["secretReferences"] = []ContextReference{{"new_secret", "context_hub", 1}}
		}
	}), nil
}
func TestNativeConfigurationIdleWatchRearmsOnlyAfterVerifiedRead(t *testing.T) {
	f := configurationWireFixture(t)
	f.keys.verified = make(chan struct{})
	exchange := &nativeConfigurationTestExchange{fixture: f, t: t, rearmed: make(chan struct{}), assertRearm: true}
	owner := &NativeConfigurationOwner{authority: nativeConfigurationTestPreparer{f, t}, keys: f.keys, bindings: map[string]NativeConfigurationClientBinding{f.authority.binding.Owner.InstanceID: {Binding: f.binding, Exchange: exchange, ReplyPrefix: "_INBOX.configurationfixture"}}, leases: map[*nativeConfigurationLease]bool{}, watchBudget: 20 * time.Millisecond}
	opening, cancel := context.WithTimeout(context.Background(), time.Second)
	lease, err := owner.Open(opening, f.authority.binding)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if lease.Close(cleanup) != nil {
			t.Error("configuration lease cleanup did not join")
		}
	}()
	select {
	case <-exchange.rearmed:
	case <-time.After(time.Second):
		t.Fatal("idle watch did not use a fresh verified read")
	}
	select {
	case <-f.keys.verified:
	case <-time.After(time.Second):
		t.Fatal("rearm read skipped current-key verification")
	}
	read, stopRead := context.WithTimeout(context.Background(), time.Second)
	snapshot, _, readErr := lease.Snapshot(read)
	stopRead()
	if readErr != nil || snapshot.Revision != 7 || !bytes.Equal(snapshot.Configuration.Bytes(), f.authority.binding.Configuration.Bytes()) {
		t.Fatal("rearmed lease did not return a verified snapshot", readErr)
	}
	select {
	case <-lease.Done():
		t.Fatal("Open cancellation or idle watch ended lease")
	default:
	}
	cleanup, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err = lease.Close(cleanup); err != nil {
		t.Fatal(err)
	}
	exchange.mu.Lock()
	active := exchange.activeWatch
	exchange.mu.Unlock()
	if active {
		t.Fatal("Close returned before original watch joined")
	}
}

func TestNativeConfigurationLeaseFencesGapRollbackReferenceChangeAndUnavailableRead(t *testing.T) {
	for _, kind := range []string{"gap", "rollback", "secret-reference", "unavailable"} {
		t.Run(kind, func(t *testing.T) {
			f := configurationWireFixture(t)
			exchange := &nativeConfigurationTestExchange{fixture: f, t: t, rearmed: make(chan struct{})}
			owner := &NativeConfigurationOwner{authority: nativeConfigurationTestPreparer{f, t}, keys: f.keys, bindings: map[string]NativeConfigurationClientBinding{f.authority.binding.Owner.InstanceID: {Binding: f.binding, Exchange: exchange, ReplyPrefix: "_INBOX.configurationfixture"}}, leases: map[*nativeConfigurationLease]bool{}}
			lease, err := owner.Open(context.Background(), f.authority.binding)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				lease.Close(ctx)
			}()
			switch kind {
			case "gap":
				exchange.nextRevision.Store(9)
			case "rollback":
				exchange.nextRevision.Store(6)
			case "secret-reference":
				exchange.nextRevision.Store(8)
				exchange.changedSecret.Store(true)
			case "unavailable":
				exchange.refusedRead.Store(true)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			snapshot, changed, err := lease.Snapshot(ctx)
			if err == nil || len(snapshot.Configuration.Bytes()) != 0 || changed != nil {
				t.Fatal("unavailable or substituted configuration released cached values")
			}
			select {
			case <-lease.Done():
			case <-ctx.Done():
				t.Fatal("failed configuration did not join original watch")
			}
			if err = lease.Close(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestNativeConfigurationFailedWatchJoinPreventsRearmAndKeepsOriginalOwner(t *testing.T) {
	f := configurationWireFixture(t)
	exchange := &nativeConfigurationTestExchange{fixture: f, t: t, rearmed: make(chan struct{})}
	owner := &NativeConfigurationOwner{authority: nativeConfigurationTestPreparer{f, t}, keys: f.keys, bindings: map[string]NativeConfigurationClientBinding{f.authority.binding.Owner.InstanceID: {Binding: f.binding, Exchange: exchange, ReplyPrefix: "_INBOX.configurationfixture"}}, leases: map[*nativeConfigurationLease]bool{}, watchBudget: 20 * time.Millisecond}
	lease, err := owner.Open(context.Background(), f.authority.binding)
	if err != nil {
		t.Fatal(err)
	}
	exchange.unjoined.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	select {
	case <-lease.(*nativeConfigurationLease).workerDone:
	case <-ctx.Done():
		t.Fatal("watch failure did not stop original worker")
	}
	if completed(lease.Done()) {
		t.Fatal("unjoined original transport closed Done")
	}
	exchange.mu.Lock()
	reads := exchange.reads
	exchange.mu.Unlock()
	if reads != 1 {
		t.Fatal("watch was rearmed before original subscription joined")
	}
	if err = lease.Close(ctx); err == nil {
		t.Fatal("unresolved original transport cleanup was reported complete")
	}
	if exchange.closeCalls.Load() != 1 {
		t.Fatal("original transport recovery owner was not used")
	}
	// The fixture resolves its original owner; no replacement is looked up.
	exchange.unjoined.Store(false)
	if err = lease.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if exchange.closeCalls.Load() != 2 {
		t.Fatal("recovery did not finish the original owner")
	}
	if err = lease.Close(ctx); err != nil || exchange.closeCalls.Load() != 2 {
		t.Fatal("completed transport cleanup was retried")
	}
}

type nativeConfigurationCancelledCleanupExchange struct {
	*nativeConfigurationTestExchange
	mode    string
	entered chan struct{}
	reads   atomic.Int32
}

func (e *nativeConfigurationCancelledCleanupExchange) ExchangeConfiguration(ctx context.Context, reply string, raw []byte) ([]byte, error) {
	var request struct {
		ContractID string `json:"contractId"`
	}
	json.Unmarshal(raw, &request)
	cancelHere := e.mode == "watch" && request.ContractID == "configuration-watch"
	if request.ContractID == "configuration-read" && e.reads.Add(1) > 1 && e.mode == "snapshot" {
		cancelHere = true
	}
	if !cancelHere {
		return e.nativeConfigurationTestExchange.ExchangeConfiguration(ctx, reply, raw)
	}
	close(e.entered)
	<-ctx.Done()
	e.unjoined.Store(true)
	return nil, errors.Join(ctx.Err(), errors.New("original cancelled subscription cleanup unresolved"))
}
func TestNativeConfigurationCancellationRetainsOriginalCleanupOwner(t *testing.T) {
	for _, mode := range []string{"watch", "snapshot"} {
		t.Run(mode, func(t *testing.T) {
			f := configurationWireFixture(t)
			exchange := &nativeConfigurationCancelledCleanupExchange{nativeConfigurationTestExchange: &nativeConfigurationTestExchange{fixture: f, t: t, rearmed: make(chan struct{})}, mode: mode, entered: make(chan struct{})}
			owner := &NativeConfigurationOwner{authority: nativeConfigurationTestPreparer{f, t}, keys: f.keys, bindings: map[string]NativeConfigurationClientBinding{f.authority.binding.Owner.InstanceID: {Binding: f.binding, Exchange: exchange, ReplyPrefix: "_INBOX.configurationfixture"}}, leases: map[*nativeConfigurationLease]bool{}}
			lease, err := owner.Open(context.Background(), f.authority.binding)
			if err != nil {
				t.Fatal(err)
			}
			cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if mode == "snapshot" {
				request, stop := context.WithCancel(context.Background())
				done := make(chan error, 1)
				go func() { _, _, err := lease.Snapshot(request); done <- err }()
				select {
				case <-exchange.entered:
				case <-cleanup.Done():
					stop()
					t.Fatal("snapshot did not start")
				}
				stop()
				select {
				case err = <-done:
					if err == nil {
						t.Fatal("cancelled snapshot returned configuration")
					}
				case <-cleanup.Done():
					t.Fatal("original cancelled snapshot was not joined")
				}
			} else {
				select {
				case <-exchange.entered:
				case <-cleanup.Done():
					t.Fatal("watch did not start")
				}
			}
			closeErr := lease.Close(cleanup)
			owner.mu.Lock()
			retained := len(owner.leases)
			owner.mu.Unlock()
			if closeErr == nil || retained != 1 || exchange.closeCalls.Load() != 1 || exchange.ConfigurationReusable() {
				t.Fatal("cancellation discarded original unresolved cleanup owner")
			}
			exchange.unjoined.Store(false)
			if err = owner.Close(cleanup); err != nil {
				t.Fatal(err)
			}
			if exchange.closeCalls.Load() != 2 {
				t.Fatal("recovery did not close the same original transport")
			}
		})
	}
}
