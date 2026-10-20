package plugins

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type nativeInitialReadFixture struct {
	owner          *NativeConfigurationOwner
	lease          *nativeConfigurationLease
	receipt        *nativeConfigurationInitialRead
	binding        ContextBinding
	admission      ContextInstanceAdmission
	exchange       *nativeConfigurationTestExchange
	ctx            context.Context
	cancel         context.CancelFunc
	lifetime       chan struct{}
	parentLifetime chan struct{}
	keys           *nativeConfigurationTestKeys
}

func initialReadFixture(t *testing.T, private bool, change func(*ContextInstanceAdmission), parent ...bool) *nativeInitialReadFixture {
	t.Helper()
	wire := configurationWireFixture(t)
	binding := cloneContextBinding(wire.authority.binding)
	binding.Lifecycle = newNativeContextLifecycle(binding.Owner)
	lifetime := make(chan struct{})
	binding.LifetimeDone = lifetime
	var parentLifetime chan struct{}
	if len(parent) > 0 && parent[0] {
		parentLifetime = make(chan struct{})
		binding.ParentLifetime = parentLifetime
		originalParent := binding.Owner
		originalParent.InstanceID = "receipt_parent"
		binding.Parent = &originalParent
	}
	exchange := &nativeConfigurationTestExchange{fixture: wire, t: t, rearmed: make(chan struct{})}
	owner := &NativeConfigurationOwner{authority: nativeConfigurationTestPreparer{wire, t}, keys: wire.keys, bindings: map[string]NativeConfigurationClientBinding{binding.Owner.InstanceID: {Binding: wire.binding, Exchange: exchange, ReplyPrefix: "_INBOX.configurationfixture"}}, leases: map[*nativeConfigurationLease]bool{}}
	admission := ContextInstanceAdmission{ConfigurationRevision: 7, SecretReferences: []ContextReference{}}
	if change != nil {
		change(&admission)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	var lease ContextConfigurationLease
	var receipt *nativeConfigurationInitialRead
	var err error
	if private {
		lease, receipt, err = owner.openForContext(ctx, binding, admission)
	} else {
		lease, err = owner.Open(ctx, binding)
	}
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	f := &nativeInitialReadFixture{owner: owner, lease: lease.(*nativeConfigurationLease), receipt: receipt, binding: binding, admission: admission, exchange: exchange, ctx: ctx, cancel: cancel, lifetime: lifetime, parentLifetime: parentLifetime, keys: wire.keys}
	t.Cleanup(func() {
		cancel()
		cleanup, finish := context.WithTimeout(context.Background(), time.Second)
		defer finish()
		if f.lease.Close(cleanup) != nil {
			t.Error("original initial-read owner did not join")
		}
	})
	return f
}

func TestNativeConfigurationInitialReadIsOneUseForExactOpening(t *testing.T) {
	f := initialReadFixture(t, true, nil)
	configuration, err := newContextConfigurationWithInitial(f.ctx, f.binding, f.admission, f.lease, f.receipt)
	if err != nil || configuration == nil {
		t.Fatal("verified opening read refused")
	}
	f.exchange.mu.Lock()
	reads := f.exchange.reads
	f.exchange.mu.Unlock()
	if reads != 1 {
		t.Fatal("private opening sent a duplicate read")
	}
	if _, err := newContextConfigurationWithInitial(f.ctx, f.binding, f.admission, f.lease, f.receipt); err == nil {
		t.Fatal("initial read receipt was reused")
	}
	if _, err := configuration.Read(f.ctx); err != nil {
		t.Fatal("public read refused after private handoff")
	}
	f.exchange.refusedRead.Store(true)
	if got, err := configuration.Read(f.ctx); err == nil || len(got.Configuration.Bytes()) != 0 {
		t.Fatal("public read reused initial data after owner refusal")
	}
	f.exchange.mu.Lock()
	reads = f.exchange.reads
	f.exchange.mu.Unlock()
	if reads != 3 {
		t.Fatal("public reads did not use fresh owner requests")
	}
}

func TestNativeConfigurationPublicAndGenericOpeningKeepFreshReads(t *testing.T) {
	f := initialReadFixture(t, false, nil)
	if f.receipt != nil {
		t.Fatal("public Open exposed an initial receipt")
	}
	if _, err := newContextConfiguration(f.ctx, f.binding, f.admission, f.lease); err != nil {
		t.Fatal(err)
	}
	f.exchange.mu.Lock()
	reads := f.exchange.reads
	f.exchange.mu.Unlock()
	if reads != 2 {
		t.Fatal("public opening bypassed fresh Snapshot")
	}
	_, _, exchange, _ := nativeConfigurationStartingContext(t, true)
	exchange.mu.Lock()
	reads = exchange.reads
	exchange.mu.Unlock()
	if reads != 2 {
		t.Fatal("generic owner was admitted through private native path")
	}
}

func TestNativeConfigurationInitialReadCannotAuthorizePublicReadAfterSignerRevocation(t *testing.T) {
	f := initialReadFixture(t, true, nil)
	configuration, err := newContextConfigurationWithInitial(f.ctx, f.binding, f.admission, f.lease, f.receipt)
	if err != nil {
		t.Fatal(err)
	}
	f.keys.revokeAfter = f.keys.calls.Load()
	if got, err := configuration.Read(f.ctx); err == nil || len(got.Configuration.Bytes()) != 0 {
		t.Fatal("public read reused opening authority after signer revocation")
	}
	f.exchange.mu.Lock()
	reads := f.exchange.reads
	f.exchange.mu.Unlock()
	if reads != 2 {
		t.Fatal("revoked public read did not contact the actual owner")
	}
}

func TestNativeConfigurationRejectedInitialReadStaysAttachedToActualProvider(t *testing.T) {
	f, owner, exchange, _ := nativeConfigurationStartingContext(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := f.lease.Close(ctx); err != nil {
		t.Fatal(err)
	}
	f.authority.instance.ConfigurationRevision = 8
	opening, err := f.provider.Open(ctx, cloneContextBinding(f.lease.binding))
	if err == nil || opening == nil {
		t.Fatal("contradictory initial revision was admitted or original owner lost")
	}
	failed := opening.(*contextLease)
	if failed.configurationLease == nil {
		t.Fatal("original lease was not attached before receipt consumption")
	}
	owner.mu.Lock()
	retained := len(owner.leases)
	owner.mu.Unlock()
	if retained != 1 || completed(failed.configurationLease.Done()) {
		t.Fatal("rejected receipt discarded original cleanup ownership")
	}
	if err := failed.Close(ctx); err != nil || !completed(failed.configurationLease.Done()) {
		t.Fatal("actual provider did not join original rejected owner")
	}
	exchange.mu.Lock()
	reads := exchange.reads
	exchange.mu.Unlock()
	if reads != 2 {
		t.Fatal("rejected initial handoff silently fetched replacement data")
	}
}

func TestNativeConfigurationInitialReadInvalidAttemptBurnsReceipt(t *testing.T) {
	cases := []string{"owner", "package", "lifetime-binding", "parent", "admission", "lease", "renewed-context", "canceled", "deadline", "reply-expiry", "changed", "snapshot-bytes", "snapshot-checksum", "snapshot-schema", "snapshot-pin", "snapshot-revision", "snapshot-secrets", "owner-closing", "owner-detached", "route", "lease-closing", "unavailable", "lifetime-ended", "parent-ended", "draining", "missing-drain", "changed-drain", "transport-unusable"}
	for _, mode := range cases {
		t.Run(mode, func(t *testing.T) {
			f := initialReadFixture(t, true, nil, mode == "parent-ended")
			binding, admission, lease, ctx := cloneContextBinding(f.binding), cloneInstanceAdmission(f.admission), ContextConfigurationLease(f.lease), f.ctx
			switch mode {
			case "owner":
				binding.Owner.Generation++
			case "package":
				binding.Package = fixturePackage(t, fixtureManifest("other_receipt_package"), map[string][]byte{"schemas/config.json": []byte(`{"type":"object"}`)})
			case "lifetime-binding":
				binding.LifetimeDone = make(chan struct{})
			case "parent":
				parent := binding.Owner
				parent.Generation++
				binding.Parent = &parent
				binding.ParentLifetime = make(chan struct{})
			case "admission":
				admission.ConfigurationRevision++
			case "lease":
				lease = &nativeConfigurationLease{}
			case "renewed-context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(context.Background(), f.receipt.deadline)
				defer cancel()
			case "canceled":
				f.cancel()
			case "deadline":
				f.receipt.deadline = time.Now().Add(-time.Millisecond)
			case "reply-expiry":
				f.receipt.until = time.Now().Add(-time.Millisecond)
			case "changed":
				f.lease.mu.Lock()
				f.lease.changed = make(chan struct{})
				f.lease.mu.Unlock()
			case "snapshot-bytes":
				f.receipt.snapshot.Configuration.raw[0] = ' '
			case "snapshot-checksum":
				f.receipt.snapshot.Configuration.digest = "sha256:wrong"
			case "snapshot-schema":
				f.receipt.snapshot.Configuration.schemaRef = "different.json"
			case "snapshot-pin":
				f.receipt.snapshot.Configuration.pin.Version = "2.0.0"
			case "snapshot-revision":
				f.receipt.snapshot.Revision++
			case "snapshot-secrets":
				f.receipt.snapshot.SecretReferences = []ContextReference{{"other_secret", "context_hub", 1}}
			case "owner-closing":
				f.owner.mu.Lock()
				f.owner.closing = true
				f.owner.mu.Unlock()
			case "owner-detached":
				f.owner.mu.Lock()
				delete(f.owner.leases, f.lease)
				f.owner.mu.Unlock()
			case "route":
				f.owner.mu.Lock()
				input := f.owner.bindings[binding.Owner.InstanceID]
				input.Binding.ConfigurationRef.Revision++
				f.owner.bindings[binding.Owner.InstanceID] = input
				f.owner.mu.Unlock()
			case "lease-closing":
				f.lease.mu.Lock()
				f.lease.closing = true
				f.lease.mu.Unlock()
			case "unavailable":
				f.lease.unavailable()
			case "lifetime-ended":
				close(f.lifetime)
			case "parent-ended":
				close(f.parentLifetime)
			case "draining":
				f.binding.Lifecycle.(*nativeContextLifecycle).beginDrain()
			case "missing-drain":
				f.receipt.drain = nil
			case "changed-drain":
				f.receipt.drain = make(chan struct{})
			case "transport-unusable":
				f.exchange.unjoined.Store(true)
				defer f.exchange.unjoined.Store(false)
			}
			if _, _, err := f.receipt.consume(ctx, binding, admission, lease); err == nil {
				t.Fatal("invalid initial-read handoff accepted")
			}
			if _, _, err := f.receipt.consume(f.ctx, f.binding, f.admission, f.lease); err == nil {
				t.Fatal("invalid attempt did not burn original receipt")
			}
			f.exchange.mu.Lock()
			reads := f.exchange.reads
			f.exchange.mu.Unlock()
			if reads != 1 {
				t.Fatal("invalid receipt silently fetched replacement authority")
			}
		})
	}
}

func TestNativeConfigurationInitialReadKeepsPureAdmissionChecks(t *testing.T) {
	for _, mode := range []string{"revision", "secret"} {
		t.Run(mode, func(t *testing.T) {
			f := initialReadFixture(t, true, func(a *ContextInstanceAdmission) {
				if mode == "revision" {
					a.ConfigurationRevision++
				} else {
					a.SecretReferences = []ContextReference{{"required_secret", "context_hub", 1}}
				}
			})
			if _, err := newContextConfigurationWithInitial(f.ctx, f.binding, f.admission, f.lease, f.receipt); err == nil {
				t.Fatal("initial receipt bypassed constructor admission checks")
			}
			f.owner.mu.Lock()
			retained := f.owner.leases[f.lease]
			f.owner.mu.Unlock()
			if !retained || completed(f.lease.Done()) {
				t.Fatal("rejected constructor abandoned original cleanup")
			}
		})
	}
}

func TestNativeConfigurationInitialReadConcurrentConsumption(t *testing.T) {
	f := initialReadFixture(t, true, nil)
	var succeeded atomic.Int32
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if _, _, err := f.receipt.consume(f.ctx, f.binding, f.admission, f.lease); err == nil {
				succeeded.Add(1)
			}
		}()
	}
	workers.Wait()
	if succeeded.Load() != 1 {
		t.Fatal("initial read receipt was not consumed exactly once")
	}
}

func TestNativeConfigurationInitialReadRechecksOwnerAfterPureValidation(t *testing.T) {
	f := initialReadFixture(t, true, nil)
	if _, err := newContextConfigurationWithInitial(f.ctx, f.binding, f.admission, f.lease, f.receipt); err != nil {
		t.Fatal(err)
	}
	f.owner.mu.Lock()
	f.owner.closing = true
	f.owner.mu.Unlock()
	if err := f.receipt.recheckOpening(f.ctx, f.binding, f.admission, f.lease); err == nil {
		t.Fatal("late owner close passed initial admission")
	}
	if !f.receipt.used {
		t.Fatal("late failed admission did not consume original receipt")
	}
}

func TestNativeConfigurationInitialReadRejectsDrainBeforeWorkerUpdates(t *testing.T) {
	f := initialReadFixture(t, true, nil)
	// Hold the worker's state lock so only the original drain signal can
	// invalidate this receipt. Cleanup still joins the same waiting worker.
	f.lease.mu.Lock()
	f.binding.Lifecycle.(*nativeContextLifecycle).beginDrain()
	result := make(chan error, 1)
	go func() {
		_, _, err := f.receipt.consume(f.ctx, f.binding, f.admission, f.lease)
		result <- err
	}()
	select {
	case err := <-result:
		f.lease.mu.Unlock()
		if err == nil {
			t.Fatal("initial handoff accepted a draining original lifecycle")
		}
	case <-time.After(time.Second):
		f.lease.mu.Unlock()
		<-result
		t.Fatal("initial handoff waited for the worker to notice drain")
	}
}
