package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"
)

// NativeConfigurationExchange returns only after the original request's local
// subscription has drained. A failed drain must fence the original transport.
type NativeConfigurationExchange interface {
	ExchangeConfiguration(context.Context, string, []byte) ([]byte, error)
	ConfigurationReusable() bool
	Close(context.Context) error
}
type NativeConfigurationClientBinding struct {
	Binding     NativeConfigurationBinding
	Exchange    NativeConfigurationExchange
	ReplyPrefix string
}

// NativeConfigurationOwner reads the existing configuration owner. It never
// writes configuration, creates a stream, or accepts unverified cached values.
// The host retains the original authority, key source and transports through
// Close; each Open owns its exact read/watch calls and their joined lifetime.
type NativeConfigurationOwner struct {
	mu          sync.Mutex
	authority   NativeConfigurationRequestPreparer
	keys        NativeConfigurationKeySource
	bindings    map[string]NativeConfigurationClientBinding
	leases      map[*nativeConfigurationLease]bool
	closing     bool
	watchBudget time.Duration
}

func (*NativeConfigurationOwner) Format(state fmt.State, _ rune) {
	fmt.Fprint(state, "[private native configuration owner]")
}
func (*NativeConfigurationOwner) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-native-configuration-owner"}`), nil
}

func NewNativeConfigurationOwner(authority *NativeContextAuthority, keys *NativeEnrolledKeys, bindings map[string]NativeConfigurationClientBinding) (*NativeConfigurationOwner, error) {
	if authority == nil || authority.client == nil || keys == nil || !nativeAuthorityReplyPrefix.MatchString(authority.client.options.ReplyPrefix) || len(bindings) == 0 || len(bindings) > 64 {
		return nil, pluginError("context_configuration_unavailable")
	}
	r := &NativeConfigurationOwner{authority: authority, keys: keys, bindings: map[string]NativeConfigurationClientBinding{}, leases: map[*nativeConfigurationLease]bool{}}
	for instance, input := range bindings {
		if input.ReplyPrefix != authority.client.options.ReplyPrefix {
			return nil, pluginError("context_configuration_unavailable")
		}
		b := input.Binding
		if !registryIdentifier.MatchString(instance) || !contextReferenceValid(b.ConfigurationRef) || !contextReferenceValid(b.AuthorityRef) || b.Service.ProfileID != authority.client.options.ProfileID || b.Service.HubID != authority.client.options.HubID || b.ConfigurationRef.OwnerHubID != b.Service.HubID || b.AuthorityRef.OwnerHubID != b.Service.HubID || !registryIdentifier.MatchString(b.Service.ServiceInstanceID) || !contextReferenceValid(b.Service.ServiceIdentityRef) || !contextReferenceValid(b.Service.SigningKeyRef) || nilContextDependency(input.Exchange) || !nativeAuthorityReplyPrefix.MatchString(input.ReplyPrefix) {
			return nil, pluginError("context_configuration_unavailable")
		}
		input.Binding.Resources = append([]SchemaResource(nil), b.Resources...)
		r.bindings[instance] = input
	}
	return r, nil
}

func (o *NativeConfigurationOwner) Open(ctx context.Context, binding ContextBinding) (ContextConfigurationLease, error) {
	lease, _, err := o.open(ctx, binding, nil)
	return lease, err
}

func (o *NativeConfigurationOwner) openForContext(ctx context.Context, binding ContextBinding, admission ContextInstanceAdmission) (ContextConfigurationLease, *nativeConfigurationInitialRead, error) {
	return o.open(ctx, binding, &admission)
}

func (o *NativeConfigurationOwner) open(ctx context.Context, binding ContextBinding, initial *ContextInstanceAdmission) (ContextConfigurationLease, *nativeConfigurationInitialRead, error) {
	if o == nil || ctx == nil || ctx.Err() != nil || !contextOwnerValid(binding.Owner) || !binding.Configuration.BelongsTo(binding.Package) || binding.LifetimeDone == nil || completed(binding.LifetimeDone) || completed(binding.ParentLifetime) {
		return nil, nil, pluginError("context_configuration_unavailable")
	}
	if _, ok := ctx.Deadline(); initial != nil && (!ok || ctx.Done() == nil) {
		return nil, nil, pluginError("context_configuration_unavailable")
	}
	o.mu.Lock()
	input, ok := o.bindings[binding.Owner.InstanceID]
	if !ok || o.closing || len(o.leases) >= 64 {
		o.mu.Unlock()
		return nil, nil, pluginError("context_configuration_unavailable")
	}
	for old := range o.leases {
		if old.binding.Owner == binding.Owner {
			o.mu.Unlock()
			return nil, nil, pluginError("context_instance_owned")
		}
	}
	lifetime, cancel := context.WithCancel(context.Background())
	l := &nativeConfigurationLease{owner: o, binding: cloneContextBinding(binding), input: input, ctx: lifetime, cancel: cancel, changed: make(chan struct{}), started: make(chan struct{}), done: make(chan struct{}), workerDone: make(chan struct{}), terminal: make(chan struct{}), watchDemand: make(chan struct{}), cleanupGate: make(chan struct{}, 1)}
	o.leases[l] = true
	o.mu.Unlock()
	// The worker waits for initial admission; Close can already cancel and join
	// this exact opening lease if its original read is still in progress.
	go l.run()
	snapshot, until, err := l.fetch(ctx, "configuration-read", 0)
	if err == nil && snapshot.Configuration.Checksum() != binding.Configuration.Checksum() {
		err = pluginError("context_configuration_unavailable")
	}
	if err == nil {
		err = l.apply(snapshot, until, true)
	}
	if err != nil {
		l.fail(err)
	}
	var receipt *nativeConfigurationInitialRead
	if err == nil && initial != nil {
		deadline, _ := ctx.Deadline()
		l.mu.Lock()
		originalInput := input
		originalInput.Binding.Resources = append([]SchemaResource(nil), input.Binding.Resources...)
		receipt = &nativeConfigurationInitialRead{lease: l, owner: o, binding: cloneContextBinding(binding), admission: cloneInstanceAdmission(*initial), input: originalInput, openingDone: ctx.Done(), deadline: deadline, until: until, changed: l.changed, snapshot: cloneContextConfiguration(snapshot)}
		if binding.Lifecycle != nil {
			receipt.drain = binding.Lifecycle.DrainDone()
		}
		l.mu.Unlock()
	}
	close(l.started)
	return l, receipt, err
}
func (o *NativeConfigurationOwner) Close(ctx context.Context) error {
	if o == nil {
		return nil
	}
	if ctx == nil {
		return pluginError("context_cleanup_incomplete")
	}
	o.mu.Lock()
	o.closing = true
	leases := make([]*nativeConfigurationLease, 0, len(o.leases))
	for lease := range o.leases {
		leases = append(leases, lease)
	}
	o.mu.Unlock()
	var failures []error
	for _, lease := range leases {
		if err := lease.Close(ctx); err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) > 0 {
		return &nativeConfigurationFailure{cause: errors.Join(failures...), owner: o}
	}
	return nil
}

type nativeConfigurationFailure struct {
	cause error
	owner any
}

func (*nativeConfigurationFailure) Error() string                    { return "context_configuration_unavailable" }
func (e *nativeConfigurationFailure) Unwrap() error                  { return e.cause }
func (e *nativeConfigurationFailure) Format(state fmt.State, _ rune) { fmt.Fprint(state, e.Error()) }
func (*nativeConfigurationFailure) MarshalJSON() ([]byte, error) {
	return []byte(`"context_configuration_unavailable"`), nil
}

type nativeConfigurationLease struct {
	mu                  sync.Mutex
	owner               *NativeConfigurationOwner
	binding             ContextBinding
	input               NativeConfigurationClientBinding
	ctx                 context.Context
	cancel              context.CancelFunc
	started, done       chan struct{}
	workerDone          chan struct{}
	doneOnce            sync.Once
	terminal            chan struct{}
	terminalOnce        sync.Once
	watchDemand         chan struct{}
	watchDemandOnce     sync.Once
	cleanupGate         chan struct{}
	pendingWatch        nativeConfigurationWatchCleanup
	changed             chan struct{}
	changedClosed       bool
	calls               sync.WaitGroup
	last                ContextConfigurationSnapshot
	until               time.Time
	available           bool
	closing             bool
	failure             error
	cleanupFailure      *AdmissionCleanupFailure
	transportNeedsClose bool
	transportClosed     bool
}

func (l *nativeConfigurationLease) Owner() OwnerReference            { return l.binding.Owner }
func (l *nativeConfigurationLease) Done() <-chan struct{}            { return l.done }
func (l *nativeConfigurationLease) unavailableDone() <-chan struct{} { return l.terminal }
func (l *nativeConfigurationLease) requestConfigurationWatch() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ready, ok := l.binding.Lifecycle.(nativeContextReadySource); ok && completed(l.binding.Lifecycle.DrainDone()) && !completed(ready.nativeReadyDone()) {
		return
	}
	if !l.closing && l.ctx.Err() == nil {
		l.watchDemandOnce.Do(func() { close(l.watchDemand) })
	}
}
func (l *nativeConfigurationLease) wake() {
	if !l.changedClosed {
		close(l.changed)
		l.changedClosed = true
	}
}
func (l *nativeConfigurationLease) fail(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failure == nil {
		l.failure = err
	}
	var cleanup *AdmissionCleanupFailure
	if errors.As(err, &cleanup) {
		l.cleanupFailure = cleanup
	}
	l.available = false
	l.closing = true
	l.terminalOnce.Do(func() { close(l.terminal) })
	if !l.input.Exchange.ConfigurationReusable() {
		l.transportNeedsClose = true
	}
	l.wake()
	l.cancel()
}
func (l *nativeConfigurationLease) unavailable() {
	l.mu.Lock()
	l.available = false
	l.wake()
	l.mu.Unlock()
}
func (l *nativeConfigurationLease) apply(snapshot ContextConfigurationSnapshot, until time.Time, initial bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closing || l.ctx.Err() != nil || completed(l.binding.LifetimeDone) || completed(l.binding.ParentLifetime) || !time.Now().Before(until) {
		return pluginError("context_configuration_unavailable")
	}
	if !initial {
		if snapshot.Revision < l.last.Revision || snapshot.Revision > l.last.Revision+1 || !reflect.DeepEqual(snapshot.SecretReferences, l.last.SecretReferences) {
			return pluginError("context_configuration_unavailable")
		}
		if snapshot.Revision == l.last.Revision && !sameContextConfiguration(snapshot, l.last) {
			return pluginError("context_configuration_unavailable")
		}
	}
	if initial || snapshot.Revision != l.last.Revision || !l.available {
		l.wake()
		l.changed = make(chan struct{})
		l.changedClosed = false
	}
	l.last = cloneContextConfiguration(snapshot)
	l.until = until
	l.available = true
	return nil
}
func (l *nativeConfigurationLease) fetch(parent context.Context, contract string, after uint64) (ContextConfigurationSnapshot, time.Time, error) {
	work, cancel := context.WithTimeout(parent, contextCallBudget)
	defer cancel()
	stop := context.AfterFunc(l.ctx, cancel)
	defer stop()
	if l.ctx.Err() != nil {
		return ContextConfigurationSnapshot{}, time.Time{}, l.ctx.Err()
	}
	if completed(l.binding.LifetimeDone) || completed(l.binding.ParentLifetime) {
		return ContextConfigurationSnapshot{}, time.Time{}, pluginError("context_configuration_unavailable")
	}
	if work.Err() != nil {
		return ContextConfigurationSnapshot{}, time.Time{}, work.Err()
	}
	nonce, err := randomControlID()
	if err != nil {
		return ContextConfigurationSnapshot{}, time.Time{}, err
	}
	cancellationRef := ContextReference{ID: "configuration_" + nonce, OwnerHubID: l.input.Binding.Service.HubID, Revision: 1}
	request, err := l.owner.authority.PrepareConfigurationRequest(work, l.binding.Owner, l.input.Binding.ConfigurationRef, contract, after, cancellationRef)
	if err != nil {
		return ContextConfigurationSnapshot{}, time.Time{}, &nativeConfigurationFailure{cause: err, owner: l}
	}
	if _, err = nativeConfigurationRequest(request, l.binding.Owner, l.input.Binding); err != nil {
		return ContextConfigurationSnapshot{}, time.Time{}, err
	}
	cancellationRaw, err := json.Marshal(cancellationRef)
	if err != nil || !nativeCapabilityEqual(fieldsForClaim(fieldsForClaim(request, "operation"), "cancellationRef"), cancellationRaw) {
		return ContextConfigurationSnapshot{}, time.Time{}, pluginError("context_configuration_unavailable")
	}
	if contract == "configuration-watch" {
		preparer, ok := l.owner.authority.(nativeConfigurationWatchPreparer)
		if !ok {
			return ContextConfigurationSnapshot{}, time.Time{}, pluginError("context_configuration_unavailable")
		}
		watch, err := preparer.prepareConfigurationWatchCleanup(work, request, l.input, l.owner.keys)
		if err != nil || watch == nil {
			return ContextConfigurationSnapshot{}, time.Time{}, pluginError("context_configuration_unavailable")
		}
		l.mu.Lock()
		if l.pendingWatch != nil {
			l.mu.Unlock()
			return ContextConfigurationSnapshot{}, time.Time{}, pluginError("context_cleanup_incomplete")
		}
		l.pendingWatch = watch
		l.mu.Unlock()
	}
	raw, err := l.input.Exchange.ExchangeConfiguration(work, l.input.ReplyPrefix+"."+nonce, request)
	if contract == "configuration-watch" {
		if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(work.Err(), context.DeadlineExceeded) {
			l.fail(err)
		}
		// Caller cancellation ends disclosure, but cleanup retains the original
		// watch until its authenticated join and receipt confirmation finish.
		cleanup, finish := context.WithTimeout(context.Background(), contextCallBudget)
		cleanupErr := l.closeWatch(cleanup)
		finish()
		if cleanupErr != nil {
			return ContextConfigurationSnapshot{}, time.Time{}, &nativeConfigurationFailure{cause: errors.Join(err, cleanupErr), owner: l}
		}
	}
	if err != nil {
		if work.Err() != nil {
			return ContextConfigurationSnapshot{}, time.Time{}, &nativeConfigurationFailure{cause: errors.Join(err, work.Err()), owner: l}
		}
		return ContextConfigurationSnapshot{}, time.Time{}, &nativeConfigurationFailure{cause: err, owner: l}
	}
	snapshot, until, err := verifyNativeConfigurationResponse(work, raw, request, l.binding, l.input.Binding, l.owner.keys)
	return snapshot, until, err
}
func (l *nativeConfigurationLease) Snapshot(ctx context.Context) (ContextConfigurationSnapshot, <-chan struct{}, error) {
	if ctx == nil {
		return ContextConfigurationSnapshot{}, nil, pluginError("context_configuration_unavailable")
	}
	l.mu.Lock()
	if l.closing {
		failure := l.failure
		l.mu.Unlock()
		return ContextConfigurationSnapshot{}, nil, &nativeConfigurationFailure{cause: failure, owner: l}
	}
	l.calls.Add(1)
	l.mu.Unlock()
	defer l.calls.Done()
	snapshot, until, err := l.fetch(ctx, "configuration-read", 0)
	if err == nil {
		err = l.apply(snapshot, until, false)
	}
	if err != nil {
		var cleanup *AdmissionCleanupFailure
		if ctx.Err() == nil || !l.input.Exchange.ConfigurationReusable() || errors.As(err, &cleanup) {
			l.fail(err)
		} else {
			l.unavailable()
		}
		return ContextConfigurationSnapshot{}, nil, &nativeConfigurationFailure{cause: err, owner: l}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.available || l.closing || !time.Now().Before(l.until) {
		return ContextConfigurationSnapshot{}, nil, pluginError("context_configuration_unavailable")
	}
	return cloneContextConfiguration(l.last), l.changed, nil
}
func (l *nativeConfigurationLease) run() {
	<-l.started
	defer func() {
		l.cancel()
		l.calls.Wait()
		l.mu.Lock()
		l.available = false
		l.closing = true
		l.terminalOnce.Do(func() { close(l.terminal) })
		l.wake()
		l.mu.Unlock()
		l.mu.Lock()
		cleanupPending := l.cleanupFailure != nil || l.transportNeedsClose || l.pendingWatch != nil
		close(l.workerDone)
		if !cleanupPending {
			l.doneOnce.Do(func() { close(l.done) })
		}
		l.mu.Unlock()
		l.owner.mu.Lock()
		if !cleanupPending {
			delete(l.owner.leases, l)
		}
		l.owner.mu.Unlock()
	}()
	if ready, ok := l.binding.Lifecycle.(nativeContextReadySource); ok {
		notification := ready.nativeReadyDone()
		if notification == nil {
			l.fail(pluginError("context_configuration_unavailable"))
			return
		}
		// Opening reads stay fresh. The background watch must not compete
		// with those reads and child readiness on the remote owner's event loop.
		select {
		case <-notification:
		case <-l.watchDemand:
		case <-l.ctx.Done():
			return
		case <-l.binding.LifetimeDone:
			return
		case <-l.binding.ParentLifetime:
			return
		case <-l.binding.Lifecycle.DrainDone():
			// If readiness preceded drain, preserve the existing running-instance
			// lifetime. A failed start with no readiness owns no remote watch.
			if !completed(notification) && !completed(l.watchDemand) {
				return
			}
		}
	}
	for {
		l.mu.Lock()
		revision, closing := l.last.Revision, l.closing
		l.mu.Unlock()
		if closing || l.ctx.Err() != nil {
			return
		}
		budget := l.owner.watchBudget
		if budget <= 0 {
			budget = contextCallBudget
		}
		watch, cancel := context.WithTimeout(l.ctx, budget)
		snapshot, until, err := l.fetch(watch, "configuration-watch", revision)
		timedOut := errors.Is(watch.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded)
		cancel()
		if err != nil {
			l.mu.Lock()
			remotePending := l.pendingWatch != nil
			l.mu.Unlock()
			if remotePending {
				l.fail(err)
				return
			}
			if l.ctx.Err() != nil {
				var cleanup *AdmissionCleanupFailure
				if !l.input.Exchange.ConfigurationReusable() || errors.As(err, &cleanup) {
					l.fail(err)
				}
				return
			}
			var cleanup *AdmissionCleanupFailure
			if !timedOut || !l.input.Exchange.ConfigurationReusable() || errors.As(err, &cleanup) {
				l.fail(err)
				return
			}
			// Exchange has joined the original local request before returning. Silence
			// is unavailable, not an unchanged configuration. Only a fresh verified
			// authorized read may restore a snapshot and permit the next watch.
			l.unavailable()
			snapshot, until, err = l.fetch(l.ctx, "configuration-read", 0)
			if err != nil {
				l.fail(err)
				return
			}
		} else if snapshot.Revision <= revision {
			l.fail(pluginError("context_configuration_unavailable"))
			return
		}
		if err = l.apply(snapshot, until, false); err != nil {
			l.fail(err)
			return
		}
	}
}
func (l *nativeConfigurationLease) Close(ctx context.Context) error {
	if ctx == nil {
		return pluginError("context_cleanup_incomplete")
	}
	l.mu.Lock()
	l.closing = true
	l.available = false
	l.terminalOnce.Do(func() { close(l.terminal) })
	l.wake()
	l.cancel()
	l.mu.Unlock()
	select {
	case <-l.workerDone:
	case <-ctx.Done():
		return pluginError("context_cleanup_incomplete")
	}
	if err := l.closeWatch(ctx); err != nil {
		return &nativeConfigurationFailure{cause: err, owner: l}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.transportNeedsClose && !l.transportClosed {
		if err := l.input.Exchange.Close(ctx); err != nil {
			return &nativeConfigurationFailure{cause: err, owner: l}
		}
		l.transportClosed = true
		l.transportNeedsClose = false
		if l.cleanupFailure == nil {
			l.owner.mu.Lock()
			delete(l.owner.leases, l)
			l.owner.mu.Unlock()
		}
	}
	if l.cleanupFailure != nil {
		return &nativeConfigurationFailure{cause: l.cleanupFailure, owner: l}
	}
	l.doneOnce.Do(func() { close(l.done) })
	l.owner.mu.Lock()
	delete(l.owner.leases, l)
	l.owner.mu.Unlock()
	return nil
}

func (l *nativeConfigurationLease) closeWatch(ctx context.Context) error {
	select {
	case l.cleanupGate <- struct{}{}:
	case <-ctx.Done():
		return pluginError("context_cleanup_incomplete")
	}
	defer func() { <-l.cleanupGate }()
	l.mu.Lock()
	watch := l.pendingWatch
	l.mu.Unlock()
	if watch == nil {
		return nil
	}
	if err := watch.Close(ctx); err != nil {
		return err
	}
	l.mu.Lock()
	l.pendingWatch = nil
	l.mu.Unlock()
	return nil
}

var _ ContextConfigurationOwner = (*NativeConfigurationOwner)(nil)
