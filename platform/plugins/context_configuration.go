package plugins

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"reflect"
	"sync"
)

// ContextConfigurationOwner opens the existing configuration owner's scoped
// subscription. It must not create another authoritative configuration store.
type ContextConfigurationOwner interface {
	Open(context.Context, ContextBinding) (ContextConfigurationLease, error)
}

// Snapshot atomically returns current values and a channel closed on their next
// change. Done closes only after this exact subscription and all its resources
// have joined. Snapshot fails immediately when unavailable or closing. Methods
// must honor their context; Close succeeds only after Done closes. A Close error
// retains the original lease for another join attempt.
// A nonnil lease returned alongside an error still belongs to the caller.
type ContextConfigurationLease interface {
	Owner() OwnerReference
	Snapshot(context.Context) (ContextConfigurationSnapshot, <-chan struct{}, error)
	Done() <-chan struct{}
	Close(context.Context) error
}

// Native owners can stop context use before unresolved cleanup has joined.
// This notification never replaces the public joined-only Done channel.
type contextConfigurationUnavailable interface {
	unavailableDone() <-chan struct{}
}

// A pre-ready caller waiting for a change needs the same owned watch. Ordinary
// reads and constructor validation do not start background notification work.
type contextConfigurationWatchDemand interface {
	requestConfigurationWatch()
}

type ContextConfigurationSnapshot struct {
	Configuration    ValidatedConfiguration
	Revision         uint64
	SecretReferences []ContextReference
}

func (ContextConfigurationSnapshot) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private configuration snapshot]")
}
func (ContextConfigurationSnapshot) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-configuration-snapshot"}`), nil
}

// This state checks owner snapshots; its retained value is only a revision
// guard, never a fallback source when the real owner is unavailable.
type contextConfiguration struct {
	lease             ContextConfigurationLease
	binding           ContextBinding
	mu                sync.Mutex
	last              ContextConfigurationSnapshot
	allowedReferences map[ContextReference]bool
}

func newContextConfiguration(ctx context.Context, binding ContextBinding, admission ContextInstanceAdmission, lease ContextConfigurationLease) (*contextConfiguration, error) {
	return newContextConfigurationWithInitial(ctx, binding, admission, lease, nil)
}

func newContextConfigurationWithInitial(ctx context.Context, binding ContextBinding, admission ContextInstanceAdmission, lease ContextConfigurationLease, initial *nativeConfigurationInitialRead) (*contextConfiguration, error) {
	var initialSnapshot ContextConfigurationSnapshot
	var initialChanged <-chan struct{}
	if initial != nil {
		var err error
		initialSnapshot, initialChanged, err = initial.consume(ctx, binding, admission, lease)
		if err != nil {
			return nil, err
		}
	}
	if ctx == nil || lease == nil {
		return nil, pluginError("context_configuration_unavailable")
	}
	v := reflect.ValueOf(lease)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan:
		if v.IsNil() {
			return nil, pluginError("context_configuration_unavailable")
		}
	}
	if lease.Owner() != binding.Owner || lease.Done() == nil {
		return nil, pluginError("context_configuration_unavailable")
	}
	c := &contextConfiguration{lease: lease, binding: cloneContextBinding(binding), last: cloneContextConfiguration(ContextConfigurationSnapshot{
		Configuration: binding.Configuration, Revision: admission.ConfigurationRevision, SecretReferences: admission.SecretReferences,
	})}
	c.allowedReferences = make(map[ContextReference]bool, len(admission.SecretReferences))
	for _, reference := range admission.SecretReferences {
		c.allowedReferences[reference] = true
	}
	expected := cloneContextConfiguration(c.last)
	work, cancel := context.WithTimeout(ctx, contextCallBudget)
	defer cancel()
	var snapshot ContextConfigurationSnapshot
	var err error
	if initial != nil {
		snapshot, _, err = c.acceptSnapshot(work, initialSnapshot, initialChanged)
	} else {
		snapshot, _, err = c.snapshot(work)
	}
	if err != nil || !sameContextConfiguration(snapshot, expected) {
		return nil, pluginError("context_configuration_unavailable")
	}
	if initial != nil {
		if err := initial.recheckOpening(ctx, binding, admission, lease); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *contextConfiguration) Done() <-chan struct{} { return c.lease.Done() }
func (c *contextConfiguration) Close(ctx context.Context) error {
	if ctx == nil || c.lease.Close(ctx) != nil || !completed(c.lease.Done()) {
		return pluginError("context_cleanup_incomplete")
	}
	return nil
}

func cloneContextConfiguration(snapshot ContextConfigurationSnapshot) ContextConfigurationSnapshot {
	snapshot.Configuration.raw = bytes.Clone(snapshot.Configuration.raw)
	snapshot.SecretReferences = append([]ContextReference{}, snapshot.SecretReferences...)
	return snapshot
}

func sameContextConfiguration(a, b ContextConfigurationSnapshot) bool {
	return a.Revision == b.Revision && a.Configuration.Pin() == b.Configuration.Pin() &&
		a.Configuration.SchemaRef() == b.Configuration.SchemaRef() && bytes.Equal(a.Configuration.Bytes(), b.Configuration.Bytes()) &&
		reflect.DeepEqual(a.SecretReferences, b.SecretReferences)
}

func (c *contextConfiguration) snapshot(ctx context.Context) (ContextConfigurationSnapshot, <-chan struct{}, error) {
	fail := func() (ContextConfigurationSnapshot, <-chan struct{}, error) {
		return ContextConfigurationSnapshot{}, nil, pluginError("context_configuration_unavailable")
	}
	if ctx == nil || ctx.Err() != nil || completed(c.lease.Done()) || completed(c.binding.LifetimeDone) || completed(c.binding.ParentLifetime) {
		return fail()
	}
	snapshot, changed, err := c.lease.Snapshot(ctx)
	if err != nil {
		return fail()
	}
	return c.acceptSnapshot(ctx, snapshot, changed)
}

func (c *contextConfiguration) acceptSnapshot(ctx context.Context, snapshot ContextConfigurationSnapshot, changed <-chan struct{}) (ContextConfigurationSnapshot, <-chan struct{}, error) {
	fail := func() (ContextConfigurationSnapshot, <-chan struct{}, error) {
		return ContextConfigurationSnapshot{}, nil, pluginError("context_configuration_unavailable")
	}
	if ctx == nil || changed == nil || ctx.Err() != nil || completed(c.lease.Done()) || completed(c.binding.LifetimeDone) || completed(c.binding.ParentLifetime) {
		return fail()
	}
	snapshot = cloneContextConfiguration(snapshot)
	if !snapshot.Configuration.BelongsTo(c.binding.Package) || snapshot.Revision > maxGeneration || len(snapshot.SecretReferences) > 64 {
		return fail()
	}
	seen := map[ContextReference]bool{}
	for _, reference := range snapshot.SecretReferences {
		// Recheck receives the immutable instance admission. New or rotated
		// secret references therefore require a new admitted context lease.
		if !contextReferenceValid(reference) || seen[reference] || !c.allowedReferences[reference] {
			return fail()
		}
		seen[reference] = true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx.Err() != nil || completed(c.lease.Done()) || completed(c.binding.LifetimeDone) || completed(c.binding.ParentLifetime) ||
		snapshot.Revision < c.last.Revision || snapshot.Revision == c.last.Revision && !sameContextConfiguration(snapshot, c.last) {
		return fail()
	}
	c.last = cloneContextConfiguration(snapshot)
	return snapshot, changed, nil
}

func (c *contextConfiguration) Read(ctx context.Context) (ContextConfigurationSnapshot, error) {
	if ctx == nil {
		return ContextConfigurationSnapshot{}, pluginError("context_configuration_unavailable")
	}
	work, cancel := context.WithTimeout(ctx, contextCallBudget)
	defer cancel()
	snapshot, _, err := c.snapshot(work)
	return snapshot, err
}

// Next waits for an actual newer owner revision, with no polling worker or
// detached call. Concurrent readers each hold their own bounded service slot.
func (c *contextConfiguration) Next(ctx context.Context, afterRevision uint64) (ContextConfigurationSnapshot, error) {
	if ctx == nil || ctx.Err() != nil || afterRevision > maxGeneration {
		return ContextConfigurationSnapshot{}, pluginError("context_configuration_unavailable")
	}
	if demand, ok := c.lease.(contextConfigurationWatchDemand); ok {
		demand.requestConfigurationWatch()
	}
	work, cancel := context.WithTimeout(ctx, contextCallBudget)
	defer cancel()
	notified := false
	for {
		snapshot, changed, err := c.snapshot(work)
		if err != nil {
			return ContextConfigurationSnapshot{}, err
		}
		if snapshot.Revision > afterRevision {
			return snapshot, nil
		}
		if notified || snapshot.Revision < afterRevision {
			return ContextConfigurationSnapshot{}, pluginError("context_configuration_unavailable")
		}
		select {
		case <-changed:
			notified = true
		case <-c.lease.Done():
			return ContextConfigurationSnapshot{}, pluginError("context_configuration_unavailable")
		case <-c.binding.LifetimeDone:
			return ContextConfigurationSnapshot{}, pluginError("context_configuration_unavailable")
		case <-c.binding.ParentLifetime:
			return ContextConfigurationSnapshot{}, pluginError("context_configuration_unavailable")
		case <-work.Done():
			return ContextConfigurationSnapshot{}, pluginError("context_operation_canceled")
		}
	}
}
