package plugins

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"
)

// This receipt belongs to one straight-line context opening. It carries the
// exact verified initial fetch, never a later copy of the lease's last value.
// Public reads cannot obtain or reuse it as authority for another operation.
type nativeConfigurationInitialRead struct {
	mu              sync.Mutex
	used            bool
	lease           *nativeConfigurationLease
	owner           *NativeConfigurationOwner
	binding         ContextBinding
	admission       ContextInstanceAdmission
	input           NativeConfigurationClientBinding
	openingDone     <-chan struct{}
	drain           <-chan struct{}
	deadline, until time.Time
	changed         <-chan struct{}
	snapshot        ContextConfigurationSnapshot
}

func (*nativeConfigurationInitialRead) Format(s fmt.State, _ rune) {
	io.WriteString(s, "[private initial configuration read]")
}
func (*nativeConfigurationInitialRead) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-initial-configuration-read"}`), nil
}

func (r *nativeConfigurationInitialRead) consume(ctx context.Context, binding ContextBinding, admission ContextInstanceAdmission, lease ContextConfigurationLease) (ContextConfigurationSnapshot, <-chan struct{}, error) {
	fail := func() (ContextConfigurationSnapshot, <-chan struct{}, error) {
		return ContextConfigurationSnapshot{}, nil, pluginError("context_configuration_unavailable")
	}
	if r == nil {
		return fail()
	}
	r.mu.Lock()
	if r.used {
		r.mu.Unlock()
		return fail()
	}
	r.used = true
	r.mu.Unlock()
	if err := r.recheckOpening(ctx, binding, admission, lease); err != nil {
		return fail()
	}
	return cloneContextConfiguration(r.snapshot), r.changed, nil
}

func (r *nativeConfigurationInitialRead) recheckOpening(ctx context.Context, binding ContextBinding, admission ContextInstanceAdmission, lease ContextConfigurationLease) error {
	fail := func() error { return pluginError("context_configuration_unavailable") }
	if r == nil {
		return fail()
	}
	original, ok := lease.(*nativeConfigurationLease)
	if !ok || original == nil || original != r.lease || r.owner == nil || original.owner != r.owner || ctx == nil || ctx.Err() != nil || r.openingDone == nil || ctx.Done() != r.openingDone || !reflect.DeepEqual(binding, r.binding) || !reflect.DeepEqual(cloneInstanceAdmission(admission), r.admission) {
		return fail()
	}
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.Equal(r.deadline) || !time.Now().Before(deadline) || !time.Now().Before(r.until) || binding.Lifecycle == nil || r.drain == nil || binding.Lifecycle.DrainDone() != r.drain || completed(r.drain) || r.input.Exchange == nil || !r.input.Exchange.ConfigurationReusable() {
		return fail()
	}
	original.mu.Lock()
	defer original.mu.Unlock()
	r.owner.mu.Lock()
	defer r.owner.mu.Unlock()
	if r.owner.closing || !r.owner.leases[original] || original.closing || original.ctx.Err() != nil || !original.available || original.changedClosed || original.changed != r.changed || !original.until.Equal(r.until) || !reflect.DeepEqual(original.binding, r.binding) || !reflect.DeepEqual(original.input, r.input) || !reflect.DeepEqual(r.owner.bindings[binding.Owner.InstanceID], r.input) || !sameContextConfiguration(original.last, r.snapshot) || original.last.Configuration.Checksum() != r.snapshot.Configuration.Checksum() || ctx.Err() != nil || completed(original.binding.LifetimeDone) || completed(original.binding.ParentLifetime) || completed(original.done) || completed(original.terminal) || !time.Now().Before(r.until) || !time.Now().Before(r.deadline) {
		return fail()
	}
	if completed(r.drain) || !r.input.Exchange.ConfigurationReusable() {
		return fail()
	}
	return nil
}
