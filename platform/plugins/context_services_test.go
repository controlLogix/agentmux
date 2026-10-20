package plugins

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type contextConfigurationOwnerFunc func(context.Context, ContextBinding) (ContextConfigurationLease, error)

func (f contextConfigurationOwnerFunc) Open(ctx context.Context, binding ContextBinding) (ContextConfigurationLease, error) {
	return f(ctx, binding)
}

func contextServiceConfigurationFixture(t *testing.T) (*contextTestFixture, *contextMemoryConfigurationOwner, *atomic.Bool, <-chan struct{}) {
	t.Helper()
	owner := newContextMemoryConfigurationOwner()
	var observe atomic.Bool
	entered := make(chan struct{})
	var once sync.Once
	f := newContextTestFixture(t, func(_ *ContextBinding, ports *ContextPorts) {
		ports.Configuration = contextConfigurationOwnerFunc(func(ctx context.Context, binding ContextBinding) (ContextConfigurationLease, error) {
			lease, err := owner.Open(ctx, binding)
			if err != nil {
				return lease, err
			}
			return contextConfigurationInterceptLease{ContextConfigurationLease: lease, snapshot: func(ctx context.Context) (ContextConfigurationSnapshot, <-chan struct{}, error) {
				snapshot, changed, err := lease.Snapshot(ctx)
				if observe.Load() {
					once.Do(func() { close(entered) })
				}
				return snapshot, changed, err
			}}, nil
		})
	})
	return f, owner, &observe, entered
}

func contextServiceAwait(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("configuration owner was not called")
	}
}

func contextServiceReplyRead(t *testing.T, f *contextTestFixture) contextServiceReply {
	t.Helper()
	var reply contextServiceReply
	if decodeContextJSON("plugin-context-reply", contextTestRead(t, f.connection.replies), &reply) != nil {
		t.Fatal("invalid service reply")
	}
	return reply
}

func TestContextServiceConfigurationWaitUsesRealOwnerNotification(t *testing.T) {
	f, owner, observe, entered := contextServiceConfigurationFixture(t)
	handle, result := f.dispatch(t, context.Background(), "a")
	first := f.call(t, "config", "read", &handle, map[string]any{})
	if first.Code != "ok" {
		t.Fatal("initial read failed")
	}
	before := bytes.Clone(first.Value)
	observe.Store(true)
	f.connection.requests <- f.request("config", "wait-change", &handle, map[string]any{"afterRevision": 7})
	contextServiceAwait(t, entered)
	config, err := PrepareConfiguration(f.lease.binding.Package, nil, []byte(`{"private":"updated-value"}`))
	if err != nil {
		t.Fatal(err)
	}
	owner.Lease(f.lease.Owner()).Update(config, 8, nil)
	reply := contextServiceReplyRead(t, f)
	var value struct {
		Bytes    string `json:"configurationBytes"`
		Revision uint64 `json:"configurationRevision"`
	}
	if reply.Code != "ok" || json.Unmarshal(reply.Value, &value) != nil || value.Revision != 8 {
		t.Fatal("owner notification not delivered")
	}
	raw, err := base64.StdEncoding.DecodeString(value.Bytes)
	if err != nil || !bytes.Equal(raw, config.Bytes()) || !bytes.Equal(first.Value, before) {
		t.Fatal("configuration snapshot changed or lost its bytes")
	}
	f.complete(handle)
	if contextTestResult(t, result).err != nil {
		t.Fatal("operation failed")
	}
}

func TestContextServiceConfigurationCanceledWaitDisclosesNoPayload(t *testing.T) {
	f, _, observe, entered := contextServiceConfigurationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handle, result := f.dispatch(t, ctx, "a")
	observe.Store(true)
	f.connection.requests <- f.request("config", "wait-change", &handle, map[string]any{"afterRevision": 7})
	contextServiceAwait(t, entered)
	cancel()
	reply := contextServiceReplyRead(t, f)
	if reply.Outcome != "rejected" || !bytes.Equal(reply.Value, []byte("null")) {
		t.Fatal("canceled configuration wait disclosed values")
	}
	if contextTestResult(t, result).err == nil {
		t.Fatal("canceled operation succeeded")
	}
}

func TestContextServiceConfigurationRechecksAuthorityAfterChange(t *testing.T) {
	f, owner, observe, entered := contextServiceConfigurationFixture(t)
	handle, result := f.dispatch(t, context.Background(), "a")
	observe.Store(true)
	f.connection.requests <- f.request("config", "wait-change", &handle, map[string]any{"afterRevision": 7})
	contextServiceAwait(t, entered)
	f.authority.deny.Store(true)
	owner.Lease(f.lease.Owner()).Update(f.lease.binding.Configuration, 8, nil)
	reply := contextServiceReplyRead(t, f)
	if reply.Code != "context_authority_unavailable" || !bytes.Equal(reply.Value, []byte("null")) {
		t.Fatal("revoked wait disclosed configuration")
	}
	f.complete(handle)
	if contextTestResult(t, result).err == nil {
		t.Fatal("revoked operation succeeded")
	}
}

func TestContextServiceConfigurationUncooperativeCloseRetainsOriginal(t *testing.T) {
	owner := newContextMemoryConfigurationOwner()
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var calls atomic.Int32
	f := newContextTestFixture(t, func(_ *ContextBinding, ports *ContextPorts) {
		ports.Configuration = contextConfigurationOwnerFunc(func(ctx context.Context, binding ContextBinding) (ContextConfigurationLease, error) {
			lease, err := owner.Open(ctx, binding)
			if err != nil {
				return lease, err
			}
			return contextConfigurationInterceptLease{ContextConfigurationLease: lease, close: func(context.Context) error {
				if calls.Add(1) == 1 {
					close(entered)
				}
				<-release
				return lease.Close(context.Background())
			}}, nil
		})
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- f.lease.Close(ctx) }()
	contextServiceAwait(t, entered)
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("unjoined close succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("caller close did not return")
	}
	if completed(f.lease.joined) || completed(owner.Lease(f.lease.Owner()).Done()) {
		t.Fatal("original owner was discarded")
	}
	if _, err := f.provider.Open(context.Background(), f.lease.binding); err == nil || err.Error() != "context_instance_owned" {
		t.Fatal("duplicate owner replaced unjoined configuration")
	}
	if err := f.lease.Close(ctx); err == nil || calls.Load() != 1 {
		t.Fatal("retry duplicated original cleanup")
	}
	releaseOnce.Do(func() { close(release) })
	joined, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := f.lease.Close(joined); err != nil || !completed(f.lease.joined) || !completed(owner.Lease(f.lease.Owner()).Done()) || calls.Load() != 1 {
		t.Fatal("original configuration cleanup did not join")
	}
}

func TestContextServiceConfigurationPortIsRequired(t *testing.T) {
	f := newContextTestFixture(t, nil)
	ports := f.provider.ports
	ports.Configuration = nil
	if contextPortsValid(ports) {
		t.Fatal("missing configuration owner accepted")
	}
	var owner *contextMemoryConfigurationOwner
	ports.Configuration = owner
	if contextPortsValid(ports) {
		t.Fatal("nil configuration owner accepted")
	}
}

func TestContextServiceConfigurationLateOpenErrorRetainsLease(t *testing.T) {
	f := newContextTestFixture(t, nil)
	if err := f.lease.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	owner := newContextMemoryConfigurationOwner()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.provider.ports.Configuration = contextConfigurationOwnerFunc(func(_ context.Context, binding ContextBinding) (ContextConfigurationLease, error) {
		cancel()
		lease, err := owner.Open(context.Background(), binding)
		if err != nil {
			return lease, err
		}
		return lease, pluginError("fixture_open_failed")
	})
	late, err := f.provider.Open(ctx, f.lease.binding)
	if err == nil || late == nil {
		t.Fatal("late configuration ownership lost")
	}
	t.Cleanup(func() {
		closeCtx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := late.Close(closeCtx); err != nil {
			t.Error(err)
		}
	})
	original := owner.Lease(f.lease.Owner())
	if original == nil || completed(original.Done()) {
		t.Fatal("late original lease disappeared")
	}
	if _, err := f.provider.Open(context.Background(), f.lease.binding); err == nil || err.Error() != "context_instance_owned" {
		t.Fatal("failed late owner was replaced")
	}
	closeCtx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := late.Close(closeCtx); err != nil || !completed(original.Done()) {
		t.Fatal("late configuration lease did not join")
	}
}

func TestContextServiceDomainRechecksAuthorityAfterOwnerReply(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		name := "current"
		if revoked {
			name = "revoked"
		}
		t.Run(name, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			f := newContextTestFixture(t, func(_ *ContextBinding, ports *ContextPorts) {
				ports.Domain = func(ctx context.Context, _ ContextApprovedEnvelope) ([]byte, error) {
					close(entered)
					select {
					case <-release:
						return []byte(`{"private":"domain-result"}`), nil
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
			})
			handle, result := f.dispatch(t, context.Background(), "a")
			f.connection.requests <- f.request("domainGateway", "request", &handle, map[string]any{"bindingId": "owner", "contractId": "status-query", "payload": map[string]any{}})
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("domain owner was not called")
			}
			f.authority.deny.Store(revoked)
			releaseOnce.Do(func() { close(release) })
			reply := contextServiceReplyRead(t, f)
			if revoked {
				if reply.Code != "context_authority_unavailable" || reply.Outcome != "rejected" || !bytes.Equal(reply.Value, []byte("null")) {
					t.Fatal("revoked caller received domain content")
				}
			} else if reply.Code != "ok" || !bytes.Equal(reply.Value, []byte(`{"private":"domain-result"}`)) {
				t.Fatal("current caller lost the original domain reply")
			}
			f.complete(handle)
			if got := contextTestResult(t, result); (got.err != nil) != revoked {
				t.Fatal("operation completion did not preserve its authority outcome")
			}
		})
	}
}
