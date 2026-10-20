package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

// This explicit fixture owner has actual mutable state and change subscriptions.
// It does not stand in for a production configuration ledger or grant authority.
type contextMemoryConfigurationOwner struct {
	mu     sync.Mutex
	leases map[OwnerReference]*contextMemoryConfigurationLease
}

func newContextMemoryConfigurationOwner() *contextMemoryConfigurationOwner {
	return &contextMemoryConfigurationOwner{leases: map[OwnerReference]*contextMemoryConfigurationLease{}}
}

func (o *contextMemoryConfigurationOwner) Open(ctx context.Context, binding ContextBinding) (ContextConfigurationLease, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, pluginError("context_configuration_unavailable")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if previous := o.leases[binding.Owner]; previous != nil && !completed(previous.Done()) {
		return nil, pluginError("context_instance_owned")
	}
	lease := &contextMemoryConfigurationLease{owner: binding.Owner, current: cloneContextConfiguration(ContextConfigurationSnapshot{
		Configuration: binding.Configuration, Revision: 7, SecretReferences: []ContextReference{},
	}), changed: make(chan struct{}), done: make(chan struct{})}
	o.leases[binding.Owner] = lease
	return lease, nil
}

func (o *contextMemoryConfigurationOwner) Lease(owner OwnerReference) *contextMemoryConfigurationLease {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.leases[owner]
}

type contextMemoryConfigurationLease struct {
	owner   OwnerReference
	mu      sync.Mutex
	current ContextConfigurationSnapshot
	changed chan struct{}
	done    chan struct{}
	closed  bool
}

func (l *contextMemoryConfigurationLease) Owner() OwnerReference { return l.owner }
func (l *contextMemoryConfigurationLease) Done() <-chan struct{} { return l.done }
func (l *contextMemoryConfigurationLease) Snapshot(ctx context.Context) (ContextConfigurationSnapshot, <-chan struct{}, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || l.closed {
		return ContextConfigurationSnapshot{}, nil, pluginError("context_configuration_unavailable")
	}
	return cloneContextConfiguration(l.current), l.changed, nil
}
func (l *contextMemoryConfigurationLease) Update(configuration ValidatedConfiguration, revision uint64, refs []ContextReference) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	l.current = cloneContextConfiguration(ContextConfigurationSnapshot{Configuration: configuration, Revision: revision, SecretReferences: refs})
	close(l.changed)
	l.changed = make(chan struct{})
}
func (l *contextMemoryConfigurationLease) Close(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	if ctx == nil || ctx.Err() != nil {
		return pluginError("context_cleanup_incomplete")
	}
	l.closed = true
	close(l.changed)
	close(l.done)
	return nil
}

func contextConfigurationFixture(t *testing.T) (ContextBinding, ContextInstanceAdmission, *contextMemoryConfigurationLease) {
	t.Helper()
	pkg := fixturePackage(t, fixtureManifest("configuration_context"), map[string][]byte{"schemas/config.json": []byte(`{"type":"object"}`)})
	configuration, err := PrepareConfiguration(pkg, nil, []byte(`{"private":"initial-secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	binding := ContextBinding{Owner: OwnerReference{Pin: pkg.Pin(), InstanceID: "configuration_instance", Epoch: fmt.Sprintf("%064x", 1), Generation: 1}, Package: pkg, Configuration: configuration, LifetimeDone: make(chan struct{})}
	owner := newContextMemoryConfigurationOwner()
	lease, err := owner.Open(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := lease.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return binding, ContextInstanceAdmission{ConfigurationRevision: 7, SecretReferences: []ContextReference{}}, lease.(*contextMemoryConfigurationLease)
}

func TestContextConfigurationInitialSnapshotMustMatchAdmission(t *testing.T) {
	for _, mismatch := range []string{"revision", "bytes", "owner", "secrets"} {
		t.Run(mismatch, func(t *testing.T) {
			binding, admission, lease := contextConfigurationFixture(t)
			switch mismatch {
			case "revision":
				lease.current.Revision++
			case "bytes":
				var err error
				lease.current.Configuration, err = PrepareConfiguration(binding.Package, nil, []byte(`{"private":"changed"}`))
				if err != nil {
					t.Fatal(err)
				}
			case "owner":
				lease.owner.Generation++
			case "secrets":
				lease.current.SecretReferences = []ContextReference{{ID: "secret", OwnerHubID: "hub", Revision: 1}}
			}
			if _, err := newContextConfiguration(context.Background(), binding, admission, lease); err == nil {
				t.Fatal("mismatched configuration admitted")
			}
			if completed(lease.Done()) {
				t.Fatal("constructor discarded original lease")
			}
		})
	}
}

func TestContextConfigurationChangesCarryImmutableValidatedSnapshots(t *testing.T) {
	binding, admission, lease := contextConfigurationFixture(t)
	admission.SecretReferences = []ContextReference{{ID: "secret", OwnerHubID: "hub", Revision: 2}}
	lease.current.SecretReferences = append([]ContextReference{}, admission.SecretReferences...)
	state, err := newContextConfiguration(context.Background(), binding, admission, lease)
	if err != nil {
		t.Fatal(err)
	}
	next, err := PrepareConfiguration(binding.Package, nil, []byte(`{"private":"updated-secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	type outcome struct {
		snapshot ContextConfigurationSnapshot
		err      error
	}
	result := make(chan outcome, 1)
	go func() { snapshot, err := state.Next(ctx, 7); result <- outcome{snapshot, err} }()
	refs := []ContextReference{{ID: "secret", OwnerHubID: "hub", Revision: 2}}
	lease.Update(next, 8, refs)
	refs[0].ID = "mutated"
	got := <-result
	if got.err != nil || got.snapshot.Revision != 8 || !bytes.Equal(got.snapshot.Configuration.Bytes(), next.Bytes()) || got.snapshot.SecretReferences[0].ID != "secret" {
		t.Fatal("real owner update not delivered")
	}
	got.snapshot.Configuration.raw[0] = 'x'
	got.snapshot.SecretReferences[0].ID = "changed"
	current, err := state.Read(ctx)
	if err != nil || !bytes.Equal(current.Configuration.Bytes(), next.Bytes()) || current.SecretReferences[0].ID != "secret" {
		t.Fatal("reader mutated owner snapshot")
	}
	raw, _ := json.Marshal(current)
	if bytes.Contains(raw, []byte("updated-secret")) || bytes.Contains([]byte(fmt.Sprintf("%+v", current)), []byte("updated-secret")) {
		t.Fatal("snapshot formatting leaked private values")
	}
}

func TestContextConfigurationRejectsRollbackAndUnversionedChange(t *testing.T) {
	for _, change := range []string{"rollback", "same_revision", "foreign_package", "bad_reference"} {
		t.Run(change, func(t *testing.T) {
			binding, admission, lease := contextConfigurationFixture(t)
			state, err := newContextConfiguration(context.Background(), binding, admission, lease)
			if err != nil {
				t.Fatal(err)
			}
			config, err := PrepareConfiguration(binding.Package, nil, []byte(`{"private":"next"}`))
			if err != nil {
				t.Fatal(err)
			}
			revision := uint64(8)
			var refs []ContextReference
			switch change {
			case "rollback":
				revision = 6
			case "same_revision":
				revision = 7
			case "foreign_package":
				config.pin.PackageID = "foreign"
			case "bad_reference":
				refs = []ContextReference{{ID: "not a reference"}}
			}
			lease.Update(config, revision, refs)
			if _, err := state.Read(context.Background()); err == nil {
				t.Fatal("invalid owner snapshot accepted")
			}
		})
	}
}

func TestContextConfigurationWaitCancelsAndOwnerCloseJoins(t *testing.T) {
	binding, admission, lease := contextConfigurationFixture(t)
	state, err := newContextConfiguration(context.Background(), binding, admission, lease)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := state.Next(ctx, 7); result <- err }()
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled wait succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("wait did not join")
	}
	if err := state.Close(context.Background()); err != nil || !completed(state.Done()) {
		t.Fatal("original owner did not join")
	}
	if _, err := state.Read(context.Background()); err == nil {
		t.Fatal("closed owner supplied cached values")
	}
}

func TestContextConfigurationUnchangedNotificationCannotSpin(t *testing.T) {
	binding, admission, lease := contextConfigurationFixture(t)
	state, err := newContextConfiguration(context.Background(), binding, admission, lease)
	if err != nil {
		t.Fatal(err)
	}
	lease.mu.Lock()
	close(lease.changed)
	lease.mu.Unlock()
	if _, err := state.Next(context.Background(), 7); err == nil {
		t.Fatal("unchanged notification accepted")
	}
	lease.mu.Lock()
	lease.changed = make(chan struct{})
	lease.mu.Unlock()
}

type contextConfigurationInterceptLease struct {
	ContextConfigurationLease
	snapshot func(context.Context) (ContextConfigurationSnapshot, <-chan struct{}, error)
	close    func(context.Context) error
}

func (l contextConfigurationInterceptLease) Snapshot(ctx context.Context) (ContextConfigurationSnapshot, <-chan struct{}, error) {
	if l.snapshot != nil {
		return l.snapshot(ctx)
	}
	return l.ContextConfigurationLease.Snapshot(ctx)
}
func (l contextConfigurationInterceptLease) Close(ctx context.Context) error {
	if l.close != nil {
		return l.close(ctx)
	}
	return l.ContextConfigurationLease.Close(ctx)
}

func TestContextConfigurationLateSnapshotCannotDiscloseValues(t *testing.T) {
	binding, admission, lease := contextConfigurationFixture(t)
	state, err := newContextConfiguration(context.Background(), binding, admission, lease)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	state.lease = contextConfigurationInterceptLease{ContextConfigurationLease: lease, snapshot: func(work context.Context) (ContextConfigurationSnapshot, <-chan struct{}, error) {
		if deadline, ok := work.Deadline(); !ok || time.Until(deadline) > contextCallBudget {
			t.Error("owner read lacks bounded context")
		}
		snapshot, changed, err := lease.Snapshot(work)
		cancel()
		return snapshot, changed, err
	}}
	got, err := state.Read(ctx)
	if err == nil || len(got.Configuration.Bytes()) != 0 {
		t.Fatal("late snapshot disclosed private configuration")
	}
}

func TestContextConfigurationCloseRequiresOriginalJoin(t *testing.T) {
	binding, admission, lease := contextConfigurationFixture(t)
	state, err := newContextConfiguration(context.Background(), binding, admission, lease)
	if err != nil {
		t.Fatal(err)
	}
	state.lease = contextConfigurationInterceptLease{ContextConfigurationLease: lease, close: func(context.Context) error { return nil }}
	if err := state.Close(context.Background()); err == nil || completed(state.Done()) {
		t.Fatal("unjoined close reported success")
	}
	state.lease = lease
	if err := state.Close(context.Background()); err != nil || !completed(state.Done()) {
		t.Fatal("original owner join failed")
	}
}

func TestContextConfigurationCannotIntroduceUnadmittedSecretReferences(t *testing.T) {
	for _, change := range []string{"new", "rotated", "removed"} {
		t.Run(change, func(t *testing.T) {
			binding, admission, lease := contextConfigurationFixture(t)
			admission.SecretReferences = []ContextReference{{ID: "secret", OwnerHubID: "hub", Revision: 1}}
			lease.current.SecretReferences = append([]ContextReference{}, admission.SecretReferences...)
			state, err := newContextConfiguration(context.Background(), binding, admission, lease)
			if err != nil {
				t.Fatal(err)
			}
			var refs []ContextReference
			switch change {
			case "new":
				refs = []ContextReference{{ID: "other", OwnerHubID: "hub", Revision: 1}}
			case "rotated":
				refs = []ContextReference{{ID: "secret", OwnerHubID: "hub", Revision: 2}}
			}
			lease.Update(binding.Configuration, 8, refs)
			snapshot, err := state.Read(context.Background())
			if change == "removed" {
				if err != nil || len(snapshot.SecretReferences) != 0 {
					t.Fatal("reference removal refused")
				}
			} else if err == nil || len(snapshot.Configuration.Bytes()) != 0 {
				t.Fatal("unadmitted reference disclosed")
			}
		})
	}
}
