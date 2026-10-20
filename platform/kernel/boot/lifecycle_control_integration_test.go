package boot_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

type selfRecoveryObservation struct {
	generation uint64
	event      protocol.Event
}

func TestLifecycleControlRealTLSDefersSelfRecoveryUntilBrokerReturns(t *testing.T) {
	f := newRecoveryFixture(t)
	client := fixture{trust: f.trust, url: f.endpoint, secrets: f.secrets, scope: f.scope, wire: f.wire}.client(t, "kernel-lifecycle")
	inventories, err := client.SubscribeSync(f.wire.Commands["kernel-lifecycle"])
	if err != nil || client.FlushTimeout(time.Second) != nil {
		t.Fatal("actual lifecycle inventory observer unavailable")
	}
	defer inventories.Unsubscribe()
	owner := &controlTestOwner{requests: make(chan protocol.LifecycleRequest, 16)}
	for _, role := range protocol.Roles() {
		owner.members = append(owner.members, protocol.LifecycleMember{Role: role, Generation: 1, State: "running"})
	}
	config := protocol.Config{Credentials: protocol.Credentials{SchemaVersion: protocol.Version, Role: "kernel-lifecycle",
		Username: "kernel-lifecycle", Password: f.secrets["kernel-lifecycle"], NATSURL: f.endpoint, Scope: f.scope},
		ServerTrust: f.trust, Interval: recoveryInterval, StaleAfter: recoveryStaleAfter}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- protocol.RunLifecycleSupervisor(ctx, config, f.wire, owner) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error("broker recovery control transport cleanup failed")
			}
		case <-time.After(time.Second):
			t.Error("broker recovery control owner did not join")
		}
	})
	if _, err := inventories.NextMsgWithContext(ctx); err != nil {
		t.Fatal("initial authenticated lifecycle inventory unavailable")
	}
	f.stopBroker()
	owner.mu.Lock()
	owner.members[1].State = "exited"
	owner.mu.Unlock()
	// A reconnecting control connection must not consume either replacement
	// attempt while the broker needed by the new child is still unavailable.
	select {
	case <-owner.requests:
		t.Fatal("lifecycle replacement was admitted while the real broker was stopped")
	case <-time.After(300 * time.Millisecond):
	}
	f.startBroker()
	_, closeReader := f.reader(time.Now().Add(time.Second))
	closeReader()
	select {
	case request := <-owner.requests:
		if request.Role != "kernel-lifecycle" || request.Action != "recover" || request.ExpectedGeneration != 1 {
			t.Fatal("broker return consumed the wrong owned replacement attempt")
		}
	case <-ctx.Done():
		t.Fatal("lifecycle replacement did not resume after authenticated broker return")
	}
}

type selfRecoveryControlOwner struct {
	controlTestOwner
	publish  func(context.Context) error
	observed chan selfRecoveryObservation
}

func (o *selfRecoveryControlOwner) Apply(ctx context.Context, request protocol.LifecycleRequest) (uint64, error) {
	generation, err := o.controlTestOwner.Apply(ctx, request)
	if err == nil {
		// Queue a real replacement event while the trusted operation still
		// owns the supervisor loop, before Apply can return to event selection.
		err = o.publish(ctx)
	}
	return generation, err
}

func (o *selfRecoveryControlOwner) Observe(role string, generation uint64, event protocol.Event) {
	if role == "kernel-lifecycle" {
		select {
		case o.observed <- selfRecoveryObservation{generation, event}:
		default:
		}
	}
}

func TestLifecycleControlRealTLSSelfRecoveryBindsQueuedIncarnation(t *testing.T) {
	f := newRecoveryFixture(t)
	client := fixture{trust: f.trust, url: f.endpoint, secrets: f.secrets, scope: f.scope, wire: f.wire}.client(t, "kernel-lifecycle")
	inventories, err := client.SubscribeSync(f.wire.Commands["kernel-lifecycle"])
	if err != nil || client.FlushTimeout(time.Second) != nil {
		t.Fatal("actual lifecycle inventory observer unavailable")
	}
	defer inventories.Unsubscribe()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	incarnation := strings.Repeat("b", 32)
	oldTime := time.Now()
	publish := func(ctx context.Context, revision uint64, at time.Time, incarnation string) error {
		members := []protocol.Member{}
		for _, role := range protocol.Roles() {
			members = append(members, protocol.Member{Role: role, State: "unknown"})
		}
		event := protocol.Event{SchemaVersion: protocol.Version, Kind: "kernel-role-observation", Scope: f.scope,
			Role: "kernel-lifecycle", Incarnation: incarnation, Revision: revision,
			ObservedAt: at.UTC().Format(time.RFC3339Nano), State: "ready", ErrorCodes: []string{"peer_unavailable"}, Members: members}
		raw, _ := json.Marshal(event)
		if err := client.Publish(f.wire.Events["kernel-lifecycle"], raw); err != nil {
			return err
		}
		return client.FlushWithContext(ctx)
	}
	owner := &selfRecoveryControlOwner{controlTestOwner: controlTestOwner{requests: make(chan protocol.LifecycleRequest, 16)},
		observed: make(chan selfRecoveryObservation, 16)}
	for _, role := range protocol.Roles() {
		state := "running"
		if role == "kernel-lifecycle" {
			state = "exited"
		}
		owner.members = append(owner.members, protocol.LifecycleMember{Role: role, Generation: 1, State: state})
	}
	owner.publish = func(ctx context.Context) error { return publish(ctx, 1, time.Now(), incarnation) }
	config := protocol.Config{Credentials: protocol.Credentials{SchemaVersion: protocol.Version, Role: "kernel-lifecycle",
		Username: "kernel-lifecycle", Password: f.secrets["kernel-lifecycle"], NATSURL: f.endpoint, Scope: f.scope},
		ServerTrust: f.trust, Interval: time.Second, StaleAfter: 3 * time.Second}
	done := make(chan error, 1)
	go func() { done <- protocol.RunLifecycleSupervisor(ctx, config, f.wire, owner) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error("self-recovery control transport cleanup failed")
			}
		case <-time.After(time.Second):
			t.Error("self-recovery control owner did not join")
		}
	})
	// Wait for an actual published generation-two inventory, then send a fresh
	// event of that same replacement. An early queued event must neither bind
	// generation one nor permanently retire the replacement's incarnation.
	for {
		message, err := inventories.NextMsgWithContext(ctx)
		if err != nil {
			t.Fatal("self-recovery generation inventory unavailable")
		}
		inventory, err := protocol.DecodeLifecycleInventory(message.Data, f.scope, time.Now())
		if err != nil {
			continue
		}
		if inventory.Members[1].Role == "kernel-lifecycle" && inventory.Members[1].Generation == 2 {
			break
		}
	}
	if publish(ctx, 2, time.Now(), incarnation) != nil {
		t.Fatal("fresh replacement lifecycle event publication failed")
	}
	for {
		select {
		case observed := <-owner.observed:
			if observed.generation != 2 || observed.event.Incarnation != incarnation {
				t.Fatal("queued replacement event was bound to the retired generation")
			}
			if observed.event.Revision != 2 {
				continue
			}
		case <-ctx.Done():
			t.Fatal("fresh replacement incarnation was permanently retired")
		}
		break
	}
	if publish(ctx, 1, oldTime, strings.Repeat("a", 32)) != nil {
		t.Fatal("prior-generation event control publication failed")
	}
	select {
	case <-owner.observed:
		t.Fatal("prior-generation event crossed the new generation boundary")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestLifecycleControlRealTLSPermissionRefusalIsTerminal(t *testing.T) {
	f := newRecoveryFixture(t)
	f.stopBroker()
	raw, err := os.ReadFile(f.config)
	if err != nil {
		t.Fatal("owned broker configuration unavailable")
	}
	var document map[string]any
	if json.Unmarshal(raw, &document) != nil {
		t.Fatal("owned broker configuration invalid")
	}
	users := document["accounts"].(map[string]any)["KERNEL"].(map[string]any)["users"].([]any)
	for _, entry := range users {
		user := entry.(map[string]any)
		if user["user"] == "kernel-lifecycle" {
			user["permissions"].(map[string]any)["subscribe"] = map[string]any{"allow": []string{}, "deny": []string{">"}}
		}
	}
	var updated bytes.Buffer
	encoder := json.NewEncoder(&updated)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(document) != nil || os.WriteFile(f.config, updated.Bytes(), 0600) != nil {
		t.Fatal("owned broker permission change failed")
	}
	f.startBroker()
	_, closeReady := f.reader(time.Now().Add(time.Second))
	closeReady()
	owner := &controlTestOwner{requests: make(chan protocol.LifecycleRequest, 16)}
	for _, role := range protocol.Roles() {
		owner.members = append(owner.members, protocol.LifecycleMember{Role: role, Generation: 1, State: "running"})
	}
	config := protocol.Config{Credentials: protocol.Credentials{SchemaVersion: protocol.Version, Role: "kernel-lifecycle", Username: "kernel-lifecycle", Password: f.secrets["kernel-lifecycle"], NATSURL: f.endpoint, Scope: f.scope}, ServerTrust: f.trust, Interval: 40 * time.Millisecond, StaleAfter: 160 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = protocol.RunLifecycleSupervisor(ctx, config, f.wire, owner)
	if !errors.Is(err, protocol.ErrBrokerAuthorization) {
		t.Fatal("real permission refusal did not retain its terminal authority category", err)
	}
	if owner.count != 0 {
		t.Fatal("permission refusal admitted lifecycle mutation")
	}
}

// This owner proves the protected NATS control boundary only. It does not
// replace the native exact-process recovery checks.
type controlTestOwner struct {
	mu       sync.Mutex
	members  []protocol.LifecycleMember
	requests chan protocol.LifecycleRequest
	count    int
}

func (o *controlTestOwner) Inventory() []protocol.LifecycleMember {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]protocol.LifecycleMember(nil), o.members...)
}
func (o *controlTestOwner) Apply(_ context.Context, r protocol.LifecycleRequest) (uint64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.count++
	for i := range o.members {
		if o.members[i].Role == r.Role {
			o.members[i].Generation++
			o.members[i].State = "running"
		}
	}
	o.requests <- r
	return r.ExpectedGeneration + 1, nil
}

func TestLifecycleControlRealTLSCoordinatesOneSiblingRecovery(t *testing.T) {
	f := newRecoveryFixture(t)
	actors := fixture{trust: f.trust, url: f.endpoint, secrets: f.secrets, scope: f.scope, wire: f.wire}
	cancels := map[string]context.CancelFunc{}
	for _, role := range protocol.Roles() {
		cancels[role] = actors.start(t, role)
	}
	initial, closeInitial := f.snapshotReader(time.Now().Add(3 * time.Second))
	f.ready(initial, time.Now().Add(3*time.Second), time.Time{})
	closeInitial()
	owner := &controlTestOwner{requests: make(chan protocol.LifecycleRequest, 16)}
	for _, role := range protocol.Roles() {
		owner.members = append(owner.members, protocol.LifecycleMember{Role: role, Generation: 1, State: "running"})
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	config := protocol.Config{Credentials: protocol.Credentials{SchemaVersion: protocol.Version, Role: "kernel-lifecycle", Username: "kernel-lifecycle", Password: f.secrets["kernel-lifecycle"], NATSURL: f.endpoint, Scope: f.scope}, ServerTrust: f.trust, Interval: 40 * time.Millisecond, StaleAfter: 160 * time.Millisecond}
	go func() { done <- protocol.RunLifecycleSupervisor(ctx, config, f.wire, owner) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error("control transport cleanup failed")
			}
		case <-time.After(time.Second):
			t.Error("control transport did not join")
		}
	})
	// The peer actor really exits. A completed control result and an owned
	// generation alone must not make its absence into a ready kernel snapshot.
	cancels["boot"]()
	owner.mu.Lock()
	owner.members[0].State = "exited"
	owner.mu.Unlock()
	var request protocol.LifecycleRequest
	select {
	case request = <-owner.requests:
	case <-time.After(3 * time.Second):
		t.Fatal("lifecycle did not coordinate sibling recovery over NATS")
	}
	if request.Role != "boot" || request.ExpectedGeneration != 1 || request.Action != "recover" {
		t.Fatal("wrong owned slot selected")
	}
	client := fixture{trust: f.trust, url: f.endpoint, secrets: f.secrets, scope: f.scope, wire: f.wire}.client(t, "kernel-lifecycle")
	duplicate, _ := json.Marshal(request)
	for i := 0; i < 3; i++ {
		if client.Publish(f.wire.Commands["kernel-lifecycle"], duplicate) != nil {
			t.Fatal("control delivery failed")
		}
	}
	if client.FlushTimeout(time.Second) != nil {
		t.Fatal("control delivery did not flush")
	}
	select {
	case <-owner.requests:
		t.Fatal("duplicate request repeated mutation")
	case <-time.After(250 * time.Millisecond):
	}
	owner.mu.Lock()
	count := owner.count
	owner.mu.Unlock()
	if count != 1 {
		t.Fatal("recovery count changed")
	}
	reader, closeReader := f.reader(time.Now().Add(time.Second))
	defer closeReader()
	sub, err := reader.SubscribeSync(f.wire.Snapshot)
	if err != nil {
		t.Fatal("snapshot subscription failed")
	}
	if reader.FlushTimeout(time.Second) != nil {
		t.Fatal("snapshot subscription did not flush")
	}
	message, err := sub.NextMsg(time.Second)
	if err != nil {
		t.Fatal("snapshot unavailable")
	}
	snapshot, err := protocol.DecodeSnapshot(message.Data, f.scope, time.Now(), recoveryStaleAfter)
	if err != nil || snapshot.KernelReadiness == "ready" {
		t.Fatal("ownership inventory or control result invented kernel readiness")
	}
}
