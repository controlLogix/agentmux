//go:build linux || darwin

package launcher

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// This fixture exercises the private state and mapper with real enrollment and
// an acquired OS lease. Direct enter is a component control, not a claimed Run.
func pendingOperationFixture(t *testing.T) (*bootstrapOperation, bridgeFixture, *BootstrapLock, context.CancelFunc, context.CancelFunc) {
	t.Helper()
	f := newBridgeFixture(t)
	server, err := LoadOwnerBridgeServer(f.config, f.owner, f.enrollment)
	if err != nil {
		t.Fatal("private server fixture rejected")
	}
	startup, cancelStartup := context.WithTimeout(context.Background(), 30*time.Second)
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	t.Cleanup(cancelStartup)
	t.Cleanup(cancelLifetime)
	lease, err := AcquireBootstrapLock(startup, f.profile.ProfileDirectory, f.profile.InstanceID, "owner-status-service")
	if err != nil {
		t.Fatal("actual service lease rejected")
	}
	t.Cleanup(func() {
		if lease.Close() != nil {
			t.Error("fixture lease cleanup failed")
		}
	})
	op, err := newBootstrapOperation(startup, lifetime, server, lease, "attempt_"+strings.Repeat("a", 32))
	if err != nil {
		t.Fatal("actual owner binding rejected")
	}
	return op, f, lease, cancelStartup, cancelLifetime
}

func TestBootstrapOperationPendingRequiresCoreAdmission(t *testing.T) {
	op, f, _, _, _ := pendingOperationFixture(t)
	if _, err := f.owner.mapStartingContext(context.Background(), op); err == nil {
		t.Fatal("created operation manufactured starting")
	}
	if err := op.enter(op.startup, f.config, f.profile, op.attemptID); err != nil {
		t.Fatal("matching component admission rejected")
	}
	select {
	case <-op.enteredDone:
	default:
		t.Fatal("actual admitted transition did not notify")
	}
	if err := op.enter(op.startup, f.config, f.profile, op.attemptID); err == nil {
		t.Fatal("second core admission accepted")
	}
	cause := errors.New("actual_bootstrap_control_failure")
	if err := op.complete(nil, cause); err != nil {
		t.Fatal("actual failed result not retained")
	}
	if _, err := f.owner.mapStartingContext(context.Background(), op); err == nil {
		t.Fatal("completed operation manufactured starting")
	}
	if _, err := op.resultContext(context.Background()); !errors.Is(err, cause) {
		t.Fatal("actual completed cause lost")
	}
	if op.complete(nil, nil) == nil {
		t.Fatal("completion could be overwritten")
	}
}

func TestBootstrapOperationRetainsExactCompletionAndCause(t *testing.T) {
	op, f, _, _, _ := pendingOperationFixture(t)
	if op.enter(op.startup, f.config, f.profile, op.attemptID) != nil {
		t.Fatal("component admission rejected")
	}
	session := &Session{startupAttemptID: op.attemptID}
	cause := errors.New("actual_return_control")
	if op.complete(session, cause) != nil {
		t.Fatal("actual return rejected")
	}
	got, err := op.resultContext(context.Background())
	if got != session || !errors.Is(err, cause) {
		t.Fatal("exact owned return changed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := op.resultContext(ctx); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost to completed result")
	}
	if strings.Contains(fmt.Sprintf("%+v %#v %+v %#v", op, op, *op, *op), f.profile.ProfileDirectory) {
		t.Fatal("private operation disclosed enrollment")
	}
}

func TestBootstrapOperationAdmissionBindingDenials(t *testing.T) {
	for _, field := range []string{"hub", "instance", "profile", "assembly", "release", "version", "compose_bytes", "assembly_bytes", "profile_declaration", "attempt", "authority", "policy"} {
		t.Run(field, func(t *testing.T) {
			op, f, _, _, _ := pendingOperationFixture(t)
			c, p, id := f.config, f.profile, op.attemptID
			switch field {
			case "hub":
				c.Kernel.Scope.HubID = "another_hub"
			case "instance":
				c.Kernel.Scope.InstanceID = "another_instance"
			case "profile":
				c.Kernel.Scope.ProfileID = "another_profile"
			case "assembly":
				c.Kernel.Scope.AssemblyDigest = "sha256:" + strings.Repeat("c", 64)
			case "release":
				c.Kernel.Scope.ReleaseManifestDigest = "sha256:" + strings.Repeat("c", 64)
			case "version":
				c.Kernel.Scope.ReleaseVersion = "2.0.0"
			case "compose_bytes":
				c.Compose = append([]byte(nil), c.Compose...)
				c.Compose = append(c.Compose, ' ')
			case "assembly_bytes":
				c.Assembly = append([]byte(nil), c.Assembly...)
				c.Assembly = append(c.Assembly, ' ')
			case "profile_declaration":
				p.DisplayName = "changed declaration"
			case "attempt":
				id = "attempt_" + strings.Repeat("b", 32)
			case "authority":
				c.Kernel.authority = nil
			case "policy":
				c.admissionPolicy = nil
			}
			if op.enter(op.startup, c, p, id) == nil {
				t.Fatal("otherwise valid binding mismatch admitted")
			}
			if op.pending(f.owner) == nil {
				t.Fatal("rejected core manufactured pending")
			}
		})
	}
}

func TestBootstrapOperationPreEntryFailureRetained(t *testing.T) {
	op, _, _, _, _ := pendingOperationFixture(t)
	cause := errors.New("actual_preparation_failure")
	if op.complete(nil, cause) != nil {
		t.Fatal("pre-entry failure rejected")
	}
	select {
	case <-op.enteredDone:
		t.Fatal("pre-entry failure manufactured admitted transition")
	default:
	}
	if _, err := op.resultContext(context.Background()); !errors.Is(err, cause) {
		t.Fatal("pre-entry failure lost")
	}
	if op.enter(op.startup, op.server.config, op.profile, op.attemptID) == nil {
		t.Fatal("completed failure entered bootstrap")
	}
}

func TestBootstrapOperationActualCoreAdmissionRefusalCannotStart(t *testing.T) {
	op, f, _, _, _ := pendingOperationFixture(t)
	c := f.config
	c.Roles[0].Args = []string{"--unapproved-role-argument"}
	session, err := bootstrapForOperation(op.startup, op.lifetime, c, op.attemptID, op)
	if err == nil || err.Error() != "bootstrap_role_binding_invalid" || session != nil {
		t.Fatal("actual admission refusal changed")
	}
	select {
	case <-op.done:
	default:
		t.Fatal("actual denied bootstrap return not recorded")
	}
	if op.completedTime().IsZero() {
		t.Fatal("actual return receipt absent")
	}
	if _, err := op.resultContext(context.Background()); err == nil || err.Error() != "bootstrap_role_binding_invalid" {
		t.Fatal("actual core failure lost")
	}
	if out, err := f.owner.mapStartingContext(context.Background(), op); err == nil || out.ObservationID != "" {
		t.Fatal("actual denied core manufactured starting")
	}
}

func TestBootstrapOperationCoreDeadlineCannotWiden(t *testing.T) {
	op, f, _, _, _ := pendingOperationFixture(t)
	core, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := op.enter(core, f.config, f.profile, op.attemptID); err == nil || err.Error() != "bootstrap_operation_deadline_widened" {
		t.Fatal("core widened admitted startup budget")
	}
}

func TestBootstrapOperationInvalidCompletionRetainsOwnedSession(t *testing.T) {
	op, _, _, _, _ := pendingOperationFixture(t)
	session := &Session{startupAttemptID: op.attemptID}
	if op.complete(session, nil) == nil {
		t.Fatal("unadmitted success accepted")
	}
	got, err := op.resultContext(context.Background())
	if got != session || err == nil {
		t.Fatal("bookkeeping refusal discarded actual owned session")
	}
}

func TestBootstrapOperationConcurrentSafeFormatting(t *testing.T) {
	op, f, _, _, _ := pendingOperationFixture(t)
	if op.enter(op.startup, f.config, f.profile, op.attemptID) != nil {
		t.Fatal("component admission rejected")
	}
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for n := 0; n < 200; n++ {
				if text := fmt.Sprintf("%+v %#v", op, *op); text != "[private bootstrap operation] [private bootstrap operation]" {
					t.Error("private formatting changed")
				}
			}
		}()
	}
	close(start)
	if op.complete(&Session{startupAttemptID: op.attemptID}, nil) != nil {
		t.Fatal("actual return rejected")
	}
	workers.Wait()
}
