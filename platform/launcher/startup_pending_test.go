//go:build linux || darwin

package launcher

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPendingStartingHonestL04AndIndependentAttempt(t *testing.T) {
	op, f, _, _, _ := pendingOperationFixture(t)
	if op.enter(op.startup, f.config, f.profile, op.attemptID) != nil {
		t.Fatal("matching component admission rejected")
	}
	out, err := f.owner.mapStartingContext(context.Background(), op)
	if err != nil || out.Disposition != "starting" || out.StartupAttemptID == nil || *out.StartupAttemptID != op.attemptID || out.Instance.Readiness != "not_ready" || out.Instance.RunningVersion != nil {
		t.Fatal("pending attempt or readiness invented")
	}
	if out.Persistence.Availability != "unavailable" || out.Persistence.Readiness != "unknown" || out.Persistence.Backend != nil || out.Persistence.ObservedAt != nil || out.Persistence.StoragePressure.PercentUsed != nil || out.Persistence.ReplicationHealth.Replicas != nil || out.Work.State != "unavailable" || out.Work.Active != nil || out.Work.ObservedAt != nil || out.Hubs.InventoryState != "unavailable" || len(out.Hubs.Entries) != 0 {
		t.Fatal("pending bootstrap invented persistence or business facts")
	}
	for _, service := range out.Instance.Services {
		if service.Availability != "unavailable" || service.Readiness != "unknown" || service.ObservedAt != nil || service.SourceRevision != nil {
			t.Fatal("pending bootstrap invented service facts")
		}
	}
	raw := mustStatusJSON(out)
	if validateOwnerBridgeJSON(raw, "startup-status-observation", ownerBridgeReplyLimit) != nil {
		t.Fatal("starting output violates accepted L04")
	}
	for _, secret := range []string{f.profile.ProfileDirectory, f.profile.Docker.Executable, f.profile.Docker.Endpoint, op.server.credential.Password} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("starting output disclosed private data")
		}
	}
	next, err := f.owner.mapStartingContext(context.Background(), op)
	if err != nil || next.SourceRevision != out.SourceRevision+1 || next.ObservationID == out.ObservationID || *next.StartupAttemptID != op.attemptID {
		t.Fatal("current receipt changed actual attempt or failed to advance")
	}
}

func TestPendingStartingCancellationAndLeaseDenials(t *testing.T) {
	for _, kind := range []string{"startup", "lifetime", "core", "lease", "caller"} {
		t.Run(kind, func(t *testing.T) {
			op, f, lease, cancelStartup, cancelLifetime := pendingOperationFixture(t)
			core, cancelCore := context.WithTimeout(op.startup, 20*time.Second)
			defer cancelCore()
			if op.enter(core, f.config, f.profile, op.attemptID) != nil {
				t.Fatal("component admission rejected")
			}
			ctx := context.Background()
			switch kind {
			case "startup":
				cancelStartup()
			case "lifetime":
				cancelLifetime()
			case "core":
				cancelCore()
			case "lease":
				if lease.Close() != nil {
					t.Fatal("actual lease close failed")
				}
			case "caller":
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}
			if out, err := f.owner.mapStartingContext(ctx, op); err == nil || out.ObservationID != "" {
				t.Fatal("invalid pending ownership produced output")
			}
		})
	}
}

func TestPendingStartingEnrollmentAndProfileRevalidation(t *testing.T) {
	for _, kind := range []string{"owner_revision", "owner_scope", "profile"} {
		t.Run(kind, func(t *testing.T) {
			op, f, _, _, _ := pendingOperationFixture(t)
			if op.enter(op.startup, f.config, f.profile, op.attemptID) != nil {
				t.Fatal("component admission rejected")
			}
			if kind == "profile" {
				p := f.profile
				p.DisplayName = "changed profile"
				if os.WriteFile(filepath.Join(p.ProfileDirectory, "profile.json"), mustStatusJSON(p), 0600) != nil {
					t.Fatal("profile change control failed")
				}
			} else {
				e := f.enrollment.Owner
				if kind == "owner_revision" {
					e.Identity.Revision++
				} else {
					e.Scope.OrganizationID = "another_org"
				}
				writeOwnerFixture(t, f.profile.ProfileDirectory, mustStatusJSON(e))
			}
			if out, err := f.owner.mapStartingContext(context.Background(), op); err == nil || out.ObservationID != "" {
				t.Fatal("changed enrollment manufactured pending")
			}
		})
	}
}

func TestPendingStartingHeldLeaseAndDeadline(t *testing.T) {
	op, f, _, _, _ := pendingOperationFixture(t)
	if op.enter(op.startup, f.config, f.profile, op.attemptID) != nil {
		t.Fatal("component admission rejected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	contender, err := AcquireBootstrapLock(ctx, f.profile.ProfileDirectory, f.profile.InstanceID, "owner-status-service")
	if contender != nil {
		contender.Close()
		t.Fatal("pending operation did not retain real service lease")
	}
	if err == nil {
		t.Fatal("lease contender incorrectly admitted")
	}
	f.owner.mu.Lock()
	defer f.owner.mu.Unlock()
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if out, err := f.owner.mapStartingContext(ctx, op); err == nil || err.Error() != "owner_status_deadline" || out.ObservationID != "" {
		t.Fatal("pending owner lock ignored caller deadline")
	}
	if out, err := f.owner.mapStartingContext(nil, op); err == nil || out.ObservationID != "" {
		t.Fatal("nil context admitted")
	}
}
