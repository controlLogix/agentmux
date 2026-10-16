//go:build linux || darwin

package launcher

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestOwnerBridgeStartingBoundHasNoReadyFacts(t *testing.T) {
	op, f, _, _, _ := pendingOperationFixture(t)
	if op.enter(op.startup, f.config, f.profile, op.attemptID) != nil {
		t.Fatal("component entry rejected")
	}
	out, err := f.owner.mapStartingContext(context.Background(), op)
	outer := "attempt_" + strings.Repeat("b", 32)
	if err != nil || !bridgeObservationBound(out, f.enrollment, outer, time.Now()) {
		t.Fatal("otherwise-valid separate cold attempt rejected")
	}
	for _, secret := range []string{f.profile.ProfileDirectory, f.config.OwnerBridge.ClientPassword, f.config.OwnerBridge.ServerPassword} {
		if bytes.Contains(mustStatusJSON(out), []byte(secret)) {
			t.Fatal("starting output disclosed private data")
		}
	}
	for _, fault := range []string{"ready_instance", "running_version", "dashboard", "ready_service", "service_receipt", "service_revision", "duplicate_service", "persistence_available", "persistence_ready", "storage_known", "replicas_known", "work_zero", "known_empty_hubs", "attempt_nil", "scope"} {
		t.Run(fault, func(t *testing.T) {
			candidate := out
			candidate.Instance.Services = append([]StartupStatusService(nil), out.Instance.Services...)
			switch fault {
			case "ready_instance":
				candidate.Instance.Readiness = "ready"
			case "running_version":
				candidate.Instance.RunningVersion = statusString("1.2.3")
			case "dashboard":
				candidate.Instance.Dashboard = statusString("https://dashboard.example.invalid")
			case "ready_service":
				candidate.Instance.Services[0].Readiness = "ready"
			case "service_receipt":
				candidate.Instance.Services[0].ObservedAt = statusString(statusTimestamp(time.Now()))
			case "service_revision":
				candidate.Instance.Services[0].SourceRevision = statusRevision(1)
			case "duplicate_service":
				candidate.Instance.Services[1] = candidate.Instance.Services[0]
			case "persistence_available":
				candidate.Persistence.Availability = "available"
			case "persistence_ready":
				candidate.Persistence.Readiness = "ready"
			case "storage_known":
				candidate.Persistence.StoragePressure.PercentUsed = new(float64)
			case "replicas_known":
				candidate.Persistence.ReplicationHealth.Replicas = statusRevision(1)
			case "work_zero":
				candidate.Work.Active = statusRevision(0)
			case "known_empty_hubs":
				candidate.Hubs.InventoryState = "known"
			case "attempt_nil":
				candidate.StartupAttemptID = nil
			case "scope":
				candidate.Caller.Scope.OrganizationID = "another_org"
			}
			if bridgeObservationBound(candidate, f.enrollment, outer, time.Now()) {
				t.Fatal("starting exception admitted unsupported fact")
			}
		})
	}
	candidate := out
	candidate.Disposition = "reused"
	if bridgeObservationBound(candidate, f.enrollment, outer, time.Now()) {
		t.Fatal("different cold attempt escaped starting-only exception")
	}
}
