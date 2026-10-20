//go:build linux || darwin

package launcher

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

func TestSessionOwnerObservationRetainsProvenance(t *testing.T) {
	policy, profile := ownerStatusFixture(t)
	owner, err := LoadOwnerStatus(policy)
	if err != nil {
		t.Fatal("actual owner enrollment failed")
	}
	input := ownerObservationFixture(policy, profile, "reused")
	session := &Session{Status: input.status, startupAttemptID: input.attemptID, observedAt: input.receivedAt}
	first, err := session.OwnerObservation(owner)
	if err != nil || first.Disposition != "reused" || first.StartupAttemptID == nil || *first.StartupAttemptID != input.attemptID {
		t.Fatal("session lost its actual invocation or reuse disposition")
	}
	if first.Persistence.Readiness != "unknown" || first.Work.Active != nil || first.Hubs.InventoryState != "unavailable" {
		t.Fatal("read-only session invented write readiness or application state")
	}
	// A private value alone is not qualified write evidence. The adapter has no
	// write-ready branch until the actual probe binding is independently checked.
	session.healthProof = &completedHealthProbe{result: deployment.ProbeResult{Sequence: 1}, completedAt: time.Now()}
	second, err := session.OwnerObservation(owner)
	if err != nil || second.Persistence.Readiness != "unknown" {
		t.Fatal("unqualified private proof made persistence ready")
	}
	session.cleanupFailure = errors.New("private cleanup detail")
	failed, err := session.OwnerObservation(owner)
	if err != nil || failed.Disposition != "failed" || failed.Instance.Readiness != "not_ready" || failed.Errors[len(failed.Errors)-1].Code != "owned_cleanup_incomplete" {
		t.Fatal("known cleanup failure was hidden by a fresh cached frame")
	}
	session.cleanupFailure = nil
	session.observedAt = time.Now().Add(-time.Minute)
	stale, err := session.OwnerObservation(owner)
	if err != nil || stale.Disposition != "failed" || len(stale.Errors) == 0 || stale.Errors[0].Code != "observation_unavailable" {
		t.Fatal("session getter refreshed an old receipt time")
	}
}

func TestSessionOwnerObservationRequiresEnrolledHandle(t *testing.T) {
	if _, err := (*Session)(nil).OwnerObservation(nil); err == nil {
		t.Fatal("missing session or owner was accepted")
	}
	if _, err := (&Session{}).OwnerObservation(nil); err == nil {
		t.Fatal("missing owner handle was accepted")
	}
}

// These are projector inputs; installed lifecycle tests supply actual Group facts.
func TestOwnedProcessFailureKeepsVerifiedSurvivors(t *testing.T) {
	for _, condition := range []string{"single-exit", "whole-exit", "cleanup-only", "no-current-exit", "unverified-services"} {
		t.Run(condition, func(t *testing.T) {
			policy, profile := ownerStatusFixture(t)
			owner, err := LoadOwnerStatus(policy)
			if err != nil {
				t.Fatal("enrolled owner unavailable")
			}
			input := ownerObservationFixture(policy, profile, "reused")
			input.attemptID = "attempt_" + strings.Repeat("a", 32)
			if condition == "unverified-services" {
				input.status.Kernel = protocol.Snapshot{}
			}
			out, err := owner.mapObservation(input)
			if err != nil {
				t.Fatal("scoped observation unavailable")
			}
			before := append([]StartupStatusService(nil), out.Instance.Services...)
			facts := ownedProcessObservation{exitedRoles: []string{"internal-communication"}}
			switch condition {
			case "whole-exit":
				roles := protocol.Roles()
				facts.exitedRoles, facts.terminal = roles[:], true
			case "cleanup-only":
				facts = ownedProcessObservation{cleanupFailed: true}
			case "no-current-exit":
				facts = ownedProcessObservation{}
			}
			applyOwnedProcessObservation(&out, facts)
			if condition == "no-current-exit" {
				if out.Disposition != "reused" || !reflect.DeepEqual(out.Instance.Services, before) {
					t.Fatal("historical exit was inferred without a current owned failure")
				}
				return
			}
			if out.Disposition != "failed" || out.Instance.Readiness != "not_ready" || out.Persistence.Availability != "available" || out.Persistence.Readiness != "unknown" {
				t.Fatal("owned failure discarded verified persistence or retained success")
			}
			if condition == "whole-exit" && out.Instance.RunningVersion != nil {
				t.Fatal("completed group retained a current running version")
			}
			for _, service := range out.Instance.Services {
				exited := slices.Contains(facts.exitedRoles, service.ServiceID)
				if exited {
					if service.Availability != "unavailable" || service.Readiness != "unknown" || service.ObservedAt != nil || service.SourceRevision != nil || service.UnavailableReason == nil || *service.UnavailableReason != "probe_failed" {
						t.Fatal("exited role retained a current ready observation")
					}
					continue
				}
				found := false
				for _, original := range before {
					found = found || reflect.DeepEqual(original, service)
				}
				if !found {
					t.Fatal("owned exit changed an independently verified survivor")
				}
			}
			for _, role := range facts.exitedRoles {
				found := false
				for _, failure := range out.Errors {
					found = found || (failure.Code == "owned_role_exited" && failure.Message == "The owned protected role "+role+" has exited.")
				}
				if !found {
					t.Fatal("the exact failed role was not identified safely")
				}
			}
			if condition == "unverified-services" && (len(out.Instance.Services) != 1 || out.Instance.Services[0].ServiceID != "internal-communication") {
				t.Fatal("owned exit invented observations for unverified survivors")
			}
			if decodeBridgeReply(mustStatusJSON(ownerBridgeReply{protocol.Version, "host-owner-status-reply", "request_" + strings.Repeat("b", 32), input.attemptID, policy.KernelScope, bridgeTime(time.Now()), out}), &ownerBridgeReply{}) != nil {
				t.Fatal("owned failure projection broke the accepted L04 schema")
			}
		})
	}
}

func TestCurrentKernelRoleMaskPreservesOnlyVerifiedRows(t *testing.T) {
	for _, missing := range []bool{false, true} {
		policy, profile := ownerStatusFixture(t)
		owner, err := LoadOwnerStatus(policy)
		if err != nil {
			t.Fatal("enrolled owner unavailable")
		}
		out, err := owner.mapObservation(ownerObservationFixture(policy, profile, "reused"))
		if err != nil {
			t.Fatal("valid scoped observation unavailable")
		}
		verified := map[string]bool{"boot": true, "kernel-lifecycle": true, "exported-status": true}
		if missing {
			verified = nil
		}
		filterCurrentKernelRoles(&out, verified, false)
		if out.Disposition != "failed" || out.Instance.Readiness != "not_ready" || out.Persistence.Availability != "available" || out.Persistence.Readiness != "unknown" {
			t.Fatal("generation mismatch erased persistence or retained command success")
		}
		if (out.Instance.RunningVersion == nil) != missing {
			t.Fatal("running version was not bound to a verified current member")
		}
		for _, service := range out.Instance.Services {
			for _, role := range protocol.Roles() {
				if service.ServiceID != role {
					continue
				}
				if verified[role] {
					if service.Readiness != "ready" || service.ObservedAt == nil || service.SourceRevision == nil {
						t.Fatal("independently verified sibling observation was erased")
					}
				} else if service.Readiness != "unknown" || service.ObservedAt != nil || service.SourceRevision != nil {
					t.Fatal("prior-generation member retained a current observation")
				}
			}
		}
		applyOwnedProcessObservation(&out, ownedProcessObservation{exitedRoles: []string{"internal-communication"}})
		found := false
		for _, service := range out.Instance.Services {
			found = found || (service.ServiceID == "internal-communication" && service.Availability == "unavailable" && service.UnavailableReason != nil && *service.UnavailableReason == "probe_failed")
		}
		if !found {
			t.Fatal("known current role exit was hidden by generation filtering")
		}
	}
}
