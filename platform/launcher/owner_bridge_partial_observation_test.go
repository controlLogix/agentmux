//go:build linux || darwin

package launcher

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/nats-io/nats.go"
)

func TestOwnerBridgeFailedRefreshPreservesVerifiedServiceObservations(t *testing.T) {
	for _, scenario := range []string{"kernel-degraded", "kernel-not-ready", "persistence-absent"} {
		t.Run(scenario, func(t *testing.T) {
			f := newBridgeFixture(t)
			f.startBroker(t)
			f.controlledDocker(t)
			if scenario != "persistence-absent" {
				if _, err := deployment.ProvisionAndProbe(context.Background(), f.config.Health); err != nil {
					t.Fatal("real FILE probe failed")
				}
			}
			publisher, err := f.rawTLSClient(t, "exported-status", nats.UserInfo("exported-status", f.users["exported-status"]))
			if err != nil {
				t.Fatal("scoped TLS status publisher unavailable")
			}
			wire, _ := communication.Subjects(f.config.Kernel.Scope.HubID)
			frame := ownerObservationFixture(f.policy, f.profile, "reused").status.Kernel
			wantService := "ready"
			if scenario == "kernel-degraded" {
				frame.KernelReadiness, wantService = "degraded", "degraded"
			} else if scenario == "kernel-not-ready" {
				frame.KernelReadiness, wantService = "not_ready", "unknown"
			}
			for i := range frame.Members {
				if frame.Members[i].Role == "internal-communication" {
					frame.Members[i].State = wantService
					if wantService == "unknown" {
						frame.Members[i] = protocol.Member{Role: "internal-communication", State: "unknown"}
					}
				}
			}
			// The actual TLS broker transports scoped non-ready frames. This
			// checks projection, not an installed process-failure qualification.
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				ticker := time.NewTicker(20 * time.Millisecond)
				defer ticker.Stop()
				for {
					select {
					case <-ctx.Done():
						done <- nil
						return
					case now := <-ticker.C:
						frame.ObservedAt = now.UTC().Format(time.RFC3339Nano)
						frame.ValidUntil = now.Add(3 * time.Second).UTC().Format(time.RFC3339Nano)
						for i := range frame.Members {
							if frame.Members[i].State != "unknown" {
								frame.Members[i].ObservedAt = frame.ObservedAt
							}
						}
						if err := publisher.Publish(wire.Snapshot, mustStatusJSON(frame)); err != nil {
							done <- err
							return
						}
					}
				}
			}()
			t.Cleanup(func() {
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Error("owned status publisher failed")
					}
				case <-time.After(time.Second):
					t.Error("owned status publisher did not join")
				}
			})
			server, err := LoadOwnerBridgeServer(f.config, f.owner, f.enrollment)
			if err != nil {
				t.Fatal("enrolled server admission failed")
			}
			request, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			invocation := "attempt_" + strings.Repeat("a", 32)
			out, err := server.refresh(request, invocation, nil, nil)
			if err != nil || out.Disposition != "failed" || out.Instance.Readiness != "not_ready" || out.Instance.RunningVersion == nil {
				t.Fatal("non-ready observations were discarded or admitted as reuse")
			}
			found := false
			for _, service := range out.Instance.Services {
				if service.ServiceID == "internal-communication" {
					found = service.Readiness == wantService
				}
			}
			if !found || len(out.Instance.Services) != 6 {
				t.Fatal("failed refresh lost the observed protected service state")
			}
			wantPersistence := "available"
			if scenario == "persistence-absent" {
				wantPersistence = "unavailable"
			}
			if out.Persistence.Availability != wantPersistence || out.Persistence.Readiness == "ready" || !bridgeObservationBound(out, f.enrollment, invocation, time.Now()) {
				t.Fatal("failed refresh lost scoped persistence facts or invented readiness")
			}
			if decodeBridgeReply(mustStatusJSON(ownerBridgeReply{protocol.Version, "host-owner-status-reply", "request_" + strings.Repeat("b", 32), invocation, f.config.Kernel.Scope, bridgeTime(time.Now()), out}), &ownerBridgeReply{}) != nil {
				t.Fatal("partial failed observation broke the accepted status schema")
			}
		})
	}
}

func TestOwnerStatusKeepsPersistenceWhenKernelIsUnavailable(t *testing.T) {
	for _, condition := range []string{"kernel-unavailable", "receipt-stale", "profile-mismatch", "persistence-mismatch"} {
		t.Run(condition, func(t *testing.T) {
			policy, profile := ownerStatusFixture(t)
			owner, err := LoadOwnerStatus(policy)
			if err != nil {
				t.Fatal("enrolled owner unavailable")
			}
			input := ownerObservationFixture(policy, profile, "failed")
			input.status.Kernel = protocol.Snapshot{}
			switch condition {
			case "receipt-stale":
				input.receivedAt = time.Now().Add(-4 * time.Second)
			case "profile-mismatch":
				input.status.Profile.InstanceID = "other_instance"
			case "persistence-mismatch":
				input.status.Persistence.Domain = "other_domain"
			}
			out, err := owner.mapObservation(input)
			if err != nil || out.Disposition != "failed" || out.Instance.RunningVersion != nil || out.Instance.Readiness == "ready" || out.Persistence.Readiness != "unknown" {
				t.Fatal("unavailable kernel became a current runtime or write claim")
			}
			want := "unavailable"
			if condition == "kernel-unavailable" {
				want = "available"
			}
			if out.Persistence.Availability != want {
				t.Fatal("independent persistence lost its receipt, profile or identity checks")
			}
		})
	}
}
