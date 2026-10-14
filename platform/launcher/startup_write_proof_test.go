//go:build linux || darwin

package launcher

import (
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
)

func TestColdWriteProofBindingAndAge(t *testing.T) {
	policy, profile := ownerStatusFixture(t)
	now := time.Now().UTC()
	valid := func() ownerStatusObservation {
		input := ownerObservationFixture(policy, profile, "started")
		input.receivedAt = now
		input.healthProof = &completedHealthProbe{scope: policy.KernelScope, endpoint: policy.PublicEndpoint, completedAt: now.Add(-time.Millisecond), result: deployment.ProbeResult{ServerName: policy.ServerName, ServerVersion: "2.15.0", Domain: policy.Domain, Stream: deployment.HealthStream(policy.KernelScope.HubID), Sequence: input.status.Persistence.RecordSequence}}
		return input
	}
	cases := []struct {
		name   string
		change func(*ownerStatusObservation)
	}{
		{"warm", func(i *ownerStatusObservation) { i.status.Disposition = "reused" }},
		{"absent", func(i *ownerStatusObservation) { i.healthProof = nil }},
		{"scope", func(i *ownerStatusObservation) { i.healthProof.scope.HubID = "other_hub" }},
		{"endpoint", func(i *ownerStatusObservation) { i.healthProof.endpoint = "nats://127.0.0.1:9999" }},
		{"future", func(i *ownerStatusObservation) { i.healthProof.completedAt = now.Add(time.Second) }},
		{"stale", func(i *ownerStatusObservation) { i.healthProof.completedAt = now.Add(-6 * time.Second) }},
		{"zero-time", func(i *ownerStatusObservation) { i.healthProof.completedAt = time.Time{} }},
		{"after-receipt", func(i *ownerStatusObservation) { i.receivedAt = now.Add(-time.Second) }},
		{"server", func(i *ownerStatusObservation) { i.healthProof.result.ServerName = "other_server" }},
		{"version", func(i *ownerStatusObservation) { i.healthProof.result.ServerVersion = "2.14.0" }},
		{"domain", func(i *ownerStatusObservation) { i.healthProof.result.Domain = "other_domain" }},
		{"stream", func(i *ownerStatusObservation) { i.healthProof.result.Stream = "other_stream" }},
		{"zero-sequence", func(i *ownerStatusObservation) { i.healthProof.result.Sequence = 0 }},
		{"different-record", func(i *ownerStatusObservation) { i.status.Persistence.RecordSequence++ }},
		{"unverified", func(i *ownerStatusObservation) { i.status.Persistence.BrokerVerified = false }},
		{"configuration-only", func(i *ownerStatusObservation) {
			i.status.Persistence.PersistenceEvidence = deployment.PersistenceConfigSeen
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := valid()
			tc.change(&input)
			out := StartupStatusObservation{Persistence: StartupStatusPersistence{Availability: "available", Readiness: "unknown"}}
			if qualifyWriteProof(policy, input, &out, now) || out.Persistence.Readiness != "unknown" || out.Persistence.ObservedAt != nil {
				t.Fatal("unbound or old proof became current write readiness")
			}
		})
	}
	input := valid()
	out := StartupStatusObservation{Persistence: StartupStatusPersistence{Availability: "available", Readiness: "unknown", StoragePressure: StartupStoragePressure{State: "unknown"}, ReplicationHealth: StartupReplicationHealth{State: "unknown"}}}
	if !qualifyWriteProof(policy, input, &out, now) || out.Persistence.Readiness != "ready" || out.Persistence.ObservedAt == nil || *out.Persistence.ObservedAt != statusTimestamp(input.healthProof.completedAt) || out.Persistence.StoragePressure.State != "unknown" || out.Persistence.ReplicationHealth.State != "unknown" {
		t.Fatal("bound current proof failed or invented wider health")
	}
	out.Persistence.Availability = "unavailable"
	if qualifyWriteProof(policy, input, &out, now) || qualifyWriteProof(policy, input, nil, now) {
		t.Fatal("proof bypassed existing persistence validation")
	}
}

func TestColdWriteProofOwnerStatusKeepsBusinessUnavailable(t *testing.T) {
	policy, profile := ownerStatusFixture(t)
	owner, err := LoadOwnerStatus(policy)
	if err != nil {
		t.Fatal(err)
	}
	input := ownerObservationFixture(policy, profile, "started")
	input.healthProof = &completedHealthProbe{scope: policy.KernelScope, endpoint: policy.PublicEndpoint, completedAt: input.receivedAt.Add(-time.Millisecond), result: deployment.ProbeResult{ServerName: policy.ServerName, ServerVersion: "2.15.0", Domain: policy.Domain, Stream: input.status.Persistence.Stream, Sequence: input.status.Persistence.RecordSequence}}
	out, err := owner.mapObservation(input)
	if err != nil || out.Persistence.Readiness != "ready" || out.Instance.Readiness != "degraded" || out.Work.State != "unavailable" || out.Hubs.InventoryState != "unavailable" || len(out.Errors) != 0 {
		t.Fatal("cold write proof changed unsupported service claims")
	}
}
