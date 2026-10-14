//go:build linux || darwin

package launcher

import (
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
)

// A completed cold-start write can establish current write readiness only for
// its own enrolled scope, selected endpoint and subsequently observed record.
// It does not establish capacity, replication or application readiness.
func qualifyWriteProof(policy OwnerPolicy, input ownerStatusObservation, out *StartupStatusObservation, now time.Time) bool {
	proof := input.healthProof
	if out == nil || proof == nil || input.status.Disposition != "started" || out.Persistence.Availability != "available" || proof.scope != policy.KernelScope || proof.endpoint != policy.PublicEndpoint {
		return false
	}
	if proof.completedAt.IsZero() || proof.completedAt.After(now) || now.Sub(proof.completedAt) > 5*time.Second || input.receivedAt.IsZero() || proof.completedAt.After(input.receivedAt) {
		return false
	}
	result, observed := proof.result, input.status.Persistence
	if !observed.BrokerVerified || observed.PersistenceEvidence != deployment.PersistenceRecordSeen || result.ServerName != policy.ServerName || result.ServerVersion != "2.15.0" || result.Domain != policy.Domain || result.Stream != deployment.HealthStream(policy.KernelScope.HubID) || result.Sequence == 0 || result.ServerName != observed.ServerName || result.ServerVersion != observed.ServerVersion || result.Domain != observed.Domain || result.Stream != observed.Stream || result.Sequence != observed.RecordSequence {
		return false
	}
	out.Persistence.Readiness = "ready"
	out.Persistence.ObservedAt = statusString(statusTimestamp(proof.completedAt))
	return true
}
