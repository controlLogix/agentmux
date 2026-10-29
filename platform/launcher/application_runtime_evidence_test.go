//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

func applicationEvidenceTestStates() []protected.ProcessStatus {
	states := make([]protected.ProcessStatus, 0, 4)
	for index, role := range protocol.Roles() {
		states = append(states, protected.ProcessStatus{Role: role, PID: 100 + index, Generation: 1})
	}
	return states
}

func TestApplicationEvidenceGenerationVectorRejectsMissingExitedAndDuplicateMembers(t *testing.T) {
	states := applicationEvidenceTestStates()
	first, err := applicationGenerationVector(states)
	if err != nil {
		t.Fatal(err)
	}
	states[0], states[3] = states[3], states[0]
	reordered, err := applicationGenerationVector(states)
	if err != nil || reordered != first {
		t.Fatal("member order changed generation identity")
	}
	for _, kind := range []string{"missing", "duplicate", "exited", "zero-generation", "overflow", "invalid-pid"} {
		t.Run(kind, func(t *testing.T) {
			changed := applicationEvidenceTestStates()
			switch kind {
			case "missing":
				changed = changed[:3]
			case "duplicate":
				changed[1].Role = changed[0].Role
			case "exited":
				changed[0].Exited = true
			case "zero-generation":
				changed[0].Generation = 0
			case "overflow":
				changed[0].Generation = applicationMaxGeneration + 1
			case "invalid-pid":
				changed[0].PID = 0
			}
			if _, err := applicationGenerationVector(changed); err == nil {
				t.Fatal("invalid generation admitted")
			}
		})
	}
	states = applicationEvidenceTestStates()
	states[0].Generation++
	replacement, err := applicationGenerationVector(states)
	if err != nil || replacement == first {
		t.Fatal("recovery did not change generation identity")
	}
}

func TestApplicationEvidenceRequiresRealOwnerAndCannotSerializeUnsignedAuthority(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		ctx        context.Context
		operation  *bootstrapOperation
		generation uint64
	}{
		{nil, nil, 1}, {context.Background(), nil, 1}, {ctx, nil, 1},
		{context.Background(), &bootstrapOperation{lifetime: context.Background()}, 0},
		{context.Background(), &bootstrapOperation{lifetime: context.Background()}, applicationMaxGeneration + 1},
	} {
		if _, err := newApplicationRuntimeProducer(tc.ctx, tc.operation, tc.generation); err == nil {
			t.Fatal("unowned producer admitted")
		}
	}
	var evidence *ApplicationRuntimeEvidence
	if evidence.Recheck(context.Background()) == nil {
		t.Fatal("nil evidence admitted")
	}
	evidence = &ApplicationRuntimeEvidence{lifetimeID: strings.Repeat("a", 64)}
	if _, _, _, _, _, err := evidence.Facts(context.Background()); err == nil {
		t.Fatal("constructed fields granted evidence")
	}
	if _, err := json.Marshal(evidence); err == nil {
		t.Fatal("unsigned evidence serialized as authority")
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, evidence), evidence.lifetimeID) {
			t.Fatal("private evidence exposed")
		}
	}
}

// Evidence lives applicationEvidenceValidity from the snapshot's observation, never
// longer, and only a snapshot within the kernel's 3 s freshness limit is admitted.
func TestApplicationEvidenceValidityRunsFromSnapshotObservation(t *testing.T) {
	scope := protocol.Scope{HubID: "fixture_hub", InstanceID: "fixture_instance", ProfileID: "fixture_profile", AssemblyDigest: "sha256:" + strings.Repeat("a", 64), ReleaseManifestDigest: "sha256:" + strings.Repeat("b", 64), ReleaseVersion: "1.0.0"}
	now := time.Now().UTC()
	snapshot := observerFrame(kernelObserverFixture{options: KernelStatusOptions{Scope: scope}})
	snapshot.ObservedAt = now.Add(-2 * time.Second).Format(time.RFC3339Nano)
	snapshot.ValidUntil = now.Add(time.Second).Format(time.RFC3339Nano)
	snapshot.KernelReadiness = "ready"
	for i := range snapshot.Members {
		snapshot.Members[i].State = "ready"
		snapshot.Members[i].Incarnation = snapshot.Incarnation
		snapshot.Members[i].Revision = 1
		snapshot.Members[i].ObservedAt = snapshot.ObservedAt
	}
	expiry, err := applicationSnapshotExpiry(snapshot, scope, now)
	observed, _ := time.Parse(time.RFC3339Nano, snapshot.ObservedAt)
	if err != nil || !expiry.Equal(observed.Add(applicationEvidenceValidity)) {
		t.Fatal("evidence validity changed", expiry, err)
	}
	for _, kind := range []string{"stale", "future", "wrong-scope", "not-ready"} {
		t.Run(kind, func(t *testing.T) {
			changed := snapshot
			switch kind {
			case "stale":
				changed.ValidUntil = now.Add(-time.Second).Format(time.RFC3339Nano)
			case "future":
				changed.ObservedAt = now.Add(time.Second).Format(time.RFC3339Nano)
			case "wrong-scope":
				changed.Scope.InstanceID = "other_instance"
			case "not-ready":
				changed.KernelReadiness = "not_ready"
			}
			if _, err := applicationSnapshotExpiry(changed, scope, now); err == nil {
				t.Fatal("invalid kernel evidence admitted")
			}
		})
	}
	a, err := applicationLifetimeID()
	if err != nil || len(a) != 64 {
		t.Fatal("lifetime identifier unavailable")
	}
	b, err := applicationLifetimeID()
	if err != nil || a == b {
		t.Fatal("lifetime identifier reused")
	}
}
