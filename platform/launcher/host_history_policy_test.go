//go:build linux || darwin

package launcher

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type historyPolicyFixture struct {
	host       *EnrolledHostPolicy
	invocation *EnsureInvocation
	store      *bootstrapHistoryStore
	operation  *bootstrapOperation
	lease      *BootstrapLock
	config     BootstrapConfig
	record     hostPolicyRecord
	selection  HostPolicySelection
}

// These real signed policy files and flock descriptors exercise the facade.
// Private operation transitions remain a component seam, not installed Run.
func newHistoryPolicyFixture(t *testing.T, runtimeBinary string) historyPolicyFixture {
	t.Helper()
	selection, record := installedBridgePolicyFixture(t)
	if runtimeBinary != "" {
		raw, err := os.ReadFile(runtimeBinary)
		if err != nil {
			t.Fatal("owned runtime fixture unavailable")
		}
		record.RuntimeExecutable = hostPolicyExecutable{Path: runtimeBinary, Digest: historyDigest(raw)}
		writeInstalledHostPolicy(t, selection.Path, record)
	}
	host, err := LoadEnrolledHostPolicy(selection)
	if err != nil {
		t.Fatal("installed policy fixture refused")
	}
	config, _, err := host.Load()
	if err != nil {
		t.Fatal("fresh policy admission refused")
	}
	server, _, err := host.BridgeServer()
	if err != nil {
		t.Fatal("actual owner bridge admission refused")
	}
	// Use the same admitted capabilities retained by the concrete server.
	config = server.config
	invocation, err := host.BeginEnsure()
	if err != nil {
		t.Fatal("actual ensure invocation unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	lease, err := AcquireBootstrapLock(ctx, config.ProfilePolicy.Directory, config.Kernel.Scope.InstanceID, "owner-status-service")
	if lease != nil {
		t.Cleanup(func() {
			if lease.Close() != nil {
				t.Error("owned service lease cleanup failed")
			}
		})
	}
	if err != nil {
		t.Fatal("actual service lease unavailable")
	}
	operation, err := newBootstrapOperation(ctx, ctx, server, lease, invocation.ID())
	if err != nil {
		t.Fatal("concrete operation admission refused")
	}
	binding, err := host.BootstrapReceiptBinding(invocation.ID())
	if err != nil {
		t.Fatal("actual receipt binding unavailable")
	}
	store, err := openBootstrapHistory(ctx, operation, binding)
	if store != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if !store.state.closed && store.Close(ctx) != nil {
				t.Error("owned history cleanup failed")
			}
		})
	}
	if err != nil {
		t.Fatal("actual history admission refused")
	}
	loaded, err := LoadProfile(config.ProfilePolicy)
	if err != nil {
		t.Fatal("actual enrolled profile unavailable")
	}
	if err := operation.enter(ctx, config, loaded.Declaration(), invocation.ID()); err != nil {
		t.Fatalf("actual entry: %v", err)
	}
	if err := store.Begin(ctx); err != nil {
		t.Fatalf("actual history begin: %v", err)
	}
	if err := operation.complete(nil, refusal("command_failed")); err != nil {
		t.Fatalf("actual completion: %v", err)
	}
	if err := store.RecordTerminal(ctx); err != nil {
		t.Fatalf("actual terminal record: %v", err)
	}
	return historyPolicyFixture{host, invocation, store, operation, lease, config, record, selection}
}

func TestHostHistoryPolicyRealLeaseAndPublicShape(t *testing.T) {
	f := newHistoryPolicyFixture(t, "")
	if result, err := f.host.PreviousBootstrapFailure(f.operation.startup); err != nil || result != nil {
		t.Fatal("general facade bypassed held service lease")
	}
	if f.store.Close(f.operation.startup) != nil || f.lease.Close() != nil {
		t.Fatal("actual lease release failed")
	}
	result, err := f.host.PreviousBootstrapFailure(f.operation.startup)
	if err != nil || result == nil || result.InvocationID != f.invocation.ID() || result.Meaning != "previous_recorded_terminal_failure" || result.RecordedCleanup != "unknown" || result.Diagnostic != requestDiagnostic("docker_command_failed") {
		t.Fatal("qualified past failure unavailable")
	}
	raw, err := json.Marshal(result)
	var keys map[string]json.RawMessage
	if err != nil || json.Unmarshal(raw, &keys) != nil || len(keys) != 7 {
		t.Fatal("history shape changed")
	}
	for _, name := range []string{"schemaVersion", "kind", "meaning", "invocationId", "completedAt", "diagnostic", "recordedCleanup"} {
		if keys[name] == nil {
			t.Fatal("required historical field missing")
		}
	}
	if bytes.Contains(raw, []byte(f.record.ProfileDirectory)) || bytes.Contains(raw, []byte(f.record.Owner.PrincipalID)) {
		t.Fatal("history exposed private binding")
	}
}

func TestHostHistoryPolicyFreshEnrollmentAndRuntimeRefusal(t *testing.T) {
	for _, kind := range []string{"owner", "runtime", "invalid_generation"} {
		t.Run(kind, func(t *testing.T) {
			f := newHistoryPolicyFixture(t, "")
			if f.store.Close(f.operation.startup) != nil || f.lease.Close() != nil {
				t.Fatal("actual lease release failed")
			}
			switch kind {
			case "owner":
				changed := f.record.Owner
				changed.Identity.Revision++
				writeOwnerFixture(t, f.record.ProfileDirectory, mustStatusJSON(changed))
			case "runtime":
				changed := f.record
				changed.RuntimeExecutable.Digest = "sha256:" + strings.Repeat("e", 64)
				writeInstalledHostPolicy(t, f.selection.Path, changed)
			case "invalid_generation":
				path := filepath.Join(f.record.ProfileDirectory, bootstrapHistoryName)
				raw, e := os.ReadFile(path)
				if e != nil {
					t.Fatal("owned history unavailable")
				}
				var record bootstrapHistoryRecord
				if json.Unmarshal(raw, &record) != nil {
					t.Fatal("owned history malformed")
				}
				record.Generation = "invalid_generation"
				if os.WriteFile(path, mustStatusJSON(record), 0600) != nil {
					t.Fatal("owned negative history write failed")
				}
			}
			if result, err := f.host.PreviousBootstrapFailure(f.operation.startup); err == nil || result != nil {
				t.Fatal("changed current admission exposed old history")
			}
		})
	}
}

func TestHostHistoryPolicyRefusesCanceledCallerAndSyntheticCreator(t *testing.T) {
	f := newHistoryPolicyFixture(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := f.host.PreviousBootstrapFailure(ctx); err == nil || result != nil {
		t.Fatal("canceled caller obtained history")
	}
	if result, err := f.invocation.CreatorPreviousBootstrapFailure(f.operation.startup, nil); err == nil || result != nil {
		t.Fatal("missing creator supplied receipt authority")
	}
	if result, err := f.host.PreviousBootstrapFailure(context.Background()); err == nil || result != nil {
		t.Fatal("unbounded caller admitted")
	}
	if result, err := f.host.PreviousBootstrapFailure(nil); err == nil || result != nil {
		t.Fatal("nil caller admitted")
	}
}
