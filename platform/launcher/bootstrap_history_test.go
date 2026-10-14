//go:build linux || darwin

package launcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	protected "github.com/controlLogix/agentmux/platform/runtime"
)

// Real private enrollment, files and acquired flock are used. Direct operation
// enter/complete are component seams, not a claim of real Bootstrap execution,
// installed producer provenance, Docker or supported-host qualification.
func historyFixture(t *testing.T) (*bootstrapHistoryStore, *bootstrapOperation, bridgeFixture, *BootstrapLock, protected.BootstrapReceiptBinding) {
	t.Helper()
	op, f, lease, _, _ := pendingOperationFixture(t)
	binding := protected.BootstrapReceiptBinding{Scope: op.scope, EnrollmentDigest: historyDigest(mustStatusJSON(f.enrollment.Owner)), ColdInvocationID: op.attemptID, RuntimeDigest: "sha256:" + strings.Repeat("d", 64)}
	store, err := openBootstrapHistory(op.startup, op, binding)
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
		t.Fatal("history fixture admission rejected")
	}
	return store, op, f, lease, binding
}
func enterHistoryFixture(t *testing.T, store *bootstrapHistoryStore, op *bootstrapOperation, f bridgeFixture) {
	t.Helper()
	if op.enter(op.startup, f.config, f.profile, op.attemptID) != nil || store.Begin(op.startup) != nil {
		t.Fatal("actual private component transition rejected")
	}
}
func completeHistoryFailure(t *testing.T, store *bootstrapHistoryStore, op *bootstrapOperation) {
	t.Helper()
	if op.complete(nil, refusal("command_failed")) != nil || store.RecordTerminal(op.startup) != nil {
		t.Fatal("actual component completion rejected")
	}
}

func TestBootstrapHistoryOwnDuplicateRetainsActualFlock(t *testing.T) {
	store, op, f, lease, _ := historyFixture(t)
	if lease.Close() != nil {
		t.Fatal("original lease close failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	contender, err := AcquireBootstrapLock(ctx, f.profile.ProfileDirectory, f.profile.InstanceID, "owner-status-service")
	cancel()
	if contender != nil {
		contender.Close()
		t.Fatal("closing original released duplicate-held flock")
	}
	if err == nil {
		t.Fatal("no actual contention observed")
	}
	if store.Close(op.startup) != nil {
		t.Fatal("owned duplicate close failed")
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	next, err := AcquireBootstrapLock(ctx, f.profile.ProfileDirectory, f.profile.InstanceID, "owner-status-service")
	if err != nil {
		t.Fatal("flock not released after all own copies closed")
	}
	if next.Close() != nil {
		t.Fatal("contender cleanup failed")
	}
}

func TestBootstrapHistoryMarkerFailureAndFreeLeaseDisplay(t *testing.T) {
	store, op, f, lease, binding := historyFixture(t)
	if store.Begin(op.startup) == nil {
		t.Fatal("constructor manufactured an admitted marker")
	}
	enterHistoryFixture(t, store, op, f)
	marker, _, err := readHistoryFile(op.startup, store.root, store.binding.OwnerUID)
	if err != nil {
		t.Fatal("marker read failed")
	}
	record, err := decodeBootstrapHistory(marker, time.Now().UTC())
	if err != nil || record.LatestAttempt.Terminal != nil || record.LatestAttempt.InvocationID != op.attemptID {
		t.Fatal("neutral marker acquired terminal facts")
	}
	completeHistoryFailure(t, store, op)
	if result, err := readBootstrapHistory(op.startup, f.owner, binding.RuntimeDigest); err != nil || result != nil {
		t.Fatal("held lease exposed history to general reader")
	}
	if store.Close(op.startup) != nil || lease.Close() != nil {
		t.Fatal("actual lease cleanup failed")
	}
	result, err := readBootstrapHistory(op.startup, f.owner, binding.RuntimeDigest)
	if err != nil || result == nil || result.InvocationID != op.attemptID || result.DiagnosticCode != "docker_command_failed" || result.Cleanup != "unknown" {
		t.Fatal("qualified terminal history not available after real lease release")
	}
}

func TestBootstrapHistoryCASPreservesForeignGeneration(t *testing.T) {
	store, op, f, _, _ := historyFixture(t)
	enterHistoryFixture(t, store, op, f)
	path := filepath.Join(f.profile.ProfileDirectory, bootstrapHistoryName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("fixture read/decode failed")
	}
	record, err := decodeBootstrapHistory(raw, time.Now().UTC())
	if err != nil {
		t.Fatal("fixture read/decode failed")
	}
	record.Generation = "history_" + strings.Repeat("e", 32)
	mutated := mustStatusJSON(record)
	if os.WriteFile(path, mutated, 0600) != nil {
		t.Fatal("private mutation failed")
	}
	if op.complete(nil, refusal("command_failed")) != nil {
		t.Fatal("component completion failed")
	}
	if store.RecordTerminal(op.startup) == nil {
		t.Fatal("foreign generation overwritten")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, mutated) {
		t.Fatal("conflicting history was changed")
	}
}

func TestBootstrapHistoryMalformedSourceRetainedAndNoResultInvented(t *testing.T) {
	store, op, f, _, binding := historyFixture(t)
	path := filepath.Join(f.profile.ProfileDirectory, bootstrapHistoryName)
	raw := []byte(`{"kind":"unknown"}`)
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("malformed private fixture write failed")
	}
	if op.enter(op.startup, f.config, f.profile, op.attemptID) != nil {
		t.Fatal("component admission failed")
	}
	if store.Begin(op.startup) == nil {
		t.Fatal("malformed state overwritten")
	}
	second, err := openBootstrapHistory(op.startup, op, binding)
	if second != nil {
		defer second.Close(op.startup)
	}
	if err == nil {
		t.Fatal("malformed state loaded as known history")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(raw, after) {
		t.Fatal("unknown state changed")
	}
	// The component error is not an authority to cancel the actual operation.
	if op.complete(&Session{startupAttemptID: op.attemptID}, nil) != nil {
		t.Fatal("history failure vetoed genuine component result")
	}
}

func TestBootstrapHistoryNewerAttemptAndSuccessSuppressOldFailure(t *testing.T) {
	first, op, f, lease, binding := historyFixture(t)
	enterHistoryFixture(t, first, op, f)
	completeHistoryFailure(t, first, op)
	prior := first.state.expected.Generation
	if first.Close(op.startup) != nil {
		t.Fatal("first store close failed")
	}
	newer, err := newBootstrapOperation(op.startup, op.lifetime, op.server, lease, "attempt_"+strings.Repeat("b", 32))
	if err != nil {
		t.Fatal("new real-lease component operation rejected")
	}
	binding.ColdInvocationID = newer.attemptID
	store, err := openBootstrapHistory(op.startup, newer, binding)
	if store != nil {
		defer store.Close(op.startup)
	}
	if err != nil {
		t.Fatal("valid old nonterminal/terminal slot deadlocked new operation")
	}
	if newer.enter(newer.startup, f.config, f.profile, newer.attemptID) != nil || store.Begin(newer.startup) != nil {
		t.Fatal("new marker refused")
	}
	if store.state.expected.Generation == prior || store.state.expected.PreviousGeneration == nil || *store.state.expected.PreviousGeneration != prior || historyRelevantFailure(*store.state.expected, time.Now().UTC()) != nil {
		t.Fatal("new neutral marker exposed old failure")
	}
	if newer.complete(&Session{startupAttemptID: newer.attemptID}, nil) != nil || store.RecordTerminal(newer.startup) != nil {
		t.Fatal("actual successful component result not recorded")
	}
	if store.state.expected.PreviousFailure != nil || historyRelevantFailure(*store.state.expected, time.Now().UTC()) != nil {
		t.Fatal("success failed to supersede old failure")
	}
}

func TestBootstrapHistoryStrictSchemaAndAge(t *testing.T) {
	store, op, f, _, _ := historyFixture(t)
	enterHistoryFixture(t, store, op, f)
	completeHistoryFailure(t, store, op)
	raw := mustStatusJSON(store.state.expected)
	if _, err := decodeBootstrapHistory(raw, time.Now().UTC()); err != nil {
		t.Fatal("positive schema control failed")
	}
	for _, name := range []string{"missing-null", "alias", "duplicate", "unknown", "future", "calendar", "conditional", "cleanup", "generation", "oversize"} {
		t.Run(name, func(t *testing.T) {
			var fields map[string]any
			if json.Unmarshal(raw, &fields) != nil {
				t.Fatal("fixture decode failed")
			}
			switch name {
			case "missing-null":
				delete(fields, "previousFailure")
			case "alias":
				fields["Kind"] = fields["kind"]
			case "unknown":
				fields["currentReadiness"] = "ready"
			case "future":
				fields["writtenAt"] = historyTimestamp(time.Now().Add(time.Hour))
			case "calendar":
				fields["writtenAt"] = "2026-02-31T00:00:00Z"
			case "conditional":
				fields["latestAttempt"].(map[string]any)["terminal"].(map[string]any)["diagnosticCode"] = nil
			case "cleanup":
				fields["latestAttempt"].(map[string]any)["terminal"].(map[string]any)["cleanup"] = "cleaned"
			case "generation":
				fields["previousGeneration"] = fields["generation"]
			case "oversize":
				fields["padding"] = strings.Repeat("x", bootstrapHistoryLimit)
			}
			candidate, _ := json.Marshal(fields)
			if name == "duplicate" {
				candidate = append([]byte(`{"kind":"bootstrap-operation-history",`), candidate[1:]...)
			}
			if _, err := decodeBootstrapHistory(candidate, time.Now().UTC()); err == nil {
				t.Fatal("invalid history admitted")
			}
		})
	}
	record := *store.state.expected
	completed, _ := time.Parse(time.RFC3339Nano, record.LatestAttempt.Terminal.CompletedAt)
	if historyRelevantFailure(record, completed.Add(bootstrapHistoryRelevance)) == nil || historyRelevantFailure(record, completed.Add(bootstrapHistoryRelevance+time.Microsecond)) != nil {
		t.Fatal("historical age boundary wrong")
	}
}

func TestBootstrapHistoryUnsafeFilesAndEnrollmentChange(t *testing.T) {
	for _, name := range []string{"symlink", "hardlink", "mode", "new-owner"} {
		t.Run(name, func(t *testing.T) {
			store, op, f, _, binding := historyFixture(t)
			enterHistoryFixture(t, store, op, f)
			completeHistoryFailure(t, store, op)
			path := filepath.Join(f.profile.ProfileDirectory, bootstrapHistoryName)
			switch name {
			case "symlink":
				target := path + ".owned"
				if os.Rename(path, target) != nil || os.Symlink(target, path) != nil {
					t.Fatal("link setup failed")
				}
			case "hardlink":
				if os.Link(path, path+".owned") != nil {
					t.Fatal("hardlink setup failed")
				}
			case "mode":
				if os.Chmod(path, 0644) != nil {
					t.Fatal("mode setup failed")
				}
			case "new-owner":
				changed := f.enrollment.Owner
				changed.Identity.Revision++
				writeOwnerFixture(t, f.profile.ProfileDirectory, mustStatusJSON(changed))
			}
			next, err := openBootstrapHistory(op.startup, op, binding)
			if next != nil {
				defer next.Close(op.startup)
			}
			if err == nil {
				t.Fatal("unsafe or newly bound source accepted")
			}
		})
	}
}

func TestBootstrapHistoryPublicationFailureRetainsActualCause(t *testing.T) {
	store, op, f, _, _ := historyFixture(t)
	if op.enter(op.startup, f.config, f.profile, op.attemptID) != nil {
		t.Fatal("component admission failed")
	}
	// An actual closed owned root prevents publication, without a generic injected
	// closer or fake committed result. The operation's exact cleanup cause stays.
	if store.root.Close() != nil {
		t.Fatal("owned root close failed")
	}
	if store.Begin(op.startup) == nil {
		t.Fatal("closed root fabricated publication")
	}
	owned := &TransportCleanupError{cause: errors.New("private-fixture-secret")}
	if op.complete(nil, owned) != nil {
		t.Fatal("actual completion not retained")
	}
	if store.RecordTerminal(op.startup) == nil {
		t.Fatal("closed root fabricated terminal publication")
	}
	_, cause := op.resultContext(op.startup)
	var actual *TransportCleanupError
	if !errors.As(cause, &actual) || actual != owned {
		t.Fatal("publication error discarded original owner")
	}
	// os.Root.Close is idempotent. Closing our actual duplicate descriptor first
	// creates a real Close error, without an injected closer or numeric-FD retry.
	if store.leaseFile.Close() != nil {
		t.Fatal("duplicate pre-close failed")
	}
	if store.Close(op.startup) == nil {
		t.Fatal("owned close failure was hidden")
	}
	// Cleanup already happened; the fixture must not report the deliberate error
	// as an unexpected second failure on its own repeated Close.
	if store.Close(op.startup) == nil {
		t.Fatal("historical close error was erased on repeat")
	}
}

func TestBootstrapHistoryErrorPrivacyAndDeadline(t *testing.T) {
	value := bootstrapHistoryError{code: "publication_failed", cause: errors.New("private /fixture/path password")}
	for _, e := range []any{value, &value} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, e), "private") {
				t.Fatal("private cause exposed")
			}
		}
		raw, _ := json.Marshal(e)
		if strings.Contains(string(raw), "private") {
			t.Fatal("private cause serialized")
		}
	}
	store, op, _, _, _ := historyFixture(t)
	store.state.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := store.Begin(ctx)
	store.state.mu.Unlock()
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("held history gate ignored deadline")
	}
	if store.Begin(context.Background()) == nil {
		t.Fatal("unbounded artifact context admitted")
	}
	if _, _, _, err := historyCompletion(op.startup, op); err == nil {
		t.Fatal("unfinished operation became completion")
	}
}

func TestBootstrapHistoryRepeatedCompletionChecksCurrentGeneration(t *testing.T) {
	store, op, f, _, _ := historyFixture(t)
	enterHistoryFixture(t, store, op, f)
	completeHistoryFailure(t, store, op)
	path := filepath.Join(f.profile.ProfileDirectory, bootstrapHistoryName)
	changed := *store.state.expected
	changed.Generation = "history_" + strings.Repeat("f", 32)
	raw := mustStatusJSON(changed)
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("generation replacement failed")
	}
	if store.RecordTerminal(op.startup) == nil {
		t.Fatal("repeat completion accepted replaced generation")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, raw) {
		t.Fatal("repeat completion changed foreign generation")
	}
}

func TestBootstrapHistoryNewAdmissionReplacesNonterminalOnlyUnderActualLease(t *testing.T) {
	store, op, f, lease, binding := historyFixture(t)
	enterHistoryFixture(t, store, op, f)
	previous := store.state.expected.Generation
	if op.complete(nil, refusal("command_failed")) != nil {
		t.Fatal("old operation completion failed")
	}
	// No terminal publication occurred; a new genuine lease-owning operation may
	// advance the neutral slot. Its marker is not inferred from age or metadata.
	if store.Close(op.startup) != nil {
		t.Fatal("old store cleanup failed")
	}
	newer, err := newBootstrapOperation(op.startup, op.lifetime, op.server, lease, "attempt_"+strings.Repeat("c", 32))
	if err != nil {
		t.Fatal("new actual-lease operation rejected")
	}
	binding.ColdInvocationID = newer.attemptID
	next, err := openBootstrapHistory(newer.startup, newer, binding)
	if next != nil {
		t.Cleanup(func() {
			if next.Close(newer.startup) != nil {
				t.Error("new store cleanup failed")
			}
		})
	}
	if err != nil || newer.enter(newer.startup, f.config, f.profile, newer.attemptID) != nil || next.Begin(newer.startup) != nil {
		t.Fatal("neutral old slot blocked new admission")
	}
	if next.state.expected.PreviousGeneration == nil || *next.state.expected.PreviousGeneration != previous || next.state.expected.LatestAttempt.Terminal != nil || next.state.expected.PreviousFailure != nil {
		t.Fatal("new neutral slot invented completion")
	}
}

func TestBootstrapHistoryCreatorExceptionRefusesUnmintedProof(t *testing.T) {
	store, op, f, _, binding := historyFixture(t)
	enterHistoryFixture(t, store, op, f)
	completeHistoryFailure(t, store, op)
	for _, creator := range []*protected.ReceiptHostProcess{nil, {}, {HostProcess: &protected.HostProcess{}}} {
		if _, err := readCreatorBootstrapHistory(op.startup, f.owner, binding, creator); err == nil {
			t.Fatal("unminted creator selected held-lease exception")
		}
	}
}

func TestBootstrapHistoryCloseRequiresOriginalBoundedContext(t *testing.T) {
	store, op, _, _, _ := historyFixture(t)
	if store.Close(context.Background()) == nil {
		t.Fatal("unbounded close admitted")
	}
	if store.state.closed {
		t.Fatal("refused close discarded ownership")
	}
	if store.Close(op.startup) != nil {
		t.Fatal("bounded owned close failed")
	}
}

func TestBootstrapHistoryRefusesReplacedCanonicalRoot(t *testing.T) {
	store, op, f, _, _ := historyFixture(t)
	directory := f.profile.ProfileDirectory
	previous := directory + ".original-history-root"
	if os.Rename(directory, previous) != nil || os.Mkdir(directory, 0700) != nil {
		t.Fatal("owned root replacement setup failed")
	}
	t.Cleanup(func() {
		if os.Rename(directory, directory+".rejected-history-root") != nil || os.Rename(previous, directory) != nil {
			t.Error("exact original root restoration failed")
		}
	})
	// Both roots contain byte-identical declarations. A pathname reload must not
	// grant write authority over the different original held-root/lease inode.
	entries, err := os.ReadDir(previous)
	if err != nil {
		t.Fatal("owned fixture enumeration failed")
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(previous, entry.Name()))
		if err != nil {
			t.Fatal("owned declaration read failed")
		}
		if os.WriteFile(filepath.Join(directory, entry.Name()), raw, 0600) != nil {
			t.Fatal("equivalent private declaration copy failed")
		}
	}
	if op.enter(op.startup, f.config, f.profile, op.attemptID) != nil {
		t.Fatal("component admission failed")
	}
	if store.Begin(op.startup) == nil {
		t.Fatal("equivalent replacement pathname authorized old held root")
	}
	if _, err := os.Lstat(filepath.Join(previous, bootstrapHistoryName)); !os.IsNotExist(err) {
		t.Fatal("original held root was mutated after replacement")
	}
	if _, err := os.Lstat(filepath.Join(directory, bootstrapHistoryName)); !os.IsNotExist(err) {
		t.Fatal("replacement root was mutated")
	}
}
