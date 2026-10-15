//go:build linux || darwin

package launcher

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"syscall"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const bootstrapHistoryName = "bootstrap-operation-history.json"
const bootstrapHistoryLimit = 4096
const bootstrapHistoryRelevance = 24 * time.Hour
const bootstrapHistoryIOBudget = 500 * time.Millisecond

// This proposed private resource has no network or filesystem schema loader.
// Promotion to the authoritative contracts registry is a separate root review.
//
//go:embed bootstrap_history.schema.json
var bootstrapHistorySchemaText string

type bootstrapHistoryBinding struct {
	OwnerUID                    uint32                 `json:"ownerUid"`
	OwnerIdentityRef            OwnerIdentityReference `json:"ownerIdentityRef"`
	OwnerEnrollmentDigest       string                 `json:"ownerEnrollmentDigest"`
	Scope                       protocol.Scope         `json:"scope"`
	RuntimeDigest               string                 `json:"runtimeDigest"`
	ComposeConfigDigest         string                 `json:"composeConfigDigest"`
	SelectedEngineBindingDigest string                 `json:"selectedEngineBindingDigest"`
	ServerTrustDigest           string                 `json:"serverTrustDigest"`
	ServiceLeaseIdentityDigest  string                 `json:"serviceLeaseIdentityDigest"`
}

type bootstrapHistoryTerminal struct {
	CompletedAt     string               `json:"completedAt"`
	Outcome         string               `json:"outcome"`
	DiagnosticCode  *string              `json:"diagnosticCode"`
	Cleanup         string               `json:"cleanup"`
	DiagnosticStage *string              `json:"diagnosticStage,omitempty"`
	FailedRead      *bootstrapFailedRead `json:"failedRead,omitempty"`
}
type bootstrapHistoryAttempt struct {
	InvocationID string                    `json:"invocationId"`
	BeganAt      string                    `json:"beganAt"`
	Terminal     *bootstrapHistoryTerminal `json:"terminal"`
}
type bootstrapHistoryFailure struct {
	InvocationID    string               `json:"invocationId"`
	CompletedAt     string               `json:"completedAt"`
	DiagnosticCode  string               `json:"diagnosticCode"`
	Cleanup         string               `json:"cleanup"`
	DiagnosticStage *string              `json:"diagnosticStage,omitempty"`
	FailedRead      *bootstrapFailedRead `json:"failedRead,omitempty"`
}
type bootstrapHistoryRecord struct {
	SchemaVersion      string                   `json:"schemaVersion"`
	Kind               string                   `json:"kind"`
	Binding            bootstrapHistoryBinding  `json:"binding"`
	Generation         string                   `json:"generation"`
	PreviousGeneration *string                  `json:"previousGeneration"`
	WrittenAt          string                   `json:"writtenAt"`
	LatestAttempt      bootstrapHistoryAttempt  `json:"latestAttempt"`
	PreviousFailure    *bootstrapHistoryFailure `json:"previousFailure"`
}

// Error formatting exposes only a fixed code. Unwrap keeps the original
// failure and any exact cleanup owners; history never replaces those owners.
type bootstrapHistoryError struct {
	code  string
	cause error
}

func (e bootstrapHistoryError) Error() string {
	switch e.code {
	case "context_invalid", "invalid", "binding_invalid", "lease_invalid", "conflict", "publication_failed", "cleanup_failed", "state_invalid":
		return "bootstrap_history_" + e.code
	default:
		return "bootstrap_history_invalid"
	}
}
func (e bootstrapHistoryError) Format(s fmt.State, _ rune)   { fmt.Fprint(s, e.Error()) }
func (e bootstrapHistoryError) MarshalJSON() ([]byte, error) { return json.Marshal(e.Error()) }
func (e bootstrapHistoryError) Unwrap() error                { return e.cause }
func historyError(code string, cause error) error {
	return &bootstrapHistoryError{code: code, cause: cause}
}

var bootstrapHistorySchemaOnce sync.Once
var bootstrapHistorySchema *jsonschema.Schema
var bootstrapHistorySchemaError error

func compileBootstrapHistorySchema() {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(ownerBridgeDenyLoader{})
	c.UseRegexpEngine(compileOwnerBridgeRegexp)
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader([]byte(bootstrapHistorySchemaText)))
	if err == nil {
		err = c.AddResource("urn:agentmux:proposal:bootstrap-operation-history:1", value)
	}
	if err == nil {
		bootstrapHistorySchema, err = c.Compile("urn:agentmux:proposal:bootstrap-operation-history:1")
	}
	if err != nil {
		bootstrapHistorySchemaError = historyError("invalid", nil)
	}
}

func decodeBootstrapHistory(raw []byte, now time.Time) (bootstrapHistoryRecord, error) {
	var result bootstrapHistoryRecord
	if protocol.DecodeClosedJSON(raw, &result, bootstrapHistoryLimit) != nil {
		return result, historyError("invalid", nil)
	}
	bootstrapHistorySchemaOnce.Do(compileBootstrapHistorySchema)
	if bootstrapHistorySchemaError != nil {
		return result, bootstrapHistorySchemaError
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil || bootstrapHistorySchema.Validate(value) != nil {
		return result, historyError("invalid", nil)
	}
	stamp := func(value string) (time.Time, error) {
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil || parsed.After(now) {
			return time.Time{}, historyError("invalid", nil)
		}
		return parsed, nil
	}
	written, err := stamp(result.WrittenAt)
	if err != nil {
		return result, err
	}
	began, err := stamp(result.LatestAttempt.BeganAt)
	if err != nil || began.After(written) {
		return result, historyError("invalid", nil)
	}
	if result.PreviousGeneration != nil && *result.PreviousGeneration == result.Generation {
		return result, historyError("invalid", nil)
	}
	if terminal := result.LatestAttempt.Terminal; terminal != nil {
		completed, err := stamp(terminal.CompletedAt)
		if err != nil || completed.Before(began) || completed.After(written) {
			return result, historyError("invalid", nil)
		}
		if terminal.FailedRead != nil && (terminal.Outcome != "failed" || !validBootstrapFailedRead(terminal.FailedRead)) {
			return result, historyError("invalid", nil)
		}
		if terminal.DiagnosticStage != nil && (terminal.Outcome != "failed" || !validBootstrapDiagnosticStage(*terminal.DiagnosticStage)) {
			return result, historyError("invalid", nil)
		}
		if terminal.Outcome == "completed" && result.PreviousFailure != nil {
			return result, historyError("invalid", nil)
		}
	}
	if previous := result.PreviousFailure; previous != nil {
		if previous.FailedRead != nil && !validBootstrapFailedRead(previous.FailedRead) {
			return result, historyError("invalid", nil)
		}
		if previous.DiagnosticStage != nil && !validBootstrapDiagnosticStage(*previous.DiagnosticStage) {
			return result, historyError("invalid", nil)
		}
		completed, err := stamp(previous.CompletedAt)
		if err != nil || completed.After(began) || previous.InvocationID == result.LatestAttempt.InvocationID {
			return result, historyError("invalid", nil)
		}
	}
	return result, nil
}

func historyTimestamp(now time.Time) string {
	return now.UTC().Truncate(time.Microsecond).Format("2006-01-02T15:04:05.999999Z")
}
func historyDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func historyGeneration() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", historyError("publication_failed", err)
	}
	return "history_" + hex.EncodeToString(nonce[:]), nil
}

func historyLeaseName(scope protocol.Scope) string {
	sum := sha256.Sum256([]byte(scope.InstanceID + "\x00owner-status-service"))
	return "bootstrap-" + hex.EncodeToString(sum[:]) + ".lock"
}
func historyLeaseDigest(info os.FileInfo) (string, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", historyError("lease_invalid", nil)
	}
	return historyDigest([]byte(fmt.Sprintf("%d/%d", stat.Dev, stat.Ino))), nil
}

// runtimeDigest originates in separately verified installed policy, never the
// history being loaded. This local owner trust does not sandbox same-UID code.
func historyBinding(ctx context.Context, owner *OwnerStatus, runtimeDigest string, lease os.FileInfo) (bootstrapHistoryBinding, error) {
	var empty bootstrapHistoryBinding
	if ctx == nil || ctx.Err() != nil || owner == nil {
		return empty, historyError("context_invalid", nil)
	}
	if err := lockHistory(ctx, &owner.mu); err != nil {
		return empty, historyError("context_invalid", err)
	}
	defer owner.mu.Unlock()
	current, err := LoadOwnerStatus(owner.policy)
	if err != nil || current.profile == nil || !reflect.DeepEqual(current.profile, owner.profile) {
		return empty, historyError("binding_invalid", err)
	}
	p := current.profile
	if p.Docker == nil || !digest.MatchString(runtimeDigest) || !digest.MatchString(p.ServerTrustDigest) {
		return empty, historyError("binding_invalid", nil)
	}
	ownerRaw, err := json.Marshal(owner.policy.Enrollment)
	if err != nil {
		return empty, historyError("binding_invalid", err)
	}
	engineRaw, err := json.Marshal(*p.Docker)
	if err != nil {
		return empty, historyError("binding_invalid", err)
	}
	leaseDigest, err := historyLeaseDigest(lease)
	if err != nil {
		return empty, err
	}
	if err := ctx.Err(); err != nil {
		return empty, historyError("context_invalid", err)
	}
	return bootstrapHistoryBinding{owner.policy.Profile.OwnerUID, owner.policy.Enrollment.Identity, historyDigest(ownerRaw), owner.policy.KernelScope, runtimeDigest, p.ConfigDigest, historyDigest(engineRaw), p.ServerTrustDigest, leaseDigest}, nil
}

// Each store is for one actual Run-created operation. It borrows that held
// service lease through an owned duplicate and owns its profile root descriptor.
// Its integration into Run is deliberately separate from this component.
type bootstrapHistoryStore struct {
	guard     *historyRootGuard
	state     *bootstrapHistoryState
	operation *bootstrapOperation
	root      *os.Root
	leaseFile *os.File
	binding   bootstrapHistoryBinding
	beganAt   time.Time
}

// Formatting copies immutable references, never fields being changed under
// the private gate. Exact owned files remain attached to the store pointer.
type bootstrapHistoryState struct {
	publishingClosed, leaseClosed bool
	stage                         *historyOwnedStage
	mu                            sync.Mutex
	expected                      *bootstrapHistoryRecord
	expectedRaw                   []byte
	expectedInfo                  os.FileInfo
	closed                        bool
	closeFailure                  error
}

func (bootstrapHistoryStore) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "[private bootstrap history]")
}
func (bootstrapHistoryStore) MarshalJSON() ([]byte, error) {
	return json.Marshal("[private bootstrap history]")
}

// Construction checks borrowed descriptor identity. Real flock acquisition is
// supplied by the existing Run path; a filename or saved generation is no proof.
func openBootstrapHistory(ctx context.Context, operation *bootstrapOperation, binding protected.BootstrapReceiptBinding) (store *bootstrapHistoryStore, failure error) {
	if operation == nil || operation.state == nil || operation.server == nil || operation.server.owner == nil || operation.leaseFile == nil || !ownerBridgeReceiptBindingMatches(binding, operation.server, operation.attemptID) {
		return nil, historyError("binding_invalid", nil)
	}
	bounded, cancel, err := historyIOContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	ctx = bounded
	root, err := openProfileDirectory(operation.server.owner.policy.Profile)
	if err != nil {
		return nil, historyError("binding_invalid", err)
	}
	store = &bootstrapHistoryStore{state: &bootstrapHistoryState{}, operation: operation, root: root, beganAt: operation.createdAt}
	store.guard, err = captureHistoryRoot(ctx, root, operation.server.owner.policy.Profile)
	if err != nil {
		return store, err
	}
	store.leaseFile, err = duplicateHistoryLease(operation.leaseFile)
	if err != nil {
		return store, err
	}
	info, err := store.checkLease(ctx)
	if err != nil {
		return store, err
	}
	store.binding, err = historyBinding(ctx, operation.server.owner, binding.RuntimeDigest, info)
	if err != nil {
		return store, err
	}
	if store.binding.Scope != operation.scope || store.binding.ComposeConfigDigest != historyDigest(operation.server.config.Compose) {
		return store, historyError("binding_invalid", nil)
	}
	raw, info, err := readHistoryFile(ctx, root, store.binding.OwnerUID)
	if err != nil {
		return store, err
	}
	if raw != nil {
		record, err := decodeBootstrapHistory(raw, time.Now().UTC())
		if err != nil {
			return store, err
		}
		if record.Binding != store.binding {
			return store, historyError("binding_invalid", nil)
		}
		store.state.expected, store.state.expectedRaw, store.state.expectedInfo = &record, raw, info
	}
	return store, nil
}

func (s *bootstrapHistoryStore) Begin(ctx context.Context) error {
	if s == nil {
		return historyError("state_invalid", nil)
	}
	bounded, cancel, err := historyIOContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	ctx = bounded
	if err := lockHistory(ctx, &s.state.mu); err != nil {
		return historyError("context_invalid", err)
	}
	defer s.state.mu.Unlock()
	if s.state.closed || s.state.publishingClosed {
		return historyError("state_invalid", nil)
	}
	if err := historyPending(ctx, s.operation); err != nil {
		return err
	}
	if s.state.expected != nil && s.state.expected.LatestAttempt.InvocationID == s.operation.attemptID {
		return historyError("state_invalid", nil)
	}
	now := time.Now().UTC()
	next := bootstrapHistoryRecord{SchemaVersion: "1.0.0", Kind: "bootstrap-operation-history", Binding: s.binding, WrittenAt: historyTimestamp(now), LatestAttempt: bootstrapHistoryAttempt{InvocationID: s.operation.attemptID, BeganAt: historyTimestamp(s.beganAt)}}
	if s.state.expected != nil {
		next.PreviousFailure = s.state.expected.PreviousFailure
		if t := s.state.expected.LatestAttempt.Terminal; t != nil && t.Outcome == "failed" {
			next.PreviousFailure = &bootstrapHistoryFailure{InvocationID: s.state.expected.LatestAttempt.InvocationID, CompletedAt: t.CompletedAt, DiagnosticCode: *t.DiagnosticCode, Cleanup: t.Cleanup, DiagnosticStage: copyBootstrapDiagnosticStage(t.DiagnosticStage), FailedRead: copyBootstrapFailedRead(t.FailedRead)}
		}
	}
	return s.publish(ctx, &next)
}

func (s *bootstrapHistoryStore) RecordTerminal(ctx context.Context) error {
	if s == nil {
		return historyError("state_invalid", nil)
	}
	bounded, cancel, err := historyIOContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	ctx = bounded
	if err := lockHistory(ctx, &s.state.mu); err != nil {
		return historyError("context_invalid", err)
	}
	defer s.state.mu.Unlock()
	if s.state.closed || s.state.publishingClosed {
		return historyError("state_invalid", nil)
	}
	select {
	case <-s.operation.done:
	default:
		return historyError("state_invalid", nil)
	}
	session, cause, completed, readErr := historyCompletion(ctx, s.operation)
	if readErr != nil {
		return readErr
	}
	if cause == nil && session == nil {
		return historyError("state_invalid", nil)
	}
	if s.state.expected != nil && s.state.expected.LatestAttempt.InvocationID == s.operation.attemptID && s.state.expected.LatestAttempt.Terminal != nil {
		return s.verifyExpected(ctx)
	}
	now := time.Now().UTC()
	if completed.IsZero() || completed.Before(s.beganAt) {
		return historyError("state_invalid", nil)
	}
	next := bootstrapHistoryRecord{SchemaVersion: "1.0.0", Kind: "bootstrap-operation-history", Binding: s.binding, WrittenAt: historyTimestamp(now), LatestAttempt: bootstrapHistoryAttempt{InvocationID: s.operation.attemptID, BeganAt: historyTimestamp(s.beganAt), Terminal: &bootstrapHistoryTerminal{CompletedAt: historyTimestamp(completed), Outcome: "completed", Cleanup: "unknown"}}}
	if cause != nil {
		code := ProjectRequestDiagnostic(cause).Code
		next.LatestAttempt.Terminal.Outcome = "failed"
		next.LatestAttempt.Terminal.DiagnosticCode = &code
		next.LatestAttempt.Terminal.DiagnosticStage = bootstrapDiagnosticStage(cause)
		next.LatestAttempt.Terminal.FailedRead = bootstrapFailedReadFromError(cause)
		if code == "owned_cleanup_incomplete" {
			next.LatestAttempt.Terminal.Cleanup = "incomplete"
		}
	}
	// A live successful session is not reaped; no complete-cleanup fact is
	// inferred here. Later exact cleanup publication needs its own integration.
	return s.publish(ctx, &next)
}

func (s *bootstrapHistoryStore) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	bounded, cancel, err := historyIOContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	ctx = bounded
	if err := lockHistory(ctx, &s.state.mu); err != nil {
		return historyError("cleanup_failed", err)
	}
	defer s.state.mu.Unlock()
	if s.state.closed {
		return s.state.closeFailure
	}
	// Holding the same gate joins every synchronous publication phase. Once
	// publication is retired, old-temp cleanup cannot alter the shared slot.
	s.state.publishingClosed = true
	cleanupErr := s.cleanupStage(ctx)
	if !s.state.leaseClosed && s.leaseFile != nil {
		closeErr := s.leaseFile.Close()
		s.state.leaseClosed = true
		if closeErr != nil {
			s.state.closeFailure = errors.Join(s.state.closeFailure, historyError("cleanup_failed", closeErr))
		}
	}
	if s.state.stage != nil {
		return s.stageFailure(errors.Join(cleanupErr, s.state.closeFailure))
	}
	// No pending staging object remains. Historical close errors stay safe;
	// consumed handles are never retried, even if Close reported an error.
	s.state.closeFailure = errors.Join(s.state.closeFailure, cleanupErr)
	if err := s.root.Close(); err != nil {
		s.state.closeFailure = joinHistoryCleanup(s.state.closeFailure, err)
	}
	s.state.closed = true

	return s.state.closeFailure
}

// These snapshots acquire only the actual operation state gate and respect the
// caller deadline. They do not wait for completion while holding another gate.
func historyPending(ctx context.Context, op *bootstrapOperation) error {
	if op == nil || op.state == nil {
		return historyError("state_invalid", nil)
	}
	if err := lockHistory(ctx, &op.state.mu); err != nil {
		return historyError("context_invalid", err)
	}
	defer op.state.mu.Unlock()
	if !op.state.entered || op.state.completed || op.state.core == nil || op.startup.Err() != nil || op.lifetime.Err() != nil || op.state.core.Err() != nil {
		return historyError("state_invalid", nil)
	}
	return nil
}
func historyCompletion(ctx context.Context, op *bootstrapOperation) (*Session, error, time.Time, error) {
	if op == nil || op.state == nil {
		return nil, nil, time.Time{}, historyError("state_invalid", nil)
	}
	if err := lockHistory(ctx, &op.state.mu); err != nil {
		return nil, nil, time.Time{}, historyError("context_invalid", err)
	}
	defer op.state.mu.Unlock()
	if !op.state.completed {
		return nil, nil, time.Time{}, historyError("state_invalid", nil)
	}
	return op.state.session, op.state.failure, op.state.completedAt, nil
}

// Reuse the existing cancelable gate algorithm while retaining the caller's
// actual deadline/cancellation cause beneath this artifact's fixed code.
func lockHistory(ctx context.Context, gate *sync.Mutex) error {
	if ctx == nil {
		return historyError("context_invalid", nil)
	}
	if err := lockOwnerObservation(ctx, gate); err != nil {
		return errors.Join(err, ctx.Err())
	}
	return nil
}
