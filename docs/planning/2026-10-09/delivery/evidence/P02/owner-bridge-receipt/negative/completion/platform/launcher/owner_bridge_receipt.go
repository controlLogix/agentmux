//go:build linux || darwin

package launcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	protected "github.com/controlLogix/agentmux/platform/runtime"
)

// Only the installed factory can attach this exact inherited writer. Its
// attempt bookkeeping is not readiness or caller-selected status authority.
type ownerBridgeReceiptState struct {
	mu        sync.Mutex
	writer    *protected.BootstrapReceiptWriter
	binding   protected.BootstrapReceiptBinding
	attempted bool
}

func (state *ownerBridgeReceiptState) matches(server *OwnerBridgeServer, attemptID string) bool {
	if state == nil || state.writer == nil {
		return false
	}
	return ownerBridgeReceiptBindingMatches(state.binding, server, attemptID)
}
func ownerBridgeReceiptBindingMatches(binding protected.BootstrapReceiptBinding, server *OwnerBridgeServer, attemptID string) bool {
	if server == nil {
		return false
	}
	raw, err := json.Marshal(server.enrollment.Owner)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(raw)
	return binding.ColdInvocationID == attemptID && binding.Scope == server.config.Kernel.Scope && binding.EnrollmentDigest == "sha256:"+hex.EncodeToString(sum[:])
}
func (state *ownerBridgeReceiptState) emit(ctx context.Context, accepted bool) {
	state.mu.Lock()
	if state.attempted {
		state.mu.Unlock()
		return
	}
	state.attempted = true
	state.mu.Unlock()
	// A departed frontend must not cancel the admitted host. The writer consumes
	// and closes its one frame even when the pipe peer has already gone away.
	if accepted {
		_ = state.writer.Accepted(ctx)
	} else {
		_ = state.writer.Failed(ctx)
	}
}

// The core calls this after successful enter, outside the operation mutex.
// No constructor, process flag or lease metadata can emit accepted on its own.
func (operation *bootstrapOperation) emitBootstrapAccepted(ctx context.Context) error {
	if operation == nil || operation.server == nil {
		return operationError("owner_invalid")
	}
	state := operation.server.receipt
	if state == nil {
		return nil
	}
	if ctx == nil || ctx.Err() != nil {
		return operationError("context_invalid")
	}
	if !state.matches(operation.server, operation.attemptID) {
		return bridgeError("receipt_binding_invalid")
	}
	if err := operation.pending(operation.server.owner); err != nil {
		return err
	}
	admission, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	owner := operation.server.owner
	if err := lockOwnerObservation(admission, &owner.mu); err != nil {
		return bridgeError("receipt_owner_invalid")
	}
	current, err := LoadOwnerStatus(owner.policy)
	valid := err == nil && reflect.DeepEqual(current.profile, owner.profile)
	owner.mu.Unlock()
	if !valid || admission.Err() != nil {
		return bridgeError("receipt_owner_invalid")
	}
	if err := operation.pending(owner); err != nil {
		return err
	}
	state.emit(admission, true)
	return nil
}

// Run has joined its actual bootstrap before this final defer. A service-lease
// refusal currently proves only failure, not actual OS lock contention.
func (server *OwnerBridgeServer) finishBootstrapReceipt(startup context.Context, failure error) error {
	state := server.receipt
	if state == nil {
		return failure
	}
	if failure != nil {
		parent := startup
		if parent == nil || parent.Err() != nil {
			parent = context.Background()
		}
		cleanup, cancel := context.WithTimeout(parent, time.Second)
		state.emit(cleanup, false)
		cancel()
	}
	if state.writer.Close() != nil {
		return errors.Join(failure, bridgeError("receipt_cleanup_failed"))
	}
	return failure
}

// Retain the actual joined result even when the transport loop ended first.
// A fixed public code hides arbitrary file/socket details without flattening
// the exact typed cleanup owner available through errors.As and Unwrap.
type bridgeCompletionCause struct {
	code  string
	cause error
}

func (e bridgeCompletionCause) Error() string                  { return bridgeCompletionCode(e.code) }
func (e bridgeCompletionCause) Format(state fmt.State, _ rune) { fmt.Fprint(state, e.Error()) }
func (e bridgeCompletionCause) MarshalJSON() ([]byte, error)   { return json.Marshal(e.Error()) }
func (e bridgeCompletionCause) Unwrap() error                  { return e.cause }
func bridgeCompletionCode(code string) string {
	switch code {
	case "owner_bridge_startup_failed", "owner_bridge_connection_unavailable", "owner_bridge_connection_lost", "owner_bridge_authority_rejected", "owner_bridge_deadline", "owner_bridge_reply_failed", "owner_bridge_subscribe_failed", "owner_bridge_owned_connection_cleanup_failed", "owner_bridge_receipt_owner_invalid", "owner_bridge_receipt_binding_invalid", "owner_bridge_receipt_cleanup_failed", "owner_bridge_runtime_cleanup_failed", "kernel_status_owned_connection_cleanup_failed", "launcher_owned_transport_cleanup_failed", "health_owned_transport_cleanup_failed", "health_connection_cleanup_failed", "observe_connection_cleanup_failed", "bootstrap_owned_cleanup_incomplete", "bootstrap_context_invalid", "bootstrap_observation_deadline", "bootstrap_local_broker_authority_unavailable", "kernel_status_cancelled", "kernel_status_deadline", "kernel_status_unavailable", "kernel_status_invalid", "kernel_status_authority_rejected":
		return code
	}
	return "owner_bridge_startup_failed"
}
func joinedBridgeBootstrapResult(operation *bootstrapOperation, primary error) (*Session, error) {
	session, _ := operation.resultContext(context.Background())
	return session, primary
}
