//go:build linux || darwin

package launcher

import (
	"context"
	"time"

	protected "github.com/controlLogix/agentmux/platform/runtime"
)

// BootstrapTerminalHistory describes a recorded past failure. It supplies no
// current readiness, instance state or permission to start another runtime.
type BootstrapTerminalHistory struct {
	SchemaVersion   string            `json:"schemaVersion"`
	Kind            string            `json:"kind"`
	Meaning         string            `json:"meaning"`
	InvocationID    string            `json:"invocationId"`
	CompletedAt     string            `json:"completedAt"`
	Diagnostic      RequestDiagnostic `json:"diagnostic"`
	RecordedCleanup string            `json:"recordedCleanup"`
}

func terminalHistory(failure *bootstrapHistoryFailure, now time.Time) (*BootstrapTerminalHistory, error) {
	if failure == nil {
		return nil, nil
	}
	completed, err := time.Parse(time.RFC3339Nano, failure.CompletedAt)
	if failure.DiagnosticStage != nil && !validBootstrapDiagnosticStage(*failure.DiagnosticStage) {
		return nil, historyError("invalid", nil)
	}
	diagnostic := requestDiagnostic(failure.DiagnosticCode)
	if !ownerBridgeInvocation.MatchString(failure.InvocationID) || err != nil || completed.IsZero() || completed.After(now) || now.Sub(completed) > bootstrapHistoryRelevance || diagnostic.Code != failure.DiagnosticCode || !ValidRequestDiagnostic(diagnostic) || (failure.Cleanup != "unknown" && failure.Cleanup != "incomplete") {
		return nil, historyError("invalid", nil)
	}
	return &BootstrapTerminalHistory{"1.0.0", "bootstrap-terminal-history", "previous_recorded_terminal_failure", failure.InvocationID, failure.CompletedAt, diagnostic, failure.Cleanup}, nil
}

// PreviousBootstrapFailure derives all authority from current installed policy
// and a real free service lease. A held lease suppresses history.
func (h *EnrolledHostPolicy) PreviousBootstrapFailure(ctx context.Context) (*BootstrapTerminalHistory, error) {
	bounded, cancel, err := historyIOContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	if h == nil {
		return nil, historyError("binding_invalid", nil)
	}
	fresh, err := LoadEnrolledHostPolicy(h.selection)
	if err != nil {
		return nil, err
	}
	_, owner, err := fresh.Load()
	if err != nil {
		return nil, err
	}
	if err := bounded.Err(); err != nil {
		return nil, historyError("context_invalid", err)
	}
	failure, err := readBootstrapHistory(bounded, owner, fresh.record.RuntimeExecutable.Digest)
	if err != nil {
		return nil, err
	}
	if err := bounded.Err(); err != nil {
		return nil, historyError("context_invalid", err)
	}
	result, err := terminalHistory(failure, time.Now().UTC())
	if canceled := bounded.Err(); canceled != nil {
		return nil, historyError("context_invalid", canceled)
	}
	return result, err
}

// CreatorPreviousBootstrapFailure uses only the original factory-created child
// and this actual ensure invocation. Its receipt proves past admission only.
func (i *EnsureInvocation) CreatorPreviousBootstrapFailure(ctx context.Context, creator *protected.ReceiptHostProcess) (*BootstrapTerminalHistory, error) {
	bounded, cancel, err := historyIOContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	if i == nil || i.host == nil || !ownerBridgeInvocation.MatchString(i.id) {
		return nil, historyError("binding_invalid", nil)
	}
	fresh, err := LoadEnrolledHostPolicy(i.host.selection)
	if err != nil {
		return nil, err
	}
	_, owner, err := fresh.Load()
	if err != nil {
		return nil, err
	}
	binding, err := fresh.BootstrapReceiptBinding(i.id)
	if err != nil {
		return nil, err
	}
	if err := bounded.Err(); err != nil {
		return nil, historyError("context_invalid", err)
	}
	if creator == nil || !creator.HasValidatedBootstrapReceipt(binding) {
		return nil, historyError("binding_invalid", nil)
	}
	failure, err := readCreatorBootstrapHistory(bounded, owner, binding, creator)
	if err != nil {
		return nil, err
	}
	if failure != nil && failure.InvocationID != i.id {
		return nil, historyError("binding_invalid", nil)
	}
	if err := bounded.Err(); err != nil {
		return nil, historyError("context_invalid", err)
	}
	result, err := terminalHistory(failure, time.Now().UTC())
	if canceled := bounded.Err(); canceled != nil {
		return nil, historyError("context_invalid", canceled)
	}
	return result, err
}
