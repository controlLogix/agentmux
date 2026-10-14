//go:build linux || darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/controlLogix/agentmux/platform/launcher"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

const frontendHistoryLimit = 200 * time.Millisecond
const frontendHistoryOutputAllowance = 300 * time.Millisecond

func frontendHistoryContext(total context.Context) (context.Context, context.CancelFunc, error) {
	if total == nil || total.Err() != nil {
		return nil, nil, errors.New("history_context_unavailable")
	}
	deadline, ok := total.Deadline()
	if !ok {
		return nil, nil, errors.New("history_context_unavailable")
	}
	cutoff := deadline.Add(-frontendReceiptCleanupLimit - frontendHistoryOutputAllowance)
	if !time.Now().Before(cutoff) {
		return nil, nil, errors.New("history_context_unavailable")
	}
	bounded, cancel := context.WithDeadline(total, cutoff)
	limited, stop := context.WithTimeout(bounded, frontendHistoryLimit)
	return limited, func() { stop(); cancel() }, nil
}

// History output preserves the original unavailable request as a failure.
// The document describes a past terminal error, never an L04 observation.
func emitPreviousBootstrapFailure(ctx context.Context, output io.Writer, history *launcher.BootstrapTerminalHistory, requestErr error) (bool, error) {
	if ctx == nil || ctx.Err() != nil || history == nil || requestErr == nil {
		return false, nil
	}
	if json.NewEncoder(output).Encode(history) != nil {
		return true, errors.Join(requestErr, errors.New("output_failed"))
	}
	return true, requestErr
}

func statusHistoryFallback(total context.Context, output io.Writer, policy *launcher.EnrolledHostPolicy, requestErr error) (bool, error) {
	if !progressObservationUnavailable(requestErr) {
		return false, nil
	}
	ctx, cancel, err := frontendHistoryContext(total)
	if err != nil {
		return false, nil
	}
	defer cancel()
	history, err := policy.PreviousBootstrapFailure(ctx)
	if err != nil {
		return false, nil
	}
	return emitPreviousBootstrapFailure(ctx, output, history, requestErr)
}

func creatorHistoryFallback(total context.Context, output io.Writer, invocation *launcher.EnsureInvocation, child *protected.ReceiptHostProcess, requestErr error) (bool, error) {
	if !progressObservationUnavailable(requestErr) && requestErr != context.DeadlineExceeded {
		return false, nil
	}
	ctx, cancel, err := frontendHistoryContext(total)
	if err != nil {
		return false, nil
	}
	defer cancel()
	history, err := invocation.CreatorPreviousBootstrapFailure(ctx, child)
	if err != nil {
		return false, nil
	}
	return emitPreviousBootstrapFailure(ctx, output, history, requestErr)
}
