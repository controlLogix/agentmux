//go:build linux || darwin

package launcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/assembly"
	"github.com/controlLogix/agentmux/platform/privatefs"
	protected "github.com/controlLogix/agentmux/platform/runtime"
	"golang.org/x/sys/unix"
)

func historyIOContext(parent context.Context) (context.Context, context.CancelFunc, error) {
	if parent == nil || parent.Done() == nil {
		return nil, nil, historyError("context_invalid", nil)
	}
	if err := parent.Err(); err != nil {
		return nil, nil, historyError("context_invalid", err)
	}
	deadline, ok := parent.Deadline()
	if !ok || !deadline.After(time.Now()) {
		return nil, nil, historyError("context_invalid", nil)
	}
	ctx, cancel := context.WithTimeout(parent, bootstrapHistoryIOBudget)
	return ctx, cancel, nil
}

// Read the held regular file with before/after identity and ACL checks. Close
// errors are retained, and no background goroutine preempts filesystem calls.
func readHistoryFile(ctx context.Context, root *os.Root, uid uint32) (raw []byte, info os.FileInfo, failure error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, historyError("context_invalid", nil)
	}
	before, err := root.Lstat(bootstrapHistoryName)
	if os.IsNotExist(err) {
		return nil, nil, nil
	}
	if err != nil || !privateProfileInfo(before, uid, false) || before.Size() > bootstrapHistoryLimit {
		return nil, nil, historyError("invalid", err)
	}
	file, err := assembly.OpenMember(root, bootstrapHistoryName)
	if err != nil {
		return nil, nil, historyError("invalid", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			raw, info = nil, nil
			failure = errors.Join(failure, historyError("cleanup_failed", err))
		}
	}()
	opened, err := file.Stat()
	if err != nil || !hostReadMetadataEqual(before, opened) || !privateProfileInfo(opened, uid, false) || privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil {
		return nil, nil, historyError("invalid", err)
	}
	raw, err = io.ReadAll(io.LimitReader(file, bootstrapHistoryLimit+1))
	after, afterErr := root.Lstat(bootstrapHistoryName)
	final, finalErr := file.Stat()
	if err != nil || afterErr != nil || finalErr != nil || ctx.Err() != nil || len(raw) > bootstrapHistoryLimit || int64(len(raw)) != opened.Size() || !hostReadMetadataEqual(opened, after) || !hostReadMetadataEqual(opened, final) || !privateProfileInfo(final, uid, false) || privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil {
		return nil, nil, historyError("invalid", errors.Join(err, afterErr, finalErr, ctx.Err()))
	}
	return raw, final, nil
}

func (s *bootstrapHistoryStore) checkLease(ctx context.Context) (os.FileInfo, error) {
	if s == nil || s.operation == nil || s.root == nil || s.leaseFile == nil || s.operation.server == nil || s.operation.server.owner == nil {
		return nil, historyError("lease_invalid", nil)
	}
	if err := s.guard.check(ctx, s.root); err != nil {
		return nil, err
	}
	op := s.operation
	name := historyLeaseName(op.scope)
	if s.leaseFile.Name() != filepath.Join(op.server.owner.policy.Profile.Directory, name) {
		return nil, historyError("lease_invalid", nil)
	}
	held, err := s.leaseFile.Stat()
	current, currentErr := s.root.Lstat(name)
	if err != nil || currentErr != nil || !os.SameFile(held, current) || !privateProfileInfo(held, op.server.owner.policy.Profile.OwnerUID, false) || !privateProfileInfo(current, op.server.owner.policy.Profile.OwnerUID, false) || privatefs.CheckDescriptor(s.leaseFile, privatefs.PrivateObject) != nil {
		return nil, historyError("lease_invalid", errors.Join(err, currentErr))
	}
	return held, nil
}

func (s *bootstrapHistoryStore) verifyExpected(ctx context.Context) (failure error) {
	defer func() {
		if err := s.guard.check(ctx, s.root); err != nil {
			failure = errors.Join(failure, err)
		}
	}()
	held, err := s.checkLease(ctx)
	if err != nil {
		return err
	}
	currentBinding, err := historyBinding(ctx, s.operation.server.owner, s.binding.RuntimeDigest, held)
	if err != nil || currentBinding != s.binding {
		return historyError("binding_invalid", err)
	}
	raw, info, err := readHistoryFile(ctx, s.root, s.binding.OwnerUID)
	if err != nil {
		return err
	}
	if s.state.expected == nil {
		if raw != nil {
			return historyError("conflict", nil)
		}
		return nil
	}
	if raw == nil || !bytes.Equal(raw, s.state.expectedRaw) || !hostReadMetadataEqual(s.state.expectedInfo, info) {
		return historyError("conflict", nil)
	}
	record, err := decodeBootstrapHistory(raw, time.Now().UTC())
	if err != nil || record.Generation != s.state.expected.Generation || record.Binding != s.binding {
		return historyError("conflict", err)
	}
	return nil
}

// This CAS is serialized by the borrowed actual service lease. It does not
// claim protection from a malicious noncooperating writer with the same UID.
func (s *bootstrapHistoryStore) publish(ctx context.Context, next *bootstrapHistoryRecord) (failure error) {
	if s.state.closed || s.state.publishingClosed {
		return historyError("state_invalid", nil)
	}
	bounded, cancel, err := historyIOContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if err := s.verifyExpected(bounded); err != nil {
		return err
	}
	generation, err := historyGeneration()
	if err != nil {
		return err
	}
	next.Generation = generation
	if s.state.expected != nil {
		previous := s.state.expected.Generation
		next.PreviousGeneration = &previous
	}
	raw, err := jsonMarshalHistory(next)
	if err != nil {
		return err
	}
	if _, err := decodeBootstrapHistory(raw, time.Now().UTC()); err != nil {
		return err
	}
	tempName := ".bootstrap-" + generation + ".tmp"
	defer func() {
		if err := s.cleanupStage(bounded); err != nil {
			failure = s.stageFailure(errors.Join(failure, err))
		}
	}()
	file, err := s.createStage(bounded, tempName)
	if err != nil {
		return err
	}
	if err := s.mutationReady(bounded); err != nil {
		return err
	}
	if n, err := file.Write(raw); err != nil || n != len(raw) {
		return historyError("publication_failed", err)
	}
	if err := s.mutationReady(bounded); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return historyError("publication_failed", err)
	}
	if err := bounded.Err(); err != nil {
		return historyError("publication_failed", err)
	}
	if err := file.Close(); err != nil {
		s.state.stage.closed = true
		return historyError("cleanup_failed", err)
	}
	s.state.stage.closed = true
	if err := s.verifyExpected(bounded); err != nil {
		return err
	}
	if err := s.mutationReady(bounded); err != nil {
		return err
	}
	if s.state.expected == nil {
		if err := s.root.Link(tempName, bootstrapHistoryName); err != nil {
			return historyError("conflict", err)
		}
		// Drop only our own staging link so the final source is again single-link.
		if err := s.cleanupStage(bounded); err != nil {
			return err
		}
	} else {
		if err := s.mutationReady(bounded); err != nil {
			return err
		}
		if err := s.root.Rename(tempName, bootstrapHistoryName); err != nil {
			return historyError("publication_failed", err)
		}
	}
	if err := s.mutationReady(bounded); err != nil {
		return err
	}
	directory, err := s.root.Open(".")
	if err != nil {
		return historyError("publication_failed", err)
	}
	if err := s.mutationReady(bounded); err != nil {
		return errors.Join(err, historyErrorIfClose(directory.Close()))
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		var cause error
		if syncErr != nil {
			cause = historyError("publication_failed", syncErr)
		}
		if closeErr != nil {
			cause = errors.Join(cause, historyError("cleanup_failed", closeErr))
		}
		return cause
	}
	finalRaw, info, err := readHistoryFile(bounded, s.root, s.binding.OwnerUID)
	if err != nil || !bytes.Equal(finalRaw, raw) {
		return historyError("publication_failed", err)
	}
	if err := s.mutationReady(bounded); err != nil {
		return err
	}
	s.state.expected, s.state.expectedRaw, s.state.expectedInfo = next, append([]byte(nil), raw...), info
	return nil
}

func jsonMarshalHistory(record *bootstrapHistoryRecord) ([]byte, error) {
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > bootstrapHistoryLimit {
		return nil, historyError("publication_failed", err)
	}
	return raw, nil
}

// This general reader proves only momentary lease exclusion. A held, absent or
// uncertain lease suppresses history; it never becomes a starting observation.
// The original-creator exception needs a separate retained runtime capability
// and is intentionally not available through a nonce or boolean here.
func readBootstrapHistory(ctx context.Context, owner *OwnerStatus, runtimeDigest string) (result *bootstrapHistoryFailure, failure error) {
	bounded, cancel, err := historyIOContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	if owner == nil {
		return nil, historyError("binding_invalid", nil)
	}
	root, err := openProfileDirectory(owner.policy.Profile)
	if err != nil {
		return nil, historyError("binding_invalid", err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			result = nil
			failure = errors.Join(failure, historyError("cleanup_failed", err))
		}
	}()
	guard, err := captureHistoryRoot(bounded, root, owner.policy.Profile)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := guard.check(bounded, root); err != nil {
			result = nil
			failure = errors.Join(failure, err)
		}
	}()
	name := historyLeaseName(owner.policy.KernelScope)
	before, err := root.Lstat(name)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil || !privateProfileInfo(before, owner.policy.Profile.OwnerUID, false) {
		return nil, historyError("lease_invalid", err)
	}
	file, err := assembly.OpenMember(root, name)
	if err != nil {
		return nil, historyError("lease_invalid", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			result = nil
			failure = errors.Join(failure, historyError("cleanup_failed", err))
		}
	}()
	held, err := file.Stat()
	if err != nil || !hostReadMetadataEqual(before, held) || privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil {
		return nil, historyError("lease_invalid", err)
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return nil, historyError("lease_invalid", err)
	}
	var lockErr error
	if raw.Control(func(fd uintptr) { lockErr = syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB) }) != nil {
		return nil, historyError("lease_invalid", nil)
	}
	if lockErr == unix.EWOULDBLOCK || lockErr == unix.EAGAIN {
		return nil, nil
	}
	if lockErr != nil {
		return nil, historyError("lease_invalid", lockErr)
	}
	// Closing this exact descriptor releases only the temporary lock. No lease
	// metadata is read/written and no caller-supplied PID is ever examined.
	binding, err := historyBinding(bounded, owner, runtimeDigest, held)
	if err != nil {
		return nil, err
	}
	historyRaw, _, err := readHistoryFile(bounded, root, binding.OwnerUID)
	if err != nil {
		return nil, err
	}
	if historyRaw == nil {
		return nil, nil
	}
	record, err := decodeBootstrapHistory(historyRaw, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	current, currentErr := root.Lstat(name)
	final, finalErr := file.Stat()
	if currentErr != nil || finalErr != nil || !hostReadMetadataEqual(held, current) || !hostReadMetadataEqual(held, final) || privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil || record.Binding != binding {
		return nil, historyError("binding_invalid", errors.Join(currentErr, finalErr))
	}
	terminal := record.LatestAttempt.Terminal
	if terminal == nil || terminal.Outcome != "failed" {
		return nil, nil
	}
	completed, _ := time.Parse(time.RFC3339Nano, terminal.CompletedAt)
	if time.Since(completed) > bootstrapHistoryRelevance {
		return nil, nil
	}
	if err := bounded.Err(); err != nil {
		return nil, historyError("context_invalid", err)
	}
	return &bootstrapHistoryFailure{record.LatestAttempt.InvocationID, terminal.CompletedAt, *terminal.DiagnosticCode, terminal.Cleanup}, nil
}

func joinHistoryCleanup(primary, cause error) error {
	return errors.Join(primary, historyError("cleanup_failed", cause))
}

// Only an exact borrowed os.File from the existing operation is duplicated.
// SyscallConn prevents concurrent Close/reuse until the atomic CLOEXEC dup.
func duplicateHistoryLease(original *os.File) (copy *os.File, failure error) {
	if original == nil {
		return nil, historyError("lease_invalid", nil)
	}
	raw, err := original.SyscallConn()
	if err != nil {
		return nil, historyError("lease_invalid", err)
	}
	fd := -1
	var dupErr error
	err = raw.Control(func(owned uintptr) { fd, dupErr = unix.FcntlInt(owned, unix.F_DUPFD_CLOEXEC, 3) })
	if fd >= 0 {
		copy = os.NewFile(uintptr(fd), original.Name())
	}
	if err != nil || dupErr != nil {
		return copy, historyError("lease_invalid", errors.Join(err, dupErr))
	}
	if copy == nil {
		return nil, historyError("lease_invalid", nil)
	}
	return copy, nil
}

// The approved runtime helper compares a successfully validated accepted
// receipt to its original factory-minted child. A nonce or synthetic pipe
// cannot select this held-lease exception. This remains terminal history only.
func readCreatorBootstrapHistory(ctx context.Context, owner *OwnerStatus, binding protected.BootstrapReceiptBinding, creator *protected.ReceiptHostProcess) (result *bootstrapHistoryFailure, failure error) {
	if !historyCreatorEligible(creator, binding) {
		return nil, historyError("binding_invalid", nil)
	}
	bounded, cancel, err := historyIOContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	if owner == nil {
		return nil, historyError("binding_invalid", nil)
	}
	root, err := openProfileDirectory(owner.policy.Profile)
	if err != nil {
		return nil, historyError("binding_invalid", err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			result = nil
			failure = joinHistoryCleanup(failure, err)
		}
	}()
	guard, err := captureHistoryRoot(bounded, root, owner.policy.Profile)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := guard.check(bounded, root); err != nil {
			result = nil
			failure = errors.Join(failure, err)
		}
	}()
	name := historyLeaseName(owner.policy.KernelScope)
	before, err := root.Lstat(name)
	if err != nil || !privateProfileInfo(before, owner.policy.Profile.OwnerUID, false) {
		return nil, historyError("lease_invalid", err)
	}
	file, err := assembly.OpenMember(root, name)
	if err != nil {
		return nil, historyError("lease_invalid", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			result = nil
			failure = joinHistoryCleanup(failure, err)
		}
	}()
	info, err := file.Stat()
	if err != nil || !hostReadMetadataEqual(before, info) || privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil {
		return nil, historyError("lease_invalid", err)
	}
	expected, err := historyBinding(bounded, owner, binding.RuntimeDigest, info)
	if err != nil {
		return nil, err
	}
	if expected.Scope != binding.Scope || expected.OwnerEnrollmentDigest != binding.EnrollmentDigest {
		return nil, historyError("binding_invalid", nil)
	}
	raw, _, err := readHistoryFile(bounded, root, expected.OwnerUID)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	record, err := decodeBootstrapHistory(raw, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	after, afterErr := root.Lstat(name)
	final, finalErr := file.Stat()
	if afterErr != nil || finalErr != nil || !hostReadMetadataEqual(info, after) || !hostReadMetadataEqual(info, final) || privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil || record.Binding != expected || record.LatestAttempt.InvocationID != binding.ColdInvocationID {
		return nil, historyError("binding_invalid", errors.Join(afterErr, finalErr))
	}
	if err := bounded.Err(); err != nil {
		return nil, historyError("context_invalid", err)
	}
	if !historyCreatorEligible(creator, binding) {
		return nil, historyError("binding_invalid", nil)
	}
	return historyRelevantFailure(record, time.Now().UTC()), nil
}

// This is historical receipt provenance, never current child liveness. An
// already-exited original child can still have published genuine terminal
// history within the original caller budget; no adoption follows from it.
func historyCreatorEligible(creator *protected.ReceiptHostProcess, binding protected.BootstrapReceiptBinding) bool {
	return creator != nil && creator.HasValidatedBootstrapReceipt(binding)
}

func historyRelevantFailure(record bootstrapHistoryRecord, now time.Time) *bootstrapHistoryFailure {
	terminal := record.LatestAttempt.Terminal
	if terminal == nil || terminal.Outcome != "failed" {
		return nil
	}
	completed, err := time.Parse(time.RFC3339Nano, terminal.CompletedAt)
	if err != nil || completed.After(now) || terminal.DiagnosticCode == nil || now.Sub(completed) > bootstrapHistoryRelevance {
		return nil
	}
	return &bootstrapHistoryFailure{record.LatestAttempt.InvocationID, terminal.CompletedAt, *terminal.DiagnosticCode, terminal.Cleanup}
}
