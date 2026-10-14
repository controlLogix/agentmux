//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/controlLogix/agentmux/platform/privatefs"
)

// Only a file created by this store's fixed staging operation can occupy this
// slot. The held root and recorded inode are cleanup authority, not its name.
type historyOwnedStage struct {
	name   string
	file   *os.File
	info   os.FileInfo
	closed bool
}

// This error retains the concrete store until its exact staged object is
// resolved. No arbitrary closer, path, descriptor or process is accepted.
type historyStageCleanupError struct {
	store *bootstrapHistoryStore
	cause error
}

func (historyStageCleanupError) Error() string                  { return "bootstrap_history_cleanup_failed" }
func (e historyStageCleanupError) Format(s fmt.State, _ rune)   { fmt.Fprint(s, e.Error()) }
func (e historyStageCleanupError) MarshalJSON() ([]byte, error) { return json.Marshal(e.Error()) }
func (e historyStageCleanupError) Unwrap() error                { return e.cause }
func (e *historyStageCleanupError) Close(ctx context.Context) error {
	if e == nil || e.store == nil {
		return historyError("state_invalid", nil)
	}
	return e.store.Close(ctx)
}
func (s *bootstrapHistoryStore) stageFailure(cause error) error {
	if s.state.stage == nil {
		return cause
	}
	return &historyStageCleanupError{store: s, cause: cause}
}
func (s *bootstrapHistoryStore) mutationReady(ctx context.Context) error {
	if ctx == nil {
		return historyError("context_invalid", nil)
	}
	if err := ctx.Err(); err != nil {
		return historyError("context_invalid", err)
	}
	if err := s.guard.check(ctx, s.root); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return historyError("context_invalid", err)
	}
	return nil
}
func (s *bootstrapHistoryStore) createStage(ctx context.Context, tempName string) (*os.File, error) {
	if s.state.stage != nil {
		return nil, s.stageFailure(historyError("state_invalid", nil))
	}
	if err := s.mutationReady(ctx); err != nil {
		return nil, err
	}
	file, err := s.root.OpenFile(tempName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if file != nil {
		s.state.stage = &historyOwnedStage{name: tempName, file: file}
	}
	if err != nil {
		return nil, s.stageFailure(historyError("publication_failed", err))
	}
	info, err := file.Stat()
	s.state.stage.info = info
	if err != nil || !privateProfileInfo(info, s.binding.OwnerUID, false) || privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil {
		return nil, s.stageFailure(historyError("publication_failed", err))
	}
	if err := ctx.Err(); err != nil {
		return nil, s.stageFailure(historyError("context_invalid", err))
	}
	return file, nil
}

// Removal is confined to the original held root. Current profile replacement
// cannot authorize new writes, but does not erase ownership of our old stage.
func (s *bootstrapHistoryStore) cleanupStage(ctx context.Context) error {
	stage := s.state.stage
	if stage == nil {
		return nil
	}
	if ctx == nil {
		return s.stageFailure(historyError("context_invalid", nil))
	}
	if err := ctx.Err(); err != nil {
		return s.stageFailure(historyError("context_invalid", err))
	}
	held, err := s.root.Stat(".")
	if err != nil || s.guard == nil || !os.SameFile(s.guard.rootInfo, held) || !privateProfileInfo(held, s.binding.OwnerUID, true) {
		return s.stageFailure(historyError("cleanup_failed", err))
	}
	directory, err := s.root.Open(".")
	if err != nil {
		return s.stageFailure(historyError("cleanup_failed", err))
	}
	aclErr := privatefs.CheckDescriptor(directory, privatefs.PrivateObject)
	closeErr := directory.Close()
	if aclErr != nil || closeErr != nil {
		return s.stageFailure(historyError("cleanup_failed", errors.Join(aclErr, closeErr)))
	}
	if stage.info == nil && !stage.closed {
		stage.info, err = stage.file.Stat()
		if err != nil {
			return s.stageFailure(historyError("cleanup_failed", err))
		}
	}
	if stage.info == nil {
		return s.stageFailure(historyError("cleanup_failed", nil))
	}
	// os.File.Close invalidates its handle even on error. Never retry it.
	var fileCloseErr error
	if !stage.closed {
		fileCloseErr = stage.file.Close()
		stage.closed = true
	}
	if err := ctx.Err(); err != nil {
		return s.stageFailure(errors.Join(historyError("context_invalid", err), historyErrorIfClose(fileCloseErr)))
	}
	current, err := s.root.Lstat(stage.name)
	if os.IsNotExist(err) {
		s.state.stage = nil
		return historyErrorIfClose(fileCloseErr)
	}
	if err != nil || !os.SameFile(stage.info, current) || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() {
		return s.stageFailure(errors.Join(historyError("cleanup_failed", err), historyErrorIfClose(fileCloseErr)))
	}
	stat, ok := current.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != s.binding.OwnerUID || current.Mode().Perm()&0077 != 0 || stat.Nlink > 2 {
		return s.stageFailure(errors.Join(historyError("cleanup_failed", nil), historyErrorIfClose(fileCloseErr)))
	}
	if err := ctx.Err(); err != nil {
		return s.stageFailure(errors.Join(historyError("context_invalid", err), historyErrorIfClose(fileCloseErr)))
	}
	if err := s.root.Remove(stage.name); err != nil {
		return s.stageFailure(errors.Join(historyError("cleanup_failed", err), historyErrorIfClose(fileCloseErr)))
	}
	// A changed object is retained/refused; never delete a replacement merely
	// because the original removal succeeded.
	if _, err := s.root.Lstat(stage.name); !os.IsNotExist(err) {
		return s.stageFailure(errors.Join(historyError("cleanup_failed", err), historyErrorIfClose(fileCloseErr)))
	}
	s.state.stage = nil
	return historyErrorIfClose(fileCloseErr)
}
func historyErrorIfClose(err error) error {
	if err == nil {
		return nil
	}
	return historyError("cleanup_failed", err)
}

// retirePublication is called only by the sole Run publication producer after
// its synchronous publication call returns. TryLock refuses an active call.
// It releases only the history duplicate; root/stage cleanup remains owned.
func (s *bootstrapHistoryStore) retirePublication() (bool, error) {
	if s == nil || s.state == nil {
		return true, nil
	}
	if !s.state.mu.TryLock() {
		return false, historyError("state_invalid", nil)
	}
	defer s.state.mu.Unlock()
	s.state.publishingClosed = true
	if !s.state.leaseClosed && s.leaseFile != nil {
		closeErr := s.leaseFile.Close()
		s.state.leaseClosed = true
		s.state.closeFailure = errors.Join(s.state.closeFailure, historyErrorIfClose(closeErr))
	}
	return true, s.state.closeFailure
}
