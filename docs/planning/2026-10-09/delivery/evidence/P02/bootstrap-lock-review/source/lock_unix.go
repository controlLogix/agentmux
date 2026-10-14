//go:build linux || darwin

package launcher

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// BootstrapLock holds an OS lock until Close. The file is never removed: another
// launcher may already hold a descriptor for the same inode.
type BootstrapLock struct {
	file      *os.File
	AttemptID string
}

// StartingElsewhereError identifies the observed owner without treating its
// metadata as authority. Unknown or malformed metadata stays unknown.
type StartingElsewhereError struct {
	AttemptID string
	Cause     error
}

func (e *StartingElsewhereError) Error() string { return "starting_elsewhere: " + e.AttemptID }
func (e *StartingElsewhereError) Unwrap() error { return e.Cause }

func waitingError(f *os.File, cause error) error {
	var buf [256]byte
	n, _ := f.ReadAt(buf[:], 0)
	var metadata struct {
		AttemptID string `json:"attemptId"`
	}
	attempt := "unknown"
	if json.Unmarshal(buf[:n], &metadata) == nil && len(metadata.AttemptID) == 32 {
		if decoded, err := hex.DecodeString(metadata.AttemptID); err == nil && len(decoded) == 16 {
			attempt = hex.EncodeToString(decoded)
		}
	}
	return &StartingElsewhereError{AttemptID: attempt, Cause: cause}
}

// AcquireBootstrapLock requires an existing, private, user-owned profile
// directory. The caller supplies its own bounded context. No PID or file age
// permits takeover; process exit releases the OS lock.
func AcquireBootstrapLock(ctx context.Context, profileDir, instanceID, contextFingerprint string) (*BootstrapLock, error) {
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("bootstrap_lock_deadline_missing")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if instanceID == "" || contextFingerprint == "" {
		return nil, errors.New("bootstrap_lock_identity_missing")
	}
	info, err := os.Lstat(profileDir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("bootstrap_profile_not_private")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("bootstrap_profile_wrong_owner")
	}
	identity := sha256.Sum256([]byte(instanceID + "\x00" + contextFingerprint))
	path := filepath.Join(profileDir, "bootstrap-"+hex.EncodeToString(identity[:])+".lock")
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errors.New("bootstrap_lock_open_failed")
	}
	f := os.NewFile(uintptr(fd), path)
	keep := false
	defer func() {
		if !keep {
			_ = f.Close()
		}
	}()
	fileInfo, err := f.Stat()
	if err != nil || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm()&0077 != 0 {
		return nil, errors.New("bootstrap_lock_not_private_file")
	}
	fileOwner, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok || fileOwner.Uid != uint32(os.Geteuid()) || fileOwner.Nlink != 1 {
		return nil, errors.New("bootstrap_lock_wrong_owner")
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, waitingError(f, err)
		}
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN && err != syscall.EINTR {
			return nil, errors.New("bootstrap_lock_failed")
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, waitingError(f, ctx.Err())
		case <-timer.C:
		}
	}
	// Check the path still identifies the locked file before changing metadata.
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(fileInfo, current) {
		return nil, errors.New("bootstrap_lock_identity_changed")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errors.New("bootstrap_attempt_id_failed")
	}
	attempt := hex.EncodeToString(nonce[:])
	metadata, _ := json.Marshal(struct {
		AttemptID string `json:"attemptId"`
	}{attempt})
	if err := f.Truncate(0); err != nil {
		return nil, errors.New("bootstrap_lock_metadata_failed")
	}
	if _, err := f.WriteAt(append(metadata, '\n'), 0); err != nil {
		return nil, errors.New("bootstrap_lock_metadata_failed")
	}
	if err := f.Sync(); err != nil {
		return nil, errors.New("bootstrap_lock_metadata_failed")
	}
	keep = true
	return &BootstrapLock{file: f, AttemptID: attempt}, nil
}

// Close releases only this descriptor; it never deletes or steals a lock file.
func (l *BootstrapLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	f := l.file
	l.file = nil
	return f.Close()
}
