//go:build darwin && cgo

package launcher

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func setOwnedLockACL(t *testing.T, path string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/chmod", "+a", "everyone allow read,write", path)
	cmd.WaitDelay = time.Second
	if cmd.Run() != nil {
		t.Fatal("owned native ACL fixture operation failed")
	}
}

func TestDarwinLockRefusesGrantingDirectoryACLBeforeCreatingLease(t *testing.T) {
	dir := privateLockDirectory(t)
	setOwnedLockACL(t, dir)
	lock, err := AcquireBootstrapLock(boundedLockContext(t), dir, "instance", "context")
	if lock != nil {
		_ = lock.Close()
		t.Fatal("granting directory ACL accepted")
	}
	entries, readErr := os.ReadDir(dir)
	if err == nil || readErr != nil || len(entries) != 0 {
		t.Fatal("directory ACL refusal changed the profile")
	}
}

func TestDarwinLockRefusesGrantingFileACLWithoutChangingMetadata(t *testing.T) {
	dir := privateLockDirectory(t)
	owner, err := AcquireBootstrapLock(boundedLockContext(t), dir, "instance", "context")
	if err != nil {
		t.Fatal(err)
	}
	path := lockPath(t, dir)
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	setOwnedLockACL(t, path)
	lock, err := AcquireBootstrapLock(boundedLockContext(t), dir, "instance", "context")
	if lock != nil {
		_ = lock.Close()
		t.Fatal("granting file ACL accepted")
	}
	after, readErr := os.ReadFile(path)
	if err == nil || readErr != nil || string(before) != string(after) {
		t.Fatal("file ACL refusal changed owner metadata")
	}
}
