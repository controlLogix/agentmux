//go:build linux || darwin

package launcher

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLockWaitsForDescriptorAndRetainsIdentity(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	first, err := AcquireBootstrapLock(boundedLockContext(t), dir, "instance", "context")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	entries, _ := os.ReadDir(dir)
	path := filepath.Join(dir, entries[0].Name())
	before, _ := os.Stat(path)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	_, err = AcquireBootstrapLock(ctx, dir, "instance", "context")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contender stole lock: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := AcquireBootstrapLock(boundedLockContext(t), dir, "instance", "context")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	after, _ := os.Stat(path)
	if !os.SameFile(before, after) || first.AttemptID == second.AttemptID {
		t.Fatal("lock inode or attempt identity incorrect")
	}
}

func TestLockRejectsPublicDirectoryAndSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireBootstrapLock(boundedLockContext(t), dir, "i", "c"); err == nil {
		t.Fatal("accepted public profile")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "linked-profile")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireBootstrapLock(boundedLockContext(t), link, "i", "c"); err == nil {
		t.Fatal("accepted linked profile")
	}
}

func boundedLockContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func lockPath(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected one lock file: %v %v", entries, err)
	}
	return filepath.Join(dir, entries[0].Name())
}

func privateLockDirectory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLockRequiresFiniteDeadline(t *testing.T) {
	dir := privateLockDirectory(t)
	lock, err := AcquireBootstrapLock(context.Background(), dir, "instance", "context")
	if lock != nil {
		_ = lock.Close()
		t.Fatal("unbounded lock acquisition accepted")
	}
	if err == nil || err.Error() != "bootstrap_lock_deadline_missing" {
		t.Fatalf("missing deadline was not rejected: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("missing deadline changed profile: %v %v", entries, err)
	}
}

func TestLockRefusesFileAliasesWithoutChangingTarget(t *testing.T) {
	for _, alias := range []string{"symlink", "hardlink"} {
		t.Run(alias, func(t *testing.T) {
			dir := privateLockDirectory(t)
			owner, err := AcquireBootstrapLock(boundedLockContext(t), dir, "instance", "context")
			if err != nil {
				t.Fatal(err)
			}
			path := lockPath(t, dir)
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			// Replacing a closed fixture inode sets up a hostile alias; production never unlinks.
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(privateLockDirectory(t), "target")
			const sentinel = "target must remain intact\n"
			if err := os.WriteFile(target, []byte(sentinel), 0600); err != nil {
				t.Fatal(err)
			}
			if alias == "symlink" {
				err = os.Symlink(target, path)
			} else {
				err = os.Link(target, path)
			}
			if err != nil {
				t.Fatal(err)
			}
			lock, err := AcquireBootstrapLock(boundedLockContext(t), dir, "instance", "context")
			if lock != nil {
				_ = lock.Close()
				t.Fatal("accepted aliased lock file")
			}
			if err == nil {
				t.Fatal("alias did not cause rejection")
			}
			actual, err := os.ReadFile(target)
			if err != nil || string(actual) != sentinel {
				t.Fatalf("alias target changed: %q %v", actual, err)
			}
		})
	}
}

func TestLockWaitReportsOwnerAndPreservesMetadata(t *testing.T) {
	dir := privateLockDirectory(t)
	owner, err := AcquireBootstrapLock(boundedLockContext(t), dir, "instance", "context")
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	path := lockPath(t, dir)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		AttemptID string `json:"attemptId"`
	}
	if err := json.Unmarshal(before, &metadata); err != nil || metadata.AttemptID != owner.AttemptID {
		t.Fatalf("owner metadata mismatch: %v", err)
	}
	for _, cancellation := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
		if cancellation {
			cancel()
		}
		_, err := AcquireBootstrapLock(ctx, dir, "instance", "context")
		cancel()
		cause := context.DeadlineExceeded
		if cancellation {
			cause = context.Canceled
		}
		var waiting *StartingElsewhereError
		if !errors.Is(err, cause) || !errors.As(err, &waiting) || waiting.AttemptID != owner.AttemptID {
			t.Fatalf("wait did not report the actual owner and cause: %v", err)
		}
		after, readErr := os.ReadFile(path)
		if readErr != nil || string(before) != string(after) {
			t.Fatalf("contender changed metadata: %v", readErr)
		}
	}
}

func TestLockDoesNotTrustMalformedOwnerMetadata(t *testing.T) {
	for _, payload := range []string{`{"attemptId":"raw-private-value"}`, `not json`, `{"attemptId":"1234"}`} {
		t.Run(payload[:4], func(t *testing.T) {
			dir := privateLockDirectory(t)
			owner, err := AcquireBootstrapLock(boundedLockContext(t), dir, "instance", "context")
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			if err := owner.file.Truncate(0); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.file.WriteAt([]byte(payload), 0); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
			defer cancel()
			_, err = AcquireBootstrapLock(ctx, dir, "instance", "context")
			var waiting *StartingElsewhereError
			if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &waiting) || waiting.AttemptID != "unknown" {
				t.Fatalf("malformed metadata became owner identity: %v", err)
			}
			if strings.Contains(err.Error(), payload) || strings.Contains(err.Error(), "raw-private-value") {
				t.Fatal("raw metadata leaked into diagnostic")
			}
		})
	}
}

// This subprocess helper acquires a real descriptor lock, then waits for its parent to kill it.
func TestLockChildOwner(t *testing.T) {
	if os.Getenv("AGENTMUX_LOCK_CHILD") != "1" {
		return
	}
	owner, err := AcquireBootstrapLock(boundedLockContext(t), os.Getenv("AGENTMUX_LOCK_DIR"), "instance", "context")
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if _, err := os.Stdout.WriteString(owner.AttemptID + "\n"); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Second)
	}
}

func TestKilledChildReleasesLockWithoutRemovingIdentity(t *testing.T) {
	dir := privateLockDirectory(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockChildOwner$", "-test.timeout=15s")
	cmd.Env = append(os.Environ(), "AGENTMUX_LOCK_CHILD=1", "AGENTMUX_LOCK_DIR="+dir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			ready <- scanner.Text()
		} else {
			ready <- ""
		}
	}()
	var attempt string
	select {
	case attempt = <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("child did not acquire lock within deadline")
	}
	if len(attempt) != 32 {
		t.Fatalf("child readiness lacks attempt ID: %q", attempt)
	}
	path := lockPath(t, dir)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	_, err = AcquireBootstrapLock(ctx, dir, "instance", "context")
	cancel()
	var waiting *StartingElsewhereError
	if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &waiting) || waiting.AttemptID != attempt {
		t.Fatalf("real child lock was stolen or owner missing: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("killed child unexpectedly exited successfully")
	}
	waited = true
	owner, err := AcquireBootstrapLock(boundedLockContext(t), dir, "instance", "context")
	if err != nil {
		t.Fatalf("dead child still owns lock: %v", err)
	}
	defer owner.Close()
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) || owner.AttemptID == attempt {
		t.Fatalf("recovery changed inode or reused attempt ID: %v", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal("Close is not idempotent")
	}
}

func TestLockNormalizesObservedAttemptWithoutGrantingOwnership(t *testing.T) {
	dir := privateLockDirectory(t)
	owner, err := AcquireBootstrapLock(boundedLockContext(t), dir, "instance", "context")
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	const payload = `{"attemptId":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`
	if err := owner.file.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.file.WriteAt([]byte(payload), 0); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	lock, err := AcquireBootstrapLock(ctx, dir, "instance", "context")
	var waiting *StartingElsewhereError
	if lock != nil || !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &waiting) || waiting.AttemptID != strings.Repeat("a", 32) {
		t.Fatalf("observed metadata changed ownership or was not normalized: %v", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := AcquireBootstrapLock(boundedLockContext(t), dir, "instance", "context")
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if next.AttemptID == strings.Repeat("a", 32) || next.AttemptID == owner.AttemptID {
		t.Fatal("new acquisition reused stale observed metadata")
	}
}

func TestCancelledUnownedLockDoesNotAcquireOrWriteAttempt(t *testing.T) {
	dir := privateLockDirectory(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	cancel()
	lock, err := AcquireBootstrapLock(ctx, dir, "instance", "context")
	var waiting *StartingElsewhereError
	if lock != nil || !errors.Is(err, context.Canceled) || !errors.As(err, &waiting) || waiting.AttemptID != "unknown" {
		t.Fatalf("cancelled acquisition succeeded: %v", err)
	}
	// Opening a cancelled request may leave an empty private file; it must not write an attempt.
	data, err := os.ReadFile(lockPath(t, dir))
	if err != nil || len(data) != 0 {
		t.Fatalf("cancelled request wrote owner metadata: %v", err)
	}
	next, err := AcquireBootstrapLock(boundedLockContext(t), dir, "instance", "context")
	if err != nil {
		t.Fatalf("cancelled request retained a descriptor lock: %v", err)
	}
	defer next.Close()
}

func TestLockMissingOrNonDirectoryProfileReturnsError(t *testing.T) {
	dir := privateLockDirectory(t)
	file := filepath.Join(dir, "ordinary-file")
	if err := os.WriteFile(file, []byte("intact"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(dir, "missing"), file} {
		lock, err := AcquireBootstrapLock(boundedLockContext(t), path, "instance", "context")
		if lock != nil || err == nil || err.Error() != "bootstrap_profile_not_private" {
			t.Fatalf("invalid profile was accepted: %v", err)
		}
	}
}

func TestLockWaitHasHardMaximum(t *testing.T) {
	dir := privateLockDirectory(t)
	owner, err := AcquireBootstrapLock(boundedLockContext(t), dir, "instance", "context")
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	started := time.Now()
	lock, err := AcquireBootstrapLock(ctx, dir, "instance", "context")
	elapsed := time.Since(started)
	var waiting *StartingElsewhereError
	if lock != nil || !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &waiting) || waiting.AttemptID != owner.AttemptID {
		t.Fatalf("maximum wait did not return owner timeout: %v", err)
	}
	if elapsed < 29*time.Second || elapsed > 35*time.Second {
		t.Fatalf("30-second limit was not enforced: %v", elapsed)
	}
	if ctx.Err() != nil {
		t.Fatal("test caller deadline expired before implementation maximum")
	}
}
