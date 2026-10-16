//go:build darwin

package launcher

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fixedArchiveChildHandles(t *testing.T, dir string) []*dockerDarwinChildObservation {
	t.Helper()
	var handles []*dockerDarwinChildObservation
	deadline := time.Now().Add(time.Second)
	for _, name := range []string{"private.conf", "server-cert.pem", "server-key.pem"} {
		var raw []byte
		for {
			var err error
			raw, err = os.ReadFile(filepath.Join(dir, "started-"+name))
			if err == nil && len(raw) > 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("owned archive child handshake unavailable")
			}
			time.Sleep(time.Millisecond)
		}
		pid, err := strconv.Atoi(string(raw))
		if err != nil || pid <= 0 {
			t.Fatal("invalid owned child handshake")
		}
		handles = append(handles, dockerDarwinObserveChild(t, pid))
	}
	return handles
}

func assertFixedArchiveChildrenExited(t *testing.T, handles []*dockerDarwinChildObservation) {
	t.Helper()
	dockerDarwinAssertChildrenExited(t, handles, "archive helper returned before owned child exit")
}

func TestFixedTLSArchiveFailureCancelsAndJoinsActualChildren(t *testing.T) {
	driver, _, dir := fixedArchiveSetup(t, "cancel")
	a, b, c := fixedArchiveDigests()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	finished := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("controlled archive verification cleanup did not join")
		}
	})
	go func() {
		defer close(finished)
		result <- driver.verifyOwnedTLSArchives(ctx, instanceID(), a, b, c)
	}()
	handles := fixedArchiveChildHandles(t, dir)
	if os.WriteFile(filepath.Join(dir, "release-failure"), []byte("release"), 0600) != nil {
		t.Fatal("controlled failure release unavailable")
	}
	select {
	case err := <-result:
		if err == nil || err.Error() != "docker_broker_tls_file_mismatch" || strings.Contains(err.Error(), "synthetic-private") {
			t.Fatal("invalid archive failure lost or leaked", err)
		}
	case <-ctx.Done():
		t.Fatal("sibling cancellation exceeded original deadline")
	}
	assertFixedArchiveChildrenExited(t, handles)
}

func TestFixedTLSArchiveDeadlineJoinsActualChildren(t *testing.T) {
	driver, _, dir := fixedArchiveSetup(t, "deadline")
	a, b, c := fixedArchiveDigests()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	finished := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("controlled archive verification cleanup did not join")
		}
	})
	go func() {
		defer close(finished)
		result <- driver.verifyOwnedTLSArchives(ctx, instanceID(), a, b, c)
	}()
	handles := fixedArchiveChildHandles(t, dir)
	select {
	case err := <-result:
		if err == nil || err.Error() != "docker_command_timeout_outcome_unknown" {
			t.Fatal("deadline error missing", err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not join archive children")
	}
	assertFixedArchiveChildrenExited(t, handles)
}
