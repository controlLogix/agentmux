//go:build linux && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestComposeCLICreatorObservationChild(t *testing.T) {
	if os.Getenv("AMX_CREATOR_OBSERVATION_CHILD") != "1" {
		return
	}
	var b [1]byte
	n, err := os.Stdin.Read(b[:])
	if n != 0 || err != io.EOF {
		t.Fatal("owned child did not receive input EOF")
	}
}

func TestComposeCLICreatorObservation(t *testing.T) {
	// This original lifecycle budget covers Start, observation, cancellation and Wait.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestComposeCLICreatorObservationChild$")
	cmd.Env = append(os.Environ(), "AMX_CREATOR_OBSERVATION_CHILD=1")
	input, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal("owned child input unavailable")
	}
	inputClosed := false
	closeInput := func() error {
		if inputClosed {
			return nil
		}
		inputClosed = true // Close consumes this fixture-owned handle, including errors.
		return input.Close()
	}
	if err = cmd.Start(); err != nil {
		closeErr := closeInput()
		cancel()
		if closeErr != nil {
			t.Error("failed-start owned input cleanup failed")
		}
		t.Fatal("owned child start failed")
	}
	fd := -1
	waited := false
	t.Cleanup(func() {
		if closeInput() != nil {
			t.Error("owned child input cleanup failed")
		}
		if !waited {
			waitErr := cmd.Wait()
			waited = true
			if waitErr != nil {
				// Only cancellation of this exact fixture-owned child may explain cleanup exit.
				var exit *exec.ExitError
				canceledExit := false
				if ctx.Err() != nil && errors.As(waitErr, &exit) {
					status, ok := exit.Sys().(syscall.WaitStatus)
					canceledExit = ok && status.Signaled() && status.Signal() == syscall.SIGKILL
				}
				if !canceledExit {
					t.Error("owned child cleanup wait failed")
				}
			}
		}
		if fd >= 0 {
			owned := fd
			fd = -1
			if unix.Close(owned) != nil {
				t.Error("owned child handle cleanup failed")
			}
		}
		cancel()
	})
	fd, err = unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		t.Fatal("owned child handle unavailable")
	}
	x := &composeCLIFront{hostFD: fd, hostAttempt: "attempt_0123456789abcdef0123456789abcdef"}
	liveFacts := composeCLICreatorPollObservation(x)
	if liveFacts.Result != "live" || !liveFacts.Performed || liveFacts.Count == nil || *liveFacts.Count != 0 || liveFacts.Revents == nil || *liveFacts.Revents != 0 || liveFacts.ErrnoCategory != "none" {
		t.Fatal("actual live child facts rejected")
	}
	raw, encodeErr := json.Marshal(liveFacts)
	if encodeErr != nil || strings.Contains(string(raw), x.hostAttempt) || strings.Contains(string(raw), "hostFD") {
		t.Fatal("creator poll facts exposed identity")
	}

	absent := composeCLICreatorPollObservation(nil)
	if absent.Result != "not_provided" || absent.Performed || absent.Count != nil || absent.Revents != nil || absent.ErrnoCategory != "not_observed" {
		t.Fatal("missing creator was observed")
	}

	bad := composeCLIFront{hostFD: x.hostFD, hostAttempt: "malformed"}
	malformed := composeCLICreatorPollObservation(&bad)
	if malformed.Result != "creator_host_observation_unknown" || malformed.Performed || malformed.Count != nil || malformed.Revents != nil || malformed.ErrnoCategory != "not_observed" {
		t.Fatal("malformed creator was observed")
	}

	if closeInput() != nil {
		t.Fatal("owned child input close failed")
	}
	// Leave the child unreaped until the borrowed-handle observation completes.
	fact := liveFacts
	for fact.Result == "live" && ctx.Err() == nil {
		fact = composeCLICreatorPollObservation(x)
		if fact.Result == "live" {
			time.Sleep(time.Millisecond)
		}
	}
	if fact.Result != "creator_host_exited" || !fact.Performed || fact.Count == nil || *fact.Count != 1 || fact.Revents == nil || *fact.Revents != uint16(unix.POLLIN) || fact.ErrnoCategory != "none" {
		t.Fatal("actual unreaped child facts rejected")
	}

	err = cmd.Wait()
	waited = true
	if err != nil {
		t.Fatal("owned child wait failed")
	}
	owned := fd
	fd = -1
	x.hostFD = -1 // The consumed descriptor must never be closed or reused again.
	if unix.Close(owned) != nil {
		t.Fatal("owned child handle close failed")
	}
	consumed := composeCLICreatorPollObservation(x)
	if consumed.Result != "creator_host_observation_unknown" || consumed.Performed || consumed.Count != nil || consumed.Revents != nil || consumed.ErrnoCategory != "not_observed" {
		t.Fatal("consumed handle was observed")
	}

}
