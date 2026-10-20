//go:build linux || darwin

package runtime

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"
)

type refusedInstalledHostImage struct{ validated, closed bool }

func (i *refusedInstalledHostImage) command([]string) *exec.Cmd {
	return exec.Command("/not-an-installed-host")
}

func TestInstalledHostCanceledWhileImageLocked(t *testing.T) {
	host := &InstalledHostImage{image: &refusedInstalledHostImage{}}
	host.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := host.StartHost(ctx, HostInvocation{PolicyPath: "/private/policy", InvocationID: "attempt_00000000000000000000000000000000", WorkspaceRoots: []string{"/work"}})
		done <- err
	}()
	select {
	case err := <-done:
		host.mu.Unlock()
		if err == nil || err.Error() != "installed_host_start_cancelled" {
			t.Fatal("blocked start did not report caller cancellation")
		}
	case <-time.After(150 * time.Millisecond):
		host.mu.Unlock()
		<-done
		t.Fatal("blocked image lock ignored caller cancellation")
	}
	host.Close()
}
func (i *refusedInstalledHostImage) close() error { i.closed = true; return nil }
func (i *refusedInstalledHostImage) validateForStart(context.Context) error {
	i.validated = true
	return errors.New("controlled_protected_image_change")
}

func TestInstalledHostRevalidatesHeldImageBeforeSpawn(t *testing.T) {
	image := &refusedInstalledHostImage{}
	host := &InstalledHostImage{image: image}
	if child, err := host.StartHost(context.Background(), HostInvocation{PolicyPath: "/private/policy", InvocationID: "attempt_00000000000000000000000000000000", WorkspaceRoots: []string{"/work"}}); err == nil || child != nil || err.Error() != "installed_host_image_changed" {
		t.Fatal("failed protected validation reached process spawn")
	}
	if !image.validated || image.closed || host.consumed {
		t.Fatal("refusal lost the retained image")
	}
	if host.Close() != nil || !image.closed {
		t.Fatal("held image was not closed by its owner")
	}
}

func TestInstalledHostRecheckKeepsAdmissionUntilExplicitClose(t *testing.T) {
	image := &refusedInstalledHostImage{}
	host := &InstalledHostImage{image: image}
	err := host.Recheck(context.Background())
	if err == nil || !image.validated || image.closed || host.consumed || host.image != image {
		t.Fatal("host recheck lost or consumed the changed image")
	}
	if host.Close() != nil || !image.closed || host.Recheck(context.Background()) == nil {
		t.Fatal("closed host admission was reused")
	}
}

func TestInstalledHostRecheckCancellationKeepsLockedOwner(t *testing.T) {
	image := &refusedInstalledHostImage{}
	host := &InstalledHostImage{image: image}
	host.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- host.Recheck(ctx) }()
	select {
	case err := <-done:
		host.mu.Unlock()
		if err == nil || image.validated || image.closed || host.consumed {
			t.Fatal("cancelled recheck consumed or validated a locked image")
		}
	case <-time.After(150 * time.Millisecond):
		host.mu.Unlock()
		<-done
		t.Fatal("recheck ignored cancellation while its owner was locked")
	}
	if host.Close() != nil || !image.closed {
		t.Fatal("cancelled recheck lost the original close owner")
	}
}
