//go:build linux

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const parentHelperSource = `package main
import("context";"encoding/json";"os";"strconv";"time"; protected "github.com/controlLogix/agentmux/platform/runtime")
func main(){ctx,cleanup,err:=protected.ParentLifetime(context.Background());if err!=nil{os.Exit(2)};defer cleanup();parent,_:=strconv.Atoi(os.Getenv("AGENTMUX_KERNEL_PARENT_FD"));lease,_:=strconv.Atoi(os.Getenv("AGENTMUX_KERNEL_LEASE_FD"));json.NewEncoder(os.Stdout).Encode(map[string]any{"ready":true,"parentFD":parent,"leaseFD":lease});select{case <-ctx.Done():case <-time.After(5*time.Second):os.Exit(7)}}`

func parentHelper(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	source := filepath.Join(directory, "main.go")
	binary := filepath.Join(directory, "parent-role")
	if os.WriteFile(source, []byte(parentHelperSource), 0600) != nil {
		t.Fatal("parent fixture source unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(goruntime.GOROOT(), "bin", "go"), "build", "-o", binary, source)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOENV=off")
	if output, err := cmd.CombinedOutput(); err != nil {
		_ = os.WriteFile(filepath.Join(directory, "build.log"), output, 0600)
		t.Fatal("parent fixture build failed")
	}
	return binary
}

func TestParentLifetimeRejectsInvalidDescriptors(t *testing.T) {
	for _, value := range []string{"", "2", "-1", "04", "100000", "invalid"} {
		t.Setenv("AGENTMUX_KERNEL_PARENT_FD", value)
		if _, _, err := ParentLifetime(context.Background()); err == nil {
			t.Fatal("invalid descriptor accepted")
		}
	}
	file, err := os.CreateTemp(t.TempDir(), "regular")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	t.Setenv("AGENTMUX_KERNEL_PARENT_FD", strconv.Itoa(int(file.Fd())))
	if _, _, err := ParentLifetime(context.Background()); err == nil {
		t.Fatal("regular descriptor accepted")
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	t.Setenv("AGENTMUX_KERNEL_PARENT_FD", strconv.Itoa(int(writer.Fd())))
	if _, _, err := ParentLifetime(context.Background()); err == nil {
		t.Fatal("write descriptor accepted")
	}
	if _, _, err := ParentLifetime(nil); err == nil {
		t.Fatal("nil parent context accepted")
	}
}

func TestParentLifetimeEOFBytesAndCancelledReadJoin(t *testing.T) {
	for _, kind := range []string{"eof", "bytes", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			fd, err := unix.FcntlInt(reader.Fd(), unix.F_DUPFD_CLOEXEC, 0)
			if err != nil {
				t.Fatal("pipe duplication failed")
			}
			t.Setenv("AGENTMUX_KERNEL_PARENT_FD", strconv.Itoa(fd))
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx, cleanup, err := ParentLifetime(parent)
			if err != nil {
				unix.Close(fd)
				t.Fatal(err)
			}
			switch kind {
			case "eof":
				writer.Close()
			case "bytes":
				writer.Write([]byte("unexpected"))
			case "cancel":
				cancel()
			}
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("parent lifetime did not cancel")
			}
			done := make(chan struct{})
			go func() { cleanup(); cleanup(); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("reader cleanup did not join")
			}
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
				t.Fatal("owned reader remains open")
			}
		})
	}
}

func TestParentLeaseValidationAndDuplication(t *testing.T) {
	file, err := os.OpenFile(filepath.Join(t.TempDir(), "lease"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		t.Fatal("fixture lock unavailable")
	}
	reader, writer, copy, err := prepareChildLifetime(file)
	if err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(copy.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("lease duplicate is not close-on-exec")
	}
	if err := closeChildStartFiles(reader, writer, copy); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Stat(); err != nil {
		t.Fatal("caller lease was closed")
	}
	os.Chmod(file.Name(), 0644)
	if validateLifetimeLease(file) == nil {
		t.Fatal("public lease accepted")
	}
	os.Chmod(file.Name(), 0600)
	file.Close()
	if validateLifetimeLease(file) == nil {
		t.Fatal("closed lease accepted")
	}
	reader, writer, err = os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if validateLifetimeLease(reader) == nil {
		t.Fatal("pipe accepted as regular lease")
	}
}

func TestParentEOFStopsActualChild(t *testing.T) {
	binary := parentHelper(t)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	cmd := exec.Command(binary)
	cmd.ExtraFiles = []*os.File{reader}
	cmd.Env = []string{"AGENTMUX_KERNEL_PARENT_FD=3"}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Start() != nil {
		t.Fatal("parent fixture start failed")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait(); close(done) }()
	defer func() { _ = cmd.Process.Kill(); <-done }()
	reader.Close()
	var ready map[string]any
	if json.NewDecoder(output).Decode(&ready) != nil || ready["ready"] != true {
		t.Fatal("actual child did not validate parent descriptor")
	}
	writer.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("actual child did not exit on parent EOF")
		}
	case <-time.After(2 * time.Second):
		cmd.Process.Kill()
		<-done
		t.Fatal("actual child ignored parent EOF")
	}
}

func TestParentInheritedLeasesLastUntilOwnedReap(t *testing.T) {
	binary := parentHelper(t)
	root, raw, trust, opts := releaseFixture(t)
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	json.Unmarshal(raw, &document)
	paths := map[string]string{}
	for i, role := range opts {
		if os.WriteFile(filepath.Join(root, role.ID), data, 0700) != nil {
			t.Fatal("role fixture unavailable")
		}
		document["plugins"].([]any)[i].(map[string]any)["binaryDigest"] = hash(data)
		path := filepath.Join(root, "lease-"+role.ID)
		lease, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { lease.Close() })
		if unix.Flock(int(lease.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
			t.Fatal("role lease acquisition failed")
		}
		opts[i].LifetimeLease = lease
		opts[i].Args = nil
		paths[role.ID] = path
	}
	raw, _ = json.Marshal(document)
	trust.AssemblyDigest = hash(raw)
	g, err := prepared(t, root, raw, trust).Start(context.Background(), opts, budgets())
	if err != nil {
		t.Fatal(err)
	}
	defer stop(t, g)
	end := time.Now().Add(2 * time.Second)
	for time.Now().Before(end) {
		ready := 0
		for _, role := range opts {
			out, _ := g.Output(role.ID)
			var value map[string]any
			if json.Unmarshal([]byte(strings.TrimSpace(string(out))), &value) == nil && value["ready"] == true {
				if value["parentFD"] != float64(4) || value["leaseFD"] != float64(5) {
					t.Fatal("forced descriptor slots changed")
				}
				ready++
			}
		}
		if ready == 4 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	for _, role := range opts {
		out, _ := g.Output(role.ID)
		if !strings.Contains(string(out), `"ready":true`) {
			t.Fatal("leased real role did not become ready")
		}
		if _, err := role.LifetimeLease.Stat(); err != nil {
			t.Fatal("runtime closed caller lease")
		}
		role.LifetimeLease.Close()
		assertLease(t, paths[role.ID], false)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := g.StopRole(ctx, "boot"); err != nil {
		t.Fatal(err)
	}
	for _, role := range opts {
		assertLease(t, paths[role.ID], role.ID == "boot")
	}
	stop(t, g)
	if err := g.CleanupError(); err != nil {
		t.Fatal(err)
	}
	for _, role := range opts {
		assertLease(t, paths[role.ID], true)
	}
}

func assertLease(t *testing.T, path string, free bool) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal("lease observer unavailable")
	}
	defer file.Close()
	err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if free && err != nil {
		t.Fatal("reaped child retained lease")
	}
	if !free && err == nil {
		t.Fatal("live child did not retain lease")
	}
	if !free && err != unix.EWOULDBLOCK && err != unix.EAGAIN {
		t.Fatal("lease contention was not observed")
	}
}

func TestParentCleanupErrorSurfacesAfterReap(t *testing.T) {
	root, raw, trust, opts := releaseFixture(t)
	g, err := prepared(t, root, raw, trust).Start(context.Background(), opts, budgets())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = g.Stop(ctx)
		select {
		case <-g.Done():
		default:
			t.Error("fault fixture did not reap all owned children")
		}
	}()
	observations(t, g)
	// Close one actually owned writer early to exercise the real close failure.
	if g.children[0].parentWriter.Close() != nil {
		t.Fatal("fixture writer close failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if g.Stop(ctx) == nil {
		t.Fatal("descriptor cleanup error was discarded")
	}
	<-g.Done()
	if g.CleanupError() == nil {
		t.Fatal("cleanup failure disappeared after actual reap")
	}
}

func TestParentContextCleanupFailureRemainsObservable(t *testing.T) {
	root, raw, trust, opts := releaseFixture(t)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, err := prepared(t, root, raw, trust).Start(parent, opts, budgets())
	if err != nil {
		t.Fatal(err)
	}
	observations(t, g)
	<-g.stopToken
	held := true
	defer func() {
		if held {
			g.stopToken <- struct{}{}
		}
		stop(t, g)
	}()
	cancel()
	select {
	case <-g.contextCleanupDone:
	case <-time.After(3 * time.Second):
		t.Fatal("automatic context cleanup did not honor its bound")
	}
	if !errors.Is(g.CleanupError(), context.DeadlineExceeded) {
		t.Fatal("automatic cleanup failure was discarded")
	}
	g.stopToken <- struct{}{}
	held = false
	stop(t, g)
	<-g.Done()
	if !errors.Is(g.CleanupError(), context.DeadlineExceeded) {
		t.Fatal("actual reap erased historical cleanup failure")
	}
}
