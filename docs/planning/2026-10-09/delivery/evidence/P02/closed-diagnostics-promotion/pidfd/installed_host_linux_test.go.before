//go:build linux

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func installedHostTestBinary(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	source := filepath.Join(directory, "host.go")
	binary := filepath.Join(directory, "host")
	const body = `package main
import("encoding/json";"os";"os/signal";"syscall";"time")
func main(){if len(os.Args)!=8||os.Args[1]!="host"||os.Args[2]!="--host-policy"||os.Args[4]!="--invocation-id"||os.Args[6]!="--workspace"{os.Exit(3)};signals:=make(chan os.Signal,1);signal.Notify(signals,syscall.SIGTERM);report:=map[string]any{"pid":os.Getpid(),"parentPid":os.Getppid(),"secretEnvironmentAbsent":os.Getenv("SYNTHETIC_HOST_SECRET")=="","kernelParentEnvironmentAbsent":os.Getenv("AGENTMUX_KERNEL_PARENT_FD")==""};raw,_:=json.Marshal(report);if os.WriteFile(os.Args[3],raw,0600)!=nil{os.Exit(4)};for{select{case <-signals:return;case <-time.After(50*time.Millisecond):}}}`
	if os.WriteFile(source, []byte(body), 0600) != nil {
		t.Fatal("host fixture source write failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	build := exec.CommandContext(ctx, filepath.Join(goruntime.GOROOT(), "bin", "go"), "build", "-o", binary, source)
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	build.WaitDelay = 2 * time.Second
	if build.Run() != nil || os.Chmod(binary, 0700) != nil {
		t.Fatal("static host fixture build failed")
	}
	return binary
}
func installedHostTestImage(t *testing.T, path string) *InstalledHostImage {
	t.Helper()
	bytes, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("host fixture bytes unavailable")
	}
	digest := sha256.Sum256(bytes)
	source, e := os.Open(path)
	if e != nil {
		t.Fatal("host fixture file unavailable")
	}
	defer source.Close()
	image, e := PrepareInstalledHost(context.Background(), source, "sha256:"+hex.EncodeToString(digest[:]), 128*1024*1024)
	if e != nil {
		t.Fatal(e)
	}
	return image
}
func waitHostTestRecord(t *testing.T, path string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if bytes, e := os.ReadFile(path); e == nil {
			var record map[string]any
			if json.Unmarshal(bytes, &record) == nil {
				return record
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("host fixture did not report readiness")
	return nil
}

func TestInstalledHostSealedImageAndFrontendContextSeparation(t *testing.T) {
	binary := installedHostTestBinary(t)
	image := installedHostTestImage(t, binary)
	defer image.Close()
	// Replacement cannot alter the sealed bytes used by the actual child.
	if os.WriteFile(binary, []byte("#!/bin/sh\nexit 9\n"), 0700) != nil {
		t.Fatal("host fixture replacement failed")
	}
	t.Setenv("SYNTHETIC_HOST_SECRET", "synthetic-private-marker")
	t.Setenv("AGENTMUX_KERNEL_PARENT_FD", "999")
	report := filepath.Join(t.TempDir(), "report.json")
	ctx, cancel := context.WithCancel(context.Background())
	child, e := image.StartHost(ctx, HostInvocation{InvocationID: "attempt_00000000000000000000000000000000", PolicyPath: report, WorkspaceRoots: []string{t.TempDir()}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		stop, finish := context.WithTimeout(context.Background(), 3*time.Second)
		defer finish()
		if child.Stop(stop) != nil {
			t.Error("owned host fixture cleanup failed")
		}
	})
	actual := waitHostTestRecord(t, report)
	if actual["secretEnvironmentAbsent"] != true || actual["kernelParentEnvironmentAbsent"] != true {
		t.Fatal("host environment was not sanitized")
	}
	cancel()
	if image.Close() != nil {
		t.Fatal("sealed host image close failed")
	}
	select {
	case <-child.Done():
		t.Fatal("frontend context or image close stopped detached host")
	case <-time.After(100 * time.Millisecond):
	}
	if _, e := image.StartHost(context.Background(), HostInvocation{InvocationID: "attempt_00000000000000000000000000000000", PolicyPath: report, WorkspaceRoots: []string{t.TempDir()}}); e == nil {
		t.Fatal("consumed image launched another host")
	}
	stop, finish := context.WithTimeout(context.Background(), 3*time.Second)
	defer finish()
	if child.Stop(stop) != nil || child.Wait(stop) != nil {
		t.Fatal("exact owned host did not stop and reap")
	}
}

func TestInstalledHostRefusesInvalidPreparationAndArguments(t *testing.T) {
	binary := installedHostTestBinary(t)
	file, e := os.Open(binary)
	if e != nil {
		t.Fatal("host fixture unavailable")
	}
	defer file.Close()
	for _, digest := range []string{"", "sha256:" + strings.Repeat("0", 64)} {
		if _, e := PrepareInstalledHost(context.Background(), file, digest, 128*1024*1024); e == nil {
			t.Fatal("untrusted host digest accepted")
		}
	}
	if os.Chmod(binary, 0755) != nil {
		t.Fatal("host fixture mode change failed")
	}
	if _, e := PrepareInstalledHost(context.Background(), file, "sha256:"+strings.Repeat("0", 64), 128*1024*1024); e == nil {
		t.Fatal("nonprivate installed image accepted")
	}
	os.Chmod(binary, 0700)
	image := installedHostTestImage(t, binary)
	defer image.Close()
	for _, invocation := range []HostInvocation{{PolicyPath: "relative", WorkspaceRoots: []string{"/tmp"}}, {PolicyPath: "/tmp/policy\nunsafe", WorkspaceRoots: []string{"/tmp"}}, {PolicyPath: "/tmp/policy", WorkspaceRoots: nil}, {PolicyPath: "/tmp/policy", WorkspaceRoots: []string{"/tmp", "/tmp"}}} {
		invocation.InvocationID = "attempt_" + strings.Repeat("a", 32)
		if _, e := image.StartHost(context.Background(), invocation); e == nil {
			t.Fatal("invalid host arguments created a process")
		}
	}
	for _, id := range []string{"", "attempt_short", "attempt_" + strings.Repeat("A", 32)} {
		if _, e := image.StartHost(context.Background(), HostInvocation{InvocationID: id, PolicyPath: "/tmp/policy", WorkspaceRoots: []string{"/tmp"}}); e == nil {
			t.Fatal("invalid launch invocation ID created a process")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := image.StartHost(ctx, HostInvocation{InvocationID: "attempt_00000000000000000000000000000000", PolicyPath: "/tmp/policy", WorkspaceRoots: []string{"/tmp"}}); e == nil {
		t.Fatal("cancelled frontend created a host")
	}
}

// This proves OS lifetime separation with a real sealed child and an actual
// exiting frontend. It is not product-daemon, NATS or Docker qualification.
func TestInstalledHostSurvivesActualFrontendExit(t *testing.T) {
	binary := installedHostTestBinary(t)
	content, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal("sealed child fixture unavailable")
	}
	want := sha256.Sum256(content)
	directory := t.TempDir()
	frontendSource := filepath.Join(directory, "frontend.go")
	frontendBinary := filepath.Join(directory, "frontend")
	report := filepath.Join(directory, "child.json")
	gate := filepath.Join(directory, "exit-frontend")
	const source = `package main
import("context";"os";"time";protected "github.com/controlLogix/agentmux/platform/runtime")
func main(){if len(os.Args)!=6{os.Exit(2)};file,e:=os.Open(os.Args[1]);if e!=nil{os.Exit(3)};image,e:=protected.PrepareInstalledHost(context.Background(),file,os.Args[2],128*1024*1024);file.Close();if e!=nil{os.Exit(4)};_,e=image.StartHost(context.Background(),protected.HostInvocation{InvocationID:"attempt_00000000000000000000000000000000",PolicyPath:os.Args[3],WorkspaceRoots:[]string{os.Args[4]}});image.Close();if e!=nil{os.Exit(5)};deadline:=time.Now().Add(10*time.Second);for time.Now().Before(deadline){if _,e:=os.Stat(os.Args[5]);e==nil{return};time.Sleep(10*time.Millisecond)};os.Exit(6)}`
	if os.WriteFile(frontendSource, []byte(source), 0600) != nil {
		t.Fatal("frontend fixture source unavailable")
	}
	buildContext, cancelBuild := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelBuild()
	build := exec.CommandContext(buildContext, filepath.Join(goruntime.GOROOT(), "bin", "go"), "build", "-o", frontendBinary, frontendSource)
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	build.WaitDelay = 2 * time.Second
	if build.Run() != nil {
		t.Fatal("frontend infrastructure fixture build failed")
	}
	frontend := exec.Command(frontendBinary, binary, "sha256:"+hex.EncodeToString(want[:]), report, directory, gate)
	if frontend.Start() != nil {
		t.Fatal("frontend infrastructure fixture start failed")
	}
	parentDone := make(chan error, 1)
	go func() { parentDone <- frontend.Wait() }()
	t.Cleanup(func() { frontend.Process.Kill() })
	actual := waitHostTestRecord(t, report)
	pid, ok := actual["pid"].(float64)
	if !ok || actual["parentPid"] != float64(frontend.Process.Pid) {
		t.Fatal("fixture child was not created by the exact frontend")
	}
	// Open the exact kernel process handle while its verified parent is still
	// alive. Only that descriptor is signalled after the parent exits.
	fd, err := unix.PidfdOpen(int(pid), 0)
	if err != nil {
		t.Fatal("exact detached-child process handle unavailable")
	}
	t.Cleanup(func() { unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0); unix.Close(fd) })
	if sid, err := unix.Getsid(int(pid)); err != nil || sid != int(pid) {
		t.Fatal("installed child did not detach its OS session")
	}
	if os.WriteFile(gate, []byte("exit"), 0600) != nil {
		t.Fatal("frontend exit gate failed")
	}
	select {
	case err := <-parentDone:
		if err != nil {
			t.Fatal("frontend did not exit cleanly")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("frontend did not exit")
	}
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	if count, err := unix.Poll(poll, 100); err != nil || count != 0 {
		t.Fatal("detached child exited with its frontend")
	}
	if unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0) != nil {
		t.Fatal("exact detached-child stop failed")
	}
	if count, err := unix.Poll(poll, 3000); err != nil || count != 1 {
		t.Fatal("exact detached child did not exit after owned signal")
	}
}
