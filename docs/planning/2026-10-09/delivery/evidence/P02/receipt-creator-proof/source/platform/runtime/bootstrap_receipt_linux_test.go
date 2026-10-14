//go:build linux

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"testing"
	"time"
)

// This genuine sealed child tests transport and lifetime only. It does not
// replace the product operation's admission/enter capability or NATS status.
func bootstrapReceiptChildBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	source := filepath.Join(dir, "child.go")
	binary := filepath.Join(dir, "child")
	body := `package main
import("context";"encoding/json";"os";"os/signal";"syscall";"time";"path/filepath";protected "github.com/controlLogix/agentmux/platform/runtime")
func main(){signals:=make(chan os.Signal,1);signal.Notify(signals,syscall.SIGTERM);raw,e:=os.ReadFile(os.Args[3]);if e!=nil{os.Exit(2)};var binding protected.BootstrapReceiptBinding;if json.Unmarshal(raw,&binding)!=nil{os.Exit(3)};writer,e:=protected.OpenBootstrapReceiptWriter(binding);if e!=nil{os.Exit(4)};ctx,cancel:=context.WithTimeout(context.Background(),time.Second);e=writer.Accepted(ctx);cancel();if e!=nil{os.Exit(5)};report,_:=json.Marshal(map[string]any{"pid":os.Getpid(),"parentPid":os.Getppid()});if os.WriteFile(filepath.Join(filepath.Dir(os.Args[3]),"receipt-child.json"),report,0600)!=nil{os.Exit(6)};<-signals}
`
	if os.WriteFile(source, []byte(body), 0600) != nil {
		t.Fatal("fixture source unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(goruntime.GOROOT(), "bin", "go"), "build", "-o", binary, source)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	cmd.WaitDelay = time.Second
	if cmd.Run() != nil || os.Chmod(binary, 0700) != nil {
		t.Fatal("static fixture build failed")
	}
	return binary
}

func TestBootstrapReceiptSealedChildAndDetachedLifetime(t *testing.T) {
	binary := bootstrapReceiptChildBinary(t)
	dir := t.TempDir()
	policy := filepath.Join(dir, "binding.json")
	raw, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	binding := receiptTestBinding()
	binding.RuntimeDigest = "sha256:" + hex.EncodeToString(sum[:])
	raw, _ = json.Marshal(binding)
	if os.WriteFile(policy, raw, 0600) != nil {
		t.Fatal("private fixture binding unavailable")
	}
	image := installedHostTestImage(t, binary)
	defer image.Close()
	start, cancelStart := context.WithCancel(context.Background())
	p, e := image.StartHostWithBootstrapReceipt(start, HostInvocation{InvocationID: binding.ColdInvocationID, PolicyPath: policy, WorkspaceRoots: []string{dir}}, binding)
	if p != nil {
		t.Cleanup(func() {
			join, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			p.CloseBootstrapReceipt(join)
			if p.Stop(join) != nil {
				t.Error("exact receipt child cleanup failed")
			}
		})
	}
	if e != nil || p == nil {
		t.Fatal("sealed receipt child failed")
	}
	cancelStart()
	if p.HasValidatedBootstrapReceipt(binding) {
		t.Fatal("unread child receipt established proof")
	}
	read, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	receipt, e := p.BootstrapReceipt(read)
	if e != nil || receipt.Binding != binding {
		t.Fatal("sealed image fd or receipt binding lost")
	}
	if !p.HasValidatedBootstrapReceipt(binding) {
		t.Fatal("genuine sealed child did not establish accepted proof")
	}
	replaced := *p
	replaced.HostProcess = &HostProcess{}
	if replaced.HasValidatedBootstrapReceipt(binding) {
		t.Fatal("copied receipt admitted a replacement child")
	}
	if p.CloseBootstrapReceipt(read) != nil {
		t.Fatal("receipt close failed")
	}
	select {
	case <-p.Done():
		t.Fatal("frontend cancellation killed detached child")
	default:
	}
}

// The parent opens the kernel handle only while the verified creator is alive.
// Report PIDs are test correlation data and are never signalled.
func TestBootstrapReceiptSurvivesActualFrontendExit(t *testing.T) {
	binary := bootstrapReceiptChildBinary(t)
	raw, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	binding := receiptTestBinding()
	binding.RuntimeDigest = "sha256:" + hex.EncodeToString(sum[:])
	dir := t.TempDir()
	policy := filepath.Join(dir, "binding.json")
	raw, _ = json.Marshal(binding)
	if os.WriteFile(policy, raw, 0600) != nil {
		t.Fatal("binding fixture unavailable")
	}
	source := filepath.Join(dir, "frontend.go")
	frontBinary := filepath.Join(dir, "frontend")
	gate := filepath.Join(dir, "exit-gate")
	accepted := filepath.Join(dir, "accepted")
	body := `package main
import("context";"encoding/json";"os";"os/signal";"syscall";"time";protected "github.com/controlLogix/agentmux/platform/runtime")
func main(){ctx,cancel:=signal.NotifyContext(context.Background(),syscall.SIGTERM);defer cancel();raw,e:=os.ReadFile(os.Args[2]);if e!=nil{os.Exit(2)};var binding protected.BootstrapReceiptBinding;if json.Unmarshal(raw,&binding)!=nil{os.Exit(3)};file,e:=os.Open(os.Args[1]);if e!=nil{os.Exit(4)};image,e:=protected.PrepareInstalledHost(ctx,file,binding.RuntimeDigest,128*1024*1024);file.Close();if e!=nil{os.Exit(5)};child,e:=image.StartHostWithBootstrapReceipt(ctx,protected.HostInvocation{InvocationID:binding.ColdInvocationID,PolicyPath:os.Args[2],WorkspaceRoots:[]string{os.Args[3]}},binding);image.Close();handed:=false;defer func(){if child!=nil&&!handed{stop,cancel:=context.WithTimeout(context.Background(),3*time.Second);defer cancel();child.CloseBootstrapReceipt(stop);child.Stop(stop)}}();if e!=nil||child==nil{return};read,stopRead:=context.WithTimeout(ctx,2*time.Second);_,e=child.BootstrapReceipt(read);stopRead();if e!=nil{return};if os.WriteFile(os.Args[5],[]byte("accepted"),0600)!=nil{return};timer:=time.NewTimer(10*time.Second);defer timer.Stop();for{select{case <-ctx.Done():return;case <-timer.C:return;default:};if b,e:=os.ReadFile(os.Args[4]);e==nil&&string(b)=="exit"{handed=true;return};time.Sleep(time.Millisecond)}}
`
	if os.WriteFile(source, []byte(body), 0600) != nil {
		t.Fatal("frontend fixture source unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	build := exec.CommandContext(ctx, filepath.Join(goruntime.GOROOT(), "bin", "go"), "build", "-o", frontBinary, source)
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	build.WaitDelay = time.Second
	if build.Run() != nil {
		t.Fatal("frontend fixture build failed")
	}
	front := exec.Command(frontBinary, binary, policy, dir, gate, accepted)
	if front.Start() != nil {
		t.Fatal("frontend fixture unavailable")
	}
	done := make(chan error, 1)
	go func() { done <- front.Wait() }()
	frontJoined := false
	t.Cleanup(func() {
		if !frontJoined {
			front.Process.Signal(unix.SIGTERM)
			select {
			case <-done:
			case <-time.After(4 * time.Second):
				front.Process.Kill()
				<-done
				t.Error("frontend-owned cleanup exceeded bound")
			}
		}
	})
	record := waitHostTestRecord(t, filepath.Join(dir, "receipt-child.json"))
	pid, ok := record["pid"].(float64)
	if !ok || record["parentPid"] != float64(front.Process.Pid) {
		t.Fatal("exact receipt child identity unavailable")
	}
	fd, e := unix.PidfdOpen(int(pid), 0)
	if e != nil {
		t.Fatal("receipt child handle unavailable")
	}
	t.Cleanup(func() {
		unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0)
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if n, e := unix.Poll(poll, 3000); e != nil || n != 1 {
			t.Error("receipt child exit not joined")
		}
		unix.Close(fd)
	})
	deadline := time.Now().Add(2 * time.Second)
	for {
		if b, e := os.ReadFile(accepted); e == nil && string(b) == "accepted" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("frontend did not validate receipt")
		}
		time.Sleep(time.Millisecond)
	}
	if os.WriteFile(gate, []byte("exit"), 0600) != nil {
		t.Fatal("owned gate unavailable")
	}
	select {
	case e := <-done:
		frontJoined = true
		if e != nil {
			t.Fatal("frontend exit failed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("frontend did not exit")
	}
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	if n, e := unix.Poll(poll, 100); e != nil || n != 0 {
		t.Fatal("receipt child exited with frontend")
	}
}
