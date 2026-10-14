//go:build linux

package launcher

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"testing"
	"time"

	protected "github.com/controlLogix/agentmux/platform/runtime"
)

// This actual sealed child supplies receipt transport provenance only. The
// operation enter/complete remains a private component seam, not product Run.
func TestBootstrapHistoryActualCreatorTerminalWhileLeaseHeldAndAfterExit(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "receipt-child.go")
	binary := filepath.Join(dir, "receipt-child")
	body := `package main
import("context";"encoding/json";"os";"os/signal";"syscall";"time";protected "github.com/controlLogix/agentmux/platform/runtime")
func main(){signals:=make(chan os.Signal,1);signal.Notify(signals,syscall.SIGTERM);raw,e:=os.ReadFile(os.Args[3]);if e!=nil{os.Exit(2)};var b protected.BootstrapReceiptBinding;if json.Unmarshal(raw,&b)!=nil{os.Exit(3)};w,e:=protected.OpenBootstrapReceiptWriter(b);if e!=nil{os.Exit(4)};ctx,cancel:=context.WithTimeout(context.Background(),time.Second);e=w.Accepted(ctx);cancel();if e!=nil{os.Exit(5)};<-signals}
`
	if os.WriteFile(source, []byte(body), 0600) != nil {
		t.Fatal("sealed fixture source unavailable")
	}
	build, cancelBuild := context.WithTimeout(context.Background(), 60*time.Second)
	cmd := exec.CommandContext(build, filepath.Join(goruntime.GOROOT(), "bin", "go"), "build", "-o", binary, source)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	cmd.WaitDelay = time.Second
	buildErr := cmd.Run()
	cancelBuild()
	if buildErr != nil || os.Chmod(binary, 0700) != nil {
		t.Fatal("static fixture build failed")
	}
	imageRaw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal("fixture image read failed")
	}
	op, f, _, _, _ := pendingOperationFixture(t)
	binding := receiptServerBinding(op.server, op.attemptID)
	binding.RuntimeDigest = historyDigest(imageRaw)
	store, err := openBootstrapHistory(op.startup, op, binding)
	if store != nil {
		t.Cleanup(func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if store.Close(closeCtx) != nil {
				t.Error("history ownership cleanup failed")
			}
		})
	}
	if err != nil {
		t.Fatal("actual binding rejected")
	}
	enterHistoryFixture(t, store, op, f)
	completeHistoryFailure(t, store, op)
	file, err := os.Open(binary)
	if err != nil {
		t.Fatal("fixture image open failed")
	}
	image, prepareErr := protected.PrepareInstalledHost(op.startup, file, binding.RuntimeDigest, 128*1024*1024)
	closeErr := file.Close()
	if image != nil {
		t.Cleanup(func() {
			if image.Close() != nil {
				t.Error("fixture image cleanup failed")
			}
		})
	}
	if prepareErr != nil || closeErr != nil {
		t.Fatal("sealed fixture preparation failed")
	}
	policy := filepath.Join(dir, "binding.json")
	if os.WriteFile(policy, mustStatusJSON(binding), 0600) != nil {
		t.Fatal("fixture binding write failed")
	}
	child, err := image.StartHostWithBootstrapReceipt(op.startup, protected.HostInvocation{InvocationID: binding.ColdInvocationID, PolicyPath: policy, WorkspaceRoots: []string{dir}}, binding)
	if child != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			receiptErr := child.CloseBootstrapReceipt(ctx)
			stopErr := child.Stop(ctx)
			if receiptErr != nil || stopErr != nil {
				t.Error("exact creator cleanup failed")
			}
		})
	}
	if err != nil || child == nil {
		t.Fatal("exact creator start failed")
	}
	if _, err := child.BootstrapReceipt(op.startup); err != nil {
		t.Fatal("actual accepted receipt read failed")
	}
	if result, err := readBootstrapHistory(op.startup, f.owner, binding.RuntimeDigest); err != nil || result != nil {
		t.Fatal("general reader bypassed held service lease")
	}
	if result, err := readCreatorBootstrapHistory(op.startup, f.owner, binding, child); err != nil || result == nil || result.InvocationID != op.attemptID || result.Cleanup != "unknown" {
		t.Fatal("matching creator could not read historical terminal")
	}
	changed := binding
	changed.ColdInvocationID = "attempt_00000000000000000000000000000000"
	if _, err := readCreatorBootstrapHistory(op.startup, f.owner, changed, child); err == nil {
		t.Fatal("foreign invocation selected creator exception")
	}
	stop, cancelStop := context.WithTimeout(context.Background(), 3*time.Second)
	stopErr := child.Stop(stop)
	cancelStop()
	if stopErr != nil {
		t.Fatal("exact creator exit failed")
	}
	select {
	case <-child.Done():
	default:
		t.Fatal("creator not reaped")
	}
	if result, err := readCreatorBootstrapHistory(op.startup, f.owner, binding, child); err != nil || result == nil {
		t.Fatal("actual creator exit erased historical provenance")
	}
}
