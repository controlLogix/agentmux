//go:build linux

package main

import (
	"bytes"
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

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

// This real sealed child exercises only receipt transport and the exact owned
// child guard. It does not claim admitted Bootstrap, NATS or Compose behavior.
func childExitGuardBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	source, binary := filepath.Join(dir, "child.go"), filepath.Join(dir, "child")
	body := `package main
import("context";"encoding/json";"os";"os/signal";"syscall";"time";protected "github.com/controlLogix/agentmux/platform/runtime")
func main(){signals:=make(chan os.Signal,1);signal.Notify(signals,syscall.SIGTERM);raw,e:=os.ReadFile(os.Args[3]);if e!=nil{os.Exit(2)};var policy struct{Binding protected.BootstrapReceiptBinding;Stay bool};if json.Unmarshal(raw,&policy)!=nil{os.Exit(3)};writer,e:=protected.OpenBootstrapReceiptWriter(policy.Binding);if e!=nil{os.Exit(4)};ctx,cancel:=context.WithTimeout(context.Background(),time.Second);e=writer.Accepted(ctx);cancel();if e!=nil{os.Exit(5)};if policy.Stay{<-signals}}
`
	if os.WriteFile(source, []byte(body), 0600) != nil {
		t.Fatal("child fixture source unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(goruntime.GOROOT(), "bin", "go"), "build", "-mod=readonly", "-trimpath", "-o", binary, source)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOENV=off", "GOWORK=off")
	cmd.WaitDelay = time.Second
	if cmd.Run() != nil || os.Chmod(binary, 0700) != nil {
		t.Fatal("real static receipt child build failed")
	}
	return binary
}

func childExitGuardStart(t *testing.T, binary string, stay bool) (*protected.ReceiptHostProcess, protected.BootstrapControlReceipt) {
	t.Helper()
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal("real child image unavailable")
	}
	sum := sha256.Sum256(raw)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	binding := protected.BootstrapReceiptBinding{Scope: protocol.Scope{HubID: "fixture_hub", InstanceID: "instance_" + strings.Repeat("b", 32), ProfileID: "profile_" + strings.Repeat("a", 32), AssemblyDigest: "sha256:" + strings.Repeat("c", 64), ReleaseManifestDigest: "sha256:" + strings.Repeat("d", 64), ReleaseVersion: "1.2.3"}, EnrollmentDigest: "sha256:" + strings.Repeat("e", 64), ColdInvocationID: "attempt_" + strings.Repeat("f", 32), RuntimeDigest: digest}
	dir := t.TempDir()
	policy := filepath.Join(dir, "child-policy.json")
	data, err := json.Marshal(struct {
		Binding protected.BootstrapReceiptBinding
		Stay    bool
	}{binding, stay})
	if err != nil || os.WriteFile(policy, data, 0600) != nil {
		t.Fatal("private child policy unavailable")
	}
	file, err := os.Open(binary)
	if err != nil {
		t.Fatal("held child image unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	image, err := protected.PrepareInstalledHost(ctx, file, digest, 128*1024*1024)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		if image != nil {
			image.Close()
		}
		t.Fatal("real sealed child image refused")
	}
	t.Cleanup(func() {
		if image.Close() != nil {
			t.Error("sealed image cleanup failed")
		}
	})
	child, err := image.StartHostWithBootstrapReceipt(ctx, protected.HostInvocation{InvocationID: binding.ColdInvocationID, PolicyPath: policy, WorkspaceRoots: []string{dir}}, binding)
	if child != nil {
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if child.CloseBootstrapReceipt(cleanup) != nil {
				t.Error("owned receipt cleanup failed")
			}
			if child.Stop(cleanup) != nil {
				t.Error("exact child exit was not joined")
			}
		})
	}
	if err != nil || child == nil {
		t.Fatal("real owned receipt child refused")
	}
	receipt, err := child.BootstrapReceipt(ctx)
	if err != nil || receipt.Binding != binding || receipt.Outcome != "accepted" {
		t.Fatal("actual child bound receipt unavailable")
	}
	return child, receipt
}

func TestOwnedBootstrapProgressChecksActualChildAndCaller(t *testing.T) {
	binary := childExitGuardBinary(t)
	t.Run("accepted_then_exited", func(t *testing.T) {
		child, receipt := childExitGuardStart(t, binary, false)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if child.Wait(ctx) != nil {
			t.Fatal("real exited child could not be joined")
		}
		select {
		case <-child.Done():
		default:
			t.Fatal("single child wait did not finish")
		}
		var output bytes.Buffer
		if err := emitOwnedBootstrapProgress(ctx, &output, child, receipt); err == nil || err.Error() != "host_unavailable" || output.Len() != 0 {
			t.Fatal("historical receipt from exited child became current progress")
		}
	})
	t.Run("cancelled_caller", func(t *testing.T) {
		child, receipt := childExitGuardStart(t, binary, true)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var output bytes.Buffer
		if err := emitOwnedBootstrapProgress(ctx, &output, child, receipt); err == nil || err.Error() != "startup_unconfirmed" || output.Len() != 0 {
			t.Fatal("cancelled caller emitted startup progress")
		}
		select {
		case <-child.Done():
			t.Fatal("caller cancellation stopped detached child")
		default:
		}
	})
	t.Run("live_child_has_unknown_instance", func(t *testing.T) {
		child, receipt := childExitGuardStart(t, binary, true)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		var output bytes.Buffer
		if emitOwnedBootstrapProgress(ctx, &output, child, receipt) != nil {
			t.Fatal("actual live child receipt refused")
		}
		var document map[string]json.RawMessage
		if json.Unmarshal(output.Bytes(), &document) != nil || string(document["kind"]) != `"bootstrap-progress"` || string(document["requestDisposition"]) != `"accepted"` || string(document["instanceState"]) != `"unknown"` || string(document["detailsAvailable"]) != "false" {
			t.Fatal("live child receipt invented instance facts")
		}
		if _, ok := document["disposition"]; ok {
			t.Fatal("control receipt reused authenticated L04 disposition")
		}
	})
}
