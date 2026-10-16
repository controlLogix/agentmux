//go:build darwin && arm64 && cgo && agentmux_darwin_install

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

// These tests consume a separately reviewed immutable installation of
// testdata/frontend_receipt_child. They never build, install or request elevation.
// Missing prerequisites fail this explicit selection; they are not skipped.
// Receipt transport proves no admitted Bootstrap, NATS or Compose behavior.
func childExitGuardBinary(t *testing.T) string {
	t.Helper()
	if os.Getenv("AMX_DARWIN_FRONTEND_RECEIPT_AUTHORIZED") != "1" || os.Geteuid() == 0 {
		t.Fatal("native receipt controls require explicit selection and an ordinary user")
	}
	path := os.Getenv("AMX_DARWIN_FRONTEND_RECEIPT_FIXTURE")
	root := "/Library/Application Support/Agentmux/Protected/releases"
	version := filepath.Base(filepath.Dir(path))
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(filepath.Dir(path)) != root ||
		filepath.Base(path) != "agentmux-frontend-receipt-fixture" || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(version) ||
		!regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(os.Getenv("AMX_DARWIN_FRONTEND_RECEIPT_SHA256")) {
		t.Fatal("reviewed native receipt fixture path and digest are required")
	}
	return path
}

func childExitGuardStart(t *testing.T, binary string, stay bool) (*protected.ReceiptHostProcess, protected.BootstrapControlReceipt) {
	t.Helper()
	file, err := os.Open(binary)
	if err != nil {
		t.Fatal("installed native receipt child image unavailable")
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, 128*1024*1024+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(raw) == 0 || len(raw) > 128*1024*1024 {
		t.Fatal("installed native receipt child image exceeds its read bound")
	}
	sum := sha256.Sum256(raw)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if digest != os.Getenv("AMX_DARWIN_FRONTEND_RECEIPT_SHA256") {
		t.Fatal("installed native receipt child differs from its reviewed digest")
	}
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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	image, err := protected.PrepareProtectedInstalledHost(ctx, binary, digest, 128*1024*1024)
	if err != nil {
		if image != nil && image.Close() != nil {
			t.Error("refused protected image cleanup failed")
		}
		t.Fatal("real protected child image refused")
	}
	t.Cleanup(func() {
		if image.Close() != nil {
			t.Error("protected image cleanup failed")
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

// This uses an actual immutable installed child and the factory's bound receipt
// pipe. It preserves the Linux budget and output assertions without memfd.
func TestFrontendNearExpiryOwnedReceiptRetainsUnknownFactsAndCleanup(t *testing.T) {
	binary := childExitGuardBinary(t)
	child, receipt := childExitGuardStart(t, binary, true)
	parent, cancelParent := context.WithTimeout(context.Background(), 1800*time.Millisecond)
	defer cancelParent()
	total, cancelTotal := frontendTotalContext(parent, "ensure", time.Now())
	defer cancelTotal()
	work, cancelWork := frontendWorkContext(total)
	defer cancelWork()
	<-work.Done()
	var output bytes.Buffer
	if emitOwnedBootstrapProgress(total, &output, child, receipt) != nil {
		t.Fatal("near-expiry work consumed the genuine receipt response allowance")
	}
	cleanup, cancelCleanup := frontendCleanupContext(total)
	defer cancelCleanup()
	if child.CloseBootstrapReceipt(cleanup) != nil || total.Err() != nil {
		t.Fatal("actual owned receipt cleanup failed or exhausted the total deadline")
	}
	var document map[string]json.RawMessage
	if json.Unmarshal(output.Bytes(), &document) != nil || string(document["instanceState"]) != `"unknown"` || string(document["requestDisposition"]) != `"accepted"` {
		t.Fatal("receipt invented current readiness")
	}
	if _, exists := document["disposition"]; exists {
		t.Fatal("receipt became an authenticated L04 observation")
	}
	select {
	case <-child.Done():
		t.Fatal("frontend response or receipt cleanup stopped its detached child")
	default:
	}
	for _, hard := range []error{errors.New("owner_bridge_authority_rejected"), errors.New("host_policy_owner_enrollment_invalid"), errors.Join(errors.New("owner_bridge_deadline"), errors.New("owner_bridge_owned_connection_cleanup_failed"))} {
		if progressObservationUnavailable(hard) {
			t.Fatal("response reserve converted a hard failure into accepted progress")
		}
	}
}
