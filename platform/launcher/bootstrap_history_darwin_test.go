//go:build darwin && arm64 && cgo && agentmux_darwin_install

package launcher

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	protected "github.com/controlLogix/agentmux/platform/runtime"
)

// Reuse the separately reviewed frontend_receipt_child installation. The path
// and digest come from the same explicit prerequisites as the frontend controls;
// these tests never build, install or derive their own admission pin.
func historyDarwinReceiptImage(t *testing.T) (string, string, *protected.InstalledHostImage) {
	t.Helper()
	if os.Getenv("AMX_DARWIN_FRONTEND_RECEIPT_AUTHORIZED") != "1" || os.Geteuid() == 0 || os.Getuid() != os.Geteuid() {
		t.Fatal("native history receipt controls require explicit selection and an ordinary user")
	}
	path := os.Getenv("AMX_DARWIN_FRONTEND_RECEIPT_FIXTURE")
	digest := os.Getenv("AMX_DARWIN_FRONTEND_RECEIPT_SHA256")
	const base = "/Library/Application Support/Agentmux/Protected/releases"
	version := filepath.Base(filepath.Dir(path))
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(filepath.Dir(path)) != base ||
		filepath.Base(path) != "agentmux-frontend-receipt-fixture" || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(version) ||
		!regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(digest) {
		t.Fatal("separately pinned native history receipt prerequisite required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	image, err := protected.PrepareProtectedInstalledHost(ctx, path, digest, 128*1024*1024)
	if image != nil {
		t.Cleanup(func() {
			if image.Close() != nil {
				t.Error("history receipt protected image cleanup failed")
			}
		})
	}
	if err != nil || image == nil {
		t.Fatal("root-admitted native history receipt image unavailable")
	}
	return path, digest, image
}

func historyDarwinStartReceiptChild(t *testing.T, ctx context.Context, image *protected.InstalledHostImage, binding protected.BootstrapReceiptBinding) *protected.ReceiptHostProcess {
	t.Helper()
	dir := t.TempDir()
	policy := filepath.Join(dir, "binding.json")
	// The existing payload's closed policy differs from the Linux inline child:
	// Stay keeps this exact receipt writer alive until the original owner stops it.
	if os.WriteFile(policy, mustStatusJSON(struct {
		Binding protected.BootstrapReceiptBinding
		Stay    bool
	}{binding, true}), 0600) != nil {
		t.Fatal("private history receipt binding unavailable")
	}
	child, err := image.StartHostWithBootstrapReceipt(ctx, protected.HostInvocation{InvocationID: binding.ColdInvocationID, PolicyPath: policy, WorkspaceRoots: []string{dir}}, binding)
	if child != nil {
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			receiptErr := child.CloseBootstrapReceipt(cleanup)
			stopErr := child.Stop(cleanup)
			if receiptErr != nil || stopErr != nil {
				t.Error("exact history receipt creator cleanup failed")
			}
		})
	}
	if err != nil || child == nil {
		t.Fatal("root-admitted history receipt creator start failed")
	}
	receipt, err := child.BootstrapReceipt(ctx)
	if err != nil || receipt.Binding != binding || receipt.Outcome != "accepted" || !child.HasValidatedBootstrapReceipt(binding) {
		t.Fatal("actual history creator bound receipt unavailable")
	}
	select {
	case <-child.Done():
		t.Fatal("history creator exited before held-lease observations")
	default:
	}
	return child
}

// Port of bootstrap_history_linux_test.go's creator-history assertions. The
// operation transitions remain component seams; the root-admitted child supplies
// actual receipt provenance, not product Bootstrap, NATS or Compose acceptance.
func TestBootstrapHistoryActualCreatorTerminalWhileLeaseHeldAndAfterExit(t *testing.T) {
	_, digest, image := historyDarwinReceiptImage(t)
	op, f, _, _, _ := pendingOperationFixture(t)
	binding := receiptServerBinding(op.server, op.attemptID)
	binding.RuntimeDigest = digest
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
	child := historyDarwinStartReceiptChild(t, op.startup, image, binding)
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
