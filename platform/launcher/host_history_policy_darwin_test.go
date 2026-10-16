//go:build darwin && arm64 && cgo && agentmux_darwin_install

package launcher

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Port of host_history_policy_linux_test.go's exact creator and revocation
// controls, using the existing separately pinned native receipt payload. The
// private policy fixture does not install or authorize that protected payload.
func TestHostHistoryPolicyActualSealedCreatorAndDrift(t *testing.T) {
	binary, digest, image := historyDarwinReceiptImage(t)
	f := newHistoryPolicyFixture(t, binary)
	op := f.operation
	binding, err := f.host.BootstrapReceiptBinding(f.invocation.ID())
	if err != nil || binding.RuntimeDigest != digest || f.record.RuntimeExecutable.Path != binary || f.record.RuntimeExecutable.Digest != digest {
		t.Fatal("actual installed binding differs from the separately reviewed receipt image")
	}
	child := historyDarwinStartReceiptChild(t, op.startup, image, binding)
	if result, err := f.host.PreviousBootstrapFailure(op.startup); err != nil || result != nil {
		t.Fatal("general reader bypassed held service lease")
	}
	if result, err := f.invocation.CreatorPreviousBootstrapFailure(op.startup, child); err != nil || result == nil || result.InvocationID != op.attemptID || result.RecordedCleanup != "unknown" {
		t.Fatal("matching creator could not read historical terminal")
	}

	foreign := &EnsureInvocation{host: f.host, id: "attempt_00000000000000000000000000000000"}
	if result, err := foreign.CreatorPreviousBootstrapFailure(op.startup, child); err == nil || result != nil {
		t.Fatal("foreign actual invocation bypassed creator proof")
	}
	changed := f.record.Owner
	changed.Identity.Revision++
	writeOwnerFixture(t, f.record.ProfileDirectory, mustStatusJSON(changed))
	if result, err := f.invocation.CreatorPreviousBootstrapFailure(op.startup, child); err == nil || result != nil {
		t.Fatal("revoked current owner exposed creator history")
	}
	writeOwnerFixture(t, f.record.ProfileDirectory, mustStatusJSON(f.record.Owner))
	changedPolicy := f.record
	changedPolicy.RuntimeExecutable.Digest = "sha256:" + strings.Repeat("e", 64)
	writeInstalledHostPolicy(t, f.selection.Path, changedPolicy)
	if result, err := f.invocation.CreatorPreviousBootstrapFailure(op.startup, child); err == nil || result != nil {
		t.Fatal("changed enrolled runtime matched original receipt")
	}
	writeInstalledHostPolicy(t, f.selection.Path, f.record)
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
	if result, err := f.invocation.CreatorPreviousBootstrapFailure(op.startup, child); err != nil || result == nil {
		t.Fatal("actual creator exit erased historical provenance")
	}
}
