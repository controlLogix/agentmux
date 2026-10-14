//go:build linux || darwin

package launcher

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	protected "github.com/controlLogix/agentmux/platform/runtime"
)

// BootstrapReceiptBinding reloads the enrolled declarations for one actual
// installed invocation. It does not establish startup or broker readiness.
// StartHostWithBootstrapReceipt separately verifies the held executable digest.
func (h *EnrolledHostPolicy) BootstrapReceiptBinding(invocationID string) (protected.BootstrapReceiptBinding, error) {
	if h == nil || !ownerBridgeInvocation.MatchString(invocationID) {
		return protected.BootstrapReceiptBinding{}, hostPolicyError("receipt_invocation_invalid")
	}
	c, _, err := h.Load()
	if err != nil {
		return protected.BootstrapReceiptBinding{}, err
	}
	// This native Go control encoding is versioned by BootstrapReceiptBinding.
	// The typed enrollment has a fixed field order and no map fields.
	raw, err := json.Marshal(h.record.Owner)
	if err != nil {
		return protected.BootstrapReceiptBinding{}, hostPolicyError("receipt_enrollment_invalid")
	}
	sum := sha256.Sum256(raw)
	return protected.BootstrapReceiptBinding{
		Scope:            c.Kernel.Scope,
		EnrollmentDigest: "sha256:" + hex.EncodeToString(sum[:]),
		ColdInvocationID: invocationID,
		RuntimeDigest:    h.record.RuntimeExecutable.Digest,
	}, nil
}
