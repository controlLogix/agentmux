//go:build linux || darwin

package launcher

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestInstalledReceiptBindingUsesCurrentEnrollment(t *testing.T) {
	s, record := installedBridgePolicyFixture(t)
	h, err := LoadEnrolledHostPolicy(s)
	if err != nil {
		t.Fatal(err)
	}
	i, err := h.BeginEnsure()
	if err != nil {
		t.Fatal(err)
	}
	binding, err := h.BootstrapReceiptBinding(i.ID())
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := h.Load()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(record.Owner)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if binding.Scope != c.Kernel.Scope || binding.EnrollmentDigest != "sha256:"+hex.EncodeToString(sum[:]) || binding.RuntimeDigest != record.RuntimeExecutable.Digest || binding.ColdInvocationID != i.ID() {
		t.Fatal("receipt binding differs from admitted enrollment")
	}
	// A retained policy must not bypass later changes to private enrollment.
	changed := record.Owner
	changed.PrincipalID = "different_owner"
	writeOwnerFixture(t, record.ProfileDirectory, mustStatusJSON(changed))
	if _, err := h.BootstrapReceiptBinding(i.ID()); err == nil {
		t.Fatal("changed owner enrollment was accepted")
	}
}

func TestInstalledReceiptBindingRejectsInvalidInvocation(t *testing.T) {
	var absent *EnrolledHostPolicy
	if _, err := absent.BootstrapReceiptBinding("attempt_0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("nil policy accepted")
	}
	s, _ := installedBridgePolicyFixture(t)
	h, err := LoadEnrolledHostPolicy(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "owner", "attempt_0123", "attempt_0123456789abcdef0123456789abcdeF"} {
		if _, err := h.BootstrapReceiptBinding(id); err == nil {
			t.Fatal("invalid invocation accepted")
		}
	}
}
