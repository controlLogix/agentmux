//go:build linux || darwin

package launcher

import (
	"context"
	"strings"
	"testing"
)

func TestBootstrapInvocationRejectsUnboundIdentifiersBeforeEffects(t *testing.T) {
	for _, id := range []string{"", "attempt_fixture", "attempt_" + strings.Repeat("a", 31), "attempt_" + strings.Repeat("A", 32), "attempt_" + strings.Repeat("a", 32) + "\n", "attempt_" + strings.Repeat("a", 33)} {
		session, err := BootstrapForInvocation(context.Background(), context.Background(), BootstrapConfig{}, id)
		if session != nil || err == nil || err.Error() != "bootstrap_invocation_invalid" {
			t.Fatal("invalid invocation reached configuration or process work")
		}
	}
	// An admitted correlation value still grants no configuration authority.
	session, err := BootstrapForInvocation(context.Background(), context.Background(), BootstrapConfig{}, "attempt_"+strings.Repeat("a", 32))
	if session != nil || err == nil || err.Error() != "bootstrap_context_invalid" {
		t.Fatal("an invocation identifier granted startup authority")
	}
}
