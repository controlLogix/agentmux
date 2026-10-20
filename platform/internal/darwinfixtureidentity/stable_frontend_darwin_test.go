//go:build darwin && arm64 && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"context"
	"strings"
	"testing"

	protected "github.com/controlLogix/agentmux/platform/runtime"
)

func TestStableFrontendPreparationKeepsModesSeparate(t *testing.T) {
	for _, stable := range []bool{false, true} {
		// A malformed digest refuses before any installed path is opened. The
		// distinct refusal identifies which private admission mode was selected.
		_, err := prepareLaunchImage(context.Background(), Launch{Path: protected.StableFrontendPath, Digest: "bad"}, stable)
		if err == nil {
			t.Fatal("invalid candidate admitted")
		}
		prefix := "installed_host_"
		if stable {
			prefix = "installed_frontend_"
		}
		if !strings.HasPrefix(err.Error(), prefix) {
			t.Fatalf("wrong admission mode: %s", err)
		}
	}
	want := "sha256:" + strings.Repeat("a", 64)
	if _, err := prepareLaunchImage(context.Background(), Launch{Path: protected.StableFrontendPath + "-sibling", Digest: want}, true); err == nil {
		t.Fatal("sibling admitted as stable frontend")
	}
	if _, err := prepareLaunchImage(context.Background(), Launch{Path: protected.StableFrontendPath, Digest: want}, false); err == nil {
		t.Fatal("stable frontend admitted as release host")
	}
}
