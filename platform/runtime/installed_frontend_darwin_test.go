//go:build darwin && arm64 && cgo

package runtime

import (
	"context"
	"strings"
	"testing"
)

func TestInstalledFrontendRejectsInvalidSelectionsBeforeOpening(t *testing.T) {
	want := "sha256:" + strings.Repeat("a", 64)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name, path, digest string
		ctx                context.Context
		max                int64
	}{
		{"sibling", StableFrontendPath + "-other", want, context.Background(), 1024},
		{"noncanonical", "/Library/Application Support/Agentmux/Protected/./agentmux-runtime", want, context.Background(), 1024},
		{"release", darwinReleaseBase + "/" + strings.Repeat("a", 64) + "/agentmux-runtime", want, context.Background(), 1024},
		{"relative", "agentmux-runtime", want, context.Background(), 1024},
		{"digest", StableFrontendPath, "bad", context.Background(), 1024},
		{"nil_context", StableFrontendPath, want, nil, 1024},
		{"cancelled", StableFrontendPath, want, cancelled, 1024},
		{"zero_bound", StableFrontendPath, want, context.Background(), 0},
		{"large_bound", StableFrontendPath, want, context.Background(), 128*1024*1024 + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			image, err := PrepareProtectedInstalledFrontend(tc.ctx, tc.path, tc.digest, tc.max)
			if image != nil || err == nil || err.Error() != "installed_frontend_preparation_invalid" {
				t.Fatal("invalid frontend selection crossed admission", err)
			}
		})
	}
}

func TestInstalledFrontendDoesNotExpandReleaseAdmission(t *testing.T) {
	want := "sha256:" + strings.Repeat("a", 64)
	if image, err := openDarwinProtected(context.Background(), StableFrontendPath, want, 1024); image != nil || err == nil {
		t.Fatal("stable frontend admitted as release member")
	}
	if image, err := PrepareProtectedInstalledHost(context.Background(), StableFrontendPath, want, 1024); image != nil || err == nil {
		t.Fatal("stable frontend acquired host capability")
	}
	if image, err := openDarwinStableFrontend(context.Background(), darwinReleaseBase+"/"+strings.Repeat("a", 64)+"/agentmux-runtime", want, 1024); image != nil || err == nil {
		t.Fatal("release path admitted as stable frontend")
	}
}
