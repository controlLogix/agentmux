package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/controlLogix/agentmux/platform/installer"
)

func TestLauncherInstallArgumentsStaySeparate(t *testing.T) {
	for _, args := range [][]string{
		{"install-launcher"},
		{"install-launcher", "--selection", "/private/selection", "--host-policy", "/private/policy"},
		{"install-launcher", "--selection", "/private/selection", "--workspace", "/private/work"},
		{"install", "--selection", "/private/selection", "--selection-sha256", "sha256:" + strings.Repeat("a", 64), "--replace-launcher-sha256", ""},
		{"verify", "--selection", "/private/selection", "--selection-sha256", "sha256:" + strings.Repeat("a", 64), "--replace-launcher-sha256", "sha256:" + strings.Repeat("a", 64)},
		{"check", "--host-policy", "/private/policy", "--workspace", "/private/work", "--replace-launcher-sha256", ""},
	} {
		var output bytes.Buffer
		err := run(context.Background(), args, &output)
		if err == nil || err.Error() != "installer_command_invalid" || output.Len() != 0 {
			t.Fatal("launcher-only arguments escaped command admission")
		}
		raw, err := json.Marshal(installer.Diagnose(err))
		if err != nil || bytes.Contains(raw, []byte("/private/")) {
			t.Fatal("installer diagnostic exposed selection")
		}
	}
}
