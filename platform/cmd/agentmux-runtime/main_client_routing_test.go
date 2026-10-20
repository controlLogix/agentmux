//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/controlLogix/agentmux/platform/launcher"
)

func TestDoctorClientOptionIsExplicitAndDoctorOnly(t *testing.T) {
	for _, client := range []string{"claude", "codex", "pi", "claude-desktop"} {
		args := []string{"doctor", "--host-policy", "/private/policy", "--workspace", "/work with spaces", "--client", client}
		o, err := parse(args)
		if err != nil || o.client != client || o.operation != "doctor" || !launcher.ValidClientDoctorID(o.client) {
			t.Fatal("supported doctor selection refused or changed")
		}
	}
	o, err := parse([]string{"doctor", "--host-policy", "/private/policy", "--workspace", "/work"})
	if err != nil || o.client != "" {
		t.Fatal("unselected doctor no longer uses original report")
	}
	for _, operation := range []string{"ensure", "status", "host", "prepare", "doctor"} {
		for _, client := range []string{"", "sh", "../codex", "codex --version", "$(private)", "codex"} {
			if operation == "doctor" && client == "codex" {
				continue
			}
			args := []string{operation, "--host-policy", "/private/policy", "--workspace", "/work", "--client", client}
			if operation == "host" {
				args = append(args, "--invocation-id", "attempt_"+strings.Repeat("a", 32))
			}
			var output bytes.Buffer
			err := run(context.Background(), args, &output)
			if err == nil || err.Error() != "arguments_invalid" || output.Len() != 0 {
				t.Fatalf("invalid %s client selection reached policy or emitted output", operation)
			}
		}
	}
}

func TestDoctorClientSelectionCannotBypassPrivatePolicyAdmission(t *testing.T) {
	for _, client := range []string{"claude", "codex", "pi", "claude-desktop"} {
		var output bytes.Buffer
		args := []string{"doctor", "--host-policy", "/missing-private-doctor-policy", "--workspace", t.TempDir(), "--client", client}
		if err := run(context.Background(), args, &output); err == nil || output.Len() != 0 {
			t.Fatal("missing enrollment reached client diagnostics")
		}
	}
}
