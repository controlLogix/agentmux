//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestInstalledClientRouteKeepsLiteralSelectionAndClosedArguments(t *testing.T) {
	id := strings.Repeat("a", 64)
	selection := "/private/a 'quoted' $(literal) selection.json"
	for _, verb := range []string{"mcp", "startup", "dashboard", "launch-claude-desktop", "claude-code-hook"} {
		op, gotID, path, err := parseInstalledClient([]string{verb, "--client-installation", id, "--selection", selection})
		if err != nil || op != verb || gotID != id || path != selection {
			t.Fatal("client selection changed", err)
		}
	}
	op, gotID, path, err := parseInstalledClient([]string{"claude-code-hook", "--client-installation", id, "--selection", selection, "--managed-worker"})
	if err != nil || op != "claude-code-hook-worker" || gotID != id || path != selection {
		t.Fatal("managed Claude hook context changed", err)
	}
	for _, args := range [][]string{
		{"mcp"}, {"mcp", "--client-installation", id, "--selection", "relative"},
		{"mcp", "--client-installation", id, "--selection", selection, "--enrolled"},
		{"startup", "--client-installation", id, "--selection", selection, "--host-policy", "/private/foreign"},
		{"mcp", "--client-installation", strings.ToUpper(id), "--selection", "/private/../bad"},
		{"launch-claude-desktop"},
		{"launch-claude-desktop", "--client-installation", id, "--selection", selection, "--app", "/Applications/Other.app"},
		{"launch-claude-desktop", "--client-installation", id, "--selection", "relative"},
		{"claude-code-hook", "--client-installation", id, "--selection", selection, "--managed-worker=false"},
		{"claude-code-hook", "--client-installation", id, "--selection", selection, "--managed-worker", "extra"},
	} {
		var output bytes.Buffer
		if err := run(context.Background(), args, &output); err == nil || err.Error() != "installed_client_arguments_invalid" || output.Len() != 0 {
			t.Fatal("invalid client route emitted protocol output")
		}
	}
}

func TestInstalledClientSetupRouteKeepsReviewAndApplyExplicit(t *testing.T) {
	id := strings.Repeat("a", 64)
	selection, receipt := "/private/a 'quoted' $(literal) selection.json", "/private/setup 'receipt'.json"
	for _, operation := range []string{"install", "remove", "restore", "recover"} {
		args := []string{"client-setup", "--client-installation", id, "--selection", selection, "--receipt", receipt, "--operation", operation}
		for _, apply := range []bool{false, true} {
			if apply {
				args = append(args, "--apply")
			}
			selected, err := parseInstalledClientSetup(args)
			if err != nil || selected.id != id || selected.selection != selection || selected.receipt != receipt || selected.operation != operation || selected.apply != apply {
				t.Fatal("setup changed literal arguments or explicit apply", err)
			}
		}
	}
	base := []string{"client-setup", "--client-installation", id, "--selection", selection, "--receipt", receipt, "--operation", "install"}
	for _, invalid := range [][]string{
		{"client-setup"},
		append(append([]string{}, base...), "--apply=false"),
		append(append([]string{}, base...), "--apply", "--apply"),
		append(append([]string{}, base...), "--host-policy", "/private/policy.json"),
		{"client-setup", "--client-installation", id, "--selection", "relative", "--receipt", receipt, "--operation", "install"},
		{"client-setup", "--client-installation", id, "--selection", selection, "--receipt", "/private/../receipt", "--operation", "install"},
		{"client-setup", "--client-installation", id, "--selection", selection, "--receipt", receipt, "--operation", "start"},
	} {
		var output bytes.Buffer
		if err := run(context.Background(), invalid, &output); err == nil || output.Len() != 0 {
			t.Fatal("invalid setup route reached admission or emitted output")
		}
	}
}

func TestClaudeHookSetupRejectsPublicConfigurationOverride(t *testing.T) {
	id := strings.Repeat("a", 64)
	args := []string{"claude-hook-setup", "--client-installation", id, "--selection", "/private/selection.json", "--receipt", "/private/receipt.json", "--operation", "install", "--apply"}
	selected, err := parseInstalledClientSetup(args)
	if err != nil || selected.id != id || !selected.apply {
		t.Fatal("fixed Claude setup route refused", err)
	}
	for _, extra := range [][]string{{"--configuration", "/private/other/settings.json"}, {"--apply"}} {
		var output bytes.Buffer
		if err := run(context.Background(), append(append([]string{}, args...), extra...), &output); err == nil || output.Len() != 0 {
			t.Fatal("public setup accepted an internal argument")
		}
	}
}

func TestInstalledClientPrivateServicesHaveNoPublicRoute(t *testing.T) {
	args := []string{"application-services", "--client-installation", strings.Repeat("a", 64), "--selection", "/private/selected.json"}
	if _, _, _, err := parseInstalledClient(args); err == nil || err.Error() != "installed_client_arguments_invalid" {
		t.Fatal("private service receiver exposed as a client command", err)
	}
	var output bytes.Buffer
	if err := run(context.Background(), args, &output); err == nil || err.Error() != "command_invalid" || output.Len() != 0 {
		t.Fatal("public frontend accepted a private service command", err)
	}
}

func TestLocalEnrollmentRouteRefusesMalformedArgumentsBeforeAdmission(t *testing.T) {
	id := strings.Repeat("a", 64)
	request, digest := "/private/setup 'literal' request.json", "sha256:"+strings.Repeat("b", 64)
	for _, invalid := range [][]string{
		{"application-enroll"},
		{"application-enroll", "--client-installation", id, "--request", request},
		{"application-enroll", "--client-installation", "short", "--request", request, "--request-sha256", digest},
		{"application-enroll", "--client-installation", id, "--request", "relative.json", "--request-sha256", digest},
		{"application-enroll", "--client-installation", id, "--request", "/private/../request.json", "--request-sha256", digest},
		{"application-enroll", "--client-installation", id, "--request", "/private/request\n.json", "--request-sha256", digest},
		{"application-enroll", "--client-installation", id, "--request", request, "--request-sha256", "sha256:BAD"},
		{"application-enroll", "--client-installation", id, "--request", request, "--request-sha256", digest, "--apply"},
		{"application-enroll", "--client-installation", id, "--selection", request, "--request-sha256", digest},
	} {
		var output bytes.Buffer
		err := run(context.Background(), invalid, &output)
		if err == nil || err.Error() != "installed_client_arguments_invalid" || output.Len() != 0 {
			t.Fatalf("malformed enrollment route reached admission or emitted output: %v %v", invalid, err)
		}
	}
}
