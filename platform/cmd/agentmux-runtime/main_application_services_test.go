//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/controlLogix/agentmux/platform/launcher"
)

func serviceCommandArguments(t *testing.T, operation string) []string {
	t.Helper()
	args := []string{operation, "--host-policy", "/private/host.json", "--workspace", "/workspace",
		"--application-attestor-selection", "/private/attestor.json", "--application-attestor-selection-sha256", "sha256:" + strings.Repeat("a", 64),
		"--application-services-installation", strings.Repeat("b", 64),
		"--application-services-selection", "/private/service 'quoted' $(literal).json",
		"--application-services-selection-sha256", "sha256:" + strings.Repeat("c", 64)}
	if operation == "host" {
		args = append(args, "--invocation-id", "attempt_"+strings.Repeat("d", 32))
	}
	return args
}

func TestApplicationServicesSelectionRequiresCompleteLiteralPins(t *testing.T) {
	for _, operation := range []string{"ensure", "host"} {
		args := serviceCommandArguments(t, operation)
		selected, err := parse(args)
		if err != nil || selected.services != (applicationServicesOptions{args[10], args[12], args[14]}) {
			t.Fatal("service selection pins were refused or changed", err)
		}
	}
	base := serviceCommandArguments(t, "ensure")
	for index := 9; index < 15; index += 2 {
		missing := append(append([]string{}, base[:index]...), base[index+2:]...)
		duplicate := append(append([]string{}, base...), base[index:index+2]...)
		for _, args := range [][]string{missing, duplicate} {
			var output bytes.Buffer
			if err := run(context.Background(), args, &output); err == nil || err.Error() != "arguments_invalid" || output.Len() != 0 {
				t.Fatal("partial or duplicate service pins reached host admission")
			}
		}
	}
	for _, mutation := range []struct {
		index int
		value string
	}{{10, strings.Repeat("B", 64)}, {10, ""}, {12, "relative"}, {12, "/private/../selection"}, {12, "/private/control\nselection"},
		{12, "/" + strings.Repeat("s", 4096)}, {14, "sha256:" + strings.Repeat("C", 64)}, {14, ""}} {
		args := append([]string{}, base...)
		args[mutation.index] = mutation.value
		if _, err := parse(args); err == nil {
			t.Fatal("invalid service pin accepted")
		}
	}
	for _, operation := range []string{"status", "doctor", "prepare"} {
		args := append([]string{}, base...)
		args[0] = operation
		if _, err := parse(args); err == nil {
			t.Fatal("service startup pins accepted on a non-launch command")
		}
	}
	withoutAttestor := append(append([]string{}, base[:5]...), base[9:]...)
	if _, err := parse(withoutAttestor); err == nil {
		t.Fatal("service pins accepted without explicit attestor enrollment")
	}
	stale := append(append([]string{}, base...), "--application-services-host-account", strings.Repeat("A", 56))
	if _, err := parse(stale); err == nil {
		t.Fatal("stale HOST account option was accepted")
	}
}

type selectedApplicationHost struct {
	ctx        context.Context
	invocation string
	attestor   launcher.ApplicationAttestorHostSelection
	services   *launcher.ApplicationServiceProcessSelection
	calls      int
	failure    error
}

type selectedApplicationHostFailure struct{ owner *selectedApplicationHost }

func (*selectedApplicationHostFailure) Error() string { return "owned_service_cleanup_failure" }

func (h *selectedApplicationHost) RunWithApplicationAttestor(ctx context.Context, invocation string, attestor launcher.ApplicationAttestorHostSelection) error {
	h.ctx, h.invocation, h.attestor, h.calls = ctx, invocation, attestor, h.calls+1
	return h.failure
}
func (h *selectedApplicationHost) RunWithApplicationServices(ctx context.Context, invocation string, attestor launcher.ApplicationAttestorHostSelection, services launcher.ApplicationServiceProcessSelection) error {
	h.ctx, h.invocation, h.attestor, h.services, h.calls = ctx, invocation, attestor, &services, h.calls+1
	return h.failure
}

func TestApplicationServicesHostDispatchPreservesAttestorOnlyAndSelectedOwner(t *testing.T) {
	args := serviceCommandArguments(t, "host")
	selected, err := parse(args)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	attestor := launcher.ApplicationAttestorHostSelection{AccountPublicKey: "admitted_application_account", InitialGeneration: 7}
	for _, services := range []applicationServicesOptions{{}, selected.services} {
		requested := selected
		requested.services = services
		host := &selectedApplicationHost{}
		failure := &selectedApplicationHostFailure{owner: host}
		host.failure = failure
		if err := runApplicationHost(ctx, host, requested, attestor); err != failure || host.calls != 1 || host.ctx != ctx || host.invocation != selected.invocation || !reflect.DeepEqual(host.attestor, attestor) {
			t.Fatal("dispatch changed the host lifetime, admitted attestor or original error owner")
		}
		if services.installationID == "" {
			if host.services != nil {
				t.Fatal("absent service selection changed the attestor-only route")
			}
		} else if host.services == nil || *host.services != (launcher.ApplicationServiceProcessSelection{InstallationID: services.installationID, Path: services.path, SHA256: services.digest}) {
			t.Fatal("service composition did not receive the literal selection pins")
		}
	}
}
