//go:build linux || darwin

package main

import (
	"strings"
	"testing"
)

func TestApplicationAttestorSelectionRequiresExactPairOnEnsureOrHost(t *testing.T) {
	path := "/private/a 'quoted' $(literal) application.json"
	pin := "sha256:" + strings.Repeat("a", 64)
	for _, operation := range []string{"ensure", "host"} {
		args := []string{operation, "--host-policy", "/private/policy.json", "--workspace", "/private/workspace", "--application-attestor-selection", path, "--application-attestor-selection-sha256", pin}
		if operation == "host" {
			args = append(args, "--invocation-id", "attempt_"+strings.Repeat("a", 32))
		}
		o, err := parse(args)
		if err != nil || o.applicationSelection != path || o.applicationDigest != pin {
			t.Fatal("literal application selection was not preserved", err)
		}
	}
	for _, extra := range [][]string{
		{"--application-attestor-selection", path},
		{"--application-attestor-selection-sha256", pin},
		{"--application-attestor-selection", "relative", "--application-attestor-selection-sha256", pin},
		{"--application-attestor-selection", path, "--application-attestor-selection-sha256", "sha256:bad"},
		{"--application-attestor-selection", path, "--application-attestor-selection", path, "--application-attestor-selection-sha256", pin},
		{"--application-attestor-selection", path, "--application-attestor-selection-sha256", pin, "--application-attestor-selection-sha256", pin},
	} {
		args := append([]string{"ensure", "--host-policy", "/private/policy.json", "--workspace", "/private/workspace"}, extra...)
		if _, err := parse(args); err == nil {
			t.Fatal("invalid application pair accepted")
		}
	}
	for _, operation := range []string{"status", "doctor", "prepare"} {
		if _, err := parse([]string{operation, "--host-policy", "/private/policy.json", "--workspace", "/private/workspace", "--application-attestor-selection", path, "--application-attestor-selection-sha256", pin}); err == nil {
			t.Fatal("application launch selection accepted on non-launch command")
		}
	}
}
