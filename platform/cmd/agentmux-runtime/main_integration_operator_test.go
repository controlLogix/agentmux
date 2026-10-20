//go:build darwin && arm64

package main

import (
	"bytes"
	"strings"
	"testing"
)

func integrationOperatorArgs() []string {
	return []string{"provision-integration-effect",
		"--host-policy", "/private/host-policy.json",
		"--workspace", "/private/workspace",
		"--application-services-installation", strings.Repeat("a", 64),
		"--application-services-selection", "/private/services.json",
		"--application-services-selection-sha256", "sha256:" + strings.Repeat("b", 64),
		"--custody-root", "/private/custody"}
}

func TestIntegrationOperatorStdinCarriesSignedRequestAndOperation(t *testing.T) {
	raw := []byte(`{"schemaVersion":"1.0.0","kind":"integration-effect-provision-request","originalOperationId":"integration_one","resolutionRequest":{"schemaVersion":"1.0.0","operation":{"operationId":"resolve_one"}}}`)
	command, err := decodeIntegrationOperatorInput(raw)
	if err != nil || command.OriginalOperationID != "integration_one" || !bytes.Contains(command.ResolutionRequest, []byte(`"resolve_one"`)) {
		t.Fatal("closed operator stdin request refused")
	}
	for _, changed := range [][]byte{
		bytes.Replace(raw, []byte(`"integration_one"`), []byte(`"bad.value"`), 1),
		append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"secret":"private"}`)...),
	} {
		if _, err := decodeIntegrationOperatorInput(changed); err == nil {
			t.Fatal("invalid operator stdin request accepted")
		}
	}
}

func TestIntegrationOperatorArgumentsCarryNoSecretOrOperation(t *testing.T) {
	selected, err := parseIntegrationOperator(integrationOperatorArgs())
	if err != nil || selected.custody != "/private/custody" || selected.selection != "/private/services.json" {
		t.Fatal("valid operator arguments refused")
	}
	for _, extra := range [][]string{
		{"--resolution-request", "private"},
		{"--original-operation-id", "substitute"},
		{"--administrator-credential", "private"},
	} {
		if _, err := parseIntegrationOperator(append(integrationOperatorArgs(), extra...)); err == nil {
			t.Fatal("private or authority argument was accepted", extra[0])
		}
	}
}

func TestIntegrationOperatorArgumentsRequireExactPins(t *testing.T) {
	for index, value := range []string{"relative", "relative", "bad", "relative"} {
		args := integrationOperatorArgs()
		positions := []int{2, 4, 8, 12}
		args[positions[index]] = value
		if _, err := parseIntegrationOperator(args); err == nil {
			t.Fatal("invalid protected pin accepted", positions[index])
		}
	}
}
