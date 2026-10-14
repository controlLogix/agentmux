//go:build linux || darwin

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/controlLogix/agentmux/platform/launcher"
)

func TestRequestDiagnosticOutputDoesNotTrustErrorText(t *testing.T) {
	var output bytes.Buffer
	if err := emitRequestDiagnostic(&output, errors.New("docker_environment_conflict password=/private/fixture")); err != nil {
		t.Fatal(err)
	}
	var value launcher.RequestDiagnostic
	decoder := json.NewDecoder(&output)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	if value.Code != "request_failed" || !launcher.ValidRequestDiagnostic(value) {
		t.Fatal("untrusted text classified")
	}
	encoded, _ := json.Marshal(value)
	if strings.Contains(string(encoded), "password") || strings.Contains(string(encoded), "/private") || value.Kind == "startup-status-observation" {
		t.Fatal("diagnostic leaked text or claimed runtime observation")
	}
}
