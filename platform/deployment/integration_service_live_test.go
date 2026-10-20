package deployment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func integrationPythonEnvironment(t *testing.T, root string) []string {
	t.Helper()
	dependencies := os.Getenv("AGENTMUX_NATS_CREDENTIAL_DEPENDENCIES")
	if dependencies == "" {
		t.Fatal("prepared Python NATS dependencies required")
	}
	private := t.TempDir()
	if os.Chmod(private, 0700) != nil {
		t.Fatal("private Python fixture directory unavailable")
	}
	return []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + private,
		"TMPDIR=" + private,
		"PYTHONPATH=" + dependencies + string(os.PathListSeparator) +
			filepath.Join(root, "sdk/python") + string(os.PathListSeparator) + root,
		"PYTHONDONTWRITEBYTECODE=1"}
}

// Reuse the existing owned TLS/JWT broker fixture. Only the Python application
// owner and exact service permissions are additional behavior under test.
func TestIntegrationServiceRealBrokerCredentialsAndSignedQuery(t *testing.T) {
	python := os.Getenv("AGENTMUX_NATS_CREDENTIAL_PYTHON")
	if python == "" {
		t.Fatal("prepared Python NATS and SDK runtime required")
	}
	f := newJWTWorkerFixture(t)
	peer, err := f.publisher.TLSConnectionState()
	if err != nil || len(peer.PeerCertificates) == 0 {
		t.Fatal("verified fixture TLS peer unavailable")
	}
	leaf := sha256.Sum256(peer.PeerCertificates[0].Raw)
	seed, err := f.account.Seed()
	if err != nil {
		t.Fatal("fixture account seed unavailable")
	}
	defer clear(seed)
	directory := t.TempDir()
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("private integration fixture directory unavailable")
	}
	input, err := json.Marshal(map[string]any{
		"endpoint": f.policy.Endpoint, "rootsPEM": string(f.policy.TLSRootsPEM),
		"serverName": f.policy.TLSServerName, "domain": f.policy.ExpectedDomain,
		"leafPin":     "sha256:" + hex.EncodeToString(leaf[:]),
		"accountSeed": string(seed), "directory": directory,
	})
	if err != nil {
		t.Fatal("private live input encoding failed")
	}
	defer clear(input)
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal("repository root unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, python, "-B", "-m", "integration_owner.live_broker")
	command.Dir = root
	command.Env = integrationPythonEnvironment(t, root)
	command.Stdin = bytes.NewReader(input)
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	// Run owns the original process wait and output-copy completion. Broker
	// cleanup remains registered with the existing fixture even on failure.
	if err := command.Run(); err != nil {
		t.Fatalf("integration service live client failed: %s", output.String())
	}
	stages := []string{"fixture-admin-connect", "fixture-stream-provisioning", "exact-role-credentials", "owner-composition", "service-start", "signed-intent", "signed-query", "own-stream-read", "unrelated-stream-denial", "unrelated-publication-denial", "cleanup-service", "cleanup-clients", "cleanup-done"}
	var expected strings.Builder
	for _, stage := range stages {
		expected.WriteString("integration live stage: " + stage + "\n")
	}
	expected.WriteString("integration service broker checks passed; clients and service joined\n")
	if output.String() != expected.String() {
		t.Fatal("unexpected integration live client output")
	}
	t.Log("real TLS/JWT service: own intent/query passed; unrelated stream access and publication denied; Python wait/readers joined")
}

func TestIntegrationOperatorRealBrokerProvisioningAndRoute(t *testing.T) {
	python := os.Getenv("AGENTMUX_NATS_CREDENTIAL_PYTHON")
	if python == "" {
		t.Fatal("prepared Python NATS and SDK runtime required")
	}
	f := newJWTWorkerFixtureTLSMode(t, true)
	peer, err := f.publisher.TLSConnectionState()
	if err != nil || len(peer.PeerCertificates) == 0 {
		t.Fatal("verified fixture TLS peer unavailable")
	}
	leaf := sha256.Sum256(peer.PeerCertificates[0].Raw)
	seed, err := f.account.Seed()
	if err != nil {
		t.Fatal("fixture account seed unavailable")
	}
	defer clear(seed)
	directory := t.TempDir()
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("private operator fixture directory unavailable")
	}
	input, err := json.Marshal(map[string]any{
		"endpoint": f.policy.Endpoint, "rootsPEM": string(f.policy.TLSRootsPEM),
		"serverName": f.policy.TLSServerName, "domain": f.policy.ExpectedDomain,
		"leafPin":     "sha256:" + hex.EncodeToString(leaf[:]),
		"accountSeed": string(seed), "directory": directory,
	})
	if err != nil {
		t.Fatal("private operator input encoding failed")
	}
	defer clear(input)
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal("repository root unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, python, "-B", "-m", "integration_owner.live_operator")
	command.Dir = root
	command.Env = integrationPythonEnvironment(t, root)
	command.Stdin = bytes.NewReader(input)
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Run(); err != nil {
		t.Fatalf("integration operator live client failed: %s", output.String())
	}
	stages := []string{"fixture-authority", "selection-and-custody", "operator-provision",
		"routed-credential", "cleanup", "cleanup-done"}
	var expected strings.Builder
	for _, stage := range stages {
		expected.WriteString("integration operator live stage: " + stage + "\n")
	}
	expected.WriteString("integration operator broker checks passed; route and clients joined\n")
	if output.String() != expected.String() {
		t.Fatal("unexpected integration operator live client output")
	}
	t.Log("real TLS/JWT operator: current custody provisioned one exact effect stream; routed credential used only that stream; clients and process joined")
}
