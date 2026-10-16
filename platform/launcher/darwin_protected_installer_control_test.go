//go:build darwin && cgo && agentmux_bootstrap_docker

package launcher

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/controlLogix/agentmux/platform/privatefs"
)

// This explicitly selected setup control generates a review candidate only.
// It neither installs protected files nor starts a fixture or Docker engine.
func TestDarwinIdentityFixtureBuildInstallerEnvelope(t *testing.T) {
	if os.Geteuid() == 0 || os.Getenv("AMX_DARWIN_IDENTITY_FIXTURE_PLAN_AUTHORIZED") != "1" {
		t.Fatal("unprivileged envelope generation needs its own cleared source and build window")
	}
	source := os.Getenv("AMX_DARWIN_IDENTITY_FIXTURE_BINARY")
	version := os.Getenv("AMX_DARWIN_IDENTITY_FIXTURE_RELEASE_ID")
	directory := os.Getenv("AMX_DARWIN_IDENTITY_FIXTURE_OUTPUT_DIRECTORY")
	expectedPayload := os.Getenv("AMX_DARWIN_IDENTITY_FIXTURE_PAYLOAD_SHA256")
	if !bootstrapFixtureAbsolute(directory) || !releaseHash.MatchString(expectedPayload) {
		t.Fatal("exact private output directory and reviewed revised payload hash are required")
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		t.Fatal("envelope output directory must be an existing canonical private directory")
	}
	root, err := os.Open(directory)
	if err != nil {
		t.Fatal("private envelope output directory unavailable")
	}
	info, statErr := root.Stat()
	policyErr := privatefs.CheckDescriptor(root, privatefs.PrivateObject)
	closeErr := root.Close()
	if statErr != nil || policyErr != nil || closeErr != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("private envelope output directory admission or descriptor close failed")
	}
	const installerSHA = "sha256:0d74190d6be9f1eb65b54ba49b87a547641b11fdd8f95073489f31874959708f"
	installerBefore, err := os.ReadFile("testdata/darwin_protected_installer.py")
	if err != nil || releaseDigest(installerBefore) != installerSHA {
		t.Fatal("installer source differs from the reviewed unprivileged control candidate")
	}
	plan, payload, err := bootstrapPlanDarwinIdentityFixture(source, version)
	if err != nil || !plan.SourceDescriptorClosed || plan.InputDigest != expectedPayload {
		t.Fatal("revised fixture bytes or actual source descriptor close proof refused")
	}
	// This flag marks the proposed manifest shape. It grants no privilege:
	// main must review its exact digest before any installer invocation.
	plan.ReadyForExecution = true
	envelope, manifestDigest, err := bootstrapDarwinIdentityFixtureInput(plan, payload)
	if err != nil {
		t.Fatal("owned Go fixture envelope builder refused")
	}
	manifest, err := json.Marshal(plan)
	if err != nil || releaseDigest(manifest) != manifestDigest {
		t.Fatal("installer manifest serialization differs from the actual builder")
	}
	write := func(name string, raw []byte) {
		t.Helper()
		file, err := os.OpenFile(filepath.Join(directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal("exclusive private envelope evidence creation failed; existing files retained")
		}
		n, writeErr := file.Write(raw)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil || n != len(raw) {
			t.Fatalf("partial envelope evidence retained; descriptorCloseSucceeded=%t", closeErr == nil)
		}
	}
	write("installer-envelope.private", envelope)
	write("installer-manifest.private", manifest)
	installerAfter, err := os.ReadFile("testdata/darwin_protected_installer.py")
	if err != nil || releaseDigest(installerAfter) != installerSHA {
		t.Fatal("installer source changed during envelope generation; candidate retained")
	}
	paths := make([]string, 0, len(plan.Members))
	for _, member := range plan.Members {
		paths = append(paths, filepath.Join(plan.ReleaseDirectory, member.RelativePath))
	}
	record := map[string]any{"purpose": plan.Purpose, "privilegedExecutionAuthorized": false,
		"installerSourceBeforeSHA256": installerSHA, "installerSourceAfterSHA256": installerSHA,
		"manifestDigest": manifestDigest, "envelopeDigest": releaseDigest(envelope),
		"payloadDigest": plan.InputDigest, "payloadBytes": plan.InputBytes,
		"sourceDescriptorClosed": plan.SourceDescriptorClosed, "protectedPaths": paths,
		"protectedLoaderQualified": false, "nativeProcessIdentityQualified": false}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal("private envelope generation result encoding failed")
	}
	write("installer-plan-result.json", raw)
	t.Logf("review candidate generated: manifestDigest=%s payloadDigest=%s sourceDescriptorClosed=true privilegedExecutionAuthorized=false", manifestDigest, plan.InputDigest)
}
