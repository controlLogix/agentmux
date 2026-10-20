package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/launcher"
	"github.com/controlLogix/agentmux/platform/plugins"
)

func TestNativeContextReadOnlyCommandsPreserveExplicitSelection(t *testing.T) {
	input, file := graphCommandFixture(t)
	input.SchemaVersion = "1.2.0"
	input.NativeContext = &launcher.NativeContextHostRequest{ProfileID: "profile", RepositoryRoot: filepath.Dir(file), SelectionPath: filepath.Join(filepath.Dir(file), "selected-native.json"), SelectionSHA256: "sha256:" + strings.Repeat("a", 64), Observability: launcher.NativeContextObservabilitySelection{Path: filepath.Join(filepath.Dir(file), "diagnostics.jsonl"), MaxBytes: 65536, EventCodes: []string{}, SpanCodes: []string{}, MetricCodes: []string{}}}
	writeComposition(t, file, input)
	for _, verb := range []string{"validate", "plan"} {
		var output bytes.Buffer
		if err := execute(context.Background(), []string{verb, "--composition", file}, &output); err != nil {
			t.Fatal(err)
		}
		var result commandResult
		if json.Unmarshal(output.Bytes(), &result) != nil || result.SchemaVersion != "1.2.0" || result.Snapshot != nil {
			t.Fatal("read-only native composition claimed runtime activation")
		}
		assertGraphCommandNoEffects(t, input)
	}
	for _, version := range []string{"1.0.0", "1.1.0"} {
		input.SchemaVersion = version
		writeComposition(t, file, input)
		if _, err := loadComposition(context.Background(), file); err == nil {
			t.Fatal("older version accepted native context input")
		}
	}
	input.SchemaVersion = "1.2.0"
	input.NativeContext.SelectionSHA256 = "sha256:" + strings.Repeat("a", 64) + "\n"
	writeComposition(t, file, input)
	if _, err := loadComposition(context.Background(), file); err == nil {
		t.Fatal("invalid native selection accepted")
	}
	input.NativeContext = nil
	writeComposition(t, file, input)
	if _, err := loadComposition(context.Background(), file); err == nil {
		t.Fatal("native context composition inferred missing selection")
	}
}

type joinedNativeTestOwner struct{ calls int }

func (o *joinedNativeTestOwner) Close(context.Context) error {
	o.calls++
	return errors.New("private historical failure")
}
func (*joinedNativeTestOwner) CleanupComplete() bool { return true }
func TestNativeContextCleanupPreservesCompletedFailureWithoutRetry(t *testing.T) {
	owner := &joinedNativeTestOwner{}
	var output bytes.Buffer
	err := closeForegroundDriver(owner, time.Second, &output)
	if err == nil || owner.calls != 1 || output.Len() != 0 {
		t.Fatal("completed cleanup retried or forgot historical error")
	}
}

func TestNativeContextPlanningRetainsRequiredCapabilityDeclaration(t *testing.T) {
	input, file := graphCommandFixture(t)
	entry := input.Catalog[0]
	manifestPath := filepath.Join(entry.Directory, entry.ManifestPath)
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest plugins.Manifest
	if json.Unmarshal(raw, &manifest) != nil {
		t.Fatal("fixture manifest invalid")
	}
	manifest.RequestedCapabilities = []plugins.Capability{{Action: "read", ResourceClass: "storage", Required: true}}
	raw, err = json.Marshal(manifest)
	if err != nil || os.WriteFile(manifestPath, raw, 0700) != nil {
		t.Fatal("fixture manifest update failed")
	}
	source, err := os.ReadFile(entry.SourceFile)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := plugins.AdmitPackage(context.Background(), plugins.PackageInput{Directory: entry.Directory, ManifestPath: entry.ManifestPath, SourceID: entry.SourceID, SourcePath: entry.SourcePath, Scope: entry.Scope, Source: source, SourceChecksum: entry.SourceChecksum, Limits: plugins.AdmissionLimits{MaxFileBytes: entry.Limits.MaxFileBytes, MaxTotalBytes: entry.Limits.MaxTotalBytes, MaxFiles: entry.Limits.MaxFiles}})
	if err != nil {
		t.Fatal(err)
	}
	old := input.Topology.Instances[0].Pin
	for i := range input.Topology.Instances {
		if input.Topology.Instances[i].Pin == old {
			input.Topology.Instances[i].Pin = pkg.Pin()
		}
	}
	for i := range input.InstanceConfigurations {
		if input.InstanceConfigurations[i].Pin == old {
			input.InstanceConfigurations[i].Pin = pkg.Pin()
		}
	}
	for i := range input.Driver.Bindings {
		if input.Driver.Bindings[i].Pin == old {
			input.Driver.Bindings[i].Pin = pkg.Pin()
		}
	}
	writeComposition(t, file, input)
	if _, err := loadComposition(context.Background(), file); errorCode(err) != "package_capability_binding_unsupported" {
		t.Fatal("lifecycle-only command did not refuse required capability", err)
	}
	input.SchemaVersion = "1.2.0"
	input.NativeContext = &launcher.NativeContextHostRequest{ProfileID: "profile", RepositoryRoot: filepath.Dir(file), SelectionPath: filepath.Join(filepath.Dir(file), "selected-native.json"), SelectionSHA256: "sha256:" + strings.Repeat("a", 64), Observability: launcher.NativeContextObservabilitySelection{Path: filepath.Join(filepath.Dir(file), "diagnostics.jsonl"), MaxBytes: 65536, EventCodes: []string{}, SpanCodes: []string{}, MetricCodes: []string{}}}
	writeComposition(t, file, input)
	prepared, err := loadComposition(context.Background(), file)
	if err != nil {
		t.Fatal("native context planning refused required declaration", err)
	}
	selected, exists := prepared.request.Catalog[0].Manifest().RequestedCapabilities, prepared.nativeContext != nil
	if !exists || len(selected) != 1 || !selected[0].Required {
		t.Fatal("planning dropped the required capability")
	}
	assertGraphCommandNoEffects(t, input)
}
