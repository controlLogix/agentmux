package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Reuse the existing native child, private-file handoff and externally owned TLS
// service fixture. This test neither installs a host nor starts a broker.
func TestNativeLiveCLIRegisteredContextActivationAndEOF(t *testing.T) {
	directory := os.Getenv("AMX_NATIVE_CONTEXT_FOREGROUND_LIVE_DIR")
	if directory == "" {
		t.Skip("coordinated registered native context fixture required")
	}
	cli := os.Getenv("AGENTMUX_PLUGIN_CLI")
	info, err := os.Lstat(directory)
	if os.Getenv("AMX_NATIVE_CONTEXT_FOREGROUND_LIVE") != "1" || runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" || cli == "" || !filepath.IsAbs(cli) || err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !filepath.IsAbs(directory) {
		t.Fatal("native registered context fixture prerequisites invalid")
	}
	pkg := nativeFixturePackage(t, "native_foreground", func(manifest *Manifest) {
		manifest.RequestedCapabilities = []Capability{{Action: "read", ResourceClass: "storage", Required: true}, {Action: "subscribe", ResourceClass: "configuration", Required: true}}
		manifest.Runtime.Args = []string{"-test.run=^TestNativeChild$", "-test.timeout=0"}
		manifest.Lifecycle.DrainDeadlineMS = 8000
	})
	configuration, err := PrepareConfiguration(pkg, nil, []byte(`{}`))
	if err != nil {
		t.Fatal("foreground configuration preparation failed")
	}
	sourcePath := filepath.Join(directory, "foreground-source.md")
	source, err := os.OpenFile(sourcePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("foreground source creation failed")
	}
	_, writeErr := source.Write(pkg.Provenance().Source())
	closeErr := source.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("foreground source write or close failed")
	}
	provenance := pkg.Provenance()
	nativeLiveWrite(t, directory, "go-foreground-package.json", map[string]any{
		"instanceId": "plugin-one", "pin": pkg.Pin(), "manifestDigest": pkg.Pin().ManifestChecksum,
		"configurationChecksum": configuration.Checksum(), "schemaRef": pkg.Manifest().ConfigurationSchemaRef,
		"configurationBytes": []byte(`{}`),
		"catalog":            map[string]any{"directory": filepath.Dir(provenance.Path), "manifestPath": "manifest.json", "sourceId": provenance.SourceID, "sourcePath": provenance.Path, "scope": provenance.Scope, "sourceFile": sourcePath, "sourceChecksum": provenance.Checksum, "limits": map[string]any{"maxFileBytes": 128 << 20, "maxTotalBytes": 256 << 20, "maxFiles": 64}},
		"contracts":          []ContractBinding{{Kind: "tool", ContractRef: "urn:fixture:tool"}},
	})
	// The provisioner supplies an actual registered host and selected service
	// owners. It must not predict the manager's epoch or process generation.
	work, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var ready struct {
		CompositionPath   string `json:"compositionPath"`
		CompositionSHA256 string `json:"compositionSHA256"`
	}
	nativeLiveWait(t, work, directory, "foreground-ready.json", func(raw []byte) bool {
		if nativeLiveDecode(raw, &ready) != nil {
			t.Fatal("foreground ready document invalid")
		}
		return true
	})
	raw, err := ReadOwnerPrivateFile(ready.CompositionPath, 1<<20)
	if err != nil || nativeAuthorityDigest(raw) != ready.CompositionSHA256 {
		t.Fatal("foreground composition unavailable or changed")
	}
	var selected struct {
		SchemaVersion string `json:"schemaVersion"`
		NativeContext *struct {
			ProfileID       string `json:"profileId"`
			RepositoryRoot  string `json:"repositoryRoot"`
			SelectionPath   string `json:"selectionPath"`
			SelectionSHA256 string `json:"selectionSHA256"`
		} `json:"nativeContext"`
		Driver   NativeDriverOptions   `json:"driver"`
		Topology InstanceTopologyInput `json:"topology"`
	}
	if json.Unmarshal(raw, &selected) != nil || selected.SchemaVersion != "1.2.0" || selected.NativeContext == nil || len(selected.Topology.Instances) != 1 || len(selected.Topology.Roots) != 1 || selected.Topology.Roots[0] != "plugin-one" || selected.Topology.Instances[0].InstanceID != "plugin-one" || selected.Topology.Instances[0].Pin != pkg.Pin() {
		t.Fatal("foreground composition replaced the declared package or native host")
	}
	selectionRaw, err := ReadOwnerPrivateFile(selected.NativeContext.SelectionPath, nativeAuthorityLimit)
	if err != nil || nativeAuthorityDigest(selectionRaw) != selected.NativeContext.SelectionSHA256 || ValidateNativeHostSelection(selectionRaw) != nil {
		t.Fatal("foreground protected selection unavailable or changed")
	}
	var enrollment struct {
		ActivationDeclarations map[string]NativeActivationDeclaration `json:"activationDeclarations"`
		ConfigurationRoutes    map[string]struct {
			ConfigurationRef ContextReference `json:"configurationRef"`
		} `json:"configurationRoutes"`
	}
	if json.Unmarshal(selectionRaw, &enrollment) != nil {
		t.Fatal("foreground protected selection invalid")
	}
	declaration, exists := enrollment.ActivationDeclarations["plugin-one"]
	initial, hasConfiguration := enrollment.ConfigurationRoutes["plugin-one"]
	if !exists || !hasConfiguration || declaration.Pin != pkg.Pin() || declaration.ManifestDigest != pkg.Pin().ManifestChecksum || declaration.ConfigurationChecksum != configuration.Checksum() || declaration.RecordRef.Revision != 1 || declaration.PreviousRef != nil || initial.ConfigurationRef.Revision != 0 {
		t.Fatal("foreground protected selection replaced package or activation inputs")
	}
	expectedConfiguration := initial.ConfigurationRef
	expectedConfiguration.Revision++

	// The real command performs the complete closed-input, profile and selection
	// admission. These read-only commands cannot establish execution readiness.
	for _, verb := range []string{"validate", "plan"} {
		command := exec.CommandContext(work, cli, verb, "--composition", ready.CompositionPath)
		var output bytes.Buffer
		command.Stdout, command.Stderr = &output, &output
		if command.Run() != nil {
			t.Fatal("foreground read-only command refused its declarations")
		}
		want := "validated"
		if verb == "plan" {
			want = "planned"
		}
		var frame nativeCLIChildrenFrame
		if json.Unmarshal(bytes.TrimSpace(output.Bytes()), &frame) != nil || frame.Status != want || frame.SchemaVersion != "1.2.0" || len(frame.Pins) != 1 || frame.Pins[0] != pkg.Pin() || frame.Snapshot != nil {
			t.Fatal("foreground read-only result changed package identity or claimed activation")
		}
	}
	output, err := os.OpenFile(filepath.Join(directory, "foreground.private.jsonl"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("foreground private output unavailable")
	}
	command := exec.Command(cli, "run", "--composition", ready.CompositionPath, "--control-stdin")
	command.Stdout, command.Stderr = output, output
	input, err := command.StdinPipe()
	if err != nil {
		output.Close()
		t.Fatal("foreground original input unavailable")
	}
	if err = command.Start(); err != nil {
		input.Close()
		output.Close()
		t.Fatal("foreground command start failed")
	}
	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = command.Wait(); close(done) }()
	inputClosed := false
	t.Cleanup(func() {
		if !inputClosed {
			if input.Close() != nil {
				t.Error("foreground original input close failed")
			}
			inputClosed = true
		}
		select {
		case <-done:
		default:
			_ = command.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(8 * time.Second):
				t.Log("original foreground command and borrowed services retained for cooperative cleanup")
				nativeSubscriptionLiveCleanupState(directory, map[string]any{"phase": "foreground-cleanup-required"})
				<-done
			}
		}
		if output.Close() != nil {
			t.Error("foreground original output close failed")
		}
	})
	readFrames := func() []nativeCLIChildrenFrame {
		info, err := output.Stat()
		if err != nil || info.Size() > 1<<20 {
			t.Fatal("foreground output unavailable or exceeded bound")
		}
		raw := make([]byte, int(info.Size()))
		n, err := output.ReadAt(raw, 0)
		if n != len(raw) || err != nil {
			t.Fatal("foreground output read failed")
		}
		var frames []nativeCLIChildrenFrame
		lines := bytes.Split(raw, []byte{'\n'})
		for index, line := range lines {
			if len(line) == 0 {
				continue
			}
			var frame nativeCLIChildrenFrame
			if json.Unmarshal(line, &frame) != nil {
				if index == len(lines)-1 && !completed(done) {
					continue
				}
				t.Fatal("foreground command emitted an invalid result frame")
			}
			if frame.Status == "cleanup_required" {
				t.Fatal("foreground activation or cleanup remained incomplete")
			}
			frames = append(frames, frame)
		}
		return frames
	}
	var allocated OwnerReference
	for allocated.InstanceID == "" {
		for _, frame := range readFrames() {
			if frame.Status != "active" {
				continue
			}
			if frame.SchemaVersion != "1.2.0" || frame.Snapshot == nil || frame.Snapshot.RetainedCleanup != 0 || len(frame.Snapshot.Instances) != 1 || len(frame.Pins) != 1 || frame.Pins[0] != pkg.Pin() {
				t.Fatal("foreground native activation snapshot invalid")
			}
			instance := frame.Snapshot.Instances[0]
			if !contextOwnerValid(instance.Owner) || instance.Owner.InstanceID != "plugin-one" || instance.Owner.Pin != pkg.Pin() || instance.Owner.Generation != 1 || instance.State != "ready" || instance.Code != "" || instance.ConfigurationChecksum != configuration.Checksum() {
				t.Fatal("foreground process owner or readiness changed")
			}
			allocated = instance.Owner
		}
		if allocated.InstanceID != "" {
			break
		}
		select {
		case <-done:
			t.Fatal("foreground command exited before activation")
		case <-work.Done():
			t.Fatal("foreground activation deadline elapsed")
		case <-time.After(20 * time.Millisecond):
		}
	}
	nativeLiveWrite(t, directory, "go-foreground-result.json", map[string]any{"phase": "active", "owner": allocated, "configurationChecksum": configuration.Checksum()})
	var observed struct {
		Owner             OwnerReference   `json:"owner"`
		NativeInstanceRef ContextReference `json:"nativeInstanceRef"`
		ConfigurationRef  ContextReference `json:"configurationRef"`
	}
	nativeLiveWait(t, work, directory, "foreground-observed.json", func(raw []byte) bool {
		if nativeLiveDecode(raw, &observed) != nil {
			t.Fatal("foreground retained observation invalid")
		}
		return true
	})
	if observed.Owner != allocated || !contextReferenceValid(observed.NativeInstanceRef) || observed.NativeInstanceRef != declaration.RecordRef || !contextReferenceValid(observed.ConfigurationRef) || observed.ConfigurationRef != expectedConfiguration || observed.NativeInstanceRef.OwnerHubID != selected.Driver.HubID || observed.ConfigurationRef.OwnerHubID != selected.Driver.HubID {
		t.Fatal("retained native activation or configuration did not match the allocated owner")
	}
	if input.Close() != nil {
		inputClosed = true
		t.Fatal("foreground EOF close failed")
	}
	inputClosed = true
	select {
	case <-done:
	case <-work.Done():
		t.Fatal("foreground shutdown has not joined")
	}
	if waitErr != nil {
		t.Fatal("foreground command failed during shutdown")
	}
	frames := readFrames()
	if len(frames) < 2 || frames[len(frames)-1].SchemaVersion != "1.2.0" || frames[len(frames)-1].Status != "stopped" {
		t.Fatal("foreground command did not report completed shutdown")
	}
	entries, err := os.ReadDir(selected.Driver.StateDirectory)
	if err != nil {
		t.Fatal("foreground state directory unavailable after shutdown")
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "instance-") {
			t.Fatal("foreground original stage remained after shutdown")
		}
	}
	nativeLiveWrite(t, directory, "go-foreground-result.json", map[string]any{"phase": "complete", "activation": true, "retainedOwner": true, "cleanup": true})
}
