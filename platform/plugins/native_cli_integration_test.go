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

// This check runs the actual command and native child against the existing
// private TLS broker fixture. It does not qualify an installed kernel release.
func TestNativeLiveCLIPlanAndForegroundShutdown(t *testing.T) {
	cli := os.Getenv("AGENTMUX_PLUGIN_CLI")
	if cli == "" || os.Getenv("AGENTMUX_PLUGIN_NATS") == "" || os.Getenv("AGENTMUX_PLUGIN_NSC") == "" {
		t.Skip("prepared native CLI, NATS and nsc paths required")
	}
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("native macOS ARM64 check")
	}
	pkg := nativeFixturePackage(t, "foreground")
	fixture := liveNativeBroker(t, []AdmittedPackage{pkg})
	options := fixture.options
	options.StateDirectory = filepath.Join(fixture.root, "cli-state")
	// Source bytes remain outside the admitted package, preserving its exact pin.
	provenance := pkg.Provenance()
	sourcePath := filepath.Join(fixture.root, "source.md")
	configurationPath := filepath.Join(fixture.root, "configuration.json")
	compositionPath := filepath.Join(fixture.root, "composition.json")
	write := func(path string, raw []byte) {
		t.Helper()
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal("private CLI input write failed")
		}
	}
	write(sourcePath, provenance.Source())
	write(configurationPath, []byte(`{"behavior":"normal"}`))
	input := map[string]any{
		"schemaVersion": "1.0.0", "installationMode": "independent",
		"platform":            Platform{OS: "darwin", Arch: "arm64"},
		"activationTimeoutMs": 5000, "cleanupTimeoutMs": 4000,
		"catalog": []any{map[string]any{
			"directory": filepath.Dir(provenance.Path), "manifestPath": "manifest.json",
			"sourceId": provenance.SourceID, "sourcePath": provenance.Path, "scope": provenance.Scope,
			"sourceFile": sourcePath, "sourceChecksum": provenance.Checksum,
			"limits": map[string]any{"maxFileBytes": 128 << 20, "maxTotalBytes": 256 << 20, "maxFiles": 64},
		}},
		"roots": []PackagePin{pkg.Pin()}, "selected": []PackagePin{},
		"configurations": []any{map[string]any{
			"pin": pkg.Pin(), "resources": []SchemaResource{{Ref: "schemas/config.json", File: "schemas/config.json"}},
			"configurationFile": configurationPath,
		}},
		"contracts": []ContractBinding{{Kind: "tool", ContractRef: "urn:fixture:tool"}},
		"instances": map[string]string{pkg.Pin().PackageID: pkg.Pin().PackageID}, "driver": options,
	}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal("CLI composition encoding failed")
	}
	write(compositionPath, raw)
	for _, verb := range []string{"validate", "plan"} {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		command := exec.CommandContext(ctx, cli, verb, "--composition", compositionPath)
		var output bytes.Buffer
		command.Stdout, command.Stderr = &output, &output
		err = command.Run() // Run waits for this original process and its output copy.
		cancel()
		if err != nil {
			t.Fatal("read-only CLI command failed; private output withheld")
		}
		status := "validated"
		if verb == "plan" {
			status = "planned"
		}
		frames := nativeCLIFrames(t, output.Bytes())
		if len(frames) != 1 || frames[0].Status != status || len(frames[0].Pins) != 1 || frames[0].Pins[0] != pkg.Pin() || frames[0].PackageCount != 1 || frames[0].ContributionCount != 1 {
			t.Fatal("read-only CLI result did not preserve the selected package")
		}
		if _, err := os.Lstat(options.StateDirectory); !os.IsNotExist(err) {
			t.Fatal("read-only CLI created runtime state")
		}
	}
	// Runtime state is an explicit owner-prepared input, not a dry-run effect.
	if err := os.Mkdir(options.StateDirectory, 0700); err != nil {
		t.Fatal("private CLI state preparation failed")
	}
	outputPath := filepath.Join(fixture.root, "cli-output.private.jsonl")
	output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("CLI private output file failed")
	}
	command := exec.Command(cli, "run", "--composition", compositionPath)
	command.Stdout, command.Stderr = output, output
	if err = command.Start(); err != nil {
		_ = output.Close()
		t.Fatal("foreground CLI start failed")
	}
	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = command.Wait(); close(done) }()
	// Keep this exact command and its output file until the original Wait joins.
	// This cleanup runs before the broker fixture cleanup on every failure path.
	t.Cleanup(func() {
		select {
		case <-done:
		default:
			_ = command.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(6 * time.Second):
				_ = command.Process.Kill()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("original CLI process ownership unresolved")
				}
			}
		}
		if err := output.Close(); err != nil {
			t.Error("CLI output file close failed")
		}
	})
	active := false
	until := time.Now().Add(8 * time.Second)
	for time.Now().Before(until) {
		raw, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatal("CLI private output read failed")
		}
		// The writer may still be completing its final line.
		for _, line := range bytes.Split(raw, []byte{'\n'}) {
			var frame nativeCLIFrame
			if json.Unmarshal(line, &frame) == nil && frame.Status == "active" {
				active = true
			}
		}
		if active {
			break
		}
		select {
		case <-done:
			t.Fatal("foreground CLI exited before active; private output withheld")
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !active {
		t.Fatal("foreground CLI did not report active")
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal("foreground CLI stop signal failed")
	}
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("foreground CLI did not join after stop")
	}
	if waitErr != nil {
		t.Fatal("foreground CLI failed during shutdown; private output withheld")
	}
	raw, err = os.ReadFile(outputPath)
	if err != nil {
		t.Fatal("joined CLI output read failed")
	}
	frames := nativeCLIFrames(t, raw)
	if len(frames) != 2 || frames[0].Status != "active" || frames[1].Status != "stopped" {
		t.Fatal("foreground CLI lifecycle results invalid")
	}
	for _, frame := range frames {
		if len(frame.Pins) != 1 || frame.Pins[0] != pkg.Pin() || frame.PackageCount != 1 || frame.ContributionCount != 1 {
			t.Fatal("foreground CLI result changed package identity")
		}
	}
	entries, err := os.ReadDir(options.StateDirectory)
	if err != nil {
		t.Fatal("joined CLI state read failed")
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "instance-") {
			t.Fatal("foreground CLI left an owned stage")
		}
	}
}

type nativeCLIFrame struct {
	SchemaVersion     string       `json:"schemaVersion"`
	Status            string       `json:"status"`
	PackageCount      int          `json:"packageCount"`
	ContributionCount int          `json:"contributionCount"`
	Pins              []PackagePin `json:"pins"`
}

func nativeCLIFrames(t *testing.T, raw []byte) []nativeCLIFrame {
	t.Helper()
	var result []nativeCLIFrame
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
		var frame nativeCLIFrame
		if json.Unmarshal(line, &frame) != nil || frame.SchemaVersion != "1.0.0" {
			t.Fatal("CLI output was not a complete result frame; private output withheld")
		}
		result = append(result, frame)
	}
	return result
}
