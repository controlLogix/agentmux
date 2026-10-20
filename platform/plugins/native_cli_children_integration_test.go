package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type nativeCLIChildrenFrame struct {
	SchemaVersion string           `json:"schemaVersion"`
	Status        string           `json:"status"`
	Code          string           `json:"code"`
	Pins          []PackagePin     `json:"pins"`
	Snapshot      *ManagerSnapshot `json:"snapshot"`
}

// This exercises the actual foreground command's owner controls. Broker and
// process lifecycle faults are covered by the separate native manager checks.
func TestNativeLiveCLIChildRootControlsAndEOF(t *testing.T) {
	cli := os.Getenv("AGENTMUX_PLUGIN_CLI")
	if cli == "" || os.Getenv("AGENTMUX_PLUGIN_NATS") == "" || os.Getenv("AGENTMUX_PLUGIN_NSC") == "" {
		t.Skip("prepared native CLI, NATS and nsc paths required")
	}
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("native macOS ARM64 check")
	}
	private := nativeFixturePackage(t, "private", func(m *Manifest) { m.InstallationModes = []string{"private-child"} })
	shared := nativeFixturePackage(t, "shared")
	parent := func(m *Manifest) {
		m.Children = []Child{{"private", "private", true}, {"shared", "independent-reference", true}}
	}
	a, b := nativeFixturePackage(t, "parenta", parent), nativeFixturePackage(t, "parentb", parent)
	packages := []AdmittedPackage{a, b, private, shared}
	fixture := liveNativeBroker(t, []AdmittedPackage{a, b, private, private, shared}, "parenta", "parentb", "privatea", "privateb", "shared")
	topology := InstanceTopologyInput{Roots: []string{"parenta", "parentb", "shared"}, Children: []ChildBinding{{"parenta", "privatea", "private"}, {"parentb", "privateb", "private"}, {"parenta", "shared", "independent-reference"}, {"parentb", "shared", "independent-reference"}}, Dependencies: []DependencyBinding{}}
	for index, id := range []string{"parenta", "parentb", "privatea", "privateb", "shared"} {
		p := []AdmittedPackage{a, b, private, private, shared}[index]
		mode := "independent"
		if strings.HasPrefix(id, "private") {
			mode = "private-child"
		}
		topology.Instances = append(topology.Instances, InstanceSpec{id, p.Pin(), mode, Placement{"local-process"}})
	}
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(fixture.root, name)
		if os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("private graph CLI input write failed")
		}
		return path
	}
	var catalog, configs []any
	for _, p := range packages {
		provenance := p.Provenance()
		source := write(p.Pin().PackageID+"-source.md", provenance.Source())
		catalog = append(catalog, map[string]any{"directory": filepath.Dir(provenance.Path), "manifestPath": "manifest.json", "sourceId": provenance.SourceID, "sourcePath": provenance.Path, "scope": provenance.Scope, "sourceFile": source, "sourceChecksum": provenance.Checksum, "limits": map[string]any{"maxFileBytes": 128 << 20, "maxTotalBytes": 128 << 20, "maxFiles": 64}})
	}
	for _, node := range topology.Instances {
		config := write(node.InstanceID+"-config.json", []byte(`{"behavior":"normal"}`))
		configs = append(configs, map[string]any{"instanceId": node.InstanceID, "pin": node.Pin, "resources": []SchemaResource{{Ref: "schemas/config.json", File: "schemas/config.json"}}, "configurationFile": config})
	}
	options := fixture.options
	options.StateDirectory = filepath.Join(fixture.root, "cli-children-state")
	if os.Mkdir(options.StateDirectory, 0700) != nil {
		t.Fatal("private graph CLI state preparation failed")
	}
	composition := map[string]any{"schemaVersion": "1.1.0", "installationMode": "independent", "platform": Platform{"darwin", "arm64"}, "activationTimeoutMs": 8000, "cleanupTimeoutMs": 5000, "catalog": catalog, "selected": []PackagePin{}, "contracts": []ContractBinding{{Kind: "tool", ContractRef: "urn:fixture:tool"}}, "driver": options, "topology": topology, "instanceConfigurations": configs}
	raw, err := json.Marshal(composition)
	if err != nil {
		t.Fatal("graph CLI composition encoding failed")
	}
	compositionPath := write("children-composition.json", raw)
	outputPath := filepath.Join(fixture.root, "cli-children-output.private.jsonl")
	output, err := os.OpenFile(outputPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("graph CLI private output unavailable")
	}
	command := exec.Command(cli, "run", "--composition", compositionPath, "--control-stdin")
	command.Stdout, command.Stderr = output, output
	stdin, err := command.StdinPipe()
	if err != nil {
		_ = output.Close()
		t.Fatal("graph CLI input pipe unavailable")
	}
	if err = command.Start(); err != nil {
		_ = stdin.Close()
		_ = output.Close()
		t.Fatal("graph CLI foreground start failed")
	}
	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = command.Wait(); close(done) }()
	inputClosed := false
	// This cleanup precedes the fixture broker cleanup. Keep the original command,
	// pipe and output descriptor until its Wait has joined; never adopt descendants.
	t.Cleanup(func() {
		if !inputClosed {
			if stdin.Close() != nil {
				t.Error("graph CLI input close failed")
			}
			inputClosed = true
		}
		select {
		case <-done:
		default:
			_ = command.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(7 * time.Second):
				t.Error("graph CLI required forced stop; descendant cleanup unconfirmed")
				_ = command.Process.Kill()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("original graph CLI ownership unresolved")
					return
				}
			}
		}
		if output.Close() != nil {
			t.Error("graph CLI output close failed")
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	readFrames := func() []nativeCLIChildrenFrame {
		t.Helper()
		info, e := output.Stat()
		if e != nil || info.Size() > 1<<20 {
			t.Fatal("graph CLI output unavailable or exceeded bound")
		}
		buf := make([]byte, info.Size())
		if len(buf) > 0 {
			if _, e = output.ReadAt(buf, 0); e != nil {
				t.Fatal("graph CLI private output read failed")
			}
		}
		if completed(done) && len(buf) > 0 && buf[len(buf)-1] != '\n' {
			t.Fatal("joined graph CLI left incomplete output")
		}
		var frames []nativeCLIChildrenFrame
		complete := bytes.LastIndexByte(buf, '\n')
		if complete < 0 {
			return frames
		}
		for _, line := range bytes.Split(buf[:complete], []byte{'\n'}) {
			if len(line) == 0 {
				continue
			}
			var frame nativeCLIChildrenFrame
			if json.Unmarshal(line, &frame) != nil || frame.SchemaVersion != "1.1.0" {
				t.Fatal("graph CLI emitted invalid or failure output; private bytes withheld")
			}
			frames = append(frames, frame)
		}
		return frames
	}
	cursor := 0
	await := func(status string, predicate func(nativeCLIChildrenFrame) bool) nativeCLIChildrenFrame {
		t.Helper()
		for {
			frames := readFrames()
			for cursor < len(frames) {
				frame := frames[cursor]
				cursor++
				if frame.Status == status && (predicate == nil || predicate(frame)) {
					return frame
				}
			}
			select {
			case <-done:
				t.Fatal("graph CLI exited before expected result; private output withheld")
			case <-ctx.Done():
				t.Fatal("graph CLI result deadline exceeded")
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	send := func(value any) {
		t.Helper()
		wire, e := json.Marshal(value)
		if e != nil || len(wire) > 8191 {
			t.Fatal("graph CLI control encoding failed")
		}
		wire = append(wire, '\n')
		file, ok := stdin.(*os.File)
		if !ok {
			t.Fatal("graph CLI original input descriptor unavailable")
		}
		// One-byte writes after polling cannot wait for a larger atomic pipe slot.
		// The same context bounds every write; there is no extra writer goroutine.
		for len(wire) > 0 {
			if ctx.Err() != nil {
				t.Fatal("graph CLI control write deadline exceeded")
			}
			poll := []unix.PollFd{{Fd: int32(file.Fd()), Events: unix.POLLOUT}}
			ready, e := unix.Poll(poll, 25)
			if e == unix.EINTR {
				continue
			}
			if e != nil || poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				t.Fatal("graph CLI control pipe failed")
			}
			if ready == 0 {
				continue
			}
			n, e := unix.Write(int(file.Fd()), wire[:1])
			if e == unix.EINTR || e == unix.EAGAIN {
				continue
			}
			if e != nil || n != 1 {
				t.Fatal("graph CLI control write failed")
			}
			wire = wire[1:]
		}
		runtime.KeepAlive(file)
	}
	instances := func(frame nativeCLIChildrenFrame) map[string]InstanceSnapshot {
		t.Helper()
		if frame.Snapshot == nil || frame.Snapshot.RetainedCleanup != 0 {
			t.Fatal("graph CLI snapshot missing or cleanup incomplete")
		}
		result := map[string]InstanceSnapshot{}
		for _, instance := range frame.Snapshot.Instances {
			if result[instance.Owner.InstanceID].Owner.InstanceID != "" || instance.State != "ready" || instance.Code != "" {
				t.Fatal("graph CLI snapshot not exclusively current ready instances")
			}
			result[instance.Owner.InstanceID] = instance
		}
		return result
	}
	active := await("active", nil)
	owners := instances(active)
	if len(owners) != 5 {
		t.Fatal("graph CLI did not activate complete topology")
	}
	for _, node := range topology.Instances {
		current := owners[node.InstanceID]
		if current.Instance != node || current.Owner.Pin != node.Pin || current.Owner.Generation != 1 {
			t.Fatal("graph CLI changed instance pin or explicit placement")
		}
		if node.InstallationMode == "private-child" {
			parentID := "parenta"
			if node.InstanceID == "privateb" {
				parentID = "parentb"
			}
			if current.Parent == nil || *current.Parent != owners[parentID].Owner || current.RootRetained {
				t.Fatal("graph CLI lost exact private lifetime")
			}
		} else if current.Parent != nil || !current.RootRetained {
			t.Fatal("independent instance acquired private ownership")
		}
	}
	if !reflect.DeepEqual(owners["shared"].Consumers, []string{"parenta", "parentb"}) {
		t.Fatal("graph CLI lost shared consumers")
	}
	send(map[string]any{"schemaVersion": "1.0.0", "action": "snapshot"})
	snapshot := instances(await("snapshot", nil))
	if len(snapshot) != 5 || snapshot["shared"].Owner != owners["shared"].Owner {
		t.Fatal("snapshot command changed active owner")
	}
	release := func(owner OwnerReference) {
		send(map[string]any{"schemaVersion": "1.0.0", "action": "release-root", "owner": owner})
	}
	release(owners["shared"].Owner)
	frame := await("snapshot", func(f nativeCLIChildrenFrame) bool {
		return f.Snapshot != nil && len(f.Snapshot.Instances) == 5 && !instances(f)["shared"].RootRetained
	})
	if instances(frame)["shared"].Owner != owners["shared"].Owner {
		t.Fatal("shared root release changed consumer-owned instance")
	}
	release(owners["parenta"].Owner)
	frame = await("snapshot", func(f nativeCLIChildrenFrame) bool { return f.Snapshot != nil && len(f.Snapshot.Instances) == 3 })
	remaining := instances(frame)
	for _, id := range []string{"parentb", "privateb", "shared"} {
		if remaining[id].Owner != owners[id].Owner {
			t.Fatal("one parent release interrupted another owner")
		}
	}
	if !reflect.DeepEqual(remaining["shared"].Consumers, []string{"parentb"}) || remaining["shared"].RootRetained {
		t.Fatal("shared retention claims were conflated")
	}
	assertNativeCLIChildStages(t, options.StateDirectory, []string{"parentb", "privateb", "shared"})
	release(owners["parenta"].Owner)
	rejected := await("rejected", nil)
	if rejected.Code != "plugin_owner_stale" {
		t.Fatal("stale root owner was not refused")
	}
	remaining = instances(rejected)
	if len(remaining) != 3 || remaining["shared"].Owner != owners["shared"].Owner {
		t.Fatal("stale control ended unrelated active owners")
	}
	// A still-live shared process no longer owns a root claim. Refusing this
	// second release must preserve both its consumer and that consumer's child.
	release(owners["shared"].Owner)
	rejected = await("rejected", nil)
	if rejected.Code != "plugin_root_not_retained" || len(instances(rejected)) != 3 {
		t.Fatal("invalid retention release changed active graph")
	}
	if stdin.Close() != nil {
		t.Fatal("graph CLI input EOF failed")
	}
	inputClosed = true
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("graph CLI did not join after EOF")
	}
	if waitErr != nil {
		t.Fatal("graph CLI failed during EOF cleanup; private output withheld")
	}
	frames := readFrames()
	if len(frames) == 0 || frames[len(frames)-1].Status != "stopped" {
		t.Fatal("graph CLI did not report joined stop")
	}
	for _, f := range frames {
		if !reflect.DeepEqual(f.Pins, active.Pins) {
			t.Fatal("graph CLI changed admitted package pins")
		}
	}
	assertNativeCLIChildStages(t, options.StateDirectory, nil)
}

func assertNativeCLIChildStages(t *testing.T, state string, expected []string) {
	t.Helper()
	entries, err := os.ReadDir(state)
	if err != nil {
		t.Fatal("graph CLI private state unavailable")
	}
	var actual []string
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "instance-") {
			continue
		}
		file, err := os.OpenFile(filepath.Join(state, entry.Name(), "bootstrap.json"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal("graph CLI owned stage inspection failed")
		}
		raw, readErr := io.ReadAll(io.LimitReader(file, 8193))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(raw) > 8192 {
			t.Fatal("graph CLI owned stage inspection failed")
		}
		var bootstrap struct {
			Prepare LifecycleControl `json:"prepare"`
		}
		if json.Unmarshal(raw, &bootstrap) != nil {
			t.Fatal("graph CLI owned stage metadata invalid")
		}
		actual = append(actual, bootstrap.Prepare.Owner.InstanceID)
	}
	sort.Strings(actual)
	want := append([]string(nil), expected...)
	sort.Strings(want)
	if !reflect.DeepEqual(actual, want) {
		t.Fatal("graph CLI private stages did not match joined owner set")
	}
}
