package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/plugins"
	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"
)

func testChecksum(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func commandFixture(t *testing.T) (composition, string) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	packageDir := filepath.Join(base, "package")
	if err = os.MkdirAll(filepath.Join(packageDir, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(packageDir, "schemas"), 0700); err != nil {
		t.Fatal(err)
	}
	manifest := plugins.Manifest{SchemaVersion: "1.0.0", PackageID: "example", Version: "1.0.0", APIMajor: 1, InstallationModes: []string{"independent"}, Platforms: []plugins.Platform{{OS: "darwin", Arch: "arm64"}}, Runtime: plugins.Runtime{Kind: "process", ExecutableRef: "bin/run", Args: []string{}, WorkingDirectoryPolicy: "package"}, Dependencies: []plugins.Dependency{}, Children: []plugins.Child{}, RequestedCapabilities: []plugins.Capability{}, ConfigurationSchemaRef: "schemas/config.json", Contributions: []plugins.Contribution{{Kind: "tool", ID: "inspect", ContractRef: "urn:example:inspect"}}, Lifecycle: plugins.Lifecycle{StartDeadlineMS: 1000, DrainDeadlineMS: 1000, RestartLimit: 0}, Migrations: []plugins.Migration{}}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string][]byte{"manifest.json": raw, "bin/run": []byte("not an executable qualification"), "schemas/config.json": []byte(`{"type":"object","properties":{"token":{"type":"string"}},"required":["token"],"additionalProperties":false}`)} {
		if err = os.WriteFile(filepath.Join(packageDir, name), value, 0700); err != nil {
			t.Fatal(err)
		}
	}
	source := []byte("original private-marker persona")
	sourceFile := filepath.Join(base, "source.md")
	if err = os.WriteFile(sourceFile, source, 0644); err != nil {
		t.Fatal(err)
	}
	configuration := filepath.Join(base, "configuration.json")
	if err = os.WriteFile(configuration, []byte(`{"token":"private-marker"}`), 0600); err != nil {
		t.Fatal(err)
	}
	input := plugins.PackageInput{Directory: packageDir, ManifestPath: "manifest.json", SourceID: "local-definition", SourcePath: sourceFile, Scope: "repo", Source: source, SourceChecksum: testChecksum(source), Limits: plugins.AdmissionLimits{MaxFileBytes: 4 << 20, MaxTotalBytes: 16 << 20, MaxFiles: 32}}
	admitted, err := plugins.AdmitPackage(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	account, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	defer account.Wipe()
	public, err := account.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	driver := plugins.NativeDriverOptions{HubID: "command-hub", AccountPublicKey: public, ServerURL: "tls://127.0.0.1:4222", CAFile: filepath.Join(base, "ca.pem"), StateDirectory: filepath.Join(base, "not-created"), ControllerCredentialsFile: filepath.Join(base, "controller.creds"), Bindings: []plugins.NativeBinding{{Pin: admitted.Pin(), InstanceID: "command-example", CredentialsFile: filepath.Join(base, "child.creds")}}}
	composition := composition{SchemaVersion: "1.0.0", Catalog: []catalogEntry{{Directory: packageDir, ManifestPath: "manifest.json", SourceID: input.SourceID, SourcePath: sourceFile, Scope: "repo", SourceFile: sourceFile, SourceChecksum: input.SourceChecksum, Limits: limits{MaxFileBytes: 4 << 20, MaxTotalBytes: 16 << 20, MaxFiles: 32}}}, Roots: []plugins.PackagePin{admitted.Pin()}, Selected: []plugins.PackagePin{}, InstallationMode: "independent", Platform: plugins.Platform{OS: "darwin", Arch: "arm64"}, Configurations: []configurationFile{{Pin: admitted.Pin(), Resources: []plugins.SchemaResource{}, ConfigurationFile: configuration}}, Contracts: []plugins.ContractBinding{{Kind: "tool", ContractRef: "urn:example:inspect"}}, Instances: map[string]string{"example": "command-example"}, Driver: driver, ActivationTimeoutMS: 5000, CleanupTimeoutMS: 1000}
	file := filepath.Join(base, "composition.json")
	writeComposition(t, file, composition)
	if _, err := plugins.ReadOwnerPrivateFile(file, compositionLimit); err != nil {
		t.Fatalf("fixture private file admission: %v", err)
	}
	return composition, file
}
func writeComposition(t *testing.T, file string, input composition) {
	t.Helper()
	type wireComposition composition
	raw, err := json.Marshal(wireComposition(input))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestReadOnlyCommandsUseActualAdmissionConfigurationAndRegistry(t *testing.T) {
	input, file := commandFixture(t)
	for _, verb := range []string{"validate", "plan"} {
		var output bytes.Buffer
		if err := execute(context.Background(), []string{verb, "--composition", file}, &output); err != nil {
			t.Fatal(err)
		}
		var result commandResult
		if json.Unmarshal(output.Bytes(), &result) != nil {
			t.Fatal("invalid result")
		}
		expected := "validated"
		if verb == "plan" {
			expected = "planned"
		}
		if result.Status != expected || result.PackageCount != 1 || result.ContributionCount != 1 || len(result.Pins) != 1 || result.Pins[0] != input.Roots[0] {
			t.Fatal("invalid plan response")
		}
		if strings.Contains(output.String(), "private-marker") || strings.Contains(output.String(), filepath.Dir(file)) {
			t.Fatal("private input exposed")
		}
	}
	// Dry planning deliberately neither creates state nor reads nonexistent broker
	// credentials. This is not a native image, transport or readiness qualification.
	if _, err := os.Stat(input.Driver.StateDirectory); !os.IsNotExist(err) {
		t.Fatal("read-only command created state")
	}
	for _, path := range []string{input.Driver.ControllerCredentialsFile, input.Driver.Bindings[0].CredentialsFile} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("read-only command touched credential reference")
		}
	}
}

func TestCommandPreflightRefusesInvalidCandidateWithoutRuntimeEffects(t *testing.T) {
	changes := []struct {
		name   string
		change func(*composition)
	}{
		{"source-checksum", func(c *composition) { c.Catalog[0].SourceChecksum = testChecksum([]byte("wrong")) }},
		{"pin", func(c *composition) { c.Roots[0].PackageChecksum = testChecksum([]byte("wrong")) }},
		{"contract", func(c *composition) { c.Contracts = nil }},
		{"missing-configuration", func(c *composition) { c.Configurations = []configurationFile{} }},
		{"instance", func(c *composition) { c.Instances["example"] = "other" }},
		{"driver-pin", func(c *composition) { c.Driver.Bindings[0].Pin.ProvenanceChecksum = testChecksum([]byte("wrong")) }},
		{"endpoint", func(c *composition) { c.Driver.ServerURL = "nats://private-marker@example.invalid:4222" }},
	}
	for _, test := range changes {
		t.Run(test.name, func(t *testing.T) {
			input, file := commandFixture(t)
			test.change(&input)
			writeComposition(t, file, input)
			var output bytes.Buffer
			err := execute(context.Background(), []string{"run", "--composition", file}, &output)
			if err == nil {
				t.Fatal("invalid candidate activated")
			}
			if output.Len() != 0 || strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), "private-marker") {
				t.Fatal("private input exposed")
			}
			if _, err := os.Stat(input.Driver.StateDirectory); !os.IsNotExist(err) {
				t.Fatal("invalid candidate created driver state")
			}
		})
	}
}

func TestCompositionClosedFieldsAndPrivateFileAdmission(t *testing.T) {
	input, file := commandFixture(t)
	type wireComposition composition
	raw, _ := json.Marshal(wireComposition(input))
	cases := [][]byte{bytes.Replace(raw, []byte(`"schemaVersion"`), []byte(`"SchemaVersion"`), 1), bytes.Replace(raw, []byte(`"instanceId"`), []byte(`"instanceID"`), 1), bytes.Replace(raw, []byte(`"schemaVersion":"1.0.0"`), []byte(`"schemaVersion":"1.0.0","schemaVersion":"1.0.0"`), 1), append(bytes.Clone(raw), []byte(` {}`)...), []byte(`"\ud800"`)}
	for _, candidate := range cases {
		if err := os.WriteFile(file, candidate, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadComposition(context.Background(), file); err == nil {
			t.Fatal("non-closed composition accepted")
		}
	}
	writeComposition(t, file, input)
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadComposition(context.Background(), file); err == nil {
		t.Fatal("public composition accepted")
	}
	if err := os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(file), "link.json")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadComposition(context.Background(), link); err == nil {
		t.Fatal("composition symlink accepted")
	}
	source := input.Catalog[0].SourceFile
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = readSource(source); err != nil {
		t.Fatal("0644 owner source rejected")
	}
	if after, _ := os.ReadFile(source); !bytes.Equal(original, after) {
		t.Fatal("source mutated")
	}
	for _, value := range []any{input, preparedComposition{}} {
		encoded, _ := json.Marshal(value)
		if strings.Contains(fmt.Sprintf("%v %+v %#v", value, value, value)+string(encoded), "private-marker") {
			t.Fatal("private composition formatted")
		}
	}
}

func TestCommandArgumentsCancellationAndOutputBackpressure(t *testing.T) {
	var output bytes.Buffer
	for _, args := range [][]string{nil, {"unknown", "--composition", "private-marker"}, {"plan", "--composition"}, {"plan", "--composition", "private-marker", "extra"}} {
		if err := execute(context.Background(), args, &output); err == nil {
			t.Fatal("invalid arguments accepted")
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := execute(canceled, []string{"plan", "--composition", "private-marker"}, &output); err == nil {
		t.Fatal("canceled command admitted")
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	fd := int(writer.Fd())
	if err = unix.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	for {
		_, err = unix.Write(fd, make([]byte, 4096))
		if err == unix.EAGAIN {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err = unix.SetNonblock(fd, false); err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer stop()
	start := time.Now()
	if err = writeResult(ctx, writer, commandResult{SchemaVersion: "1.0.0", Status: "validated"}); err == nil {
		t.Fatal("blocked output reported success")
	}
	if time.Since(start) > time.Second {
		t.Fatal("output owner did not return within budget")
	}
}

type testManagerOwner struct {
	done                   chan struct{}
	closeCalls, retryCalls int
	events                 *[]string
}

func (o *testManagerOwner) Close(context.Context) error {
	o.closeCalls++
	*o.events = append(*o.events, "manager-close")
	if o.closeCalls == 1 {
		return errors.New("private-marker")
	}
	return nil
}
func (o *testManagerOwner) RetryCleanup(context.Context) error {
	o.retryCalls++
	*o.events = append(*o.events, "manager-retry")
	close(o.done)
	return nil
}
func (o *testManagerOwner) Done() <-chan struct{} { return o.done }

type testDriverOwner struct {
	manager *testManagerOwner
	calls   int
	events  *[]string
}

func (o *testDriverOwner) Close(context.Context) error {
	o.calls++
	select {
	case <-o.manager.done:
	default:
		panic("driver closed before manager joined")
	}
	*o.events = append(*o.events, "driver-close")
	if o.calls == 1 {
		return errors.New("private-marker")
	}
	return nil
}
func TestCommandCleanupKeepsOriginalOwnersAndJoinsManagerFirst(t *testing.T) {
	var events []string
	manager := &testManagerOwner{done: make(chan struct{}), events: &events}
	driver := &testDriverOwner{manager: manager, events: &events}
	var output bytes.Buffer
	err := shutdownOwned(manager, driver, time.Second, &output)
	if err == nil || errorCode(err) != "plugin_cleanup_delayed" || manager.closeCalls != 2 || manager.retryCalls != 1 || driver.calls != 2 {
		t.Fatal("cleanup ownership lost")
	}
	if strings.Contains(output.String()+fmt.Sprintf("%v %+v %#v", err, err, err), "private-marker") {
		t.Fatal("cleanup cause exposed")
	}
	if strings.Count(output.String(), "cleanup_required") != 1 || len(events) != 5 {
		t.Fatal("cleanup progress unbounded")
	}
}

func TestCommandOutputShortWriteFails(t *testing.T) {
	if err := writeResult(context.Background(), shortOutput{}, commandResult{Status: "validated"}); err == nil {
		t.Fatal("short output accepted")
	}
}

type shortOutput struct{}

func (shortOutput) Write(raw []byte) (int, error) { return 0, io.ErrShortWrite }
