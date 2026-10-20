package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/controlLogix/agentmux/platform/plugins"
)

func graphCommandFixture(t *testing.T) (composition, string) {
	t.Helper()
	input, file := commandFixture(t)
	child, _ := commandFixture(t)
	admit := func(entry catalogEntry, edit func(*plugins.Manifest)) plugins.PackagePin {
		t.Helper()
		path := filepath.Join(entry.Directory, "manifest.json")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("graph manifest fixture unavailable")
		}
		var manifest plugins.Manifest
		if json.Unmarshal(raw, &manifest) != nil {
			t.Fatal("graph manifest fixture invalid")
		}
		edit(&manifest)
		raw, err = json.Marshal(manifest)
		if err != nil || os.WriteFile(path, raw, 0700) != nil {
			t.Fatal("graph manifest fixture write failed")
		}
		source, err := os.ReadFile(entry.SourceFile)
		if err != nil {
			t.Fatal("graph source fixture unavailable")
		}
		pkg, err := plugins.AdmitPackage(context.Background(), plugins.PackageInput{Directory: entry.Directory, ManifestPath: entry.ManifestPath, SourceID: entry.SourceID, SourcePath: entry.SourcePath, Scope: entry.Scope, Source: source, SourceChecksum: entry.SourceChecksum, Limits: plugins.AdmissionLimits{MaxFileBytes: entry.Limits.MaxFileBytes, MaxTotalBytes: entry.Limits.MaxTotalBytes, MaxFiles: entry.Limits.MaxFiles}})
		if err != nil {
			t.Fatal("graph package fixture admission failed")
		}
		return pkg.Pin()
	}
	parentPin := admit(input.Catalog[0], func(m *plugins.Manifest) {
		m.Children = []plugins.Child{{PackageID: "private", Relationship: "private", Required: true}}
	})
	childPin := admit(child.Catalog[0], func(m *plugins.Manifest) {
		m.PackageID = "private"
		m.InstallationModes = []string{"private-child"}
		m.Contributions[0].ID = "private-inspect"
	})
	parentID, childID := "command-parent", "command-private"
	input.SchemaVersion = "1.1.0"
	input.Catalog = append(input.Catalog, child.Catalog[0])
	input.Roots = nil
	input.Instances = nil
	input.Configurations = nil
	input.Topology = &plugins.InstanceTopologyInput{Instances: []plugins.InstanceSpec{{InstanceID: parentID, Pin: parentPin, InstallationMode: "independent", Placement: plugins.Placement{Kind: "local-process"}}, {InstanceID: childID, Pin: childPin, InstallationMode: "private-child", Placement: plugins.Placement{Kind: "local-process"}}}, Roots: []string{parentID}, Children: []plugins.ChildBinding{{ParentID: parentID, ChildID: childID, Relationship: "private"}}, Dependencies: []plugins.DependencyBinding{}}
	input.InstanceConfigurations = []instanceConfigurationFile{{InstanceID: parentID, Pin: parentPin, Resources: []plugins.SchemaResource{}, ConfigurationFile: filepath.Join(filepath.Dir(file), "configuration.json")}, {InstanceID: childID, Pin: childPin, Resources: []plugins.SchemaResource{}, ConfigurationFile: child.Configurations[0].ConfigurationFile}}
	input.Driver.Bindings = []plugins.NativeBinding{{Pin: parentPin, InstanceID: parentID, CredentialsFile: filepath.Join(filepath.Dir(file), "parent.creds")}, {Pin: childPin, InstanceID: childID, CredentialsFile: filepath.Join(filepath.Dir(file), "private.creds")}}
	writeComposition(t, file, input)
	return input, file
}
func assertGraphCommandNoEffects(t *testing.T, input composition) {
	t.Helper()
	for _, path := range append([]string{input.Driver.StateDirectory, input.Driver.ControllerCredentialsFile, input.Driver.CAFile}, input.Driver.Bindings[0].CredentialsFile, input.Driver.Bindings[1].CredentialsFile) {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("read-only graph command touched runtime or credential reference")
		}
	}
}
func TestGraphReadOnlyCommandsPreserveExactBindingsAndPrivateInputs(t *testing.T) {
	input, file := graphCommandFixture(t)
	prepared, err := loadComposition(context.Background(), file)
	if err != nil {
		t.Fatal(err)
	}
	if !prepared.graph || prepared.request.Topology == nil || !reflect.DeepEqual(*prepared.request.Topology, *input.Topology) || len(prepared.request.InstanceConfigurations) != 2 || len(prepared.request.Configurations) != 0 || len(prepared.request.Instances) != 0 || len(prepared.request.Roots) != 0 {
		t.Fatal("graph normalization changed explicit instance binding")
	}
	for _, verb := range []string{"validate", "plan"} {
		var output bytes.Buffer
		if err := execute(context.Background(), []string{verb, "--composition", file}, &output); err != nil {
			t.Fatal(err)
		}
		var result commandResult
		if json.Unmarshal(output.Bytes(), &result) != nil {
			t.Fatal("invalid graph result")
		}
		want := "validated"
		if verb == "plan" {
			want = "planned"
		}
		if result.SchemaVersion != "1.1.0" || result.Status != want || result.PackageCount != 2 || result.ContributionCount != 2 || len(result.Pins) != 2 || result.Snapshot != nil {
			t.Fatal("read-only graph result claimed wrong identity or runtime state")
		}
		pins := map[plugins.PackagePin]bool{}
		for _, pin := range result.Pins {
			pins[pin] = true
		}
		for _, node := range input.Topology.Instances {
			if !pins[node.Pin] {
				t.Fatal("graph output lost full package pin")
			}
		}
		if strings.Contains(output.String(), "private-marker") || strings.Contains(output.String(), filepath.Dir(file)) {
			t.Fatal("graph command exposed private input")
		}
	}
	assertGraphCommandNoEffects(t, input)
}
func TestGraphCommandRejectsInvalidTopologyBindingsBeforeEffects(t *testing.T) {
	cases := []struct {
		name   string
		change func(*composition)
	}{
		{"legacy-roots", func(c *composition) { c.Roots = []plugins.PackagePin{c.Topology.Instances[0].Pin} }},
		{"legacy-empty-roots", func(c *composition) { c.Roots = []plugins.PackagePin{} }},
		{"legacy-instances", func(c *composition) { c.Instances = map[string]string{"example": "command-parent"} }},
		{"legacy-empty-instances", func(c *composition) { c.Instances = map[string]string{} }},
		{"legacy-configurations", func(c *composition) { c.Configurations = []configurationFile{} }},
		{"placement", func(c *composition) { c.Topology.Instances[0].Placement.Kind = "remote-process" }},
		{"configuration-pin", func(c *composition) {
			c.InstanceConfigurations[1].Pin.ProvenanceChecksum = testChecksum([]byte("private-marker"))
		}},
		{"configuration-id", func(c *composition) { c.InstanceConfigurations[1].InstanceID = "unknown" }},
		{"configuration-duplicate", func(c *composition) { c.InstanceConfigurations[1] = c.InstanceConfigurations[0] }},
		{"configuration-missing", func(c *composition) { c.InstanceConfigurations = c.InstanceConfigurations[:1] }},
		{"instance-duplicate", func(c *composition) { c.Topology.Instances[1].InstanceID = c.Topology.Instances[0].InstanceID }},
		{"native-binding-duplicate", func(c *composition) { c.Driver.Bindings[1] = c.Driver.Bindings[0] }},
		{"native-binding-pin", func(c *composition) { c.Driver.Bindings[1].Pin = c.Driver.Bindings[0].Pin }},
		{"native-binding-missing", func(c *composition) { c.Driver.Bindings = c.Driver.Bindings[:1] }},
		{"private-owner-missing", func(c *composition) { c.Topology.Children = []plugins.ChildBinding{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input, file := graphCommandFixture(t)
			original := input.Driver
			tc.change(&input)
			writeComposition(t, file, input)
			var output bytes.Buffer
			err := execute(context.Background(), []string{"validate", "--composition", file}, &output)
			if err == nil {
				t.Fatal("invalid graph accepted")
			}
			if output.Len() != 0 || strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), "private-marker") {
				t.Fatal("invalid graph exposed private input")
			}
			input.Driver = original
			assertGraphCommandNoEffects(t, input)
		})
	}
}
func TestGraphCompositionRejectsCaseAliasesAndUnknownPlacementFields(t *testing.T) {
	input, file := graphCommandFixture(t)
	type wire composition
	raw, _ := json.Marshal(wire(input))
	for _, candidate := range [][]byte{bytes.Replace(raw, []byte(`"parentId"`), []byte(`"parentID"`), 1), bytes.Replace(raw, []byte(`"installationMode":"private-child"`), []byte(`"InstallationMode":"private-child"`), 1), bytes.Replace(raw, []byte(`"kind":"local-process"`), []byte(`"kind":"local-process","node":"private-marker"`), 1)} {
		if os.WriteFile(file, candidate, 0600) != nil {
			t.Fatal("graph fixture write failed")
		}
		if _, err := loadComposition(context.Background(), file); err == nil {
			t.Fatal("non-closed graph fields accepted")
		}
	}
	assertGraphCommandNoEffects(t, input)
}
func TestOwnerControlClosedShapeAndLineBound(t *testing.T) {
	input, _ := graphCommandFixture(t)
	owner := plugins.OwnerReference{Pin: input.Topology.Instances[0].Pin, InstanceID: "command-parent", Epoch: strings.Repeat("a", 64), Generation: 1}
	snapshot := []byte(`{"schemaVersion":"1.0.0","action":"snapshot"}`)
	release, _ := json.Marshal(ownerControl{SchemaVersion: "1.0.0", Action: "release-root", Owner: &owner})
	for _, wire := range [][]byte{snapshot, release, append(bytes.Clone(snapshot), bytes.Repeat([]byte{' '}, 8192-len(snapshot))...)} {
		if _, err := decodeOwnerControl(wire); err != nil {
			t.Fatal("valid explicit owner control refused")
		}
	}
	for _, wire := range [][]byte{
		nil, []byte(`{"schemaVersion":"1.0.0","action":"unknown-private-marker"}`),
		[]byte(`{"schemaVersion":"1.0.0","action":"snapshot","owner":null}`),
		[]byte(`{"schemaVersion":"1.0.0","action":"release-root"}`),
		bytes.Replace(snapshot, []byte(`"action":"snapshot"`), []byte(`"action":"snapshot","action":"snapshot"`), 1),
		bytes.Replace(snapshot, []byte(`"schemaVersion"`), []byte(`"SchemaVersion"`), 1),
		bytes.Replace(snapshot, []byte(`"action":"snapshot"`), []byte(`"action":"snapshot","future":"private-marker"`), 1),
		bytes.Replace(release, []byte(`"instanceId"`), []byte(`"instanceID"`), 1),
		bytes.Replace(release, []byte(`"generation":1`), []byte(`"generation":1,"generation":1`), 1),
		bytes.Replace(release, []byte(`"generation":1`), []byte(`"generation":1,"future":"private-marker"`), 1),
		append(bytes.Clone(snapshot), bytes.Repeat([]byte{' '}, 8193-len(snapshot))...),
	} {
		if _, err := decodeOwnerControl(wire); err == nil {
			t.Fatal("non-closed or oversized owner control accepted")
		} else if errorCode(err) != "plugin_owner_control_invalid" || strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), "private-marker") {
			t.Fatal("owner control failure exposed private input")
		}
	}
}
