package plugins

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureManifest(id string) Manifest {
	return Manifest{SchemaVersion: "1.0.0", PackageID: id, Version: "1.0.0", APIMajor: 1, InstallationModes: []string{"independent"}, Platforms: []Platform{{OS: "darwin", Arch: "arm64"}}, Runtime: Runtime{Kind: "process", ExecutableRef: "bin/run", Args: []string{}, WorkingDirectoryPolicy: "package"}, Dependencies: []Dependency{}, Children: []Child{}, RequestedCapabilities: []Capability{}, ConfigurationSchemaRef: "schemas/config.json", Contributions: []Contribution{}, Lifecycle: Lifecycle{StartDeadlineMS: 1000, DrainDeadlineMS: 1000, RestartLimit: 1}, Migrations: []Migration{}}
}
func manifestBytes(t *testing.T, m Manifest) []byte {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal("fixture encoding")
	}
	return raw
}
func TestManifestFullFieldsAndAcceptedResources(t *testing.T) {
	for _, name := range []string{"common", "plugin-manifest"} {
		actual, e := manifestResources.ReadFile("schemas/" + name + ".schema.json")
		expected, err := os.ReadFile(filepath.Join("..", "..", "contracts", "v1", "schemas", name+".schema.json"))
		if e != nil || err != nil || !bytes.Equal(actual, expected) {
			t.Fatal("schema changed")
		}
	}
	m := fixtureManifest("example")
	m.Runtime.Args = []string{"private-marker"}
	m.Dependencies = []Dependency{{PackageID: "dependency", MinimumVersion: "1.0.0", ExclusiveMaximumVersion: "999999999999999999999999999.0.0", Optional: true}}
	m.Children = []Child{{PackageID: "child", Relationship: "private", Required: true}}
	m.Contributions = []Contribution{{Kind: "tool", ID: "inspect", ContractRef: "contracts/tool.json"}}
	m.Migrations = []Migration{{Domain: "work", FromSchema: "1.0.0", ToSchema: "2.0.0", ContractRef: "migration.json"}}
	m.RequestedCapabilities = []Capability{{Action: "subscribe", ResourceClass: "kernel-status"}}
	raw := manifestBytes(t, m)
	v, err := ValidateManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(v.Raw(), raw) || !bytes.Equal(manifestBytes(t, v.Manifest()), raw) {
		t.Fatal("field loss")
	}
	copy := v.Manifest()
	copy.Runtime.Args[0] = "changed"
	raw[0] = 'x'
	if v.Manifest().Runtime.Args[0] != "private-marker" {
		t.Fatal("mutable admission")
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", v, v), "private-marker") {
		t.Fatal("source leak")
	}
}
func TestManifestStrictRejectionsAndSemantics(t *testing.T) {
	base := manifestBytes(t, fixtureManifest("example"))
	for _, raw := range [][]byte{[]byte(`{"packageId":"a","packageId":"b"}`), {0xff}, []byte(`"\ud800"`), []byte(strings.Repeat("[", 65) + strings.Repeat("]", 65)), append(bytes.Clone(base), []byte(` {}`)...), []byte(strings.Repeat(" ", manifestLimit+1)), bytes.Replace(base, []byte(`"apiMajor":1`), []byte(`"apiMajor":9007199254740992`), 1), bytes.Replace(base, []byte(`"apiMajor":1`), []byte(`"apiMajor":1,"unknown":true`), 1)} {
		if _, err := ValidateManifest(raw); err == nil {
			t.Fatal("invalid wire accepted")
		}
	}
	changes := []func(*Manifest){func(m *Manifest) {
		m.Dependencies = []Dependency{{PackageID: m.PackageID, MinimumVersion: "1.0.0", ExclusiveMaximumVersion: "2.0.0"}}
	}, func(m *Manifest) {
		m.Dependencies = []Dependency{{PackageID: "dep", MinimumVersion: "2.0.0", ExclusiveMaximumVersion: "1.0.0"}}
	}, func(m *Manifest) { m.Children = []Child{{PackageID: m.PackageID, Relationship: "private"}} }, func(m *Manifest) {
		m.RequestedCapabilities = []Capability{{Action: "write", ResourceClass: "kernel-lifecycle"}}
	}, func(m *Manifest) {
		m.Contributions = []Contribution{{Kind: "tool", ID: "same", ContractRef: "a"}, {Kind: "cli", ID: "same", ContractRef: "b"}}
	}}
	for _, change := range changes {
		m := fixtureManifest("example")
		change(&m)
		if _, err := ValidateManifest(manifestBytes(t, m)); err == nil {
			t.Fatal("invalid semantic accepted")
		}
	}
	if compareVersion("999999999999999999999999999999.0.0", "1000000000000000000000000000000.0.0") >= 0 {
		t.Fatal("version overflow")
	}
}

func TestAcceptedSDKManifestExamplesAndSemanticVectors(t *testing.T) {
	raw, err := os.ReadFile("../../tests/contracts/vectors/valid-examples.json")
	if err != nil {
		t.Fatal("examples unavailable")
	}
	var examples map[string]json.RawMessage
	if json.Unmarshal(raw, &examples) != nil {
		t.Fatal("examples invalid")
	}
	base := examples["plugin-manifest"]
	if _, err := ValidateManifest(base); err != nil {
		t.Fatal("accepted SDK example refused")
	}
	type semanticFixture struct {
		Schema string          `json:"schema"`
		Path   []any           `json:"path"`
		Value  json.RawMessage `json:"value"`
	}
	raw, err = os.ReadFile("../../tests/contracts/vectors/semantic-examples.json")
	if err != nil {
		t.Fatal("semantic vectors unavailable")
	}
	var fixtures []semanticFixture
	if json.Unmarshal(raw, &fixtures) != nil {
		t.Fatal("semantic vectors invalid")
	}
	checked := 0
	for _, fixture := range fixtures {
		if fixture.Schema != "plugin-manifest" {
			continue
		}
		var value map[string]json.RawMessage
		if json.Unmarshal(base, &value) != nil || len(fixture.Path) != 1 {
			t.Fatal("fixture shape changed")
		}
		key, ok := fixture.Path[0].(string)
		if !ok {
			t.Fatal("fixture path invalid")
		}
		value[key] = fixture.Value
		mutated, _ := json.Marshal(value)
		if _, err := ValidateManifest(mutated); err == nil {
			t.Fatal("accepted SDK semantic rejection lost")
		}
		checked++
	}
	if checked != 3 {
		t.Fatal("review changed semantic coverage")
	}
}
