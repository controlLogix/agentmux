// Package plugins implements ordinary package admission outside the protected kernel.
package plugins

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const manifestLimit = 1048576

type Platform struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}
type Runtime struct {
	Kind                   string   `json:"kind"`
	ExecutableRef          string   `json:"executableRef"`
	Args                   []string `json:"args"`
	WorkingDirectoryPolicy string   `json:"workingDirectoryPolicy"`
}
type Dependency struct {
	PackageID               string `json:"packageId"`
	MinimumVersion          string `json:"minimumVersion"`
	ExclusiveMaximumVersion string `json:"exclusiveMaximumVersion"`
	Optional                bool   `json:"optional"`
}
type Child struct {
	PackageID    string `json:"packageId"`
	Relationship string `json:"relationship"`
	Required     bool   `json:"required"`
}
type Capability struct {
	Action        string `json:"action"`
	ResourceClass string `json:"resourceClass"`
	Required      bool   `json:"required"`
}
type Contribution struct {
	Kind        string `json:"kind"`
	ID          string `json:"id"`
	ContractRef string `json:"contractRef"`
}
type Lifecycle struct {
	StartDeadlineMS int `json:"startDeadlineMs"`
	DrainDeadlineMS int `json:"drainDeadlineMs"`
	RestartLimit    int `json:"restartLimit"`
}
type Migration struct {
	Domain      string `json:"domain"`
	FromSchema  string `json:"fromSchema"`
	ToSchema    string `json:"toSchema"`
	ContractRef string `json:"contractRef"`
}
type Manifest struct {
	SchemaVersion          string         `json:"schemaVersion"`
	PackageID              string         `json:"packageId"`
	Version                string         `json:"version"`
	APIMajor               int            `json:"apiMajor"`
	InstallationModes      []string       `json:"installationModes"`
	Platforms              []Platform     `json:"platforms"`
	Runtime                Runtime        `json:"runtime"`
	Dependencies           []Dependency   `json:"dependencies"`
	Children               []Child        `json:"children"`
	RequestedCapabilities  []Capability   `json:"requestedCapabilities"`
	ConfigurationSchemaRef string         `json:"configurationSchemaRef"`
	Contributions          []Contribution `json:"contributions"`
	Lifecycle              Lifecycle      `json:"lifecycle"`
	Migrations             []Migration    `json:"migrations"`
}

func cloneManifest(m Manifest) Manifest {
	raw, _ := json.Marshal(m)
	var out Manifest
	_ = json.Unmarshal(raw, &out)
	return out
}

type ValidatedManifest struct {
	manifest Manifest
	raw      []byte
}

func (v ValidatedManifest) Manifest() Manifest { return cloneManifest(v.manifest) }
func (v ValidatedManifest) Raw() []byte        { return bytes.Clone(v.raw) }
func (v ValidatedManifest) Checksum() string   { return checksum(v.raw) }
func (ValidatedManifest) String() string       { return "[validated plugin manifest]" }
func (ValidatedManifest) GoString() string     { return "[validated plugin manifest]" }
func (ValidatedManifest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[validated plugin manifest]")
}
func (ValidatedManifest) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"validated-plugin-manifest"}`), nil
}

//go:embed schemas/common.schema.json schemas/plugin-manifest.schema.json
var manifestResources embed.FS
var manifestOnce sync.Once
var manifestSchema *jsonschema.Schema
var manifestCompileError error

type manifestDenyLoader struct{}

func (manifestDenyLoader) Load(string) (any, error) {
	return nil, pluginError("schema_resource_unavailable")
}
func compileManifest() {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(manifestDenyLoader{})
	for _, name := range []string{"common", "plugin-manifest"} {
		raw, err := manifestResources.ReadFile("schemas/" + name + ".schema.json")
		if err != nil {
			manifestCompileError = err
			return
		}
		value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err == nil {
			err = c.AddResource("urn:agentmux:contract:1:"+name, value)
		}
		if err != nil {
			manifestCompileError = err
			return
		}
	}
	manifestSchema, manifestCompileError = c.Compile("urn:agentmux:contract:1:plugin-manifest")
}

func ValidateManifest(raw []byte) (ValidatedManifest, error) {
	if strictDocument(raw) != nil {
		return ValidatedManifest{}, pluginError("manifest_wire_invalid")
	}
	manifestOnce.Do(compileManifest)
	if manifestCompileError != nil {
		return ValidatedManifest{}, pluginError("manifest_schema_unavailable")
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil || manifestSchema.Validate(value) != nil {
		return ValidatedManifest{}, pluginError("manifest_schema_invalid")
	}
	// JSON Schema treats 1, 1.0 and 1e0 as the same integer. Preserve raw
	// source bytes while normalizing validated numeric fields for typed decoding.
	normalized, err := json.Marshal(normalizeManifestNumbers(value))
	var m Manifest
	if err != nil || json.Unmarshal(normalized, &m) != nil {
		return ValidatedManifest{}, pluginError("manifest_schema_invalid")
	}
	for _, collection := range [][]string{dependencyIDs(m.Dependencies), childIDs(m.Children), contributionIDs(m.Contributions)} {
		seen := map[string]bool{}
		for _, id := range collection {
			if seen[id] {
				return ValidatedManifest{}, pluginError("manifest_duplicate_identity")
			}
			seen[id] = true
		}
	}
	for _, d := range m.Dependencies {
		if d.PackageID == m.PackageID {
			return ValidatedManifest{}, pluginError("manifest_self_dependency")
		}
		if compareVersion(d.MinimumVersion, d.ExclusiveMaximumVersion) >= 0 {
			return ValidatedManifest{}, pluginError("manifest_dependency_interval")
		}
	}
	for _, c := range m.Children {
		if c.PackageID == m.PackageID {
			return ValidatedManifest{}, pluginError("manifest_self_dependency")
		}
	}
	for _, c := range m.RequestedCapabilities {
		if strings.HasPrefix(c.ResourceClass, "kernel") && (c.ResourceClass != "kernel-status" || c.Action != "subscribe") {
			return ValidatedManifest{}, pluginError("protected_kernel_access")
		}
	}
	return ValidatedManifest{manifest: m, raw: bytes.Clone(raw)}, nil
}
func dependencyIDs(ds []Dependency) []string {
	r := []string{}
	for _, d := range ds {
		r = append(r, d.PackageID)
	}
	return r
}
func childIDs(cs []Child) []string {
	r := []string{}
	for _, c := range cs {
		r = append(r, c.PackageID)
	}
	return r
}
func contributionIDs(cs []Contribution) []string {
	r := []string{}
	for _, c := range cs {
		r = append(r, c.ID)
	}
	return r
}

var numericVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func compareVersion(a, b string) int {
	aa, bb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		if len(aa[i]) < len(bb[i]) {
			return -1
		}
		if len(aa[i]) > len(bb[i]) {
			return 1
		}
		if aa[i] < bb[i] {
			return -1
		}
		if aa[i] > bb[i] {
			return 1
		}
	}
	return 0
}

func normalizeManifestNumbers(value any) any {
	switch v := value.(type) {
	case json.Number:
		r, ok := new(big.Rat).SetString(string(v))
		if ok && r.IsInt() && r.Num().IsInt64() {
			return r.Num().Int64()
		}
		return v
	case map[string]any:
		for k, item := range v {
			v[k] = normalizeManifestNumbers(item)
		}
		return v
	case []any:
		for i, item := range v {
			v[i] = normalizeManifestNumbers(item)
		}
		return v
	default:
		return v
	}
}
