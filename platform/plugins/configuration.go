package plugins

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// SchemaResource binds a logical local reference to a file in an admitted package.
// It never authorizes reading a path outside that package or fetching a URL.
type SchemaResource struct {
	Ref  string `json:"ref"`
	File string `json:"file"`
}

// ValidatedConfiguration retains exact bytes. Formatting and JSON never expose values.
// Bytes is an explicit disclosure to the trusted process owner, not a public status API.
type ValidatedConfiguration struct {
	pin               PackagePin
	schemaRef, digest string
	raw               []byte
}

func (c ValidatedConfiguration) Pin() PackagePin   { return c.pin }
func (c ValidatedConfiguration) SchemaRef() string { return c.schemaRef }
func (c ValidatedConfiguration) Checksum() string  { return c.digest }
func (c ValidatedConfiguration) Bytes() []byte     { return bytes.Clone(c.raw) }
func (c ValidatedConfiguration) BelongsTo(p AdmittedPackage) bool {
	return len(c.raw) > 0 && c.pin == p.Pin() && c.schemaRef == p.Manifest().ConfigurationSchemaRef && c.digest == checksum(c.raw)
}
func (ValidatedConfiguration) String() string   { return "[validated plugin configuration]" }
func (ValidatedConfiguration) GoString() string { return "[validated plugin configuration]" }
func (ValidatedConfiguration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[validated plugin configuration]")
}
func (ValidatedConfiguration) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"validated-plugin-configuration"}`), nil
}

type configurationRegexp struct {
	expression *regexp2.Regexp
	failed     *atomic.Bool
}

func (r configurationRegexp) String() string { return r.expression.String() }
func (r configurationRegexp) MatchString(value string) bool {
	matched, err := r.expression.MatchString(value)
	if err != nil {
		r.failed.Store(true)
	}
	return err == nil && matched
}

// Configuration validation uses Draft 2020-12 core/applicator/validation and
// unevaluated semantics. Format and content are standard annotations; defaults
// are never inserted. Custom dialects and required custom vocabularies are refused.
// Resource/JSON/regex limits bound inputs; this is not a CPU sandbox for trusted
// administrator-authored schemas. Validation runs synchronously, without an
// abandoned timeout goroutine.
func PrepareConfiguration(pkg AdmittedPackage, resources []SchemaResource, raw []byte) (ValidatedConfiguration, error) {
	fail := func(code string) (ValidatedConfiguration, error) { return ValidatedConfiguration{}, pluginError(code) }
	if !configurationPin(pkg.Pin()) || strictDocument(raw) != nil {
		return fail("configuration_wire_invalid")
	}
	reference := pkg.Manifest().ConfigurationSchemaRef
	base := "https://schemas.agentmux.invalid/package/" + strings.TrimPrefix(pkg.Pin().PackageChecksum, "sha256:") + "/"
	main, err := configurationLocation(base, reference)
	if err != nil {
		return fail("configuration_schema_reference_invalid")
	}
	bindings := append([]SchemaResource(nil), resources...)
	mainDocument := *main
	mainDocument.Fragment = ""
	mainDocument.RawFragment = ""
	found := false
	for _, binding := range bindings {
		u, e := configurationLocation(base, binding.Ref)
		if e == nil && u.String() == mainDocument.String() {
			found = true
		}
	}
	if !found {
		u, e := url.Parse(reference)
		if e != nil || u.IsAbs() || u.RawQuery != "" {
			return fail("configuration_schema_resource_unavailable")
		}
		u.Fragment = ""
		u.RawFragment = ""
		bindings = append(bindings, SchemaResource{Ref: u.String(), File: u.Path})
	}
	if len(bindings) == 0 || len(bindings) > 64 {
		return fail("configuration_schema_limit")
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.UseLoader(manifestDenyLoader{})
	var patternFailure atomic.Bool
	compiler.UseRegexpEngine(func(pattern string) (jsonschema.Regexp, error) {
		expression, e := regexp2.Compile(pattern, regexp2.ECMAScript)
		if e != nil {
			return nil, pluginError("configuration_schema_invalid")
		}
		expression.MatchTimeout = 25 * time.Millisecond
		return configurationRegexp{expression, &patternFailure}, nil
	})
	seen := map[string]bool{}
	total := 0
	nodes := 0
	for _, binding := range bindings {
		location, e := configurationLocation(base, binding.Ref)
		if e != nil || location.Fragment != "" || seen[location.String()] {
			return fail("configuration_schema_resource_invalid")
		}
		seen[location.String()] = true
		schemaRaw, e := pkg.File(binding.File)
		if e != nil {
			return fail("configuration_schema_resource_unavailable")
		}
		total += len(schemaRaw)
		if total > 4*manifestLimit {
			return fail("configuration_schema_limit")
		}
		if strictDocument(schemaRaw) != nil {
			return fail("configuration_schema_invalid")
		}
		value, e := jsonschema.UnmarshalJSON(bytes.NewReader(schemaRaw))
		if e != nil {
			return fail("configuration_schema_invalid")
		}
		if e = checkConfigurationDialect(value, &nodes); e != nil {
			return fail("configuration_schema_unsupported")
		}
		if compiler.AddResource(location.String(), value) != nil {
			return fail("configuration_schema_invalid")
		}
	}
	compiled, err := compiler.Compile(main.String())
	if err != nil {
		return fail("configuration_schema_invalid")
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fail("configuration_wire_invalid")
	}
	err = compiled.Validate(value)
	if patternFailure.Load() {
		return fail("configuration_pattern_budget")
	}
	if err != nil {
		return fail("configuration_invalid")
	}
	return ValidatedConfiguration{pin: pkg.Pin(), schemaRef: reference, digest: checksum(raw), raw: bytes.Clone(raw)}, nil
}

var configurationDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func configurationPin(pin PackagePin) bool {
	return pin.PackageID != "" && pin.Version != "" && configurationDigest.MatchString(pin.PackageChecksum) && configurationDigest.MatchString(pin.ManifestChecksum) && configurationDigest.MatchString(pin.ProvenanceChecksum)
}
func configurationLocation(base, reference string) (*url.URL, error) {
	if reference == "" || len(reference) > 4096 || strings.ContainsAny(reference, "\\\x00\r\n\t") {
		return nil, pluginError("configuration_schema_reference_invalid")
	}
	u, e := url.Parse(reference)
	if e != nil || u.RawQuery != "" || u.User != nil {
		return nil, pluginError("configuration_schema_reference_invalid")
	}
	if !u.IsAbs() {
		if u.Host != "" || strings.HasPrefix(u.Path, "/") || u.Path == "" || path.Clean(u.Path) != u.Path || u.Path == ".." || strings.HasPrefix(u.Path, "../") {
			return nil, pluginError("configuration_schema_reference_invalid")
		}
		b, _ := url.Parse(base)
		u = b.ResolveReference(u)
	}
	return u, nil
}

func checkConfigurationDialect(value any, nodes *int) error {
	*nodes++
	if *nodes > 32768 {
		return pluginError("configuration_schema_limit")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	if dialect, exists := object["$schema"]; exists && dialect != "https://json-schema.org/draft/2020-12/schema" {
		return pluginError("configuration_schema_unsupported")
	}
	if vocabularies, ok := object["$vocabulary"].(map[string]any); ok {
		for name, required := range vocabularies {
			if required == true && !configurationVocabulary(name) {
				return pluginError("configuration_schema_unsupported")
			}
		}
	}
	// Only schema-bearing positions contain dialect declarations. Values in const,
	// enum, examples or default are application data, not nested schemas.
	for _, name := range []string{"additionalProperties", "unevaluatedProperties", "propertyNames", "contains", "items", "unevaluatedItems", "not", "if", "then", "else", "contentSchema"} {
		if child, exists := object[name]; exists {
			if err := checkConfigurationDialect(child, nodes); err != nil {
				return err
			}
		}
	}
	for _, name := range []string{"allOf", "anyOf", "oneOf", "prefixItems"} {
		if children, ok := object[name].([]any); ok {
			for _, child := range children {
				if err := checkConfigurationDialect(child, nodes); err != nil {
					return err
				}
			}
		}
	}
	for _, name := range []string{"$defs", "properties", "patternProperties", "dependentSchemas"} {
		if children, ok := object[name].(map[string]any); ok {
			for _, child := range children {
				if err := checkConfigurationDialect(child, nodes); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func configurationVocabulary(name string) bool {
	switch name {
	case "https://json-schema.org/draft/2020-12/vocab/core", "https://json-schema.org/draft/2020-12/vocab/applicator", "https://json-schema.org/draft/2020-12/vocab/unevaluated", "https://json-schema.org/draft/2020-12/vocab/validation", "https://json-schema.org/draft/2020-12/vocab/meta-data", "https://json-schema.org/draft/2020-12/vocab/format-annotation", "https://json-schema.org/draft/2020-12/vocab/content":
		return true
	}
	return false
}
