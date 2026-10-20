package plugins

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigurationLocalResourcesExactValuesAndCopies(t *testing.T) {
	schema := []byte(`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"mode":{"enum":["local","team"]},"limits":{"$ref":"limits.json"},"token":{"type":"string"},"defaulted":{"type":"integer","default":7}},"required":["mode","limits","token"],"unevaluatedProperties":false}`)
	pkg := fixturePackage(t, fixtureManifest("configured"), map[string][]byte{"schemas/config.json": schema, "schemas/limits.json": []byte(`{"type":"object","properties":{"count":{"type":"integer","minimum":1}},"required":["count"],"additionalProperties":false}`)})
	raw := []byte("{\n \"mode\":\"local\",\"limits\":{\"count\":3},\"token\":\"private-marker\"\n}")
	original := bytes.Clone(raw)
	resources := []SchemaResource{{Ref: "schemas/limits.json", File: "schemas/limits.json"}}
	result, err := PrepareConfiguration(pkg, resources, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !result.BelongsTo(pkg) || result.Checksum() != checksum(original) || result.SchemaRef() != pkg.Manifest().ConfigurationSchemaRef || !bytes.Equal(result.Bytes(), original) {
		t.Fatal("configuration changed")
	}
	raw[0] = 'x'
	copy := result.Bytes()
	copy[0] = 'x'
	if !bytes.Equal(result.Bytes(), original) {
		t.Fatal("mutable configuration")
	}
	other := fixturePackage(t, fixtureManifest("other"), nil)
	if result.BelongsTo(other) {
		t.Fatal("configuration not bound to package")
	}
	for _, value := range []any{result, &result} {
		encoded, _ := json.Marshal(value)
		if strings.Contains(fmt.Sprintf("%v %+v %#v %s %q", value, value, value, value, value)+string(encoded), "private-marker") {
			t.Fatal("configuration exposed")
		}
	}
	for _, invalid := range []string{`{"mode":"local","limits":{"count":0},"token":"private-marker"}`, `{"mode":"local","limits":{"count":3},"token":"private-marker","extra":true}`, `{"mode":"unknown","limits":{"count":3},"token":"private-marker"}`} {
		if _, err := PrepareConfiguration(pkg, resources, []byte(invalid)); err == nil {
			t.Fatal("schema constraint ignored")
		}
	}
}

func TestConfigurationDraftApplicatorsAndRecursiveReferences(t *testing.T) {
	schema := []byte(`{"$schema":"https://json-schema.org/draft/2020-12/schema","$defs":{"node":{"type":"object","properties":{"value":{"type":"integer"},"child":{"$ref":"#/$defs/node"}},"required":["value"],"additionalProperties":false}},"type":"object","properties":{"node":{"$ref":"#/$defs/node"},"values":{"type":"array","prefixItems":[{"const":"start"}],"contains":{"type":"integer"},"minContains":2},"gate":{"type":"boolean"},"proof":{"type":"string"}},"required":["node","values"],"dependentRequired":{"gate":["proof"]},"allOf":[{"if":{"required":["gate"],"properties":{"gate":{"const":true}}},"then":{"properties":{"proof":{"minLength":3}}}}],"unevaluatedProperties":false}`)
	pkg := fixturePackage(t, fixtureManifest("applicators"), map[string][]byte{"schemas/config.json": schema})
	valid := []byte(`{"node":{"value":1,"child":{"value":2}},"values":["start",2,3],"gate":true,"proof":"yes"}`)
	if _, err := PrepareConfiguration(pkg, nil, valid); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{"node":{"value":"bad"},"values":["start",2,3]}`, `{"node":{"value":1},"values":["start",2]}`, `{"node":{"value":1},"values":["start",2,3],"gate":true}`, `{"node":{"value":1},"values":["start",2,3],"gate":true,"proof":"x"}`} {
		if _, err := PrepareConfiguration(pkg, nil, []byte(raw)); err == nil {
			t.Fatal("applicator ignored")
		}
	}
}

func TestConfigurationUnsupportedAndAnnotationSemantics(t *testing.T) {
	for _, schema := range []string{`{"$schema":"http://json-schema.org/draft-07/schema#"}`, `{"$vocabulary":{"urn:unknown:vocabulary":true}}`, `{"$vocabulary":{"https://json-schema.org/draft/2020-12/vocab/format-assertion":true}}`} {
		pkg := fixturePackage(t, fixtureManifest("unsupported"), map[string][]byte{"schemas/config.json": []byte(schema)})
		if _, err := PrepareConfiguration(pkg, nil, []byte(`{}`)); err == nil || err.Error() != "configuration_schema_unsupported" {
			t.Fatalf("unsupported schema result: %v", err)
		}
	}
	schema := []byte(`{"type":"object","properties":{"email":{"type":"string","format":"email"},"defaulted":{"default":{"$schema":"private-marker"}}},"required":["email"]}`)
	pkg := fixturePackage(t, fixtureManifest("annotations"), map[string][]byte{"schemas/config.json": schema})
	raw := []byte(`{"email":"not-an-email"}`)
	result, err := PrepareConfiguration(pkg, nil, raw)
	if err != nil || !bytes.Equal(result.Bytes(), raw) {
		t.Fatal("annotation applied as mutation or assertion")
	}
	for _, schema := range []string{"true", "false"} {
		pkg := fixturePackage(t, fixtureManifest("boolean"), map[string][]byte{"schemas/config.json": []byte(schema)})
		_, err := PrepareConfiguration(pkg, nil, []byte(`{}`))
		if (err == nil) != (schema == "true") {
			t.Fatal("boolean schema ignored")
		}
	}
}

func TestConfigurationRefusesExternalResourceAndUnsafeBindings(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte(`true`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{(&url.URL{Scheme: "file", Path: outside}).String(), "https://unavailable.invalid/schema.json"} {
		encoded, _ := json.Marshal(map[string]string{"$ref": ref})
		pkg := fixturePackage(t, fixtureManifest("offline"), map[string][]byte{"schemas/config.json": encoded})
		if _, err := PrepareConfiguration(pkg, nil, []byte(`{}`)); err == nil {
			t.Fatal("external schema admitted")
		}
	}
	pkg := fixturePackage(t, fixtureManifest("binding"), nil)
	for _, resources := range [][]SchemaResource{{{Ref: "schemas/other.json", File: "../outside.json"}}, {{Ref: "schemas/config.json", File: "missing.json"}}, {{Ref: "schemas/config.json", File: "schemas/config.json"}, {Ref: "schemas/config.json", File: "schemas/config.json"}}} {
		if _, err := PrepareConfiguration(pkg, resources, []byte(`{}`)); err == nil {
			t.Fatal("unsafe resource binding")
		}
	}
	manifest := fixtureManifest("logical")
	manifest.ConfigurationSchemaRef = "urn:private-marker:configuration"
	logical := fixturePackage(t, manifest, nil)
	if _, err := PrepareConfiguration(logical, nil, []byte(`{}`)); err == nil {
		t.Fatal("implicit logical binding")
	}
	result, err := PrepareConfiguration(logical, []SchemaResource{{Ref: manifest.ConfigurationSchemaRef, File: "schemas/config.json"}}, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(fmt.Sprintf("%+v %#v", result, result)+string(encoded), "private-marker") {
		t.Fatal("schema reference leaked")
	}
}

func TestConfigurationWireErrorsAreClosed(t *testing.T) {
	pkg := fixturePackage(t, fixtureManifest("wire"), nil)
	for _, raw := range [][]byte{[]byte(`{"private-marker":1,"private-marker":2}`), []byte(`"\ud800"`), {0xff}, []byte(`{} {}`), []byte(strings.Repeat("[", 65) + strings.Repeat("]", 65)), []byte(strings.Repeat(" ", manifestLimit+1))} {
		_, err := PrepareConfiguration(pkg, nil, raw)
		if err == nil {
			t.Fatal("malformed configuration accepted")
		}
		encoded, _ := json.Marshal(err)
		if strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err)+string(encoded), "private-marker") {
			t.Fatal("invalid value exposed")
		}
	}
	if _, err := PrepareConfiguration(AdmittedPackage{}, nil, []byte(`{}`)); err == nil {
		t.Fatal("unadmitted package")
	}
}

func TestConfigurationNegatedPatternTimeoutCannotValidate(t *testing.T) {
	pkg := fixturePackage(t, fixtureManifest("pattern"), map[string][]byte{"schemas/config.json": []byte(`{"type":"string","not":{"pattern":"(a+)+$"}}`)})
	raw, _ := json.Marshal(strings.Repeat("a", 1000) + "!")
	_, err := PrepareConfiguration(pkg, nil, raw)
	if err == nil || err.Error() != "configuration_pattern_budget" {
		t.Fatalf("pattern timeout result: %v", err)
	}
}

func TestConfigurationSelectsDeclaredSchemaFragment(t *testing.T) {
	manifest := fixtureManifest("fragment")
	manifest.ConfigurationSchemaRef = "schemas/config.json#/$defs/config"
	pkg := fixturePackage(t, manifest, map[string][]byte{"schemas/config.json": []byte(`{"type":"string","$defs":{"config":{"type":"object","required":["value"]}}}`)})
	if _, err := PrepareConfiguration(pkg, nil, []byte(`{"value":1}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareConfiguration(pkg, nil, []byte(`{}`)); err == nil {
		t.Fatal("declared fragment ignored")
	}
}
