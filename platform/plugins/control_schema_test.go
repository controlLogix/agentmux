package plugins

import (
	"bytes"
	"embed"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schemas/ordinary-plugin-lifecycle.schema.json
var ordinaryControlResource embed.FS

func schemaFieldNames(t *testing.T, object map[string]any, raw []byte) {
	t.Helper()
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("wire fixture invalid")
	}
	properties, ok := object["properties"].(map[string]any)
	if !ok {
		t.Fatal("schema object invalid")
	}
	names, required := []string{}, []string{}
	for name := range fields {
		names = append(names, name)
	}
	for _, name := range object["required"].([]any) {
		required = append(required, name.(string))
	}
	sort.Strings(names)
	sort.Strings(required)
	if strings.Join(names, "\n") != strings.Join(required, "\n") || len(properties) != len(names) || object["additionalProperties"] != false {
		t.Fatal("schema/struct field drift")
	}
	for _, name := range names {
		if _, ok := properties[name]; !ok {
			t.Fatal("schema/struct field drift")
		}
	}
}
func TestOrdinaryLifecycleContractSchemaAndRoundTrip(t *testing.T) {
	raw, err := ordinaryControlResource.ReadFile("schemas/ordinary-plugin-lifecycle.schema.json")
	expected, e := os.ReadFile("../../contracts/v1/schemas/ordinary-plugin-lifecycle.schema.json")
	if err != nil || e != nil || !bytes.Equal(raw, expected) {
		t.Fatal("lifecycle schema drift")
	}
	var definition map[string]any
	if json.Unmarshal(raw, &definition) != nil {
		t.Fatal("schema invalid")
	}
	defs := definition["$defs"].(map[string]any)
	owner := OwnerReference{Pin: PackagePin{PackageID: "example", Version: "1.0.0", ManifestChecksum: checksum([]byte("manifest")), PackageChecksum: checksum([]byte("package")), ProvenanceChecksum: checksum([]byte("source"))}, InstanceID: "instance", Epoch: strings.Repeat("a", 64), Generation: 1}
	command := LifecycleControl{SchemaVersion: "1.0.0", Kind: "ordinary-plugin-control", Action: "prepare", CommandID: strings.Repeat("b", 64), Owner: owner, ConfigurationChecksum: checksum([]byte("config")), ContributionsChecksum: checksum([]byte("contributions")), Deadline: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)}
	report := LifecycleReport{SchemaVersion: "1.0.0", Kind: "ordinary-plugin-report", CommandID: command.CommandID, Owner: owner, ConfigurationChecksum: command.ConfigurationChecksum, ContributionsChecksum: command.ContributionsChecksum, Status: "ready", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	commandRaw, _ := json.Marshal(command)
	reportRaw, _ := json.Marshal(report)
	ownerRaw, _ := json.Marshal(owner)
	pinRaw, _ := json.Marshal(owner.Pin)
	for name, value := range map[string][]byte{"control": commandRaw, "report": reportRaw, "owner": ownerRaw, "packagePin": pinRaw} {
		schemaFieldNames(t, defs[name].(map[string]any), value)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.UseLoader(manifestDenyLoader{})
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil || compiler.AddResource("urn:agentmux:contract:1:ordinary-plugin-lifecycle", value) != nil {
		t.Fatal("schema resource invalid")
	}
	schema, err := compiler.Compile("urn:agentmux:contract:1:ordinary-plugin-lifecycle")
	if err != nil {
		t.Fatal("schema compile failed")
	}
	for _, wire := range [][]byte{commandRaw, reportRaw, bytes.Replace(reportRaw, []byte(`"generation":1`), []byte(`"generation":1e0`), 1)} {
		value, err := jsonschema.UnmarshalJSON(bytes.NewReader(wire))
		if err != nil || schema.Validate(value) != nil {
			t.Fatal("ordinary lifecycle frame refused")
		}
	}
	privateControl, privateReport, parent := command, report, owner
	parent.InstanceID, parent.Generation = "parent", 3
	privateControl.SchemaVersion, privateControl.ParentOwner = "1.1.0", &parent
	privateReport.SchemaVersion, privateReport.ParentOwner = "1.1.0", &parent
	privateControlRaw, _ := json.Marshal(privateControl)
	privateReportRaw, _ := json.Marshal(privateReport)
	for name, wire := range map[string][]byte{"privateControl": privateControlRaw, "privateReport": privateReportRaw} {
		schemaFieldNames(t, defs[name].(map[string]any), wire)
		value, err := jsonschema.UnmarshalJSON(bytes.NewReader(wire))
		if err != nil || schema.Validate(value) != nil {
			t.Fatal("private lifecycle frame refused")
		}
		bad := bytes.Replace(wire, []byte(`"schemaVersion":"1.1.0"`), []byte(`"schemaVersion":"1.0.0"`), 1)
		value, err = jsonschema.UnmarshalJSON(bytes.NewReader(bad))
		if err == nil && schema.Validate(value) == nil {
			t.Fatal("private fields accepted in independent protocol")
		}
	}
	for _, private := range []bool{false, true} {
		contextControl, contextReport := command, report
		controlName, reportName := "contextControl", "contextReport"
		if private {
			contextControl, contextReport = privateControl, privateReport
			controlName, reportName = "privateContextControl", "privateContextReport"
		}
		contextControl.SchemaVersion, contextReport.SchemaVersion = "1.2.0", "1.2.0"
		contextControl.ContextChecksum, contextReport.ContextChecksum = checksum([]byte("context")), checksum([]byte("context"))
		controlWire, _ := json.Marshal(contextControl)
		reportWire, _ := json.Marshal(contextReport)
		for name, wire := range map[string][]byte{controlName: controlWire, reportName: reportWire} {
			schemaFieldNames(t, defs[name].(map[string]any), wire)
			value, err := jsonschema.UnmarshalJSON(bytes.NewReader(wire))
			if err != nil || schema.Validate(value) != nil {
				t.Fatal("context lifecycle frame refused")
			}
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(wire, &fields)
			delete(fields, "contextChecksum")
			missing, _ := json.Marshal(fields)
			value, err = jsonschema.UnmarshalJSON(bytes.NewReader(missing))
			if err == nil && schema.Validate(value) == nil {
				t.Fatal("context lifecycle frame accepted without context binding")
			}
		}
	}
	var decoded LifecycleControl
	if json.Unmarshal(commandRaw, &decoded) != nil || decoded.Owner != command.Owner || decoded.Action != command.Action {
		t.Fatal("control roundtrip changed")
	}
	if decoded, err := decodeLifecycleReport(reportRaw, command); err != nil || decoded != report {
		t.Fatal("report roundtrip changed")
	}
	for _, field := range []string{"schemaVersion", "kind", "commandId", "owner", "pin", "packageId", "version", "manifestChecksum", "packageChecksum", "provenanceChecksum", "instanceId", "epoch", "generation", "configurationChecksum", "contributionsChecksum", "status", "observedAt"} {
		bad := bytes.Replace(reportRaw, []byte(`"`+field+`":`), []byte(`"`+strings.ToUpper(field[:1])+field[1:]+`":`), 1)
		value, err := jsonschema.UnmarshalJSON(bytes.NewReader(bad))
		if err == nil && schema.Validate(value) == nil {
			t.Fatal("schema accepted case alias")
		}
		if _, err := decodeLifecycleReport(bad, command); err == nil {
			t.Fatal("runtime accepted case alias")
		}
	}
}
