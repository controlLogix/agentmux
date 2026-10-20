package plugins

import (
	"bytes"
	"embed"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"sync"
)

const nativeCapabilityRequestLimit = 96 * 1024

//go:embed schemas/capability-service-request.schema.json schemas/capability-service-response.schema.json schemas/capability-content-reply.schema.json schemas/capability-decision-request-reply.schema.json schemas/capability-outcome-query-reply.schema.json schemas/capability-policy-evaluate-reply.schema.json schemas/capability-process-cancel-reply.schema.json schemas/capability-process-start-reply.schema.json schemas/capability-secret-use-reply.schema.json schemas/capability-storage-write-reply.schema.json
var nativeCapabilityResources embed.FS
var nativeCapabilityOnce sync.Once
var nativeCapabilitySchemas map[string]*jsonschema.Schema
var nativeCapabilitySchemaNames = []string{"capability-service-request", "capability-service-response", "capability-content-reply", "capability-decision-request-reply", "capability-outcome-query-reply", "capability-policy-evaluate-reply", "capability-process-cancel-reply", "capability-process-start-reply", "capability-secret-use-reply", "capability-storage-write-reply"}

func nativeCapabilitySchema(name string, raw []byte) error {
	limit := nativeAuthorityLimit
	if name == "capability-service-request" {
		limit = nativeCapabilityRequestLimit
	}
	if len(raw) > limit || strictDocument(raw) != nil {
		return pluginError("capability_service_wire_invalid")
	}
	nativeCapabilityOnce.Do(func() {
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		compiler.UseLoader(manifestDenyLoader{})
		for _, name := range append([]string{"common", "ordinary-plugin-lifecycle"}, nativeCapabilitySchemaNames...) {
			raw, err := nativeCapabilityResources.ReadFile("schemas/" + name + ".schema.json")
			if err != nil {
				raw, err = contextResources.ReadFile("schemas/" + name + ".schema.json")
			}
			if err != nil {
				return
			}
			value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil || compiler.AddResource("urn:agentmux:contract:1:"+name, value) != nil {
				return
			}
		}
		schemas := map[string]*jsonschema.Schema{}
		for _, name := range nativeCapabilitySchemaNames {
			schema, err := compiler.Compile("urn:agentmux:contract:1:" + name)
			if err != nil {
				return
			}
			schemas[name] = schema
		}
		nativeCapabilitySchemas = schemas
	})
	schema := nativeCapabilitySchemas[name]
	if schema == nil {
		return pluginError("capability_service_schema_unavailable")
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil || schema.Validate(value) != nil {
		return pluginError("capability_service_wire_invalid")
	}
	return nil
}
