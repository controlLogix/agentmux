package plugins

import (
	"bytes"
	"embed"
	"encoding/json"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schemas/common.schema.json schemas/ordinary-plugin-lifecycle.schema.json schemas/plugin-context.schema.json schemas/operation-context.schema.json schemas/plugin-context-request.schema.json schemas/plugin-context-reply.schema.json schemas/plugin-context-operation.schema.json
var contextResources embed.FS
var contextSchemaOnce sync.Once
var contextSchemas map[string]*jsonschema.Schema
var contextSchemaFailure error

func compileContextSchemas() {
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.UseLoader(manifestDenyLoader{})
	names := []string{"common", "ordinary-plugin-lifecycle", "plugin-context", "operation-context", "plugin-context-request", "plugin-context-reply", "plugin-context-operation"}
	for _, name := range names {
		raw, err := contextResources.ReadFile("schemas/" + name + ".schema.json")
		if err != nil {
			contextSchemaFailure = err
			return
		}
		value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err == nil {
			err = compiler.AddResource("urn:agentmux:contract:1:"+name, value)
		}
		if err != nil {
			contextSchemaFailure = err
			return
		}
	}
	contextSchemas = map[string]*jsonschema.Schema{}
	for _, name := range names[2:] {
		schema, err := compiler.Compile("urn:agentmux:contract:1:" + name)
		if err != nil {
			contextSchemaFailure = err
			return
		}
		contextSchemas[name] = schema
	}
}

func validateContextJSON(name string, raw []byte) error {
	if strictDocument(raw) != nil {
		return pluginError("context_request_invalid")
	}
	contextSchemaOnce.Do(compileContextSchemas)
	if contextSchemaFailure != nil || contextSchemas[name] == nil {
		return pluginError("context_schema_unavailable")
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil || contextSchemas[name].Validate(value) != nil {
		return pluginError("context_request_invalid")
	}
	return nil
}

func decodeContextJSON(name string, raw []byte, out any) error {
	if err := validateContextJSON(name, raw); err != nil {
		return err
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return pluginError("context_request_invalid")
	}
	normalized, err := json.Marshal(normalizeManifestNumbers(value))
	if err != nil || json.Unmarshal(normalized, out) != nil {
		return pluginError("context_request_invalid")
	}
	return nil
}

type contextServiceRequest struct {
	SchemaVersion   string          `json:"schemaVersion"`
	Kind            string          `json:"kind"`
	RequestID       string          `json:"requestId"`
	Owner           OwnerReference  `json:"owner"`
	HandleID        string          `json:"handleId"`
	Service         string          `json:"service"`
	Method          string          `json:"method"`
	OperationHandle *string         `json:"operationHandle"`
	Parameters      json.RawMessage `json:"parameters"`
}

type contextServiceReply struct {
	SchemaVersion string          `json:"schemaVersion"`
	Kind          string          `json:"kind"`
	RequestID     string          `json:"requestId"`
	Owner         OwnerReference  `json:"owner"`
	Outcome       string          `json:"outcome"`
	Code          string          `json:"code"`
	Value         json.RawMessage `json:"value"`
}

type contextOperationResult struct {
	SchemaVersion   string          `json:"schemaVersion"`
	Kind            string          `json:"kind"`
	Owner           OwnerReference  `json:"owner"`
	OperationHandle string          `json:"operationHandle"`
	Outcome         string          `json:"outcome"`
	Value           json.RawMessage `json:"value"`
}
