package plugins

import (
	"bytes"
	"embed"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schemas/native-authority-host-selection.schema.json
var nativeHostSelectionResources embed.FS
var nativeHostSelectionOnce sync.Once
var nativeHostSelectionSchema *jsonschema.Schema

// ValidateNativeHostSelection checks the canonical enrollment format. It grants
// no authority; the launcher must admit the original private files and profile.
func ValidateNativeHostSelection(raw []byte) error {
	if len(raw) > nativeAuthorityLimit || strictDocument(raw) != nil {
		return pluginError("context_host_selection_invalid")
	}
	nativeHostSelectionOnce.Do(func() {
		c := jsonschema.NewCompiler()
		c.DefaultDraft(jsonschema.Draft2020)
		c.UseLoader(manifestDenyLoader{})
		for _, name := range []string{"common", "ordinary-plugin-lifecycle", "native-authority-facts", "native-authority-host-selection"} {
			path := "schemas/" + name + ".schema.json"
			data, err := contextResources.ReadFile(path)
			if err != nil {
				data, err = nativeAuthorityResources.ReadFile(path)
			}
			if err != nil {
				data, err = nativeHostSelectionResources.ReadFile(path)
			}
			if err != nil {
				return
			}
			value, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
			if err != nil || c.AddResource("urn:agentmux:contract:1:"+name, value) != nil {
				return
			}
		}
		nativeHostSelectionSchema, _ = c.Compile("urn:agentmux:contract:1:native-authority-host-selection")
	})
	if nativeHostSelectionSchema == nil {
		return pluginError("context_host_selection_invalid")
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil || nativeHostSelectionSchema.Validate(value) != nil {
		return pluginError("context_host_selection_invalid")
	}
	return nil
}
