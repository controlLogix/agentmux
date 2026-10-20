package plugins

import "github.com/controlLogix/agentmux/platform/internal/wirejson"

func strictDocument(raw []byte) error {
	if wirejson.Validate(raw, manifestLimit) != nil {
		return pluginError("manifest_wire_invalid")
	}
	return nil
}

// ValidateJSON applies SDK wire bounds, not a schema or authorization check.
func ValidateJSON(raw []byte) error { return strictDocument(raw) }
