package plugins

import (
	"encoding/json"
	"github.com/controlLogix/agentmux/platform/internal/wirejson"
)

const nativeAuthorityLimit = 65536

func nativeAuthorityCanonical(raw []byte) ([]byte, error) {
	return nativeAuthorityCanonicalLimit(raw, nativeAuthorityLimit)
}

func nativeAuthorityCanonicalLimit(raw []byte, limit int) ([]byte, error) {
	canonical, err := wirejson.Canonical(raw, limit)
	if err != nil {
		return nil, pluginError("context_authority_wire_invalid")
	}
	return canonical, nil
}

// Closed fields are checked before typed decoding, including required nulls.
func nativeAuthorityObject(raw []byte, fields ...string) (map[string]json.RawMessage, error) {
	if len(raw) > nativeAuthorityLimit || strictDocument(raw) != nil {
		return nil, pluginError("context_authority_wire_invalid")
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || obj == nil || len(obj) != len(fields) {
		return nil, pluginError("context_authority_wire_invalid")
	}
	for _, f := range fields {
		if _, ok := obj[f]; !ok {
			return nil, pluginError("context_authority_wire_invalid")
		}
	}
	return obj, nil
}
