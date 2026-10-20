package plugins

import (
	"bytes"
	"embed"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"regexp"
	"sync"
)

//go:embed schemas/native-authority-request.schema.json schemas/native-authority-response.schema.json schemas/native-authority-facts.schema.json schemas/message-envelope.schema.json schemas/ingress-attestation.schema.json schemas/owner-record.schema.json schemas/identity-authority-state.schema.json schemas/identity-legacy-alias.schema.json schemas/identity-secret-reference.schema.json schemas/identity-ordinary-secret-reference.schema.json schemas/identity-application-account.schema.json schemas/identity-native-instance.schema.json schemas/configuration-set.schema.json schemas/configuration-change.schema.json schemas/configuration-change-subscribe.schema.json schemas/configuration-change-subscribe-reply.schema.json schemas/configuration-subscription-control.schema.json schemas/configuration-subscription-response.schema.json schemas/configuration-watch-close.schema.json schemas/configuration-watch-close-response.schema.json
var nativeAuthorityResources embed.FS

var nativeAuthoritySchemaOnce sync.Once
var nativeAuthoritySchemas map[string]*jsonschema.Schema

func nativeAuthorityRegexp(pattern string) (jsonschema.Regexp, error) {
	// The canonical alias pattern uses JSON Schema Unicode escapes. Go's
	// parser needs hex escapes for these same control codepoints.
	if pattern == `^[^\u0000-\u001f\u007f]+$` {
		pattern = `^[^\x00-\x1f\x7f]+$`
	}
	return regexp.Compile(pattern)
}

func nativeAuthoritySchema(name string, raw []byte) error {
	if strictDocument(raw) != nil {
		return pluginError("context_authority_wire_invalid")
	}
	nativeAuthoritySchemaOnce.Do(func() {
		c := jsonschema.NewCompiler()
		c.DefaultDraft(jsonschema.Draft2020)
		c.UseLoader(manifestDenyLoader{})
		c.UseRegexpEngine(nativeAuthorityRegexp)
		for _, n := range []string{"common", "ordinary-plugin-lifecycle", "operation-context", "message-envelope", "ingress-attestation", "native-authority-request", "native-authority-response", "native-authority-facts", "owner-record", "identity-authority-state", "identity-legacy-alias", "identity-secret-reference", "identity-ordinary-secret-reference", "identity-application-account", "identity-native-instance", "configuration-set", "configuration-change", "configuration-change-subscribe", "configuration-change-subscribe-reply", "configuration-subscription-control", "configuration-subscription-response", "configuration-watch-close", "configuration-watch-close-response"} {
			raw, e := contextResources.ReadFile("schemas/" + n + ".schema.json")
			if e != nil {
				raw, e = nativeAuthorityResources.ReadFile("schemas/" + n + ".schema.json")
			}
			if e != nil {
				return
			}
			v, e := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if e != nil {
				return
			}
			if c.AddResource("urn:agentmux:contract:1:"+n, v) != nil {
				return
			}
		}
		schemas := map[string]*jsonschema.Schema{}
		for key, uri := range map[string]string{"configuration-watch-close": "configuration-watch-close", "configuration-watch-close-response": "configuration-watch-close-response", "configuration-event-source": "identity-native-instance#/properties/configurationEventSources/items", "configuration-subscription-control": "configuration-subscription-control", "configuration-subscription-response": "configuration-subscription-response", "configuration-change": "configuration-change", "configuration-change-subscribe": "configuration-change-subscribe", "configuration-change-subscribe-reply": "configuration-change-subscribe-reply", "identity-native-instance": "identity-native-instance", "record": "owner-record", "state": "identity-authority-state", "envelope": "message-envelope", "request": "native-authority-request", "response": "native-authority-response", "facts": "native-authority-facts", "grant": "common#/$defs/grant", "scope": "common#/$defs/scope", "reference": "common#/$defs/reference", "owner": "ordinary-plugin-lifecycle#/$defs/owner", "operation": "operation-context"} {
			s, e := c.Compile("urn:agentmux:contract:1:" + uri)
			if e != nil {
				return
			}
			schemas[key] = s
		}
		nativeAuthoritySchemas = schemas
	})
	s := nativeAuthoritySchemas[name]
	if s == nil {
		return pluginError("context_authority_schema_unavailable")
	}
	v, e := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if e != nil || s.Validate(v) != nil {
		return pluginError("context_authority_wire_invalid")
	}
	return nil
}
