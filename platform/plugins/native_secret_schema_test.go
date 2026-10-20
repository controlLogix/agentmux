package plugins

import (
	"bytes"
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestNativeSecretAuthoritySchemaClosure(t *testing.T) {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(manifestDenyLoader{})
	c.UseRegexpEngine(nativeAuthorityRegexp)
	seen := map[string]bool{}
	for _, resources := range []interface {
		ReadFile(string) ([]byte, error)
		ReadDir(string) ([]os.DirEntry, error)
	}{contextResources, nativeAuthorityResources} {
		entries, err := resources.ReadDir("schemas")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if seen[name] {
				continue
			}
			seen[name] = true
			raw, err := resources.ReadFile("schemas/" + name)
			if err != nil {
				t.Fatal(err)
			}
			v, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			if err := c.AddResource("urn:agentmux:contract:1:"+name[:len(name)-len(".schema.json")], v); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := c.Compile("urn:agentmux:contract:1:identity-authority-state"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"identity-authority-state", "identity-legacy-alias", "identity-secret-reference", "identity-ordinary-secret-reference", "identity-application-account"} {
		canonical, err := os.ReadFile("../../contracts/v1/schemas/" + name + ".schema.json")
		if err != nil {
			t.Fatal(err)
		}
		embedded, err := nativeAuthorityResources.ReadFile("schemas/" + name + ".schema.json")
		if err != nil || !bytes.Equal(canonical, embedded) {
			t.Fatal("native authority schema differs from canonical contract", name)
		}
	}
}

func TestNativeAuthorityAliasControlCharacters(t *testing.T) {
	expression, err := nativeAuthorityRegexp(`^[^\u0000-\u001f\u007f]+$`)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"ordinary-account", " ", "~", "\u0080", "u0000", `\`} {
		if !expression.MatchString(value) {
			t.Fatal("allowed alias refused")
		}
	}
	for _, value := range []string{"", "\x00", "\x01", "\x1f", "\x7f", "a\nb"} {
		if expression.MatchString(value) {
			t.Fatal("control alias accepted")
		}
	}
}
