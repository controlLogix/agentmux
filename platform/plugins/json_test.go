package plugins

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestOrdinaryJSONSDKBoundsAndNumbers(t *testing.T) {
	for _, raw := range []string{`{"x":1e9999}`, `{"x":9007199254740992}`, `{"x":"\udc00"}`, `{"x":"\ud800x"}`, `{"x":1,"x":2}`, `[] false`} {
		if strictDocument([]byte(raw)) == nil {
			t.Fatal("invalid ordinary JSON accepted")
		}
	}
	for _, raw := range []string{`{"x":1e20}`, `{"x":1.5}`, `{"x":"\ud83d\ude00"}`, `{"x":9007199254740991}`} {
		if strictDocument([]byte(raw)) != nil {
			t.Fatal("SDK-compatible JSON refused")
		}
	}
	base := manifestBytes(t, fixtureManifest("example"))
	raw := bytes.Replace(base, []byte(`"apiMajor":1`), []byte(`"apiMajor":1e0`), 1)
	v, e := ValidateManifest(raw)
	if e != nil || v.Manifest().APIMajor != 1 || !bytes.Equal(v.Raw(), raw) {
		t.Fatal("JSON integer representation narrowed")
	}
	var data any
	if json.Unmarshal(raw, &data) != nil {
		t.Fatal("fixture invalid")
	}
}
