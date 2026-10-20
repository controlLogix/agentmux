package wirejson

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestSDKCanonicalCorpus(t *testing.T) {
	raw, err := os.ReadFile("../../plugins/testdata/native-authority-jcs.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct{ Raw, Canonical string }
	}
	if json.Unmarshal(raw, &corpus) != nil || len(corpus.Vectors) == 0 {
		t.Fatal("SDK corpus invalid")
	}
	for i, v := range corpus.Vectors {
		canonical, err := Canonical([]byte(v.Raw), 65536)
		if err != nil || string(canonical) != v.Canonical {
			t.Fatalf("SDK canonical vector %d differs", i)
		}
	}
}
func TestStrictAdmissionAndLimits(t *testing.T) {
	for _, raw := range []string{`{"same":1,"same":2}`, `"\ud800"`, `"\udfff"`, `9007199254740992`, `1e999`, strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65), "true false", string([]byte{'"', 255, '"'})} {
		if Validate([]byte(raw), 65536) == nil {
			t.Fatal("invalid JSON admitted")
		}
	}
	for _, limit := range []int{-1, 0, 3} {
		if _, err := Canonical([]byte("true"), limit); err == nil {
			t.Fatal("byte limit ignored")
		}
	}
	if result, err := Canonical([]byte(`{"z":1e20,"a":-0.0}`), 65536); err != nil || string(result) != `{"a":0,"z":100000000000000000000}` {
		t.Fatal("binary64 canonicalization changed")
	}
}
