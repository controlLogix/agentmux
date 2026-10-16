//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFixturePolicyRejectsOverflowAndTrailingData(t *testing.T) {
	valid := `{"scenario":"four","deadlineUnixNano":1}`
	for _, raw := range []string{valid + strings.Repeat(" ", 64*1024) + "trailing", valid + "{}", `{"scenario":"unknown","deadlineUnixNano":1}`, `{"scenario":"four","deadlineUnixNano":1,"extra":true}`} {
		path := filepath.Join(t.TempDir(), "policy.json")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal("fixture_test_input_failed")
		}
		if _, err := loadPolicy(path); err == nil {
			t.Fatal("invalid fixture policy accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
		t.Fatal("fixture_test_input_failed")
	}
	if _, err := loadPolicy(path); err != nil {
		t.Fatal("valid fixture policy refused")
	}
}
func TestFixtureClosedAttemptAndPathGrammar(t *testing.T) {
	valid := "attempt_0123456789abcdef0123456789abcdef"
	if !validAttempt(valid) {
		t.Fatal("valid attempt refused")
	}
	for _, value := range []string{valid + "0", strings.ToUpper(valid), "attempt_" + strings.Repeat("g", 32), "attempt_"} {
		if validAttempt(value) {
			t.Fatal("invalid attempt accepted")
		}
	}
	if !literalPath("/private/fixture-policy") {
		t.Fatal("literal path refused")
	}
	for _, path := range []string{"relative", "/private/../policy", "/private/policy\n", "/private//policy"} {
		if literalPath(path) {
			t.Fatal("invalid path accepted")
		}
	}
}
