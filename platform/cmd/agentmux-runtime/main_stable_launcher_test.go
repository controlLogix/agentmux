//go:build linux || darwin

package main

import (
	"reflect"
	"testing"
)

// The stable installer publishes this frontend's bytes, not a shell wrapper or
// a second dispatcher. Its existing policy/host admission remains the route.
func TestStableFrontendPreservesLiteralSelection(t *testing.T) {
	policy := "/private/quote\" and ' policy.json"
	roots := []string{"/work/with spaces", "/work/$(literal)\\backslash"}
	for _, operation := range []string{"ensure", "status"} {
		args := []string{operation, "--host-policy", policy}
		for _, root := range roots {
			args = append(args, "--workspace", root)
		}
		actual, err := parse(args)
		if err != nil || actual.policy != policy || actual.operation != operation || !reflect.DeepEqual([]string(actual.roots), roots) {
			t.Fatal("stable frontend changed literal policy or workspace selection")
		}
	}
}
