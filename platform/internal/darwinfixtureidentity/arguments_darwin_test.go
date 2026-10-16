//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

func argumentBlob(count uint32, header string, args []string) []byte {
	raw := make([]byte, 4)
	binary.NativeEndian.PutUint32(raw, count)
	raw = append(raw, []byte(header)...)
	raw = append(raw, 0, 0)
	for _, arg := range args {
		raw = append(raw, []byte(arg)...)
		raw = append(raw, 0)
	}
	return raw
}

func TestNativeArgumentsMaximumHostInvocation(t *testing.T) {
	args := []string{"/fixture/host", "host", "--host-policy", "/fixture/policy", "--invocation-id", "attempt_00000000000000000000000000000000"}
	for range 16 {
		args = append(args, "--workspace", "/fixture/workspace")
	}
	if len(args) != 38 {
		t.Fatal("native_argument_host_fixture_invalid")
	}
	got, err := parseNativeArguments(argumentBlob(uint32(len(args)), args[0], args))
	if err != nil || !reflect.DeepEqual(got, args) {
		t.Fatal("native_argument_host_limit_refused")
	}
}

func TestNativeArgumentsAcceptedBounds(t *testing.T) {
	args := make([]string, 64)
	for i := range args {
		args[i] = "fixture"
	}
	got, err := parseNativeArguments(argumentBlob(64, "/fixture", args))
	if err != nil || !reflect.DeepEqual(got, args) {
		t.Fatal("native_argument_count_limit_refused")
	}
	arg := strings.Repeat("a", 4096)
	got, err = parseNativeArguments(argumentBlob(1, "/fixture", []string{arg}))
	if err != nil || len(got) != 1 || got[0] != arg {
		t.Fatal("native_argument_size_limit_refused")
	}
	raw := argumentBlob(1, "/fixture", []string{"fixture"})
	raw = append(raw, make([]byte, 256*1024-len(raw))...)
	got, err = parseNativeArguments(raw)
	if err != nil || len(got) != 1 || got[0] != "fixture" {
		t.Fatal("native_argument_buffer_limit_refused")
	}
}

func TestNativeArgumentsMalformedBuffersRefused(t *testing.T) {
	unterminated := argumentBlob(1, "/fixture", []string{"fixture"})
	unterminated = unterminated[:len(unterminated)-1]
	missingHeaderNul := make([]byte, 4)
	binary.NativeEndian.PutUint32(missingHeaderNul, 1)
	missingHeaderNul = append(missingHeaderNul, []byte("fixture")...)
	cases := map[string][]byte{
		"short":                   make([]byte, 3),
		"header_only_count":       make([]byte, 4),
		"oversize_buffer":         make([]byte, 256*1024+1),
		"zero_count":              argumentBlob(0, "/fixture", nil),
		"count65":                 argumentBlob(65, "/fixture", nil),
		"unsigned_count":          argumentBlob(^uint32(0), "/fixture", nil),
		"empty_header":            argumentBlob(1, "", []string{"fixture"}),
		"unterminated_header":     missingHeaderNul,
		"missing_arguments":       argumentBlob(1, "/fixture", nil),
		"unterminated_argument":   unterminated,
		"oversize_argument":       argumentBlob(1, "/fixture", []string{strings.Repeat("a", 4097)}),
		"empty_later_argument":    argumentBlob(2, "/fixture", []string{"fixture", ""}),
		"count_exceeds_arguments": argumentBlob(2, "/fixture", []string{"fixture"}),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseNativeArguments(raw); err == nil {
				t.Fatal("native_argument_malformed_accepted")
			}
		})
	}
}
