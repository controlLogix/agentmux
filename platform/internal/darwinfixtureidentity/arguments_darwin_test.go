//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
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
	args = append(args, "--application-attestor-selection", "/fixture/attestor", "--application-attestor-selection-sha256", "sha256:"+strings.Repeat("a", 64),
		"--application-services-installation", strings.Repeat("b", 64), "--application-services-selection", "/fixture/services", "--application-services-selection-sha256", "sha256:"+strings.Repeat("c", 64))
	if len(args) != 48 {
		t.Fatal("native_argument_host_fixture_invalid")
	}
	got, err := parseNativeArguments(argumentBlob(uint32(len(args)), args[0], args))
	if err != nil || !reflect.DeepEqual(got, args) {
		t.Fatal("native_argument_host_limit_refused")
	}
}

func TestNativeArgumentReadFailureCategories(t *testing.T) {
	for _, test := range []struct {
		code  int
		stage string
	}{
		{nativeArgumentsAllocationRefused, "fixture_arguments_allocation_refused"},
		{nativeArgumentsQueryRefused, "fixture_arguments_query_refused"},
		{nativeArgumentsLayoutRefused, "fixture_arguments_layout_refused"},
		{99, "fixture_arguments_layout_refused"},
	} {
		err := nativeArgumentReadError(test.code, int(unix.EPERM))
		if got := FailureCategories(failed("fixture_child_arguments_refused", err)); !reflect.DeepEqual(got, []string{"fixture_child_arguments_refused", test.stage}) {
			t.Fatal("argument read failure lost its fixed category")
		}
		if test.code == nativeArgumentsQueryRefused || test.code == nativeArgumentsAllocationRefused {
			if !errors.Is(err, unix.EPERM) {
				t.Fatal("argument read failure lost its private native error")
			}
		} else if errors.Is(err, unix.EPERM) {
			t.Fatal("argument layout failure acquired an unrelated native error")
		}
	}
	if nativeArgumentReadError(nativeArgumentsReadOK, 0) != nil {
		t.Fatal("successful argument read was refused")
	}
}

func TestNativeArgumentParserFailureCategoriesStayPrivate(t *testing.T) {
	for _, test := range []struct {
		raw   []byte
		stage string
	}{
		{make([]byte, 3), "fixture_arguments_buffer_refused"},
		{argumentBlob(65, "/PRIVATE_HEADER", nil), "fixture_arguments_count_refused"},
		{argumentBlob(1, "", []string{"PRIVATE_ARGUMENT"}), "fixture_arguments_header_refused"},
		{argumentBlob(2, "/PRIVATE_HEADER", []string{"PRIVATE_ARGUMENT", ""}), "fixture_arguments_shape_refused"},
	} {
		_, err := parseNativeArguments(test.raw)
		got := FailureCategories(failed("fixture_child_arguments_refused", err))
		if !reflect.DeepEqual(got, []string{"fixture_child_arguments_refused", test.stage}) || strings.Contains(strings.Join(got, ","), "PRIVATE") {
			t.Fatal("argument parser lost its fixed category or exposed private bytes")
		}
	}
	for _, cause := range []error{unknownDiagnosticFailure{}, failed("PRIVATE_ARGUMENT_DETAIL", unknownDiagnosticFailure{})} {
		got := FailureCategories(failed("fixture_child_arguments_refused", cause))
		if !reflect.DeepEqual(got, []string{"fixture_child_arguments_refused"}) {
			t.Fatal("argument diagnostic inspected or exposed an unknown cause")
		}
	}
	for _, stage := range []string{"fixture_arguments_allocation_refused", "fixture_arguments_query_refused", "fixture_arguments_layout_refused",
		"fixture_arguments_buffer_refused", "fixture_arguments_count_refused", "fixture_arguments_header_refused", "fixture_arguments_shape_refused"} {
		got := FailureCategories(failed("fixture_child_arguments_refused", failed(stage, unknownDiagnosticFailure{})))
		if !reflect.DeepEqual(got, []string{"fixture_child_arguments_refused", stage}) {
			t.Fatal("argument diagnostic inspected a private native cause")
		}
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
