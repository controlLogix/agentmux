//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestOwnerProfilePreparationRouteRejectsBeforeAdmission(t *testing.T) {
	for _, args := range [][]string{
		{"prepare-owner-profile"},
		{"prepare-owner-profile", "--request", "PRIVATE"},
		{"prepare-owner-profile", "--request", "/private/request.json", "--request-sha256", "sha256:" + strings.Repeat("a", 64), "--apply=false"},
		{"recover-owner-profile"},
		{"recover-owner-profile", "--request", "PRIVATE"},
		{"recover-owner-profile", "--request", "/private/request.json", "--request-sha256", "sha256:" + strings.Repeat("a", 64), "--apply=false"},
	} {
		var output bytes.Buffer
		failure := run(context.Background(), args, &output)
		if failure == nil || failure.Error() != "owner_profile_preparation_arguments_invalid" || output.Len() != 0 {
			t.Fatal("owner preparation bypassed closed dispatch", failure)
		}
	}
}
