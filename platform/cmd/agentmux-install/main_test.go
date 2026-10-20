package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/controlLogix/agentmux/platform/installer"
)

func TestCommandsRequireExplicitSelectionAndKeepFailuresPrivate(t *testing.T) {
	for _, args := range [][]string{
		nil, {"upgrade"}, {"install"}, {"verify", "--selection", "/private/missing"},
		{"install", "--selection", "/private/missing", "--selection-sha256", "sha256:" + strings.Repeat("a", 64), "--owner-uid", "501"},
		{"check", "--host-policy", "/private/missing"},
		{"check", "--host-policy", "/private/missing", "--workspace", "/private/workspace"},
		{"install", "--owner-uid", "4294967296"},
		{"verify", "--unrecognized", "private value"},
	} {
		var output bytes.Buffer
		err := run(context.Background(), args, &output)
		if err == nil || output.Len() != 0 {
			t.Fatal("invalid or missing installation input reported success")
		}
		raw, encodeErr := json.Marshal(installer.Diagnose(err))
		if encodeErr != nil || bytes.Contains(raw, []byte("/private/")) || bytes.Contains(raw, []byte("private value")) {
			t.Fatal("diagnostic disclosed private arguments")
		}
	}
}
