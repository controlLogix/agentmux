//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
)

const applicationRuntimeCommandLimit = 0

// The application runtime is qualified only on native macOS ARM64.
func runApplicationRuntime(context.Context, []string, io.Writer) error {
	return errors.New("application_runtime_platform_unqualified")
}

func writeApplicationRuntimeDiagnostic(output io.Writer, _ error) error {
	return json.NewEncoder(output).Encode(map[string]string{"schemaVersion": "1.0.0",
		"kind": "application-runtime-diagnostic", "code": "application_runtime_platform_unqualified"})
}
