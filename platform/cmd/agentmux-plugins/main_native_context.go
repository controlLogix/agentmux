package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"

	"github.com/controlLogix/agentmux/platform/launcher"
)

var nativeSelectionDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func validNativeContextRequest(input launcher.NativeContextHostRequest) bool {
	clean := func(path string) bool { return filepath.IsAbs(path) && filepath.Clean(path) == path }
	return commandIdentifier.MatchString(input.ProfileID) && clean(input.RepositoryRoot) && clean(input.SelectionPath) && nativeSelectionDigest.MatchString(input.SelectionSHA256) && clean(input.Observability.Path) && input.Observability.MaxBytes >= 64<<10 && input.Observability.MaxBytes <= 64<<20 && input.Observability.EventCodes != nil && input.Observability.SpanCodes != nil && input.Observability.MetricCodes != nil
}

func runNativeContextComposition(ctx context.Context, prepared preparedComposition, output io.Writer, input *os.File) error {
	host, err := launcher.PrepareNativeContextHost(ctx, *prepared.nativeContext)
	cleanup := func(cause error) error {
		if host == nil {
			return cause
		}
		return errors.Join(cause, closeForegroundDriver(host, prepared.options.CleanupTimeout, output))
	}
	if err != nil {
		return cleanup(err)
	}
	if !reflect.DeepEqual(host.DriverOptions(), prepared.driver) {
		return cleanup(fail("plugin_native_driver_selection_mismatch", nil))
	}
	driver, err := host.Driver()
	if err != nil {
		return cleanup(err)
	}
	return runOwnedComposition(ctx, prepared, output, input, driver, host)
}
