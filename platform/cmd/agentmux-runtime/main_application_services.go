//go:build linux || darwin

package main

import (
	"context"
	"errors"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/controlLogix/agentmux/platform/launcher"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

type applicationServicesOptions struct {
	installationID, path, digest string
}

func validateApplicationServiceFlags(o options, installationPresent, pathPresent, digestPresent bool) error {
	count := 0
	for _, selected := range []bool{installationPresent, pathPresent, digestPresent} {
		if selected {
			count++
		}
	}
	if count == 0 {
		return nil
	}
	selected := o.services
	if count != 3 || (o.operation != "ensure" && o.operation != "host") || o.applicationSelection == "" || o.applicationDigest == "" ||
		!protected.ValidClientInstallationID(selected.installationID) || !filepath.IsAbs(selected.path) || filepath.Clean(selected.path) != selected.path || len(selected.path) > 4096 ||
		strings.IndexFunc(selected.path, func(r rune) bool { return r < 32 || r == 127 }) >= 0 || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(selected.digest) {
		return errors.New("arguments_invalid")
	}
	return nil
}

type applicationHostRunner interface {
	RunWithApplicationAttestor(context.Context, string, launcher.ApplicationAttestorHostSelection) error
	RunWithApplicationServices(context.Context, string, launcher.ApplicationAttestorHostSelection, launcher.ApplicationServiceProcessSelection) error
}

func runApplicationHost(ctx context.Context, host applicationHostRunner, o options, attestor launcher.ApplicationAttestorHostSelection) error {
	if o.services.installationID == "" {
		return host.RunWithApplicationAttestor(ctx, o.invocation, attestor)
	}
	// Composition binds these literal pins to the admitted host and attestor. It
	// retains partial process owners and joins cleanup before returning an error.
	return host.RunWithApplicationServices(ctx, o.invocation, attestor, launcher.ApplicationServiceProcessSelection{
		InstallationID: o.services.installationID, Path: o.services.path, SHA256: o.services.digest,
	})
}
