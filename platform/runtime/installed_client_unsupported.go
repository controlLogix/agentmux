//go:build !linux && !darwin

package runtime

import (
	"context"
	"os"
)

func PrepareInstalledClient(context.Context, string) (*InstalledClientAdmission, error) {
	return nil, ErrPlatformUnqualified
}

func execInstalledClient(string, []string, []string) error { return ErrPlatformUnqualified }

func withClientRegistration(context.Context, *os.File, string, string, func(*os.File) error) error {
	return ErrPlatformUnqualified
}

func execInstalledRegisteredClient(string, []string, []string, *os.File) error {
	return ErrPlatformUnqualified
}
