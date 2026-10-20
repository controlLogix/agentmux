//go:build !darwin || !arm64 || !cgo

package runtime

import "context"

func PrepareProtectedInstalledFrontend(context.Context, string, string, int64) (*InstalledFrontendImage, error) {
	return nil, ErrPlatformUnqualified
}
