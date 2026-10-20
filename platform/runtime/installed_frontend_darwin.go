//go:build darwin && arm64 && cgo

package runtime

import "context"

// PrepareProtectedInstalledFrontend admits only the fixed frontend path. It
// shares protected image checks, but never expands host or role path admission.
func PrepareProtectedInstalledFrontend(ctx context.Context, path, want string, max int64) (*InstalledFrontendImage, error) {
	if ctx == nil || ctx.Err() != nil || !installedHostDigest.MatchString(want) || max < 1 || max > 128*1024*1024 || path != StableFrontendPath {
		return nil, &installedFrontendFailure{code: "preparation_invalid"}
	}
	image, err := openDarwinStableFrontend(ctx, path, want, max)
	if err != nil {
		return nil, &installedFrontendFailure{"protected_image_invalid", err}
	}
	return &InstalledFrontendImage{image: image}, nil
}
