//go:build darwin && cgo

package runtime

import (
	"context"
	"os"
	"path/filepath"
)

// Darwin requires an existing immutable root-owned installation. A user-owned
// file cannot become protected through a mutable staging copy.
func PrepareInstalledHost(context.Context, *os.File, string, int64) (*InstalledHostImage, error) {
	return nil, ErrPlatformUnqualified
}

// PrepareProtectedInstalledHost retains the protected path's real descriptors.
// StartHost revalidates their identities, ACLs, mount policy and image digest
// immediately before execution. The runtime never installs or elevates itself.
func PrepareProtectedInstalledHost(ctx context.Context, path, want string, max int64) (*InstalledHostImage, error) {
	if ctx == nil || ctx.Err() != nil || !installedHostDigest.MatchString(want) || max < 1 || max > 128*1024*1024 || !darwinReleaseRoot(filepath.Dir(path)) || filepath.Base(path) == "." {
		return nil, hostExecutionError("preparation_invalid")
	}
	image, err := openDarwinProtected(ctx, path, want, max)
	if err != nil {
		return nil, installedHostPreparationFailure(err)
	}
	return &InstalledHostImage{image: image, digest: want}, nil
}
