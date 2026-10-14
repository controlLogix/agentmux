//go:build darwin && !cgo

package runtime

import (
	"context"
	"os"
)

func PrepareInstalledHost(context.Context, *os.File, string, int64) (*InstalledHostImage, error) {
	return nil, ErrPlatformUnqualified
}
func PrepareProtectedInstalledHost(context.Context, string, string, int64) (*InstalledHostImage, error) {
	return nil, ErrPlatformUnqualified
}
