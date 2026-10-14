//go:build !linux

package runtime

import (
	"context"
	"os"
)

func prepareExecutable(context.Context, *os.Root, string, string, int64) (executable, error) {
	return nil, ErrPlatformUnqualified
}
