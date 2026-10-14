//go:build !linux && !darwin

package runtime

import (
	"context"
	"os"
)

type HostInvocation struct {
	InvocationID   string
	PolicyPath     string
	WorkspaceRoots []string
}
type InstalledHostImage struct{}
type HostProcess struct{}

func PrepareInstalledHost(context.Context, *os.File, string, int64) (*InstalledHostImage, error) {
	return nil, ErrPlatformUnqualified
}
func (*InstalledHostImage) Close() error { return nil }
func (*InstalledHostImage) StartHost(context.Context, HostInvocation) (*HostProcess, error) {
	return nil, ErrPlatformUnqualified
}
func (*HostProcess) Done() <-chan struct{}      { return nil }
func (*HostProcess) Wait(context.Context) error { return ErrPlatformUnqualified }
func (*HostProcess) Stop(context.Context) error { return ErrPlatformUnqualified }

func PrepareProtectedInstalledHost(context.Context, string, string, int64) (*InstalledHostImage, error) {
	return nil, ErrPlatformUnqualified
}
