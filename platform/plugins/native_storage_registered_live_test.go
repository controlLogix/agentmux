//go:build darwin && arm64 && cgo

package plugins_test

import (
	"context"
	"os"
	"testing"

	"github.com/controlLogix/agentmux/platform/launcher"
	"github.com/controlLogix/agentmux/platform/plugins"
)

// The external test package can borrow the real launcher profile owner without
// making the plugins production package depend on its caller.
func TestNativeInstalledStorageProviders(t *testing.T) {
	if os.Getenv("AMX_INSTALLED_STORAGE_CONTRACT_MATERIAL") == "" {
		t.Skip("installed storage collector required")
	}
	if os.Getenv("AMX_INSTALLED_STORAGE_AUTHORIZED") != "1" {
		t.Fatal("installed storage authorization required")
	}
	profile, err := launcher.ResolveCentralProfile(context.Background(), os.Getenv("AMX_INSTALLED_STORAGE_PROFILE"), os.Getenv("AMX_INSTALLED_STORAGE_WORKSPACE"))
	if profile != nil {
		defer func() {
			if profile.Close() != nil {
				t.Error("registered storage profile cleanup failed")
			}
		}()
	}
	if err != nil {
		t.Fatal("registered storage profile admission refused")
	}
	plugins.RunNativeInstalledStorageProviders(t, profile)
}
