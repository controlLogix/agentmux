//go:build linux || darwin

package launcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCentralProfileNativeContextUsesRetainedBinding(t *testing.T) {
	fixture := centralFixture(t)
	owner, err := registerCentralProfile(context.Background(), fixture.request, fixture.deps)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	profile, err := owner.NativeContextProfile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if profile.ProfileID != owner.record.ProfileID || profile.InstanceID != owner.record.InstanceID || profile.HubID != owner.selected.HubID || profile.Context.Environment == nil || profile.Context.Project != nil {
		t.Fatal("native context binding inferred or changed metadata")
	}
	*profile.Context.Environment = "Changed"
	again, err := owner.NativeContextProfile(context.Background())
	if err != nil || *again.Context.Environment != "Development" {
		t.Fatal("native context metadata was mutable")
	}
	path := filepath.Join(fixture.directory, "host-policy.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(path, path+".held"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = owner.NativeContextProfile(context.Background()); err == nil {
		t.Fatal("native context accepted replaced original host policy")
	}
}
