//go:build darwin && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

// This runtime fixture consumes only a separately enrolled protected release.
// Admission proves installed bytes and policy, not that they were built from
// the current source candidate. A separate source-pinned rebuild/prequalification
// receipt remains required before the final gate; older artifacts stay historical.
func bootstrapPrepareFixtureRelease(t *testing.T, selected bootstrapFixtureSelection, _ string) bootstrapFixtureRelease {
	t.Helper()
	raw := bootstrapDarwinPrivatePrerequisite(t, "AMX_DARWIN_ROLE_RELEASE_POLICY", "AMX_DARWIN_REVIEWED_ROLE_RELEASE_POLICY")
	var policy ReleasePolicy
	if protocol.DecodeClosedJSON(raw, &policy, 64*1024) != nil || filepath.Dir(policy.PackageDirectory) != bootstrapDarwinReleaseBase || !fullID.MatchString(filepath.Base(policy.PackageDirectory)) {
		t.Fatal("reviewed installed role policy invalid")
	}
	bootstrapAssertDarwinDirectory(t, policy.PackageDirectory)
	installed, err := LoadInstalledRelease(policy)
	if err != nil || installed.BrokerPins() != (BrokerPins{Image: selected.Image, NATSVersion: selected.NATSVersion, ComposeVersion: selected.Docker.ComposeVersion}) {
		t.Fatal("installed signed role release or broker prerequisites refused")
	}
	var kernelDigest string
	roles := protocol.Roles()
	for i, member := range installed.VerifiedAssembly().Members() {
		if member.ID != roles[i] || member.Path != filepath.Join(policy.PackageDirectory, "bin", roles[i]) {
			t.Fatal("installed role member path differs from the fixed fixture assembly")
		}
		if i == 0 {
			kernelDigest = member.BinaryDigest
		} else if member.BinaryDigest != kernelDigest {
			t.Fatal("installed fixture roles do not share the expected kernel image")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	prepared, err := protected.Prepare(ctx, installed.Assembly(), installed.PackageDirectory(), installed.Trust(), protected.Limits{})
	if err != nil {
		t.Fatal("actual protected role preparation refused the installed release")
	}
	if err := prepared.Close(); err != nil {
		t.Fatal("actual protected role preparation cleanup failed")
	}
	return bootstrapFixtureRelease{policy: policy, assemblyDigest: installed.Trust().AssemblyDigest, kernelDigest: kernelDigest}
}
