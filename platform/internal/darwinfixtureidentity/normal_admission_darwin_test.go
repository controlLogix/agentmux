//go:build darwin && cgo && agentmux_bootstrap_docker && agentmux_darwin_identity_normal_probe

package darwinfixtureidentity

import (
	"os"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// This explicit self-only probe uses the unchanged normal constructor. Build
// with the separately pinned MacOSX26.5.sdk (intrinsic 260500), not the default
// SDK symlink. A pass establishes neither child authority nor full native API,
// protected-image, installation, product, or normal SDK lifecycle qualification.
func TestNormalAdmissionSelfSDK265(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" || os.Getuid() == 0 || os.Getuid() != os.Geteuid() {
		t.Fatal("normal self-probe ordinary-user native ARM64 tuple refused")
	}
	version, sdk, err := nativeAdmission()
	if err != nil || version != "26.6" || sdk != 260500 {
		t.Fatal("normal self-probe OS or compiled SDK tuple differs")
	}
	kernel, err := unix.Sysctl("kern.osrelease")
	if err != nil || kernel != "25.6.0" {
		t.Fatal("normal self-probe kernel tuple differs")
	}
	creator, err := NewCreator()
	if err != nil || creator == nil {
		t.Fatal("unchanged normal creator refused actual self admission")
	}
	if _, normal := creator.admission.(normalAdmission); !normal {
		t.Fatal("self-probe did not use the unchanged normal admission implementation")
	}
	layout := nativeSelfLayout()
	// Keep the reviewed ABI bounds explicit. Matching compiler sizes alone does
	// not substitute for the actual self query's exact returned size and identity.
	if layout.bsdSize != 136 || layout.uniqueSize != 56 || layout.combinedSize != 192 ||
		layout.uniqueOffset != 136 || layout.versionOffset != 32 || layout.selector != 18 ||
		layout.returnedSize != 192 || !layout.identityValid {
		t.Fatal("normal self-probe native layout or actual self result differs")
	}
	actual, err := observe(os.Getpid())
	if err != nil || !sameIdentity(creator.self, actual) || actual.PID != int32(os.Getpid()) ||
		actual.UID != uint32(os.Geteuid()) || actual.RealUID != uint32(os.Getuid()) ||
		actual.Version <= 0 || actual.Unique == 0 || actual.Status == 0 || actual.Status == 5 {
		t.Fatal("normal self-probe actual creator identity differs")
	}
	t.Logf("normal_self_only os=%s kernel=%s sdk=%d bsd=%d unique=%d combined=%d unique_offset=%d version_offset=%d selector=%d returned=%d identity_valid=%t",
		version, kernel, sdk, layout.bsdSize, layout.uniqueSize, layout.combinedSize,
		layout.uniqueOffset, layout.versionOffset, layout.selector, layout.returnedSize, layout.identityValid)
}
