//go:build darwin && cgo && agentmux_bootstrap_docker && agentmux_darwin_identity_protected_normal && !agentmux_darwin_identity_candidate && !agentmux_darwin_identity_protected_candidate

package darwinfixtureidentity

import (
	"encoding/hex"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Only the unchanged normal constructor can create authority in this mode.
// Exact compiled SDK and host checks prevent silently qualifying the SDK symlink.
func protectedControlInput(t *testing.T) (*Creator, string, string) {
	t.Helper()
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" || os.Getuid() == 0 || os.Getuid() != os.Geteuid() {
		t.Fatal("protected_normal_host_credentials_refused")
	}
	version, sdk, admissionErr := nativeAdmission()
	kernel, kernelErr := unix.Sysctl("kern.osrelease")
	if admissionErr != nil || kernelErr != nil || version != "26.6" || sdk != 260500 || kernel != "25.6.0" {
		t.Fatal("protected_normal_exact_sdk_host_tuple_refused")
	}
	layout := nativeSelfLayout()
	if layout.bsdSize != 136 || layout.uniqueSize != 56 || layout.combinedSize != 192 ||
		layout.uniqueOffset != 136 || layout.versionOffset != 32 || layout.selector != 18 ||
		layout.returnedSize != 192 || !layout.identityValid {
		t.Fatal("protected_normal_self_layout_refused")
	}
	path, digest := os.Getenv("AGENTMUX_IDENTITY_FIXTURE_PATH"), os.Getenv("AGENTMUX_IDENTITY_FIXTURE_DIGEST")
	root := filepath.Dir(path)
	const base = "/Library/Application Support/Agentmux/Protected/releases"
	decoded, err := hex.DecodeString(filepath.Base(root))
	if path == "" || filepath.Clean(path) != path || filepath.Base(path) != "fixture" || filepath.Dir(root) != base || len(decoded) != 32 || err != nil || strings.ToLower(filepath.Base(root)) != filepath.Base(root) || len(digest) != 71 || !strings.HasPrefix(digest, "sha256:") {
		t.Fatal("protected_candidate_installation_input_refused")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:")); err != nil {
		t.Fatal("protected_candidate_digest_input_refused")
	}

	creator, err := NewCreator()
	if err != nil || creator == nil {
		t.Fatal("protected_normal_creator_refused")
	}
	if _, normal := creator.admission.(normalAdmission); !normal {
		t.Fatal("protected_normal_admission_implementation_refused")
	}
	return creator, path, digest
}

func TestProtectedNormalLoaderAdmission(t *testing.T) { runProtectedCandidateLoaderAdmission(t) }

func TestProtectedNormalFastCompletion(t *testing.T) { runProtectedCandidateFastCompletion(t) }

func TestProtectedNormalWrongDigest(t *testing.T) { runProtectedCandidateWrongDigest(t) }

func TestProtectedNormalInvalidArguments(t *testing.T) { runProtectedCandidateInvalidArguments(t) }

func TestProtectedNormalReparentedRoles(t *testing.T) { runProtectedCandidateReparentedRoles(t) }

func TestProtectedNormalHostRefusals(t *testing.T) { runProtectedCandidateHostRefusals(t) }

func TestProtectedNormalRoleRosterRefusals(t *testing.T) { runProtectedCandidateRoleRosterRefusals(t) }
