//go:build darwin && cgo && agentmux_bootstrap_docker && agentmux_darwin_identity_candidate && agentmux_darwin_identity_protected_candidate && !agentmux_darwin_identity_protected_normal

package darwinfixtureidentity

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Preserve the SDK 27 diagnostic route and normal-creator refusal separately
// from normal SDK 26.5 qualification. Shared assertions do not enroll an ABI.
func protectedCandidateInput(t *testing.T) (*Creator, string, string) {
	t.Helper()
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
	creator, err := newCandidateCreator()
	if err != nil {
		t.Fatal("protected_candidate_creator_refused")
	}
	if normal, err := NewCreator(); err == nil || normal != nil {
		t.Fatal("protected_candidate_normal_creator_accepted")
	}
	return creator, path, digest
}

func protectedControlInput(t *testing.T) (*Creator, string, string) {
	return protectedCandidateInput(t)
}

func TestProtectedCandidateLoaderAdmission(t *testing.T) { runProtectedCandidateLoaderAdmission(t) }

func TestProtectedCandidateFastCompletion(t *testing.T) { runProtectedCandidateFastCompletion(t) }

func TestProtectedCandidateWrongDigest(t *testing.T) { runProtectedCandidateWrongDigest(t) }

func TestProtectedCandidateInvalidArguments(t *testing.T) { runProtectedCandidateInvalidArguments(t) }

func TestProtectedCandidateReparentedRoles(t *testing.T) { runProtectedCandidateReparentedRoles(t) }

func TestProtectedCandidateHostRefusals(t *testing.T) { runProtectedCandidateHostRefusals(t) }

func TestProtectedCandidateRoleRosterRefusals(t *testing.T) {
	runProtectedCandidateRoleRosterRefusals(t)
}
