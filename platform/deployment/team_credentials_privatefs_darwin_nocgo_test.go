//go:build darwin && !cgo

package deployment

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDarwinTeamPrivateCredentialWithoutCGORefuses(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("canonical private fixture unavailable")
	}
	if os.Chmod(directory, 0700) != nil || os.WriteFile(filepath.Join(directory, "credential.json"), []byte(`{"fixture":"synthetic"}`), 0600) != nil {
		t.Fatal("private refusal fixture unavailable")
	}
	raw, err := teamReadPrivate(directory, "credential.json", uint32(os.Geteuid()))
	if err == nil || err.Error() != "team_private_platform_unqualified" || raw != nil {
		t.Fatal("Darwin without cgo admitted team credential bytes")
	}
}
