package assembly

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyHeldRootDoesNotResolveReplacement(t *testing.T) {
	directory, m, trust := fixture(t)
	directory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	raw, trust := encode(t, m, trust)
	moved := directory + "-moved"
	if err = os.Rename(directory, moved); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory); os.Rename(moved, directory) })
	if err = os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(raw, directory, trust); err == nil {
		t.Fatal("replacement directory unexpectedly verified")
	}
	if _, err = VerifyRoot(raw, directory, root, trust, Limits{MaxMemberBytes, MaxAssemblyBytes}); err != nil {
		t.Fatal(err)
	}
	if _, err = root.Stat("bin"); err != nil {
		t.Fatal("verifier closed caller-owned root")
	}
	if _, err = VerifyRoot(raw, moved, root, trust, Limits{MaxMemberBytes, MaxAssemblyBytes}); err == nil {
		t.Fatal("different root name accepted")
	}
}
