//go:build linux || darwin

package assembly

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestMemberOpenRefusesSpecialFileAndSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "regular"), []byte("member"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("regular", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, name := range []string{"fifo", "link"} {
		if f, err := openMemberFile(root, name); err == nil {
			f.Close()
			t.Fatalf("unsafe %s opened", name)
		}
	}
	f, err := openMemberFile(root, "regular")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}
