//go:build linux

package privatefs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxDescriptorCheckPreservesCallerPermissionGates(t *testing.T) {
	directory := t.TempDir()
	file, err := os.OpenFile(filepath.Join(directory, "private"), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal("private fixture file unavailable")
	}
	defer file.Close()
	if CheckDescriptor(file, PrivateObject) != nil {
		t.Fatal("valid held private file refused")
	}
	parent, err := os.Open(directory)
	if err != nil {
		t.Fatal("fixture directory unavailable")
	}
	defer parent.Close()
	if CheckDescriptor(parent, PrivateObject) != nil || CheckDescriptor(parent, PublicAncestor) != nil {
		t.Fatal("held directory refused")
	}
	// The helper provides no ownership/mode grant. Its caller must still reject
	// this public file; the descriptor check alone deliberately does not do so.
	if file.Chmod(0644) != nil {
		t.Fatal("fixture mode change unavailable")
	}
	if CheckDescriptor(file, PrivateObject) != nil {
		t.Fatal("helper changed the caller's POSIX mode responsibility")
	}
}
