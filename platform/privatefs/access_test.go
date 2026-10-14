package privatefs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDescriptorRejectsInvalidKindClosedFileAndInvalidType(t *testing.T) {
	if !errors.Is(CheckDescriptor(nil, PrivateObject), ErrInvalidDescriptor) {
		t.Fatal("nil descriptor accepted")
	}
	file, err := os.CreateTemp(t.TempDir(), "private")
	if err != nil {
		t.Fatal("fixture file unavailable")
	}
	if !errors.Is(CheckDescriptor(file, AccessKind(0)), ErrInvalidDescriptor) {
		t.Fatal("unknown access kind accepted")
	}
	if !errors.Is(CheckDescriptor(file, PublicAncestor), ErrInvalidDescriptor) {
		t.Fatal("regular file treated as public ancestor")
	}
	file.Close()
	if !errors.Is(CheckDescriptor(file, PrivateObject), ErrInvalidDescriptor) {
		t.Fatal("closed descriptor accepted")
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal("fixture pipe unavailable")
	}
	defer read.Close()
	defer write.Close()
	if !errors.Is(CheckDescriptor(read, PrivateObject), ErrInvalidDescriptor) {
		t.Fatal("pipe treated as private regular object")
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if file, err := os.Open(missing); err == nil {
		file.Close()
		t.Fatal("missing fixture unexpectedly exists")
	}
}
