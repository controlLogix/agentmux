//go:build darwin && !cgo

package privatefs

import (
	"errors"
	"os"
	"testing"
)

func TestDarwinWithoutCGORefusesDescriptorAccessQualification(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "private")
	if err != nil {
		t.Fatal("fixture descriptor unavailable")
	}
	defer file.Close()
	if !errors.Is(CheckDescriptor(file, PrivateObject), ErrPlatformUnqualified) {
		t.Fatal("unqualified Darwin backend granted private access")
	}
}
