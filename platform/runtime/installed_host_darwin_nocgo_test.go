//go:build darwin && !cgo

package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"testing"
)

// These controlled non-image bytes prove refusal before image admission only.
// They do not qualify a Mach-O image or any child-process lifecycle.
func TestDarwinWithoutCGORefusesInstalledHostAdmission(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "owned-non-image-")
	if err != nil {
		t.Fatal("owned private refusal file unavailable")
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error("owned refusal descriptor cleanup failed")
		}
	})
	payload := []byte("controlled non-image bytes for cgo-disabled admission refusal\n")
	if n, err := file.Write(payload); err != nil || n != len(payload) {
		t.Fatal("owned refusal bytes unavailable")
	}
	const offset = int64(3)
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		t.Fatal("owned refusal descriptor offset unavailable")
	}
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 {
		t.Fatal("owned private refusal metadata invalid")
	}
	nativeBefore, ok := before.Sys().(*syscall.Stat_t)
	if !ok || nativeBefore.Uid != uint32(os.Geteuid()) || nativeBefore.Nlink != 1 {
		t.Fatal("owned refusal identity invalid")
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(payload))
	for _, tc := range []struct {
		name    string
		prepare func() (*InstalledHostImage, error)
	}{
		{"descriptor", func() (*InstalledHostImage, error) {
			return PrepareInstalledHost(context.Background(), file, digest, int64(len(payload)))
		}},
		{"protected_path", func() (*InstalledHostImage, error) {
			return PrepareProtectedInstalledHost(context.Background(), file.Name(), digest, int64(len(payload)))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			image, failure := tc.prepare()
			if image != nil {
				t.Cleanup(func() {
					if err := image.Close(); err != nil {
						t.Error("unexpected image cleanup failed")
					}
				})
				t.Error("cgo-disabled admission returned an image")
			}
			if !errors.Is(failure, ErrPlatformUnqualified) {
				t.Error("cgo-disabled admission lost its platform refusal")
			}
			after, err := file.Stat()
			if err != nil {
				t.Fatal("refusal consumed the original owned descriptor")
			}
			pathInfo, err := os.Lstat(file.Name())
			if err != nil || !os.SameFile(before, after) || !os.SameFile(before, pathInfo) {
				t.Fatal("refusal replaced the owned file or descriptor identity")
			}
			nativeAfter, ok := after.Sys().(*syscall.Stat_t)
			if !ok || after.Mode() != before.Mode() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) ||
				nativeAfter.Uid != nativeBefore.Uid || nativeAfter.Gid != nativeBefore.Gid || nativeAfter.Nlink != nativeBefore.Nlink ||
				nativeAfter.Flags != nativeBefore.Flags || nativeAfter.Ctimespec != nativeBefore.Ctimespec {
				t.Fatal("refusal changed owned file metadata")
			}
			position, err := file.Seek(0, io.SeekCurrent)
			if err != nil || position != offset {
				t.Fatal("refusal changed the original descriptor offset")
			}
			got := make([]byte, len(payload)+1)
			n, readErr := file.ReadAt(got, 0)
			if n != len(payload) || !errors.Is(readErr, io.EOF) || !bytes.Equal(got[:n], payload) {
				t.Fatal("refusal changed bytes visible through the original descriptor")
			}
			pathBytes, err := os.ReadFile(file.Name())
			if err != nil || !bytes.Equal(pathBytes, payload) {
				t.Fatal("refusal changed bytes at the owned path")
			}
		})
	}
}
