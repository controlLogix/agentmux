//go:build darwin && cgo

package privatefs

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func nativeACLChange(t *testing.T, path string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	args = append(args, path)
	cmd := exec.CommandContext(ctx, "/bin/chmod", args...)
	cmd.WaitDelay = time.Second
	if cmd.Run() != nil {
		t.Fatal("owned native ACL fixture operation failed")
	}
}

func TestDarwinPrivateDescriptorRejectsReadAndWriteAllowACL(t *testing.T) {
	for _, permission := range []string{"read", "write"} {
		t.Run(permission, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private")
			file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				t.Fatal("owned fixture file unavailable")
			}
			defer file.Close()
			nativeACLChange(t, path, "-N")
			if CheckDescriptor(file, PrivateObject) != nil {
				t.Fatal("empty valid native ACL refused")
			}
			nativeACLChange(t, path, "+a", "everyone allow "+permission)
			if !errors.Is(CheckDescriptor(file, PrivateObject), ErrAccessDenied) {
				t.Fatal("private descriptor admitted a read/write granting ACL")
			}
			nativeACLChange(t, path, "-N")
			nativeACLChange(t, path, "+a", "everyone deny write")
			if CheckDescriptor(file, PrivateObject) != nil {
				t.Fatal("DENY-only native ACL refused")
			}
			nativeACLChange(t, path, "-N")
		})
	}
}

func TestDarwinAncestorDescriptorRejectsMutationAllows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ancestor")
	if os.Mkdir(path, 0700) != nil {
		t.Fatal("owned fixture ancestor unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("held ancestor unavailable")
	}
	defer file.Close()
	for _, permission := range []string{"write", "append", "delete", "delete_child", "writeattr", "writeextattr", "writesecurity", "chown"} {
		t.Run(permission, func(t *testing.T) {
			nativeACLChange(t, path, "-N")
			nativeACLChange(t, path, "+a", "everyone allow "+permission)
			if !errors.Is(CheckDescriptor(file, PublicAncestor), ErrAccessDenied) {
				t.Fatal("mutating ancestor ACL accepted")
			}
			nativeACLChange(t, path, "-N")
		})
	}
	nativeACLChange(t, path, "+a", "everyone allow read,search")
	if CheckDescriptor(file, PublicAncestor) != nil {
		t.Fatal("nonmutating public ancestor ACL refused")
	}
	if !errors.Is(CheckDescriptor(file, PrivateObject), ErrAccessDenied) {
		t.Fatal("private directory admitted an ALLOW entry")
	}
	nativeACLChange(t, path, "-N")
}
