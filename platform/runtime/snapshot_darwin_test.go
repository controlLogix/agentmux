//go:build darwin

package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "darwin-fd-research-child" {
		fmt.Println("darwin-descriptor-child")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestDarwinProductRemainsFailClosed(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := prepareExecutable(context.Background(), root, filepath.Base("unused"), "unused", 1); err != ErrPlatformUnqualified {
		t.Fatal("research silently became product support")
	}
}
