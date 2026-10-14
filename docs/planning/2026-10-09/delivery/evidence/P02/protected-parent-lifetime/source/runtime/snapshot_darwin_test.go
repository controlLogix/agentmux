//go:build darwin

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "darwin-fd-research-child" {
		fmt.Println("darwin-descriptor-child")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// This test is research, not a product backend. If Darwin cannot execute the
// unlinked read-only descriptor, the recorded native failure must remain visible.
func TestDarwinUnlinkedDescriptorResearch(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.CreateTemp(t.TempDir(), "research-")
	if err != nil {
		t.Fatal(err)
	}
	path := file.Name()
	defer os.Remove(path)
	if _, err = file.Write(data); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err = file.Chmod(0500); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err = file.Sync(); err != nil {
		file.Close()
		t.Fatal(err)
	}
	file.Close()
	read, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	_, readOnlyWriteErr := read.WriteAt(data[:1], 0)
	writer, reopenErr := os.OpenFile(fmt.Sprintf("/dev/fd/%d", read.Fd()), os.O_WRONLY, 0)
	reopenedWriteAllowed := false
	if reopenErr == nil {
		// Rewrite identical bytes so the execution probe still has the original
		// image; this only measures whether the descriptor permits a write.
		n, writeErr := writer.WriteAt(data[:1], 0)
		reopenedWriteAllowed = n == 1 && writeErr == nil
		writer.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/dev/fd/3", "darwin-fd-research-child")
	cmd.ExtraFiles = []*os.File{read}
	cmd.Env = []string{}
	cmd.Dir = "/"
	output, execErr := cmd.CombinedOutput()
	h := sha256.Sum256(data)
	result := map[string]any{"researchOnly": true, "snapshotSHA256": hex.EncodeToString(h[:]), "unlinkedPathAbsent": true, "readOnlyDescriptorRefusedWrite": readOnlyWriteErr != nil, "reopenedWriteDescriptorAllowedWrite": reopenedWriteAllowed, "actualChildExecuted": execErr == nil && strings.TrimSpace(string(output)) == "darwin-descriptor-child", "sameUIDImmutabilityProven": false, "productBackend": "fail-closed"}
	if execErr != nil {
		result["execError"] = execErr.Error()
	}
	raw, _ := json.Marshal(result)
	t.Log(string(raw))
	if execErr != nil {
		t.Fatalf("native Darwin descriptor research did not execute: %v", execErr)
	}
	if strings.TrimSpace(string(output)) != "darwin-descriptor-child" {
		t.Fatal("native descriptor execution marker differs")
	}
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
