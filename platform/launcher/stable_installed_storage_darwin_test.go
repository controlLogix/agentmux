//go:build darwin && arm64 && cgo && agentmux_bootstrap_docker

package launcher

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/privatefs"
	"golang.org/x/sys/unix"
)

func installedStorageExecutable(path, digest string) (*os.File, error) {
	fail := errors.New("installed_storage_test_executable_refused")
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(digest) != 71 {
		return nil, fail
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, fail
	}
	directory := filepath.Dir(path)
	parent, err := os.Lstat(directory)
	if err != nil || !privateProfileInfo(parent, uint32(os.Geteuid()), true) {
		return nil, fail
	}
	ancestors, err := trustedHostAncestors(directory, uint32(os.Geteuid()))
	if err != nil {
		return nil, fail
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fail
	}
	file := os.NewFile(uintptr(fd), "installed-storage-test")
	var before, after, slot unix.Stat_t
	good := unix.Fstat(fd, &before) == nil && before.Mode&unix.S_IFMT == unix.S_IFREG && before.Uid == uint32(os.Geteuid()) && before.Nlink == 1 && before.Mode&0077 == 0 && before.Mode&0100 != 0 && before.Size > 0 && before.Size <= 256*1024*1024 && privatefs.CheckDescriptor(file, privatefs.PrivateObject) == nil
	if good {
		hash := sha256.New()
		count, readErr := io.Copy(hash, io.LimitReader(file, before.Size+1))
		same := func(a, b unix.Stat_t) bool {
			return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
		}
		good = readErr == nil && count == before.Size && "sha256:"+hex.EncodeToString(hash.Sum(nil)) == digest && unix.Fstat(fd, &after) == nil && unix.Lstat(path, &slot) == nil && same(before, after) && same(before, slot)
	}
	current, ancestorErr := trustedHostAncestors(directory, uint32(os.Geteuid()))
	good = good && ancestorErr == nil && len(current) == len(ancestors)
	if good {
		for i := range ancestors {
			if !os.SameFile(ancestors[i], current[i]) {
				good = false
			}
		}
	}
	if !good {
		if file.Close() != nil {
			return file, fail
		}
		return nil, fail
	}
	return file, nil
}

func TestInstalledStorageExecutableRefusesChangedOrSharedFile(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("canonical test directory unavailable")
	}
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("private test directory unavailable")
	}
	path := filepath.Join(directory, "plugins.test")
	raw := []byte("selected native test image")
	if os.WriteFile(path, raw, 0700) != nil {
		t.Fatal("test executable setup failed")
	}
	sum := sha256.Sum256(raw)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	file, err := installedStorageExecutable(path, digest)
	if err != nil || file == nil {
		t.Fatal("selected private executable refused")
	}
	if file.Close() != nil {
		t.Fatal("original executable descriptor did not close")
	}
	refuse := func(candidate, pin string) {
		t.Helper()
		file, err := installedStorageExecutable(candidate, pin)
		if file != nil {
			file.Close()
		}
		if err == nil {
			t.Fatal("substituted or shared executable admitted")
		}
	}
	refuse(path, "sha256:"+hex.EncodeToString(make([]byte, 32)))
	alias := filepath.Join(directory, "alias")
	if os.Symlink(path, alias) != nil {
		t.Fatal("symlink setup failed")
	}
	refuse(alias, digest)
	if os.Remove(alias) != nil || os.Link(path, alias) != nil {
		t.Fatal("hardlink setup failed")
	}
	refuse(path, digest)
	if os.Remove(alias) != nil || os.Chmod(path, 0720) != nil {
		t.Fatal("permission setup failed")
	}
	refuse(path, digest)
	if os.Chmod(path, 0700) != nil || os.Chmod(directory, 0755) != nil {
		t.Fatal("parent permission setup failed")
	}
	refuse(path, digest)
}

func TestStableInstalledClientDarwinStorageProviders(t *testing.T) {
	if os.Getenv("AMX_INSTALLED_CLIENT_COLD_FAILURE_HOLD") != "1" {
		t.Fatal("installed storage failure hold required")
	}
	if _, finite := t.Deadline(); finite {
		t.Fatal("installed storage collector requires timeout disabled")
	}
	material := bootstrapDarwinPrivatePrerequisite(t, "AMX_INSTALLED_STORAGE_CONTRACT_MATERIAL", "AMX_INSTALLED_STORAGE_CONTRACT_MATERIAL_SHA256")
	var header struct {
		SchemaVersion    string `json:"schemaVersion"`
		ServiceSelection struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"serviceSelection"`
	}
	// The child admits the complete closed contract. This independently binds
	// it to the service selection admitted by the actual installed host below.
	if json.Unmarshal(material, &header) != nil || header.SchemaVersion != protocol.Version {
		t.Fatal("installed storage material invalid")
	}
	python, binary, digest := os.Getenv("AGENTMUX_NATS_CREDENTIAL_PYTHON"), os.Getenv("AMX_INSTALLED_STORAGE_TEST_BINARY"), os.Getenv("AMX_INSTALLED_STORAGE_TEST_BINARY_SHA256")
	root, err := filepath.Abs("../..")
	if err != nil || !filepath.IsAbs(python) {
		t.Fatal("prepared storage tools required")
	}
	executable, err := installedStorageExecutable(binary, digest)
	if err != nil {
		t.Fatal("storage executable admission failed")
	}
	if executable.Close() != nil {
		t.Fatal("storage executable admission cleanup failed")
	}
	pin, clientID := stableInstalledClientPrerequisites(t)
	application := stableInstalledApplicationPrerequisites(t, clientID)
	if application == nil || application.selected.ApplicationServices.Selection != header.ServiceSelection.Path || application.selected.ApplicationServices.SHA256 != header.ServiceSelection.SHA256 {
		t.Fatal("storage contract selected a different installed service")
	}
	application.serviceCheck = func(t *testing.T, f *bootstrapDockerFixture, cold *composeDarwinCLIFront) {
		cold.lifetime.assertUnchanged(t, f)
		file, err := installedStorageExecutable(binary, digest)
		if err != nil {
			cold.lifetime.admissionFailure(err)
			return
		}
		output, e1 := os.CreateTemp(filepath.Dir(header.ServiceSelection.Path), "native-storage-*.private.log")
		if e1 != nil {
			cold.lifetime.admissionFailure(e1)
			return
		}
		command := exec.Command(binary, "-test.run=^TestNativeInstalledStorageProviders$", "-test.count=1", "-test.timeout=0", "-test.v")
		command.Dir = filepath.Join(root, "platform")
		command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "AMX_INSTALLED_STORAGE_AUTHORIZED=1", "AMX_INSTALLED_STORAGE_PROFILE=" + application.selected.ProfileID, "AMX_INSTALLED_STORAGE_WORKSPACE=" + application.selected.Workspaces[0], "AMX_INSTALLED_STORAGE_REPOSITORY=" + root, "AGENTMUX_NATS_CREDENTIAL_PYTHON=" + python,
			"AMX_INSTALLED_STORAGE_CONTRACT_MATERIAL=" + os.Getenv("AMX_INSTALLED_STORAGE_CONTRACT_MATERIAL"), "AMX_INSTALLED_STORAGE_CONTRACT_MATERIAL_SHA256=" + os.Getenv("AMX_INSTALLED_STORAGE_CONTRACT_MATERIAL_SHA256")}
		command.Stdout, command.Stderr = output, output
		// Run owns the sole wait and output copying. No context or timeout can
		// kill this child while it retains a native process or transport.
		waitErr := command.Run()
		closeErr, imageErr := output.Close(), file.Close()
		if waitErr != nil || closeErr != nil || imageErr != nil {
			cold.lifetime.admissionFailure(errors.New("installed_storage_native_run_unconfirmed"))
			return
		}
		log, err := os.Open(output.Name())
		if err != nil {
			cold.lifetime.admissionFailure(err)
			return
		}
		raw, readErr := io.ReadAll(io.LimitReader(log, 1048577))
		logErr := log.Close()
		if readErr != nil || logErr != nil || len(raw) > 1048576 || !bytes.Contains(raw, []byte("--- PASS: TestNativeInstalledStorageProviders (")) {
			cold.lifetime.admissionFailure(errors.New("installed_storage_native_result_unconfirmed"))
			return
		}
	}
	f, s, r := stableInstalledClientFixture(t)
	stableInstalledClientScenario(t, f, s, r, pin, clientID, true, application)
}
