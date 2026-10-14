//go:build linux || darwin

package launcher

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/assembly"
	"golang.org/x/sys/unix"
)

func TestProfileBoundaryPrivateSizeAndExactNames(t *testing.T) {
	policy, profile := profileFixture(t)
	if err := EnrollProfile(policy, profile); err != nil {
		t.Fatal("fixture enrollment failed")
	}
	path := filepath.Join(policy.Directory, "profile.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("fixture profile unavailable")
	}
	write := func(b []byte) {
		t.Helper()
		if os.WriteFile(path, b, 0600) != nil {
			t.Fatal("fixture profile write failed")
		}
	}
	t.Run("private-size-not-wire-size", func(t *testing.T) {
		large := append(append([]byte{}, raw...), bytes.Repeat([]byte(" "), 9000)...)
		if len(large) <= 8192 || len(large) >= profileLimit {
			t.Fatal("size fixture is outside intended range")
		}
		write(large)
		loaded, err := LoadProfile(policy)
		if err != nil || loaded.Declaration().ProfileID != profile.ProfileID {
			t.Fatal("otherwise valid private profile above wire limit rejected")
		}
		if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, large) {
			t.Fatal("profile load changed private bytes")
		}
		write(append(large, bytes.Repeat([]byte(" "), profileLimit)...))
		if _, err := LoadProfile(policy); err == nil {
			t.Fatal("private profile hard limit not enforced")
		}
	})
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("fixture profile JSON invalid")
	}
	for _, key := range []string{"schemaVersion", "profileId", "displayName", "instanceId", "ownerUid", "profileDirectory", "mode", "releaseFingerprint", "configDigest", "natsEndpoint", "credentialRef", "composeProject", "docker"} {
		t.Run("top-"+key, func(t *testing.T) {
			alias := strings.ToUpper(key[:1]) + key[1:]
			trimmed := bytes.TrimSpace(raw)
			mutated := append(append([]byte{}, trimmed[:len(trimmed)-1]...), []byte(`,"`+alias+`":`+string(fields[key])+`}`)...)
			var control Profile
			if json.Unmarshal(mutated, &control) != nil || validateProfile(control, policy) != nil {
				t.Fatal("alias fixture did not preserve valid profile")
			}
			write(mutated)
			if _, err := LoadProfile(policy); err == nil || err.Error() != "profile_invalid_fields" {
				t.Fatal("top field alias not rejected by exact name guard")
			}
		})
	}
	for _, key := range []string{"backend", "executable", "context", "endpoint", "engineId", "clientVersion", "serverVersion", "composeVersion"} {
		t.Run("docker-"+key, func(t *testing.T) {
			needle := []byte(`"` + key + `":`)
			if bytes.Count(raw, needle) != 1 {
				t.Fatal("nested fixture field missing")
			}
			alias := strings.ToUpper(key[:1]) + key[1:]
			mutated := bytes.Replace(raw, needle, []byte(`"`+alias+`":`), 1)
			var control Profile
			if json.Unmarshal(mutated, &control) != nil || validateProfile(control, policy) != nil {
				t.Fatal("nested alias fixture changed valid profile")
			}
			write(mutated)
			if _, err := LoadProfile(policy); err == nil || err.Error() != "profile_invalid_fields" {
				t.Fatal("nested field alias accepted")
			}
		})
	}
	write(raw)
	if _, err := LoadProfile(policy); err != nil {
		t.Fatal("valid profile reload failed after aliases")
	}
}

func TestProfileBoundarySwapHelper(t *testing.T) {
	mode := os.Getenv("AMX_PROFILE_SWAP")
	if mode == "" {
		return
	}
	if mode != "fifo" && mode != "symlink" {
		t.Fatal("invalid private fixture invocation")
	}
	policy, profile := profileFixture(t)
	if err := EnrollProfile(policy, profile); err != nil {
		t.Fatal("fixture enrollment failed")
	}
	called := false
	opener := func(root *os.Root, name string) (*os.File, error) {
		called = true
		if name != "profile.json" || root.Name() != policy.Directory {
			t.Fatal("unexpected opener boundary")
		}
		if err := root.Rename(name, "original.json"); err != nil {
			t.Fatal("fixture rename failed")
		}
		switch mode {
		case "fifo":
			if unix.Mkfifo(filepath.Join(policy.Directory, name), 0600) != nil {
				t.Fatal("real FIFO fixture failed")
			}
		case "symlink":
			// The symlink targets the same regular inode inspected before the
			// swap, so SameFile alone cannot detect a followed leaf symlink.
			if root.Symlink("original.json", name) != nil {
				t.Fatal("real symlink fixture failed")
			}
		}
		return assembly.OpenMember(root, name)
	}
	if _, err := loadProfile(policy, opener); !called || err == nil || err.Error() != "profile_open_failed" {
		t.Fatal("swapped file not denied at actual contained opener")
	}
	info, err := os.Lstat(filepath.Join(policy.Directory, "profile.json"))
	if err != nil || mode == "fifo" && info.Mode()&os.ModeNamedPipe == 0 || mode == "symlink" && info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("swap fixture was not retained")
	}
	if mode == "symlink" {
		original, err := os.Stat(filepath.Join(policy.Directory, "original.json"))
		if err != nil || !original.Mode().IsRegular() {
			t.Fatal("symlink did not retain real regular target")
		}
	}
}

func TestProfileBoundaryAfterInspectionSwaps(t *testing.T) {
	for _, mode := range []string{"fifo", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal("fixture child executable unavailable")
			}
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestProfileBoundarySwapHelper$", "-test.timeout=2s")
			cmd.WaitDelay = time.Second
			for _, entry := range os.Environ() {
				key, _, _ := strings.Cut(entry, "=")
				if strings.EqualFold(key, "AMX_PROFILE_SWAP") || strings.EqualFold(key, "AMX_DOCKER_FIXTURE") {
					continue
				}
				cmd.Env = append(cmd.Env, entry)
			}
			cmd.Env = append(cmd.Env, "AMX_PROFILE_SWAP="+mode)
			// Child output stays in memory and contains only safe fixture errors;
			// private profile paths and JSON bytes are never printed on failure.
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			if cmd.Run() != nil || ctx.Err() != nil {
				t.Fatal("bounded file swap child failed or exceeded deadline")
			}
		})
	}
}
