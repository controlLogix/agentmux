//go:build linux

package boot_test

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/assembly"
	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
	"golang.org/x/sys/unix"
)

type lifetimeHostInput struct {
	PackageDir string
	Assembly   []byte
	Trust      assembly.Trust
	Options    [4]protected.RoleOptions
	LeasePaths [4]string
}

// The helper is the actual process owner. Its private input comes from the
// signature-verifying fixture; it contains credential references, not secrets.
func TestParentLifetimeHostHelper(t *testing.T) {
	path := os.Getenv("AGENTMUX_LIFETIME_HOST_INPUT")
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("private host input unavailable")
	}
	var input lifetimeHostInput
	if json.Unmarshal(data, &input) != nil {
		t.Fatal("private host input invalid")
	}
	for i, path := range input.LeasePaths {
		file, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			t.Fatal("private lease open failed")
		}
		if unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
			t.Fatal("private lease acquisition failed")
		}
		defer file.Close()
		input.Options[i].LifetimeLease = file
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	prepared, err := protected.Prepare(ctx, input.Assembly, input.PackageDir, input.Trust, protected.Limits{})
	cancel()
	if err != nil {
		t.Fatal("private host preparation failed")
	}
	defer prepared.Close()
	group, err := prepared.Start(context.Background(), input.Options, protected.Deadlines{StartTimeout: 5 * time.Second, StopGrace: time.Second, ReapTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal("private host start failed")
	}
	if err := json.NewEncoder(os.Stdout).Encode(group.Status()); err != nil {
		t.Fatal("private host observation failed")
	}
	// SIGKILL prevents normal Stop/Wait cleanup. The roles must exit on EOF.
	select {}
}

func TestKilledHostFourProtectedRolesExitAndReleaseLeases(t *testing.T) {
	f := setup(t)
	packageDir, raw, trust, options := staticKernelFixture(t, &f)
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private host directory failed")
	}
	input := lifetimeHostInput{PackageDir: packageDir, Assembly: raw, Trust: trust, Options: options}
	for i := range input.LeasePaths {
		input.LeasePaths[i] = filepath.Join(dir, options[i].ID+".lock")
		if os.WriteFile(input.LeasePaths[i], nil, 0600) != nil {
			t.Fatal("private lease fixture failed")
		}
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal("private host encoding failed")
	}
	inputPath := filepath.Join(dir, "host.json")
	if os.WriteFile(inputPath, encoded, 0600) != nil {
		t.Fatal("private host write failed")
	}
	host := exec.Command(os.Args[0], "-test.run=^TestParentLifetimeHostHelper$", "-test.timeout=25s")
	host.Env = append(os.Environ(), "AGENTMUX_LIFETIME_HOST_INPUT="+inputPath)
	stdout, err := host.StdoutPipe()
	if err != nil {
		t.Fatal("private host pipe failed")
	}
	if err := host.Start(); err != nil {
		t.Fatal("private host launch failed")
	}
	reaped := false
	t.Cleanup(func() {
		if !reaped {
			host.Process.Kill()
			host.Wait()
		}
	})
	var states []protected.ProcessStatus
	decoded := make(chan error, 1)
	go func() { decoded <- json.NewDecoder(io.LimitReader(stdout, 8192)).Decode(&states) }()
	select {
	case err := <-decoded:
		if err != nil {
			t.Fatal("private child identities unavailable")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("private host startup deadline exceeded")
	}
	if len(states) != 4 {
		t.Fatal("host did not start four protected roles")
	}
	seen := map[int]bool{}
	var descriptors []unix.PollFd
	for _, state := range states {
		if state.PID <= 0 || seen[state.PID] || state.Exited {
			t.Fatal("protected process identity invalid")
		}
		seen[state.PID] = true
		fd, err := unix.PidfdOpen(state.PID, 0)
		if err != nil {
			t.Fatal("exact process exit observation unavailable")
		}
		t.Cleanup(func() { unix.Close(fd) })
		descriptors = append(descriptors, unix.PollFd{Fd: int32(fd), Events: unix.POLLIN})
	}
	reader := f.client(t, communication.OrdinaryPlugin)
	sub, err := reader.SubscribeSync(f.wire.Snapshot)
	if err != nil || reader.FlushTimeout(time.Second) != nil {
		t.Fatal("kernel snapshot subscription failed")
	}
	processSnapshot(t, sub, f.scope, func(s protocol.Snapshot) bool { return s.KernelReadiness == "ready" })
	for _, path := range input.LeasePaths {
		lease, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			t.Fatal("lease observation open failed")
		}
		err = unix.Flock(int(lease.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		lease.Close()
		if err != unix.EWOULDBLOCK {
			t.Fatal("live protected role did not retain its lease")
		}
	}
	if err := host.Process.Kill(); err != nil {
		t.Fatal("owned host kill failed")
	}
	if err := host.Wait(); err == nil {
		t.Fatal("host was not actually killed")
	}
	reaped = true
	deadline := time.Now().Add(5 * time.Second)
	for {
		all := true
		if _, err := unix.Poll(descriptors, 50); err != nil && err != unix.EINTR {
			t.Fatal("process exit observation failed")
		}
		for _, fd := range descriptors {
			if fd.Revents&unix.POLLIN == 0 {
				all = false
			}
		}
		if all {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("protected children survived their owning host")
		}
	}
	for _, path := range input.LeasePaths {
		before, err := os.Stat(path)
		if err != nil {
			t.Fatal("retained lease inode unavailable")
		}
		lease, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			t.Fatal("retained lease reopen failed")
		}
		after, statErr := lease.Stat()
		lockErr := unix.Flock(int(lease.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		lease.Close()
		if statErr != nil || !os.SameFile(before, after) || lockErr != nil {
			t.Fatal("exited protected role did not release the retained lease")
		}
	}
	t.Log("killedOwnedHost=true independentlyObservedChildExits=4 retainedLeaseReacquisitions=4 childSignalsSent=0")
}
