//go:build darwin && cgo && agentmux_bootstrap_docker && agentmux_darwin_identity_protected_normal && agentmux_darwin_runtime_fixture && !agentmux_darwin_identity_candidate && !agentmux_darwin_identity_protected_candidate

package darwinfixtureidentity

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
	"golang.org/x/sys/unix"
)

type runtimeParentFixture struct {
	creator                *Creator
	path, digest, deadline string
	assembly               Assembly
}

func runtimeParentNormalFixture(t *testing.T) runtimeParentFixture {
	t.Helper()
	path, digest := os.Getenv("AGENTMUX_RUNTIME_FIXTURE_PATH"), os.Getenv("AGENTMUX_RUNTIME_FIXTURE_DIGEST")
	root := filepath.Dir(path)
	version, versionErr := hex.DecodeString(filepath.Base(root))
	if os.Getenv("AGENTMUX_RUNTIME_FIXTURE_AUTHORIZED") != "1" || runtime.GOARCH != "arm64" || os.Getuid() == 0 || os.Getuid() != os.Geteuid() ||
		filepath.Base(path) != "runtime-fixture" || filepath.Clean(path) != path || filepath.Dir(root) != "/Library/Application Support/Agentmux/Protected/releases" ||
		versionErr != nil || len(version) != 32 || strings.ToLower(filepath.Base(root)) != filepath.Base(root) {
		t.Fatal("separately installed runtime fixture prerequisite refused")
	}
	// This normal lifecycle profile requires the explicitly selected SDK26.5.
	// The self-only probe does not qualify these protected parent controls.
	osVersion, sdk, err := nativeAdmission()
	if err != nil || osVersion != "26.6" || sdk != 260500 {
		t.Fatal("normal runtime parent OS or compiled SDK tuple differs")
	}
	kernel, err := unix.Sysctl("kern.osrelease")
	if err != nil || kernel != "25.6.0" {
		t.Fatal("normal runtime parent kernel tuple differs")
	}
	creator, err := NewCreator()
	if err != nil || creator == nil {
		t.Fatal("unchanged normal creator refused runtime parent admission")
	}
	if _, normal := creator.admission.(normalAdmission); !normal {
		t.Fatal("runtime parent fixture did not use normal admission")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	image, err := protected.PrepareProtectedInstalledHost(ctx, path, digest, 128*1024*1024)
	if err != nil {
		t.Fatal("actual protected runtime fixture admission failed")
	}
	if image.Close() != nil {
		t.Fatal("actual protected runtime fixture admission cleanup failed")
	}
	deadline := strconv.FormatInt(time.Now().Add(15*time.Second).UnixNano(), 10)
	// Reuse the existing fixture-only in-memory assembly definition. This does
	// not enroll a key, sign a release, install files, or qualify product trust.
	input, _ := protectedCandidateAssembly(t, path, digest, deadline)
	prepared, err := protected.Prepare(ctx, input.Raw, input.PackageDir, input.Trust, protected.Limits{})
	if err != nil {
		t.Fatal("actual protected runtime role admission failed")
	}
	if prepared.Close() != nil {
		t.Fatal("actual protected runtime role admission cleanup failed")
	}
	return runtimeParentFixture{creator: creator, path: path, digest: digest, deadline: deadline, assembly: input}
}

func runtimeParentPipe(t *testing.T) (reader, writer *os.File) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal("actual runtime parent pipe unavailable")
	}
	return reader, writer
}

func closeRuntimeParentFile(slot **os.File) error {
	file := *slot
	*slot = nil
	if file == nil {
		return nil
	}
	return file.Close()
}

func TestRuntimeNormalParentEOFStopsActualChild(t *testing.T) {
	fixture := runtimeParentNormalFixture(t)
	reader, writer := runtimeParentPipe(t)
	t.Cleanup(func() {
		for _, slot := range []**os.File{&reader, &writer} {
			if closeRuntimeParentFile(slot) != nil {
				t.Error("owned parent EOF pipe cleanup failed")
			}
		}
	})
	readyRead, readyWrite := runtimeParentPipe(t)
	t.Cleanup(func() {
		for _, slot := range []**os.File{&readyRead, &readyWrite} {
			if closeRuntimeParentFile(slot) != nil {
				t.Error("owned parent EOF pipe cleanup failed")
			}
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	child, err := fixture.creator.StartProtected(ctx, Launch{
		Path: fixture.path, Digest: fixture.digest,
		Args: []string{"parent-ready", "boot", fixture.deadline},
		Env: []string{"AGENTMUX_KERNEL_ROLE=boot", "AGENTMUX_KERNEL_PARENT_FD=4"},
		ExtraFiles: []*os.File{readyWrite, reader}, Dir: "/",
	})
	joined := false
	if child != nil {
		t.Cleanup(func() {
			if closeRuntimeParentFile(&writer) != nil {
				t.Error("owned parent EOF cleanup close failed")
			}
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if !joined {
				if signalErr := child.Signal(syscall.SIGKILL); signalErr != nil && !errors.Is(signalErr, ErrExited) {
					t.Error("exact owned parent child cleanup signal failed")
				}
				if _, joinErr := child.Join(cleanup); joinErr != nil {
					t.Error("exact owned parent child cleanup did not join")
					return
				}
			}
			if child.Close() != nil {
				t.Error("exact owned parent child descriptor cleanup failed")
			}
		})
	}
	if err != nil || child == nil {
		t.Fatal("actual protected parent child did not start")
	}
	if closeRuntimeParentFile(&reader) != nil || closeRuntimeParentFile(&readyWrite) != nil {
		t.Fatal("parent child inherited descriptor handoff failed")
	}
	deadline := time.Now().Add(2 * time.Second)
	if readyRead.SetReadDeadline(deadline) != nil {
		t.Fatal("parent readiness deadline setup failed")
	}
	var receipt [1]byte
	if n, err := io.ReadFull(readyRead, receipt[:]); err != nil || n != 1 || receipt[0] != 1 {
		t.Fatal("actual child did not validate ParentLifetime before EOF")
	}
	if n, err := readyRead.Read(receipt[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatal("actual parent readiness receipt did not finish")
	}
	proof, err := child.Pin(ctx)
	if err != nil || proof.Live() != nil {
		t.Fatal("actual ready parent child lacks exact live identity")
	}
	if closeRuntimeParentFile(&writer) != nil {
		t.Fatal("owned parent EOF writer close failed")
	}
	wait, finish := context.WithTimeout(context.Background(), 2*time.Second)
	defer finish()
	completion, err := child.Join(wait)
	if err != nil {
		t.Fatal("actual child ignored parent EOF")
	}
	joined = true
	if completion.Err != nil || completion.Stdout.Err != nil || completion.Stderr.Err != nil || completion.Stdout.Overflow || completion.Stderr.Overflow || len(completion.Stderr.Bytes) != 0 {
		t.Fatal("actual parent EOF child did not exit and join cleanly")
	}
	if proof.WaitExit(wait) != nil {
		t.Fatal("exact parent child exit watch did not confirm completion")
	}
	var ready struct {
		Ready    bool   `json:"ready"`
		Role     string `json:"role"`
		ParentFD int    `json:"parentFD"`
		LeaseFD  int    `json:"leaseFD"`
	}
	if json.Unmarshal(completion.Stdout.Bytes, &ready) != nil || !ready.Ready || ready.Role != "boot" || ready.ParentFD != 4 || ready.LeaseFD != 0 {
		t.Fatal("joined actual parent child readiness differs")
	}
}

func assertRuntimeParentLease(t *testing.T, path string, free bool) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal("actual lease observer unavailable")
	}
	defer func() {
		if file.Close() != nil {
			t.Error("actual lease observer cleanup failed")
		}
	}()
	err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if free && err != nil {
		t.Fatal("actually reaped child retained its inherited lease")
	}
	if !free && !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
		t.Fatal("live child did not retain the actual inherited lease")
	}
}

func TestRuntimeNormalParentInheritedLeasesLastUntilOwnedReap(t *testing.T) {
	fixture := runtimeParentNormalFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	prepared, err := protected.Prepare(ctx, fixture.assembly.Raw, fixture.assembly.PackageDir, fixture.assembly.Trust, protected.Limits{})
	if err != nil {
		t.Fatal("actual protected runtime role preparation failed")
	}
	t.Cleanup(func() {
		if prepared.Close() != nil {
			t.Error("owned prepared runtime role cleanup failed")
		}
	})
	var options [4]protected.RoleOptions
	var callerLeases [4]*os.File
	t.Cleanup(func() {
		for i := range callerLeases {
			if closeRuntimeParentFile(&callerLeases[i]) != nil {
				t.Error("actual caller role lease cleanup failed")
			}
		}
	})
	paths := map[string]string{}
	for i, role := range protocol.Roles() {
		path := filepath.Join(t.TempDir(), "lease-"+role)
		lease, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			t.Fatal("actual caller role lease unavailable")
		}
		callerLeases[i] = lease
		if unix.Flock(int(lease.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
			t.Fatal("actual caller role lease acquisition failed")
		}
		options[i] = protected.RoleOptions{ID: role, Args: []string{"parent", role, fixture.deadline}, LifetimeLease: lease}
		paths[role] = path
	}
	group, err := prepared.Start(context.Background(), options, protected.Deadlines{StartTimeout: 3 * time.Second, StopGrace: 50 * time.Millisecond, ReapTimeout: 2 * time.Second})
	if group != nil {
		t.Cleanup(func() {
			cleanup, finish := context.WithTimeout(context.Background(), 3*time.Second)
			defer finish()
			if group.Stop(cleanup) != nil {
				t.Error("actual owned runtime group cleanup failed")
			}
		})
	}
	if err != nil || group == nil {
		t.Fatal("actual protected runtime roles did not start")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		readyCount := 0
		for _, option := range options {
			out, truncated := group.Output(option.ID)
			var ready struct {
				Ready    bool   `json:"ready"`
				Role     string `json:"role"`
				ParentFD int    `json:"parentFD"`
				LeaseFD  int    `json:"leaseFD"`
			}
			if !truncated && json.Unmarshal(out, &ready) == nil && ready.Ready {
				if ready.Role != option.ID || ready.ParentFD != 3 || ready.LeaseFD != 4 {
					t.Fatal("native runtime inherited descriptor slots differ")
				}
				readyCount++
			}
		}
		if readyCount == 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("actual leased roles did not validate parent lifetime")
		}
		time.Sleep(time.Millisecond)
	}
	states := group.Status()
	if len(states) != 4 {
		t.Fatal("actual leased role roster differs")
	}
	for _, state := range states {
		if state.Exited {
			t.Fatal("leased role exited before the ownership control")
		}
	}
	for i, option := range options {
		if _, err := option.LifetimeLease.Stat(); err != nil {
			t.Fatal("runtime closed the caller-owned role lease")
		}
		if closeRuntimeParentFile(&callerLeases[i]) != nil {
			t.Fatal("caller-owned role lease close failed")
		}
		assertRuntimeParentLease(t, paths[option.ID], false)
	}
	stopRole, finishRole := context.WithTimeout(context.Background(), time.Second)
	err = group.StopRole(stopRole, "boot")
	finishRole()
	if err != nil {
		t.Fatal("exact owned boot role stop failed")
	}
	for _, state := range group.Status() {
		if state.Exited != (state.Role == "boot") {
			t.Fatal("single owned-role stop affected another child")
		}
	}
	for _, option := range options {
		assertRuntimeParentLease(t, paths[option.ID], option.ID == "boot")
	}
	stopGroup, finishGroup := context.WithTimeout(context.Background(), 3*time.Second)
	err = group.Stop(stopGroup)
	finishGroup()
	if err != nil || group.CleanupError() != nil {
		t.Fatal("actual owned group stop or descriptor cleanup failed")
	}
	select {
	case <-group.Done():
	default:
		t.Fatal("actual owned group was not reaped")
	}
	for _, state := range group.Status() {
		if !state.Exited {
			t.Fatal("owned leased child remained live after stop")
		}
	}
	for _, option := range options {
		assertRuntimeParentLease(t, paths[option.ID], true)
	}
}
