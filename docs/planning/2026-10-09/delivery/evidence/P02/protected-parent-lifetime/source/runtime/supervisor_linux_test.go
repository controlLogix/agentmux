//go:build linux

package runtime

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/assembly"
	"golang.org/x/sys/unix"
)

var fixtureExecutable string
var dynamicFixtureExecutable string

func TestMain(m *testing.M) {
	directory, err := os.MkdirTemp("", "agentmux-static-role-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "static fixture directory unavailable")
		os.Exit(1)
	}
	fixtureExecutable = filepath.Join(directory, "role")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	command := exec.CommandContext(ctx, filepath.Join(goruntime.GOROOT(), "bin", "go"), "build", "-o", fixtureExecutable, "./testdata/role")
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOENV=off")
	output, err := command.CombinedOutput()
	cancel()
	if err != nil {
		os.RemoveAll(directory)
		fmt.Fprintln(os.Stderr, "static fixture build failed:", err, string(output))
		os.Exit(1)
	}
	dynamicFixtureExecutable = filepath.Join(directory, "dynamic-role")
	ctx, cancel = context.WithTimeout(context.Background(), 90*time.Second)
	command = exec.CommandContext(ctx, filepath.Join(goruntime.GOROOT(), "bin", "go"), "build", "-o", dynamicFixtureExecutable, "./testdata/dynamic")
	command.Env = append(os.Environ(), "CGO_ENABLED=1", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOENV=off")
	output, err = command.CombinedOutput()
	cancel()
	if err != nil {
		os.RemoveAll(directory)
		fmt.Fprintln(os.Stderr, "dynamic denial fixture build failed:", err, string(output))
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(directory)
	os.Exit(code)
}

func hash(data []byte) string { h := sha256.Sum256(data); return "sha256:" + hex.EncodeToString(h[:]) }

func releaseFixture(t *testing.T) (string, []byte, assembly.Trust, [4]RoleOptions) {
	t.Helper()
	root := t.TempDir()
	data, err := os.ReadFile(fixtureExecutable)
	if err != nil {
		t.Fatal(err)
	}
	roles := [4]string{"boot", "kernel-lifecycle", "internal-communication", "exported-status"}
	plugins := []map[string]string{}
	var opts [4]RoleOptions
	for i, role := range roles {
		if err := os.WriteFile(filepath.Join(root, role), data, 0700); err != nil {
			t.Fatal(err)
		}
		plugins = append(plugins, map[string]string{"id": role, "entrypoint": role, "binaryDigest": hash(data)})
		opts[i] = RoleOptions{ID: role, Args: []string{"fixture-child", "ignore-term"}, Env: map[string]string{"AGENTMUX_INSTANCE_ID": "fixture_instance"}}
	}
	authority := assembly.Authority{ID: "release_authority", OwnerHubID: "fixture_hub", Revision: 1}
	parent := "sha256:" + strings.Repeat("a", 64)
	raw, err := json.Marshal(map[string]any{"schemaVersion": "1.0.0", "releaseVersion": "1.0.0", "releaseManifestDigest": parent, "releaseAuthorityRef": authority, "kernelApiMajor": 1, "plugins": plugins})
	if err != nil {
		t.Fatal(err)
	}
	return root, raw, assembly.Trust{AssemblyDigest: hash(raw), ReleaseManifestDigest: parent, ReleaseVersion: "1.0.0", ReleaseAuthority: authority, KernelAPIMajor: 1}, opts
}

func budgets() Deadlines {
	return Deadlines{StartTimeout: 3 * time.Second, StopGrace: 50 * time.Millisecond, ReapTimeout: 2 * time.Second}
}
func prepared(t *testing.T, root string, raw []byte, trust assembly.Trust) *Prepared {
	t.Helper()
	p, err := Prepare(context.Background(), raw, root, trust, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}
func stop(t *testing.T, g *Group) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := g.Stop(ctx); err != nil {
		t.Error(err)
	}
}
func observations(t *testing.T, g *Group) []map[string]any {
	t.Helper()
	end := time.Now().Add(3 * time.Second)
	for time.Now().Before(end) {
		all := []map[string]any{}
		for _, s := range g.Status() {
			data, _ := g.Output(s.Role)
			line := strings.SplitN(string(data), "\n", 2)[0]
			var value map[string]any
			if json.Unmarshal([]byte(line), &value) == nil {
				all = append(all, value)
			}
		}
		if len(all) == 4 {
			return all
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("real protected subprocesses did not report their own observations")
	return nil
}

func TestFourLiteralProcessesAndOwnedStop(t *testing.T) {
	root, raw, trust, opts := releaseFixture(t)
	p := prepared(t, root, raw, trust)
	sentinel := exec.Command(fixtureExecutable, "fixture-child", "ignore-term")
	if err := sentinel.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { sentinel.Process.Kill(); sentinel.Wait() }()
	t.Setenv("UNRELATED_SECRET", "fixture_secret")
	t.Setenv("LD_PRELOAD", "fixture_loader")
	for i := range opts {
		opts[i].Args = append(opts[i].Args, "$(touch not-a-shell)", "a b; literal")
	}
	g, err := p.Start(context.Background(), opts, budgets())
	if err != nil {
		t.Fatal(err)
	}
	defer stop(t, g)
	seen := map[int]bool{}
	for _, o := range observations(t, g) {
		pid := int(o["pid"].(float64))
		if seen[pid] {
			t.Fatal("protected members share a process")
		}
		seen[pid] = true
		if o["loader"] != "" || o["private"] != "" || o["instance"] != "fixture_instance" {
			t.Fatal("unexpected inherited environment")
		}
		args := o["args"].([]any)
		if args[0] != "$(touch not-a-shell)" || args[1] != "a b; literal" {
			t.Fatal("literal argument bytes changed")
		}
	}
	stop(t, g)
	for _, s := range g.Status() {
		if !s.Exited || s.ExitCode != -1 {
			t.Fatalf("owned child was not killed and reaped: %+v", s)
		}
	}
	if err := sentinel.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("unrelated sentinel was affected")
	}
	if _, err := p.Start(context.Background(), opts, budgets()); err == nil {
		t.Fatal("prepared assembly started twice")
	}
}

func TestSealedSnapshotSurvivesSourceReplacement(t *testing.T) {
	root, raw, trust, opts := releaseFixture(t)
	p := prepared(t, root, raw, trust)
	for _, option := range opts {
		if err := os.WriteFile(filepath.Join(root, option.ID), []byte("replaced package bytes"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, image := range p.images {
		sealed := image.(*sealedExecutable)
		seals, err := unix.FcntlInt(sealed.file.Fd(), unix.F_GET_SEALS, 0)
		want := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL | unix.F_SEAL_EXEC
		if err != nil || seals&want != want {
			t.Fatal("snapshot lacks required seals")
		}
		// The owner can restore a write permission bit without changing executable
		// bits. The kernel seal must still deny writes through a new write handle.
		if err := unix.Fchmod(int(sealed.file.Fd()), 0700); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", sealed.file.Fd()), unix.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := unix.Write(fd, []byte("tamper"))
		unix.Close(fd)
		if writeErr != syscall.EPERM {
			t.Fatalf("sealed snapshot write not refused: %v", writeErr)
		}
	}
	g, err := p.Start(context.Background(), opts, budgets())
	if err != nil {
		t.Fatal(err)
	}
	defer stop(t, g)
	observations(t, g)
}

func TestRoleAndEnvironmentRefusalBeforeSpawn(t *testing.T) {
	for _, bad := range []string{"duplicate", "unknown", "loader", "private", "nul-arg", "nul-env"} {
		t.Run(bad, func(t *testing.T) {
			root, raw, trust, opts := releaseFixture(t)
			p := prepared(t, root, raw, trust)
			switch bad {
			case "duplicate":
				opts[1].ID = opts[0].ID
			case "unknown":
				opts[0].ID = "ordinary"
			case "loader":
				opts[0].Env["LD_PRELOAD"] = "loader"
			case "private":
				opts[0].Env["UNRELATED_SECRET"] = "secret"
			case "nul-arg":
				opts[0].Args = append(opts[0].Args, "x\x00y")
			case "nul-env":
				opts[0].Env["AGENTMUX_INSTANCE_ID"] = "x\x00y"
			}
			g, err := p.Start(context.Background(), opts, budgets())
			if err == nil || g != nil {
				t.Fatal("invalid launch options created a group")
			}
		})
	}
}

func TestParentCancellationReapsProcesses(t *testing.T) {
	root, raw, trust, opts := releaseFixture(t)
	p := prepared(t, root, raw, trust)
	ctx, cancel := context.WithCancel(context.Background())
	g, err := p.Start(ctx, opts, budgets())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer stop(t, g)
	observations(t, g)
	cancel()
	select {
	case <-g.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("parent cancellation did not reap owned children")
	}
	for _, s := range g.Status() {
		if !s.Exited {
			t.Fatal("owned child still running")
		}
	}
}

func TestCanceledStartupCreatesNoProcesses(t *testing.T) {
	root, raw, trust, opts := releaseFixture(t)
	p := prepared(t, root, raw, trust)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	g, err := p.Start(ctx, opts, budgets())
	if err == nil || g == nil || len(g.Status()) != 0 {
		t.Fatal("canceled startup created a process")
	}
	select {
	case <-g.Done():
	default:
		t.Fatal("empty failed-start group not completed")
	}
}

func TestPartialStartFailureReapsEarlierChild(t *testing.T) {
	root, raw, trust, opts := releaseFixture(t)
	p := prepared(t, root, raw, trust)
	p.images[1].close()
	g, err := p.Start(context.Background(), opts, budgets())
	if err == nil || g == nil || len(g.Status()) != 1 {
		t.Fatal("partial start failure was not reported")
	}
	select {
	case <-g.Done():
	default:
		t.Fatal("partially started child not reaped")
	}
	if !g.Status()[0].Exited {
		t.Fatal("partial child still running")
	}
}

func TestImmediateExitUsesActualWaitState(t *testing.T) {
	root, raw, trust, opts := releaseFixture(t)
	p := prepared(t, root, raw, trust)
	for i := range opts {
		opts[i].Args = []string{"fixture-child", "exit"}
	}
	g, err := p.Start(context.Background(), opts, budgets())
	if err != nil {
		t.Fatal(err)
	}
	defer stop(t, g)
	select {
	case <-g.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("real exit not observed")
	}
	for _, s := range g.Status() {
		if !s.Exited || s.ExitCode != 0 {
			t.Fatalf("actual exit state lost: %+v", s)
		}
	}
}

func TestBoundedProtectedOutput(t *testing.T) {
	root, raw, trust, opts := releaseFixture(t)
	p := prepared(t, root, raw, trust)
	for i := range opts {
		opts[i].Args = []string{"fixture-child", "flood"}
	}
	g, err := p.Start(context.Background(), opts, budgets())
	if err != nil {
		t.Fatal(err)
	}
	defer stop(t, g)
	observations(t, g)
	end := time.Now().Add(time.Second)
	for time.Now().Before(end) {
		data, truncated := g.Output("boot")
		if truncated {
			if len(data) != outputLimit {
				t.Fatal("output bound changed")
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("real output flood not captured as truncated")
}

func TestPreparationLimitsAndScripts(t *testing.T) {
	root, raw, trust, _ := releaseFixture(t)
	if p, err := Prepare(context.Background(), raw, root, trust, Limits{MaxBinaryBytes: 1}); err == nil {
		p.Close()
		t.Fatal("oversized binary prepared")
	}
	var manifest map[string]any
	json.Unmarshal(raw, &manifest)
	script := []byte("#!/bin/sh\necho forbidden\n")
	for _, entry := range manifest["plugins"].([]any) {
		member := entry.(map[string]any)
		member["binaryDigest"] = hash(script)
		os.WriteFile(filepath.Join(root, member["id"].(string)), script, 0700)
	}
	raw, _ = json.Marshal(manifest)
	trust.AssemblyDigest = hash(raw)
	if p, err := Prepare(context.Background(), raw, root, trust, Limits{}); err == nil {
		p.Close()
		t.Fatal("script accepted as a protected executable")
	}
}

func TestConcurrentStopHonorsCallerDeadline(t *testing.T) {
	root, raw, trust, opts := releaseFixture(t)
	p := prepared(t, root, raw, trust)
	g, err := p.Start(context.Background(), opts, budgets())
	if err != nil {
		t.Fatal(err)
	}
	defer stop(t, g)
	observations(t, g)
	first := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		first <- g.Stop(ctx)
	}()
	end := time.Now().Add(time.Second)
	for len(g.stopToken) != 0 && time.Now().Before(end) {
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := g.Stop(ctx); err != context.DeadlineExceeded {
		t.Fatalf("concurrent caller deadline was ignored: %v", err)
	}
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	for _, s := range g.Status() {
		if !s.Exited {
			t.Fatal("first stop did not reap its owned process")
		}
	}
}

type cancelAtCommand struct {
	image  executable
	cancel context.CancelFunc
}

func (e *cancelAtCommand) command(args []string) *exec.Cmd { e.cancel(); return e.image.command(args) }
func (e *cancelAtCommand) close() error                    { return e.image.close() }

func TestCancellationDuringPartialStartupReapsOwnedChildren(t *testing.T) {
	root, raw, trust, opts := releaseFixture(t)
	p := prepared(t, root, raw, trust)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Only cancellation timing is injected. Both commands still execute the real
	// staged fixture, and completion comes from actual Wait results.
	p.images[1] = &cancelAtCommand{image: p.images[1], cancel: cancel}
	g, err := p.Start(ctx, opts, budgets())
	if err == nil || g == nil || len(g.Status()) < 1 {
		t.Fatal("partial canceled startup was not observed")
	}
	select {
	case <-g.Done():
	default:
		t.Fatal("partial canceled children were not reaped before return")
	}
	for _, s := range g.Status() {
		if !s.Exited {
			t.Fatal("partial canceled child is still running")
		}
	}
}

func TestUnownedHandlesAreRefused(t *testing.T) {
	var g Group
	if err := g.Stop(context.Background()); err == nil {
		t.Fatal("unowned zero group accepted")
	}
	var p *Prepared
	if _, err := p.Start(context.Background(), [4]RoleOptions{}, budgets()); err == nil {
		t.Fatal("missing prepared assembly accepted")
	}
}

func TestChangedMemfdBeforeSealIsRejected(t *testing.T) {
	data, err := os.ReadFile(fixtureExecutable)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.MemfdCreate("tampered-fixture", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING|unix.MFD_EXEC)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "tampered-fixture")
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		t.Fatal(err)
	}
	// The source digest remains correct, but the actual staged object changes.
	if _, err := file.WriteAt([]byte{data[len(data)-1] ^ 0xff}, int64(len(data)-1)); err != nil {
		t.Fatal(err)
	}
	image, err := sealAndVerify(context.Background(), file, hash(data), int64(len(data)))
	if image != nil || err == nil || err.Error() != "immutable snapshot digest differs from the trusted binary digest" {
		t.Fatalf("changed staged object accepted: %v", err)
	}
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals&unix.F_SEAL_WRITE == 0 {
		t.Fatal("negative did not check a sealed real memfd")
	}
}

func TestStaticFoundationAndDynamicDependencies(t *testing.T) {
	static, err := elf.Open(fixtureExecutable)
	if err != nil {
		t.Fatal(err)
	}
	defer static.Close()
	for _, p := range static.Progs {
		if p.Type == elf.PT_INTERP {
			t.Fatal("positive fixture is not static")
		}
	}
	needed, err := static.DynString(elf.DT_NEEDED)
	if err != nil || len(needed) != 0 {
		t.Fatal("positive fixture has unqualified dependencies")
	}
	dynamic, err := elf.Open(dynamicFixtureExecutable)
	if err != nil {
		t.Fatal(err)
	}
	defer dynamic.Close()
	interpreter := false
	for _, p := range dynamic.Progs {
		if p.Type == elf.PT_INTERP {
			interpreter = true
		}
	}
	needed, err = dynamic.DynString(elf.DT_NEEDED)
	if err != nil || !interpreter || len(needed) == 0 {
		t.Fatal("real dynamic denial fixture lacks expected dependencies")
	}
	data, err := os.ReadFile(dynamicFixtureExecutable)
	if err != nil {
		t.Fatal(err)
	}
	withoutInterpreter := append([]byte(nil), data...)
	if dynamic.Class != elf.ELFCLASS64 {
		t.Fatal("dynamic fixture must use the supported 64-bit ABI")
	}
	offset := dynamic.ByteOrder.Uint64(data[32:40])
	entrySize := uint64(dynamic.ByteOrder.Uint16(data[54:56]))
	for i, program := range dynamic.Progs {
		if program.Type == elf.PT_INTERP {
			start := offset + uint64(i)*entrySize
			dynamic.ByteOrder.PutUint32(withoutInterpreter[start:start+4], uint32(elf.PT_NULL))
		}
	}
	for _, test := range []struct {
		name   string
		bytes  []byte
		reason string
	}{
		{"interpreter", data, "protected ELF interpreter dependencies are not qualified"},
		{"shared-library-without-interpreter", withoutInterpreter, "protected ELF shared-library dependencies are not qualified"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fd, err := unix.MemfdCreate("dynamic-fixture", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING|unix.MFD_EXEC)
			if err != nil {
				t.Fatal(err)
			}
			file := os.NewFile(uintptr(fd), "dynamic-fixture")
			defer file.Close()
			if _, err := file.Write(test.bytes); err != nil {
				t.Fatal(err)
			}
			image, err := sealAndVerify(context.Background(), file, hash(test.bytes), int64(len(test.bytes)))
			if image != nil || err == nil || err.Error() != test.reason {
				t.Fatalf("dynamic dependency refusal differs: %v", err)
			}
		})
	}
}
