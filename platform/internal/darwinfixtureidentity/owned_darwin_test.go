//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"bytes"
	"context"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestIdentityKeepsCreationLineageAfterReparenting(t *testing.T) {
	a := identity{PID: 7, ParentPID: 3, Version: 9, UID: 501, RealUID: 501, Unique: 55, ParentUnique: 44}
	b := a
	b.ParentPID = 1
	if !sameIdentity(a, b) {
		t.Fatal("reparenting discarded creation identity")
	}
	for _, mutate := range []func(*identity){func(x *identity) { x.PID++ }, func(x *identity) { x.Version++ }, func(x *identity) { x.Unique++ }, func(x *identity) { x.ParentUnique++ }, func(x *identity) { x.UID++ }, func(x *identity) { x.RealUID++ }} {
		b = a
		mutate(&b)
		if sameIdentity(a, b) {
			t.Fatal("changed authority admitted")
		}
	}
}
func TestZeroProofAndSignalRefusals(t *testing.T) {
	for _, p := range []*Proof{nil, {}} {
		if p.Live() == nil {
			t.Fatal("zero proof live")
		}
		for _, s := range []syscall.Signal{0, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL} {
			if p.Signal(s) == nil {
				t.Fatal("zero proof signalled")
			}
		}
		if p.LiteralArgs() != nil {
			t.Fatal("zero proof exposed arguments")
		}
	}
}

func TestCaptureBoundsAndCopies(t *testing.T) {
	c := capture{}
	input := bytes.Repeat([]byte("x"), 70*1024)
	n, err := c.Write(input)
	if n != len(input) || err != nil {
		t.Fatal("capture stopped pipe drain")
	}
	got := c.snapshot()
	if len(got.Bytes) != 64*1024 || !got.Overflow || got.Err != nil {
		t.Fatal("capture boundary or sink error lost")
	}
	got.Bytes[0] = 'z'
	if c.snapshot().Bytes[0] != 'x' {
		t.Fatal("capture buffer escaped")
	}
}
func TestRosterRequiresCompleteStableIdentities(t *testing.T) {
	a := []identity{{PID: 1, Unique: 4, Version: 2}, {PID: 2, Unique: 5, Version: 3}}
	if !sameRoster(a, []identity{a[1], a[0]}) || sameRoster(a, a[:1]) {
		t.Fatal("roster mismatch")
	}
	b := append([]identity(nil), a...)
	b[1].Version++
	if sameRoster(a, b) {
		t.Fatal("changed identity admitted")
	}
}
func TestProofLiteralArgsAreCopied(t *testing.T) {
	p := &Proof{proofState: &proofState{valid: true, expected: expectedImage{Path: "/protected/example", Args: []string{"host"}}}}
	args := p.LiteralArgs()
	args[1] = "changed"
	if p.LiteralArgs()[1] != "host" {
		t.Fatal("literal args escaped")
	}
}

func TestCopiedProofSharesConsumption(t *testing.T) {
	p := &Proof{proofState: &proofState{valid: true}}
	copyHandle := *p
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if copyHandle.Live() == nil {
		t.Fatal("copy retained authority after close")
	}
	if err := copyHandle.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestClosedHostInvocationGrammar(t *testing.T) {
	host := &ExpectedHost{Path: "/protected/example", Digest: "sha256:unused", PolicyPath: "/private/policy", WorkspaceRoots: []string{"/workspace"}}
	item := expectedImage{Path: host.Path, Digest: host.Digest, host: host}
	args := []string{host.Path, "host", "--host-policy", host.PolicyPath, "--invocation-id", "attempt_0123456789abcdef0123456789abcdef", "--workspace", "/workspace"}
	if !matchesArguments(item, host.Path, args) {
		t.Fatal("valid fixed host grammar refused")
	}
	for i := range args {
		changed := append([]string(nil), args...)
		changed[i] = "unexpected"
		if matchesArguments(item, host.Path, changed) {
			t.Fatal("changed grammar admitted")
		}
	}
	if matchesArguments(item, host.Path, append(args, "--extra")) {
		t.Fatal("extra argument admitted")
	}
}

func TestWatchPollInterruptionsStayBoundedAndFailClosed(t *testing.T) {
	calls := 0
	n, err := pollWatch(func() (int, error) { calls++; return 0, syscall.EINTR })
	if calls != 3 || n != 0 || err != syscall.EINTR {
		t.Fatal("interruption budget changed observation outcome")
	}
	calls = 0
	n, err = pollWatch(func() (int, error) { calls++; return 0, syscall.EBADF })
	if calls != 1 || n != 0 || err != syscall.EBADF {
		t.Fatal("hard failure was retried or hidden")
	}
	calls = 0
	n, err = pollWatch(func() (int, error) {
		calls++
		if calls < 3 {
			return 0, syscall.EINTR
		}
		return 1, nil
	})
	if calls != 3 || n != 1 || err != nil {
		t.Fatal("actual event was not retained")
	}
}

func TestClosedHostGrammarSupportsSixteenRoots(t *testing.T) {
	host := &ExpectedHost{Path: "/protected/example", PolicyPath: "/policy"}
	args := []string{host.Path, "host", "--host-policy", host.PolicyPath, "--invocation-id", "attempt_0123456789abcdef0123456789abcdef"}
	for i := 0; i < 16; i++ {
		root := "/workspace/" + string(rune('a'+i))
		host.WorkspaceRoots = append(host.WorkspaceRoots, root)
		args = append(args, "--workspace", root)
	}
	if len(args) != 38 || !matchesArguments(expectedImage{Path: host.Path, host: host}, host.Path, args) {
		t.Fatal("sixteen-root invocation refused")
	}
}

func TestCompletedCommandDoesNotGainFailedAdmissionAuthority(t *testing.T) {
	refused := failed("fixture_saved_admission_refusal", nil)
	done := make(chan struct{})
	close(done)
	x := &Owned{ownedState: &ownedState{admissionErr: refused, cmd: &exec.Cmd{}, done: done, waiting: true, completion: Completion{At: time.Unix(3, 0), Stdout: Output{Bytes: []byte("completed")}}}}
	result, err := x.Join(context.Background())
	if err != nil || result.Err != nil || string(result.Stdout.Bytes) != "completed" {
		t.Fatal("completion was rewritten as admission failure")
	}
	if proof, err := x.Pin(context.Background()); proof != nil || err != refused {
		t.Fatal("completed command gained false proof")
	}
	if x.Signal(syscall.SIGTERM) == nil {
		t.Fatal("failed minimal admission gained cleanup authority")
	}
	result.Stdout.Bytes[0] = 'x'
	again, err := x.Join(context.Background())
	if err != nil || string(again.Stdout.Bytes) != "completed" {
		t.Fatal("completion capture escaped")
	}
}
