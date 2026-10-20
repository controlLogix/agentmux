//go:build darwin && arm64 && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	protected "github.com/controlLogix/agentmux/platform/runtime"
)

// Both children belong to the original Python Popen. The controlled case holds
// its pre-exec phase; the unmodified case observes start_new_session=True alone.
// Neither case contacts a broker or admits the observed child as a runtime.
const ownedPythonForkProbe = `import os, signal, subprocess, sys
def interrupted(*args):
    raise KeyboardInterrupt()
signal.signal(signal.SIGTERM, interrupted)
child = None
try:
    if sys.stdin.buffer.read(1) != b'S':
        raise SystemExit(2)
    options = dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, start_new_session=True)
    if sys.argv[1] == 'controlled':
        def before_exec():
            os.read(3, 1)
            os.close(3)
        options.update(preexec_fn=before_exec, pass_fds=(3,))
    child = subprocess.Popen(['/bin/sleep', '0.25'], **options)
    sys.stdin.buffer.read(1)
    child.wait(timeout=2)
finally:
    if child is not None:
        if child.poll() is None:
            child.terminate()
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
    if sys.argv[1] == 'controlled':
        os.close(3)
`

func TestInstalledPythonOwnedPopenRosterProbe(t *testing.T) {
	if os.Getenv("AMX_DARWIN_PYTHON_FORK_PROBE_AUTHORIZED") != "1" {
		t.Fatal("serialized native process probe authorization required")
	}
	id := os.Getenv("AMX_INSTALLED_CLIENT_ID")
	if !protected.ValidClientInstallationID(id) {
		t.Fatal("explicit installed client ID required")
	}
	for _, mode := range []string{"controlled", "unmodified"} {
		t.Run(mode, func(t *testing.T) { ownedPythonRosterProbe(t, id, mode) })
	}
}

func ownedPythonRosterProbe(t *testing.T, id, mode string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	admission, err := protected.PrepareInstalledClient(ctx, id)
	if err != nil {
		t.Fatal("protected Python package admission refused")
	}
	defer func() {
		if admission.Close() != nil {
			t.Error("protected Python package ownership did not close")
		}
	}()
	creator, err := NewCreator()
	if err != nil {
		t.Fatal("native observer admission refused")
	}
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal("original Python input pipe unavailable")
	}
	gate, release, err := os.Pipe()
	if err != nil {
		input.Close()
		writer.Close()
		t.Fatal("owned pre-exec gate unavailable")
	}
	inputOpen, gateOpen, writerOpen, releaseOpen := true, true, true, true
	defer func() {
		for _, item := range []struct {
			file *os.File
			open *bool
		}{{input, &inputOpen}, {gate, &gateOpen}, {writer, &writerOpen}, {release, &releaseOpen}} {
			if *item.open {
				*item.open = false
				if item.file.Close() != nil {
					t.Error("owned probe descriptor did not close")
				}
			}
		}
	}()
	interpreter := filepath.Join(protected.InstalledClientBase, id, protected.ClientInterpreter)
	args := []string{"-I", "-S", "-c", ownedPythonForkProbe, mode}
	cmd := exec.Command(interpreter, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=en_US.UTF-8", "LC_CTYPE=UTF-8"}
	cmd.Dir = "/"
	cmd.Stdin = input
	cmd.WaitDelay = time.Second
	var out, errout capture
	cmd.Stdout = &out
	cmd.Stderr = &errout
	if mode == "controlled" {
		cmd.ExtraFiles = []*os.File{gate}
	}
	if admission.Recheck(ctx) != nil {
		t.Fatal("protected Python package changed before original spawn")
	}
	if cmd.Start() != nil {
		t.Fatal("original Python process creation refused")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	// Original command and both output-reader owners remain in scope until this
	// cleanup joins. No observed child PID is ever used to send a signal.
	defer func() {
		if releaseOpen {
			releaseOpen = false
			if release.Close() != nil {
				t.Error("pre-exec gate release failed")
			}
		}
		if writerOpen {
			writerOpen = false
			if writer.Close() != nil {
				t.Error("original Python input close failed")
			}
		}
		select {
		case err := <-done:
			if err != nil {
				t.Error("original Python process or output join failed")
			}
		case <-time.After(5 * time.Second):
			t.Error("original Python process remains owned; probe cleanup incomplete")
			// Do not return and abandon an unreaped original owner. The bounded
			// observation already failed; final exit still joins this exact wait.
			<-done
		}
		if out.snapshot().Overflow || errout.snapshot().Overflow {
			t.Error("original probe output exceeded its capture bound")
		}
	}()
	inputOpen = false
	if input.Close() != nil {
		t.Fatal("parent input descriptor close failed")
	}
	gateOpen = false
	if gate.Close() != nil {
		t.Fatal("parent pre-exec gate descriptor close failed")
	}
	parent, err := observe(cmd.Process.Pid)
	if err != nil || parent.ParentUnique != creator.self.Unique || parent.ParentPID != creator.self.PID {
		t.Fatal("original Python creation ancestry refused")
	}
	parentExpected := expectedImage{Path: interpreter, Args: append([]string(nil), args...)}
	anchor := &Proof{proofState: &proofState{expected: parentExpected}}
	want := expectedImage{Path: "/bin/sleep", Args: []string{"0.25"}}
	if writer.SetWriteDeadline(time.Now().Add(time.Second)) != nil {
		t.Fatal("original Python input deadline unavailable")
	}
	if n, err := writer.Write([]byte{'S'}); err != nil || n != 1 {
		t.Fatal("original Python start frame failed")
	}
	var beforeExec *identity
	var transition *childExecTransition
	var comparisons []ChildRosterDiagnostic
	postExec, creationStable, scanFailures := false, false, 0
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		now, e := observe(int(parent.PID))
		if e != nil || !sameIdentity(parent, now) {
			t.Fatal("original Python anchor changed during read-only probe")
		}
		children, e := nativeCandidates(parent.UID, parent.Unique, creator.admission)
		if e != nil {
			scanFailures++
			continue
		}
		if len(children) > 1 {
			t.Fatal("probe direct-child roster exceeded its single original Popen")
		}
		if transition != nil && transition.checkRoster(children) != nil {
			t.Fatal("probe replaced its original fork/exec creation roster")
		}
		for _, child := range children {
			if transition == nil {
				transition = &childExecTransition{anchor: anchor, original: child, target: want}
			}
			path, pe := nativePath(child)
			actual, ae := nativeArguments(child)
			after, ie := observe(int(child.PID))
			if pe != nil || ae != nil || ie != nil || !sameIdentity(child, after) {
				scanFailures++
				continue
			}
			ready, transitionErr := transition.ready(child, after, path, actual, nil, nil, nil)
			if transitionErr != nil {
				t.Fatal("original fork/exec transition was refused")
			}
			if ready {
				postExec = true
				creationStable = beforeExec != nil && sameCreation(*beforeExec, child)
				break
			}
			if len(comparisons) < 8 {
				comparisons = append(comparisons, ChildRosterDiagnostics(childRosterMismatch(anchor, []expectedImage{want}, path, actual, -1))...)
			}
			if path == interpreter && matchesArguments(parentExpected, path, actual) {
				copy := child
				beforeExec = &copy
				if releaseOpen {
					releaseOpen = false
					if release.Close() != nil {
						t.Fatal("owned pre-exec release failed")
					}
				}
			}
		}
		if postExec {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !postExec {
		t.Fatal("expected exec target was not observed within the fixed probe budget")
	}
	if mode == "controlled" && (beforeExec == nil || !creationStable) {
		t.Fatal("controlled fork/exec did not retain its exact creation ancestry")
	}
	raw, _ := json.Marshal(map[string]any{"mode": mode, "preExecObserved": beforeExec != nil, "postExecObserved": postExec, "sameCreationAcrossExec": creationStable, "scanFailures": scanFailures, "comparisons": comparisons, "authorityGranted": false})
	t.Log(string(raw))
}
