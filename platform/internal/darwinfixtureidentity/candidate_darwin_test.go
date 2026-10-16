//go:build darwin && cgo && agentmux_bootstrap_docker && agentmux_darwin_identity_candidate

package darwinfixtureidentity

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const candidateGateMarker = "AGENTMUX_CANDIDATE_CHILD_GATE"
const candidateDeadlineMarker = "AGENTMUX_CANDIDATE_CHILD_DEADLINE"

// TestCandidateChildGate runs only as the exact child of these controls.
func TestCandidateChildGate(t *testing.T) {
	phase := os.Getenv(candidateGateMarker)
	if phase == "" {
		t.Skip("candidate_child_only")
	}
	if phase != "first" && phase != "second" {
		os.Exit(91)
	}
	deadline, err := strconv.ParseInt(os.Getenv(candidateDeadlineMarker), 10, 64)
	if err != nil {
		os.Exit(98)
	}
	remaining := time.Until(time.Unix(0, deadline))
	if remaining <= 0 || remaining > 15*time.Second {
		os.Exit(99)
	}
	// The inherited absolute deadline prevents exec from extending the lifetime.
	go func() { time.Sleep(remaining); os.Exit(92) }()
	gate := os.NewFile(3, "candidate-gate")
	if gate == nil {
		os.Exit(93)
	}
	defer func() {
		if gate.Close() != nil {
			os.Exit(100)
		}
	}()
	var command [1]byte
	for {
		n, err := gate.Read(command[:])
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil || n != 1 {
			os.Exit(94)
		}
		if command[0] != 'E' || phase != "first" {
			os.Exit(95)
		}
		if os.Setenv(candidateGateMarker, "second") != nil {
			os.Exit(96)
		}
		// ExtraFiles descriptors survive this exact exec; EOF remains cleanup.
		if syscall.Exec(os.Args[0], []string{os.Args[0], "-test.run=^TestCandidateChildGate$"}, os.Environ()) != nil {
			os.Exit(97)
		}
	}
}

func candidateRequire(t *testing.T) candidateEvidence {
	t.Helper()
	if os.Getuid() == 0 || os.Getuid() != os.Geteuid() {
		t.Fatal("candidate_creator_credentials_refused")
	}
	for _, item := range os.Environ() {
		if strings.HasPrefix(item, "DYLD_") {
			t.Fatal("candidate_loader_environment_refused")
		}
	}
	evidence, err := candidateProbeAdmission()
	if err != nil {
		t.Fatal("candidate_admission_refused")
	}
	return evidence
}

func TestCandidateNativeLayout(t *testing.T) {
	evidence := candidateRequire(t)
	if creator, err := NewCreator(); err == nil || creator != nil {
		t.Fatal("candidate_normal_creator_sdk27_accepted")
	}
	layout := evidence.layout
	t.Logf("candidate_layout bsd=%d unique=%d combined=%d unique_offset=%d version_offset=%d selector=%d returned=%d", layout.bsdSize, layout.uniqueSize, layout.combinedSize, layout.uniqueOffset, layout.versionOffset, layout.selector, layout.returnedSize)
}

type candidateChild struct {
	cmd                *exec.Cmd
	gate               *os.File
	id                 identity
	queue              int
	output, diagnostic capture
	waitStarted        bool
	done               chan error
	joined             bool
	waitErr            error
	expectedSignal     syscall.Signal
}

// candidateStart keeps the original child unreaped until every signal decision.
func candidateStart(t *testing.T) *candidateChild {
	t.Helper()
	candidateRequire(t)
	creator, err := observe(os.Getpid())
	if err != nil {
		t.Fatal("candidate_creator_observation_refused")
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal("candidate_gate_unavailable")
	}
	child := &candidateChild{gate: write, queue: -1}
	child.cmd = exec.Command(os.Args[0], "-test.run=^TestCandidateChildGate$")
	child.cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", candidateGateMarker + "=first", candidateDeadlineMarker + "=" + strconv.FormatInt(time.Now().Add(15*time.Second).UnixNano(), 10)}
	child.cmd.ExtraFiles = []*os.File{read}
	child.cmd.Stdout = &child.output
	child.cmd.Stderr = &child.diagnostic
	child.cmd.WaitDelay = time.Second
	if err := child.cmd.Start(); err != nil {
		if read.Close() != nil {
			t.Error("candidate_gate_read_close_failed")
		}
		if write.Close() != nil {
			t.Error("candidate_gate_write_close_failed")
		}
		t.Fatal("candidate_child_start_refused")
	}
	t.Cleanup(func() {
		if err := child.gate.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Error("candidate_gate_close_failed")
		}
		if !child.joined {
			child.join(t, child.expectedSignal)
		}
		if !child.joined {
			t.Error("candidate_unjoined_watch_retained")
			return
		}
		if child.queue >= 0 {
			if err := unix.Close(child.queue); err != nil {
				t.Error("candidate_watch_close_failed")
			}
		}
	})
	if err := read.Close(); err != nil {
		t.Fatal("candidate_gate_parent_read_close_failed")
	}
	before, err := observe(child.cmd.Process.Pid)
	now, creatorErr := observe(os.Getpid())
	if err != nil || creatorErr != nil || !sameIdentity(creator, now) || before.ParentPID != creator.PID || before.ParentUnique != creator.Unique || before.UID != creator.UID || before.RealUID != creator.RealUID {
		t.Fatal("candidate_child_lineage_refused")
	}
	child.id = before
	queue, err := unix.Kqueue()
	if err != nil {
		t.Fatal("candidate_watch_unavailable")
	}
	child.queue = queue
	unix.CloseOnExec(queue)
	change := []unix.Kevent_t{{Ident: uint64(before.PID), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD, Fflags: unix.NOTE_EXIT | unix.NOTE_EXEC}}
	var event [1]unix.Kevent_t
	zero := unix.Timespec{}
	n, err := unix.Kevent(queue, change, event[:], &zero)
	after, observationErr := observe(int(before.PID))
	if err != nil || n != 0 || observationErr != nil || !sameIdentity(before, after) {
		t.Fatal("candidate_watch_binding_refused")
	}
	return child
}

func (child *candidateChild) event(t *testing.T, wanted uint32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	read := func(wait time.Duration) (int, unix.Kevent_t, error) {
		var events [1]unix.Kevent_t
		timeout := unix.NsecToTimespec(int64(wait))
		n, err := unix.Kevent(child.queue, nil, events[:], &timeout)
		return n, events[0], err
	}
	event, interruptions, err := candidatePollEvent(read, time.Now, deadline)
	t.Logf("candidate_event_interruptions=%d", interruptions)
	if errors.Is(err, candidatePollDeadline) {
		t.Fatal("candidate_event_deadline")
	}
	if errors.Is(err, candidatePollCount) {
		t.Fatal("candidate_event_count_invalid")
	}
	if err != nil {
		t.Fatal(candidateEventErrorLabel(err))
	}
	if event.Ident != uint64(child.id.PID) || event.Filter != unix.EVFILT_PROC || event.Flags&unix.EV_ERROR != 0 || event.Fflags&wanted == 0 || event.Fflags&(unix.NOTE_EXIT|unix.NOTE_EXEC) != wanted {
		t.Fatal("candidate_event_refused")
	}
}

// Fixed labels preserve useful classification without native error text.
func candidateEventErrorLabel(err error) string {
	switch {
	case errors.Is(err, unix.EINTR):
		return "candidate_event_read_interrupted"
	case errors.Is(err, unix.EBADF):
		return "candidate_event_read_bad_descriptor"
	case errors.Is(err, unix.EINVAL):
		return "candidate_event_read_invalid_argument"
	case errors.Is(err, unix.EFAULT):
		return "candidate_event_read_invalid_buffer"
	case errors.Is(err, unix.ENOENT):
		return "candidate_event_read_missing_entry"
	case errors.Is(err, unix.ENOMEM):
		return "candidate_event_read_resource_failure"
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
		return "candidate_event_read_permission_refused"
	default:
		return "candidate_event_read_other_failure"
	}
}

func (child *candidateChild) join(t *testing.T, expected syscall.Signal) {
	t.Helper()
	if !child.waitStarted {
		child.waitStarted = true
		child.expectedSignal = expected
		child.done = make(chan error, 1)
		go func() { child.done <- child.cmd.Wait() }()
	}
	if !child.joined {
		select {
		case child.waitErr = <-child.done:
			child.joined = true
		case <-time.After(17 * time.Second):
			// Retain the same waiter and watch; cleanup retries this exact join.
			t.Error("candidate_join_incomplete")
			return
		}
	}
	if errors.Is(child.waitErr, exec.ErrWaitDelay) {
		t.Error("candidate_output_drain_incomplete")
	}
	if child.expectedSignal == 0 {
		if child.waitErr != nil {
			t.Error("candidate_cooperative_wait_failed")
		}
	} else {
		var exit *exec.ExitError
		if !errors.As(child.waitErr, &exit) {
			t.Error("candidate_signal_wait_missing")
			return
		}
		status, ok := exit.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != child.expectedSignal {
			t.Error("candidate_signal_wait_refused")
		}
	}
	output, diagnostic := child.output.snapshot(), child.diagnostic.snapshot()
	if output.Overflow || diagnostic.Overflow {
		t.Error("candidate_output_overflow")
	}
	if output.Err != nil || diagnostic.Err != nil {
		t.Error("candidate_output_capture_failed")
	}
}

func TestCandidateOwnedSignals(t *testing.T) {
	for _, signal := range []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL} {
		t.Run(signalLabel(signal), func(t *testing.T) {
			child := candidateStart(t)
			now, err := observe(int(child.id.PID))
			if err != nil || !sameIdentity(child.id, now) {
				t.Fatal("candidate_signal_identity_changed")
			}
			if err := identitySignal(child.id, int(signal)); err != nil {
				t.Fatal("candidate_owned_signal_refused")
			}
			child.event(t, unix.NOTE_EXIT)
			child.join(t, signal)
		})
	}
}
func signalLabel(signal syscall.Signal) string {
	if signal == syscall.SIGTERM {
		return "term"
	}
	return "kill"
}

func TestCandidateVersionRefusal(t *testing.T) {
	child := candidateStart(t)
	wrong := child.id
	wrong.Version ^= 2
	if wrong.Version == 0 {
		wrong.Version = child.id.Version ^ 4
	}
	if err := identitySignal(wrong, int(syscall.SIGTERM)); err == nil {
		t.Fatal("candidate_wrong_version_accepted")
	}
	var empty Proof
	if empty.Signal(0) == nil {
		t.Fatal("candidate_signal_zero_policy_accepted")
	}
	now, err := observe(int(child.id.PID))
	if err != nil || !sameIdentity(child.id, now) {
		t.Fatal("candidate_refusal_child_changed")
	}
	// Native signal zero is intentionally not called: helper policy refuses it.
	if err := child.gate.Close(); err != nil {
		t.Fatal("candidate_gate_close_failed")
	}
	child.event(t, unix.NOTE_EXIT)
	child.join(t, 0)
}

func TestCandidateExecInvalidation(t *testing.T) {
	child := candidateStart(t)
	if _, err := child.gate.Write([]byte{'E'}); err != nil {
		t.Fatal("candidate_exec_gate_failed")
	}
	child.event(t, unix.NOTE_EXEC)
	current, err := observe(int(child.id.PID))
	if err != nil || current.Unique != child.id.Unique || current.ParentUnique != child.id.ParentUnique || current.UID != child.id.UID || current.RealUID != child.id.RealUID || current.Version == child.id.Version {
		t.Fatal("candidate_exec_identity_refused")
	}
	if err := identitySignal(child.id, int(syscall.SIGTERM)); err == nil {
		t.Fatal("candidate_preexec_version_accepted")
	}
	after, err := observe(int(current.PID))
	if err != nil || !sameIdentity(current, after) {
		t.Fatal("candidate_exec_refusal_child_changed")
	}
	if err := child.gate.Close(); err != nil {
		t.Fatal("candidate_gate_close_failed")
	}
	child.event(t, unix.NOTE_EXIT)
	child.join(t, 0)
}
