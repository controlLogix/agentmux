//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"errors"
	"io"
	"os/exec"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func TestChildWatchRegistrationClassifiesWithoutGrantingExit(t *testing.T) {
	id := identity{PID: 90, Unique: 190, Version: 4}
	exit := unix.Kevent_t{Ident: 90, Filter: unix.EVFILT_PROC, Fflags: unix.NOTE_EXIT}
	for _, test := range []struct {
		name     string
		count    int
		event    unix.Kevent_t
		err      error
		category string
		errno    string
	}{
		{"receipt", 1, unix.Kevent_t{Ident: 90, Filter: unix.EVFILT_PROC, Flags: unix.EV_ERROR | unix.EV_RECEIPT, Fflags: unix.NOTE_EXIT | unix.NOTE_EXEC}, nil, "", ""},
		{"missing receipt", 0, exit, nil, "fixture_watch_registration_unexpected", ""},
		{"syscall", 0, unix.Kevent_t{}, unix.EINTR, "fixture_watch_registration_syscall", "fixture_watch_registration_errno_eintr"},
		{"unknown syscall", 1, exit, unknownDiagnosticFailure{}, "fixture_watch_registration_syscall", "fixture_watch_registration_errno_unclassified"},
		{"event error", 1, unix.Kevent_t{Ident: 90, Filter: unix.EVFILT_PROC, Flags: unix.EV_ERROR, Data: int64(unix.ESRCH)}, nil, "fixture_watch_registration_ev_error", "fixture_watch_registration_errno_esrch"},
		{"event error without errno", 1, unix.Kevent_t{Ident: 90, Filter: unix.EVFILT_PROC, Flags: unix.EV_ERROR}, nil, "fixture_watch_registration_ev_error", "fixture_watch_registration_errno_unavailable"},
		{"event error invalid errno", 1, unix.Kevent_t{Ident: 90, Filter: unix.EVFILT_PROC, Flags: unix.EV_ERROR, Data: -1}, nil, "fixture_watch_registration_ev_error", "fixture_watch_registration_errno_unavailable"},
		{"exit", 1, exit, nil, "fixture_watch_registration_exit", ""},
		{"exec", 1, unix.Kevent_t{Ident: 90, Filter: unix.EVFILT_PROC, Fflags: unix.NOTE_EXEC}, nil, "fixture_watch_registration_exec", ""},
		{"exit and exec", 1, unix.Kevent_t{Ident: 90, Filter: unix.EVFILT_PROC, Fflags: unix.NOTE_EXIT | unix.NOTE_EXEC}, nil, "fixture_watch_registration_exec", ""},
		{"foreign process", 1, unix.Kevent_t{Ident: 91, Filter: unix.EVFILT_PROC, Flags: unix.EV_ERROR, Data: int64(unix.ESRCH)}, nil, "fixture_watch_registration_unexpected", ""},
		{"other filter", 1, unix.Kevent_t{Ident: 90, Filter: unix.EVFILT_READ, Fflags: unix.NOTE_EXIT}, nil, "fixture_watch_registration_unexpected", ""},
		{"empty event", 1, unix.Kevent_t{}, nil, "fixture_watch_registration_unexpected", ""},
		{"invalid count", 2, exit, nil, "fixture_watch_registration_unexpected", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := childWatchRegistrationResult(id, test.count, test.event, test.err)
			if test.category == "" {
				if err != nil {
					t.Fatal("successful registration receipt refused")
				}
				return
			}
			want := []string{"fixture_child_watch_registration_refused", test.category}
			if test.errno != "" {
				want = append(want, test.errno)
			}
			if !reflect.DeepEqual(FailureCategories(err), want) {
				t.Fatal("registration lost its closed category or inspected an unknown error")
			}
			outer, ok := err.(*failure)
			if !ok {
				t.Fatal("registration failure owner missing")
			}
			owner, ok := outer.retained.(*watchRegistrationObservation)
			if !ok || owner.id != id || owner.count != test.count || owner.event != test.event || owner.syscallError != test.err {
				t.Fatal("private original registration observation lost")
			}
			if nativeIdentityQueryAbsent(err) || inspectionQueryDisappeared(err) || err == ErrExited {
				t.Fatal("unbound registration event granted absence or exit authority")
			}
		})
	}
}

func TestChildWatchRegistrationKeepsPrivateErrnoCause(t *testing.T) {
	id := identity{PID: 90}
	for _, errno := range []unix.Errno{unix.ESRCH, unix.EPERM, unix.EACCES, unix.EINVAL, unix.EINTR, unix.EBADF, unix.EIO, unix.ENOMEM, unix.ENOENT, unix.ENOTSUP, unix.ENOSYS, unix.EPIPE} {
		for _, syscall := range []bool{true, false} {
			count, event, cause := 0, unix.Kevent_t{}, error(errno)
			if !syscall {
				count, event, cause = 1, unix.Kevent_t{Ident: 90, Filter: unix.EVFILT_PROC, Flags: unix.EV_ERROR, Data: int64(errno)}, nil
			}
			err := childWatchRegistrationResult(id, count, event, cause)
			if !errors.Is(err, errno) {
				t.Fatal("original syscall or event errno lost")
			}
		}
	}
	if got := FailureCategories(failed("fixture_child_watch_registration_refused", unknownDiagnosticFailure{})); !reflect.DeepEqual(got, []string{"fixture_child_watch_registration_refused"}) {
		t.Fatal("legacy unknown registration cause was inspected or invented")
	}
}

func TestInspectionObservationCloseSeparatesAdmissionAndDisposal(t *testing.T) {
	admission := childWatchRegistrationResult(identity{PID: 90}, 1, unix.Kevent_t{Ident: 90, Filter: unix.EVFILT_PROC, Fflags: unix.NOTE_EXEC}, nil)
	for _, closeFails := range []bool{false, true} {
		o := &inspectionObservation{id: identity{PID: 90}, queue: 42, owned: true, failure: admission}
		calls := 0
		closeError := unknownDiagnosticFailure{}
		cleanup := o.closeWith(func(queue int) error {
			calls++
			if queue != 42 {
				t.Fatal("original observation descriptor replaced")
			}
			if closeFails {
				return closeError
			}
			return nil
		})
		if calls != 1 || !o.closed || o.bound || o.exited || o.failure != admission || (closeFails != (cleanup != nil)) {
			t.Fatal("observation disposal altered original admission or claimed exit")
		}
		if again := o.closeWith(func(int) error { t.Fatal("retried consumed close and risked a reused descriptor"); return nil }); again != cleanup {
			t.Fatal("original close outcome changed")
		}
		if closeFails {
			retained, ok := cleanup.(*failure)
			if !ok || retained.retained != o || retained.cause != closeError || !reflect.DeepEqual(FailureCategories(cleanup), []string{"fixture_watch_close_failed"}) {
				t.Fatal("close uncertainty lost its owner or exposed private cause")
			}
		}
	}
}

func TestInspectionScanDisposesFailedObservationWithoutDiscardingProofs(t *testing.T) {
	queue, err := unix.Kqueue()
	if err != nil {
		t.Fatal("observation queue setup failed")
	}
	admission := childWatchRegistrationResult(identity{PID: 90}, 1, unix.Kevent_t{Ident: 90, Filter: unix.EVFILT_PROC, Flags: unix.EV_ERROR, Data: int64(unix.ESRCH)}, nil)
	observation := &inspectionObservation{queue: queue, owned: true, failure: admission}
	t.Cleanup(func() { _ = observation.close() })
	proofQueue, err := unix.Kqueue()
	if err != nil {
		t.Fatal("retained proof queue setup failed")
	}
	partial := &Proof{proofState: &proofState{queue: proofQueue, watchOwned: true}}
	t.Cleanup(func() { _ = partial.Close() })
	transferred := &inspectionObservation{queue: proofQueue, owned: true, bound: true, transferred: true}
	state := &inspectionRosterOwner{observations: []*inspectionObservation{observation, transferred}, proofs: []*Proof{partial}}
	roles, result := state.finishScan(nil, admission)
	if roles != nil || result != admission || observation.failure != admission || observation.cleanup != nil || !observation.closed || observation.exited || transferred.closed || partial.closed || len(state.proofs) != 1 || state.proofs[0] != partial {
		t.Fatal("failed observation cleanup changed refusal or discarded a retained proof")
	}
	zero := unix.Timespec{}
	if _, err := unix.Kevent(queue, nil, nil, &zero); err != unix.EBADF {
		t.Fatal("failed admission leaked its original observation queue")
	}
	if _, err := unix.Kevent(proofQueue, nil, nil, &zero); err != nil {
		t.Fatal("observation cleanup consumed transferred or partial proof queue")
	}
	parent := &Proof{proofState: &proofState{auxiliary: []any{state}}}
	if err := parent.Close(); err != nil || partial.closed || transferred.closed {
		t.Fatal("parent cleanup discarded a retained process proof")
	}
}

func TestInspectionParentCloseDrainsAuxiliaryObservationOnce(t *testing.T) {
	queue, err := unix.Kqueue()
	if err != nil {
		t.Fatal("observation queue setup failed")
	}
	admission := failed("fixture_inspection_watch_identity_refused", unix.ESRCH)
	o := &inspectionObservation{queue: queue, owned: true, failure: admission}
	t.Cleanup(func() { _ = o.close() })
	parent := &Proof{proofState: &proofState{auxiliary: []any{&inspectionRosterOwner{observations: []*inspectionObservation{o}}}}}
	if err := parent.Close(); err != nil || !o.closed || o.failure != admission {
		t.Fatal("parent close confused admission failure with queue disposal")
	}
	if err := parent.Close(); err != nil {
		t.Fatal("parent close repeated original observation disposal")
	}
	zero := unix.Timespec{}
	if _, err := unix.Kevent(queue, nil, nil, &zero); err != unix.EBADF {
		t.Fatal("parent close leaked auxiliary observation queue")
	}
}

func TestInspectionCloseUncertaintyPreservesAdmissionAndRefusesRoster(t *testing.T) {
	admission := failed("fixture_inspection_watch_identity_refused", unix.ESRCH)
	o := &inspectionObservation{queue: 42, owned: true, failure: admission}
	closeError := unix.EIO
	cleanup := o.closeWith(func(int) error { return closeError })
	state := &inspectionRosterOwner{observations: []*inspectionObservation{o}}
	roles, err := state.finishScan([]identity{{PID: 90}}, admission)
	if roles != nil || !errors.Is(err, admission) || !errors.Is(err, closeError) || o.failure != admission || o.cleanup != cleanup {
		t.Fatal("uncertain close admitted a roster or erased original admission failure")
	}
	retained, ok := err.(*failure)
	if !ok || retained.retained != state {
		t.Fatal("uncertain observation owner lost")
	}
	parent := &Proof{proofState: &proofState{queue: -1, watchOwned: true, auxiliary: []any{state}}}
	err = parent.Close()
	if !errors.Is(err, closeError) || !errors.Is(err, unix.EBADF) || parent.Close() != err {
		t.Fatal("parent close lost auxiliary close uncertainty or changed original close results")
	}
}

func TestInspectionTerminalCloseFailureIsNotAnAdmissionFailure(t *testing.T) {
	id := identity{PID: 90, Unique: 190, Version: 4}
	o := &inspectionObservation{id: id, queue: -1, owned: true, bound: true, exited: true}
	parent := &Proof{}
	result, err := parent.pinWatchedInspection(inspectionTestBudget(t), id, inspectionChildClass{role: -1, target: expectedImage{inspection: &InspectionSelection{}}, observation: o})
	if !errors.Is(err, unix.EBADF) || result.proof != nil || o.failure != nil || o.cleanup == nil || terminalInspectionObservation(id, o) {
		t.Fatal("terminal close uncertainty became admission failure or completed disposal")
	}
}

func TestProcessWatchReceiptPreservesExitEvent(t *testing.T) {
	command := exec.Command("/bin/cat")
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal("owned child input unavailable")
	}
	output, err := command.StdoutPipe()
	if err != nil {
		input.Close()
		t.Fatal("owned child output unavailable")
	}
	if err = command.Start(); err != nil {
		input.Close()
		t.Fatal("owned child unavailable")
	}
	waited := false
	defer func() {
		input.Close()
		if !waited {
			if command.Wait() != nil {
				t.Error("original child wait failed")
			}
		}
	}()
	if _, err := input.Write([]byte("ready\n")); err != nil {
		t.Fatal("child readiness write failed")
	}
	ready := make([]byte, 6)
	if _, err := io.ReadFull(output, ready); err != nil || string(ready) != "ready\n" {
		t.Fatal("child did not finish exec")
	}
	// This checks kernel queue semantics; native identity admission is tested separately.
	id := identity{PID: int32(command.Process.Pid)}
	queue, err := unix.Kqueue()
	if err != nil {
		t.Fatal("watch queue unavailable")
	}
	defer unix.Close(queue)
	if err := registerProcessWatch(queue, id); err != nil {
		t.Fatalf("registration receipt refused: %v", FailureCategories(err))
	}
	var events [1]unix.Kevent_t
	zero := unix.Timespec{}
	count, err := pollWatch(func() (int, error) { return unix.Kevent(queue, nil, events[:], &zero) })
	if err != nil || count != 0 {
		t.Fatal("registration fabricated a process event")
	}
	if input.Close() != nil {
		t.Fatal("child input close failed")
	}
	err = command.Wait()
	waited = true
	if err != nil {
		t.Fatal("original child wait failed")
	}
	count, err = pollWatch(func() (int, error) { return unix.Kevent(queue, nil, events[:], &zero) })
	if err != nil || count != 1 || !exactProcessExit(id, events[0]) {
		t.Fatal("registration lost the original child exit event")
	}
}
