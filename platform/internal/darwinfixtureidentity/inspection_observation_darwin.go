//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"context"
	"errors"
	"reflect"

	"golang.org/x/sys/unix"
)

// An observation owns only an exit/exec watch. It cannot signal a process or
// stand in for an admitted image, arguments, role, wait or output reader.
type inspectionObservation struct {
	id                                        identity
	queue                                     int
	owned, bound, exited, closed, transferred bool
	failure                                   error
	cleanup                                   error
}

func bindInspectionObservation(candidate identity, retain func(*inspectionObservation)) (o *inspectionObservation, resultErr error) {
	o = &inspectionObservation{id: candidate}
	retain(o)
	defer func() {
		if resultErr != nil {
			o.failure = resultErr
		}
	}()
	before, err := observe(int(candidate.PID))
	if err != nil || !sameIdentity(candidate, before) {
		return o, failed("fixture_inspection_watch_identity_refused", err)
	}
	queue, err := unix.Kqueue()
	if err != nil {
		return o, failed("fixture_child_watch_unavailable", err)
	}
	o.queue, o.owned = queue, true
	unix.CloseOnExec(queue)
	if registrationErr := registerProcessWatch(queue, candidate); registrationErr != nil {
		return o, registrationErr
	}
	// An exit cannot excuse a failed binding query: the watch must first be
	// tied to this same native identity on both sides of registration.
	after, err := observe(int(candidate.PID))
	if err != nil || !sameIdentity(candidate, after) {
		return o, failed("fixture_inspection_watch_identity_refused", err)
	}
	o.bound = true
	return o, nil
}

func exactProcessExit(id identity, event unix.Kevent_t) bool {
	return event.Ident == uint64(id.PID) && event.Filter == unix.EVFILT_PROC && event.Flags&unix.EV_ERROR == 0 && event.Fflags&unix.NOTE_EXIT != 0 && event.Fflags&unix.NOTE_EXEC == 0
}

func (o *inspectionObservation) poll() (bool, error) {
	if o == nil || !o.bound || o.closed || o.transferred {
		return false, failed("fixture_inspection_watch_invalid", nil)
	}
	if o.failure != nil {
		return false, o.failure
	}
	if o.exited {
		return true, nil
	}
	var events [1]unix.Kevent_t
	zero := unix.Timespec{}
	n, err := pollWatch(func() (int, error) { return unix.Kevent(o.queue, nil, events[:], &zero) })
	if err != nil {
		o.failure = failed("fixture_watch_failed", err)
	} else if n != 0 {
		if n == 1 && exactProcessExit(o.id, events[0]) {
			o.exited = true
		} else {
			o.failure = failed("fixture_unexpected_process_event", nil)
		}
	}
	return o.exited, o.failure
}

func (o *inspectionObservation) close() error {
	return o.closeWith(unix.Close)
}

// This releases only the observation descriptor, not an admitted process owner.
// Keep its close outcome separate from any original admission failure.
func (o *inspectionObservation) closeWith(closeQueue func(int) error) error {
	if o == nil {
		return nil
	}
	if o.closed || o.transferred {
		return o.cleanup
	}
	o.closed = true
	if o.owned {
		if err := closeQueue(o.queue); err != nil {
			o.cleanup = &failure{stage: "fixture_watch_close_failed", cause: err, retained: o}
		}
	}
	return o.cleanup
}

// Only these native query boundaries can report process disappearance. Never
// call Error, Is or Unwrap on an unknown cause to decide whether to discharge it.
func inspectionQueryDisappeared(cause error) bool {
	known, ok := cause.(*failure)
	if !ok || known == nil {
		return false
	}
	switch known.stage {
	case "fixture_native_query_refused", "fixture_arguments_query_refused", "version_bound_image_path_unavailable":
		errno, ok := known.cause.(unix.Errno)
		return ok && errno == unix.ESRCH
	}
	return false
}

// A known ESRCH may have occurred between the preceding poll and query. One
// check of the same bound watch can establish exact exit, never admission.
// Absence of that event, exec, watch errors and unknown query errors still refuse.
func finishInspectionQueryFailure(ctx context.Context, cause error, poll func() (bool, error)) (bool, error) {
	if !inspectionQueryDisappeared(cause) {
		return false, cause
	}
	if err := ctx.Err(); err != nil {
		return false, errors.Join(cause, err)
	}
	exited, err := poll()
	if err != nil {
		return false, errors.Join(cause, err)
	}
	if exited {
		return true, nil
	}
	return false, cause
}

// Check the original watch before every query and once after a recognized
// disappearance. No query is retried and a terminal result grants no proof.
func readWatchedInspection(ctx context.Context, candidate identity, poll func() (bool, error), readID func(int) (identity, error), readPath func(identity) (string, error), readArgs func(identity) ([]string, error)) (path string, args []string, terminal bool, result error) {
	check := func() (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		return poll()
	}
	if terminal, result = check(); terminal || result != nil {
		return
	}
	before, err := readID(int(candidate.PID))
	if err != nil || !sameIdentity(candidate, before) {
		terminal, result = finishInspectionQueryFailure(ctx, err, poll)
		if !terminal {
			result = failed("fixture_inspection_identity_refused", result)
		}
		return "", nil, terminal, result
	}
	if terminal, result = check(); terminal || result != nil {
		return
	}
	path, err = readPath(before)
	if err != nil {
		terminal, result = finishInspectionQueryFailure(ctx, err, poll)
		if !terminal {
			result = failed("fixture_inspection_path_refused", result)
		}
		return "", nil, terminal, result
	}
	if terminal, result = check(); terminal || result != nil {
		return
	}
	args, err = readArgs(before)
	if err != nil {
		terminal, result = finishInspectionQueryFailure(ctx, err, poll)
		if !terminal {
			result = failed("fixture_inspection_arguments_refused", result)
		}
		return "", nil, terminal, result
	}
	if terminal, result = check(); terminal || result != nil {
		return
	}
	after, err := readID(int(candidate.PID))
	if err != nil || !sameIdentity(candidate, after) {
		terminal, result = finishInspectionQueryFailure(ctx, err, poll)
		if !terminal {
			result = failed("fixture_inspection_identity_refused", result)
		}
		return "", nil, terminal, result
	}
	terminal, result = check()
	return
}

func (o *inspectionObservation) read(ctx context.Context) (string, []string, bool, error) {
	path, args, terminal, err := readWatchedInspection(ctx, o.id, o.poll, observe, nativePath, nativeArguments)
	if err != nil {
		o.failure = err
	}
	return path, args, terminal, err
}

type inspectionPinResult struct {
	proof    *Proof
	terminal bool
}

// Transfer the original watch only after the selected image and literal argv
// have been checked again. Exact exit before completion grants no proof.
func (p *Proof) pinWatchedInspection(ctx context.Context, candidate identity, class inspectionChildClass) (result inspectionPinResult, resultErr error) {
	o, item := class.observation, class.target
	defer func() {
		if resultErr != nil && o != nil && resultErr != o.cleanup {
			o.failure = errors.Join(o.failure, resultErr)
		}
	}()
	if o == nil || !sameIdentity(o.id, candidate) || item.inspection == nil {
		return inspectionPinResult{}, failed("fixture_inspection_watch_invalid", nil)
	}
	terminal, err := o.poll()
	if err != nil {
		return inspectionPinResult{}, err
	}
	if !terminal {
		if err := item.inspection.recheck(ctx); err != nil {
			return inspectionPinResult{}, err
		}
		path, args, exited, err := o.read(ctx)
		if err != nil {
			return inspectionPinResult{}, err
		}
		terminal = exited
		if !terminal && (path != item.Path || !reflect.DeepEqual(args, item.literalArguments())) {
			return inspectionPinResult{}, failed("fixture_inspection_postwatch_admission_refused", nil)
		}
	}
	if !terminal {
		if err := item.inspection.recheck(ctx); err != nil {
			return inspectionPinResult{}, err
		}
		if err := ctx.Err(); err != nil {
			return inspectionPinResult{}, err
		}
		terminal, err = o.poll()
		if err != nil {
			return inspectionPinResult{}, err
		}
		if !terminal {
			after, err := observe(int(candidate.PID))
			if err != nil || !sameIdentity(candidate, after) {
				terminal, err = finishInspectionQueryFailure(ctx, err, o.poll)
				if !terminal {
					return inspectionPinResult{}, failed("fixture_inspection_identity_refused", err)
				}
			}
			terminal, err = o.poll()
			if err != nil {
				return inspectionPinResult{}, err
			}
		}
	}
	if terminal {
		return inspectionPinResult{terminal: true}, o.close()
	}
	item.inspection.retain()
	child := &Proof{proofState: &proofState{id: candidate, queue: o.queue, watchOwned: true, expected: expectedImage{Path: item.Path, Digest: item.Digest, argv0: item.argv0, Args: append([]string(nil), item.Args...)}, image: item.inspection, admission: p.admission, valid: true}}
	o.transferred = true
	return inspectionPinResult{proof: child}, nil
}
