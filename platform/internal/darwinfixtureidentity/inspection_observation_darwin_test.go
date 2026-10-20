//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func TestWatchedInspectionExitStopsBeforeNextQuery(t *testing.T) {
	_, roles := liveHostRosterTestFamily()
	candidate := roles[0]
	for exitPoll := 1; exitPoll <= 5; exitPoll++ {
		polls := 0
		var reads []string
		path, args, terminal, err := readWatchedInspection(inspectionTestBudget(t), candidate, func() (bool, error) {
			polls++
			return polls == exitPoll, nil
		}, func(int) (identity, error) { reads = append(reads, "identity"); return candidate, nil },
			func(identity) (string, error) { reads = append(reads, "path"); return "/selected/docker", nil },
			func(identity) ([]string, error) {
				reads = append(reads, "argv")
				return []string{"/selected/docker", "version"}, nil
			})
		want := []string{"identity", "path", "argv", "identity"}[:exitPoll-1]
		if err != nil || !terminal || polls != exitPoll || !reflect.DeepEqual(reads, append([]string(nil), want...)) {
			t.Fatal("exact original exit triggered another native query or became an admission failure")
		}
		if exitPoll == 1 && (path != "" || args != nil) {
			t.Fatal("terminal observation fabricated image or argv")
		}
	}
}

func TestWatchedInspectionQueryFailureCannotBeExcusedByLaterExit(t *testing.T) {
	_, roles := liveHostRosterTestFamily()
	candidate := roles[0]
	for _, failedRead := range []int{1, 2, 3, 4} {
		original := errors.New("private_query_failure")
		reads, polls := 0, 0
		next := func() error {
			reads++
			if reads == failedRead {
				return original
			}
			return nil
		}
		_, _, terminal, err := readWatchedInspection(inspectionTestBudget(t), candidate, func() (bool, error) {
			polls++
			return reads >= failedRead, nil
		}, func(int) (identity, error) { return candidate, next() },
			func(identity) (string, error) { return "/selected/docker", next() },
			func(identity) ([]string, error) { return []string{"/selected/docker", "version"}, next() })
		if terminal || !errors.Is(err, original) || reads != failedRead || polls != failedRead {
			t.Fatal("failed native query was retried or excused by a later exit")
		}
	}
}

func TestWatchedInspectionDisappearanceBetweenPollAndQueryRequiresExactWatch(t *testing.T) {
	_, roles := liveHostRosterTestFamily()
	candidate := roles[0]
	for _, failedRead := range []int{1, 2, 3, 4} {
		for _, watch := range []string{"exit", "no-event", "exec", "watch-error"} {
			reads, polls := 0, 0
			stages := []string{"fixture_native_query_refused", "version_bound_image_path_unavailable", "fixture_arguments_query_refused", "fixture_native_query_refused"}
			original := failed(stages[failedRead-1], unix.ESRCH)
			watchFailure := failed("fixture_unexpected_process_event", nil)
			if watch == "watch-error" {
				watchFailure = failed("fixture_watch_failed", unix.EIO)
			}
			next := func() error {
				reads++
				if reads == failedRead {
					return original
				}
				return nil
			}
			path, args, terminal, err := readWatchedInspection(inspectionTestBudget(t), candidate, func() (bool, error) {
				polls++
				if reads < failedRead {
					return false, nil
				}
				switch watch {
				case "exit":
					return true, nil
				case "no-event":
					return false, nil
				default:
					return false, watchFailure
				}
			}, func(int) (identity, error) { return candidate, next() },
				func(identity) (string, error) { return "/selected/docker", next() },
				func(identity) ([]string, error) { return []string{"/selected/docker", "version"}, next() })
			if reads != failedRead || polls != failedRead+1 || path != "" || args != nil {
				t.Fatal("disappearance retried a query, lost its one original watch check or fabricated metadata")
			}
			if watch == "exit" {
				if err != nil || !terminal {
					t.Fatal("exact original exit after known disappearance was refused")
				}
			} else if terminal || !errors.Is(err, original) || (watch != "no-event" && !errors.Is(err, watchFailure)) {
				t.Fatal("disappearance without exact original exit discarded the original failure or gained authority")
			}
		}
	}
}

func TestInspectionDisappearanceNeverInspectsUnknownOrWrappedCauses(t *testing.T) {
	for _, cause := range []error{
		unknownDiagnosticFailure{}, errors.New("ESRCH"), unix.ESRCH,
		failed("unknown_stage", unix.ESRCH),
		failed("fixture_arguments_allocation_refused", unix.ESRCH),
		failed("fixture_arguments_layout_refused", unix.ESRCH),
		failed("fixture_native_query_refused", unix.EPERM),
		failed("fixture_native_query_refused", nil),
		failed("fixture_native_query_refused", unknownDiagnosticFailure{}),
		failed("fixture_native_query_refused", errors.Join(unix.ESRCH)),
		errors.Join(failed("fixture_native_query_refused", unix.ESRCH)),
	} {
		polls := 0
		terminal, err := finishInspectionQueryFailure(inspectionTestBudget(t), cause, func() (bool, error) { polls++; return true, nil })
		if terminal || err == nil || polls != 0 {
			t.Fatal("unknown or wrapped cause gained a disappearance exception")
		}
	}
}

func TestInspectionDisappearanceCannotRenewOriginalDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(inspectionTestBudget(t))
	cancel()
	original := failed("fixture_native_query_refused", unix.ESRCH)
	terminal, err := finishInspectionQueryFailure(ctx, original, func() (bool, error) { t.Fatal("polled after original deadline"); return true, nil })
	if terminal || !errors.Is(err, original) || !errors.Is(err, context.Canceled) {
		t.Fatal("disappearance renewed deadline or lost native failure")
	}
}

func TestWatchedInspectionRefusesChangedIdentityWatchFailureAndDeadline(t *testing.T) {
	_, roles := liveHostRosterTestFamily()
	candidate := roles[0]
	for _, stage := range []string{"initial-identity", "final-identity", "watch", "deadline"} {
		ctx, cancel := context.WithCancel(inspectionTestBudget(t))
		original := errors.New("original_watch_failure")
		reads := 0
		if stage == "deadline" {
			cancel()
		}
		_, _, terminal, err := readWatchedInspection(ctx, candidate, func() (bool, error) {
			if stage == "watch" {
				return false, original
			}
			return false, nil
		}, func(int) (identity, error) {
			reads++
			after := candidate
			if (stage == "initial-identity" && reads == 1) || (stage == "final-identity" && reads == 2) {
				after.Version++
			}
			return after, nil
		}, func(identity) (string, error) { return "/selected/docker", nil }, func(identity) ([]string, error) { return []string{"/selected/docker"}, nil })
		cancel()
		if err == nil || terminal || (stage == "watch" && (!errors.Is(err, original) || reads != 0)) || (stage == "deadline" && (!errors.Is(err, context.Canceled) || reads != 0)) {
			t.Fatal("changed identity, watch failure or original deadline granted observation")
		}
	}
}

func TestInspectionExactExitRequiresOriginalPIDAndUnchangedExec(t *testing.T) {
	id := identity{PID: 90}
	exit := unix.Kevent_t{Ident: uint64(id.PID), Filter: unix.EVFILT_PROC, Fflags: unix.NOTE_EXIT}
	if !exactProcessExit(id, exit) {
		t.Fatal("exact original exit refused")
	}
	for _, stage := range []string{"pid", "filter", "error", "exec", "exit-exec", "empty"} {
		event := exit
		switch stage {
		case "pid":
			event.Ident++
		case "filter":
			event.Filter = unix.EVFILT_READ
		case "error":
			event.Flags |= unix.EV_ERROR
		case "exec":
			event.Fflags = unix.NOTE_EXEC
		case "exit-exec":
			event.Fflags |= unix.NOTE_EXEC
		case "empty":
			event.Fflags = 0
		}
		if exactProcessExit(id, event) {
			t.Fatal("unknown or exec event treated as original exit")
		}
	}
}

func TestInspectionTerminalObservationNeverReplacesRequiredRole(t *testing.T) {
	_, roles := liveHostRosterTestFamily()
	for _, missing := range []bool{false, true} {
		roster := append([]identity(nil), roles...)
		terminalID := identity{PID: 90, Unique: 190, Version: 4}
		if missing {
			roster = roster[:len(roster)-1]
		}
		roster = append(roster, terminalID)
		pins := 0
		got, err := drainRoleInspections(inspectionTestBudget(t), &inspectionRosterOwner{}, len(roles), func() ([]identity, error) { return roster, nil }, func(candidate identity) (inspectionChildClass, error) {
			for i, role := range roles {
				if sameIdentity(candidate, role) {
					return inspectionChildClass{role: i}, nil
				}
			}
			return inspectionChildClass{role: -2, observation: &inspectionObservation{id: candidate, bound: true, exited: true, closed: true}}, nil
		}, func(identity, inspectionChildClass) (inspectionPinResult, error) {
			pins++
			return inspectionPinResult{}, nil
		},
			func(*Proof) error { t.Fatal("terminal observation gained proof wait"); return nil }, func(*Proof) error { t.Fatal("terminal observation gained proof close"); return nil }, func() error { return nil })
		if pins != 0 || (missing && (err == nil || got != nil)) || (!missing && (err != nil || !sameRoster(got, roles))) {
			t.Fatal("terminal observation gained inspection authority or replaced a required role")
		}
	}
}

func TestInspectionTerminalObservationRefusesUnboundOrFailedOwner(t *testing.T) {
	id := identity{PID: 90, Unique: 190, Version: 4}
	for _, stage := range []string{"unbound", "live", "open", "transferred", "failure", "identity"} {
		observation := &inspectionObservation{id: id, bound: true, exited: true, closed: true}
		switch stage {
		case "unbound":
			observation.bound = false
		case "live":
			observation.exited = false
		case "open":
			observation.closed = false
		case "transferred":
			observation.transferred = true
		case "failure":
			observation.failure = errors.New("original_failure")
		case "identity":
			observation.id.Unique++
		}
		if terminalInspectionObservation(id, observation) {
			t.Fatal("unconfirmed watch owner became terminal observation")
		}
	}
}

func TestInspectionObservationDiagnosticsKeepStageAndPrivateCause(t *testing.T) {
	for _, stage := range []string{"fixture_inspection_watch_identity_refused", "fixture_inspection_watch_invalid", "fixture_inspection_identity_refused", "fixture_inspection_path_refused", "fixture_inspection_arguments_refused", "fixture_inspection_postwatch_admission_refused"} {
		cause := &failure{stage: stage, cause: unknownDiagnosticFailure{}}
		err := failed("fixture_child_scan_refused", &failure{stage: "fixture_inspection_owner_retained", cause: cause})
		want := []string{"fixture_child_scan_refused", "fixture_inspection_owner_retained", stage}
		if !reflect.DeepEqual(FailureCategories(err), want) {
			t.Fatal("inspection stage lost or unknown private error inspected")
		}
	}
	for _, stage := range []string{"fixture_inspection_watch_identity_refused", "fixture_inspection_identity_refused"} {
		cause := failed(stage, failed("fixture_native_query_refused", unix.ESRCH))
		want := []string{stage, "fixture_native_query_refused", "fixture_native_query_errno_esrch"}
		if !reflect.DeepEqual(FailureCategories(cause), want) || !errors.Is(cause, unix.ESRCH) {
			t.Fatal("original native failure lost at watched inspection boundary")
		}
	}
}
