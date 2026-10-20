//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestInitialCensusOmitsDisappearedEntryWithoutInventingIdentity(t *testing.T) {
	host, roles := liveHostRosterTestFamily()
	for _, mode := range []string{"uid", "live-host"} {
		for _, absentFirst := range []bool{true, false} {
			pids := []int32{41, 42, 43, 44, 90}
			if absentFirst {
				pids = []int32{90, 41, 42, 43, 44}
			}
			if mode == "uid" {
				pids = append(pids, 91)
			}
			reads, checks := map[int]int{}, 0
			read := func(pid int) (identity, error) {
				reads[pid]++
				if pid == 90 {
					return nativeIdentityResult(pid, nativeIdentityQueryRefused, int(unix.ESRCH), identity{})
				}
				if pid == 91 {
					unrelated := roles[0]
					unrelated.PID, unrelated.Unique, unrelated.ParentUnique = 91, 191, host.Unique+100
					return unrelated, nil
				}
				for _, role := range roles {
					if int(role.PID) == pid {
						return role, nil
					}
				}
				t.Fatal("unexpected census query")
				return identity{}, nil
			}
			var got []identity
			var err error
			if mode == "uid" {
				got, err = scanNativeCandidateIdentities(pids, host.UID, host.Unique, read)
			} else {
				got, err = scanLiveHostChildren(inspectionTestBudget(t), host, func() (identity, error) { checks++; return host, nil }, func(int32) ([]int32, error) { return pids, nil }, read)
			}
			if err != nil || !sameRoster(got, roles) || len(reads) != len(pids) || (mode == "live-host" && checks != 2) {
				t.Fatal("absent census entry blocked complete role identities or skipped final host check")
			}
			for _, count := range reads {
				if count != 1 {
					t.Fatal("census omission retried an identity query")
				}
			}
		}
	}
}

func TestInitialCensusOmissionKeepsOtherErrorsTerminal(t *testing.T) {
	host, _ := liveHostRosterTestFamily()
	absent := failed("fixture_native_query_refused", unix.ESRCH)
	for _, mode := range []string{"uid", "live-host"} {
		for _, original := range []error{
			unknownDiagnosticFailure{}, unix.ESRCH,
			failed("fixture_native_query_refused", unix.EPERM),
			failed("fixture_native_query_refused", unix.EACCES),
			failed("fixture_native_query_refused", nil),
			failed("fixture_native_query_refused", unknownDiagnosticFailure{}),
			failed("fixture_native_query_refused", errors.Join(unix.ESRCH)),
			failed("fixture_native_layout_refused", unix.ESRCH),
			failed("fixture_arguments_query_refused", unix.ESRCH),
			failed("version_bound_image_path_unavailable", unix.ESRCH),
			failed("unknown_stage", unix.ESRCH), errors.Join(absent),
		} {
			reads := 0
			read := func(pid int) (identity, error) {
				reads++
				if reads == 1 && pid == 90 {
					return identity{}, absent
				}
				if reads == 2 && pid == 91 {
					return identity{}, original
				}
				t.Fatal("unknown census failure was retried or skipped")
				return identity{}, nil
			}
			var got []identity
			var err error
			if mode == "uid" {
				got, err = scanNativeCandidateIdentities([]int32{90, 91, 41}, host.UID, host.Unique, read)
			} else {
				got, err = scanLiveHostChildren(inspectionTestBudget(t), host, func() (identity, error) { return host, nil }, func(int32) ([]int32, error) { return []int32{90, 91, 41}, nil }, read)
			}
			retained, ok := err.(*failure)
			if got != nil || reads != 2 || !ok || retained.stage != "fixture_candidate_identity_refused" || retained.cause != original {
				t.Fatal("census omission swallowed a different failure or changed its original cause")
			}
		}
	}
}

func TestInitialCensusOmissionCannotSupplyMissingRequiredRole(t *testing.T) {
	host, roles := liveHostRosterTestFamily()
	for _, mode := range []string{"uid", "live-host"} {
		scan := func() ([]identity, error) {
			read := func(pid int) (identity, error) {
				if pid == int(roles[3].PID) {
					return nativeIdentityResult(pid, nativeIdentityQueryRefused, int(unix.ESRCH), identity{})
				}
				for _, role := range roles {
					if int(role.PID) == pid {
						return role, nil
					}
				}
				t.Fatal("unexpected census query")
				return identity{}, nil
			}
			pids := []int32{41, 42, 43, 44}
			if mode == "uid" {
				return scanNativeCandidateIdentities(pids, host.UID, host.Unique, read)
			}
			return scanLiveHostChildren(inspectionTestBudget(t), host, func() (identity, error) { return host, nil }, func(int32) ([]int32, error) { return pids, nil }, read)
		}
		got, err := drainRoleInspections(inspectionTestBudget(t), &inspectionRosterOwner{}, len(roles), scan, func(candidate identity) (inspectionChildClass, error) {
			for i, role := range roles {
				if sameIdentity(candidate, role) {
					return inspectionChildClass{role: i}, nil
				}
			}
			t.Fatal("census omission fabricated a required identity")
			return inspectionChildClass{}, nil
		}, func(identity, inspectionChildClass) (inspectionPinResult, error) {
			t.Fatal("missing role became inspection proof")
			return inspectionPinResult{}, nil
		},
			func(*Proof) error { t.Fatal("missing role gained an exit wait"); return nil }, func(*Proof) error { t.Fatal("missing role gained a proof close"); return nil }, func() error { return nil })
		if got != nil || err == nil {
			t.Fatal("omitted required process became a complete initial roster")
		}
		checked := false
		err = verifyFinalChildRoster(roles, false, scan, func() error { checked = true; return nil })
		if err == nil || checked {
			t.Fatal("omitted required process passed final roster comparison")
		}
	}
}

func TestLiveHostCensusOmissionPreservesCancellationAndFinalHostChecks(t *testing.T) {
	host, _ := liveHostRosterTestFamily()
	for _, reason := range []string{"cancel", "host-change", "host-exit", "watch"} {
		ctx, cancel := context.WithCancel(inspectionTestBudget(t))
		checks, reads := 0, 0
		original := failed("fixture_watch_failed", unix.EIO)
		got, err := scanLiveHostChildren(ctx, host, func() (identity, error) {
			checks++
			current := host
			if checks == 2 {
				switch reason {
				case "host-change":
					current.Version++
				case "host-exit":
					return identity{}, ErrExited
				case "watch":
					return identity{}, original
				}
			}
			return current, nil
		}, func(int32) ([]int32, error) { return []int32{90}, nil }, func(pid int) (identity, error) {
			reads++
			if reason == "cancel" {
				cancel()
			}
			return nativeIdentityResult(pid, nativeIdentityQueryRefused, int(unix.ESRCH), identity{})
		})
		cancel()
		if got != nil || err == nil || reads != 1 || (reason == "cancel" && (!errors.Is(err, context.Canceled) || checks != 1)) || (reason != "cancel" && checks != 2) || (reason == "watch" && err != original) || (reason == "host-exit" && err != ErrExited) {
			t.Fatal("omission hid cancellation, changed host or original watch failure")
		}
	}
}

func TestInitialCensusOmissionDoesNotDischargeRetainedProofChecks(t *testing.T) {
	host, roles := liveHostRosterTestFamily()
	scan := func() ([]identity, error) {
		return scanNativeCandidateIdentities([]int32{90, 41, 42, 43, 44}, host.UID, host.Unique, func(pid int) (identity, error) {
			if pid == 90 {
				return identity{}, failed("fixture_native_query_refused", unix.ESRCH)
			}
			for _, role := range roles {
				if int(role.PID) == pid {
					return role, nil
				}
			}
			t.Fatal("unexpected census query")
			return identity{}, nil
		})
	}
	for _, state := range []string{"failed-watch", "exited", "invalid"} {
		retained := &Proof{proofState: &proofState{id: roles[0], queue: -1, watchOwned: true, valid: state != "invalid", exited: state == "exited"}}
		checks := 0
		err := verifyFinalChildRoster(roles, false, scan, func() error { checks++; return retained.Live() })
		if err == nil || checks != 1 || retained.closed || retained.exited != (state == "exited") || !retained.watchOwned || retained.queue != -1 || !sameIdentity(retained.id, roles[0]) {
			t.Fatal("census omission discharged a retained process proof or skipped its strict check")
		}
		if (state == "failed-watch" && !errors.Is(err, unix.EBADF)) || (state == "exited" && err != ErrExited) {
			t.Fatal("census omission replaced an original proof failure")
		}
	}
}
