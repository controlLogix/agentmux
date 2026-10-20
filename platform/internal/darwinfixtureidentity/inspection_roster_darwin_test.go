//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func inspectionTestBudget(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestInspectionRosterWaitsForAdmittedExitWithoutRequiringQuietSnapshot(t *testing.T) {
	_, roles := liveHostRosterTestFamily()
	inspection := identity{PID: 90, Unique: 190, Version: 4}
	ctx := inspectionTestBudget(t)
	proofs := []*Proof{{}, {}}
	scans, pins, waits, closes := 0, 0, 0, 0
	var owners []*inspectionRosterOwner
	scanRoster := func() ([]identity, error) {
		state := &inspectionRosterOwner{anchor: &Proof{}}
		owners = append(owners, state)
		return drainRoleInspections(ctx, state, len(roles), func() ([]identity, error) {
			scans++
			// Each census sees a fresh legitimate inspection. There is no
			// inspection-free snapshot, but both required role rosters agree.
			return append(append([]identity{}, roles...), inspection), nil
		}, func(candidate identity) (inspectionChildClass, error) {
			for i, role := range roles {
				if sameIdentity(candidate, role) {
					return inspectionChildClass{role: i}, nil
				}
			}
			return inspectionChildClass{role: -1, target: expectedImage{inspection: &InspectionSelection{}}}, nil
		}, func(candidate identity, _ inspectionChildClass) (inspectionPinResult, error) {
			if !sameIdentity(candidate, inspection) || pins >= len(proofs) {
				t.Fatal("unexpected inspection admission or extra census")
			}
			proof := proofs[pins]
			pins++
			return inspectionPinResult{proof: proof}, nil
		}, func(original *Proof) error {
			if waits >= len(proofs) || original != proofs[waits] {
				t.Fatal("original inspection exit owner replaced")
			}
			waits++
			return nil
		}, func(original *Proof) error {
			if closes >= len(proofs) || original != proofs[closes] || waits != closes+1 {
				t.Fatal("watch close preceded its exact exit")
			}
			closes++
			return nil
		}, func() error { return nil })
	}
	got, err := scanRoster()
	if err != nil || !sameRoster(got, roles) {
		t.Fatal("initial complete roster refused")
	}
	checked := false
	err = verifyFinalChildRoster(got, false, scanRoster, func() error { checked = true; return nil })
	if err != nil || !checked || scans != 2 || pins != 2 || waits != 2 || closes != 2 || len(owners) != 2 {
		t.Fatal("role verification required global quiescence or lost original inspection waits")
	}
	for i, owner := range owners {
		if len(owner.proofs) != 1 || owner.proofs[0] != proofs[i] {
			t.Fatal("original watch owner lost")
		}
	}
}

func TestInspectionRecoveryRosterAllowsExactProductionReadWithoutReplacingOwners(t *testing.T) {
	host, oldRoles := liveHostRosterTestFamily()
	recovered := append([]identity(nil), oldRoles...)
	var expected []expectedImage
	for i := range recovered {
		recovered[i].PID += 100
		recovered[i].Unique += 100
		expected = append(expected, expectedImage{Path: "/protected/role" + string(rune('0'+i)), argv0: "agentmux-role" + string(rune('0'+i))})
	}
	// This is the literal version read emitted by Docker.Inspect through
	// runFixedRead; the launcher regression captures the full production set.
	argv := []string{"/selected/docker", "--context", "selected", "version", "--format", `{"Client":{{json .Client.Version}},"Server":{{json .Server.Version}}}`}
	selection := &InspectionSelection{path: argv[0], digest: "sha256:fixture", commands: []InspectionCommand{{Args: append([]string(nil), argv...), ContainerArgument: -1}}}
	parent := &Proof{proofState: &proofState{id: host}}
	inspection := identity{PID: 90, ParentPID: host.PID, ParentUnique: host.Unique, Unique: 190, Version: 4, UID: host.UID, RealUID: host.RealUID, Status: 2}
	state, proof := &inspectionRosterOwner{anchor: parent}, &Proof{}
	ctx := inspectionTestBudget(t)
	scans, pins, exits, closes := 0, 0, 0, 0
	got, err := drainRoleInspections(ctx, state, len(recovered), func() ([]identity, error) {
		scans++
		return append(append([]identity{}, recovered...), inspection), nil
	}, func(candidate identity) (inspectionChildClass, error) {
		for i, role := range recovered {
			if sameIdentity(candidate, role) {
				return classifyInspectionObservation(parent, expected, selection, candidate, candidate, expected[i].Path, expected[i].literalArguments(), nil, nil, nil)
			}
		}
		return classifyInspectionObservation(parent, expected, selection, candidate, candidate, selection.path, argv, nil, nil, nil)
	}, func(candidate identity, class inspectionChildClass) (inspectionPinResult, error) {
		target := class.target
		pins++
		if !sameIdentity(candidate, inspection) || target.inspection != selection || target.Path != selection.path || target.Digest != selection.digest {
			t.Fatal("recovery admission replaced the retained selected inspection")
		}
		return inspectionPinResult{proof: proof}, nil
	}, func(original *Proof) error {
		exits++
		if original != proof {
			t.Fatal("inspection exit owner replaced")
		}
		return nil
	},
		func(original *Proof) error {
			closes++
			if original != proof {
				t.Fatal("inspection close owner replaced")
			}
			return nil
		}, func() error { return nil })
	if err != nil || !sameRoster(got, recovered) || sameRoster(got, oldRoles) || scans != 1 || pins != 1 || exits != 1 || closes != 1 || state.anchor != parent || len(state.proofs) != 1 || state.proofs[0] != proof {
		t.Fatal("overlapping production inspection blocked recovery or replaced an original owner")
	}
}

func TestInspectionRosterUnknownChildNeverPermitsCountRetry(t *testing.T) {
	_, roles := liveHostRosterTestFamily()
	original := errors.New("original_unknown_child")
	for _, kind := range []string{"unknown", "missing", "duplicate", "unclassified-inspection"} {
		t.Run(kind, func(t *testing.T) {
			scans, pins := 0, 0
			roster := append([]identity(nil), roles...)
			if kind == "missing" {
				roster = roster[:3]
			} else {
				roster = append(roster, identity{PID: 90})
			}
			state := &inspectionRosterOwner{anchor: &Proof{}}
			got, err := drainRoleInspections(inspectionTestBudget(t), state, len(roles), func() ([]identity, error) { scans++; return roster, nil },
				func(candidate identity) (inspectionChildClass, error) {
					for i, role := range roles {
						if sameIdentity(candidate, role) {
							return inspectionChildClass{role: i}, nil
						}
					}
					if kind == "duplicate" {
						return inspectionChildClass{role: 0}, nil
					}
					if kind == "unclassified-inspection" {
						return inspectionChildClass{role: -1}, nil
					}
					return inspectionChildClass{}, original
				}, func(identity, inspectionChildClass) (inspectionPinResult, error) {
					pins++
					return inspectionPinResult{}, nil
				},
				func(*Proof) error { t.Fatal("waited for an unknown child"); return nil },
				func(*Proof) error { t.Fatal("closed an unknown child owner"); return nil }, func() error { return nil })
			retained, ok := err.(*failure)
			if got != nil || !ok || retained.retained != state || scans != 1 || pins != 0 || (kind == "unknown" && !errors.Is(err, original)) {
				t.Fatal("unknown or incomplete roster was retried, accepted or lost its original failure owner")
			}
		})
	}
}

func TestInspectionRosterRetainsPartialProofTimeoutAndWatchFailures(t *testing.T) {
	_, roles := liveHostRosterTestFamily()
	for _, phase := range []string{"pin", "wait", "close", "query", "host"} {
		t.Run(phase, func(t *testing.T) {
			original := errors.New("original_" + phase + "_failure")
			if phase == "wait" {
				original = context.DeadlineExceeded
			}
			state, proof := &inspectionRosterOwner{anchor: &Proof{}}, &Proof{}
			scans, pins, waits, closes := 0, 0, 0, 0
			got, err := drainRoleInspections(inspectionTestBudget(t), state, len(roles), func() ([]identity, error) {
				scans++
				if phase == "query" {
					return nil, original
				}
				return append(append([]identity{}, roles...), identity{PID: 90}), nil
			}, func(candidate identity) (inspectionChildClass, error) {
				for i, role := range roles {
					if sameIdentity(candidate, role) {
						return inspectionChildClass{role: i}, nil
					}
				}
				return inspectionChildClass{role: -1, target: expectedImage{inspection: &InspectionSelection{}}}, nil
			}, func(identity, inspectionChildClass) (inspectionPinResult, error) {
				pins++
				if phase == "pin" {
					return inspectionPinResult{proof: proof}, original
				}
				return inspectionPinResult{proof: proof}, nil
			},
				func(*Proof) error {
					waits++
					if phase == "wait" {
						return original
					}
					return nil
				},
				func(*Proof) error { closes++; return original },
				func() error {
					if phase == "host" {
						return original
					}
					return nil
				})
			retained, ok := err.(*failure)
			if got != nil || !ok || retained.retained != state || !errors.Is(err, original) || scans > 1 {
				t.Fatal("terminal scan/admission failure was retried or lost its native owner")
			}
			if pins > 0 && (len(state.proofs) != 1 || state.proofs[0] != proof) {
				t.Fatal("partial proof was not retained")
			}
			if (phase == "pin" && (waits != 0 || closes != 0)) || (phase == "wait" && closes != 0) {
				t.Fatal("uncertain inspection admission or exit caused implicit cleanup")
			}
		})
	}
}

func TestInspectionRosterRefusesChangedRoleAndOriginalDeadlineExpiry(t *testing.T) {
	_, roles := liveHostRosterTestFamily()
	for _, expire := range []bool{false, true} {
		ctx, cancel := context.WithCancel(inspectionTestBudget(t))
		state := &inspectionRosterOwner{anchor: &Proof{}}
		scans := 0
		got, err := drainRoleInspections(ctx, state, len(roles), func() ([]identity, error) {
			scans++
			return append(append([]identity{}, roles...), identity{PID: 90}), nil
		}, func(candidate identity) (inspectionChildClass, error) {
			for i, role := range roles {
				if candidate.PID == role.PID {
					return inspectionChildClass{role: i}, nil
				}
			}
			return inspectionChildClass{role: -1, target: expectedImage{inspection: &InspectionSelection{}}}, nil
		}, func(identity, inspectionChildClass) (inspectionPinResult, error) {
			return inspectionPinResult{proof: &Proof{}}, nil
		},
			func(*Proof) error {
				if expire {
					cancel()
				}
				return nil
			}, func(*Proof) error { return nil }, func() error { return nil })
		if !expire {
			if err != nil || !sameRoster(got, roles) {
				t.Fatal("initial roster failed")
			}
			err = verifyFinalChildRoster(got, false, func() ([]identity, error) {
				return drainRoleInspections(ctx, &inspectionRosterOwner{anchor: &Proof{}}, len(roles), func() ([]identity, error) {
					scans++
					changed := append([]identity(nil), roles...)
					changed[0].Version++
					return changed, nil
				}, func(candidate identity) (inspectionChildClass, error) {
					for i, role := range roles {
						if candidate.PID == role.PID {
							return inspectionChildClass{role: i}, nil
						}
					}
					return inspectionChildClass{}, errors.New("unknown_child")
				}, func(identity, inspectionChildClass) (inspectionPinResult, error) {
					t.Fatal("unexpected inspection")
					return inspectionPinResult{}, nil
				}, func(*Proof) error { return nil }, func(*Proof) error { return nil }, func() error { return nil })
			}, func() error { t.Fatal("changed roles reached live-proof checks"); return nil })
		}
		cancel()
		if err == nil || (expire && (got != nil || !errors.Is(err, context.Canceled) || scans != 1)) || (!expire && scans != 2) {
			t.Fatal("final census admitted a changed role or renewed the original admission budget")
		}
	}
}

func TestInspectionImagePinAndCommandSnapshotStayFixed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "selected-docker")
	if os.WriteFile(path, []byte("selected fixture executable bytes"), 0500) != nil {
		t.Fatal("selected image setup failed")
	}
	args := []string{path, "--context", "selected", "version", "--format", "fixed-format"}
	selection, err := PrepareInspectionSelection(inspectionTestBudget(t), path, []InspectionCommand{{Args: args, ContainerArgument: -1}})
	if err != nil {
		t.Fatal("selected executable pin refused")
	}
	args[2] = "foreign"
	if _, ok := selection.target(args); ok {
		t.Fatal("caller mutation widened the selected command")
	}
	args[2] = "selected"
	if target, ok := selection.target(args); !ok || target.Digest == "" || target.inspection != selection {
		t.Fatal("selected executable digest or command snapshot lost")
	}
	selection.retain()
	if selection.Close() != nil || selection.recheck(inspectionTestBudget(t)) != nil {
		t.Fatal("caller close consumed a still-owned inspection image")
	}
	if os.Chmod(path, 0700) != nil || os.WriteFile(path, []byte("different fixture executable bytes"), 0500) != nil {
		t.Fatal("selected image mutation setup failed")
	}
	if selection.recheck(inspectionTestBudget(t)) == nil {
		t.Fatal("changed selected executable still admitted inspections")
	}
	if selection.Close() == nil {
		t.Fatal("selected image failure was lost at its final owner close")
	}
}

func TestInspectionDiagnosticsRetainPrivateUnknownFailureWithoutCallingIt(t *testing.T) {
	state := &inspectionRosterOwner{anchor: &Proof{}}
	err := &failure{stage: "fixture_inspection_owner_retained", cause: unknownDiagnosticFailure{}, retained: state}
	got := FailureCategories(err)
	if len(got) != 2 || got[0] != "fixture_inspection_owner_retained" || got[1] != "fixture_unclassified_failure" || err.retained != state {
		t.Fatal("inspection failure disclosed private details or lost its original owner")
	}
}

func TestInspectionObservationRefusesUnknownImageArgvAndExecTransition(t *testing.T) {
	host, children := liveHostRosterTestFamily()
	parent := &Proof{proofState: &proofState{expected: expectedImage{Path: "/protected/host", Args: []string{"host", "--fixed"}}}}
	role := expectedImage{Path: "/protected/role", argv0: "agentmux-role"}
	args := []string{"/selected/docker", "--context", "selected", "version", "--format", "fixed"}
	selection := &InspectionSelection{path: args[0], digest: "sha256:fixture", commands: []InspectionCommand{{Args: append([]string(nil), args...), ContainerArgument: -1}}}
	if class, err := classifyInspectionObservation(parent, []expectedImage{role}, selection, children[0], children[0], role.Path, role.literalArguments(), nil, nil, nil); err != nil || class.role != 0 {
		t.Fatal("exact role observation was not classified")
	}
	if class, err := classifyInspectionObservation(parent, []expectedImage{role}, selection, children[0], children[0], selection.path, args, nil, nil, nil); err != nil || class.role != -1 || class.target.inspection != selection {
		t.Fatal("exact selected inspection was not classified for separate native admission")
	}
	for _, name := range []string{"unknown-path", "unknown-argv", "inherited-host", "version-change", "lineage-change", "path-query", "argv-query", "identity-query"} {
		t.Run(name, func(t *testing.T) {
			before, after := children[0], children[0]
			path, argv := selection.path, append([]string(nil), args...)
			var pathErr, argvErr, identityErr error
			switch name {
			case "unknown-path":
				path = "/other/docker"
			case "unknown-argv":
				argv[2] = "foreign"
			case "inherited-host":
				path, argv = parent.expected.Path, parent.expected.literalArguments()
			case "version-change":
				after.Version++
				if !sameCreation(before, after) {
					t.Fatal("weaker-match regression setup failed")
				}
			case "lineage-change":
				after.ParentUnique = host.ParentUnique
			case "path-query":
				pathErr = errors.New("original_path_query_failed")
			case "argv-query":
				argvErr = errors.New("original_argv_query_failed")
			case "identity-query":
				identityErr = errors.New("original_identity_query_failed")
			}
			if _, err := classifyInspectionObservation(parent, []expectedImage{role}, selection, before, after, path, argv, pathErr, argvErr, identityErr); err == nil {
				t.Fatal("unknown image/argv or an unadmitted fork/exec transition gained inspection classification")
			}
		})
	}
}
