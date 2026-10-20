//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testChildExecTransition() (*childExecTransition, identity) {
	original := identity{PID: 401, ParentPID: 400, Version: 3, UID: 501, RealUID: 501, Status: 2, Unique: 901, ParentUnique: 900}
	anchor := &Proof{proofState: &proofState{expected: expectedImage{Path: "/fixture/python", Args: []string{"-I", "bootstrap", "mcp"}}}}
	return &childExecTransition{anchor: anchor, original: original, target: expectedImage{Path: "/fixture/go", Args: []string{"ensure", "--host-policy", "/fixture/policy"}}}, original
}

func TestChildExecWaitsForExactTargetWithoutWeakeningProofIdentity(t *testing.T) {
	state, original := testChildExecTransition()
	parent := state.anchor.expected
	if ready, err := state.ready(original, original, parent.Path, parent.literalArguments(), nil, nil, nil); ready || err != nil {
		t.Fatal("exact parent image did not remain pending before exec")
	}
	final := original
	final.Version++
	if ready, err := state.ready(original, final, parent.Path, parent.literalArguments(), nil, nil, nil); ready || err != nil {
		t.Fatal("reads across initial exec granted authority or rejected unchanged creation lineage")
	}
	if ready, err := state.ready(final, final, state.target.Path, state.target.literalArguments(), nil, nil, nil); !ready || err != nil {
		t.Fatal("original creation did not converge on the exact selected target")
	}
	if sameIdentity(original, final) || !sameCreation(original, final) {
		t.Fatal("initial exec weakened full proof identity or lost creation lineage")
	}
	// Current PPID can change after the creator exits. Creation-parent identity
	// must remain fixed throughout the same child's initial exec.
	final.ParentPID = 1
	if err := state.checkRoster([]identity{final}); err != nil {
		t.Fatal("reparenting lost the original immutable creation parent")
	}
}

func TestChildExecRejectsReplacementRosterAndWrongTarget(t *testing.T) {
	state, original := testChildExecTransition()
	for _, mutate := range []func(*identity){
		func(id *identity) { id.PID++ }, func(id *identity) { id.Unique++ },
		func(id *identity) { id.ParentUnique++ }, func(id *identity) { id.UID++ }, func(id *identity) { id.RealUID++ },
	} {
		changed := original
		mutate(&changed)
		if state.checkRoster([]identity{changed}) == nil {
			t.Fatal("changed creation or credential entered the original roster")
		}
		if ready, err := state.ready(original, changed, state.target.Path, state.target.literalArguments(), nil, nil, nil); ready || err == nil {
			t.Fatal("changed creation or credential reached target readiness")
		}
	}
	for _, roster := range [][]identity{nil, {original, original}} {
		if state.checkRoster(roster) == nil {
			t.Fatal("missing or extra child entered the original roster")
		}
	}
	for _, test := range []struct {
		path string
		args []string
	}{
		{"/fixture/unexpected", state.target.literalArguments()},
		{state.target.Path, []string{state.target.Path, "unexpected"}},
		{state.anchor.expected.Path, []string{state.anchor.expected.Path, "unexpected"}},
	} {
		if ready, err := state.ready(original, original, test.path, test.args, nil, nil, nil); ready || err == nil {
			t.Fatal("stable unexpected executable or arguments were accepted")
		}
	}
	if ready, err := state.ready(original, original, state.target.Path, nil, nil, unknownDiagnosticFailure{}, nil); ready || err == nil {
		t.Fatal("unreadable target arguments reached readiness")
	}
	if ready, err := state.ready(original, original, "", nil, unknownDiagnosticFailure{}, nil, nil); ready || err == nil {
		t.Fatal("unknown target path reached readiness")
	}
}

func TestChildExecKeepsPreExecReadFailureAndOriginalDeadline(t *testing.T) {
	state, original := testChildExecTransition()
	readErr := errors.New("original_pre_exec_argument_read")
	if ready, err := state.ready(original, original, state.anchor.expected.Path, nil, nil, readErr, nil); ready || err != nil || !errors.Is(state.pending, readErr) {
		t.Fatal("pre-exec wait lost its original read failure or granted readiness")
	}
	state.pending = failed("fixture_child_arguments_refused", failed("fixture_arguments_count_refused", unknownDiagnosticFailure{}))
	retained := &failure{stage: "fixture_child_exec_incomplete", retained: state}
	if !reflect.DeepEqual(FailureCategories(retained), []string{"fixture_child_exec_incomplete", "fixture_child_arguments_refused", "fixture_arguments_count_refused"}) {
		t.Fatal("pending exec lost its closed read diagnostic or inspected a private cause")
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if proofs, err := state.anchor.awaitExpectedChildExec(ctx, state.target, []identity{original}, false); proofs != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("pending exec escaped its original deadline or returned a proof")
	}
	if proofs, err := state.anchor.awaitExpectedChildExec(context.Background(), state.target, []identity{original}, false); proofs != nil || err == nil {
		t.Fatal("initial exec wait accepted an unbounded context")
	}
}

func TestChildScanDiagnosticsDistinguishObservationAndIdentityChanges(t *testing.T) {
	state, original := testChildExecTransition()
	changed := original
	changed.Version++
	err := childScanChanged(state.anchor, original, changed, nil)
	want := ChildScanDiagnostic{Reason: "identity_changed", IdentityCompared: true, PIDMatched: true,
		CreationMatched: true, CreationParentMatched: true, UIDMatched: true, RealUIDMatched: true}
	got := ChildScanDiagnostics(errors.Join(err, unknownDiagnosticFailure{}))
	if !reflect.DeepEqual(got, []ChildScanDiagnostic{want}) || err.(*failure).retained.(*childScanOwner).anchor != state.anchor {
		t.Fatal("scan comparison lost a changed field or its original anchor")
	}
	got[0].Reason = "changed"
	if ChildScanDiagnostics(err)[0].Reason != want.Reason {
		t.Fatal("scan comparison escaped its retained copy")
	}
	wantCategories := []string{"fixture_child_scan_changed", "fixture_child_scan_identity_changed"}
	if !reflect.DeepEqual(FailureCategories(err), wantCategories) {
		t.Fatal("scan identity comparison lost its fixed category")
	}
	readErr := failed("fixture_native_query_refused", unknownDiagnosticFailure{})
	err = childScanChanged(state.anchor, original, identity{}, readErr)
	got = ChildScanDiagnostics(err)
	if len(got) != 1 || got[0].Reason != "native_observation_refused" || got[0].IdentityCompared {
		t.Fatal("failed observation was reported as a completed identity comparison")
	}
	wantCategories = []string{"fixture_child_scan_changed", "fixture_child_scan_observation_refused", "fixture_native_query_refused", "fixture_native_query_errno_unclassified"}
	if !reflect.DeepEqual(FailureCategories(err), wantCategories) {
		t.Fatal("scan observation lost its fixed native reason")
	}
	raw, marshalErr := json.Marshal(got)
	if marshalErr != nil || strings.Contains(string(raw), "401") || strings.Contains(string(raw), "901") || strings.Contains(string(raw), "/fixture") {
		t.Fatal("scan diagnostic exposed a private identifier or image")
	}
	err = childScanChanged(state.anchor, original, identity{}, unknownDiagnosticFailure{})
	if !reflect.DeepEqual(FailureCategories(err), []string{"fixture_child_scan_changed", "fixture_child_scan_observation_refused"}) {
		t.Fatal("scan observation inspected an unknown private cause")
	}
}
