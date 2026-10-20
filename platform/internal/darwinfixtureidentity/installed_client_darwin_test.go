//go:build darwin && arm64 && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"context"
	"errors"
	"testing"
)

func TestInstalledClientTransitionRequiresCreationImageAndArguments(t *testing.T) {
	original := identity{PID: 101, ParentPID: 100, Version: 4, UID: 501, RealUID: 501, Unique: 987, ParentUnique: 654}
	client := &installedClientExpectation{
		frontend: expectedImage{Path: "/protected/frontend", Args: []string{"mcp", "--client-installation", "fixed", "--selection", "/private/selection"}},
		python:   expectedImage{Path: "/protected/client/python", Args: []string{"-I", "-S", "/protected/client/bootstrap.py", "mcp", "/private/selection"}},
	}
	if ready, err := clientTransitionState(original, original, client.frontend.Path, client.frontend.literalArguments(), client); ready || err != nil {
		t.Fatal("unchanged frontend was not allowed to finish its direct exec")
	}
	python := original
	python.Version++
	if ready, err := clientTransitionState(original, python, client.python.Path, client.python.literalArguments(), client); !ready || err != nil {
		t.Fatal("exact target with the original creation identity refused")
	}
	for _, change := range []func(*identity){
		func(id *identity) { id.PID++ }, func(id *identity) { id.Unique++ },
		func(id *identity) { id.ParentUnique++ }, func(id *identity) { id.ParentPID++ },
		func(id *identity) { id.UID++ }, func(id *identity) { id.RealUID++ },
	} {
		changed := python
		change(&changed)
		if ready, err := clientTransitionState(original, changed, client.python.Path, client.python.literalArguments(), client); ready || err == nil {
			t.Fatal("changed creation identity gained target authority")
		}
	}
	args := client.python.literalArguments()
	for i := range args {
		changed := append([]string(nil), args...)
		changed[i] = "unexpected"
		if ready, err := clientTransitionState(original, python, client.python.Path, changed, client); ready || err == nil {
			t.Fatal("changed interpreter arguments gained target authority")
		}
	}
	for _, path := range []string{"/usr/bin/python3", client.python.Path + "-sibling", client.frontend.Path} {
		if ready, err := clientTransitionState(original, python, path, args, client); ready || err == nil {
			t.Fatal("unexpected executable gained target authority")
		}
	}
	if ready, err := clientTransitionState(original, python, client.frontend.Path, client.frontend.literalArguments(), client); ready || err == nil {
		t.Fatal("exec back to the frontend was allowed to wait")
	}
}

type refusedInstalledClient struct{ err error }

func (a refusedInstalledClient) Recheck(ctx context.Context) error {
	if a.err != nil {
		return a.err
	}
	return ctx.Err()
}
func (refusedInstalledClient) Close() error { return nil }

func TestInstalledClientRecheckFailureRetainsConfirmedTargetCleanup(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		refused := errors.New("package_changed")
		admission := refusedInstalledClient{err: refused}
		if cancelled {
			cancel()
			refused = context.Canceled
			admission.err = nil
		}
		original := identity{PID: 101, ParentPID: 100, Version: 4, UID: 501, RealUID: 501, Unique: 987, ParentUnique: 654}
		target := original
		target.Version++
		x := &Owned{ownedState: &ownedState{cleanupIdentity: &original,
			client:   &installedClientExpectation{admission: admission, original: original, python: expectedImage{Path: "/protected/python"}},
			expected: expectedImage{Path: "/protected/frontend"}}}
		err := x.retainInstalledClientTarget(ctx, target)
		cancel()
		if !errors.Is(err, refused) || x.cleanupIdentity == nil || !sameIdentity(*x.cleanupIdentity, target) || x.client.original != original {
			t.Fatal("recheck failure lost the exact target cleanup identity or original creation snapshot")
		}
		if x.proof != nil || x.expected.Path != "/protected/frontend" {
			t.Fatal("failed package recheck granted full target proof")
		}
		later := target
		later.Version++
		if sameIdentity(*x.cleanupIdentity, later) {
			t.Fatal("later exec retained cleanup authority")
		}
	}
}

func TestInstalledClientInvalidOperationStartsNothing(t *testing.T) {
	var creator *Creator
	if owned, err := creator.StartInstalledClient(context.Background(), Launch{}, "", "host", "/selection"); owned != nil || err == nil {
		t.Fatal("invalid operation reached package admission or creation")
	}
}

func TestInstalledClientEnsureRefusesMissingAnchorAndScope(t *testing.T) {
	var parent *Proof
	for _, host := range []ExpectedHost{{}, {PolicyPath: "/private/policy", WorkspaceRoots: []string{"/workspace"}}} {
		if proof, err := parent.PinDirectClientEnsure(context.Background(), host, "sha256:unused"); proof != nil || err == nil {
			t.Fatal("missing native anchor or scope gained ensure child authority")
		}
	}
}

func TestInstalledClientChildAbsenceDoesNotHideCleanupFailure(t *testing.T) {
	if !ChildNotPresent(childNotPresent) {
		t.Fatal("exact pre-admission absence was not retryable")
	}
	cleanup := errors.New("close_failed")
	for _, err := range []error{nil, errors.Join(childNotPresent, cleanup), failed("fixture_child_roster_count_refused", nil), failed("wrapped", childNotPresent)} {
		if ChildNotPresent(err) {
			t.Fatal("terminal admission or joined cleanup failure became retryable")
		}
	}
	partial := &Proof{proofState: &proofState{closed: true, cleanup: cleanup}}
	if got, err := singleChildResult([]*Proof{partial}, cleanup); got != partial || err != cleanup {
		t.Fatal("single-child result lost its partial proof or failure")
	}
	parent := &Proof{proofState: &proofState{valid: true}}
	admission := errors.New("admission_failed")
	result := closeFailedChildAdmission(parent, []*Proof{partial}, admission)
	if !errors.Is(result, cleanup) || !errors.Is(result, admission) || !errors.Is(parent.cleanup, cleanup) || parent.valid {
		t.Fatal("uncertain child cleanup was lost or the original anchor kept authority")
	}
	if parent.event() == nil {
		t.Fatal("later polling restored authority after uncertain cleanup")
	}
}
