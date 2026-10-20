//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNoSurvivingHostIsOnlyExactExitedEmptyObservation(t *testing.T) {
	empty := emptyChildRosterResult(ErrExited, true)
	if !NoSurvivingHost(empty) || ChildNotPresent(empty) {
		t.Fatal("post-exit empty roster lost its distinct observation result")
	}
	for _, result := range []error{
		nil, childNotPresent, unknownDiagnosticFailure{},
		errors.Join(empty, errors.New("original_cleanup_failure")), failed("wrapped", empty),
		emptyChildRosterResult(nil, true), emptyChildRosterResult(errors.Join(ErrExited, context.Canceled), true),
		emptyChildRosterResult(ErrExited, false),
	} {
		if NoSurvivingHost(result) {
			t.Fatal("unknown, live, incomplete or wrapped failure became an empty-roster observation")
		}
	}
	if !ChildNotPresent(emptyChildRosterResult(nil, false)) {
		t.Fatal("ordinary pre-admission absence lost its existing polling result")
	}
	partial := &Proof{}
	if proof, err := singleChildResult([]*Proof{partial}, empty); proof != partial || err != empty {
		t.Fatal("partial proof was lost when preserving an original result")
	}
}

func TestHostAfterExitRejectsMissingProofAndExpiredBudget(t *testing.T) {
	p := &Proof{}
	host := ExpectedHost{Path: "/fixture/runtime", PolicyPath: "/fixture/policy", WorkspaceRoots: []string{"/fixture/workspace"}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if proof, err := p.PinDirectHostAfterExit(ctx, host); proof != nil || err == nil || NoSurvivingHost(err) {
		t.Fatal("missing original proof gained an exited empty-roster observation")
	}
	if proof, err := p.PinDirectHostAfterExit(context.Background(), host); proof != nil || err == nil || NoSurvivingHost(err) {
		t.Fatal("unbounded host discovery gained an empty-roster observation")
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if proof, err := p.PinDirectHostAfterExit(expired, host); proof != nil || !errors.Is(err, context.DeadlineExceeded) || NoSurvivingHost(err) {
		t.Fatal("expired original budget became a successful survivor observation")
	}
}
