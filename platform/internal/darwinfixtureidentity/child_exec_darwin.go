//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"context"
	"errors"
	"time"
)

// This state grants no process authority. It keeps the first complete roster's
// creation identity while the parent's fork becomes the selected executable.
type childExecTransition struct {
	anchor   *Proof
	original identity
	target   expectedImage
	pending  error
}

func (s *childExecTransition) checkRoster(roster []identity) error {
	if len(roster) != 1 {
		return failed("fixture_child_roster_count_refused", nil)
	}
	if !sameCreation(s.original, roster[0]) {
		return childScanChanged(s.anchor, s.original, roster[0], nil)
	}
	return nil
}

func (s *childExecTransition) ready(before, after identity, path string, args []string, pathErr, argsErr, afterErr error) (bool, error) {
	if !sameCreation(s.original, before) {
		return false, childScanChanged(s.anchor, s.original, before, nil)
	}
	if afterErr != nil || !sameCreation(s.original, after) {
		return false, childScanChanged(s.anchor, s.original, after, afterErr)
	}
	if !sameIdentity(before, after) {
		// No proof exists yet. Discard reads that crossed the original child's
		// exec, then inspect that same creation again within the original budget.
		s.pending = failed("fixture_child_exec_in_progress", nil)
		return false, nil
	}
	if pathErr != nil {
		return false, failed("fixture_child_path_refused", pathErr)
	}
	if argsErr == nil && matchesArguments(s.target, path, args) {
		return true, nil
	}
	parent := s.anchor.expected
	if path == parent.Path {
		if argsErr != nil {
			// A fork can still expose its parent's image while exec is preparing
			// argv. This is only a wait; unreadable arguments never grant a proof.
			s.pending = failed("fixture_child_arguments_refused", argsErr)
			return false, nil
		}
		if matchesArguments(parent, path, args) {
			s.pending = failed("fixture_child_exec_in_progress", nil)
			return false, nil
		}
	}
	if argsErr != nil {
		return false, failed("fixture_child_arguments_refused", argsErr)
	}
	return false, childRosterMismatch(s.anchor, []expectedImage{s.target}, path, args, -1)
}

// The caller holds the original anchor lock. Final image admission and watch
// registration remain in pinDirectChildrenWithExec after this function returns.
func (p *Proof) awaitExpectedChildExec(ctx context.Context, target expectedImage, roster []identity, frozenRoster bool) (result []identity, resultErr error) {
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, failed("fixture_child_exec_deadline_required", nil)
	}
	if len(roster) != 1 {
		return nil, failed("fixture_child_roster_count_refused", nil)
	}
	state := &childExecTransition{anchor: p, original: roster[0], target: target}
	defer func() {
		if resultErr != nil {
			// Retain the original creation snapshot without replacing any proof
			// or comparison owner already held by the actual failure.
			resultErr = errors.Join(resultErr, &failure{stage: "fixture_child_exec_owner_retained", retained: state})
		}
	}()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return nil, &failure{stage: "fixture_child_exec_incomplete", cause: errors.Join(err, state.pending), retained: state}
		}
		if err := p.event(); err != nil && !errors.Is(err, ErrExited) {
			return nil, err
		}
		if err := state.checkRoster(roster); err != nil {
			return nil, err
		}
		before, err := observe(int(state.original.PID))
		if err != nil {
			return nil, childScanChanged(p, state.original, before, err)
		}
		if !sameCreation(state.original, before) {
			return nil, childScanChanged(p, state.original, before, nil)
		}
		path, pathErr := nativePath(before)
		args, argsErr := nativeArguments(before)
		after, afterErr := observe(int(before.PID))
		ready, err := state.ready(before, after, path, args, pathErr, argsErr, afterErr)
		if err != nil {
			return nil, err
		}
		if ready {
			final, err := refreshChildRoster(frozenRoster, []identity{after}, func() ([]identity, error) {
				return nativeCandidates(p.id.UID, p.id.Unique, p.admission)
			})
			if err != nil {
				return nil, failed("fixture_child_scan_refused", err)
			}
			if !sameRoster([]identity{after}, final) {
				return nil, failed("fixture_child_roster_changed", nil)
			}
			return final, nil
		}
		select {
		case <-ctx.Done():
			continue
		case <-ticker.C:
		}
		roster, err = refreshChildRoster(frozenRoster, roster, func() ([]identity, error) {
			return nativeCandidates(p.id.UID, p.id.Unique, p.admission)
		})
		if err != nil {
			return nil, failed("fixture_child_scan_refused", err)
		}
	}
}
