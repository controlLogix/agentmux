//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"context"
	"errors"
)

type inspectionChildClass struct {
	role        int
	target      expectedImage
	observation *inspectionObservation
}

// This owner never adopts subprocess waits or output readers. It retains every
// temporary native proof, including incomplete admission or exit observation.
type inspectionRosterOwner struct {
	anchor       *Proof
	roles        []identity
	proofs       []*Proof
	observations []*inspectionObservation
}

func terminalInspectionObservation(candidate identity, observation *inspectionObservation) bool {
	return observation != nil && observation.bound && observation.exited && observation.closed && !observation.transferred && observation.failure == nil && observation.cleanup == nil && sameIdentity(observation.id, candidate)
}

func (s *inspectionRosterOwner) closeUntransferredObservations() error {
	var cleanup error
	for _, observation := range s.observations {
		cleanup = errors.Join(cleanup, observation.close())
	}
	return cleanup
}

// Finish scan-local observation ownership even when binding or classification
// refused admission. Transferred proofs retain their separate lifetime owner.
func (s *inspectionRosterOwner) finishScan(roles []identity, cause error) ([]identity, error) {
	if cleanup := s.closeUntransferredObservations(); cleanup != nil {
		return nil, &failure{stage: "fixture_inspection_owner_retained", cause: errors.Join(cause, cleanup), retained: s}
	}
	return roles, cause
}

func (p *Proof) scanRolesWithInspections(ctx context.Context, expected []expectedImage, selection *InspectionSelection, scan func() ([]identity, error)) (roles []identity, resultErr error) {
	state := &inspectionRosterOwner{anchor: p}
	p.auxiliary = append(p.auxiliary, state)
	defer func() { roles, resultErr = state.finishScan(roles, resultErr) }()
	classify := func(candidate identity) (inspectionChildClass, error) {
		observation, err := bindInspectionObservation(candidate, func(o *inspectionObservation) { state.observations = append(state.observations, o) })
		if err != nil {
			return inspectionChildClass{}, err
		}
		path, args, terminal, err := observation.read(ctx)
		if err != nil {
			observation.failure = err
			return inspectionChildClass{}, err
		}
		if terminal {
			return inspectionChildClass{role: -2, observation: observation}, observation.close()
		}
		class, err := classifyInspectionObservation(p, expected, selection, candidate, candidate, path, args, nil, nil, nil)
		if err != nil {
			observation.failure = err
			return inspectionChildClass{}, err
		}
		class.observation = observation
		if class.role >= 0 {
			err = observation.close()
		}
		return class, err
	}
	return drainRoleInspections(ctx, state, len(expected), scan, classify,
		func(candidate identity, class inspectionChildClass) (inspectionPinResult, error) {
			return p.pinWatchedInspection(ctx, candidate, class)
		}, func(proof *Proof) error { return proof.WaitExit(ctx) },
		func(proof *Proof) error { return proof.Close() }, p.live)
}

func drainRoleInspections(ctx context.Context, state *inspectionRosterOwner, count int,
	scan func() ([]identity, error), classify func(identity) (inspectionChildClass, error),
	pin func(identity, inspectionChildClass) (inspectionPinResult, error), wait func(*Proof) error, closeProof func(*Proof) error,
	checkHost func() error) (roles []identity, resultErr error) {
	defer func() {
		if resultErr != nil {
			resultErr = &failure{stage: "fixture_inspection_owner_retained", cause: resultErr, retained: state}
		}
	}()
	if ctx == nil {
		return nil, failed("fixture_context_invalid", nil)
	}
	if _, finite := ctx.Deadline(); !finite {
		return nil, failed("fixture_child_exec_deadline_required", nil)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkHost(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	roster, err := scan()
	if err != nil {
		return nil, err
	}
	roleRoster := make([]identity, count)
	seen := make([]bool, count)
	var transients []struct {
		id    identity
		class inspectionChildClass
	}
	for _, candidate := range roster {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		class, err := classify(candidate)
		if err != nil {
			return nil, err
		}
		if class.role >= 0 {
			if class.role >= count || seen[class.role] {
				return nil, failed("fixture_child_roster_ambiguous", nil)
			}
			seen[class.role], roleRoster[class.role] = true, candidate
		} else if class.role == -2 && terminalInspectionObservation(candidate, class.observation) {
			// The original watched child is terminal. This says nothing
			// about its image, arguments or successful inspection admission.
		} else if class.role == -1 && class.target.inspection != nil {
			transients = append(transients, struct {
				id    identity
				class inspectionChildClass
			}{candidate, class})
		} else {
			return nil, failed("fixture_child_roster_unexpected", nil)
		}
	}
	for _, present := range seen {
		if !present {
			return nil, failed("fixture_child_roster_count_refused", nil)
		}
	}
	if state.roles == nil {
		state.roles = append([]identity(nil), roleRoster...)
	}
	if !sameRoster(state.roles, roleRoster) {
		return nil, failed("fixture_child_roster_changed", nil)
	}
	if err := checkHost(); err != nil {
		return nil, err
	}
	if len(transients) == 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return roleRoster, nil
	}
	var current []*Proof
	for _, transient := range transients {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		admitted, err := pin(transient.id, transient.class)
		proof := admitted.proof
		if proof != nil {
			state.proofs = append(state.proofs, proof)
			current = append(current, proof)
		}
		if err != nil {
			return nil, err
		}
		if proof == nil && (!admitted.terminal || !terminalInspectionObservation(transient.id, transient.class.observation)) {
			return nil, failed("fixture_inspection_proof_missing", nil)
		}
	}
	for _, proof := range current {
		if err := wait(proof); err != nil {
			return nil, err
		}
		if err := closeProof(proof); err != nil {
			return nil, err
		}
	}
	// The caller compares its initial and final role census. New legitimate
	// inspections may start between them; no globally quiet snapshot is needed.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkHost(); err != nil {
		return nil, err
	}
	return roleRoster, nil
}

func classifyInspectionObservation(p *Proof, expected []expectedImage, selection *InspectionSelection, before, after identity, path string, args []string, pathErr, argsErr, afterErr error) (inspectionChildClass, error) {
	if pathErr != nil || argsErr != nil || afterErr != nil || !sameIdentity(before, after) {
		return inspectionChildClass{}, failed("fixture_inspection_observation_refused", errors.Join(pathErr, argsErr, afterErr))
	}
	matched := -1
	for i, item := range expected {
		if matchesArguments(item, path, args) {
			if matched != -1 {
				return inspectionChildClass{}, failed("fixture_child_roster_ambiguous", nil)
			}
			matched = i
		}
	}
	if matched >= 0 {
		return inspectionChildClass{role: matched}, nil
	}
	if target, ok := selection.target(args); ok && path == target.Path {
		return inspectionChildClass{role: -1, target: target}, nil
	}
	// An inherited host image is still unclassified. No new fork/exec
	// inference or weaker creation-only match is introduced on this path.
	return inspectionChildClass{}, childRosterMismatch(p, expected, path, args, -1)
}
