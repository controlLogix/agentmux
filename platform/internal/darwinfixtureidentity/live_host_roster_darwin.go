//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import "context"

// The caller holds the original host proof's mutex. Current PPID selects only
// candidates; the retained watch and immutable identities establish lineage.
func (p *Proof) liveHostCandidates(ctx context.Context) ([]identity, error) {
	if p.admission == nil {
		return nil, failed("fixture_candidate_admission_invalid", nil)
	}
	if err := p.admission.check(); err != nil {
		return nil, failed("fixture_candidate_admission_refused", err)
	}
	return scanLiveHostChildren(ctx, p.id, p.liveIdentity, nativeChildPIDs, readNativeIdentity)
}

func scanLiveHostChildren(ctx context.Context, anchor identity, host func() (identity, error), list func(int32) ([]int32, error), read func(int) (identity, error)) ([]identity, error) {
	if ctx == nil {
		return nil, failed("fixture_context_invalid", nil)
	}
	checkHost := func() error {
		if err := ctx.Err(); err != nil {
			return failed("fixture_child_scan_cancelled", err)
		}
		current, err := host()
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return failed("fixture_child_scan_cancelled", err)
		}
		if anchor.PID <= 0 || anchor.Unique == 0 || anchor.Version == 0 || !sameIdentity(anchor, current) {
			return failed("fixture_live_host_identity_refused", nil)
		}
		return liveIdentityStatus(current)
	}
	if err := checkHost(); err != nil {
		return nil, err
	}
	pids, err := list(anchor.PID)
	if err != nil {
		return nil, err
	}
	children := make([]identity, 0, len(pids))
	seen := make(map[int32]bool, len(pids))
	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			return nil, failed("fixture_child_scan_cancelled", err)
		}
		if pid <= 0 || seen[pid] {
			return nil, failed("fixture_candidate_enumeration_refused", nil)
		}
		seen[pid] = true
		child, err := read(int(pid))
		if err != nil {
			if nativeIdentityQueryAbsent(err) {
				continue
			}
			return nil, failed("fixture_candidate_identity_refused", err)
		}
		if child.PID != pid || child.Unique == 0 || child.Version == 0 || child.ParentPID != anchor.PID || child.ParentUnique != anchor.Unique {
			return nil, failed("fixture_candidate_identity_refused", failed("fixture_candidate_lineage_refused", nil))
		}
		if child.UID != anchor.UID || child.RealUID != anchor.RealUID {
			return nil, failed("fixture_candidate_identity_refused", failed("fixture_candidate_credentials_refused", nil))
		}
		if err := liveIdentityStatus(child); err != nil {
			return nil, failed("fixture_candidate_identity_refused", err)
		}
		children = append(children, child)
	}
	if err := checkHost(); err != nil {
		return nil, err
	}
	return children, nil
}
