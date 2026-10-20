//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"context"
	"errors"
	"io"
	"reflect"

	"golang.org/x/sys/unix"
)

var childNotPresent = errors.New("fixture_child_not_present")
var noSurvivingHost = errors.New("fixture_no_surviving_host")

// ChildNotPresent recognizes only the helper's exact pre-admission absence
// result. A joined or wrapped failure may retain cleanup owners and is terminal.
func ChildNotPresent(err error) bool { return err == childNotPresent }

// NoSurvivingHost recognizes only a complete empty scan after the original
// frontend's exact exit. It is not a reuse or readiness assertion.
func NoSurvivingHost(err error) bool { return err == noSurvivingHost }

func singleChildResult(proofs []*Proof, err error) (*Proof, error) {
	if len(proofs) != 0 {
		return proofs[0], err
	}
	if err == nil {
		err = failed("fixture_child_roster_invalid", nil)
	}
	return nil, err
}

func closeFailedChildAdmission(parent *Proof, proofs []*Proof, cause error) error {
	var cleanup error
	for _, proof := range proofs {
		cleanup = errors.Join(cleanup, proof.Close())
	}
	if cleanup != nil {
		// Retain uncertain owners on the original anchor as well as the returned
		// error. A later observation cannot restore authority after this failure.
		parent.cleanup = errors.Join(parent.cleanup, cleanup)
		parent.valid = false
	}
	return errors.Join(cause, cleanup)
}

// pinDirectChildren admits the complete expected direct-child roster. A child
// is discovered through immutable native creation lineage, never a caller PID.
// Role admission requires its original host to remain live throughout the scan.
// Returned proofs must each be closed by the caller after exact exit evidence.
func (p *Proof) pinDirectChildren(ctx context.Context, expected []expectedImage, inspection ...*InspectionSelection) (proofs []*Proof, result error) {
	return p.pinDirectChildrenWithPolicy(ctx, expected, false, false, true, inspection...)
}

func (p *Proof) pinDirectChildrenWithExec(ctx context.Context, expected []expectedImage, initialExec bool) (proofs []*Proof, result error) {
	return p.pinDirectChildrenWithPolicy(ctx, expected, initialExec, false, false)
}

func (p *Proof) pinDirectChildrenWithPolicy(ctx context.Context, expected []expectedImage, initialExec, allowEmptyExited, liveHost bool, inspection ...*InspectionSelection) (proofs []*Proof, result error) {
	if ctx == nil {
		return nil, failed("fixture_context_invalid", nil)
	}
	if err := ctx.Err(); err != nil {
		return nil, failed("fixture_child_scan_cancelled", err)
	}
	if p == nil || p.proofState == nil || len(expected) == 0 || len(expected) > 32 {
		return nil, failed("fixture_child_roster_invalid", nil)
	}
	copyExpected := make([]expectedImage, len(expected))
	for i, item := range expected {
		copyExpected[i] = expectedImage{Path: item.Path, Digest: item.Digest, argv0: item.argv0, Args: append([]string(nil), item.Args...), host: item.host, assembly: item.assembly, stableFrontend: item.stableFrontend, clientImage: item.clientImage, inspection: item.inspection}
	}
	expected = copyExpected
	p.mu.Lock()
	defer p.mu.Unlock()
	anchorState := p.event()
	if anchorState != nil && !errors.Is(anchorState, ErrExited) {
		return nil, anchorState
	}
	if allowEmptyExited && anchorState != ErrExited {
		return nil, failed("fixture_host_exit_required", nil)
	}
	scan := func() ([]identity, error) {
		if liveHost {
			return p.liveHostCandidates(ctx)
		}
		return nativeCandidates(p.id.UID, p.id.Unique, p.admission)
	}
	if len(inspection) > 1 || (len(inspection) != 0 && (!liveHost || inspection[0] == nil)) {
		return nil, failed("fixture_inspection_selection_invalid", nil)
	}
	if len(inspection) == 1 {
		fullScan := scan
		scan = func() ([]identity, error) {
			return p.scanRolesWithInspections(ctx, expected, inspection[0], fullScan)
		}
	}
	candidates, err := scan()
	if err != nil {
		return nil, failed("fixture_child_scan_refused", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, failed("fixture_child_scan_cancelled", err)
	}
	if len(candidates) == 0 {
		if liveHost {
			return nil, failed("fixture_child_roster_count_refused", nil)
		}
		return nil, emptyChildRosterResult(anchorState, allowEmptyExited)
	}
	if len(candidates) != len(expected) {
		return nil, failed("fixture_child_roster_count_refused", nil)
	}
	// Only this original, complete scan may establish a closed creation roster.
	// An anchor that exits later cannot retroactively close an earlier scan.
	frozenRoster := freezeCompletedChildRoster(initialExec, anchorState, candidates, len(expected), err)
	if initialExec {
		if len(expected) != 1 {
			return nil, failed("fixture_child_roster_invalid", nil)
		}
		candidates, err = p.awaitExpectedChildExec(ctx, expected[0], candidates, frozenRoster)
		if err != nil {
			return nil, err
		}
	}
	for i := range expected {
		for j := 0; j < i; j++ {
			if reflect.DeepEqual(expected[i], expected[j]) {
				return nil, failed("fixture_child_roster_ambiguous", nil)
			}
		}
	}
	retained := false
	defer func() {
		if !retained {
			result = closeFailedChildAdmission(p, proofs, result)
		}
	}()
	used := make([]bool, len(expected))
	for _, candidate := range candidates {
		child, err := p.pinCandidate(ctx, candidate, expected, used)
		if child != nil {
			proofs = append(proofs, child)
		}
		if err != nil {
			return proofs, err
		}
	}
	checked := make(map[*assemblyOwner]bool)
	for _, child := range proofs {
		if child.assembly != nil && !checked[child.assembly] {
			checked[child.assembly] = true
			if err := child.assembly.revalidate(ctx); err != nil {
				return proofs, err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return proofs, failed("fixture_child_scan_cancelled", err)
	}
	if err := verifyFinalChildRoster(candidates, frozenRoster, scan, func() error {
		if liveHost {
			if err := p.live(); err != nil {
				return err
			}
		} else {
			if err := p.event(); err != nil && !errors.Is(err, ErrExited) {
				return err
			}
		}
		// Every known child must still pass its watch and strict native identity
		// check. A closed roster never turns child exit or exec into admission.
		for _, child := range proofs {
			if err := child.Live(); err != nil {
				return err
			}
		}
		if liveHost {
			if err := p.live(); err != nil {
				return err
			}
		}
		if err := ctx.Err(); err != nil {
			return failed("fixture_child_scan_cancelled", err)
		}
		return nil
	}); err != nil {
		return proofs, err
	}
	retained = true
	return proofs, nil
}

func emptyChildRosterResult(anchorState error, allowEmptyExited bool) error {
	if allowEmptyExited {
		if anchorState == ErrExited {
			return noSurvivingHost
		}
		return failed("fixture_host_exit_required", nil)
	}
	if anchorState == nil {
		return childNotPresent
	}
	return failed("fixture_child_roster_count_refused", nil)
}

func freezeCompletedChildRoster(initialExec bool, anchorBeforeScan error, candidates []identity, expectedCount int, scanErr error) bool {
	return initialExec && anchorBeforeScan == ErrExited && scanErr == nil && expectedCount > 0 && len(candidates) == expectedCount
}

// The original parent cannot create more children after its exact exit. A
// complete scan made after that exit remains the full creation roster; later
// checks must inspect those same children, rather than unrelated UID activity.
func refreshChildRoster(frozen bool, known []identity, scan func() ([]identity, error)) ([]identity, error) {
	if frozen {
		return append([]identity(nil), known...), nil
	}
	return scan()
}

func verifyFinalChildRoster(known []identity, frozen bool, scan func() ([]identity, error), checkChildren func() error) error {
	after, err := refreshChildRoster(frozen, known, scan)
	if err != nil || !sameRoster(known, after) {
		return failed("fixture_child_roster_changed", err)
	}
	return checkChildren()
}

// Only equality results are exported; native identities remain private.
func childScanChanged(parent *Proof, before, after identity, cause error) error {
	d := ChildScanDiagnostic{Reason: "native_observation_refused"}
	detail := failed("fixture_child_scan_observation_refused", cause)
	if cause == nil {
		d = ChildScanDiagnostic{Reason: "identity_changed", IdentityCompared: true,
			PIDMatched: before.PID == after.PID, VersionMatched: before.Version == after.Version,
			CreationMatched: before.Unique == after.Unique, CreationParentMatched: before.ParentUnique == after.ParentUnique,
			UIDMatched: before.UID == after.UID, RealUIDMatched: before.RealUID == after.RealUID}
		detail = failed("fixture_child_scan_identity_changed", nil)
	}
	return &failure{stage: "fixture_child_scan_changed", cause: detail, retained: &childScanOwner{anchor: parent, diagnostic: d}}
}

// This records only comparisons against the original admitted images and argv.
func childRosterMismatch(parent *Proof, expected []expectedImage, path string, args []string, matchedSlot int) error {
	d := ChildRosterDiagnostic{ExpectedCount: len(expected), ObservedArguments: len(args), ExpectedArguments: -1, FirstDifferentArgument: -1}
	if parent != nil && parent.proofState != nil {
		d.ParentImageMatched = path == parent.expected.Path
		d.ParentArgumentsMatched = reflect.DeepEqual(args, parent.expected.literalArguments())
	}
	if matchedSlot >= 0 {
		d.Reason = "duplicate_expected_slot"
		d.ExpectedImageMatched = true
	} else {
		d.Reason = "executable_path_mismatch"
		for _, item := range expected {
			if path == item.Path {
				d.ExpectedImageMatched = true
				d.Reason = "literal_arguments_mismatch"
				break
			}
		}
	}
	if len(expected) == 1 && expected[0].host == nil {
		want := expected[0].literalArguments()
		d.ExpectedArguments = len(want)
		for i := 0; i < min(len(want), len(args)); i++ {
			if want[i] != args[i] {
				d.FirstDifferentArgument = i
				break
			}
		}
		if d.FirstDifferentArgument < 0 && len(want) != len(args) {
			d.FirstDifferentArgument = min(len(want), len(args))
		}
	}
	return &failure{stage: "fixture_child_roster_unexpected", retained: &childMismatchOwner{anchor: parent, diagnostic: d}}
}
func sameRoster(a, b []identity) bool {
	if len(a) != len(b) {
		return false
	}
	for i, x := range a {
		for j := 0; j < i; j++ {
			if sameIdentity(x, a[j]) {
				return false
			}
		}
		found := false
		for _, y := range b {
			if sameIdentity(x, y) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Close consumes this proof's watch and protected descriptor exactly once.
// Direct-child proofs are normally released by Owned.Close after Join.
func (p *Proof) Close() error {
	if p == nil || p.proofState == nil {
		return nil
	}
	return p.close()
}

// Pin one observed candidate with the same image, argv, identity and watch
// checks used by complete role admission. A partial proof always returns.
func (p *Proof) pinCandidate(ctx context.Context, candidate identity, expected []expectedImage, used []bool) (child *Proof, result error) {
	if err := ctx.Err(); err != nil {
		return child, failed("fixture_child_scan_cancelled", err)
	}
	start, err := observe(int(candidate.PID))
	if err != nil || !sameIdentity(candidate, start) {
		return child, childScanChanged(p, candidate, start, err)
	}
	path, err := nativePath(start)
	if err != nil {
		return child, failed("fixture_child_path_refused", err)
	}
	args, err := nativeArguments(start)
	if err != nil {
		return child, failed("fixture_child_arguments_refused", err)
	}
	match := -1
	for i, item := range expected {
		if matchesArguments(item, path, args) {
			if match != -1 {
				return child, failed("fixture_child_roster_ambiguous", nil)
			}
			match = i
		}
	}
	if match < 0 || used[match] {
		return child, childRosterMismatch(p, expected, path, args, match)
	}
	item := expected[match]
	item.Args = append([]string(nil), args[1:]...)
	item.host = nil
	used[match] = true
	var image io.Closer
	if item.inspection != nil {
		if err := item.inspection.recheck(ctx); err != nil {
			return child, err
		}
		item.inspection.retain()
		image = item.inspection
	} else if item.clientImage != nil {
		if err := item.clientImage.recheck(ctx); err != nil {
			return child, failed("fixture_service_image_refused", err)
		}
		item.clientImage.retain()
		image = item.clientImage
	} else if item.assembly == nil {
		image, err = prepareLaunchImage(ctx, Launch{Path: item.Path, Digest: item.Digest}, item.stableFrontend)
		if err != nil {
			return child, failed("fixture_child_image_refused", err)
		}
	}
	queue, err := unix.Kqueue()
	if err != nil {
		return child, errors.Join(failed("fixture_child_watch_unavailable", err), safeClose(image, "fixture_child_image_close_failed"))
	}
	unix.CloseOnExec(queue)
	child = &Proof{proofState: &proofState{id: start, queue: queue, watchOwned: true, expected: expectedImage{Path: item.Path, Digest: item.Digest, argv0: item.argv0, Args: append([]string(nil), item.Args...), host: item.host, assembly: item.assembly}, image: image, assembly: item.assembly, admission: p.admission}}
	if item.assembly != nil {
		item.assembly.retain()
	}
	if registrationErr := registerProcessWatch(queue, start); registrationErr != nil {
		return child, registrationErr
	}
	after, err := observe(int(start.PID))
	if err != nil || !sameIdentity(start, after) {
		return child, failed("fixture_child_identity_changed", err)
	}
	zero := unix.Timespec{}
	var events [1]unix.Kevent_t
	n, err := pollWatch(func() (int, error) { return unix.Kevent(queue, nil, events[:], &zero) })
	if err != nil || n != 0 {
		return child, failed("fixture_child_admission_event_refused", err)
	}
	pathAfter, pathErr := nativePath(start)
	argsAfter, argsErr := nativeArguments(start)
	final, finalErr := observe(int(start.PID))
	if pathErr != nil || argsErr != nil || finalErr != nil || pathAfter != path || !reflect.DeepEqual(args, argsAfter) || !sameIdentity(start, final) {
		return child, failed("fixture_child_postwatch_admission_refused", errors.Join(pathErr, argsErr, finalErr))
	}
	if item.inspection != nil {
		if err := item.inspection.recheck(ctx); err != nil {
			return child, err
		}
	} else if item.clientImage != nil {
		if err := item.clientImage.recheck(ctx); err != nil {
			return child, failed("fixture_service_postwatch_image_refused", err)
		}
	} else if item.assembly == nil {
		fresh, imageErr := prepareLaunchImage(ctx, Launch{Path: item.Path, Digest: item.Digest}, item.stableFrontend)
		if imageErr != nil {
			return child, failed("fixture_child_postwatch_image_refused", imageErr)
		}
		if closeErr := safeClose(fresh, "fixture_child_postwatch_image_close_failed"); closeErr != nil {
			return child, closeErr
		}
		if item.stableFrontend {
			if recheckErr := image.(interface{ Recheck(context.Context) error }).Recheck(ctx); recheckErr != nil {
				return child, failed("fixture_child_postwatch_image_refused", recheckErr)
			}
		}
	}
	child.valid = true
	return child, nil
}
