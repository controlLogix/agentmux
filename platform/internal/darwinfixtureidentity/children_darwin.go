//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"context"
	"errors"
	"reflect"

	protected "github.com/controlLogix/agentmux/platform/runtime"
	"golang.org/x/sys/unix"
)

// pinDirectChildren admits the complete expected direct-child roster. A child
// is discovered through immutable native creation lineage, never a caller PID.
// The anchor may have exited and been reparented; an observed exec invalidates it.
// Returned proofs must each be closed by the caller after exact exit evidence.
func (p *Proof) pinDirectChildren(ctx context.Context, expected []expectedImage) (proofs []*Proof, result error) {
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
		copyExpected[i] = expectedImage{Path: item.Path, Digest: item.Digest, argv0: item.argv0, Args: append([]string(nil), item.Args...), host: item.host, assembly: item.assembly}
	}
	expected = copyExpected
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.event(); err != nil && !errors.Is(err, ErrExited) {
		return nil, err
	}
	candidates, err := nativeCandidates(p.id.UID, p.id.Unique, p.admission)
	if err != nil {
		return nil, failed("fixture_child_scan_refused", err)
	}
	if len(candidates) != len(expected) {
		return nil, failed("fixture_child_roster_count_refused", nil)
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
			for _, proof := range proofs {
				result = errors.Join(result, proof.Close())
			}

		}
	}()
	used := make([]bool, len(expected))
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return proofs, failed("fixture_child_scan_cancelled", err)
		}
		start, err := observe(int(candidate.PID))
		if err != nil || !sameIdentity(candidate, start) {
			return proofs, failed("fixture_child_scan_changed", err)
		}
		path, err := nativePath(start)
		if err != nil {
			return proofs, failed("fixture_child_path_refused", err)
		}
		args, err := nativeArguments(start)
		if err != nil {
			return proofs, failed("fixture_child_arguments_refused", err)
		}
		match := -1
		for i, item := range expected {
			if matchesArguments(item, path, args) {
				if match != -1 {
					return proofs, failed("fixture_child_roster_ambiguous", nil)
				}
				match = i
			}
		}
		if match < 0 || used[match] {
			return proofs, failed("fixture_child_roster_unexpected", nil)
		}
		item := expected[match]
		item.Args = append([]string(nil), args[1:]...)
		item.host = nil
		used[match] = true
		var image *protected.InstalledHostImage
		if item.assembly == nil {
			image, err = protected.PrepareProtectedInstalledHost(ctx, item.Path, item.Digest, 128*1024*1024)
			if err != nil {
				return proofs, failed("fixture_child_image_refused", err)
			}
		}
		queue, err := unix.Kqueue()
		if err != nil {
			return proofs, errors.Join(failed("fixture_child_watch_unavailable", err), safeClose(image, "fixture_child_image_close_failed"))
		}
		unix.CloseOnExec(queue)
		child := &Proof{proofState: &proofState{id: start, queue: queue, watchOwned: true, expected: expectedImage{Path: item.Path, Digest: item.Digest, argv0: item.argv0, Args: append([]string(nil), item.Args...), host: item.host, assembly: item.assembly}, image: image, assembly: item.assembly, admission: p.admission}}
		if item.assembly != nil {
			item.assembly.retain()
		}
		proofs = append(proofs, child)
		change := []unix.Kevent_t{{Ident: uint64(start.PID), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT | unix.NOTE_EXEC}}
		zero := unix.Timespec{}
		var events [1]unix.Kevent_t
		n, err := unix.Kevent(queue, change, events[:], &zero)
		if err != nil || n != 0 {
			return proofs, failed("fixture_child_watch_registration_refused", err)
		}
		after, err := observe(int(start.PID))
		if err != nil || !sameIdentity(start, after) {
			return proofs, failed("fixture_child_identity_changed", err)
		}
		n, err = unix.Kevent(queue, nil, events[:], &zero)
		if err != nil || n != 0 {
			return proofs, failed("fixture_child_admission_event_refused", err)
		}
		pathAfter, pathErr := nativePath(start)
		argsAfter, argsErr := nativeArguments(start)
		final, finalErr := observe(int(start.PID))
		if pathErr != nil || argsErr != nil || finalErr != nil || pathAfter != path || !reflect.DeepEqual(args, argsAfter) || !sameIdentity(start, final) {
			return proofs, failed("fixture_child_postwatch_admission_refused", errors.Join(pathErr, argsErr, finalErr))
		}
		if item.assembly == nil {
			fresh, imageErr := protected.PrepareProtectedInstalledHost(ctx, item.Path, item.Digest, 128*1024*1024)
			if imageErr != nil {
				return proofs, failed("fixture_child_postwatch_image_refused", imageErr)
			}
			if closeErr := safeClose(fresh, "fixture_child_postwatch_image_close_failed"); closeErr != nil {
				return proofs, closeErr
			}
		}
		child.valid = true
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
	after, err := nativeCandidates(p.id.UID, p.id.Unique, p.admission)
	if err != nil || !sameRoster(candidates, after) {
		return proofs, failed("fixture_child_roster_changed", err)
	}
	if err := p.event(); err != nil && !errors.Is(err, ErrExited) {
		return proofs, err
	}
	// Fence the PID-only argv reads and the complete scan with live identity
	// checks on every admitted child after every watch has been registered.
	for _, child := range proofs {
		if err := child.Live(); err != nil {
			return proofs, err
		}
	}
	retained = true
	return proofs, nil
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
