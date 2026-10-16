//go:build darwin && cgo && agentmux_bootstrap_docker && ((agentmux_darwin_identity_candidate && agentmux_darwin_identity_protected_candidate && !agentmux_darwin_identity_protected_normal) || (agentmux_darwin_identity_protected_normal && !agentmux_darwin_identity_candidate && !agentmux_darwin_identity_protected_candidate))

package darwinfixtureidentity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/controlLogix/agentmux/platform/kernel/assembly"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

// These controls require a separately installed immutable fixture. They neither
// install it nor qualify product startup, authentication or release signing.
func protectedCandidateJoin(t *testing.T, child *Owned, wantSuccess bool) (Completion, bool) {
	t.Helper()
	return protectedCandidateJoinUntil(t, child, wantSuccess, time.Now().Add(17*time.Second))
}

func protectedCandidateJoinUntil(t *testing.T, child *Owned, wantSuccess bool, deadline time.Time) (Completion, bool) {
	t.Helper()
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	completion, err := child.Join(ctx)
	if err != nil {
		t.Error("protected_candidate_join_incomplete")
		return completion, false
	}
	if (completion.Err == nil) != wantSuccess {
		t.Error("protected_candidate_completion_refused")
	}
	if completion.Stdout.Overflow || completion.Stderr.Overflow || completion.Stdout.Err != nil || completion.Stderr.Err != nil {
		t.Error("protected_candidate_output_incomplete")
	}
	return completion, true
}

// Close is attempted only after the exact original Wait has completed. A failed
// join leaves the owned handle intact and records uncertainty without guessing.
func protectedCandidateCleanupOwned(t *testing.T, child *Owned, wantSuccess bool) {
	t.Helper()
	if _, joined := protectedCandidateJoin(t, child, wantSuccess); !joined {
		t.Error("protected_candidate_unjoined_owner_retained")
		return
	}
	if child.Close() != nil {
		t.Error("protected_candidate_owned_close_failed")
	}
}

func runProtectedCandidateLoaderAdmission(t *testing.T) {
	_, path, digest := protectedControlInput(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	image, err := protected.PrepareProtectedInstalledHost(ctx, path, digest, 128*1024*1024)
	if err != nil || image == nil {
		t.Fatal("protected_candidate_direct_loader_refused")
	}
	defer func() {
		if image.Close() != nil {
			t.Error("protected_candidate_direct_loader_close_failed")
		}
	}()
	input, _ := protectedCandidateAssembly(t, path, digest, "0")
	prepared, err := protected.Prepare(ctx, input.Raw, input.PackageDir, input.Trust, protected.Limits{MaxBinaryBytes: 128 * 1024 * 1024})
	if err != nil || prepared == nil {
		t.Fatal("protected_candidate_role_loader_refused")
	}
	defer func() {
		if prepared.Close() != nil {
			t.Error("protected_candidate_role_loader_close_failed")
		}
	}()
	// Both owners remain held together: one direct image and four role images.
	// No StartHost, role Start, or creator StartProtected call occurs here.
	t.Log("protected_candidate_loader_images=5")
}

func runProtectedCandidateFastCompletion(t *testing.T) {
	creator, path, digest := protectedControlInput(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	child, startErr := creator.StartProtected(ctx, Launch{Path: path, Digest: digest, Args: []string{"fast-exit"}, Env: []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}})
	if child != nil {
		t.Cleanup(func() { protectedCandidateCleanupOwned(t, child, true) })
	}
	if startErr != nil || child == nil {
		t.Fatal("protected_candidate_fast_start_refused")
	}
	completion, joined := protectedCandidateJoin(t, child, true)
	if !joined {
		t.Fatal("protected_candidate_fast_join_unconfirmed")
	}
	if string(completion.Stdout.Bytes) != "fixture_complete\n" || len(completion.Stderr.Bytes) != 0 {
		t.Error("protected_candidate_fast_output_refused")
	}
	proof, err := child.Pin(ctx)
	if err == nil && proof != nil && proof.Live() == nil {
		t.Error("protected_candidate_exited_proof_live")
	}
}

func runProtectedCandidateWrongDigest(t *testing.T) {
	creator, path, digest := protectedControlInput(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	baseline, baselineErr := protected.PrepareProtectedInstalledHost(ctx, path, digest, 128*1024*1024)
	if baselineErr != nil || baseline == nil {
		t.Fatal("protected_candidate_wrong_digest_baseline_refused")
	}
	if baseline.Close() != nil {
		t.Fatal("protected_candidate_wrong_digest_baseline_close_failed")
	}
	child, err := creator.StartProtected(ctx, Launch{Path: path, Digest: "sha256:" + strings.Repeat("0", 64), Args: []string{"fast-exit"}})
	if child != nil {
		t.Cleanup(func() { protectedCandidateCleanupOwned(t, child, true) })
		t.Error("protected_candidate_wrong_digest_spawned")
	}
	var refusal *failure
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("protected_candidate_wrong_digest_context_expired")
	}
	if !errors.As(err, &refusal) || refusal.stage != "fixture_protected_image_refused" || refusal.cause == nil || refusal.cause.Error() != "installed_host_protected_image_invalid" {
		t.Fatal("protected_candidate_wrong_digest_refusal_mismatch")
	}
	// The runtime deliberately hides the digest-specific private cause. Admit
	// the same path again to rule out a persistent unrelated admission failure.
	after, afterErr := protected.PrepareProtectedInstalledHost(ctx, path, digest, 128*1024*1024)
	if afterErr != nil || after == nil {
		t.Fatal("protected_candidate_wrong_digest_postcheck_refused")
	}
	if after.Close() != nil {
		t.Fatal("protected_candidate_wrong_digest_postcheck_close_failed")
	}
	if ctx.Err() != nil {
		t.Fatal("protected_candidate_wrong_digest_context_expired")
	}
}

func runProtectedCandidateInvalidArguments(t *testing.T) {
	creator, path, digest := protectedControlInput(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	child, startErr := creator.StartProtected(ctx, Launch{Path: path, Digest: digest, Args: []string{"invalid-command"}, Env: []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}})
	if child != nil {
		t.Cleanup(func() { protectedCandidateCleanupOwned(t, child, false) })
	}
	if startErr != nil || child == nil {
		t.Fatal("protected_candidate_invalid_start_refused")
	}
	completion, joined := protectedCandidateJoin(t, child, false)
	if !joined {
		t.Fatal("protected_candidate_invalid_join_unconfirmed")
	}
	var refusal *exec.ExitError
	if !errors.As(completion.Err, &refusal) || refusal.ExitCode() != 70 || string(completion.Stderr.Bytes) != "fixture_mode_invalid\n" || len(completion.Stdout.Bytes) != 0 {
		t.Error("protected_candidate_invalid_refusal_evidence_mismatch")
	}
}

type protectedCandidateFamily struct {
	child                                     *Owned
	frontendGate, familyGate                  *os.File
	frontendProof, host                       *Proof
	roles                                     []*Proof
	observations                              []*protectedCandidateObservation
	hostObservation                           *protectedCandidateObservation
	cleanupReceipt                            *os.File
	cleanupReceiptCloseAttempted              bool
	absoluteDeadline                          time.Time
	policy, workspace, path, digest, deadline string
	assembly                                  Assembly
	args                                      map[string][]string
}

func (family *protectedCandidateFamily) cleanup(t *testing.T) {
	t.Helper()
	started := time.Now()
	deadline, budgetErr := cleanupBudget(started, family.absoluteDeadline)
	if budgetErr != nil {
		t.Error("protected_candidate_cleanup_deadline_margin_refused")
	}
	for _, gate := range []*os.File{family.frontendGate, family.familyGate} {
		if gate != nil {
			if err := gate.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				t.Error("protected_candidate_gate_close_failed")
			}
		}
	}
	joined := family.child == nil
	if family.child != nil {
		_, joined = protectedCandidateJoinUntil(t, family.child, true, deadline)
	}
	family.readCleanupReceipt(t, deadline)
	for _, observation := range family.observations {
		observation.finish(t, deadline)
	}
	if family.hostObservation != nil {
		family.hostObservation.finish(t, deadline)
	}
	for _, proof := range append(append([]*Proof{}, family.roles...), family.host) {
		if proof == nil {
			continue
		}
		// Failed admission may return an already consumed cleanup handle.
		proof.mu.Lock()
		consumed := proof.closed
		proof.mu.Unlock()
		if !consumed {
			ctx, cancel := context.WithDeadline(context.Background(), deadline)
			err := proof.WaitExit(ctx)
			cancel()
			if err != nil {
				t.Error("protected_candidate_exit_unconfirmed_watch_retained")
				continue
			}
		}
		if proof.Close() != nil {
			t.Error("protected_candidate_proof_close_failed")
		}
	}
	if family.child != nil {
		if !joined {
			t.Error("protected_candidate_frontend_owner_retained")
		} else if family.child.Close() != nil {
			t.Error("protected_candidate_frontend_close_failed")
		}
	}
	if time.Now().After(deadline) {
		t.Error("protected_candidate_cleanup_shared_deadline_exceeded")
	}
}

func protectedCandidateAssembly(t *testing.T, path, digest, deadline string) (Assembly, map[string][]string) {
	t.Helper()
	authority := assembly.Authority{ID: "fixture_authority", OwnerHubID: "fixture_hub", Revision: 1}
	releaseDigest := "sha256:" + strings.Repeat("a", 64)
	plugins := make([]map[string]string, 0, 4)
	args := make(map[string][]string, 4)
	for _, role := range protocol.Roles() {
		plugins = append(plugins, map[string]string{"id": role, "entrypoint": "bin/" + role, "binaryDigest": digest})
		args[role] = []string{"role", role, deadline}
	}
	raw, err := json.Marshal(map[string]any{"schemaVersion": "1.0.0", "releaseVersion": "1.2.3", "releaseManifestDigest": releaseDigest, "releaseAuthorityRef": authority, "kernelApiMajor": 1, "plugins": plugins})
	if err != nil {
		t.Fatal("protected_candidate_assembly_encode_failed")
	}
	sum := sha256.Sum256(raw)
	// Separate in-memory trust pins these exact fixture bytes; this is not signing.
	trust := assembly.Trust{AssemblyDigest: "sha256:" + hex.EncodeToString(sum[:]), ReleaseManifestDigest: releaseDigest, ReleaseVersion: "1.2.3", ReleaseAuthority: authority, KernelAPIMajor: 1}
	input := Assembly{Raw: raw, PackageDir: filepath.Dir(path), Trust: trust}
	if _, err := assembly.Verify(raw, input.PackageDir, trust); err != nil {
		t.Fatal("protected_candidate_assembly_verification_refused")
	}
	return input, args
}

func protectedCandidateStartFamily(t *testing.T, scenario string) *protectedCandidateFamily {
	t.Helper()
	creator, path, digest := protectedControlInput(t)
	dir := t.TempDir()
	deadline := time.Now().Add(15 * time.Second).UnixNano()
	family := &protectedCandidateFamily{path: path, digest: digest, policy: filepath.Join(dir, "policy.json"), workspace: dir, deadline: strconv.FormatInt(deadline, 10), absoluteDeadline: time.Unix(0, deadline)}
	t.Cleanup(func() { family.cleanup(t) })
	raw, err := json.Marshal(map[string]any{"scenario": scenario, "deadlineUnixNano": deadline})
	if err != nil || os.WriteFile(family.policy, raw, 0600) != nil {
		t.Fatal("protected_candidate_policy_unavailable")
	}
	frontendRead, frontendWrite, err := os.Pipe()
	if err != nil {
		t.Fatal("protected_candidate_frontend_gate_unavailable")
	}
	family.frontendGate = frontendWrite
	familyRead, familyWrite, err := os.Pipe()
	if err != nil {
		if frontendRead.Close() != nil {
			t.Error("protected_candidate_frontend_read_close_failed")
		}
		t.Fatal("protected_candidate_family_gate_unavailable")
	}
	family.familyGate = familyWrite
	cleanupRead, cleanupWrite, err := os.Pipe()
	if err != nil {
		if frontendRead.Close() != nil {
			t.Error("protected_candidate_frontend_read_close_failed")
		}
		if familyRead.Close() != nil {
			t.Error("protected_candidate_family_read_close_failed")
		}
		t.Fatal("protected_candidate_cleanup_receipt_unavailable")
	}
	family.cleanupReceipt = cleanupRead
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	family.child, err = creator.StartProtected(ctx, Launch{Path: path, Digest: digest, Args: []string{"frontend", family.policy, family.workspace}, Env: []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}, ExtraFiles: []*os.File{frontendRead, familyRead, cleanupWrite}})
	closeA, closeB, closeC := frontendRead.Close(), familyRead.Close(), cleanupWrite.Close()
	if closeA != nil || closeB != nil || closeC != nil {
		t.Fatal("protected_candidate_parent_read_close_failed")
	}
	if err != nil || family.child == nil {
		t.Fatal("protected_candidate_frontend_start_refused")
	}
	family.frontendProof, err = family.child.Pin(ctx)
	if err != nil {
		t.Fatal("protected_candidate_frontend_pin_refused")
	}
	// The fixture emits this only after the host completed its role-spawn attempt.
	for {
		output := family.child.out.snapshot()
		if output.Overflow || output.Err != nil {
			t.Fatal("protected_candidate_ready_output_refused")
		}
		if bytes.Equal(output.Bytes, []byte("fixture_ready\n")) {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("protected_candidate_ready_deadline")
		case <-time.After(10 * time.Millisecond):
		}
	}
	family.assembly, family.args = protectedCandidateAssembly(t, path, digest, family.deadline)
	return family
}

func (family *protectedCandidateFamily) pinHost(t *testing.T, expected ExpectedHost) (*Proof, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	proof, err := family.frontendProof.PinDirectHost(ctx, expected)
	if err == nil && proof != nil {
		family.host = proof
		family.watchHostStatus(t, proof)
	}
	return proof, err
}
func (family *protectedCandidateFamily) expectedHost() ExpectedHost {
	return ExpectedHost{Path: family.path, Digest: family.digest, PolicyPath: family.policy, WorkspaceRoots: []string{family.workspace}}
}

func runProtectedCandidateReparentedRoles(t *testing.T) {
	family := protectedCandidateStartFamily(t, "four")
	var err error
	if family.frontendGate.Close() != nil {
		t.Fatal("protected_candidate_frontend_handoff_failed")
	}
	if _, joined := protectedCandidateJoin(t, family.child, true); !joined {
		t.Fatal("protected_candidate_handoff_join_unconfirmed")
	}
	// Discover the host through the retained frontend proof only after exit.
	family.host, err = family.pinHost(t, family.expectedHost())
	if err != nil || family.host == nil {
		t.Fatal("protected_candidate_postexit_host_pin_refused")
	}
	family.watchRoster(t, 4)
	if family.host.Live() != nil {
		t.Fatal("protected_candidate_reparented_host_not_live")
	}
	reparented, observationErr := observe(int(family.host.id.PID))
	if observationErr != nil || !sameIdentity(family.host.id, reparented) || reparented.ParentPID == family.frontendProof.id.PID || reparented.ParentUnique != family.frontendProof.id.Unique {
		t.Fatal("protected_candidate_reparenting_unconfirmed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	family.roles, err = family.host.pinDirectRoles(ctx, family.assembly, family.args, false)
	if err != nil || len(family.roles) != 4 {
		t.Fatal("protected_candidate_roles_pin_refused")
	}
	// Closing both gates and observing every exit is performed by exact cleanup.
}

func runProtectedCandidateHostRefusals(t *testing.T) {
	for _, kind := range []string{"policy", "digest"} {
		t.Run(kind, func(t *testing.T) {
			family := protectedCandidateStartFamily(t, "four")
			expected := family.expectedHost()
			if kind == "policy" {
				expected.PolicyPath += ".wrong"
			} else {
				expected.Digest = "sha256:" + strings.Repeat("0", 64)
			}
			proof, err := family.pinHost(t, expected)
			if proof != nil {
				family.roles = append(family.roles, proof)
			}
			if err == nil {
				t.Fatal("protected_candidate_wrong_host_expectation_accepted")
			}
			family.host, err = family.pinHost(t, family.expectedHost())
			if err != nil || family.host == nil {
				t.Fatal("protected_candidate_host_cleanup_pin_refused")
			}
			family.watchRoster(t, 4)
		})
	}
}

func runProtectedCandidateRoleRosterRefusals(t *testing.T) {
	for _, scenario := range []string{"missing", "extra", "ambiguous"} {
		t.Run(scenario, func(t *testing.T) {
			family := protectedCandidateStartFamily(t, scenario)
			var err error
			family.host, err = family.pinHost(t, family.expectedHost())
			if err != nil || family.host == nil {
				t.Fatal("protected_candidate_negative_host_pin_refused")
			}
			expectedCount := 4
			if scenario == "missing" {
				expectedCount = 3
			} else if scenario == "extra" {
				expectedCount = 5
			}
			family.watchRoster(t, expectedCount)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			family.roles, err = family.host.pinDirectRoles(ctx, family.assembly, family.args, false)
			if err == nil {
				t.Fatal("protected_candidate_invalid_role_roster_accepted")
			}
		})
	}
}

// protectedCandidateObservation is an exit watch only. It cannot signal, inspect
// argv, adopt a public PID, or serve as an image/role proof.
type protectedCandidateObservation struct {
	id                    identity
	queue                 int
	bound, closeAttempted bool
	expectStatus          bool
}

func (family *protectedCandidateFamily) watchRoster(t *testing.T, expectedCount int) {
	t.Helper()
	if family.host == nil || expectedCount < 1 || expectedCount > 5 {
		t.Fatal("protected_candidate_observation_input_refused")
	}
	candidates, err := nativeCandidates(family.host.id.UID, family.host.id.Unique, family.host.admission)
	if err != nil || len(candidates) != expectedCount || len(candidates) > 5 {
		t.Fatal("protected_candidate_observation_roster_refused")
	}
	t.Logf("protected_candidate_observed_roster_count=%d", len(candidates))
	for _, id := range candidates {
		before, err := observe(int(id.PID))
		if err != nil || !sameIdentity(id, before) {
			t.Fatal("protected_candidate_observation_identity_changed")
		}
		queue, err := unix.Kqueue()
		if err != nil {
			t.Fatal("protected_candidate_observation_queue_failed")
		}
		unix.CloseOnExec(queue)
		watch := &protectedCandidateObservation{id: before, queue: queue}
		family.observations = append(family.observations, watch)
		change := []unix.Kevent_t{{Ident: uint64(before.PID), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT | unix.NOTE_EXEC}}
		zero := unix.Timespec{}
		var events [1]unix.Kevent_t
		n, err := unix.Kevent(queue, change, events[:], &zero)
		after, observationErr := observe(int(before.PID))
		if err != nil || n != 0 || observationErr != nil || !sameIdentity(before, after) {
			t.Fatal("protected_candidate_observation_binding_refused")
		}
		watch.bound = true
	}
	after, err := nativeCandidates(family.host.id.UID, family.host.id.Unique, family.host.admission)
	if err != nil || !sameRoster(candidates, after) {
		t.Fatal("protected_candidate_observation_roster_changed")
	}
}

// Apple's current filter permits NOTE_EXITSTATUS for children or callers allowed
// to signal the target: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_event.c
// SDK declaration and source review do not establish actual installed controls.
func (family *protectedCandidateFamily) watchHostStatus(t *testing.T, proof *Proof) {
	t.Helper()
	if family.hostObservation != nil || proof.Live() != nil {
		t.Fatal("protected_candidate_host_status_input_refused")
	}
	proof.mu.Lock()
	id := proof.id
	proof.mu.Unlock()
	before, err := observe(int(id.PID))
	if err != nil || !sameIdentity(id, before) {
		t.Fatal("protected_candidate_host_status_identity_changed")
	}
	queue, err := unix.Kqueue()
	if err != nil {
		t.Fatal("protected_candidate_host_status_queue_failed")
	}
	unix.CloseOnExec(queue)
	watch := &protectedCandidateObservation{id: before, queue: queue, expectStatus: true}
	family.hostObservation = watch
	change := []unix.Kevent_t{{Ident: uint64(before.PID), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT | unix.NOTE_EXEC | unix.NOTE_EXITSTATUS}}
	zero := unix.Timespec{}
	var events [1]unix.Kevent_t
	n, err := unix.Kevent(queue, change, events[:], &zero)
	after, observationErr := observe(int(before.PID))
	if err != nil || n != 0 || observationErr != nil || !sameIdentity(before, after) {
		t.Fatal("protected_candidate_host_status_binding_refused")
	}
	watch.bound = true
}

func (watch *protectedCandidateObservation) finish(t *testing.T, deadline time.Time) {
	t.Helper()
	if watch.closeAttempted {
		return
	}
	if watch.bound {
		read := func(wait time.Duration) (int, unix.Kevent_t, error) {
			var events [1]unix.Kevent_t
			timeout := unix.NsecToTimespec(int64(wait))
			n, err := unix.Kevent(watch.queue, nil, events[:], &timeout)
			return n, events[0], err
		}
		event, interruptions, err := candidatePollEvent(read, time.Now, deadline)
		t.Logf("protected_candidate_observation_interruptions=%d", interruptions)
		if err != nil {
			t.Error("protected_candidate_observation_exit_unconfirmed_watch_retained")
			return
		}
		if event.Ident != uint64(watch.id.PID) || event.Filter != unix.EVFILT_PROC || event.Flags&unix.EV_ERROR != 0 || event.Fflags&(unix.NOTE_EXIT|unix.NOTE_EXEC) != unix.NOTE_EXIT {
			t.Error("protected_candidate_observation_exit_event_refused_watch_retained")
			return
		}
		if watch.expectStatus && !protectedCandidateHostStatusOK(uint64(watch.id.PID), event) {
			t.Error("protected_candidate_host_exit_status_refused_watch_retained")
			return
		}
	}
	watch.closeAttempted = true
	if unix.Close(watch.queue) != nil {
		t.Error("protected_candidate_observation_close_failed")
	}
}

// A receipt is accepted only after exact cooperative host cleanup. Forced
// lifetime exit closes the writer without a receipt and cannot pass this check.
func (family *protectedCandidateFamily) readCleanupReceipt(t *testing.T, deadline time.Time) {
	t.Helper()
	if family.cleanupReceipt == nil {
		t.Error("protected_candidate_cleanup_receipt_missing")
		return
	}
	if family.cleanupReceiptCloseAttempted {
		t.Error("protected_candidate_cleanup_receipt_reused")
		return
	}
	defer func() {
		family.cleanupReceiptCloseAttempted = true
		if family.cleanupReceipt.Close() != nil {
			t.Error("protected_candidate_cleanup_receipt_close_failed")
		}
	}()
	if err := readProtectedCleanupReceipt(family.cleanupReceipt, deadline); err != nil {
		t.Error(err.Error())
	}
}
