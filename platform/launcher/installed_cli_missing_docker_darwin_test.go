//go:build darwin && arm64 && cgo && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"crypto/sha256"
	"debug/macho"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/internal/darwinfixtureidentity"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/privatefs"
	"golang.org/x/sys/unix"
)

const missingDockerGenuinePath = "/Applications/Docker.app/Contents/Resources/bin/docker"
const missingDockerGenuineSHA = "31ae2d64e51d9dfc728a2934941615cdd92f31279ed6d5c1fb2bfc0a44637a8f"

// This fixture never removes the selected system CLI or changes account config.
// All mutations are relative to a retained, exclusively created private parent.
type missingDockerSlot struct {
	path               string
	dir, image         *os.File
	dirInfo, imageInfo os.FileInfo
	absent             bool
}

func missingDockerRequire(t *testing.T, ok bool, code string) {
	t.Helper()
	if !ok {
		t.Fatal(code)
	}
}

// O_SEARCH is O_EXEC|O_DIRECTORY in the canonical macOS26.5 fcntl.h.
// x/sys v0.48.0 does not export O_SEARCH. Only ancestors use search-only FDs.
const missingDockerAncestorSearch = 0x40000000 | unix.O_DIRECTORY

// These three system directories have fixed observed macOS metadata. Only
// /Applications permits the admin group to write: the source binary is data,
// never executed here, and its complete pinned bytes are copied into our own
// exclusive private slot. No product protected-path policy is changed.
func missingDockerAncestorMetadata(path string, mode os.FileMode, st *syscall.Stat_t) bool {
	if st == nil || !mode.IsDir() {
		return false
	}
	switch path {
	case "/":
		return st.Uid == 0 && st.Gid == 0 && mode.Perm() == 0755 && st.Flags == 1048576
	case "/Users":
		return st.Uid == 0 && st.Gid == 80 && mode.Perm() == 0755 && st.Flags == 1048576
	case "/Applications":
		return st.Uid == 0 && st.Gid == 80 && mode.Perm() == 0775 && st.Flags == 1048576
	default:
		return (st.Uid == 0 || st.Uid == uint32(os.Getuid())) && mode.Perm()&0022 == 0 && st.Flags == 0
	}
}

func missingDockerOpen(t *testing.T, path string, directory bool) *os.File {
	t.Helper()
	missingDockerRequire(t, filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/", "missing_cli_noncanonical_path")
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	missingDockerRequire(t, err == nil, "missing_cli_root_open")
	parent := os.NewFile(uintptr(fd), "/")
	// Each replacement closes the preceding original descriptor exactly once.
	defer func() {
		if parent != nil && parent.Close() != nil {
			t.Error("missing_cli_parent_close")
		}
	}()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	parentPath := "/"
	for i, part := range parts {
		info, statErr := parent.Stat()
		missingDockerRequire(t, statErr == nil, "missing_cli_ancestor_stat")
		st, ok := info.Sys().(*syscall.Stat_t)
		missingDockerRequire(t, ok && missingDockerAncestorMetadata(parentPath, info.Mode(), st) &&
			privatefs.CheckDescriptor(parent, privatefs.PublicAncestor) == nil,
			"missing_cli_ancestor_admission")
		flags := missingDockerAncestorSearch
		if i == len(parts)-1 {
			flags = unix.O_RDONLY
			if directory {
				flags |= unix.O_DIRECTORY
			}
		}
		next, openErr := unix.Openat(int(parent.Fd()), part, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		missingDockerRequire(t, openErr == nil, "missing_cli_component_open")
		child := os.NewFile(uintptr(next), part)
		old := parent
		parent = child
		parentPath = filepath.Join(parentPath, part)
		missingDockerRequire(t, old.Close() == nil, "missing_cli_ancestor_close")
	}
	result := parent
	parent = nil
	t.Cleanup(func() {
		if result.Close() != nil {
			t.Error("missing_cli_held_descriptor_close")
		}
	})
	return result
}

func missingDockerHash(t *testing.T, file *os.File) string {
	t.Helper()
	info, err := file.Stat()
	missingDockerRequire(t, err == nil && info.Mode().IsRegular() && info.Size() > 0 && info.Size() <= 128*1024*1024, "missing_cli_image_bounds")
	h := sha256.New()
	n, err := io.Copy(h, io.NewSectionReader(file, 0, info.Size()))
	missingDockerRequire(t, err == nil && n == info.Size(), "missing_cli_image_read")
	return hex.EncodeToString(h.Sum(nil))
}

func missingDockerSameMetadata(a, b os.FileInfo) bool {
	if a == nil || b == nil || !os.SameFile(a, b) {
		return false
	}
	x, ok := a.Sys().(*syscall.Stat_t)
	y, other := b.Sys().(*syscall.Stat_t)
	return ok && other && x.Uid == y.Uid && x.Gid == y.Gid && x.Mode == y.Mode && x.Flags == y.Flags &&
		x.Nlink == y.Nlink && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

func missingDockerPrepareSlot(t *testing.T) *missingDockerSlot {
	t.Helper()
	source := missingDockerOpen(t, missingDockerGenuinePath, false)
	info, err := source.Stat()
	missingDockerRequire(t, err == nil, "missing_cli_source_stat")
	st, ok := info.Sys().(*syscall.Stat_t)
	missingDockerRequire(t, ok && (st.Uid == 0 || st.Uid == 501) && st.Nlink == 1 && st.Flags == 0 && info.Mode().Perm()&0022 == 0 &&
		privatefs.CheckDescriptor(source, privatefs.PrivateObject) == nil && missingDockerHash(t, source) == missingDockerGenuineSHA, "missing_cli_genuine_source_pin")
	image, err := macho.NewFile(io.NewSectionReader(source, 0, info.Size()))
	missingDockerRequire(t, err == nil && image.Cpu == macho.CpuArm64 && image.Type == macho.TypeExec, "missing_cli_genuine_macho")
	// NewFile's ReaderAt is not an owned closer; the source descriptor stays held.
	home, err := os.UserHomeDir()
	missingDockerRequire(t, err == nil, "missing_cli_home")
	cache, err := filepath.EvalSymlinks(filepath.Join(home, ".cache", "agentmux-governance"))
	missingDockerRequire(t, err == nil, "missing_cli_existing_cache_required")
	missingDockerOpen(t, cache, true)
	root, err := os.MkdirTemp(cache, "p02-missing-cli-")
	missingDockerRequire(t, err == nil, "missing_cli_private_directory")
	dir := missingDockerOpen(t, root, true)
	dirInfo, err := dir.Stat()
	missingDockerRequire(t, err == nil && dirInfo.Mode().Perm() == 0700 && privatefs.CheckDescriptor(dir, privatefs.PrivateObject) == nil, "missing_cli_private_parent_admission")
	fd, err := unix.Openat(int(dir.Fd()), "docker", unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0500)
	missingDockerRequire(t, err == nil, "missing_cli_exclusive_copy")
	writer := os.NewFile(uintptr(fd), "docker")
	n, copyErr := io.Copy(writer, io.NewSectionReader(source, 0, info.Size()))
	syncErr := writer.Sync()
	closeErr := writer.Close()
	missingDockerRequire(t, copyErr == nil && n == info.Size() && syncErr == nil && closeErr == nil, "missing_cli_copy_joined_close")
	file := missingDockerOpen(t, filepath.Join(root, "docker"), false)
	currentSource, err := source.Stat()
	missingDockerRequire(t, err == nil && missingDockerSameMetadata(info, currentSource), "missing_cli_source_drift")
	fileInfo, err := file.Stat()
	missingDockerRequire(t, err == nil && missingDockerHash(t, file) == missingDockerGenuineSHA && privatefs.CheckDescriptor(file, privatefs.PrivateObject) == nil, "missing_cli_copy_pin")
	copyStat, ok := fileInfo.Sys().(*syscall.Stat_t)
	missingDockerRequire(t, ok && copyStat.Uid == uint32(os.Getuid()) && copyStat.Nlink == 1 && copyStat.Flags == 0 && fileInfo.Mode().Perm() == 0500, "missing_cli_copy_metadata")
	return &missingDockerSlot{path: filepath.Join(root, "docker"), dir: dir, image: file, dirInfo: dirInfo, imageInfo: fileInfo}
}

func (s *missingDockerSlot) check(t *testing.T, member string) {
	t.Helper()
	directory, err := s.dir.Stat()
	var rootStat *syscall.Stat_t
	if err == nil {
		rootStat, _ = directory.Sys().(*syscall.Stat_t)
	}
	missingDockerRequire(t, err == nil && os.SameFile(s.dirInfo, directory) && directory.Mode().Perm() == 0700 &&
		rootStat != nil && rootStat.Uid == uint32(os.Getuid()) && rootStat.Flags == 0 &&
		privatefs.CheckDescriptor(s.dir, privatefs.PrivateObject) == nil, "missing_cli_parent_drift")
	pathInfo, err := os.Lstat(filepath.Dir(s.path))
	missingDockerRequire(t, err == nil && os.SameFile(directory, pathInfo), "missing_cli_parent_path_replaced")
	fd, err := unix.Openat(int(s.dir.Fd()), member, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	missingDockerRequire(t, err == nil, "missing_cli_member_open")
	file := os.NewFile(uintptr(fd), member)
	defer func() {
		if file.Close() != nil {
			t.Error("missing_cli_member_close")
		}
	}()
	info, err := file.Stat()
	missingDockerRequire(t, err == nil && missingDockerSameMetadata(s.imageInfo, info) &&
		privatefs.CheckDescriptor(file, privatefs.PrivateObject) == nil && missingDockerHash(t, file) == missingDockerGenuineSHA, "missing_cli_member_identity_drift")
}

func (s *missingDockerSlot) move(t *testing.T, from, to string) {
	t.Helper()
	missingDockerRequire(t, (from == "docker" && to == "docker.retained") || (from == "docker.retained" && to == "docker"), "missing_cli_move_grammar")
	s.check(t, from)
	missingDockerRequire(t, unix.RenameatxNp(int(s.dir.Fd()), from, int(s.dir.Fd()), to, unix.RENAME_EXCL) == nil, "missing_cli_exclusive_move")
	s.absent = to == "docker.retained"
	s.check(t, to)
	var gone unix.Stat_t
	missingDockerRequire(t, errors.Is(unix.Fstatat(int(s.dir.Fd()), from, &gone, unix.AT_SYMLINK_NOFOLLOW), unix.ENOENT), "missing_cli_old_entry_not_absent")
}

func missingDockerQuiesce(t *testing.T, f *bootstrapDockerFixture, x *composeDarwinCLIFront, signal bool, deadline time.Time) {
	t.Helper()
	missingDockerRequire(t, x.creatorOwned() && x.output.joined && x.output.captured, "missing_cli_creator_required")
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if signal {
		missingDockerRequire(t, x.lifetime.host.Signal(syscall.SIGTERM) == nil, "missing_cli_exact_host_stop")
	}
	for _, proof := range append([]*darwinfixtureidentity.Proof{x.lifetime.host}, x.lifetime.roles...) {
		if proof.WaitExit(ctx) != nil {
			f.RetainForRecovery(t)
			t.Fatal("missing_cli_exact_exit_not_established")
		}
	}
	ids := append([]string{f.Profile.Docker.EngineID, "owner-status-service"}, bootstrapFixtureRoleLeaseIDs(f.Profile.Docker.EngineID)...)
	darwinStartupOwnerLeasesFree(t, f, ctx, ids)
	missingDockerRequire(t, ctx.Err() == nil, "missing_cli_shutdown_budget")
	// Existing registered cleanup retains and closes these exact exited proofs.
}

func missingDockerDiagnostic(raw []byte) bool {
	var d RequestDiagnostic
	return protocol.DecodeClosedJSON(raw, &d, 4096) == nil && ValidRequestDiagnostic(d) &&
		d.Code == "docker_client_missing" && d.Action == "restore_enrolled_client"
}

func TestInstalledCLIDarwinActualMissingDockerPreservesDataAndRecovers(t *testing.T) {
	missingDockerRequire(t, os.Getuid() == 501 && os.Geteuid() == 501 && os.Getenv("AMX_BOOTSTRAP_DOCKER_AUTHORIZED") == "1", "missing_cli_native_ordinary_authorization")
	// installedHostEnvironment intentionally uses account HOME and fixed PATH,
	// not inherited DOCKER_CONFIG. Use the already admitted account context on
	// both sides; do not inspect credentials or change host env sanitization.
	missingDockerRequire(t, os.Getenv("HOME") == "/Users/ryan" && os.Getenv("DOCKER_CONFIG") == "", "missing_cli_account_context_environment_required")
	selected, originalPin := loadBootstrapFixtureSelection(t)
	missingDockerRequire(t, selected.Target == "native-darwin" && selected.GOARCH == "arm64" && selected.Docker.Executable == missingDockerGenuinePath, "missing_cli_genuine_selection_required")
	slot := missingDockerPrepareSlot(t)
	selected.Docker.Executable = slot.path
	raw, err := json.Marshal(selected)
	missingDockerRequire(t, err == nil, "missing_cli_selection_encoding")
	selectionPath := filepath.Join(filepath.Dir(slot.path), "selection.json")
	selectionFD, err := unix.Openat(int(slot.dir.Fd()), "selection.json", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	missingDockerRequire(t, err == nil, "missing_cli_selection_exclusive_create")
	selectionFile := os.NewFile(uintptr(selectionFD), "selection.json")
	n, writeErr := selectionFile.Write(raw)
	syncErr := selectionFile.Sync()
	closeErr := selectionFile.Close()
	missingDockerRequire(t, writeErr == nil && n == len(raw) && syncErr == nil && closeErr == nil, "missing_cli_selection_write")
	pin := sha256.Sum256(raw)
	t.Setenv("AMX_BOOTSTRAP_SELECTION_FILE", selectionPath)
	t.Setenv("AMX_BOOTSTRAP_SELECTION_SHA256", hex.EncodeToString(pin[:]))
	f, policy, record := composeDarwinCLIEnrolledFixture(t)
	// Registered after fixture cleanup, before every frontend: restore only after
	// exact frontend cleanup, and before fixture engine cleanup needs the CLI.
	t.Cleanup(func() {
		if slot.absent {
			// An early assertion failed during the negative. Do not let fixture
			// infrastructure cleanup run with an unavailable selected client.
			f.RetainForRecovery(t)
			slot.move(t, "docker.retained", "docker")
		}
	})
	missingDockerRequire(t, f.Profile.Docker.Executable == slot.path, "missing_cli_enrollment_slot_changed")
	original := darwinScenarioCold(t, f, policy, record, "missing-cli-positive")
	stored := darwinScenarioStored(t, f)
	stored.assertPreserved(t, f, "missing-cli-positive-ledger.json")
	missingDockerQuiesce(t, f, original, true, time.Now().Add(f.Config.Deadlines.StopGrace+f.Config.Deadlines.ReapTimeout))
	stored.assertPreserved(t, f, "missing-cli-quiesced-ledger.json")
	slot.move(t, "docker", "docker.retained")
	// This invokes the real adapter against the now absent selected path. No
	// child starts; the retained OS PathError must be ENOENT at exactly this slot.
	ctx, cancel := context.WithTimeout(context.Background(), darwinScenarioRefusalBudget)
	_, cause := f.Driver.run(ctx, nil, "compose", "version", "--short")
	cancel()
	var pathError *os.PathError
	missingDockerRequire(t, errors.As(cause, &pathError) && pathError.Op == "fork/exec" && pathError.Path == slot.path &&
		errors.Is(pathError.Err, syscall.ENOENT) && ProjectRequestDiagnostic(cause).Code == "docker_client_missing", "missing_cli_actual_os_cause_required")
	// Inspection may refuse before a host is created. Do not require or invent
	// host ownership for that safe failure path; require its exact diagnostic.
	negative := composeDarwinCLIStart(t, f, policy, record, "ensure", false)
	negativeRaw, success := negative.wait(t, f, "missing-cli-negative", darwinScenarioEnsureBudget)
	actionable := !success && missingDockerDiagnostic(negative.stderr.Bytes())
	if negative.creatorOwned() {
		attempt := negative.lifetime.attempt
		darwinPortNoFalseReadiness(t, f, negative, record, negativeRaw, success, true, attempt, "missing-cli-negative")
		missingDockerQuiesce(t, f, negative, false, negative.output.started.Add(f.Config.StartupTimeout))
		status := composeDarwinCLIStart(t, f, policy, record, "status", false)
		historyRaw, statusSuccess := status.wait(t, f, "missing-cli-terminal-status", darwinScenarioRefusalBudget)
		missingDockerRequire(t, !statusSuccess && !status.creatorOwned(), "missing_cli_status_must_not_start_or_succeed")
		history, code := composeCLIFailureHistoryCode(historyRaw, attempt, time.Now())
		if code == "" {
			missingDockerRequire(t, history.Diagnostic == requestDiagnostic("docker_client_missing"), "missing_cli_terminal_history_wrong_cause")
			f.WriteEvidence(t, "missing-cli-history.json", history)
			actionable = true
		} else {
			missingDockerRequire(t, len(historyRaw) == 0 && missingDockerDiagnostic(status.stderr.Bytes()), "missing_cli_exact_terminal_diagnostic_required")
			actionable = true
		}
	} else {
		missingDockerRequire(t, !success && len(negativeRaw) == 0 && actionable, "missing_cli_precreation_refusal_not_exact")
		idle, stop := context.WithTimeout(context.Background(), darwinScenarioRefusalBudget)
		darwinStartupOwnerLeasesFree(t, f, idle, append([]string{f.Profile.Docker.EngineID, "owner-status-service"}, bootstrapFixtureRoleLeaseIDs(f.Profile.Docker.EngineID)...))
		stop()
	}
	missingDockerRequire(t, actionable, "missing_cli_specific_bounded_installed_diagnostic_required")
	missingDockerRequire(t, bootstrapFixtureRecord(t, f.Config, stored.sequence) == stored.record, "missing_cli_record_lost_during_actual_negative")
	// All installed negative owners and output have joined before correction.
	// Engine reads are deliberately deferred until the selected CLI is restored.
	slot.move(t, "docker.retained", "docker")
	stored.assertPreserved(t, f, "missing-cli-negative-preservation.json")
	recovered := composeDarwinCLIStart(t, f, policy, record, "ensure", true)
	darwinScenarioResponse(t, f, recovered, record, "missing-cli-recovery", darwinScenarioEnsureBudget, true)
	darwinScenarioReady(t, f, recovered, "missing-cli-recovery-ready.json")
	missingDockerRequire(t, recovered.lifetime.attempt != original.lifetime.attempt &&
		(negative.lifetime == nil || recovered.lifetime.attempt != negative.lifetime.attempt), "missing_cli_recovery_attempt_not_fresh")
	stored.assertPreserved(t, f, "missing-cli-recovered-preservation.json")
	loaded, err := LoadProfile(f.Config.ProfilePolicy)
	missingDockerRequire(t, err == nil && reflect.DeepEqual(loaded.Declaration(), f.Profile), "missing_cli_profile_changed_during_recovery")
	currentPolicy, err := LoadEnrolledHostPolicy(policy)
	missingDockerRequire(t, err == nil && reflect.DeepEqual(currentPolicy.record, record), "missing_cli_host_policy_changed_during_recovery")
	slot.check(t, "docker")
	f.WriteEvidence(t, "missing-cli-result.json", map[string]any{
		"originalSelectionSHA256": originalPin, "derivedSelectionSHA256": hex.EncodeToString(pin[:]),
		"genuineClientSHA256": missingDockerGenuineSHA, "exactOwnedEntryRestored": true,
		"actualOSCause": "ENOENT", "installedDiagnostic": "docker_client_missing",
		"sameEnrollment": true, "sameBrokerVolumeAndRecord": true, "foreignBaselinePreserved": true,
		"freshAuthenticatedRecovery": true, "negativeFrontendWaitJoined": negative.output.joined,
		"scope": "native missing-client component fixture; not complete FAIL57 or P02 acceptance",
	})
}

// Focused controls for the exact public diagnostic; these do not start Docker.
func TestMissingDockerDiagnosticIsExact(t *testing.T) {
	encode := func(d RequestDiagnostic) []byte {
		raw, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	good := requestDiagnostic("docker_client_missing")
	missingDockerRequire(t, missingDockerDiagnostic(encode(good)), "missing_cli_valid_diagnostic_refused")
	for _, change := range []func(*RequestDiagnostic){
		func(d *RequestDiagnostic) { d.Code = "docker_command_failed" },
		func(d *RequestDiagnostic) { d.Action = "install_automatically" },
		func(d *RequestDiagnostic) { d.Message += " private stderr" },
		func(d *RequestDiagnostic) { d.Kind = "bootstrap-progress" },
	} {
		bad := good
		change(&bad)
		missingDockerRequire(t, !missingDockerDiagnostic(encode(bad)), "missing_cli_altered_diagnostic_admitted")
	}
	missingDockerRequire(t, !missingDockerDiagnostic(append(encode(good), encode(good)...)), "missing_cli_multiple_diagnostics_admitted")
}

func TestMissingDockerAncestorMetadataIsExact(t *testing.T) {
	for _, c := range []struct {
		path string
		gid  uint32
		mode os.FileMode
	}{
		{"/", 0, 0755}, {"/Users", 80, 0755}, {"/Applications", 80, 0775},
	} {
		st := syscall.Stat_t{Uid: 0, Gid: c.gid, Flags: 1048576}
		missingDockerRequire(t, missingDockerAncestorMetadata(c.path, os.ModeDir|c.mode, &st), "missing_cli_exact_system_ancestor_refused")
		for _, mutate := range []func(*syscall.Stat_t){
			func(s *syscall.Stat_t) { s.Uid = 501 },
			func(s *syscall.Stat_t) { s.Gid++ },
			func(s *syscall.Stat_t) { s.Flags = 0 },
			func(s *syscall.Stat_t) { s.Flags |= 2 },
		} {
			bad := st
			mutate(&bad)
			missingDockerRequire(t, !missingDockerAncestorMetadata(c.path, os.ModeDir|c.mode, &bad), "missing_cli_system_metadata_drift_admitted")
		}
		missingDockerRequire(t, !missingDockerAncestorMetadata(c.path, os.ModeDir|0777, &st), "missing_cli_system_world_write_admitted")
		missingDockerRequire(t, !missingDockerAncestorMetadata(c.path, c.mode, &st), "missing_cli_system_nondirectory_admitted")
	}
	ordinary := syscall.Stat_t{Uid: uint32(os.Getuid()), Flags: 0}
	missingDockerRequire(t, missingDockerAncestorMetadata("/ordinary", os.ModeDir|0700, &ordinary), "missing_cli_private_ancestor_refused")
	missingDockerRequire(t, !missingDockerAncestorMetadata("/ordinary", os.ModeDir|0775, &ordinary), "missing_cli_ordinary_group_write_admitted")
	ordinary.Flags = 1048576
	missingDockerRequire(t, !missingDockerAncestorMetadata("/ordinary", os.ModeDir|0700, &ordinary), "missing_cli_flags_exception_escaped_fixed_paths")
}
