//go:build darwin && arm64 && cgo && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"crypto/sha256"
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

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/privatefs"
	"golang.org/x/sys/unix"
)

const missingComposeSource = "/Users/ryan/.cache/agentmux-governance/compose-user-plugin-approved.k06wf501/docker-compose-5.5.1"
const missingComposeSHA = "998735c9b6fe68a4f05895e6ea73d71ad06f9fc7046383ad89e47346781b6af5"

func missingComposeContext(raw []byte, selected ProfileDocker) bool {
	var metadata struct {
		Name      string
		Metadata  map[string]any
		Endpoints map[string]struct {
			Host          string
			SkipTLSVerify bool
		}
	}
	return protocol.DecodeClosedJSON(raw, &metadata, 4096) == nil && metadata.Name == selected.Context && len(metadata.Endpoints) == 1 &&
		metadata.Endpoints["docker"].Host == selected.Endpoint && !metadata.Endpoints["docker"].SkipTLSVerify
}

type missingComposeSlot struct {
	docker                  *missingDockerSlot
	root                    *os.Root
	plugin, wrapper         *os.File
	pluginInfo, wrapperInfo os.FileInfo
	pluginDirectory         *os.File
	pluginDirectoryInfo     os.FileInfo
	wrapperDigest           string
	absent                  bool
}

func missingComposeWrite(t *testing.T, root *os.Root, name string, data []byte, mode os.FileMode) {
	t.Helper()
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	missingDockerRequire(t, err == nil, "missing_compose_exclusive_write")
	n, writeErr := f.Write(data)
	syncErr, closeErr := f.Sync(), f.Close()
	missingDockerRequire(t, n == len(data) && writeErr == nil && syncErr == nil && closeErr == nil, "missing_compose_write_joined_close")
}

func missingComposePrepare(t *testing.T, selected bootstrapFixtureSelection) (*missingComposeSlot, bootstrapFixtureSelection) {
	t.Helper()
	docker := missingDockerPrepareSlot(t)
	root, err := os.OpenRoot(filepath.Dir(docker.path))
	missingDockerRequire(t, err == nil, "missing_compose_private_root")
	t.Cleanup(func() {
		if root.Close() != nil {
			t.Error("missing_compose_root_close")
		}
	})
	for _, directory := range []string{"config", "config/contexts", "config/contexts/meta", "config/cli-plugins"} {
		missingDockerRequire(t, root.Mkdir(directory, 0700) == nil, "missing_compose_private_directory")
	}
	contextID := sha256.Sum256([]byte(selected.Docker.Context))
	contextRelative := filepath.Join("contexts", "meta", hex.EncodeToString(contextID[:]))
	source := missingDockerOpen(t, filepath.Join("/Users/ryan/.docker", contextRelative, "meta.json"), false)
	sourceInfo, err := source.Stat()
	missingDockerRequire(t, err == nil, "missing_compose_context_metadata_stat")
	sourceStat, ok := sourceInfo.Sys().(*syscall.Stat_t)
	missingDockerRequire(t, err == nil && ok && sourceInfo.Mode().IsRegular() && sourceInfo.Size() > 0 && sourceInfo.Size() <= 4096 &&
		sourceStat.Uid == 501 && sourceStat.Nlink == 1 && sourceStat.Flags == 0 && sourceInfo.Mode().Perm()&0022 == 0 &&
		privatefs.CheckDescriptor(source, privatefs.PrivateObject) == nil, "missing_compose_context_metadata_admission")
	metadata, err := io.ReadAll(io.NewSectionReader(source, 0, sourceInfo.Size()))
	missingDockerRequire(t, err == nil && missingComposeContext(metadata, selected.Docker),
		"missing_compose_exact_context_required")
	currentSource, err := source.Stat()
	missingDockerRequire(t, err == nil && missingDockerSameMetadata(sourceInfo, currentSource), "missing_compose_context_metadata_changed")
	missingDockerRequire(t, root.Mkdir(filepath.Join("config", contextRelative), 0700) == nil, "missing_compose_context_directory")
	// Only selected context metadata is copied. No account config or auth file
	// is read, copied or changed.
	missingComposeWrite(t, root, filepath.Join("config", contextRelative, "meta.json"), metadata, 0600)
	pluginSource := missingDockerOpen(t, missingComposeSource, false)
	pluginSourceInfo, err := pluginSource.Stat()
	missingDockerRequire(t, err == nil, "missing_compose_plugin_source_stat")
	pluginStat, ok := pluginSourceInfo.Sys().(*syscall.Stat_t)
	missingDockerRequire(t, err == nil && ok && pluginSourceInfo.Mode().IsRegular() && pluginSourceInfo.Mode().Perm() == 0500 &&
		pluginStat.Uid == 501 && pluginStat.Nlink == 1 && pluginStat.Flags == 0 &&
		privatefs.CheckDescriptor(pluginSource, privatefs.PrivateObject) == nil && missingDockerHash(t, pluginSource) == missingComposeSHA,
		"missing_compose_approved_plugin_required")
	writer, err := root.OpenFile("config/cli-plugins/docker-compose", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0500)
	missingDockerRequire(t, err == nil, "missing_compose_plugin_exclusive_copy")
	n, copyErr := io.Copy(writer, io.NewSectionReader(pluginSource, 0, pluginSourceInfo.Size()))
	syncErr, closeErr := writer.Sync(), writer.Close()
	missingDockerRequire(t, copyErr == nil && n == pluginSourceInfo.Size() && syncErr == nil && closeErr == nil, "missing_compose_plugin_copy_joined_close")
	currentSource, err = pluginSource.Stat()
	missingDockerRequire(t, err == nil && missingDockerSameMetadata(pluginSourceInfo, currentSource), "missing_compose_plugin_source_changed")
	configPath := filepath.Join(filepath.Dir(docker.path), "config")
	missingDockerRequire(t, !strings.ContainsAny(docker.path+configPath, "'\n\r"), "missing_compose_literal_wrapper_paths")
	wrapper := []byte("#!/bin/sh\nexec '" + docker.path + "' --config '" + configPath + "' \"$@\"\n")
	missingComposeWrite(t, root, "docker-configured", wrapper, 0500)
	s := &missingComposeSlot{docker: docker, root: root}
	s.plugin = missingDockerOpen(t, filepath.Join(configPath, "cli-plugins", "docker-compose"), false)
	s.pluginInfo, err = s.plugin.Stat()
	missingDockerRequire(t, err == nil && privateProfileInfo(s.pluginInfo, 501, false) && s.pluginInfo.Mode().Perm() == 0500 &&
		missingDockerHash(t, s.plugin) == missingComposeSHA, "missing_compose_owned_plugin_pin")
	s.wrapper = missingDockerOpen(t, filepath.Join(filepath.Dir(docker.path), "docker-configured"), false)
	s.wrapperInfo, err = s.wrapper.Stat()
	missingDockerRequire(t, err == nil && privateProfileInfo(s.wrapperInfo, 501, false) && s.wrapperInfo.Mode().Perm() == 0500, "missing_compose_wrapper_pin")
	s.wrapperDigest = missingDockerHash(t, s.wrapper)
	s.pluginDirectory = missingDockerOpen(t, filepath.Join(configPath, "cli-plugins"), true)
	s.pluginDirectoryInfo, err = s.pluginDirectory.Stat()
	missingDockerRequire(t, err == nil && privateProfileInfo(s.pluginDirectoryInfo, 501, true) && s.pluginDirectoryInfo.Mode().Perm() == 0700, "missing_compose_plugin_directory_pin")
	selected.Docker.Executable = filepath.Join(filepath.Dir(docker.path), "docker-configured")
	s.check(t, false)
	return s, selected
}

func TestMissingComposeContextMetadataIsExact(t *testing.T) {
	selected := ProfileDocker{Context: "desktop-linux", Endpoint: "unix:///private/tmp/selected.sock"}
	raw := `{"Name":"desktop-linux","Metadata":{"Description":"Docker Desktop","GODEBUG":"setting=value","otel":{"endpoint":"local"}},"Endpoints":{"docker":{"Host":"unix:///private/tmp/selected.sock","SkipTLSVerify":false}}}`
	if !missingComposeContext([]byte(raw), selected) {
		t.Fatal("actual nested context metadata shape was refused")
	}
	for _, bad := range []string{
		strings.Replace(raw, `"Name":"desktop-linux"`, `"Name":"other-context"`, 1),
		strings.Replace(raw, "selected.sock", "foreign.sock", 1),
		strings.Replace(raw, `"SkipTLSVerify":false`, `"SkipTLSVerify":true`, 1),
		strings.Replace(raw, `"Name":"desktop-linux"`, `"Name":"desktop-linux","Name":"desktop-linux"`, 1),
		strings.Replace(raw, `"Description":"Docker Desktop"`, `"Description":"Docker Desktop","Description":"other"`, 1),
		strings.Replace(raw, `"Endpoints":{`, `"extra":true,"Endpoints":{`, 1),
	} {
		if missingComposeContext([]byte(bad), selected) {
			t.Fatal("foreign, duplicate or unknown context field was accepted")
		}
	}
}

func (s *missingComposeSlot) check(t *testing.T, retained bool) {
	t.Helper()
	s.docker.check(t, "docker")
	for _, item := range []struct {
		file *os.File
		info os.FileInfo
		path string
	}{
		{s.wrapper, s.wrapperInfo, filepath.Join(filepath.Dir(s.docker.path), "docker-configured")},
		{s.pluginDirectory, s.pluginDirectoryInfo, filepath.Join(filepath.Dir(s.docker.path), "config", "cli-plugins")},
	} {
		info, err := item.file.Stat()
		pathInfo, pathErr := os.Lstat(item.path)
		missingDockerRequire(t, err == nil && pathErr == nil, "missing_compose_parent_or_wrapper_stat")
		same := missingDockerSameMetadata(item.info, info)
		code := "missing_compose_held_wrapper_changed"
		if info.IsDir() {
			code = "missing_compose_held_plugin_directory_changed"
			before, beforeOK := item.info.Sys().(*syscall.Stat_t)
			after, afterOK := info.Sys().(*syscall.Stat_t)
			same = beforeOK && afterOK && os.SameFile(item.info, info) && before.Uid == after.Uid && before.Gid == after.Gid &&
				before.Mode == after.Mode && before.Flags == after.Flags
		}
		missingDockerRequire(t, same && os.SameFile(info, pathInfo) &&
			privatefs.CheckDescriptor(item.file, privatefs.PrivateObject) == nil, code)
	}
	// APFS directory link counts change with entries. Check the exact roster
	// for this deliberate move instead; regular-file link counts stay pinned.
	entryFD, err := s.root.Open("config/cli-plugins")
	missingDockerRequire(t, err == nil, "missing_compose_plugin_roster_open")
	defer func() {
		if entryFD.Close() != nil {
			t.Error("missing_compose_plugin_roster_close")
		}
	}()
	info, err := entryFD.Stat()
	missingDockerRequire(t, err == nil && os.SameFile(info, s.pluginDirectoryInfo), "missing_compose_plugin_roster_directory_changed")
	entries, err := entryFD.ReadDir(-1)
	missingDockerRequire(t, err == nil && ((retained && len(entries) == 0) ||
		(!retained && len(entries) == 1 && entries[0].Name() == "docker-compose")), "missing_compose_plugin_roster_changed")
	missingDockerRequire(t, missingDockerHash(t, s.wrapper) == s.wrapperDigest, "missing_compose_literal_wrapper_changed")
	name := "config/cli-plugins/docker-compose"
	if retained {
		name = "docker-compose.retained"
	}
	current, err := s.root.Open(name)
	missingDockerRequire(t, err == nil, "missing_compose_owned_plugin_open")
	defer func() {
		if current.Close() != nil {
			t.Error("missing_compose_owned_plugin_close")
		}
	}()
	info, err = current.Stat()
	missingDockerRequire(t, err == nil && missingDockerSameMetadata(s.pluginInfo, info) && privatefs.CheckDescriptor(current, privatefs.PrivateObject) == nil &&
		missingDockerHash(t, current) == missingComposeSHA, "missing_compose_owned_plugin_changed")
}

func (s *missingComposeSlot) move(t *testing.T, remove bool) {
	t.Helper()
	missingDockerRequire(t, s.absent != remove, "missing_compose_move_state")
	s.check(t, s.absent)
	fromFD, toFD := int(s.pluginDirectory.Fd()), int(s.docker.dir.Fd())
	from, to := "docker-compose", "docker-compose.retained"
	if !remove {
		fromFD, toFD, from, to = toFD, fromFD, to, from
	}
	missingDockerRequire(t, unix.RenameatxNp(fromFD, from, toFD, to, unix.RENAME_EXCL) == nil, "missing_compose_exclusive_move")
	s.absent = remove
	s.check(t, s.absent)
	var gone unix.Stat_t
	missingDockerRequire(t, errors.Is(unix.Fstatat(fromFD, from, &gone, unix.AT_SYMLINK_NOFOLLOW), unix.ENOENT), "missing_compose_old_entry_not_absent")
}

func missingComposeDiagnostic(raw []byte) bool {
	var diagnostic RequestDiagnostic
	return protocol.DecodeClosedJSON(raw, &diagnostic, 4096) == nil && diagnostic == requestDiagnostic("docker_compose_check_failed")
}

func TestInstalledCLIDarwinActualMissingComposePreservesDataAndRecovers(t *testing.T) {
	missingDockerRequire(t, os.Getuid() == 501 && os.Geteuid() == 501 && os.Getenv("HOME") == "/Users/ryan" && os.Getenv("DOCKER_CONFIG") == "" &&
		os.Getenv("AMX_BOOTSTRAP_DOCKER_AUTHORIZED") == "1", "missing_compose_ordinary_account_authorization")
	selected, _ := loadBootstrapFixtureSelection(t)
	missingDockerRequire(t, selected.Target == "native-darwin" && selected.GOARCH == "arm64" && selected.Docker.Executable == missingDockerGenuinePath,
		"missing_compose_genuine_selection_required")
	slot, selected := missingComposePrepare(t, selected)
	raw, err := json.Marshal(selected)
	missingDockerRequire(t, err == nil, "missing_compose_selection_encoding")
	missingComposeWrite(t, slot.root, "selection.json", raw, 0600)
	pin := sha256.Sum256(raw)
	t.Setenv("AMX_BOOTSTRAP_SELECTION_FILE", filepath.Join(filepath.Dir(slot.docker.path), "selection.json"))
	t.Setenv("AMX_BOOTSTRAP_SELECTION_SHA256", hex.EncodeToString(pin[:]))
	f, selection, record := composeDarwinCLIEnrolledFixture(t)
	// Restore our own plugin after all later exact frontend owners have been
	// joined, before the fixture's ordinary infrastructure cleanup needs it.
	t.Cleanup(func() {
		if slot.absent {
			f.RetainForRecovery(t)
			slot.move(t, false)
		}
	})
	original := darwinScenarioCold(t, f, selection, record, "missing-compose-positive")
	stored := darwinScenarioStored(t, f)
	stored.assertPreserved(t, f, "missing-compose-positive-preservation.json")
	missingDockerQuiesce(t, f, original, true, time.Now().Add(f.Config.Deadlines.StopGrace+f.Config.Deadlines.ReapTimeout))
	slot.move(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), darwinScenarioRefusalBudget)
	version, cause := f.Driver.run(ctx, nil, "compose", "version", "--short")
	expired := ctx.Err() != nil
	cancel()
	missingDockerRequire(t, cause != nil && len(version) == 0 && !expired && ProjectRequestDiagnostic(cause) == requestDiagnostic("docker_compose_check_failed"),
		"missing_compose_actual_discovery_failure_required")
	negative := composeDarwinCLIStart(t, f, selection, record, "ensure", false)
	negativeRaw, success := negative.wait(t, f, "missing-compose-negative", darwinScenarioEnsureBudget)
	if negative.creatorOwned() {
		darwinPortNoFalseReadiness(t, f, negative, record, negativeRaw, success, true, negative.lifetime.attempt, "missing-compose-negative")
		missingDockerQuiesce(t, f, negative, false, negative.output.started.Add(f.Config.StartupTimeout))
	} else {
		missingDockerRequire(t, !success && len(negativeRaw) == 0 && missingComposeDiagnostic(negative.stderr.Bytes()), "missing_compose_precreation_refusal_required")
	}
	status := composeDarwinCLIStart(t, f, selection, record, "status", false)
	statusRaw, statusSuccess := status.wait(t, f, "missing-compose-status", darwinScenarioRefusalBudget)
	missingDockerRequire(t, !statusSuccess && !status.creatorOwned(), "missing_compose_status_false_readiness_or_owner")
	if negative.creatorOwned() {
		history, code := composeCLIFailureHistoryCode(statusRaw, negative.lifetime.attempt, time.Now())
		missingDockerRequire(t, (code == "" && history.Diagnostic == requestDiagnostic("docker_compose_check_failed")) ||
			(len(statusRaw) == 0 && missingComposeDiagnostic(status.stderr.Bytes())), "missing_compose_terminal_diagnostic_required")
	} else {
		missingDockerRequire(t, len(statusRaw) == 0 && missingComposeDiagnostic(status.stderr.Bytes()), "missing_compose_exact_status_refusal_required")
	}
	ctx, cancel = context.WithTimeout(context.Background(), darwinScenarioRefusalBudget)
	darwinStartupOwnerLeasesFree(t, f, ctx, append([]string{f.Profile.Docker.EngineID, "owner-status-service"}, bootstrapFixtureRoleLeaseIDs(f.Profile.Docker.EngineID)...))
	cancel()
	missingDockerRequire(t, bootstrapFixtureRecord(t, f.Config, stored.sequence) == stored.record, "missing_compose_record_lost_during_failure")
	slot.move(t, false)
	stored.assertPreserved(t, f, "missing-compose-negative-preservation.json")
	retry := composeDarwinCLIStart(t, f, selection, record, "ensure", true)
	darwinScenarioResponse(t, f, retry, record, "missing-compose-retry", darwinScenarioEnsureBudget, true)
	darwinScenarioReady(t, f, retry, "missing-compose-retry-ready.json")
	missingDockerRequire(t, retry.lifetime.attempt != original.lifetime.attempt &&
		(negative.lifetime == nil || retry.lifetime.attempt != negative.lifetime.attempt), "missing_compose_retry_attempt_not_fresh")
	stored.assertPreserved(t, f, "missing-compose-retry-preservation.json")
	loaded, err := LoadProfile(f.Config.ProfilePolicy)
	missingDockerRequire(t, err == nil && reflect.DeepEqual(loaded.Declaration(), f.Profile), "missing_compose_profile_changed")
	currentPolicy, err := LoadEnrolledHostPolicy(selection)
	missingDockerRequire(t, err == nil && reflect.DeepEqual(currentPolicy.record, record), "missing_compose_host_policy_changed")
	slot.check(t, false)
	f.WriteEvidence(t, "missing-compose-result.json", map[string]any{
		"actualGenuineDockerDiscoveryFailure": true, "installedDiagnostic": "docker_compose_check_failed",
		"sameEnrollmentBrokerVolumeAndRecord": true, "freshAuthenticatedReadiness": true,
		"privateCopiedPluginRestored": true, "sharedConfigurationChanged": false,
	})
}
