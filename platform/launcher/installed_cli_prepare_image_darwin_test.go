//go:build darwin && arm64 && cgo && agentmux_bootstrap_docker

package launcher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/privatefs"
	"golang.org/x/sys/unix"
)

// Preparation is a foreground CLI owner, with no HOST discovery or application
// readiness claim. The existing native creator retains its sole Wait/readers.
func darwinInstalledImagePreparation(t *testing.T, f *bootstrapDockerFixture, selection HostPolicySelection, record hostPolicyRecord,
	name string, prepared bool, privateValues []string) BrokerImagePreparationResult {
	t.Helper()
	x := composeDarwinCLIPrepare(t, f, selection, record, "prepare")
	darwinScenarioStart(t, f, x, darwinScenarioRefusalBudget)
	ctx, cancel := context.WithDeadline(context.Background(), x.output.started.Add(BrokerImagePreparationLimit))
	err := x.join(ctx)
	cancel()
	if err != nil {
		f.RetainForRecovery(t)
		t.Fatal("installed image preparation did not join its original foreground owner within 180 seconds")
	}
	raw, success := x.wait(t, f, name, BrokerImagePreparationLimit)
	if x.creatorOwned() || !x.output.joined || !x.output.captured || success != prepared {
		f.RetainForRecovery(t)
		t.Fatal("installed image preparation lost its foreground-only completion contract")
	}
	for _, value := range privateValues {
		if value != "" && (bytes.Contains(raw, []byte(value)) || bytes.Contains(x.stderr.Bytes(), []byte(value))) {
			t.Fatal("image preparation exposed synthetic private configuration")
		}
	}
	stages := []string{"checking", "waiting_for_owner", "downloading"}
	if prepared {
		stages = append(stages, "verifying")
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if len(lines) != len(stages)+1 {
		t.Fatal("installed image preparation output lost its bounded progress and terminal result")
	}
	for i, stage := range stages {
		var progress BrokerImagePreparationProgress
		if protocol.DecodeClosedJSON(lines[i], &progress, 4096) != nil || progress != brokerPreparationProgress(stage) {
			t.Fatal("installed image preparation progress was not the fixed ordered public representation")
		}
	}
	var result BrokerImagePreparationResult
	if protocol.DecodeClosedJSON(lines[len(lines)-1], &result, 4096) != nil || result.SchemaVersion != protocol.Version ||
		result.Kind != "broker-image-preparation-result" || result.Readiness != "not_observed" {
		t.Fatal("image preparation terminal result claimed readiness or violated its public contract")
	}
	if prepared {
		if result.Outcome != "prepared" || result.Stage != "prepared" || result.Diagnostic != nil || x.stderr.Len() != 0 {
			t.Fatal("corrected image preparation did not verify the exact pinned image")
		}
	} else {
		want := requestDiagnostic("docker_image_pull_failed")
		var diagnostic RequestDiagnostic
		if result.Outcome != "failed" || result.Stage != "downloading" || result.Diagnostic == nil || *result.Diagnostic != want ||
			protocol.DecodeClosedJSON(x.stderr.Bytes(), &diagnostic, 4096) != nil || diagnostic != want {
			t.Fatal("real fixed pull failure did not produce its exact closed product category")
		}
	}
	f.WriteEvidence(t, name+"-result.json", result)
	return result
}

func TestInstalledCLIDarwinRealImagePreparationFailureAndRetry(t *testing.T) {
	missingDockerRequire(t, os.Getuid() == 501 && os.Geteuid() == 501 && os.Getenv("HOME") == "/Users/ryan" && os.Getenv("DOCKER_CONFIG") == "" &&
		os.Getenv("DOCKER_AUTH_CONFIG") == "" && os.Getenv("AMX_BOOTSTRAP_DOCKER_AUTHORIZED") == "1", "image_preparation_ordinary_private_config_authorization")
	selected, _ := loadBootstrapFixtureSelection(t)
	missingDockerRequire(t, selected.Target == "native-darwin" && selected.GOARCH == "arm64" && selected.Docker.Executable == missingDockerGenuinePath,
		"image_preparation_genuine_selection_required")
	slot, selected := missingComposePrepare(t, selected)
	selectionRaw, err := json.Marshal(selected)
	missingDockerRequire(t, err == nil, "image_preparation_selection_encoding")
	missingComposeWrite(t, slot.root, "selection.json", selectionRaw, 0600)
	selectionPin := sha256.Sum256(selectionRaw)
	t.Setenv("AMX_BOOTSTRAP_SELECTION_FILE", filepath.Join(filepath.Dir(slot.docker.path), "selection.json"))
	t.Setenv("AMX_BOOTSTRAP_SELECTION_SHA256", hex.EncodeToString(selectionPin[:]))
	f, selection, record := composeDarwinCLIEnrolledFixture(t)
	original := darwinScenarioCold(t, f, selection, record, "image-preparation-cold")
	stored := darwinScenarioStored(t, f)
	missingDockerQuiesce(t, f, original, true, time.Now().Add(f.Config.Deadlines.StopGrace+f.Config.Deadlines.ReapTimeout))
	stored.assertPreserved(t, f, "image-preparation-quiesced-preservation.json")
	// This random synthetic name is deliberately outside Docker Hub's account
	// name syntax. It cannot target an existing user's registry credentials.
	username := "agentmux.fixture.invalid." + bootstrapFixtureRandom(t, 16)
	password := bootstrapFixtureRandom(t, 32)
	encoded := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	authRaw, err := json.Marshal(map[string]any{"auths": map[string]any{"https://index.docker.io/v1/": map[string]string{"auth": encoded}}})
	missingDockerRequire(t, err == nil, "image_preparation_synthetic_auth_encoding")
	missingComposeWrite(t, slot.root, "config/config.json", authRaw, 0600)
	authPath := filepath.Join(filepath.Dir(slot.docker.path), "config", "config.json")
	authFile := missingDockerOpen(t, authPath, false)
	authInfo, err := authFile.Stat()
	missingDockerRequire(t, err == nil && privateProfileInfo(authInfo, 501, false) && authInfo.Mode().Perm() == 0600 &&
		privatefs.CheckDescriptor(authFile, privatefs.PrivateObject) == nil, "image_preparation_private_auth_admission")
	authDigest := sha256.Sum256(authRaw)
	missingDockerRequire(t, missingDockerHash(t, authFile) == hex.EncodeToString(authDigest[:]), "image_preparation_synthetic_auth_pin")
	darwinInstalledImagePreparation(t, f, selection, record, "image-preparation-negative", false, []string{username, password, encoded})
	allIDs := append([]string{f.Profile.Docker.EngineID, "owner-status-service"}, bootstrapFixtureRoleLeaseIDs(f.Profile.Docker.EngineID)...)
	ctx, cancel := context.WithTimeout(context.Background(), darwinScenarioRefusalBudget)
	darwinStartupOwnerLeasesFree(t, f, ctx, allIDs)
	cancel()
	stored.assertPreserved(t, f, "image-preparation-negative-preservation.json")
	// Retain only our own bad input. A nonempty empty-auth entry avoids Docker
	// 29.8's default credential-store discovery and supplies no credentials.
	slot.check(t, false)
	currentInfo, err := slot.root.Lstat("config/config.json")
	missingDockerRequire(t, err == nil && missingDockerSameMetadata(authInfo, currentInfo) &&
		missingDockerHash(t, authFile) == hex.EncodeToString(authDigest[:]), "image_preparation_auth_changed_before_correction")
	configFD := missingDockerOpen(t, filepath.Dir(authPath), true)
	missingDockerRequire(t, unix.RenameatxNp(int(configFD.Fd()), "config.json", int(slot.docker.dir.Fd()), "config.synthetic-auth.retained", unix.RENAME_EXCL) == nil,
		"image_preparation_auth_exclusive_retention")
	retained := missingDockerOpen(t, filepath.Join(filepath.Dir(slot.docker.path), "config.synthetic-auth.retained"), false)
	retainedInfo, statErr := retained.Stat()
	missingDockerRequire(t, statErr == nil, "image_preparation_retained_auth_stat")
	retainedDigest := missingDockerHash(t, retained)
	var gone unix.Stat_t
	missingDockerRequire(t, missingDockerSameMetadata(authInfo, retainedInfo) && retainedDigest == hex.EncodeToString(authDigest[:]) &&
		errors.Is(unix.Fstatat(int(configFD.Fd()), "config.json", &gone, unix.AT_SYMLINK_NOFOLLOW), unix.ENOENT), "image_preparation_auth_retention_unconfirmed")
	anonymous := []byte(`{"auths":{"https://index.docker.io/v1/":{}}}`)
	missingComposeWrite(t, slot.root, "config/config.json", anonymous, 0600)
	darwinInstalledImagePreparation(t, f, selection, record, "image-preparation-corrected", true, []string{username, password, encoded})
	ctx, cancel = context.WithTimeout(context.Background(), darwinScenarioRefusalBudget)
	darwinStartupOwnerLeasesFree(t, f, ctx, allIDs)
	cancel()
	stored.assertPreserved(t, f, "image-preparation-corrected-preservation.json")
	loaded, err := LoadProfile(f.Config.ProfilePolicy)
	missingDockerRequire(t, err == nil && reflect.DeepEqual(loaded.Declaration(), f.Profile), "image_preparation_profile_changed")
	currentPolicy, err := LoadEnrolledHostPolicy(selection)
	missingDockerRequire(t, err == nil && reflect.DeepEqual(currentPolicy.record, record), "image_preparation_host_policy_changed")
	retry := composeDarwinCLIStart(t, f, selection, record, "ensure", true)
	darwinScenarioResponse(t, f, retry, record, "image-preparation-ensure", darwinScenarioEnsureBudget, true)
	darwinScenarioReady(t, f, retry, "image-preparation-actual-ready.json")
	missingDockerRequire(t, retry.lifetime.attempt != original.lifetime.attempt, "image_preparation_actual_start_attempt_not_fresh")
	stored.assertPreserved(t, f, "image-preparation-final-preservation.json")
	slot.check(t, false)
	f.WriteEvidence(t, "image-preparation-summary.json", map[string]any{
		"realFixedPullFailure": true, "pullDiagnostic": "docker_image_pull_failed", "specificRegistryCauseClaimed": false,
		"anonymousCorrectedPreparationVerified": true, "preparationReadiness": "not_observed", "separateApplicationReadinessVerified": true,
		"sameEnrollmentBrokerVolumeAndOriginalRecord": true, "sharedConfigurationOrImagesDeleted": false,
	})
}
