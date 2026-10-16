//go:build darwin && cgo && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

const (
	darwinMatchPreparedSHA  = "sha256:cca9d084cb8122b29582e5132d7e4a970f2078daa581d1355782ef882221af26"
	darwinMatchOldSourceSHA = "sha256:75d0838a440acebaaa57a0d6ea55a323d3249e530c7956b397d2733a2afd6da6"
	darwinMatchRootPlanSHA  = "sha256:fed6d962d517588b49dab43ab067072adacf8bea67cbe3bc94d9bcff204668b3"
	darwinMatchKernelSHA    = "sha256:4b88f1e42b7978e9ce570a19f3b5b78ed1902740f4e6f4be1507e2ad6a20ef36"
	darwinMatchCLISHA       = "sha256:a4f038fbeab062503d7c3e30b65c5f8ab0ea4fe29a7f9658a5c647155f10522a"
	darwinMatchRelease      = bootstrapDarwinReleaseBase + "/050f4f5c4cf78920cc11be3d94f96a75008d19b21201f7663cd5100ed6ced96c"
)

type darwinMatchMember struct {
	RelativePath string `json:"relativePath"`
	Digest       string `json:"digest"`
	Bytes        int64  `json:"bytes"`
	Mode         string `json:"mode"`
}

type darwinMatchRootPlan struct {
	SchemaVersion        string              `json:"schemaVersion"`
	Purpose              string              `json:"purpose"`
	PreparedPlanDigest   string              `json:"preparedPlanDigest"`
	ReleaseDirectory     string              `json:"releaseDirectory"`
	Ancestors            []string            `json:"ancestors"`
	OwnerUID             uint32              `json:"ownerUID"`
	Group                string              `json:"group"`
	DirectoryMode        string              `json:"directoryMode"`
	Members              []darwinMatchMember `json:"members"`
	CopyProtocol         string              `json:"copyProtocol"`
	ReadyForInstallation bool                `json:"readyForInstallation"`
}

// This is an explicit build-only comparison, never an install or runtime fixture.
// AMX_DARWIN_RELEASE_MATCH_AUTHORIZED=1 and MODE=pins report current source pins.
// MODE=match additionally requires BUILD_AUTHORIZED=1, SOURCE_SHA256, ROOT,
// PREPARED_PLAN and ROOT_PLAN, all with the AMX_DARWIN_RELEASE_MATCH_ prefix.
// ROOT must already be private and outside the checkout. Both plans are private
// retained files. The selection must independently bind this exact snapshot.
// Historical source pins are recorded, not compared to the current source map:
// the composer itself contains the historical plan digest.
func TestDarwinMatchPreparedReleaseCandidate(t *testing.T) {
	if os.Getenv("AMX_DARWIN_RELEASE_MATCH_AUTHORIZED") != "1" || os.Getuid() == 0 ||
		os.Getuid() != os.Geteuid() || runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Fatal("ordinary-user Mac ARM64 candidate-match authorization required")
	}
	mode := os.Getenv("AMX_DARWIN_RELEASE_MATCH_MODE")
	if mode != "pins" && mode != "match" {
		t.Fatal("explicit pins or match mode required")
	}
	working, err := os.Getwd()
	if err != nil {
		t.Fatal("candidate working directory unavailable")
	}
	root := filepath.Dir(filepath.Dir(working))
	if working != filepath.Join(root, "platform", "launcher") {
		t.Fatal("candidate match must run from the launcher package")
	}
	selected, selectionPin := loadBootstrapFixtureSelection(t)
	if selected.Target != "native-darwin" || selected.GOARCH != "arm64" || selected.WorkspaceRoot != root {
		t.Fatal("candidate selection must bind this native snapshot")
	}
	pins := darwinPrepareSourcePins(t, root)
	pinsRaw := darwinPrepareJSON(t, pins)
	sourcePin := releaseDigest(pinsRaw)
	if mode == "pins" {
		t.Logf("currentWholeSourcePinsSHA256=%s sourceFiles=%d", sourcePin, len(pins))
		return
	}
	if runtime.Version() != "go1.27.2" || os.Getenv("AMX_DARWIN_RELEASE_MATCH_BUILD_AUTHORIZED") != "1" ||
		os.Getenv("AMX_DARWIN_RELEASE_MATCH_SOURCE_SHA256") != sourcePin {
		t.Fatal("pinned current source, exact Go toolchain and separate build authorization required")
	}
	preparedRaw := darwinPrepareRead(t, os.Getenv("AMX_DARWIN_RELEASE_MATCH_PREPARED_PLAN"), 64*1024)
	rootRaw := darwinPrepareRead(t, os.Getenv("AMX_DARWIN_RELEASE_MATCH_ROOT_PLAN"), 64*1024)
	var prepared darwinPreparedReleasePlan
	var installation darwinMatchRootPlan
	if releaseDigest(preparedRaw) != darwinMatchPreparedSHA || releaseDigest(rootRaw) != darwinMatchRootPlanSHA ||
		protocol.DecodeClosedJSON(preparedRaw, &prepared, 64*1024) != nil ||
		protocol.DecodeClosedJSON(rootRaw, &installation, 64*1024) != nil {
		t.Fatal("reviewed historical plan pins or closed schemas refused")
	}
	if code := darwinMatchPlanCode(prepared, installation); code != "" {
		t.Fatal(code)
	}
	if prepared.GoVersion != runtime.Version() || selected.Compiler != prepared.Compiler || selected.SDKRoot != prepared.SDKRoot {
		t.Fatal("candidate toolchain selection differs from preparation")
	}
	// The selected SDK path alone is not proof of unchanged SDK contents.
	// Record its current resolution; runtime/SDK admission remains a separate gate.
	sdkResolved, err := filepath.EvalSymlinks(selected.SDKRoot)
	if err != nil {
		t.Fatal("selected SDK resolution unavailable")
	}
	base := os.Getenv("AMX_DARWIN_RELEASE_MATCH_ROOT")
	if !bootstrapFixtureAbsolute(base) || base == root || strings.HasPrefix(base, root+string(os.PathSeparator)) {
		t.Fatal("candidate output needs a private directory outside the snapshot")
	}
	darwinPreparePrivateDirectory(t, base)
	output, err := os.MkdirTemp(base, "darwin-release-match-")
	if err != nil {
		t.Fatal("fresh retained candidate output unavailable")
	}
	matched, sourceStable := false, false
	actual := map[string]darwinMatchMember{}
	t.Cleanup(func() {
		status := "failed_retained"
		if matched && sourceStable && !t.Failed() {
			status = "artifact_bytes_matched_for_review"
		}
		darwinPrepareWrite(t, filepath.Join(output, "candidate-match-result.json"), darwinPrepareJSON(t, map[string]any{
			"schemaVersion": "1.0.0", "status": status, "snapshotRoot": root,
			"currentWholeSourcePinsSHA256": sourcePin, "historicalWholeSourcePinsSHA256": prepared.SourcePinsSHA256,
			"oldPlanSHA256": darwinMatchPreparedSHA, "rootPlanSHA256": darwinMatchRootPlanSHA,
			"selectionSHA256": selectionPin, "goVersion": runtime.Version(), "compiler": selected.Compiler,
			"sdkRoot": selected.SDKRoot, "currentResolvedSDKRoot": sdkResolved,
			"sdkContentsHistoricallyProven": false, "actualOutputs": actual,
			"artifactBytesMatched": matched, "sourceAndSelectionUnchanged": sourceStable,
			"finalCandidateQualified": false, "requiresPostFreezeCommittedBranchRerun": true,
			"signed": false, "installed": false, "runtimeExecuted": false, "dockerContacted": false,
		}), 0600)
	})
	darwinPrepareWrite(t, filepath.Join(output, "current-source-pins.json"), pinsRaw, 0600)
	build, err := bootstrapKernelBuild(selected, bootstrapActualHost(), runtime.GOROOT(), filepath.Join(output, "agentmux-kernel"), os.Environ())
	if err != nil {
		t.Fatal("native candidate build plan refused")
	}
	build.Args = append([]string{"build", "-mod=readonly"}, build.Args[1:]...)
	for _, image := range []struct {
		name      string
		args      []string
		budget    time.Duration
		wantSHA   string
		wantBytes int64
	}{
		{"agentmux-kernel", build.Args, 120 * time.Second, prepared.KernelDigest, 6609922},
		{"agentmux-runtime", []string{"build", "-mod=readonly", "-trimpath", "-o", filepath.Join(output, "agentmux-runtime"), "./cmd/agentmux-runtime"}, 60 * time.Second, prepared.CLIDigest, 13576450},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), image.budget)
		command := exec.CommandContext(ctx, build.Executable, image.args...)
		command.Dir, command.Env, command.WaitDelay = filepath.Join(root, "platform"), build.Env, time.Second
		err = command.Run()
		cancel()
		path := filepath.Join(output, image.name)
		if err != nil || os.Chmod(path, 0500) != nil {
			t.Fatal("native candidate build failed; partial artifacts retained")
		}
		bootstrapCheckNativeKernel(t, path, "arm64")
		raw := darwinPrepareRead(t, path, 128*1024*1024)
		actual[image.name] = darwinMatchMember{RelativePath: image.name, Digest: releaseDigest(raw), Bytes: int64(len(raw)), Mode: "0500"}
		if actual[image.name].Digest != image.wantSHA || actual[image.name].Bytes != image.wantBytes {
			t.Fatal("current candidate bytes differ from reviewed prepared and root artifact expectations")
		}
	}
	current, currentPin := loadBootstrapFixtureSelection(t)
	sourceStable = current == selected && currentPin == selectionPin && reflect.DeepEqual(pins, darwinPrepareSourcePins(t, root))
	if !sourceStable || !reflect.DeepEqual(preparedRaw, darwinPrepareRead(t, os.Getenv("AMX_DARWIN_RELEASE_MATCH_PREPARED_PLAN"), 64*1024)) ||
		!reflect.DeepEqual(rootRaw, darwinPrepareRead(t, os.Getenv("AMX_DARWIN_RELEASE_MATCH_ROOT_PLAN"), 64*1024)) {
		t.Fatal("candidate source, selection or reviewed input changed during comparison")
	}
	matched = true
	t.Logf("currentWholeSourcePinsSHA256=%s oldPlanSHA256=%s retainedCandidateMatch=%s", sourcePin, darwinMatchPreparedSHA, output)
}

// Both exact plan hashes are checked before this cross-binding check. This also
// keeps the executable expectations separate from current whole-source pins.
func darwinMatchPlanCode(prepared darwinPreparedReleasePlan, installation darwinMatchRootPlan) string {
	if darwinPreparePlanCode(prepared.StageDirectory, prepared) != "" ||
		prepared.SourcePinsSHA256 != darwinMatchOldSourceSHA || prepared.KernelDigest != darwinMatchKernelSHA ||
		prepared.CLIDigest != darwinMatchCLISHA || prepared.ReleaseDirectory != darwinMatchRelease ||
		prepared.PublicTrust.PackageDirectory != darwinMatchRelease ||
		installation.PreparedPlanDigest != darwinMatchPreparedSHA || installation.ReleaseDirectory != darwinMatchRelease ||
		installation.SchemaVersion != "1.0.0" || installation.Purpose != "reviewed_nine_member_native_darwin_arm64_materialization" ||
		installation.CopyProtocol != "bounded_stdin_sha256_verified_before_exclusive_descriptor_creation" ||
		installation.OwnerUID != 0 || installation.Group != "wheel" || installation.DirectoryMode != "0755" || !installation.ReadyForInstallation ||
		len(installation.Members) != 9 {
		return "candidate_reviewed_plan_binding_refused"
	}
	for index, member := range prepared.Members {
		if installation.Members[index] != (darwinMatchMember{RelativePath: member.RelativePath, Digest: member.Digest, Bytes: member.Bytes, Mode: member.Mode}) {
			return "candidate_nine_member_cross_binding_refused"
		}
	}
	return ""
}

func TestDarwinCandidateMatchPlanCrossBinding(t *testing.T) {
	prepared := darwinPreparedReleasePlan{
		StageDirectory:   "/private/var/agentmux-candidate-control/payload",
		ReleaseDirectory: darwinMatchRelease, SourcePinsSHA256: darwinMatchOldSourceSHA,
		SelectionSHA256: strings.Repeat("a", 64), KernelDigest: darwinMatchKernelSHA,
		CLIDigest: darwinMatchCLISHA, TestOnlySigningKey: true,
	}
	prepared.PublicTrust.PackageDirectory = darwinMatchRelease
	installation := darwinMatchRootPlan{
		SchemaVersion: "1.0.0", Purpose: "reviewed_nine_member_native_darwin_arm64_materialization",
		PreparedPlanDigest: darwinMatchPreparedSHA, ReleaseDirectory: darwinMatchRelease,
		Group: "wheel", DirectoryMode: "0755", ReadyForInstallation: true,
		CopyProtocol: "bounded_stdin_sha256_verified_before_exclusive_descriptor_creation",
	}
	for _, name := range darwinPreparedMemberNames() {
		digest, mode := "sha256:"+strings.Repeat("b", 64), "0444"
		if strings.HasPrefix(name, "bin/") {
			digest, mode = darwinMatchKernelSHA, "0555"
		}
		if name == "agentmux-runtime" {
			digest, mode = darwinMatchCLISHA, "0555"
		}
		prepared.Members = append(prepared.Members, darwinPreparedReleaseMember{
			RelativePath: name, Source: filepath.Join(prepared.StageDirectory, filepath.FromSlash(name)),
			Digest: digest, Bytes: 64, Mode: mode,
		})
		installation.Members = append(installation.Members, darwinMatchMember{
			RelativePath: name, Digest: digest, Bytes: 64, Mode: mode,
		})
	}
	if darwinMatchPlanCode(prepared, installation) != "" {
		t.Fatal("bound control plans refused")
	}
	for _, change := range []func(*darwinMatchRootPlan){
		func(p *darwinMatchRootPlan) { p.PreparedPlanDigest = darwinMatchOldSourceSHA },
		func(p *darwinMatchRootPlan) { p.Members[8].Digest = darwinMatchKernelSHA },
		func(p *darwinMatchRootPlan) { p.Members[4].Bytes++ },
		func(p *darwinMatchRootPlan) { p.Members = p.Members[:8] },
	} {
		altered := installation
		altered.Members = append([]darwinMatchMember(nil), installation.Members...)
		change(&altered)
		if darwinMatchPlanCode(prepared, altered) == "" {
			t.Fatal("altered plan cross-binding accepted")
		}
	}
}
