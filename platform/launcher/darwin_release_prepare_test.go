//go:build darwin && cgo && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/privatefs"
	"golang.org/x/sys/unix"
)

// This entry point is deliberately separate from every runtime fixture. Mode
// "pins" reports the source-map digest without building or writing artifacts.
// Mode "prepare" requires that independently retained digest and a cleared
// build window. Neither mode contacts an engine or installs protected files.
//
// Required inputs:
// AMX_DARWIN_RELEASE_PREPARE_AUTHORIZED=1
// AMX_DARWIN_RELEASE_PREPARE_MODE=pins|prepare
// AMX_BOOTSTRAP_SELECTION_FILE and AMX_BOOTSTRAP_SELECTION_SHA256
// For prepare: AMX_DARWIN_RELEASE_PREPARE_SOURCE_SHA256,
// AMX_DARWIN_RELEASE_PREPARE_ROOT (an existing private directory), and
// AMX_DARWIN_CLI_BUILD_AUTHORIZED=1 for the shared CLI staging helper.
// An isolated snapshot needs its own separately pinned selection whose
// workspaceRoot is that exact snapshot root, not the original checkout.
func TestDarwinPrepareSignedRelease(t *testing.T) {
	if os.Getenv("AMX_DARWIN_RELEASE_PREPARE_AUTHORIZED") != "1" || os.Getuid() == 0 ||
		os.Getuid() != os.Geteuid() || runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Fatal("ordinary-user Mac ARM64 preparation authorization required")
	}
	mode := os.Getenv("AMX_DARWIN_RELEASE_PREPARE_MODE")
	if mode != "pins" && mode != "prepare" {
		t.Fatal("explicit source-pins or prepare mode required")
	}
	working, err := os.Getwd()
	if err != nil {
		t.Fatal("preparation working directory unavailable")
	}
	root := filepath.Dir(filepath.Dir(working))
	if working != filepath.Join(root, "platform", "launcher") {
		t.Fatal("preparation must run from the launcher package")
	}
	selected, selectionPin := loadBootstrapFixtureSelection(t)
	if selected.Target != "native-darwin" || selected.GOARCH != "arm64" || selected.WorkspaceRoot != root {
		t.Fatal("preparation selection does not bind the native source workspace")
	}
	pins := darwinPrepareSourcePins(t, root)
	pinsRaw := darwinPrepareJSON(t, pins)
	sourcePin := releaseDigest(pinsRaw)
	if mode == "pins" {
		t.Logf("preparationSourceSHA256=%s sourceFiles=%d", sourcePin, len(pins))
		return
	}
	if runtime.Version() != "go1.27.2" || os.Getenv("AMX_DARWIN_CLI_BUILD_AUTHORIZED") != "1" ||
		os.Getenv("AMX_DARWIN_RELEASE_PREPARE_SOURCE_SHA256") != sourcePin {
		t.Fatal("prepared native toolchain, build window and independently pinned source required")
	}
	base := os.Getenv("AMX_DARWIN_RELEASE_PREPARE_ROOT")
	if !bootstrapFixtureAbsolute(base) || base == root || strings.HasPrefix(base, root+string(os.PathSeparator)) {
		t.Fatal("preparation needs an existing private output directory outside the checkout")
	}
	darwinPreparePrivateDirectory(t, base)
	output, err := os.MkdirTemp(base, "darwin-release-prepare-")
	if err != nil {
		t.Fatal("fresh retained preparation directory unavailable")
	}
	completed := false
	// Preserve partial preparation on failure. A receipt is not an install
	// authorization, and no failure path removes or replaces retained artifacts.
	t.Cleanup(func() {
		status := "failed_retained"
		if completed && !t.Failed() {
			status = "prepared_for_review"
		}
		raw := darwinPrepareJSON(t, map[string]any{
			"schemaVersion": "1.0.0", "status": status, "sourcePinsSHA256": sourcePin,
			"selectionSHA256": selectionPin, "readyForInstallation": false,
			"dockerContacted": false, "runtimeExecuted": false,
		})
		darwinPrepareWrite(t, filepath.Join(output, "preparation-result.json"), raw, 0600)
	})
	stage := filepath.Join(output, "payload")
	work := filepath.Join(output, "build")
	for _, directory := range []string{stage, filepath.Join(stage, "bin"), work} {
		if os.Mkdir(directory, 0700) != nil {
			t.Fatal("fresh private preparation member directory unavailable")
		}
	}
	darwinPrepareWrite(t, filepath.Join(output, "source-pins.json"), pinsRaw, 0600)

	// Reuse the existing signature grammar and public authority. The template
	// key remains only in memory; its synthetic temporary members are never
	// copied into the retained package or listed in the nine-member plan.
	release := signedReleaseFixture(t)
	defer clear(release.private)
	release.policy.PackageDirectory = stage
	release.manifest.Broker = BrokerPins{Image: selected.Image, NATSVersion: selected.NATSVersion, ComposeVersion: selected.Docker.ComposeVersion}
	kernel := filepath.Join(work, "agentmux-kernel")
	build, err := bootstrapKernelBuild(selected, bootstrapActualHost(), runtime.GOROOT(), kernel, os.Environ())
	if err != nil {
		t.Fatal("native kernel preparation build refused")
	}
	build.Args = append([]string{"build", "-mod=readonly"}, build.Args[1:]...)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	command := exec.CommandContext(ctx, build.Executable, build.Args...)
	command.Dir, command.Env, command.WaitDelay = filepath.Join(root, "platform"), build.Env, time.Second
	err = command.Run()
	cancel()
	if err != nil || os.Chmod(kernel, 0500) != nil {
		t.Fatal("native kernel preparation build failed; partial output retained")
	}
	bootstrapCheckNativeKernel(t, kernel, "arm64")
	kernelRaw := darwinPrepareRead(t, kernel, 128*1024*1024)
	members, err := bootstrapCopyRoleMembers(stage, kernelRaw)
	if err != nil {
		t.Fatal("actual kernel role staging failed; partial output retained")
	}
	release.assembly["plugins"] = members
	release.refresh(t)
	for _, role := range protocol.Roles() {
		if os.Chmod(filepath.Join(stage, "bin", role), 0500) != nil {
			t.Fatal("private role staging mode failed")
		}
	}
	installed, err := LoadInstalledRelease(release.policy)
	if err != nil || installed.Trust().AssemblyDigest != release.authorization.AssemblyDigest ||
		installed.Trust().ReleaseManifestDigest != release.policy.ReleaseManifestDigest ||
		installed.BrokerPins() != release.manifest.Broker || len(installed.VerifiedAssembly().Members()) != 4 {
		t.Fatal("actual staged signed release validation failed")
	}
	// This stages an actual CLI independently of the four identical role images.
	// The helper has its own ordinary-user authorization and native build checks.
	cliSource := bootstrapStageDarwinCLI(t, work)
	cliRaw := darwinPrepareRead(t, cliSource, 128*1024*1024)
	cliDigest := releaseDigest(cliRaw)
	darwinPrepareWrite(t, filepath.Join(stage, "agentmux-runtime"), cliRaw, 0500)
	bootstrapCheckNativeKernel(t, filepath.Join(stage, "agentmux-runtime"), "arm64")

	version := bootstrapFixtureRandom(t, 32)
	destination := filepath.Join(bootstrapDarwinReleaseBase, version)
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatal("proposed protected release destination is not fresh")
	}
	publicTrust := release.policy
	publicTrust.PackageDirectory = destination
	plan := darwinPreparedReleasePlan{
		SchemaVersion: "1.0.0", Purpose: "prepare_only_signed_native_darwin_arm64_release",
		StageDirectory: stage, ReleaseDirectory: destination, OwnerUID: 0, Group: "wheel", DirectoryMode: "0755",
		SelectionSHA256: selectionPin, SourcePinsSHA256: sourcePin,
		PublicTrust: publicTrust, AssemblyDigest: installed.Trust().AssemblyDigest,
		KernelDigest: releaseDigest(kernelRaw), CLIDigest: cliDigest,
		GoVersion: runtime.Version(), Compiler: selected.Compiler, SDKRoot: selected.SDKRoot,
		TestOnlySigningKey: true, ReadyForInstallation: false,
	}
	for _, name := range darwinPreparedMemberNames() {
		maximum, installMode := int64(releaseMetadataLimit), "0444"
		if strings.HasPrefix(name, "bin/") || name == "agentmux-runtime" {
			maximum, installMode = 128*1024*1024, "0555"
		}
		path := filepath.Join(stage, filepath.FromSlash(name))
		raw := darwinPrepareRead(t, path, maximum)
		plan.Members = append(plan.Members, darwinPreparedReleaseMember{
			RelativePath: name, Source: path, Digest: releaseDigest(raw), Bytes: int64(len(raw)), Mode: installMode,
		})
	}
	darwinPrepareValidateRoster(t, stage, plan)
	if again, err := LoadInstalledRelease(release.policy); err != nil ||
		!reflect.DeepEqual(again.Trust(), installed.Trust()) || !reflect.DeepEqual(again.Assembly(), installed.Assembly()) {
		t.Fatal("staged signature or release trust changed during preparation")
	}
	currentSelection, currentSelectionPin := loadBootstrapFixtureSelection(t)
	if currentSelection != selected || currentSelectionPin != selectionPin ||
		!reflect.DeepEqual(pins, darwinPrepareSourcePins(t, root)) {
		t.Fatal("candidate source or selection changed during preparation")
	}
	planRaw := darwinPrepareJSON(t, plan)
	if len(planRaw) > 64*1024 {
		t.Fatal("closed nine-member preparation plan exceeds its byte bound")
	}
	darwinPrepareWrite(t, filepath.Join(output, "release-plan.json"), planRaw, 0600)
	darwinPrepareWrite(t, filepath.Join(output, "release-plan.sha256"), []byte(releaseDigest(planRaw)+"\n"), 0600)
	// A separate private artifact permits explicit CLI pin review without
	// treating the test release signing key as CLI installation authority.
	darwinPrepareWrite(t, filepath.Join(output, "cli-pin.json"), darwinPrepareJSON(t, map[string]any{
		"source": filepath.Join(stage, "agentmux-runtime"), "destination": filepath.Join(destination, "agentmux-runtime"),
		"digest": cliDigest, "bytes": len(cliRaw), "sourcePinsSHA256": sourcePin, "readyForInstallation": false,
	}), 0600)
	completed = true
	t.Logf("preparedPlanSHA256=%s memberCount=%d retainedPreparation=%s", releaseDigest(planRaw), len(plan.Members), output)
}

type darwinPreparedReleaseMember struct {
	RelativePath string `json:"relativePath"`
	Source       string `json:"source"`
	Digest       string `json:"digest"`
	Bytes        int64  `json:"bytes"`
	Mode         string `json:"mode"`
}

type darwinPreparedReleasePlan struct {
	SchemaVersion        string                        `json:"schemaVersion"`
	Purpose              string                        `json:"purpose"`
	StageDirectory       string                        `json:"stageDirectory"`
	ReleaseDirectory     string                        `json:"releaseDirectory"`
	OwnerUID             uint32                        `json:"ownerUID"`
	Group                string                        `json:"group"`
	DirectoryMode        string                        `json:"directoryMode"`
	SelectionSHA256      string                        `json:"selectionSHA256"`
	SourcePinsSHA256     string                        `json:"sourcePinsSHA256"`
	PublicTrust          ReleasePolicy                 `json:"publicTrust"`
	AssemblyDigest       string                        `json:"assemblyDigest"`
	KernelDigest         string                        `json:"kernelDigest"`
	CLIDigest            string                        `json:"cliDigest"`
	GoVersion            string                        `json:"goVersion"`
	Compiler             string                        `json:"compiler"`
	SDKRoot              string                        `json:"sdkRoot"`
	Members              []darwinPreparedReleaseMember `json:"members"`
	TestOnlySigningKey   bool                          `json:"testOnlySigningKey"`
	ReadyForInstallation bool                          `json:"readyForInstallation"`
}

func darwinPreparedMemberNames() []string {
	names := []string{"release-manifest.json", "protected-assembly.json", "release-authorization.json", "release-authorization.sig"}
	for _, role := range protocol.Roles() {
		names = append(names, "bin/"+role)
	}
	return append(names, "agentmux-runtime")
}

func darwinPrepareValidateRoster(t *testing.T, stage string, plan darwinPreparedReleasePlan) {
	t.Helper()
	if code := darwinPreparePlanCode(stage, plan); code != "" {
		t.Fatal(code)
	}
	seen := map[string]bool{}
	for _, member := range plan.Members {
		seen[member.RelativePath] = true
		raw := darwinPrepareRead(t, member.Source, 128*1024*1024)
		if releaseDigest(raw) != member.Digest || int64(len(raw)) != member.Bytes {
			t.Fatal("prepared release member changed")
		}
	}
	files := 0
	err := filepath.WalkDir(stage, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fs.ErrInvalid
		}
		rel, err := filepath.Rel(stage, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if rel != "." && rel != "bin" {
				return fs.ErrInvalid
			}
			return nil
		}
		if !entry.Type().IsRegular() || !seen[filepath.ToSlash(rel)] {
			return fs.ErrInvalid
		}
		files++
		return nil
	})
	if err != nil || files != 9 {
		t.Fatal("prepared payload tree is not the closed nine-member roster")
	}
}

// Check plan relationships without opening paths, creating keys or building.
// Filesystem byte admission remains a separate required part of preparation.
func darwinPreparePlanCode(stage string, plan darwinPreparedReleasePlan) string {
	names := darwinPreparedMemberNames()
	if len(plan.Members) != 9 || len(names) != 9 || !plan.TestOnlySigningKey || plan.ReadyForInstallation || plan.StageDirectory != stage {
		return "prepared_release_inventory_invalid"
	}
	if !releaseHash.MatchString(plan.KernelDigest) || !releaseHash.MatchString(plan.CLIDigest) ||
		!releaseHash.MatchString(plan.SourcePinsSHA256) || !fullID.MatchString(plan.SelectionSHA256) {
		return "prepared_release_pin_shape_invalid"
	}
	seen := map[string]bool{}
	for index, member := range plan.Members {
		expectedMode := "0444"
		if strings.HasPrefix(names[index], "bin/") || names[index] == "agentmux-runtime" {
			expectedMode = "0555"
		}
		if member.RelativePath != names[index] || member.Source != filepath.Join(stage, filepath.FromSlash(names[index])) ||
			member.Bytes < 1 || member.Mode != expectedMode || !releaseHash.MatchString(member.Digest) || seen[member.RelativePath] {
			return "prepared_release_member_binding_invalid"
		}
		if strings.HasPrefix(member.RelativePath, "bin/") && member.Digest != plan.KernelDigest {
			return "prepared_release_kernel_binding_invalid"
		}
		if member.RelativePath == "agentmux-runtime" && member.Digest != plan.CLIDigest {
			return "prepared_release_cli_binding_invalid"
		}
		seen[member.RelativePath] = true
	}
	return ""
}

func TestDarwinPreparedPlanRefusesCrossBinding(t *testing.T) {
	stage := "/private/var/agentmux-prepare-control/payload"
	sha := func(character string) string { return "sha256:" + strings.Repeat(character, 64) }
	plan := darwinPreparedReleasePlan{StageDirectory: stage, TestOnlySigningKey: true,
		KernelDigest: sha("a"), CLIDigest: sha("b"), SourcePinsSHA256: sha("c"), SelectionSHA256: strings.Repeat("d", 64)}
	for _, name := range darwinPreparedMemberNames() {
		digest, mode := sha("e"), "0444"
		if strings.HasPrefix(name, "bin/") {
			digest, mode = plan.KernelDigest, "0555"
		}
		if name == "agentmux-runtime" {
			digest, mode = plan.CLIDigest, "0555"
		}
		plan.Members = append(plan.Members, darwinPreparedReleaseMember{RelativePath: name,
			Source: filepath.Join(stage, filepath.FromSlash(name)), Digest: digest, Bytes: 64, Mode: mode})
	}
	if code := darwinPreparePlanCode(stage, plan); code != "" {
		t.Fatal("complete independently bound plan refused", code)
	}
	cases := []struct {
		name   string
		change func(*darwinPreparedReleasePlan)
		code   string
	}{
		{"kernel_pin_shape", func(p *darwinPreparedReleasePlan) { p.KernelDigest = "sha256:bad" }, "prepared_release_pin_shape_invalid"},
		{"cli_pin_shape", func(p *darwinPreparedReleasePlan) { p.CLIDigest = "" }, "prepared_release_pin_shape_invalid"},
		{"source_pin_shape", func(p *darwinPreparedReleasePlan) { p.SourcePinsSHA256 = "" }, "prepared_release_pin_shape_invalid"},
		{"selection_pin_shape", func(p *darwinPreparedReleasePlan) { p.SelectionSHA256 = sha("d") }, "prepared_release_pin_shape_invalid"},
		{"cli_member_uses_kernel", func(p *darwinPreparedReleasePlan) { p.Members[8].Digest = p.KernelDigest }, "prepared_release_cli_binding_invalid"},
		{"changed_cli_pin", func(p *darwinPreparedReleasePlan) { p.CLIDigest = sha("f") }, "prepared_release_cli_binding_invalid"},
		{"missing_member", func(p *darwinPreparedReleasePlan) { p.Members = p.Members[:8] }, "prepared_release_inventory_invalid"},
		{"unexpected_member", func(p *darwinPreparedReleasePlan) { p.Members[0].RelativePath = "unexpected" }, "prepared_release_member_binding_invalid"},
		{"member_mode", func(p *darwinPreparedReleasePlan) { p.Members[0].Mode = "0555" }, "prepared_release_member_binding_invalid"},
		{"install_ready", func(p *darwinPreparedReleasePlan) { p.ReadyForInstallation = true }, "prepared_release_inventory_invalid"},
	}
	for index, role := range protocol.Roles() {
		cases = append(cases, struct {
			name   string
			change func(*darwinPreparedReleasePlan)
			code   string
		}{"role_uses_cli_" + role, func(p *darwinPreparedReleasePlan) { p.Members[4+index].Digest = p.CLIDigest }, "prepared_release_kernel_binding_invalid"})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := plan
			bad.Members = append([]darwinPreparedReleaseMember(nil), plan.Members...)
			tc.change(&bad)
			if code := darwinPreparePlanCode(stage, bad); code != tc.code {
				t.Fatal("invalid plan refusal differs", code)
			}
		})
	}
}

func darwinPrepareSourcePins(t *testing.T, root string) map[string]string {
	t.Helper()
	pins := map[string]string{}
	var total int64
	for _, folder := range []string{"platform", "contracts/v1"} {
		err := filepath.WalkDir(filepath.Join(root, folder), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return fs.ErrInvalid
			}
			if entry.IsDir() {
				return nil
			}
			if !entry.Type().IsRegular() {
				return fs.ErrInvalid
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			if len(pins) >= 8192 {
				return fs.ErrInvalid
			}
			fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			file := os.NewFile(uintptr(fd), "candidate-source-pin")
			var before, after unix.Stat_t
			if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size < 0 || before.Size > 8*1024*1024 {
				closeErr := file.Close()
				if closeErr != nil {
					return closeErr
				}
				return fs.ErrInvalid
			}
			raw, readErr := io.ReadAll(io.LimitReader(file, 8*1024*1024+1))
			stable := unix.Fstat(fd, &after) == nil && before.Dev == after.Dev && before.Ino == after.Ino &&
				before.Size == after.Size && before.Mtim == after.Mtim && before.Ctim == after.Ctim
			closeErr := file.Close()
			if readErr != nil || closeErr != nil || !stable || int64(len(raw)) != before.Size {
				return fs.ErrInvalid
			}
			total += int64(len(raw))
			if total > 64*1024*1024 {
				return fs.ErrInvalid
			}
			pins[filepath.ToSlash(rel)] = releaseDigest(raw)
			return nil
		})
		if err != nil {
			t.Fatal("candidate source pin inventory refused")
		}
	}
	return pins
}

func darwinPreparePrivateDirectory(t *testing.T, path string) {
	t.Helper()
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		t.Fatal("private preparation base is not canonical")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("private preparation base unavailable")
	}
	file := os.NewFile(uintptr(fd), "private-preparation-base")
	var info unix.Stat_t
	admitted := unix.Fstat(fd, &info) == nil && info.Uid == uint32(os.Geteuid()) && info.Mode&0077 == 0 &&
		info.Mode&06000 == 0 && privatefs.CheckDescriptor(file, privatefs.PrivateObject) == nil
	closeErr := file.Close()
	if !admitted || closeErr != nil {
		t.Fatal("private preparation base access or close refused")
	}
}

func darwinPrepareRead(t *testing.T, path string, maximum int64) []byte {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("private staged input unavailable")
	}
	file := os.NewFile(uintptr(fd), "private-staged-input")
	var before, after unix.Stat_t
	admitted := unix.Fstat(fd, &before) == nil && before.Mode&unix.S_IFMT == unix.S_IFREG &&
		before.Uid == uint32(os.Geteuid()) && before.Nlink == 1 && before.Mode&0077 == 0 && before.Mode&06000 == 0 &&
		before.Size > 0 && before.Size <= maximum && privatefs.CheckDescriptor(file, privatefs.PrivateObject) == nil
	if !admitted {
		closeErr := file.Close()
		t.Fatalf("private staged input refused; descriptorCloseSucceeded=%t", closeErr == nil)
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	stable := unix.Fstat(fd, &after) == nil && before.Dev == after.Dev && before.Ino == after.Ino &&
		before.Size == after.Size && before.Mtim == after.Mtim && before.Ctim == after.Ctim
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || !stable || int64(len(raw)) != before.Size {
		t.Fatal("private staged bytes changed or descriptor close failed")
	}
	return raw
}

func darwinPrepareJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal("private preparation JSON encoding failed")
	}
	return raw
}

func darwinPrepareWrite(t *testing.T, path string, raw []byte, mode os.FileMode) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("exclusive private preparation output unavailable")
	}
	n, writeErr := file.Write(raw)
	syncErr := file.Sync()
	var modeErr error
	if writeErr == nil && n == len(raw) && syncErr == nil {
		modeErr = file.Chmod(mode)
	}
	closeErr := file.Close()
	if writeErr != nil || n != len(raw) || syncErr != nil || modeErr != nil || closeErr != nil {
		t.Fatal("private preparation output incomplete; partial artifact retained")
	}
}
