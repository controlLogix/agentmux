//go:build darwin && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"debug/macho"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/privatefs"
	"golang.org/x/sys/unix"
)

// A plan records exact paths and bytes for review before privileged setup.
// Staging never installs, and installation never builds from source.
type bootstrapDarwinCLIInstallPlan struct {
	Source      string     `json:"source"`
	Destination string     `json:"destination"`
	Digest      string     `json:"digest"`
	Bytes       int64      `json:"bytes"`
	Ancestors   []string   `json:"ancestors"`
	CopyProtocol string    `json:"copyProtocol"`
	ReadyForExecution bool `json:"readyForExecution"`
	payload []byte
}

type bootstrapDarwinFixtureMember struct {
	RelativePath string `json:"relativePath"`
	Digest string `json:"digest"`
	Bytes int64 `json:"bytes"`
	Mode string `json:"mode"`
}

// This proposal describes helper identity controls only. It cannot enroll a
// release key or qualify the real installed CLI and signed protected assembly.
type bootstrapDarwinIdentityFixturePlan struct {
	Purpose string `json:"purpose"`
	ReleaseDirectory string `json:"releaseDirectory"`
	Ancestors []string `json:"ancestors"`
	DirectoryMode string `json:"directoryMode"`
	OwnerUID uint32 `json:"ownerUID"`
	Group string `json:"group"`
	Members []bootstrapDarwinFixtureMember `json:"members"`
	InputDigest string `json:"inputDigest"`
	InputBytes int64 `json:"inputBytes"`
	CopyProtocol string `json:"copyProtocol"`
	ReadyForExecution bool `json:"readyForExecution"`
	SourceDescriptorClosed bool `json:"sourceDescriptorClosed"`
}

// The returned payload is the only proposed installer input. Source is read
// once through a held descriptor; no privileged process reopens its pathname.
// A future fixed installer must verify all input bytes before any mutation,
// hold root-owned ancestors, and record each exclusive creation and close.
func bootstrapPlanDarwinIdentityFixture(source, version string) (plan bootstrapDarwinIdentityFixturePlan, payload []byte, result error) {
	if !bootstrapFixtureAbsolute(source) || !fullID.MatchString(version) || os.Geteuid() == 0 {
		return plan, nil, errors.New("identity_fixture_plan_invalid")
	}
	directory := filepath.Join(bootstrapDarwinReleaseBase, version)
	if _, err := os.Lstat(directory); !os.IsNotExist(err) {
		return plan, nil, errors.New("identity_fixture_destination_not_fresh")
	}
	fd, err := unix.Open(source, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil { return plan, nil, errors.New("identity_fixture_source_unavailable") }
	file := os.NewFile(uintptr(fd), "identity-fixture-plan-source")
	defer func() {
		closeErr := file.Close()
		plan.SourceDescriptorClosed = closeErr == nil
		if closeErr != nil {
			result = errors.Join(result, errors.New("identity_fixture_source_close_failed"))
			payload = nil
		}
	}()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&0077 != 0 || before.Mode&06000 != 0 || before.Mode&0100 == 0 ||
		before.Uid != uint32(os.Geteuid()) || before.Nlink != 1 || before.Size < 32 || before.Size > 32*1024*1024 || privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil {
		return plan, nil, errors.New("identity_fixture_source_refused")
	}
	payload, err = io.ReadAll(io.LimitReader(file, 32*1024*1024+1))
	if err != nil || int64(len(payload)) != before.Size || unix.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino ||
		before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return plan, nil, errors.New("identity_fixture_source_changed")
	}
	digest := releaseDigest(payload)
	plan = bootstrapDarwinIdentityFixturePlan{Purpose: "cooperative_native_identity_fixture_only", ReleaseDirectory: directory,
		Ancestors: []string{"/", "/Library", "/Library/Application Support", "/Library/Application Support/Agentmux", "/Library/Application Support/Agentmux/Protected", bootstrapDarwinReleaseBase, directory, filepath.Join(directory, "bin")},
		DirectoryMode: "0755", OwnerUID: 0, Group: "wheel", InputDigest: digest, InputBytes: int64(len(payload)),
		CopyProtocol: "bounded_stdin_sha256_verified_before_exclusive_descriptor_creation", ReadyForExecution: false}
	plan.Members = append(plan.Members, bootstrapDarwinFixtureMember{RelativePath: "fixture", Digest: digest, Bytes: int64(len(payload)), Mode: "0555"})
	for _, role := range protocol.Roles() {
		plan.Members = append(plan.Members, bootstrapDarwinFixtureMember{RelativePath: "bin/"+role, Digest: digest, Bytes: int64(len(payload)), Mode: "0555"})
	}
	return plan, payload, nil
}

// Encode exact retained bytes for the reviewed fixed installer. A later setup
// invocation supplies the returned manifest digest as a separate literal
// argument. Neither the envelope nor the installer contains a source pathname.
// Changing ReadyForExecution requires a new manifest digest and source review.
func bootstrapDarwinIdentityFixtureInput(plan bootstrapDarwinIdentityFixturePlan, payload []byte) ([]byte, string, error) {
	if plan.Purpose != "cooperative_native_identity_fixture_only" || !plan.ReadyForExecution || !plan.SourceDescriptorClosed ||
		plan.InputBytes < 32 || plan.InputBytes > 32*1024*1024 || int64(len(payload)) != plan.InputBytes || releaseDigest(payload) != plan.InputDigest {
		return nil, "", errors.New("reviewed_identity_fixture_input_invalid")
	}
	manifest, err := json.Marshal(plan)
	if err != nil || len(manifest) > 64*1024 { return nil, "", errors.New("identity_fixture_manifest_invalid") }
	envelope := struct {
		Manifest []byte `json:"manifestBase64"`
		Payload []byte `json:"payloadBase64"`
	}{manifest, payload}
	raw, err := json.Marshal(envelope)
	if err != nil { return nil, "", errors.New("identity_fixture_envelope_invalid") }
	return raw, releaseDigest(manifest), nil
}

func bootstrapStageDarwinCLI(t *testing.T, directory string) string {
	t.Helper()
	if os.Getenv("AMX_DARWIN_CLI_BUILD_AUTHORIZED") != "1" || os.Geteuid() == 0 {
		t.Fatal("native CLI staging needs a cleared build window and an unprivileged process")
	}
	selected, _ := loadBootstrapFixtureSelection(t)
	if selected.GOOS != "darwin" || !bootstrapFixtureAbsolute(directory) {
		t.Fatal("native CLI staging selection refused")
	}
	stage, err := os.MkdirTemp(directory, "runtime-cli-stage-")
	if err != nil {
		t.Fatal("private CLI staging directory unavailable")
	}
	output := filepath.Join(stage, "agentmux-runtime")
	plan, err := bootstrapKernelBuild(selected, bootstrapActualHost(), goruntime.GOROOT(), output, os.Environ())
	if err != nil {
		t.Fatal("native CLI build selection refused")
	}
	plan.Args = []string{"build", "-mod=readonly", "-trimpath", "-o", output, "./cmd/agentmux-runtime"}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, plan.Executable, plan.Args...)
	command.Dir, command.Env, command.WaitDelay = "..", plan.Env, time.Second
	if command.Run() != nil || os.Chmod(output, 0500) != nil {
		t.Fatal("actual native CLI staging failed")
	}
	bootstrapCheckNativeKernel(t, output, selected.GOARCH)
	return output
}

func bootstrapPlanDarwinCLIInstall(source, version string) (bootstrapDarwinCLIInstallPlan, error) {
	if !bootstrapFixtureAbsolute(source) || filepath.Base(source) != "agentmux-runtime" || !fullID.MatchString(version) {
		return bootstrapDarwinCLIInstallPlan{}, errors.New("cli_install_plan_invalid")
	}
	fd, err := unix.Open(source, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return bootstrapDarwinCLIInstallPlan{}, errors.New("cli_install_source_invalid")
	}
	file := os.NewFile(uintptr(fd), "cli-install-source")
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&07777 != 0500 ||
		before.Uid != uint32(os.Geteuid()) || before.Nlink != 1 || before.Size < 1 || before.Size > 128*1024*1024 ||
		privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil {
		return bootstrapDarwinCLIInstallPlan{}, errors.New("cli_install_source_invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 128*1024*1024+1))
	if err != nil || int64(len(raw)) != before.Size || unix.Fstat(fd, &after) != nil ||
		before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return bootstrapDarwinCLIInstallPlan{}, errors.New("cli_install_source_unavailable")
	}
	directory := filepath.Join(bootstrapDarwinReleaseBase, version)
	destination := filepath.Join(directory, "agentmux-runtime")
	return bootstrapDarwinCLIInstallPlan{Source: source, Destination: destination, Digest: releaseDigest(raw), Bytes: int64(len(raw)),
		Ancestors: []string{"/", "/Library", "/Library/Application Support", "/Library/Application Support/Agentmux", "/Library/Application Support/Agentmux/Protected", bootstrapDarwinReleaseBase, directory},
		CopyProtocol: "bounded_stdin_sha256_verified_before_exclusive_descriptor_creation", ReadyForExecution: false, payload: raw}, nil
}

// Persist a reviewable plan before any privileged command. The caller chooses
// a fresh filename inside the retained private staging directory.
func bootstrapWriteDarwinCLIInstallPlan(t *testing.T, path string, plan bootstrapDarwinCLIInstallPlan) string {
	t.Helper()
	raw, err := json.Marshal(plan)
	if err != nil || !bootstrapFixtureAbsolute(path) || filepath.Dir(path) != filepath.Dir(plan.Source) {
		t.Fatal("CLI install review plan destination refused")
	}
	if int64(len(plan.payload)) != plan.Bytes || releaseDigest(plan.payload) != plan.Digest || plan.ReadyForExecution {
		t.Fatal("review plan must retain its exact staged bytes and remain nonexecutable")
	}
	payload, err := os.OpenFile(path+".payload.private", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil { t.Fatal("private reviewed CLI payload unavailable") }
	n, payloadErr := payload.Write(plan.payload)
	payloadCloseErr := payload.Close()
	if payloadErr != nil || n != len(plan.payload) || payloadCloseErr != nil {
		t.Fatalf("private CLI payload retained after failure; descriptorCloseSucceeded=%t", payloadCloseErr == nil)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("private CLI install review plan unavailable")
	}
	_, writeErr := file.Write(raw)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("private CLI install review plan write failed")
	}
	return releaseDigest(raw)
}

// Runtime fixtures consume an already reviewed and installed plan. They never
// invoke the staging or installation helpers to satisfy a missing prerequisite.
func bootstrapReadDarwinInstalledCLI(t *testing.T) hostPolicyExecutable {
	t.Helper()
	path := os.Getenv("AMX_DARWIN_CLI_INSTALL_PLAN")
	if !bootstrapFixtureAbsolute(path) || os.Geteuid() == 0 {
		t.Fatal("reviewed installed CLI plan is required for unprivileged runtime tests")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("reviewed installed CLI plan unavailable")
	}
	file := os.NewFile(uintptr(fd), "installed-cli-plan")
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0600 ||
		stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || stat.Size < 1 || stat.Size > 64*1024 ||
		privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil {
		t.Fatal("reviewed installed CLI plan access refused")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	var plan bootstrapDarwinCLIInstallPlan
	if err != nil || int64(len(raw)) != stat.Size || protocol.DecodeClosedJSON(raw, &plan, 64*1024) != nil ||
		os.Getenv("AMX_DARWIN_CLI_REVIEWED_INSTALL_PLAN") != releaseDigest(raw) {
		t.Fatal("installed CLI plan does not match its reviewed bytes")
	}
	directory := filepath.Dir(plan.Destination)
	// The product installer snapshots verified package bytes before exclusive
	// creation. Keep the earlier stdin installer usable for existing fixtures.
	copyProtocolValid := plan.CopyProtocol == "bounded_stdin_sha256_verified_before_exclusive_descriptor_creation" || plan.CopyProtocol == "verified_native_package_snapshot_exclusive_copy"
	if filepath.Dir(directory) != bootstrapDarwinReleaseBase || !fullID.MatchString(filepath.Base(directory)) || filepath.Base(plan.Destination) != "agentmux-runtime" ||
		plan.Bytes < 1 || plan.Bytes > 128*1024*1024 || !releaseHash.MatchString(plan.Digest) || !copyProtocolValid {
		t.Fatal("reviewed installed CLI prerequisite binding invalid")
	}
	return hostPolicyExecutable{Path: plan.Destination, Digest: plan.Digest}
}

func bootstrapCheckNativeKernel(t *testing.T, path, arch string) {
	t.Helper()
	executable, err := macho.Open(path)
	if err != nil {
		t.Fatal("actual kernel is not a native Mach-O executable")
	}
	defer executable.Close()
	want := macho.CpuAmd64
	if arch == "arm64" {
		want = macho.CpuArm64
	}
	if executable.Type != macho.TypeExec || executable.Cpu != want {
		t.Fatal("actual kernel Mach-O target does not match the native host")
	}
	// The production image loader independently checks its allowed system dylibs
	// and protected descriptors before any role spawn. No alternate runtime here.
}

// Runtime consumes a separately enrolled installation. This helper never
// builds, installs, elevates or replaces protected paths.
func bootstrapPrepareNativeRelease(t *testing.T, release *releaseTestFixture) {
	t.Helper()
	raw := bootstrapDarwinPrivatePrerequisite(t, "AMX_DARWIN_ROLE_RELEASE_POLICY", "AMX_DARWIN_REVIEWED_ROLE_RELEASE_POLICY")
	var policy ReleasePolicy
	if protocol.DecodeClosedJSON(raw, &policy, 64*1024) != nil || filepath.Dir(policy.PackageDirectory) != bootstrapDarwinReleaseBase || !fullID.MatchString(filepath.Base(policy.PackageDirectory)) {
		t.Fatal("reviewed installed role policy invalid")
	}
	bootstrapAssertDarwinDirectory(t, policy.PackageDirectory)
	installed, err := LoadInstalledRelease(policy)
	if err != nil || installed.BrokerPins() != release.manifest.Broker {
		t.Fatal("installed signed role release or broker prerequisites refused")
	}
	// Until main extracts source staging from the shared fixture, compare its
	// exact native candidate bytes with each separately installed member.
	for _, role := range protocol.Roles() {
		candidate, err := os.ReadFile(filepath.Join(release.policy.PackageDirectory, "bin", role))
		member, installedErr := os.ReadFile(filepath.Join(policy.PackageDirectory, "bin", role))
		if err != nil || installedErr != nil || releaseDigest(candidate) != releaseDigest(member) {
			t.Fatal("installed role image does not match the staged native candidate")
		}
	}
	release.policy = policy
	release.authorization.AssemblyDigest = installed.Trust().AssemblyDigest
}

func bootstrapDarwinPrivatePrerequisite(t *testing.T, pathKey, digestKey string) []byte {
	t.Helper()
	path := os.Getenv(pathKey)
	if !bootstrapFixtureAbsolute(path) || os.Geteuid() == 0 {
		t.Fatal("separately enrolled private installation prerequisite required")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("private installation prerequisite unavailable")
	}
	file := os.NewFile(uintptr(fd), "darwin-installation-prerequisite")
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0600 ||
		stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || stat.Size < 1 || stat.Size > 64*1024 ||
		privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil {
		closeErr := file.Close()
		t.Fatalf("private installation prerequisite refused; descriptorCloseSucceeded=%t", closeErr == nil)
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, 64*1024+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(raw)) != stat.Size || releaseDigest(raw) != os.Getenv(digestKey) {
		t.Fatalf("private installation prerequisite bytes refused; descriptorCloseSucceeded=%t", closeErr == nil)
	}
	return raw
}

func bootstrapAssertDarwinDirectory(t *testing.T, path string) {
	t.Helper()
	parent := unix.AT_FDCWD
	parts := append([]string{"/"}, strings.Split(strings.TrimPrefix(path, "/"), "/")...)
	var files []*os.File
	defer func() {
		for _, file := range files {
			file.Close()
		}
	}()
	for _, part := range parts {
		fd, err := unix.Openat(parent, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal("protected fixture refused unsafe ancestor")
		}
		file := os.NewFile(uintptr(fd), "fixture-ancestor")
		files = append(files, file)
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil || stat.Uid != 0 || stat.Mode&0022 != 0 || stat.Mode&06000 != 0 ||
			privatefs.CheckDescriptor(file, privatefs.PublicAncestor) != nil {
			t.Fatal("protected fixture refused writable or unprotected ancestor")
		}
		parent = fd
	}
}
