//go:build darwin && arm64 && cgo && agentmux_bootstrap_docker

package deployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/privatefs"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"
)

type installedServiceHostInput struct {
	HostPolicy       string         `json:"hostPolicy"`
	HostPolicySHA256 string         `json:"hostPolicySHA256"`
	KernelScope      protocol.Scope `json:"kernelScope"`
	Workspaces       []string       `json:"workspaces"`
	InstallationID   string         `json:"installationId"`
}

type installedServiceEnrollment struct {
	SchemaVersion string `json:"schemaVersion"`
	Enrollment    string `json:"enrollment"`
	SHA256        string `json:"sha256"`
}

type installedStorageContractMaterial struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type installedStorageServiceEnrollment struct {
	SchemaVersion    string                           `json:"schemaVersion"`
	Enrollment       string                           `json:"enrollment"`
	SHA256           string                           `json:"sha256"`
	ContractMaterial installedStorageContractMaterial `json:"contractMaterial"`
}

type installedServiceWrapperInput struct {
	SchemaVersion string                    `json:"schemaVersion"`
	Host          installedServiceHostInput `json:"host"`
	Environment   map[string]string         `json:"environment"`
	Directory     string                    `json:"directory"`
}

var installedServiceDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var installedServiceInstallation = regexp.MustCompile(`^[a-f0-9]{64}$`)

const installedServicePreparationHold = "installed service preparation held; original owner retained"
const installedServiceParentHold = "installed preparation hold observed; original preparer, readers and broker remain held"
const installedServiceCollectorDiagnostic = "installed-collector-result.private.json"

type installedServiceDiagnostic struct {
	SchemaVersion  string `json:"schemaVersion"`
	Stage          string `json:"stage"`
	WaitOutcome    string `json:"waitOutcome"`
	ExitCode       *int   `json:"exitCode"`
	Stdout         []byte `json:"stdout"`
	Stderr         []byte `json:"stderr"`
	StdoutComplete bool   `json:"stdoutComplete"`
	StderrComplete bool   `json:"stderrComplete"`
}

// Drain every original output pipe even after its private capture fills. A full
// capture is a failed result, never permission to stop reading a held child.
type installedServiceOutput struct {
	mu           sync.Mutex
	data         []byte
	limit        int
	overflow     bool
	onHold       func(string)
	matchIndex   int
	lineMismatch bool
	holdReported bool
}

func (o *installedServiceOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	count := min(len(p), o.limit-len(o.data))
	o.data = append(o.data, p[:count]...)
	o.overflow = o.overflow || count != len(p)
	notify := false
	if o.onHold != nil && !o.holdReported {
		// Match one exact complete line without buffering unknown lines. This
		// remains bounded even when stderr capture is full or contains secrets.
		for _, character := range p {
			if character == '\n' {
				if !o.lineMismatch && o.matchIndex == len(installedServicePreparationHold) {
					o.holdReported, notify = true, true
				}
				o.matchIndex, o.lineMismatch = 0, false
			} else if !o.lineMismatch {
				if o.matchIndex < len(installedServicePreparationHold) && character == installedServicePreparationHold[o.matchIndex] {
					o.matchIndex++
				} else {
					o.lineMismatch = true
				}
			}
			if o.holdReported {
				break
			}
		}
	}
	observer := o.onHold
	o.mu.Unlock()
	if notify {
		observer(installedServiceParentHold)
	}
	return len(p), nil
}

func (o *installedServiceOutput) result() ([]byte, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return bytes.Clone(o.data), !o.overflow
}

// This owner stays reachable through both child waits and any deliberate hold.
// The existing testing cleanup closures retain the broker's original cmd/done.
type installedServiceBorrow struct {
	fixture  *jwtWorkerFixture
	children []*exec.Cmd
	outputs  []*installedServiceOutput
	onHold   func()
}

func (o *installedServiceBorrow) hold(t *testing.T, code string) {
	t.Helper()
	// Install the hold before reporting: even a terminal reporting path must
	// not unwind through t.Cleanup and tear down the borrowed broker.
	defer func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for range ticker.C {
			runtime.KeepAlive(o)
			runtime.KeepAlive(t)
		}
	}()
	t.Errorf("%s; original children, output owners and broker held; cleanup has not run", code)
}

func (o *installedServiceBorrow) run(t *testing.T, command *exec.Cmd, stdoutLimit int) ([]byte, bool, error) {
	out, diagnostic := &installedServiceOutput{limit: stdoutLimit}, &installedServiceOutput{limit: 131072}
	diagnostic.onHold = func(message string) { t.Log(message) }
	if o.onHold != nil {
		diagnostic.onHold = func(message string) {
			t.Log(message)
			o.onHold()
		}
	}
	command.Stdout, command.Stderr = out, diagnostic
	o.children = append(o.children, command)
	o.outputs = append(o.outputs, out, diagnostic)
	// No CommandContext, WaitDelay or cancellation timer: preparation and the
	// installed collector can deliberately retain their original live owners.
	// Run joins the sole child wait and both original output-copy goroutines.
	err := command.Run()
	result, bounded := out.result()
	_, stderrBounded := diagnostic.result()
	return result, bounded && stderrBounded, err
}

func (o *installedServiceBorrow) saveCollectorDiagnostic(directory string, command *exec.Cmd, waitError error) error {
	out, outOK := command.Stdout.(*installedServiceOutput)
	diagnostic, errOK := command.Stderr.(*installedServiceOutput)
	if !outOK || !errOK {
		return errors.New("installed_collector_diagnostic_unavailable")
	}
	stdout, stdoutComplete := out.result()
	stderr, stderrComplete := diagnostic.result()
	defer clear(stdout)
	defer clear(stderr)
	result := installedServiceDiagnostic{SchemaVersion: protocol.Version, Stage: "installed-collector",
		WaitOutcome: "unconfirmed", Stdout: stdout, Stderr: stderr,
		StdoutComplete: stdoutComplete, StderrComplete: stderrComplete}
	if command.ProcessState != nil {
		code := command.ProcessState.ExitCode()
		result.ExitCode = &code
		result.WaitOutcome = "exited"
		if waitError != nil && command.ProcessState.Success() {
			result.WaitOutcome = "output-unconfirmed"
		}
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return errors.New("installed_collector_diagnostic_unavailable")
	}
	defer clear(raw)
	return installedServiceWriteDiagnostic(directory, raw)
}

// Use the same descriptor-relative, no-link traversal and native access checks
// as teamReadPrivate. Keep the original descriptors through write/sync/close.
func installedServiceWriteDiagnostic(directory string, raw []byte) (failure error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || len(raw) > 2*1048576 {
		return errors.New("installed_collector_diagnostic_unavailable")
	}
	parts := strings.Split(strings.TrimPrefix(directory, "/"), "/")
	if len(parts)+1 > 128 {
		return errors.New("installed_collector_diagnostic_unavailable")
	}
	var held []*os.File
	defer func() {
		for i := len(held) - 1; i >= 0; i-- {
			if held[i].Close() != nil {
				failure = errors.New("installed_collector_diagnostic_unavailable")
			}
		}
	}()
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("installed_collector_diagnostic_unavailable")
	}
	root := os.NewFile(uintptr(fd), "installed-diagnostic-ancestor")
	held = append(held, root)
	uid := uint32(os.Geteuid())
	for step := -1; step < len(parts); step++ {
		if step >= 0 {
			if parts[step] == "" {
				return errors.New("installed_collector_diagnostic_unavailable")
			}
			fd, err = unix.Openat(fd, parts[step], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if err != nil {
				return errors.New("installed_collector_diagnostic_unavailable")
			}
			root = os.NewFile(uintptr(fd), "installed-diagnostic-ancestor")
			held = append(held, root)
		}
		var metadata unix.Stat_t
		if unix.Fstat(fd, &metadata) != nil || !teamTrustedAncestor(&metadata, uid) ||
			teamDescriptorAdmission(root, privatefs.PublicAncestor, "private_directory_invalid") != nil {
			return errors.New("installed_collector_diagnostic_unavailable")
		}
	}
	var selected unix.Stat_t
	if unix.Fstat(fd, &selected) != nil || !teamPrivateStat(&selected, uid, true) ||
		teamDescriptorAdmission(root, privatefs.PrivateObject, "private_directory_invalid") != nil {
		return errors.New("installed_collector_diagnostic_unavailable")
	}
	memberFD, err := unix.Openat(fd, installedServiceCollectorDiagnostic,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errors.New("installed_collector_diagnostic_unavailable")
	}
	file := os.NewFile(uintptr(memberFD), "installed-collector-private-diagnostic")
	held = append(held, file)
	var opened unix.Stat_t
	if unix.Fstat(memberFD, &opened) != nil || !teamPrivateStat(&opened, uid, false) ||
		teamDescriptorAdmission(file, privatefs.PrivateObject, "private_file_invalid") != nil {
		return errors.New("installed_collector_diagnostic_unavailable")
	}
	if written, err := file.Write(raw); err != nil || written != len(raw) || file.Sync() != nil || unix.Fsync(fd) != nil {
		return errors.New("installed_collector_diagnostic_unavailable")
	}
	var final, path, parent unix.Stat_t
	resolved, resolveErr := filepath.EvalSymlinks(directory)
	if resolveErr != nil || resolved != directory || unix.Lstat(directory, &parent) != nil ||
		parent.Dev != selected.Dev || parent.Ino != selected.Ino || !teamPrivateStat(&parent, uid, true) ||
		unix.Fstat(memberFD, &final) != nil || unix.Fstatat(fd, installedServiceCollectorDiagnostic, &path, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		!teamPrivateStat(&final, uid, false) || !teamCredentialStatUnchanged(&final, &path) ||
		final.Dev != opened.Dev || final.Ino != opened.Ino || final.Size != int64(len(raw)) ||
		teamDescriptorAdmission(file, privatefs.PrivateObject, "private_file_invalid") != nil {
		return errors.New("installed_collector_diagnostic_unavailable")
	}
	for _, ancestor := range held[:len(held)-1] {
		var metadata unix.Stat_t
		if unix.Fstat(int(ancestor.Fd()), &metadata) != nil || !teamTrustedAncestor(&metadata, uid) ||
			teamDescriptorAdmission(ancestor, privatefs.PublicAncestor, "private_directory_invalid") != nil {
			return errors.New("installed_collector_diagnostic_unavailable")
		}
	}
	if teamDescriptorAdmission(root, privatefs.PrivateObject, "private_directory_invalid") != nil {
		return errors.New("installed_collector_diagnostic_unavailable")
	}
	return nil
}

func installedServiceDecodeResult(raw []byte, directory string) (installedServiceEnrollment, error) {
	var value installedServiceEnrollment
	if protocol.DecodeClosedJSON(raw, &value, 16384) != nil || value.SchemaVersion != protocol.Version ||
		!installedServiceDigest.MatchString(value.SHA256) || !filepath.IsAbs(value.Enrollment) ||
		filepath.Clean(value.Enrollment) != value.Enrollment || filepath.Dir(value.Enrollment) != directory {
		return installedServiceEnrollment{}, errors.New("installed_preparation_output_invalid")
	}
	return value, nil
}

func installedServiceCollectorCommand(goTool, root string, enrollment installedServiceEnrollment, environment []string) *exec.Cmd {
	return installedServiceFixedCollectorCommand(goTool, root, enrollment, environment,
		"-run=^TestStableInstalledClientDarwinColdMCPStartup$")
}

func installedServiceDecodeStorageResult(raw []byte, directory string) (installedStorageServiceEnrollment, error) {
	var value installedStorageServiceEnrollment
	if protocol.DecodeClosedJSON(raw, &value, 16384) != nil || value.SchemaVersion != protocol.Version || !installedServiceDigest.MatchString(value.SHA256) || !installedServiceDigest.MatchString(value.ContractMaterial.SHA256) {
		return installedStorageServiceEnrollment{}, errors.New("installed_storage_preparation_output_invalid")
	}
	for _, path := range []string{value.Enrollment, value.ContractMaterial.Path} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) != directory {
			return installedStorageServiceEnrollment{}, errors.New("installed_storage_preparation_output_invalid")
		}
	}
	if filepath.Base(value.ContractMaterial.Path) != "storage-contract.json" || value.Enrollment == value.ContractMaterial.Path {
		return installedStorageServiceEnrollment{}, errors.New("installed_storage_preparation_output_invalid")
	}
	return value, nil
}

func installedServiceStorageCollectorCommand(goTool, root string, enrollment installedStorageServiceEnrollment, environment []string) *exec.Cmd {
	overrides := map[string]string{"AMX_INSTALLED_STORAGE_CONTRACT_MATERIAL": enrollment.ContractMaterial.Path, "AMX_INSTALLED_STORAGE_CONTRACT_MATERIAL_SHA256": enrollment.ContractMaterial.SHA256}
	selected := make([]string, 0, len(environment)+len(overrides))
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		if _, replaced := overrides[key]; !replaced {
			selected = append(selected, entry)
		}
	}
	for key, value := range overrides {
		selected = append(selected, key+"="+value)
	}
	return installedServiceFixedCollectorCommand(goTool, root, installedServiceEnrollment{SchemaVersion: enrollment.SchemaVersion, Enrollment: enrollment.Enrollment, SHA256: enrollment.SHA256}, selected,
		"-run=^TestStableInstalledClientDarwinStorageProviders$")
}

func installedServiceFixedCollectorCommand(goTool, root string, enrollment installedServiceEnrollment, environment []string, selector string) *exec.Cmd {
	command := exec.Command(goTool, "test", "./launcher", "-tags=agentmux_bootstrap_docker",
		selector, "-count=1", "-timeout=0", "-v")
	command.Dir = filepath.Join(root, "platform")
	overrides := map[string]string{
		"AMX_INSTALLED_CLIENT_SERVICE_ENROLLMENT":                   enrollment.Enrollment,
		"AMX_INSTALLED_CLIENT_SERVICE_ENROLLMENT_SHA256":            enrollment.SHA256,
		"AMX_INSTALLED_CLIENT_APPLICATION_BROKER_BORROW_AUTHORIZED": "1",
		"AMX_INSTALLED_CLIENT_COLD_FAILURE_HOLD":                    "1",
	}
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		if _, replaced := overrides[key]; !replaced {
			command.Env = append(command.Env, entry)
		}
	}
	for key, value := range overrides {
		command.Env = append(command.Env, key+"="+value)
	}
	return command
}

// Run only after independent source/candidate review and exclusive live-slot
// assignment. The host input is a separately selected private JSON document,
// not inferred from a workspace, running process or historical fixture receipt.
func TestInstalledApplicationServicesBorrowedJWTBroker(t *testing.T) {
	runInstalledApplicationServicesBorrowedJWTBroker(t, false, false)
}

func TestInstalledStorageProvidersBorrowedJWTBroker(t *testing.T) {
	runInstalledApplicationServicesBorrowedJWTBroker(t, true, false)
}

func runInstalledApplicationServicesBorrowedJWTBroker(t *testing.T, storage, recovery bool) {
	t.Helper()
	if storage && recovery {
		t.Fatal("installed service scenario is ambiguous")
	}
	if _, finite := t.Deadline(); finite {
		t.Fatal("borrowed installed collector requires -timeout=0 for its failure hold")
	}
	if os.Getenv("AMX_BOOTSTRAP_DOCKER_AUTHORIZED") != "1" {
		t.Fatal("explicit installed cold fixture authorization required")
	}
	python, goTool := os.Getenv("AGENTMUX_NATS_CREDENTIAL_PYTHON"), os.Getenv("AGENTMUX_INSTALLED_SERVICE_GO")
	if storage && (!filepath.IsAbs(os.Getenv("AMX_INSTALLED_STORAGE_TEST_BINARY")) ||
		!installedServiceDigest.MatchString(os.Getenv("AMX_INSTALLED_STORAGE_TEST_BINARY_SHA256"))) {
		t.Fatal("explicit prepared storage test executable and digest required")
	}
	inputPath, inputDigest := os.Getenv("AMX_INSTALLED_SERVICE_HOST_INPUT"), os.Getenv("AMX_INSTALLED_SERVICE_HOST_INPUT_SHA256")
	if !filepath.IsAbs(python) || !filepath.IsAbs(goTool) || !filepath.IsAbs(inputPath) ||
		filepath.Clean(inputPath) != inputPath || !installedServiceDigest.MatchString(inputDigest) {
		t.Fatal("explicit prepared tools and private installed-service host input required")
	}
	raw, err := teamReadPrivate(filepath.Dir(inputPath), filepath.Base(inputPath), uint32(os.Geteuid()))
	if err != nil {
		t.Fatal("private installed-service host input refused")
	}
	defer clear(raw)
	sum := sha256.Sum256(raw)
	var input installedServiceWrapperInput
	if inputDigest != "sha256:"+hex.EncodeToString(sum[:]) || protocol.DecodeClosedJSON(raw, &input, 16384) != nil || input.SchemaVersion != protocol.Version {
		t.Fatal("closed pinned installed-service wrapper input required")
	}
	var nativePackage json.RawMessage
	if storage {
		packagePath, packageDigest := os.Getenv("AMX_INSTALLED_STORAGE_PACKAGE_MATERIAL"), os.Getenv("AMX_INSTALLED_STORAGE_PACKAGE_MATERIAL_SHA256")
		if !filepath.IsAbs(packagePath) || filepath.Clean(packagePath) != packagePath || filepath.Dir(packagePath) != filepath.Dir(inputPath) || !installedServiceDigest.MatchString(packageDigest) {
			t.Fatal("explicit private storage package preparation required")
		}
		material, err := teamReadPrivate(filepath.Dir(packagePath), filepath.Base(packagePath), uint32(os.Geteuid()))
		if err != nil || len(material) > 16384 || !json.Valid(material) {
			t.Fatal("private storage package preparation refused")
		}
		sum := sha256.Sum256(material)
		if packageDigest != "sha256:"+hex.EncodeToString(sum[:]) {
			t.Fatal("storage package preparation changed")
		}
		nativePackage = material
	}
	host := input.Host
	if len(input.Environment) != 7 ||
		!installedServiceDigest.MatchString(host.HostPolicySHA256) || !installedServiceInstallation.MatchString(host.InstallationID) ||
		!filepath.IsAbs(host.HostPolicy) || filepath.Clean(host.HostPolicy) != host.HostPolicy || len(host.Workspaces) != 1 ||
		!filepath.IsAbs(host.Workspaces[0]) || host.HostPolicy != input.Environment["AMX_INSTALLED_CLIENT_HOST_POLICY"] ||
		host.HostPolicySHA256 != input.Environment["AMX_INSTALLED_CLIENT_HOST_POLICY_SHA256"] || host.InstallationID != input.Environment["AMX_INSTALLED_CLIENT_ID"] {
		t.Fatal("installed-service input differs from independently selected cold collector pins")
	}
	keys := []string{"AMX_BOOTSTRAP_SELECTION_FILE", "AMX_BOOTSTRAP_SELECTION_SHA256", "AMX_INSTALLED_CLIENT_HOST_POLICY",
		"AMX_INSTALLED_CLIENT_HOST_POLICY_SHA256", "AMX_INSTALLED_CLIENT_ID", "AMX_INSTALLED_CLIENT_VOLUME_CREATED_AT", "AMX_STABLE_FRONTEND_SHA256"}
	for _, key := range keys {
		if input.Environment[key] == "" || strings.ContainsAny(input.Environment[key], "\x00\r\n") {
			t.Fatal("closed installed collector environment refused")
		}
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal("repository root unavailable")
	}
	directory := input.Directory
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		t.Fatal("absolute canonical service preparation directory required")
	}
	resolved, err := filepath.EvalSymlinks(directory)
	metadata, statErr := os.Lstat(directory)
	entries, readErr := os.ReadDir(directory)
	if err != nil || resolved != directory || statErr != nil || !metadata.IsDir() || metadata.Mode().Perm()&0077 != 0 ||
		readErr != nil || len(entries) != 0 {
		t.Fatal("canonical private service preparation directory unavailable")
	}
	var fixture *jwtWorkerFixture
	if storage || recovery {
		fixture = newJWTWorkerStorageFixture(t)
	} else {
		fixture = newJWTWorkerFixtureTLSMode(t, true)
	}
	owner := &installedServiceBorrow{fixture: fixture}
	f := owner.fixture
	peer, err := f.publisher.TLSConnectionState()
	if err != nil || len(peer.PeerCertificates) == 0 {
		t.Fatal("verified fixture TLS peer unavailable")
	}
	leaf := sha256.Sum256(peer.PeerCertificates[0].Raw)
	seed, err := f.account.Seed()
	if err != nil {
		t.Fatal("fixture account seed unavailable")
	}
	defer clear(seed)
	planFields := map[string]any{"schemaVersion": protocol.Version, "host": host, "directory": directory,
		"broker": map[string]string{"endpoint": f.policy.Endpoint, "rootsPEM": string(f.policy.TLSRootsPEM),
			"serverName": f.policy.TLSServerName, "domain": f.policy.ExpectedDomain,
			"leafPin": "sha256:" + hex.EncodeToString(leaf[:]), "accountSeed": string(seed)}}
	if storage {
		planFields["scenario"] = "storage-contract"
		planFields["nativePackage"] = nativePackage
	} else if recovery {
		host, directory, input.Environment = installedAuthoritySwitchRecoveryInputs(t, host, directory, input.Environment)
		planFields["host"] = host
		planFields["directory"] = directory
		planFields["scenario"] = "authority-switch-recovery"
	}
	plan, err := json.Marshal(planFields)
	if err != nil {
		t.Fatal("private installed preparation plan encoding failed")
	}
	defer clear(plan)
	preparation := exec.Command(python, "-B", "platform/launcher/testdata/installed_service_enrollment.py")
	preparation.Dir = root
	preparation.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + directory,
		"PYTHONPATH=" + filepath.Join(root, "sdk/python") + string(os.PathListSeparator) + root,
		"PYTHONDONTWRITEBYTECODE=1"}
	preparation.Stdin = bytes.NewReader(plan)
	output, bounded, err := owner.run(t, preparation, 16384)
	clear(plan)
	clear(seed)
	if err != nil || !bounded {
		owner.hold(t, "installed_preparation_unconfirmed")
		return
	}
	var enrollment installedServiceEnrollment
	var storageEnrollment installedStorageServiceEnrollment
	var recoveryEnrollment installedAuthoritySwitchRecoveryEnrollment
	if storage {
		storageEnrollment, err = installedServiceDecodeStorageResult(output, directory)
		enrollment = installedServiceEnrollment{SchemaVersion: storageEnrollment.SchemaVersion,
			Enrollment: storageEnrollment.Enrollment, SHA256: storageEnrollment.SHA256}
	} else if recovery {
		recoveryEnrollment, err = installedAuthoritySwitchDecodeRecoveryResult(output, directory)
		enrollment = installedServiceEnrollment{SchemaVersion: recoveryEnrollment.SchemaVersion,
			Enrollment: recoveryEnrollment.Enrollment, SHA256: recoveryEnrollment.SHA256}
	} else {
		enrollment, err = installedServiceDecodeResult(output, directory)
	}
	if err != nil {
		owner.hold(t, "installed_preparation_output_refused")
		return
	}
	selected, err := teamReadPrivate(directory, filepath.Base(enrollment.Enrollment), uint32(os.Geteuid()))
	if err != nil {
		owner.hold(t, "installed_preparation_enrollment_unavailable")
		return
	}
	enrolledSum := sha256.Sum256(selected)
	clear(selected)
	if enrollment.SHA256 != "sha256:"+hex.EncodeToString(enrolledSum[:]) {
		owner.hold(t, "installed_preparation_enrollment_changed")
		return
	}
	// Pass only the prepared tool environment and the seven pinned collector
	// inputs. Authorization flags come separately from this explicit invocation.
	environment := []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "AMX_BOOTSTRAP_DOCKER_AUTHORIZED=1",
		"GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off"}
	for _, key := range []string{"HOME", "GOMODCACHE", "GOCACHE", "SDKROOT", "CGO_ENABLED", "TMPDIR"} {
		if value := os.Getenv(key); value != "" {
			environment = append(environment, key+"="+value)
		}
	}
	if storage {
		for _, key := range []string{"AGENTMUX_NATS_CREDENTIAL_PYTHON", "AMX_INSTALLED_STORAGE_TEST_BINARY", "AMX_INSTALLED_STORAGE_TEST_BINARY_SHA256"} {
			value := os.Getenv(key)
			if value == "" || strings.ContainsAny(value, "\x00\r\n") {
				owner.hold(t, "installed_storage_prepared_tool_missing")
				return
			}
			environment = append(environment, key+"="+value)
		}
	}
	if recovery {
		environment = installedAuthoritySwitchRecoveryEnvironment(environment, recoveryEnrollment)
	}
	sort.Strings(keys)
	for _, key := range keys {
		environment = append(environment, key+"="+input.Environment[key])
	}
	collector := installedServiceCollectorCommand(goTool, root, enrollment, environment)
	passMarker := "--- PASS: TestStableInstalledClientDarwinColdMCPStartup ("
	if storage {
		collector = installedServiceStorageCollectorCommand(goTool, root, storageEnrollment, environment)
		passMarker = "--- PASS: TestStableInstalledClientDarwinStorageProviders ("
	} else if recovery {
		collector = installedAuthoritySwitchRecoveryCollectorCommand(goTool, root, recoveryEnrollment, environment)
		passMarker = "--- PASS: TestStableInstalledClientDarwinAuthoritySwitchRecovery ("
	}
	result, bounded, err := owner.run(t, collector, 1048576)
	if owner.saveCollectorDiagnostic(directory, collector, err) != nil {
		owner.hold(t, "installed_collector_diagnostic_unavailable")
		return
	}
	if err != nil || !bounded || !bytes.Contains(result, []byte(passMarker)) {
		owner.hold(t, "installed_collector_unconfirmed")
		return
	}
	t.Log("installed collector and original child waits/readers joined; borrowed broker cleanup may now run")
}

func TestInstalledServiceWrapperBoundsAndClosedResult(t *testing.T) {
	out := &installedServiceOutput{limit: 8}
	if count, err := out.Write([]byte("1234567890")); count != 10 || err != nil {
		t.Fatal("bounded capture did not keep draining original output")
	}
	raw, bounded := out.result()
	if string(raw) != "12345678" || bounded {
		t.Fatal("output overflow was not bounded and refused")
	}
	good := []byte(`{"schemaVersion":"1.0.0","enrollment":"/private/fixture/client.json","sha256":"sha256:` + strings.Repeat("a", 64) + `"}`)
	if _, err := installedServiceDecodeResult(good, "/private/fixture"); err != nil {
		t.Fatal("closed preparer result refused")
	}
	for _, changed := range [][]byte{bytes.Replace(good, []byte("/private/fixture/client.json"), []byte("/private/other/client.json"), 1),
		bytes.Replace(good, []byte(`"schemaVersion"`), []byte(`"extra":true,"schemaVersion"`), 1), append(bytes.Clone(good), []byte(` {}`)...)} {
		if _, err := installedServiceDecodeResult(changed, "/private/fixture"); err == nil {
			t.Fatal("unbound or open preparer result accepted")
		}
	}
}

func TestInstalledStorageAccountAllowancePreservesBaseline(t *testing.T) {
	baselineBytes, baselineStreams := jwtWorkerStreamLimits(false)
	storageBytes, storageStreams := jwtWorkerStreamLimits(true)
	if baselineBytes != 4*1024*1024 || baselineStreams != 4 {
		t.Fatal("baseline fixture account allowance changed")
	}
	if storageBytes != 3*2*1048576+4*524288+2*1048576 || storageStreams != 9 {
		t.Fatal("storage account does not match the selected resource reservations")
	}
}

func TestInstalledStorageAccountReservesSelectedStreams(t *testing.T) {
	f := newJWTWorkerStorageFixture(t)
	key := jwtWorkerKey(t, nkeys.CreateUser)
	token := jwtWorkerUser(t, f.account, key, []string{"$JS.>"}, []string{"_INBOX.>"})
	client, err := jwtWorkerConnect(f, token, key, nil)
	if err != nil {
		t.Fatal("fixture reservation connection failed")
	}
	t.Cleanup(client.Close)
	js, err := client.JetStream(nats.Domain(f.policy.ExpectedDomain), nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal("fixture reservation service unavailable")
	}
	// Actual server reservations must fit the private/card/allocation owners,
	// the other four owners, and the artifact and board buckets together.
	for i, size := range []int64{2 * 1024 * 1024, 2 * 1024 * 1024, 2 * 1024 * 1024, 524288, 524288, 524288, 524288, 1048576, 1048576} {
		name := fmt.Sprintf("RESERVATION_%d", i)
		info, err := js.AddStream(&nats.StreamConfig{Name: name, Subjects: []string{"fixture.reservation." + name}, Storage: nats.FileStorage, Replicas: 1, MaxBytes: size})
		if err != nil || info.Config.MaxBytes != size {
			t.Fatalf("selected storage reservation %d refused", i)
		}
	}
}

func TestInstalledServiceWrapperCollectorHasNoKillingDeadline(t *testing.T) {
	enrollment := installedServiceEnrollment{Enrollment: "/private/fixture/client.json", SHA256: "sha256:" + strings.Repeat("a", 64)}
	command := installedServiceCollectorCommand("/prepared/go", "/approved/repository", enrollment,
		[]string{"SDKROOT=/approved/sdk", "AMX_INSTALLED_CLIENT_COLD_FAILURE_HOLD=0"})
	if command.Cancel != nil || command.WaitDelay != 0 || command.Dir != "/approved/repository/platform" ||
		!strings.Contains(strings.Join(command.Args, " "), "-timeout=0") {
		t.Fatal("collector gained a cancellation deadline or changed its fixed target")
	}
	count := 0
	for _, entry := range command.Env {
		if strings.HasPrefix(entry, "AMX_INSTALLED_CLIENT_COLD_FAILURE_HOLD=") {
			count++
			if entry != "AMX_INSTALLED_CLIENT_COLD_FAILURE_HOLD=1" {
				t.Fatal("collector failure hold overridden")
			}
		}
	}
	if count != 1 {
		t.Fatal("collector failure hold is ambiguous")
	}
}

func TestInstalledStorageCollectorKeepsFixedTargetAndOriginalFailureHold(t *testing.T) {
	enrollment := installedServiceEnrollment{Enrollment: "/private/fixture/client.json", SHA256: "sha256:" + strings.Repeat("a", 64)}
	environment := []string{"SDKROOT=/approved/sdk", "AMX_INSTALLED_CLIENT_COLD_FAILURE_HOLD=0"}
	cold := installedServiceCollectorCommand("/prepared/go", "/approved/repository", enrollment, environment)
	storageEnrollment := installedStorageServiceEnrollment{SchemaVersion: protocol.Version, Enrollment: enrollment.Enrollment, SHA256: enrollment.SHA256, ContractMaterial: installedStorageContractMaterial{Path: "/private/fixture/storage-contract.json", SHA256: "sha256:" + strings.Repeat("b", 64)}}
	storage := installedServiceStorageCollectorCommand("/prepared/go", "/approved/repository", storageEnrollment, append(environment, "AMX_INSTALLED_STORAGE_CONTRACT_MATERIAL=/other"))
	for _, command := range []*exec.Cmd{cold, storage} {
		if command.Cancel != nil || command.WaitDelay != 0 || command.Dir != "/approved/repository/platform" {
			t.Fatal("fixed collector lost original process ownership")
		}
		var hold int
		for _, entry := range command.Env {
			if strings.HasPrefix(entry, "AMX_INSTALLED_CLIENT_COLD_FAILURE_HOLD=") {
				hold++
				if entry != "AMX_INSTALLED_CLIENT_COLD_FAILURE_HOLD=1" {
					t.Fatal("fixed collector failure hold overridden")
				}
			}
		}
		if hold != 1 {
			t.Fatal("fixed collector failure hold is ambiguous")
		}
	}
	coldSelector, storageSelector := "", ""
	for _, argument := range cold.Args {
		if strings.HasPrefix(argument, "-run=") {
			coldSelector = argument
		}
	}
	for _, argument := range storage.Args {
		if strings.HasPrefix(argument, "-run=") {
			storageSelector = argument
		}
	}
	if coldSelector != "-run=^TestStableInstalledClientDarwinColdMCPStartup$" || storageSelector != "-run=^TestStableInstalledClientDarwinStorageProviders$" {
		t.Fatal("storage scenario changed the baseline or selected an arbitrary test")
	}
	var material int
	for _, entry := range storage.Env {
		if strings.HasPrefix(entry, "AMX_INSTALLED_STORAGE_CONTRACT_MATERIAL=") {
			material++
			if entry != "AMX_INSTALLED_STORAGE_CONTRACT_MATERIAL=/private/fixture/storage-contract.json" {
				t.Fatal("selected contract material pin overridden")
			}
		}
	}
	if material != 1 {
		t.Fatal("selected contract material pin is ambiguous")
	}
}

func TestInstalledStoragePreparationResultKeepsClosedIndependentPins(t *testing.T) {
	good := []byte(`{"schemaVersion":"1.0.0","enrollment":"/private/fixture/client.json","sha256":"sha256:` + strings.Repeat("a", 64) + `","contractMaterial":{"path":"/private/fixture/storage-contract.json","sha256":"sha256:` + strings.Repeat("b", 64) + `"}}`)
	if _, err := installedServiceDecodeStorageResult(good, "/private/fixture"); err != nil {
		t.Fatal("closed storage preparation result refused")
	}
	if _, err := installedServiceDecodeResult(good, "/private/fixture"); err == nil {
		t.Fatal("storage setup silently replaced baseline preparation")
	}
	for _, changed := range [][]byte{bytes.Replace(good, []byte("/private/fixture/storage-contract.json"), []byte("/private/other/storage-contract.json"), 1), bytes.Replace(good, []byte(`"contractMaterial":{`), []byte(`"contractMaterial":{"extra":true,`), 1), bytes.Replace(good, []byte(`"schemaVersion"`), []byte(`"extra":true,"schemaVersion"`), 1), bytes.Replace(good, []byte("storage-contract.json"), []byte("unselected.json"), 1)} {
		if _, err := installedServiceDecodeStorageResult(changed, "/private/fixture"); err == nil {
			t.Fatal("open or substituted contract material result accepted")
		}
	}
}

func TestInstalledServiceWrapperHoldObserverSplitChunks(t *testing.T) {
	marker := installedServicePreparationHold + "\n"
	for split := 0; split <= len(marker); split++ {
		var messages []string
		out := &installedServiceOutput{limit: 4, onHold: func(message string) { messages = append(messages, message) }}
		out.Write([]byte(marker[:split]))
		if split < len(marker) && len(messages) != 0 {
			t.Fatal("partial hold line was reported")
		}
		out.Write([]byte(marker[split:]))
		out.Write([]byte(marker))
		if len(messages) != 1 || messages[0] != installedServiceParentHold {
			t.Fatal("split hold marker was not reported exactly once with the fixed message")
		}
		captured, bounded := out.result()
		if len(captured) != 4 || bounded {
			t.Fatal("hold observation changed capture limits or stopped draining")
		}
	}
}

func TestInstalledServiceWrapperHoldObserverIgnoresUnknownLines(t *testing.T) {
	var messages []string
	out := &installedServiceOutput{limit: 8, onHold: func(message string) { messages = append(messages, message) }}
	for _, line := range []string{"untrusted diagnostic\n", "prefix " + installedServicePreparationHold + "\n",
		installedServicePreparationHold + " suffix\n", strings.Repeat("x", 262144) + "\n",
		installedServicePreparationHold + "\r\n"} {
		if count, err := out.Write([]byte(line)); count != len(line) || err != nil {
			t.Fatal("unknown stderr was not fully drained")
		}
	}
	if len(messages) != 0 || out.matchIndex != 0 || out.lineMismatch {
		t.Fatal("unknown lines established a hold or retained unbounded line state")
	}
}

func TestInstalledServiceWrapperHoldObserverNeverForwardsSecretText(t *testing.T) {
	const secret = "SYNTHETIC-PRIVATE-CREDENTIAL"
	var messages []string
	out := &installedServiceOutput{limit: 8, onHold: func(message string) { messages = append(messages, message) }}
	out.Write([]byte(secret + installedServicePreparationHold + "\n"))
	out.Write([]byte(installedServicePreparationHold + secret + "\n"))
	out.Write([]byte(secret + "\n" + installedServicePreparationHold + "\n" + secret + "\n"))
	if len(messages) != 1 || messages[0] != installedServiceParentHold || strings.Contains(messages[0], secret) {
		t.Fatal("observer forwarded stderr content or failed to report the exact marker")
	}
}

func TestInstalledServiceWrapperPrivateCollectorDiagnostic(t *testing.T) {
	directory := t.TempDir()
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("private test directory unavailable")
	}
	directory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal("canonical private test directory unavailable")
	}
	out, diagnostic := &installedServiceOutput{limit: 8}, &installedServiceOutput{limit: 64}
	out.Write([]byte("truncated-stdout"))
	diagnostic.Write([]byte("SYNTHETIC-PRIVATE-DIAGNOSTIC"))
	command := &exec.Cmd{Stdout: out, Stderr: diagnostic}
	owner := &installedServiceBorrow{}
	if err := owner.saveCollectorDiagnostic(directory, command, errors.New("private failure")); err != nil {
		t.Fatal("private collector diagnostic was not preserved")
	}
	path := filepath.Join(directory, installedServiceCollectorDiagnostic)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("diagnostic is not a private regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("diagnostic unavailable")
	}
	var value installedServiceDiagnostic
	if protocol.DecodeClosedJSON(raw, &value, 4096) != nil || value.Stage != "installed-collector" ||
		value.WaitOutcome != "unconfirmed" || value.ExitCode != nil || value.StdoutComplete || !value.StderrComplete ||
		string(value.Stdout) != "truncate" || string(value.Stderr) != "SYNTHETIC-PRIVATE-DIAGNOSTIC" {
		t.Fatal("diagnostic lost bounded original output or invented a confirmed exit")
	}
	if err := owner.saveCollectorDiagnostic(directory, command, nil); err == nil {
		t.Fatal("existing diagnostic was overwritten")
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, unchanged) {
		t.Fatal("create-once diagnostic changed")
	}
}

func TestInstalledServiceWrapperDiagnosticRefusesLinksAndSharedDirectory(t *testing.T) {
	directory := t.TempDir()
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("private test directory unavailable")
	}
	directory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal("canonical private test directory unavailable")
	}
	target := filepath.Join(directory, "sentinel")
	if os.WriteFile(target, []byte("preserve"), 0600) != nil {
		t.Fatal("test sentinel unavailable")
	}
	leaf := filepath.Join(directory, installedServiceCollectorDiagnostic)
	if os.Symlink(target, leaf) != nil {
		t.Fatal("test link unavailable")
	}
	if installedServiceWriteDiagnostic(directory, []byte("untrusted")) == nil {
		t.Fatal("diagnostic followed a leaf link")
	}
	raw, err := os.ReadFile(target)
	if err != nil || string(raw) != "preserve" {
		t.Fatal("linked target changed")
	}
	if os.Remove(leaf) != nil {
		t.Fatal("owned test link cleanup failed")
	}
	alias := filepath.Join(directory, "alias")
	if os.Symlink(directory, alias) != nil {
		t.Fatal("test parent link unavailable")
	}
	if installedServiceWriteDiagnostic(alias, []byte("untrusted")) == nil {
		t.Fatal("diagnostic followed a parent link")
	}
	if os.Chmod(directory, 0755) != nil {
		t.Fatal("test mode unavailable")
	}
	defer os.Chmod(directory, 0700)
	if installedServiceWriteDiagnostic(directory, []byte("untrusted")) == nil {
		t.Fatal("diagnostic accepted a shared directory")
	}
	if _, err := os.Lstat(leaf); !os.IsNotExist(err) {
		t.Fatal("refused diagnostic created a file")
	}
}
