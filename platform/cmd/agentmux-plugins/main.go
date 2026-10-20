// agentmux-plugins is an explicitly configured foreground owner for ordinary plugins.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/controlLogix/agentmux/platform/launcher"
	"github.com/controlLogix/agentmux/platform/plugins"
	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"
)

const compositionLimit = 1 << 20
const inputTotalLimit = 512 << 20

type commandFailure struct {
	code  string
	cause error
}

func (e *commandFailure) Error() string              { return e.code }
func (e *commandFailure) Unwrap() error              { return e.cause }
func (e *commandFailure) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, e.code) }
func (e *commandFailure) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"code": e.code})
}
func fail(code string, cause error) error { return &commandFailure{code, cause} }
func errorCode(err error) string {
	var admission *plugins.AdmissionCleanupFailure
	if errors.As(err, &admission) {
		return "package_admission_cleanup_incomplete"
	}
	var local *commandFailure
	if errors.As(err, &local) {
		return local.code
	}
	var known *plugins.Error
	if errors.As(err, &known) {
		return known.Code()
	}
	return "plugin_command_failed"
}

type limits struct {
	MaxFileBytes  int64 `json:"maxFileBytes"`
	MaxTotalBytes int64 `json:"maxTotalBytes"`
	MaxFiles      int   `json:"maxFiles"`
}
type catalogEntry struct {
	Directory      string `json:"directory"`
	ManifestPath   string `json:"manifestPath"`
	SourceID       string `json:"sourceId"`
	SourcePath     string `json:"sourcePath"`
	Scope          string `json:"scope"`
	SourceFile     string `json:"sourceFile"`
	SourceChecksum string `json:"sourceChecksum"`
	Limits         limits `json:"limits"`
}
type configurationFile struct {
	Pin               plugins.PackagePin       `json:"pin"`
	Resources         []plugins.SchemaResource `json:"resources"`
	ConfigurationFile string                   `json:"configurationFile"`
}
type instanceConfigurationFile struct {
	InstanceID        string                   `json:"instanceId"`
	Pin               plugins.PackagePin       `json:"pin"`
	Resources         []plugins.SchemaResource `json:"resources"`
	ConfigurationFile string                   `json:"configurationFile"`
}
type composition struct {
	NativeContext          *launcher.NativeContextHostRequest `json:"nativeContext,omitempty"`
	SchemaVersion          string                             `json:"schemaVersion"`
	Catalog                []catalogEntry                     `json:"catalog"`
	Roots                  []plugins.PackagePin               `json:"roots"`
	Selected               []plugins.PackagePin               `json:"selected"`
	InstallationMode       string                             `json:"installationMode"`
	Platform               plugins.Platform                   `json:"platform"`
	Configurations         []configurationFile                `json:"configurations"`
	Contracts              []plugins.ContractBinding          `json:"contracts"`
	Instances              map[string]string                  `json:"instances"`
	Driver                 plugins.NativeDriverOptions        `json:"driver"`
	ActivationTimeoutMS    int64                              `json:"activationTimeoutMs"`
	CleanupTimeoutMS       int64                              `json:"cleanupTimeoutMs"`
	Topology               *plugins.InstanceTopologyInput     `json:"topology,omitempty"`
	InstanceConfigurations []instanceConfigurationFile        `json:"instanceConfigurations,omitempty"`
}

func (composition) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private ordinary plugin composition]")
}
func (composition) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-plugin-composition"}`), nil
}

type preparedComposition struct {
	nativeContext       *launcher.NativeContextHostRequest
	request             plugins.ActivationRequest
	options             plugins.ManagerOptions
	driver              plugins.NativeDriverOptions
	plan                plugins.Plan
	contributionCount   int
	graph               bool
	instanceUnavailable int
}

func (preparedComposition) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[prepared ordinary plugin composition]")
}
func (preparedComposition) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"prepared-plugin-composition"}`), nil
}

type commandResult struct {
	SchemaVersion            string                   `json:"schemaVersion"`
	Status                   string                   `json:"status"`
	Code                     string                   `json:"code,omitempty"`
	PackageCount             int                      `json:"packageCount"`
	ContributionCount        int                      `json:"contributionCount"`
	OptionalUnavailableCount int                      `json:"optionalUnavailableCount"`
	Pins                     []plugins.PackagePin     `json:"pins,omitempty"`
	Snapshot                 *plugins.ManagerSnapshot `json:"snapshot,omitempty"`
}

func resultFor(prepared preparedComposition, status string) commandResult {
	result := commandResult{SchemaVersion: "1.0.0", Status: status, PackageCount: len(prepared.plan.Packages()), ContributionCount: prepared.contributionCount, OptionalUnavailableCount: len(prepared.plan.OptionalUnavailable()), Pins: prepared.plan.Order()}
	if prepared.graph {
		result.SchemaVersion = "1.1.0"
		result.OptionalUnavailableCount = prepared.instanceUnavailable
	}
	if prepared.nativeContext != nil {
		result.SchemaVersion = "1.2.0"
	}
	return result
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	if err := execute(ctx, os.Args[1:], os.Stdout); err != nil {
		_ = writeResult(context.Background(), os.Stderr, commandResult{SchemaVersion: "1.0.0", Status: "failed", Code: errorCode(err)})
		os.Exit(1)
	}
}

func execute(ctx context.Context, args []string, output io.Writer) error {
	control := len(args) == 4 && args[0] == "run" && args[3] == "--control-stdin"
	if ctx == nil || output == nil || (len(args) != 3 && !control) || args[1] != "--composition" || (args[0] != "validate" && args[0] != "plan" && args[0] != "run") {
		return fail("plugin_command_arguments_invalid", nil)
	}
	if os.Getuid() != os.Geteuid() {
		return fail("plugin_command_owner_invalid", nil)
	}
	if ctx.Err() != nil {
		return fail("plugin_command_canceled", ctx.Err())
	}
	prepared, err := loadComposition(ctx, args[2])
	if err != nil {
		return err
	}
	if args[0] == "run" {
		if control {
			if !prepared.graph {
				return fail("plugin_control_requires_topology", nil)
			}
			return runCompositionWithControl(ctx, prepared, output, os.Stdin)
		}
		return runComposition(ctx, prepared, output)
	}
	status := "validated"
	if args[0] == "plan" {
		status = "planned"
	}
	return writeResult(ctx, output, resultFor(prepared, status))
}

func loadComposition(ctx context.Context, file string) (preparedComposition, error) {
	invalid := func(code string, err error) (preparedComposition, error) {
		return preparedComposition{}, fail(code, err)
	}
	raw, err := plugins.ReadOwnerPrivateFile(file, compositionLimit)
	if err != nil {
		return invalid("plugin_composition_unavailable", err)
	}
	var input composition
	if err = decodeComposition(raw, &input); err != nil {
		return invalid("plugin_composition_invalid", err)
	}
	native := input.SchemaVersion == "1.2.0" && input.NativeContext != nil && validNativeContextRequest(*input.NativeContext)
	graph := (input.SchemaVersion == "1.1.0" && input.NativeContext == nil || native) && input.Topology != nil
	legacy := input.NativeContext == nil && input.SchemaVersion == "1.0.0" && input.Topology == nil && input.InstanceConfigurations == nil && len(input.Roots) > 0 && input.Configurations != nil && input.Instances != nil && len(input.Instances) <= 64
	if (!legacy && !graph) || input.Catalog == nil || len(input.Catalog) == 0 || len(input.Catalog) > 64 || input.Selected == nil || input.Contracts == nil || input.InstallationMode != "independent" || input.Platform.OS != "darwin" || input.Platform.Arch != "arm64" || runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" || input.ActivationTimeoutMS < 1 || input.ActivationTimeoutMS > 180000 || input.CleanupTimeoutMS < 1 || input.CleanupTimeoutMS > 180000 {
		return invalid("plugin_composition_unsupported", nil)
	}
	work, cancel := context.WithTimeout(ctx, time.Duration(input.ActivationTimeoutMS)*time.Millisecond)
	defer cancel()
	request := plugins.ActivationRequest{Roots: input.Roots, Selected: input.Selected, Contracts: input.Contracts, Instances: input.Instances}
	var budget int64
	for _, entry := range input.Catalog {
		if work.Err() != nil {
			return invalid("plugin_command_canceled", work.Err())
		}
		if entry.Limits.MaxFileBytes < 1 || entry.Limits.MaxFileBytes > 128<<20 || entry.Limits.MaxTotalBytes < 1 || entry.Limits.MaxTotalBytes > inputTotalLimit || entry.Limits.MaxFiles < 1 || entry.Limits.MaxFiles > 4096 || entry.Limits.MaxTotalBytes > inputTotalLimit-budget {
			return invalid("plugin_catalog_limits_invalid", nil)
		}
		budget += entry.Limits.MaxTotalBytes
		source, err := readSource(entry.SourceFile)
		if err != nil {
			return invalid("plugin_source_unavailable", err)
		}
		pkg, err := plugins.AdmitPackage(work, plugins.PackageInput{Directory: entry.Directory, ManifestPath: entry.ManifestPath, SourceID: entry.SourceID, SourcePath: entry.SourcePath, Scope: entry.Scope, Source: source, SourceChecksum: entry.SourceChecksum, Limits: plugins.AdmissionLimits{MaxFileBytes: entry.Limits.MaxFileBytes, MaxTotalBytes: entry.Limits.MaxTotalBytes, MaxFiles: entry.Limits.MaxFiles}})
		if err != nil {
			return preparedComposition{}, err
		}
		request.Catalog = append(request.Catalog, pkg)
	}
	if graph {
		prepared, err := prepareGraphComposition(work, input, request)
		if err == nil {
			prepared.nativeContext = input.NativeContext
		}
		return prepared, err
	}
	plan, err := plugins.Resolve(request.Catalog, request.Roots, request.Selected)
	if err != nil {
		return preparedComposition{}, err
	}
	packages := plan.Packages()
	if err = validateDriverShape(input.Driver, plan, input.Instances); err != nil {
		return preparedComposition{}, err
	}
	if len(input.Configurations) != len(packages) || len(input.Instances) != len(packages) {
		return invalid("activation_binding_set_invalid", nil)
	}
	configurations := map[plugins.PackagePin]plugins.ConfigurationInput{}
	for _, configuration := range input.Configurations {
		if work.Err() != nil {
			return invalid("plugin_command_canceled", work.Err())
		}
		if _, exists := configurations[configuration.Pin]; exists {
			return invalid("activation_configuration_duplicate", nil)
		}
		values, err := plugins.ReadOwnerPrivateFile(configuration.ConfigurationFile, compositionLimit)
		if err != nil {
			return invalid("plugin_configuration_unavailable", err)
		}
		configurations[configuration.Pin] = plugins.ConfigurationInput{Pin: configuration.Pin, Resources: configuration.Resources, Raw: values}
	}
	used := map[string]bool{}
	count := 0
	for _, pkg := range packages {
		if err = plugins.ValidateActivationSupport(pkg, input.InstallationMode, input.Platform); err != nil {
			return preparedComposition{}, err
		}
		id, exists := input.Instances[pkg.Pin().PackageID]
		if !exists || !commandIdentifier.MatchString(id) || used[id] {
			return invalid("activation_instance_invalid", nil)
		}
		used[id] = true
		configuration, exists := configurations[pkg.Pin()]
		if !exists {
			return invalid("activation_configuration_missing", nil)
		}
		if _, err = plugins.PrepareConfiguration(pkg, configuration.Resources, configuration.Raw); err != nil {
			return preparedComposition{}, err
		}
		request.Configurations = append(request.Configurations, configuration)
		count += len(pkg.Manifest().Contributions)
	}
	if err = plugins.ValidateContributionDeclarations(plan, input.Contracts); err != nil {
		return preparedComposition{}, err
	}
	if work.Err() != nil {
		return invalid("plugin_command_canceled", work.Err())
	}
	return preparedComposition{request: request, options: plugins.ManagerOptions{Platform: input.Platform, InstallationMode: input.InstallationMode, ActivationTimeout: time.Duration(input.ActivationTimeoutMS) * time.Millisecond, CleanupTimeout: time.Duration(input.CleanupTimeoutMS) * time.Millisecond}, driver: input.Driver, plan: plan, contributionCount: count}, nil
}

// Read-only commands check declarations and binding shape only. Credential
// permissions, native images and filesystem trust are checked by the driver;
// neither a plan nor a parsed public account key is an authorization grant.
func validateDriverShape(options plugins.NativeDriverOptions, plan plugins.Plan, instances map[string]string) error {
	topology, err := plugins.FlatInstanceTopology(plan, instances)
	if err != nil {
		return err
	}
	return validateTopologyDriverShape(options, topology)
}

func validateTopologyDriverShape(options plugins.NativeDriverOptions, topology plugins.InstanceTopology) error {
	invalid := func() error { return fail("plugin_driver_binding_invalid", nil) }
	if !commandIdentifier.MatchString(options.HubID) || !nkeys.IsValidPublicAccountKey(options.AccountPublicKey) || !absolutePath(options.StateDirectory) || !absolutePath(options.ControllerCredentialsFile) || len(options.Bindings) != len(topology.Instances()) {
		return invalid()
	}
	endpoint, err := url.Parse(options.ServerURL)
	if err != nil || endpoint.User != nil || endpoint.Hostname() == "" || endpoint.Port() == "" || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" {
		return invalid()
	}
	port, err := strconv.Atoi(endpoint.Port())
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != endpoint.Port() {
		return invalid()
	}
	if endpoint.Scheme != "tls" || !absolutePath(options.CAFile) {
		return invalid()
	}
	seen := map[string]bool{}
	for _, binding := range options.Bindings {
		pkg, exists := topology.Package(binding.InstanceID)
		if !exists || pkg.Pin() != binding.Pin || seen[binding.InstanceID] || !commandIdentifier.MatchString(binding.InstanceID) || !absolutePath(binding.CredentialsFile) || binding.CredentialsFile == options.ControllerCredentialsFile {
			return invalid()
		}
		seen[binding.InstanceID] = true
		if binding.Workspace != "" && !absolutePath(binding.Workspace) {
			return invalid()
		}
		if (pkg.Manifest().Runtime.WorkingDirectoryPolicy == "assigned-workspace") != (binding.Workspace != "") {
			return invalid()
		}
	}
	return nil
}
func absolutePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}

var commandIdentifier = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,95}$`)

// The wire check rejects duplicate keys and invalid Unicode/numbers first. This
// local field walk also rejects encoding/json's case-insensitive field aliases.
func decodeComposition(raw []byte, out *composition) error {
	if plugins.ValidateJSON(raw) != nil {
		return fail("plugin_composition_invalid", nil)
	}
	if err := checkExactFields(raw, reflect.TypeOf(*out)); err != nil {
		return err
	}
	if json.Unmarshal(raw, out) != nil {
		return fail("plugin_composition_invalid", nil)
	}
	return nil
}
func checkExactFields(raw json.RawMessage, target reflect.Type) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	for target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	switch target.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil {
			return fail("plugin_composition_invalid", nil)
		}
		fields := map[string]reflect.Type{}
		for index := 0; index < target.NumField(); index++ {
			field := target.Field(index)
			if !field.IsExported() {
				continue
			}
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "" {
				name = field.Name
			}
			if name != "-" {
				fields[name] = field.Type
			}
		}
		for name, value := range object {
			field, exists := fields[name]
			if !exists {
				return fail("plugin_composition_invalid", nil)
			}
			if err := checkExactFields(value, field); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		if target.Elem().Kind() == reflect.Uint8 {
			return nil
		}
		var array []json.RawMessage
		if json.Unmarshal(raw, &array) != nil {
			return fail("plugin_composition_invalid", nil)
		}
		for _, value := range array {
			if err := checkExactFields(value, target.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil {
			return fail("plugin_composition_invalid", nil)
		}
		for _, value := range object {
			if err := checkExactFields(value, target.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func readSource(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fail("plugin_source_unavailable", nil)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, fail("plugin_source_unavailable", nil)
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fail("plugin_source_unavailable", nil)
	}
	raw, operation := readHeldSource(file)
	if closeErr := file.Close(); closeErr != nil {
		return nil, fail("plugin_source_cleanup_incomplete", errors.Join(operation, &sourceCloseFailure{owner: file, cause: closeErr}))
	}
	return raw, operation
}

type sourceCloseFailure struct {
	owner *os.File
	cause error
}

func (*sourceCloseFailure) Error() string   { return "plugin_source_cleanup_incomplete" }
func (e *sourceCloseFailure) Unwrap() error { return e.cause }
func (*sourceCloseFailure) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "plugin_source_cleanup_incomplete")
}
func readHeldSource(file *os.File) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, fail("plugin_source_unavailable", nil)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > compositionLimit {
		return nil, fail("plugin_source_unavailable", nil)
	}
	raw, err := io.ReadAll(io.LimitReader(file, compositionLimit+1))
	after, statErr := file.Stat()
	if err != nil || statErr != nil || len(raw) > compositionLimit || !os.SameFile(info, after) || info.Size() != after.Size() || info.ModTime() != after.ModTime() || info.Mode() != after.Mode() {
		return nil, fail("plugin_source_unavailable", nil)
	}
	return raw, nil
}

// The sole foreground output owner polls its inherited descriptor before small
// writes. No goroutine or descriptor flags are left behind on backpressure.
// Regular-file writes retain the supported local-filesystem assumption.
func writeResult(parent context.Context, output io.Writer, value commandResult) error {
	if parent == nil || output == nil {
		return fail("plugin_command_output_unavailable", nil)
	}
	ctx, cancel := context.WithTimeout(parent, time.Second)
	defer cancel()
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > compositionLimit {
		return fail("plugin_command_output_unavailable", nil)
	}
	raw = append(raw, '\n')
	file, native := output.(*os.File)
	if !native {
		if ctx.Err() != nil {
			return fail("plugin_command_output_unavailable", ctx.Err())
		}
		n, err := output.Write(raw)
		if err != nil || n != len(raw) {
			return fail("plugin_command_output_unavailable", nil)
		}
		return nil
	}
	if file == nil {
		return fail("plugin_command_output_unavailable", nil)
	}
	fd := int(file.Fd())
	defer runtime.KeepAlive(file)
	info, err := file.Stat()
	if err != nil {
		return fail("plugin_command_output_unavailable", nil)
	}
	chunkLimit := 1
	if info.Mode().IsRegular() || info.Mode()&os.ModeNamedPipe != 0 {
		chunkLimit = 512
	}
	for len(raw) > 0 {
		if ctx.Err() != nil {
			return fail("plugin_command_output_unavailable", ctx.Err())
		}
		deadline, _ := ctx.Deadline()
		wait := min(25, int((time.Until(deadline)+time.Millisecond-1)/time.Millisecond))
		if wait <= 0 {
			return fail("plugin_command_output_unavailable", context.DeadlineExceeded)
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		ready, err := unix.Poll(poll, wait)
		if err == unix.EINTR {
			continue
		}
		if err != nil || poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return fail("plugin_command_output_unavailable", nil)
		}
		if ready == 0 || poll[0].Revents&unix.POLLOUT == 0 {
			continue
		}
		chunk := raw
		if len(chunk) > chunkLimit {
			chunk = chunk[:chunkLimit]
		}
		n, err := unix.Write(fd, chunk)
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		if err != nil || n <= 0 {
			return fail("plugin_command_output_unavailable", nil)
		}
		raw = raw[n:]
	}
	return nil
}

func runComposition(ctx context.Context, prepared preparedComposition, output io.Writer) error {
	return runCompositionWithControl(ctx, prepared, output, nil)
}

func runCompositionWithControl(ctx context.Context, prepared preparedComposition, output io.Writer, input *os.File) error {
	if prepared.nativeContext != nil {
		return runNativeContextComposition(ctx, prepared, output, input)
	}
	driver, err := plugins.NewNativeDriver(ctx, prepared.driver)
	if err != nil {
		if driver != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), prepared.options.CleanupTimeout)
			closeErr := driver.Close(cleanup)
			cancel()
			return errors.Join(err, closeErr)
		}
		return err
	}
	return runOwnedComposition(ctx, prepared, output, input, driver, driver)
}

func runOwnedComposition(ctx context.Context, prepared preparedComposition, output io.Writer, input *os.File, driver plugins.Driver, owner driverCleanupOwner) error {
	manager, err := plugins.NewManager(ctx, driver, prepared.options)
	if err != nil {
		return errors.Join(err, closeForegroundDriver(owner, prepared.options.CleanupTimeout, output))
	}
	_, operation := manager.Activate(ctx, prepared.request)
	if operation == nil {
		result := resultFor(prepared, "active")
		if prepared.graph {
			snapshot := manager.Snapshot()
			result.Snapshot = &snapshot
		}
		operation = writeResult(ctx, output, result)
		if operation == nil {
			if prepared.graph {
				operation = superviseControlled(ctx, manager, prepared, input, output)
			} else {
				ticker := time.NewTicker(100 * time.Millisecond)
				defer ticker.Stop()
			foreground:
				for {
					select {
					case <-ctx.Done():
						break foreground
					case <-manager.Done():
						break foreground
					case <-ticker.C:
						snapshot := manager.Snapshot()
						for _, instance := range snapshot.Instances {
							if instance.Code == "plugin_restart_exhausted" || instance.Code == "plugin_generation_exhausted" {
								operation = fail("plugin_supervision_failed", nil)
								break foreground
							}
						}
						if snapshot.RetainedCleanup != 0 {
							operation = fail("plugin_cleanup_incomplete", nil)
							break foreground
						}
					}
				}
			}
		}
	}
	cleanupErr := shutdownOwned(manager, owner, prepared.options.CleanupTimeout, output)
	if operation != nil || cleanupErr != nil {
		return errors.Join(operation, cleanupErr)
	}
	return writeResult(context.Background(), output, resultFor(prepared, "stopped"))
}

type managerCleanupOwner interface {
	Close(context.Context) error
	RetryCleanup(context.Context) error
	Done() <-chan struct{}
}
type driverCleanupOwner interface{ Close(context.Context) error }

// A command cannot exit while an original child or asynchronous transport owner
// remains uncertain. Each retry has a fresh bounded budget; the foreground owner
// stays alive if cleanup cannot yet be proved. Uncatchable termination remains an
// uncertain outcome, not a successful shutdown.
func shutdownOwned(manager managerCleanupOwner, driver driverCleanupOwner, budget time.Duration, output io.Writer) error {
	var managerFailure, retryFailure, driverFailure error
	reported := false
	report := func() {
		if !reported {
			_ = writeResult(context.Background(), output, commandResult{SchemaVersion: "1.0.0", Status: "cleanup_required", Code: "plugin_cleanup_incomplete"})
			reported = true
		}
	}
	for {
		work, cancel := context.WithTimeout(context.Background(), budget)
		err := manager.Close(work)
		cancel()
		if err == nil {
			select {
			case <-manager.Done():
				goto driverClose
			default:
				err = fail("plugin_cleanup_incomplete", nil)
			}
		}
		if managerFailure == nil {
			managerFailure = err
		}
		report()
		work, cancel = context.WithTimeout(context.Background(), budget)
		retryErr := manager.RetryCleanup(work)
		cancel()
		if retryFailure == nil {
			retryFailure = retryErr
		}
		time.Sleep(100 * time.Millisecond)
	}
driverClose:
	driverFailure = closeForegroundDriverWithReport(driver, budget, report)
	if failures := errors.Join(managerFailure, retryFailure, driverFailure); failures != nil {
		return fail("plugin_cleanup_delayed", failures)
	}
	return nil
}

func closeForegroundDriver(driver driverCleanupOwner, budget time.Duration, output io.Writer) error {
	reported := false
	report := func() {
		if !reported {
			_ = writeResult(context.Background(), output, commandResult{SchemaVersion: "1.0.0", Status: "cleanup_required", Code: "plugin_cleanup_incomplete"})
			reported = true
		}
	}

	return closeForegroundDriverWithReport(driver, budget, report)
}

func closeForegroundDriverWithReport(driver driverCleanupOwner, budget time.Duration, report func()) error {
	var driverFailure error

	for {
		work, cancel := context.WithTimeout(context.Background(), budget)
		err := driver.Close(work)
		cancel()
		if err == nil {
			break
		}
		// The native driver visits every remaining descriptor once before this
		// typed historical failure. Manager.Done already proves worker joins;
		// repeating a consumed descriptor close cannot improve that evidence.
		var admission *plugins.AdmissionCleanupFailure
		if errors.As(err, &admission) {
			return errors.Join(driverFailure, err)
		}
		if joined, ok := driver.(interface{ CleanupComplete() bool }); ok && joined.CleanupComplete() {
			return errors.Join(driverFailure, err)
		}
		if driverFailure == nil {
			driverFailure = err
		}
		report()
		time.Sleep(100 * time.Millisecond)
	}
	if driverFailure != nil {
		return fail("plugin_cleanup_delayed", driverFailure)
	}
	return nil
}
