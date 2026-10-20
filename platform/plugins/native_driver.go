package plugins

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"debug/macho"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/controlLogix/agentmux/platform/localtls"
	"github.com/controlLogix/agentmux/platform/privatefs"
	"github.com/nats-io/nats.go"
)

type NativeDriverOptions struct {
	LifecycleTrust *localtls.ClientTrust `json:"-"`
	// ProfileContext comes from the admitted central profile selection.
	ProfileContext            *ProfileContext `json:"-"`
	HubID                     string          `json:"hubId"`
	AccountPublicKey          string          `json:"accountPublicKey"`
	ServerURL                 string          `json:"serverURL"`
	CAFile                    string          `json:"caFile,omitempty"`
	StateDirectory            string          `json:"stateDirectory"`
	ControllerCredentialsFile string          `json:"controllerCredentialsFile"`
	Bindings                  []NativeBinding `json:"bindings"`
}
type NativeBinding struct {
	Pin             PackagePin `json:"pin"`
	InstanceID      string     `json:"instanceId"`
	CredentialsFile string     `json:"credentialsFile"`
	Workspace       string     `json:"workspace,omitempty"`
}
type admittedNativeBinding struct {
	binding    NativeBinding
	credential lifecycleCredential
	workspace  *os.Root
}

// NativeDriver runs trusted native programs under the owner's OS identity.
// Exact broker permissions protect the lifecycle channel; this is not an OS sandbox.
type NativeDriver struct {
	mu           sync.Mutex
	options      NativeDriverOptions
	root         *os.Root
	rootInfo     os.FileInfo
	lock         *os.File
	controller   lifecycleCredential
	tls          *tls.Config
	ca           []byte
	bindings     map[string]admittedNativeBinding
	owners       map[string]*nativeInstance
	closing      bool
	closeFailure error
	contexts     ContextProvider
}

func (*NativeDriver) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[ordinary native plugin driver]")
}
func (*NativeDriver) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"ordinary-native-plugin-driver"}`), nil
}

func NewNativeDriver(ctx context.Context, options NativeDriverOptions) (driver *NativeDriver, failure error) {
	return newNativeDriver(ctx, options, nil)
}

// NewNativeDriverWithContext requires an explicit trusted context provider.
// The legacy constructor retains its lifecycle-only compatibility protocol.
func NewNativeDriverWithContext(ctx context.Context, options NativeDriverOptions, provider ContextProvider) (*NativeDriver, error) {
	if nilContextDependency(provider) {
		return nil, pluginError("context_authority_unavailable")
	}
	return newNativeDriver(ctx, options, provider)
}

func nilContextDependency(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func newNativeDriver(ctx context.Context, options NativeDriverOptions, provider ContextProvider) (driver *NativeDriver, failure error) {
	if ctx == nil || ctx.Err() != nil || runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" || len(options.Bindings) == 0 || len(options.Bindings) > 4096 {
		return nil, pluginError("native_driver_options_invalid")
	}
	if !validProfileContext(options.ProfileContext) {
		return nil, pluginError("context_profile_invalid")
	}
	options.ProfileContext = cloneProfileContext(options.ProfileContext)
	secure, err := validateLifecycleURL(options.ServerURL)
	if err != nil {
		return nil, err
	}
	d := &NativeDriver{options: options, bindings: map[string]admittedNativeBinding{}, owners: map[string]*nativeInstance{}, contexts: provider}
	// On refusal, close every acquired directory and lock. A completed close
	// failure remains attached to the returned error rather than becoming success.
	defer func() {
		if failure == nil {
			return
		}
		for _, binding := range d.bindings {
			if binding.workspace != nil {
				failure = closeAdmission(binding.workspace, failure)
			}
		}
		if d.lock != nil {
			failure = closeAdmission(d.lock, failure)
		}
		if d.root != nil {
			failure = closeAdmission(d.root, failure)
		}
	}()
	if secure {
		if options.CAFile == "" {
			return nil, pluginError("lifecycle_ca_required")
		}
		d.ca, err = ReadOwnerPrivateFile(options.CAFile, 1<<20)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(d.ca) {
			return nil, pluginError("lifecycle_ca_invalid")
		}
		u, _ := url.Parse(options.ServerURL)
		d.tls = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: u.Hostname()}
	} else if options.CAFile != "" {
		return nil, pluginError("lifecycle_ca_unexpected")
	}
	if options.LifecycleTrust != nil {
		policy := options.LifecycleTrust.Policy()
		if policy.Endpoint != options.ServerURL || !bytes.Equal(policy.RootsPEM, d.ca) {
			return nil, pluginError("lifecycle_tls_binding_invalid")
		}
	}
	var controls, events []string
	keys := map[string]bool{}
	for _, binding := range options.Bindings {
		if ctx.Err() != nil {
			return nil, pluginError("plugin_operation_canceled")
		}
		if binding.Pin.PackageID == "" || d.bindings[binding.InstanceID].binding.InstanceID != "" {
			return nil, pluginError("native_binding_invalid")
		}
		control, event, err := lifecycleSubjects(options.HubID, binding.InstanceID)
		if err != nil {
			return nil, err
		}
		credential, err := readLifecycleCredential(binding.CredentialsFile, options.AccountPublicKey, []string{event}, []string{control})
		if err != nil {
			return nil, err
		}
		if keys[credential.public] {
			return nil, pluginError("lifecycle_identity_reused")
		}
		keys[credential.public] = true
		entry := admittedNativeBinding{binding: binding, credential: credential}
		if binding.Workspace != "" {
			entry.workspace, err = openLifecycleStateRoot(binding.Workspace)
			if err != nil {
				return nil, err
			}
		}
		d.bindings[binding.InstanceID] = entry
		controls, events = append(controls, control), append(events, event)
	}
	d.controller, err = readLifecycleCredential(options.ControllerCredentialsFile, options.AccountPublicKey, controls, events)
	if err != nil {
		return nil, err
	}
	if keys[d.controller.public] {
		return nil, pluginError("lifecycle_identity_reused")
	}
	d.root, err = openLifecycleStateRoot(options.StateDirectory)
	if err != nil {
		return nil, err
	}
	d.rootInfo, err = d.root.Stat(".")
	if err != nil {
		return nil, pluginError("lifecycle_state_unavailable")
	}
	d.lock, err = d.root.OpenFile("manager.lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, pluginError("lifecycle_lock_unavailable")
	}
	info, err := d.lock.Stat()
	if err != nil || !privateNativeFile(info) || privatefs.CheckDescriptor(d.lock, privatefs.PrivateObject) != nil {
		return nil, pluginError("lifecycle_lock_invalid")
	}
	if syscall.Flock(int(d.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil, pluginError("lifecycle_already_owned")
	}
	return d, nil
}
func privateNativeFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid() && stat.Nlink == 1
}
func nativeExecutable(pkg AdmittedPackage, mode string, nativeContext bool) error {
	if err := validateActivationSupport(pkg, mode, Platform{OS: runtime.GOOS, Arch: runtime.GOARCH}, nativeContext); err != nil {
		return err
	}
	raw, err := pkg.File(pkg.Manifest().Runtime.ExecutableRef)
	if err != nil {
		return err
	}
	file, err := macho.NewFile(bytes.NewReader(raw))
	if err != nil {
		return pluginError("native_executable_unsupported")
	}
	if file.Cpu != macho.CpuArm64 || file.Type != macho.TypeExec {
		return pluginError("native_executable_unsupported")
	}
	return nil
}

// Preflight checks the full candidate before the manager starts its first process.
// It validates local execution bindings; it does not claim broker readiness.
func (d *NativeDriver) Preflight(ctx context.Context, plan Plan) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closing || ctx == nil || ctx.Err() != nil {
		return pluginError("native_driver_unavailable")
	}
	for _, pkg := range plan.Packages() {
		if ctx.Err() != nil {
			return pluginError("plugin_operation_canceled")
		}
		// The legacy plan permits one independent instance per package only.
		if len(pkg.Manifest().Children) != 0 {
			return pluginError("topology_required")
		}
		instanceID := ""
		for id, entry := range d.bindings {
			if entry.binding.Pin == pkg.Pin() {
				if instanceID != "" {
					return pluginError("native_binding_ambiguous")
				}
				instanceID = id
			}
		}
		if err := d.validatePackage(pkg, instanceID, "independent"); err != nil {
			return err
		}
	}
	return nil
}
func (d *NativeDriver) PreflightInstances(ctx context.Context, topology InstanceTopology) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closing || ctx == nil || ctx.Err() != nil || len(topology.Instances()) == 0 {
		return pluginError("native_driver_unavailable")
	}
	for _, node := range topology.Instances() {
		if ctx.Err() != nil {
			return pluginError("plugin_operation_canceled")
		}
		pkg, exists := topology.Package(node.InstanceID)
		if !exists || node.Placement.Kind != "local-process" {
			return pluginError("native_binding_invalid")
		}
		if err := d.validatePackage(pkg, node.InstanceID, node.InstallationMode); err != nil {
			return err
		}
	}
	return nil
}

// Only the concrete registered provider performs the native grant and policy
// intersection before this driver can start a process with required capabilities.
func (d *NativeDriver) requiredCapabilityAdmission() bool {
	if d == nil {
		return false
	}
	provider, ok := d.contexts.(*nativeRegisteredContextProvider)
	return ok && provider != nil
}

func (d *NativeDriver) validatePackage(pkg AdmittedPackage, instanceID, mode string) error {
	if err := nativeExecutable(pkg, mode, d.requiredCapabilityAdmission()); err != nil {
		return err
	}
	entry, found := d.bindings[instanceID]
	if !found || entry.binding.Pin != pkg.Pin() {
		return pluginError("native_binding_missing")
	}
	workspace := pkg.Manifest().Runtime.WorkingDirectoryPolicy == "assigned-workspace"
	if workspace != (entry.workspace != nil) {
		return pluginError("native_workspace_binding_invalid")
	}
	if workspace {
		current, e := os.Lstat(entry.binding.Workspace)
		held, he := entry.workspace.Stat(".")
		if e != nil || he != nil || !os.SameFile(current, held) {
			return pluginError("native_workspace_changed")
		}
	}
	current, err := os.Lstat(d.options.StateDirectory)
	if err != nil || !os.SameFile(current, d.rootInfo) {
		return pluginError("lifecycle_state_changed")
	}
	return nil
}

type nativeInstance struct {
	driver          *NativeDriver
	owner           OwnerReference
	command         LifecycleControl
	drain           time.Duration
	stage           string
	stageInfo       os.FileInfo
	cmd             *exec.Cmd
	conn            *nats.Conn
	lifecycleDialer *localtls.Dialer
	lifecycleCancel context.CancelFunc
	sub             *nats.Subscription
	controlSubject  string
	connectionLost  chan struct{}
	lifetimeDone    chan struct{}
	lifetimeOnce    sync.Once
	parentLifetime  <-chan struct{}
	transportClosed chan struct{}
	lossOnce        sync.Once
	processDone     chan struct{}
	done            chan struct{}
	stopToken       chan struct{}
	readyToken      chan struct{}
	unavailable     atomic.Bool
	ready           atomic.Bool
	mu              sync.Mutex
	exitError       error
	cleaned         bool
	cleanupFailure  error
	contextLease    ContextLease
	contextDone     <-chan struct{}
	startDone       chan struct{}
	startCancel     context.CancelFunc
	stopping        atomic.Bool
	lifecycle       *nativeContextLifecycle
}

func (*nativeInstance) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[owned native plugin process]")
}
func (*nativeInstance) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"owned-native-plugin-process"}`), nil
}
func (p *nativeInstance) Available() bool {
	if p.startDone != nil && !completed(p.startDone) {
		return false
	}
	if p.lifecycle != nil && !p.lifecycle.Snapshot().Ready {
		return false
	}
	return p.ready.Load() && !p.unavailable.Load() && !completed(p.done) && !completed(p.parentLifetime) && !completed(p.contextDone) && p.conn != nil && p.conn.IsConnected() && p.conn.LastError() == nil
}
func (p *nativeInstance) LifetimeDone() <-chan struct{} { return p.lifetimeDone }
func (p *nativeInstance) endLifetime() {
	p.unavailable.Store(true)
	if p.lifecycle != nil {
		p.lifecycle.stop()
	}
	p.lifetimeOnce.Do(func() {
		if p.lifetimeDone != nil {
			close(p.lifetimeDone)
		}
	})
	p.mu.Lock()
	lease := p.contextLease
	p.mu.Unlock()
	if lease != nil {
		lease.Invalidate()
	}
}
func (p *nativeInstance) Done() <-chan struct{} { return p.done }
func (p *nativeInstance) ExitError() error      { p.mu.Lock(); defer p.mu.Unlock(); return p.exitError }
func (p *nativeInstance) loseConnection() {
	p.endLifetime()
	p.lossOnce.Do(func() { close(p.connectionLost) })
}

func (d *NativeDriver) Start(ctx context.Context, request StartRequest) (OwnedInstance, error) {
	d.mu.Lock()
	locked := true
	defer func() {
		if locked {
			d.mu.Unlock()
		}
	}()
	if ctx == nil || ctx.Err() != nil || d.closing {
		return nil, pluginError("native_driver_unavailable")
	}
	node := request.Instance
	if node.InstanceID == "" {
		node = InstanceSpec{InstanceID: request.Owner.InstanceID, Pin: request.Package.Pin(), InstallationMode: "independent", Placement: Placement{Kind: "local-process"}}
		if len(request.Package.Manifest().Children) != 0 {
			return nil, pluginError("topology_required")
		}
	}
	if node.InstanceID != request.Owner.InstanceID || node.Pin != request.Package.Pin() || node.Placement.Kind != "local-process" {
		return nil, pluginError("native_start_binding_invalid")
	}
	if err := d.validatePackage(request.Package, node.InstanceID, node.InstallationMode); err != nil {
		return nil, err
	}
	if node.InstallationMode == "private-child" {
		if request.Parent == nil || request.ParentLifetime == nil {
			return nil, pluginError("native_parent_binding_invalid")
		}
		parent := d.owners[request.Parent.InstanceID]
		if parent == nil || parent.stopping.Load() || parent.owner != *request.Parent || parent.owner.Epoch != request.Owner.Epoch || parent.owner.InstanceID == request.Owner.InstanceID || parent.LifetimeDone() != request.ParentLifetime || completed(request.ParentLifetime) || completed(parent.done) || (parent.startDone != nil && !completed(parent.startDone)) || completed(parent.contextDone) {
			return nil, pluginError("native_parent_binding_invalid")
		}
	} else if request.Parent != nil || request.ParentLifetime != nil {
		return nil, pluginError("native_parent_binding_invalid")
	}
	entry := d.bindings[request.Owner.InstanceID]
	if request.Owner.Pin != request.Package.Pin() || request.Owner.InstanceID != entry.binding.InstanceID || !registryEpoch.MatchString(request.Owner.Epoch) || request.Owner.Generation == 0 || request.Owner.Generation > maxGeneration || !request.Configuration.BelongsTo(request.Package) {
		return nil, pluginError("native_start_binding_invalid")
	}
	if d.owners[request.Owner.InstanceID] != nil {
		return nil, pluginError("native_instance_owned")
	}
	commandID, err := randomControlID()
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(time.Duration(request.Package.Manifest().Lifecycle.StartDeadlineMS) * time.Millisecond)
	if caller, ok := ctx.Deadline(); ok && caller.Before(deadline) {
		deadline = caller
	}
	ctx, startCancel := context.WithDeadline(ctx, deadline)
	defer startCancel()
	bindings := append([]ContributionBinding(nil), request.Contributions...)
	sort.Slice(bindings, func(i, j int) bool {
		if bindings[i].Kind != bindings[j].Kind {
			return bindings[i].Kind < bindings[j].Kind
		}
		return bindings[i].ID < bindings[j].ID
	})
	bindingsRaw, err := json.Marshal(bindings)
	if err != nil {
		return nil, pluginError("native_start_binding_invalid")
	}
	control, event, _ := lifecycleSubjects(d.options.HubID, request.Owner.InstanceID)
	p := &nativeInstance{driver: d, owner: request.Owner, drain: time.Duration(request.Package.Manifest().Lifecycle.DrainDeadlineMS) * time.Millisecond,
		stage: "instance-" + commandID, controlSubject: control, connectionLost: make(chan struct{}), lifetimeDone: make(chan struct{}), parentLifetime: request.ParentLifetime, transportClosed: make(chan struct{}), processDone: make(chan struct{}), done: make(chan struct{}), stopToken: make(chan struct{}, 1), readyToken: make(chan struct{}, 1), startDone: make(chan struct{}), startCancel: startCancel}
	p.lifecycle = newNativeContextLifecycle(request.Owner)
	p.stopToken <- struct{}{}
	p.readyToken <- struct{}{}
	p.command = LifecycleControl{SchemaVersion: "1.0.0", Kind: "ordinary-plugin-control", Action: "prepare", CommandID: commandID, Owner: request.Owner, ConfigurationChecksum: request.Configuration.Checksum(), ContributionsChecksum: checksum(bindingsRaw), Deadline: deadline.UTC().Format(time.RFC3339Nano)}
	if request.Parent != nil {
		parent := *request.Parent
		p.command.SchemaVersion, p.command.ParentOwner = "1.1.0", &parent
	}
	if err := d.root.Mkdir(p.stage, 0700); err != nil {
		return nil, pluginError("native_stage_unavailable")
	}
	p.stageInfo, err = d.root.Lstat(p.stage)
	d.owners[request.Owner.InstanceID] = p
	// Reserve the exact owner before external setup. Stop must join this start
	// before it reads process/transport fields or removes the owner's stage.
	d.mu.Unlock()
	locked = false
	defer close(p.startDone)
	refuse := func(err error) (OwnedInstance, error) {
		var admission *AdmissionCleanupFailure
		if errors.As(err, &admission) {
			p.mu.Lock()
			p.cleanupFailure = admission
			p.mu.Unlock()
		}
		p.endLifetime()
		close(p.processDone)
		close(p.done)
		return p, err
	}
	if err != nil {
		return refuse(pluginError("native_stage_unavailable"))
	}
	if d.contexts != nil {
		binding := ContextBinding{ProfileContext: cloneProfileContext(d.options.ProfileContext), Owner: request.Owner, Package: request.Package, Configuration: request.Configuration, LifetimeDone: p.lifetimeDone, ParentLifetime: p.parentLifetime, Lifecycle: p.lifecycle}
		if p.command.ParentOwner != nil {
			parent := *p.command.ParentOwner
			binding.Parent = &parent
		}
		lease, openErr := d.contexts.Open(ctx, binding)
		if nilContextDependency(lease) {
			lease = nil
		}
		p.mu.Lock()
		p.contextLease = lease
		var admission *AdmissionCleanupFailure
		if errors.As(openErr, &admission) {
			p.cleanupFailure = admission
		}
		p.mu.Unlock()
		err = openErr
		if lease != nil && completed(p.lifetimeDone) {
			lease.Invalidate()
		}
		// A provider may return a retained lease with its error. Keep that original
		// owner attached so Stop can join it rather than abandoning partial work.
		if err != nil {
			return refuse(pluginError("context_open_failed"))
		}
		if p.contextLease == nil || p.contextLease.Owner() != request.Owner || p.contextLease.Done() == nil {
			return refuse(pluginError("context_owner_invalid"))
		}
		p.contextDone = p.contextLease.Done()
		descriptor := p.contextLease.Descriptor()
		if completed(p.contextDone) || len(descriptor) == 0 || len(descriptor) > manifestLimit || strictDocument(descriptor) != nil {
			return refuse(pluginError("context_unavailable"))
		}
		p.command.SchemaVersion, p.command.ContextChecksum = "1.2.0", checksum(descriptor)
	}
	if ctx.Err() != nil || completed(p.lifetimeDone) || completed(p.parentLifetime) {
		return refuse(pluginError("plugin_operation_canceled"))
	}
	if err := p.stagePackage(request, entry.credential, event, d.ca); err != nil {
		return refuse(err)
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return refuse(pluginError("plugin_deadline_exceeded"))
	}
	if remaining > 2*time.Second {
		remaining = 2 * time.Second
	}
	writeTimeout := min(100*time.Millisecond, p.drain/8)
	options := []nats.Option{nats.UserJWTAndSeed(d.controller.jwt, d.controller.seed), nats.NoReconnect(), nats.IgnoreDiscoveredServers(), nats.Timeout(remaining), nats.FlusherTimeout(writeTimeout),
		nats.ClosedHandler(func(*nats.Conn) { p.loseConnection(); close(p.transportClosed) }), nats.ErrorHandler(func(*nats.Conn, *nats.Subscription, error) { p.loseConnection() })}
	err = p.connectLifecycle(ctx, remaining, options)

	if err != nil {
		return refuse(pluginError("lifecycle_transport_unavailable"))
	}
	p.sub, err = p.conn.SubscribeSync(event)
	if err != nil {
		return refuse(pluginError("lifecycle_transport_unavailable"))
	}
	if p.sub.SetPendingLimits(64, 64*8192) != nil {
		return refuse(pluginError("lifecycle_transport_unavailable"))
	}
	flush, cancel := context.WithDeadline(ctx, deadline)
	err = p.conn.FlushWithContext(flush)
	cancel()
	if err != nil || p.unavailable.Load() || completed(p.parentLifetime) || completed(p.contextDone) || ctx.Err() != nil {
		return refuse(pluginError("lifecycle_transport_unavailable"))
	}
	rootPath := filepath.Join(d.options.StateDirectory, p.stage)
	working := filepath.Join(rootPath, "package")
	if entry.workspace != nil {
		working = entry.binding.Workspace
	}
	p.cmd = exec.Command(filepath.Join(rootPath, "package", filepath.FromSlash(request.Package.Manifest().Runtime.ExecutableRef)), request.Package.Manifest().Runtime.Args...)
	p.cmd.Dir = working
	p.cmd.Env = []string{"AGENTMUX_PLUGIN_BOOTSTRAP=" + filepath.Join(rootPath, "bootstrap.json")}
	p.cmd.Stdout, p.cmd.Stderr = io.Discard, io.Discard
	if err := p.cmd.Start(); err != nil {
		return refuse(pluginError("native_process_start_failed"))
	}
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		select {
		case <-p.processDone:
		case <-p.connectionLost:
			// Signal the original handle only. No PID adoption or process-group kill.
			_ = p.cmd.Process.Kill()
		case <-p.parentLifetime:
			p.endLifetime()
			_ = p.cmd.Process.Kill()
		case <-p.contextDone:
			p.endLifetime()
			if !p.stopping.Load() {
				_ = p.cmd.Process.Kill()
			}
		}
	}()
	go func() {
		err := p.cmd.Wait() // Also joins exec's stdout/stderr copy readers.
		p.endLifetime()
		p.mu.Lock()
		if err != nil {
			p.exitError = pluginError("native_process_failed")
		} else {
			p.exitError = pluginError("native_process_exited")
		}
		p.mu.Unlock()
		close(p.processDone)
		<-monitorDone
		close(p.done)
	}()
	return p, nil
}

func (p *nativeInstance) stagePackage(request StartRequest, credential lifecycleCredential, event string, ca []byte) error {
	d := p.driver
	if d.root.Mkdir(p.stage+"/package", 0700) != nil {
		return pluginError("native_stage_unavailable")
	}
	for _, ref := range request.Package.FilePaths() {
		parts := filepath.Dir(filepath.FromSlash(ref))
		if parts != "." {
			if err := d.root.MkdirAll(p.stage+"/package/"+filepath.ToSlash(parts), 0700); err != nil {
				return pluginError("native_stage_unavailable")
			}
		}
		raw, _ := request.Package.File(ref)
		original, _ := request.Package.FileMode(ref)
		mode := os.FileMode(0400)
		if original&0111 != 0 {
			mode = 0500
		}
		if err := p.writeStage("package/"+ref, raw, mode); err != nil {
			return err
		}
	}
	if err := p.writeStage("configuration.json", request.Configuration.Bytes(), 0600); err != nil {
		return err
	}
	if err := p.writeStage("credentials.creds", credential.raw, 0600); err != nil {
		return err
	}
	base := filepath.Join(d.options.StateDirectory, p.stage)
	bootstrap := NativeBootstrap{SchemaVersion: p.command.SchemaVersion, ServerURL: d.options.ServerURL, CredentialsFile: filepath.Join(base, "credentials.creds"), ConfigurationFile: filepath.Join(base, "configuration.json"), ControlSubject: p.controlSubject, EventSubject: event, Prepare: p.command}
	if d.options.LifecycleTrust != nil {
		policy := d.options.LifecycleTrust.Policy()
		bootstrap.ServerName = policy.ServerName
		bootstrap.LeafCertificateSHA256 = policy.LeafCertificateSHA256
	}

	if p.contextLease != nil {
		private := p.contextLease.Bootstrap()
		descriptor := private.Descriptor()
		if checksum(descriptor) != p.command.ContextChecksum || !bytes.Equal(descriptor, p.contextLease.Descriptor()) {
			return pluginError("context_bootstrap_changed")
		}
		for name, raw := range map[string][]byte{"context.json": descriptor, "context.creds": private.Credentials(), "context-ca.pem": private.CA()} {
			if len(raw) == 0 || len(raw) > manifestLimit {
				return pluginError("context_bootstrap_invalid")
			}
			if err := p.writeStage(name, raw, 0600); err != nil {
				return err
			}
		}
		bootstrap.Context = &NativeContextBootstrap{ContextFile: filepath.Join(base, "context.json"), CredentialsFile: filepath.Join(base, "context.creds"), CAFile: filepath.Join(base, "context-ca.pem"), Transport: private.Transport()}
	}
	if len(ca) > 0 {
		if err := p.writeStage("ca.pem", ca, 0600); err != nil {
			return err
		}
		bootstrap.CAFile = filepath.Join(base, "ca.pem")
	}
	raw, err := json.Marshal(bootstrap)
	if err != nil {
		return pluginError("native_bootstrap_invalid")
	}
	return p.writeStage("bootstrap.json", raw, 0600)
}
func (p *nativeInstance) writeStage(ref string, raw []byte, mode os.FileMode) error {
	file, err := p.driver.root.OpenFile(p.stage+"/"+ref, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return pluginError("native_stage_unavailable")
	}
	if privatefs.CheckDescriptor(file, privatefs.PrivateObject) != nil {
		return closeAdmission(file, pluginError("native_stage_access_invalid"))
	}
	n, err := file.Write(raw)
	if err != nil || n != len(raw) {
		return closeAdmission(file, pluginError("native_stage_unavailable"))
	}
	return closeAdmission(file, nil)
}

func (p *nativeInstance) WaitReady(ctx context.Context) error {
	if ctx == nil {
		return pluginError("plugin_context_invalid")
	}
	select {
	case <-ctx.Done():
		return pluginError("plugin_deadline_exceeded")
	case <-p.readyToken:
	}
	defer func() { p.readyToken <- struct{}{} }()
	if p.Available() {
		return nil
	}
	if p.unavailable.Load() || completed(p.contextDone) || p.sub == nil {
		return pluginError("plugin_not_ready")
	}
	deadline, _ := time.Parse(time.RFC3339Nano, p.command.Deadline)
	work, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	prepared := false
	for {
		if p.unavailable.Load() || completed(p.parentLifetime) || completed(p.contextDone) || completed(p.done) {
			return pluginError("plugin_not_ready")
		}
		message, err := p.sub.NextMsgWithContext(work)
		if err != nil {
			return pluginError("plugin_not_ready")
		}
		report, err := decodeLifecycleReport(message.Data, p.command)
		if err != nil {
			continue
		}
		switch report.Status {
		case "registered":
			if !prepared {
				raw, _ := json.Marshal(p.command)
				if p.conn.Publish(p.controlSubject, raw) != nil || p.conn.FlushWithContext(work) != nil {
					return pluginError("lifecycle_transport_unavailable")
				}
				prepared = true
			}
		case "ready":
			if prepared && !p.unavailable.Load() && !completed(p.parentLifetime) && !completed(p.contextDone) && !completed(p.done) && p.conn.IsConnected() && p.conn.LastError() == nil {
				if p.lifecycle != nil && !p.lifecycle.markReady() {
					return pluginError("plugin_not_ready")
				}
				p.ready.Store(true)
				return nil
			}
		case "failed", "stopped":
			return pluginError("plugin_not_ready")
		}
	}
}

func (p *nativeInstance) Stop(ctx context.Context) error {
	if ctx == nil {
		return pluginError("plugin_context_invalid")
	}
	select {
	case <-ctx.Done():
		return pluginError("plugin_cleanup_incomplete")
	case <-p.stopToken:
	}
	defer func() { p.stopToken <- struct{}{} }()
	p.stopping.Store(true)
	p.unavailable.Store(true)
	if p.lifecycle != nil {
		p.lifecycle.beginDrain()
	}
	// A running process keeps its admitted operations during the graceful
	// drain. An unfinished start has no running owner to drain and is canceled.
	if p.startDone != nil && !completed(p.startDone) {
		p.endLifetime()
	}
	if p.startCancel != nil {
		p.startCancel()
	}
	p.mu.Lock()
	cleaned, previousFailure := p.cleaned, p.cleanupFailure
	p.mu.Unlock()
	if cleaned {
		return previousFailure
	}
	work, cancel := context.WithTimeout(ctx, p.drain)
	defer cancel()
	if p.startDone != nil {
		select {
		case <-p.startDone:
		case <-work.Done():
			return pluginError("plugin_cleanup_incomplete")
		}
	}
	if !completed(p.done) {
		command := p.command
		command.Action = "stop"
		commandID, err := randomControlID()
		if err == nil {
			command.CommandID = commandID
			deadline, _ := work.Deadline()
			command.Deadline = deadline.UTC().Format(time.RFC3339Nano)
			raw, _ := json.Marshal(command)
			if p.conn != nil {
				_ = p.conn.Publish(p.controlSubject, raw)
			}
		}
		// Give cooperative shutdown and TERM bounded portions of the drain time;
		// leave the final half for the original wait after a forced stop.
		deadline, _ := work.Deadline()
		remaining := time.Until(deadline)
		waitFor(p.done, work, remaining/4)
		if !completed(p.done) && p.cmd != nil && p.cmd.Process != nil {
			_ = p.cmd.Process.Signal(syscall.SIGTERM)
		}
		waitFor(p.done, work, remaining/4)
		if !completed(p.done) {
			// The cooperative drain has ended. Cancel admitted context work
			// even if the original process takes longer to join after kill.
			p.endLifetime()
			if p.cmd != nil && p.cmd.Process != nil {
				_ = p.cmd.Process.Kill()
			}
		}
		select {
		case <-p.done:
		case <-work.Done():
			p.endLifetime()
			return pluginError("plugin_cleanup_incomplete")
		}
	}
	p.endLifetime()
	if p.contextLease != nil {
		if err := p.contextLease.Close(work); err != nil {
			return pluginError("context_cleanup_incomplete")
		}
	}
	if p.conn != nil {
		p.conn.Close()
		// The final callback follows our queued error callbacks. Joining it keeps
		// this owner from being discarded while an application callback is pending.
		select {
		case <-p.transportClosed:
		case <-work.Done():
			return pluginError("plugin_cleanup_incomplete")
		}
	}
	if p.lifecycleCancel != nil {
		p.lifecycleCancel()
	}
	if p.lifecycleDialer != nil && p.lifecycleDialer.Close() != nil {
		return pluginError("plugin_cleanup_incomplete")
	}

	current, err := p.driver.root.Lstat(p.stage)
	if err != nil || p.stageInfo == nil || !os.SameFile(current, p.stageInfo) {
		return pluginError("native_stage_cleanup_incomplete")
	}
	if err := p.driver.root.RemoveAll(p.stage); err != nil {
		return pluginError("native_stage_cleanup_incomplete")
	}
	p.mu.Lock()
	p.cleaned = true
	retained := p.cleanupFailure
	p.cleanupFailure = nil
	p.mu.Unlock()
	p.driver.mu.Lock()
	// The process and stage are gone. Preserve a consumed file-close failure on
	// the driver, which reports it after closing its remaining descriptors.
	p.driver.closeFailure = errors.Join(p.driver.closeFailure, retained)
	if p.driver.owners[p.owner.InstanceID] == p {
		delete(p.driver.owners, p.owner.InstanceID)
	}
	p.driver.mu.Unlock()
	return nil
}

// Dispatch invokes only the currently ready owner. The context provider admits
// the original signed envelope; this method does not turn a caller label into
// authority or allow a released generation to reuse its operation handles.
func (d *NativeDriver) Dispatch(ctx context.Context, owner OwnerReference, envelope []byte) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, pluginError("plugin_operation_canceled")
	}
	d.mu.Lock()
	p := d.owners[owner.InstanceID]
	if d.closing || p == nil || p.owner != owner || !p.Available() || p.contextLease == nil {
		d.mu.Unlock()
		return nil, pluginError("context_unavailable")
	}
	lease := p.contextLease
	d.mu.Unlock()
	return lease.Dispatch(ctx, bytes.Clone(envelope))
}
func waitFor(done <-chan struct{}, ctx context.Context, duration time.Duration) {
	if duration <= 0 {
		return
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-done:
	case <-ctx.Done():
	case <-timer.C:
	}
}

func (d *NativeDriver) Close(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return pluginError("plugin_cleanup_incomplete")
	}
	d.mu.Lock()
	d.closing = true
	var owners []*nativeInstance
	for _, owner := range d.owners {
		owners = append(owners, owner)
	}
	d.mu.Unlock()
	for _, owner := range owners {
		if owner.Stop(ctx) != nil {
			return pluginError("plugin_cleanup_incomplete")
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.owners) != 0 {
		return pluginError("plugin_cleanup_incomplete")
	}
	failure := d.closeFailure
	for id, binding := range d.bindings {
		if binding.workspace != nil {
			err := closeAdmission(binding.workspace, nil)
			binding.workspace = nil
			d.bindings[id] = binding
			failure = errors.Join(failure, err)
		}
	}
	if d.lock != nil {
		err := closeAdmission(d.lock, nil)
		d.lock = nil
		failure = errors.Join(failure, err)
	}
	if d.root != nil {
		err := closeAdmission(d.root, nil)
		d.root = nil
		failure = errors.Join(failure, err)
	}
	d.closeFailure = failure
	return failure
}
