package plugins

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sync"
	"time"
)

// Driver receives only host-admitted startup bindings. It cannot derive a grant
// or broker identity from a package declaration. Start returns the original
// owner whenever a process was started, including a later startup failure.
type Driver interface {
	Start(context.Context, StartRequest) (OwnedInstance, error)
}

// DriverPreflight validates the whole admitted plan without starting processes.
// Drivers with platform or deployment-specific constraints implement this so a
// later unsupported package cannot be discovered after an earlier start.
type DriverPreflight interface {
	Preflight(context.Context, Plan) error
}

// DriverTopologyPreflight admits all instance-specific deployment bindings before
// any process starts. The legacy plan-only hook remains available for flat input.
type DriverTopologyPreflight interface {
	PreflightInstances(context.Context, InstanceTopology) error
}

type StartRequest struct {
	Package        AdmittedPackage
	Configuration  ValidatedConfiguration
	Owner          OwnerReference
	Contributions  []ContributionBinding
	Instance       InstanceSpec
	Parent         *OwnerReference
	ParentLifetime <-chan struct{}
}

func (StartRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[ordinary plugin start request]")
}
func (StartRequest) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"ordinary-plugin-start-request"}`), nil
}

// Stop joins the original process wait and output readers. An error retains
// cleanup ownership; neither a ready frame nor a stop reply proves process exit.
type OwnedInstance interface {
	WaitReady(context.Context) error
	Done() <-chan struct{}
	Stop(context.Context) error
	ExitError() error
}

// InstanceAvailability can revoke dispatch authority before process cleanup is
// complete. Available must be safe for concurrent, nonblocking reads. Done still
// means that the original process wait and output readers have joined.
type InstanceAvailability interface {
	Available() bool
}

// InstanceLifetime closes as soon as this original process loses its lifetime
// authority, even if its process wait is still joining. Done retains its original
// cleanup meaning. Drivers without this signal use their captured Done channel.
type InstanceLifetime interface {
	LifetimeDone() <-chan struct{}
}

type ManagerOptions struct {
	Platform          Platform
	InstallationMode  string
	ActivationTimeout time.Duration
	CleanupTimeout    time.Duration
}

type ConfigurationInput struct {
	Pin       PackagePin
	Resources []SchemaResource
	Raw       []byte
}

type InstanceConfigurationInput struct {
	InstanceID string
	Pin        PackagePin
	Resources  []SchemaResource
	Raw        []byte
}

func (InstanceConfigurationInput) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[ordinary plugin instance configuration input]")
}
func (InstanceConfigurationInput) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"ordinary-plugin-instance-configuration-input"}`), nil
}

func (ConfigurationInput) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[ordinary plugin configuration input]")
}
func (ConfigurationInput) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"ordinary-plugin-configuration-input"}`), nil
}

type ActivationRequest struct {
	Catalog                []AdmittedPackage
	Roots                  []PackagePin
	Selected               []PackagePin
	Instances              map[string]string
	Configurations         []ConfigurationInput
	Contracts              []ContractBinding
	Topology               *InstanceTopologyInput
	InstanceConfigurations []InstanceConfigurationInput
}

func (ActivationRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[ordinary plugin activation request]")
}
func (ActivationRequest) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"ordinary-plugin-activation-request"}`), nil
}

type InstanceSnapshot struct {
	Owner                 OwnerReference  `json:"owner"`
	ConfigurationChecksum string          `json:"configurationChecksum"`
	State                 string          `json:"state"`
	Code                  string          `json:"code,omitempty"`
	RestartAttempts       int             `json:"restartAttempts"`
	Instance              InstanceSpec    `json:"instance"`
	Parent                *OwnerReference `json:"parent,omitempty"`
	RootRetained          bool            `json:"rootRetained"`
	Consumers             []string        `json:"consumers"`
}

type ManagerSnapshot struct {
	Epoch               string                `json:"epoch"`
	Revision            uint64                `json:"revision"`
	Closing             bool                  `json:"closing"`
	Closed              bool                  `json:"closed"`
	Instances           []InstanceSnapshot    `json:"instances"`
	OptionalUnavailable []Unavailable         `json:"optionalUnavailable"`
	InstanceUnavailable []InstanceUnavailable `json:"instanceUnavailable"`
	RetainedCleanup     int                   `json:"retainedCleanup"`
	Code                string                `json:"code,omitempty"`
}

type managedInstance struct {
	pkg            AdmittedPackage
	configuration  ValidatedConfiguration
	owner          OwnerReference
	spec           InstanceSpec
	parent         *OwnerReference
	parentLifetime <-chan struct{}
	process        OwnedInstance
	done           <-chan struct{}
	lifetime       <-chan struct{}
	state, code    string
	restarts       int
	recoveryRoot   string
}

type retainedInstance struct {
	process OwnedInstance
	done    <-chan struct{}
	owner   OwnerReference
	cause   error // First failure retains its original cleanup owner.
	latest  error // Replaced on retry; history cannot grow without bound.
}

type instanceExit struct{ owner OwnerReference }

// Manager owns ordinary processes and the one published contribution set. It
// does not own business work, reconcile effects, migrate storage, or implement
// the later immutable PluginContext and service-handle contracts.
type Manager struct {
	ctx              context.Context
	cancel           context.CancelFunc
	driver           Driver
	options          ManagerOptions
	epoch            string
	operation        chan struct{}
	events           chan instanceExit
	workers          sync.WaitGroup
	closeAttemptDone chan struct{}
	done             chan struct{}
	doneOnce         sync.Once

	mu          sync.RWMutex
	closing     bool
	closed      bool
	revision    uint64
	code        string
	active      map[string]*managedInstance
	order       []string
	plan        Plan
	topology    InstanceTopology
	roots       map[string]bool
	contracts   []ContractBinding
	registry    Registry
	retained    []retainedInstance
	generations map[string]uint64 // Serialized by operation, including failed starts.
}

func (*Manager) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[ordinary plugin manager]") }
func (*Manager) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"ordinary-plugin-manager"}`), nil
}

const maxGeneration = uint64(9007199254740991)

var instanceIdentifier = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,95}$`)

func NewManager(parent context.Context, driver Driver, options ManagerOptions) (*Manager, error) {
	if parent == nil || driver == nil || options.Platform.OS == "" || options.Platform.Arch == "" ||
		options.InstallationMode != "independent" || options.ActivationTimeout <= 0 || options.ActivationTimeout > 180*time.Second ||
		options.CleanupTimeout <= 0 || options.CleanupTimeout > 180*time.Second {
		return nil, pluginError("manager_options_invalid")
	}
	if parent.Err() != nil {
		return nil, pluginError("manager_context_canceled")
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, pluginError("manager_epoch_unavailable")
	}
	ctx, cancel := context.WithCancel(parent)
	m := &Manager{ctx: ctx, cancel: cancel, driver: driver, options: options, epoch: hex.EncodeToString(nonce[:]),
		operation: make(chan struct{}, 1), events: make(chan instanceExit, 4096), closeAttemptDone: make(chan struct{}), done: make(chan struct{}),
		active: map[string]*managedInstance{}, roots: map[string]bool{}, generations: map[string]uint64{}}
	m.operation <- struct{}{}
	m.workers.Add(1)
	go m.observeExits()
	go m.closeOnCancellation()
	return m, nil
}

func (m *Manager) acquire(ctx context.Context, cleanup bool) error {
	if ctx == nil {
		return pluginError("manager_context_invalid")
	}
	if ctx.Err() != nil {
		return managerFailure(ctx.Err(), "manager_context_canceled")
	}
	if cleanup {
		select {
		case <-ctx.Done():
			return managerFailure(ctx.Err(), "manager_context_canceled")
		case <-m.operation:
			return nil
		}
	}
	select {
	case <-ctx.Done():
		return managerFailure(ctx.Err(), "manager_context_canceled")
	case <-m.ctx.Done():
		return pluginError("manager_closed")
	case <-m.operation:
		if m.ctx.Err() != nil {
			m.release()
			return pluginError("manager_closed")
		}
		return nil
	}
}
func (m *Manager) release() { m.operation <- struct{}{} }

func managerFailure(err error, fallback string) error {
	var cleanup *AdmissionCleanupFailure
	if errors.As(err, &cleanup) {
		return cleanup
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return pluginError("plugin_deadline_exceeded")
	}
	if errors.Is(err, context.Canceled) {
		return pluginError("plugin_operation_canceled")
	}
	var known *Error
	if errors.As(err, &known) {
		return pluginError(known.Code())
	}
	return pluginError(fallback)
}
func failureCode(err error, fallback string) string { return managerFailure(err, fallback).Error() }
func completed(done <-chan struct{}) bool {
	if done == nil {
		return false
	}
	select {
	case <-done:
		return true
	default:
		return false
	}
}
func instanceAvailable(process OwnedInstance, done <-chan struct{}) bool {
	if process == nil || done == nil || completed(done) {
		return false
	}
	if availability, ok := process.(InstanceAvailability); ok {
		return availability.Available()
	}
	return true
}

// activationTopology keeps the old one-instance-per-package input separate from
// explicit instance topology. Mixing the two could otherwise invent root claims.
func activationTopology(request ActivationRequest) (InstanceTopology, map[string]InstanceConfigurationInput, error) {
	inputs := map[string]InstanceConfigurationInput{}
	if request.Topology != nil {
		if len(request.Instances) != 0 || len(request.Configurations) != 0 || len(request.Roots) != 0 {
			return InstanceTopology{}, nil, pluginError("activation_binding_ambiguous")
		}
		topology, err := ResolveInstanceTopology(request.Catalog, request.Selected, *request.Topology)
		if err != nil {
			return InstanceTopology{}, nil, err
		}
		if len(request.InstanceConfigurations) != len(topology.Instances()) {
			return InstanceTopology{}, nil, pluginError("activation_binding_set_invalid")
		}
		for _, input := range request.InstanceConfigurations {
			if _, exists := inputs[input.InstanceID]; exists {
				return InstanceTopology{}, nil, pluginError("activation_configuration_duplicate")
			}
			inputs[input.InstanceID] = input
		}
		return topology, inputs, nil
	}
	if len(request.InstanceConfigurations) != 0 {
		return InstanceTopology{}, nil, pluginError("activation_binding_ambiguous")
	}
	plan, err := Resolve(request.Catalog, request.Roots, request.Selected)
	if err != nil {
		return InstanceTopology{}, nil, err
	}
	topology, err := FlatInstanceTopology(plan, request.Instances)
	if err != nil {
		return InstanceTopology{}, nil, err
	}
	if len(request.Configurations) != len(topology.Instances()) {
		return InstanceTopology{}, nil, pluginError("activation_binding_set_invalid")
	}
	for _, input := range request.Configurations {
		id, ok := request.Instances[input.Pin.PackageID]
		if !ok {
			return InstanceTopology{}, nil, pluginError("activation_configuration_missing")
		}
		if _, exists := inputs[id]; exists {
			return InstanceTopology{}, nil, pluginError("activation_configuration_duplicate")
		}
		inputs[id] = InstanceConfigurationInput{InstanceID: id, Pin: input.Pin, Resources: input.Resources, Raw: input.Raw}
	}
	return topology, inputs, nil
}

func equalTopologyEdges(a, b InstanceTopology, id string) bool {
	ap, aok := a.Parent(id)
	bp, bok := b.Parent(id)
	if ap != bp || aok != bok {
		return false
	}
	ac, bc := a.Children(id), b.Children(id)
	ad, bd := a.Dependencies(id), b.Dependencies(id)
	if len(ac) != len(bc) || len(ad) != len(bd) {
		return false
	}
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	for i := range ad {
		if ad[i] != bd[i] {
			return false
		}
	}
	return true
}
func topologyRoots(topology InstanceTopology) map[string]bool {
	roots := map[string]bool{}
	for _, id := range topology.Roots() {
		roots[id] = true
	}
	return roots
}
func bindingsForSet(topology InstanceTopology, instances map[string]*managedInstance) []ContributionBinding {
	var bindings []ContributionBinding
	for _, id := range topology.OwnershipOrder() {
		bindings = append(bindings, bindingsFor(instances[id])...)
	}
	return bindings
}

// Activate validates the complete requested set before starting any addition.
// Running pins, configuration bytes, ownership and placement are retained exactly.
// ReleaseRoot is the separate owner action for ending a root retention claim.
func (m *Manager) Activate(ctx context.Context, request ActivationRequest) (ManagerSnapshot, error) {
	if err := m.acquire(ctx, false); err != nil {
		return m.Snapshot(), err
	}
	defer m.release()
	m.mu.RLock()
	blocked := len(m.retained) != 0
	m.mu.RUnlock()
	if blocked {
		return m.Snapshot(), pluginError("plugin_cleanup_incomplete")
	}
	work, cancel := context.WithTimeout(ctx, m.options.ActivationTimeout)
	stopParent := context.AfterFunc(m.ctx, cancel)
	defer func() { stopParent(); cancel() }()
	topology, inputs, err := activationTopology(request)
	if err != nil {
		return m.Snapshot(), err
	}
	roots := topologyRoots(topology)
	proposed := map[string]*managedInstance{}
	additions := map[string]bool{}
	for _, spec := range topology.Instances() {
		if work.Err() != nil {
			return m.Snapshot(), managerFailure(work.Err(), "plugin_operation_canceled")
		}
		pkg, _ := topology.Package(spec.InstanceID)
		if err = activationSupportForDriver(m.driver, pkg, spec.InstallationMode, m.options.Platform); err != nil {
			return m.Snapshot(), err
		}
		input, ok := inputs[spec.InstanceID]
		if !ok || input.Pin != spec.Pin {
			return m.Snapshot(), pluginError("activation_configuration_missing")
		}
		configuration, configErr := PrepareConfiguration(pkg, input.Resources, input.Raw)
		if configErr != nil {
			return m.Snapshot(), configErr
		}
		m.mu.RLock()
		previous := m.active[spec.InstanceID]
		if previous != nil {
			unchanged := previous.spec == spec && previous.configuration.Checksum() == configuration.Checksum() && equalTopologyEdges(m.topology, topology, spec.InstanceID) && m.roots[spec.InstanceID] == roots[spec.InstanceID]
			ready := m.readyLocked(previous, map[string]bool{})
			m.mu.RUnlock()
			if !unchanged {
				return m.Snapshot(), pluginError("plugin_upgrade_required")
			}
			if !ready {
				return m.Snapshot(), pluginError("active_plugin_unavailable")
			}
			proposed[spec.InstanceID] = previous
		} else {
			m.mu.RUnlock()
			if m.generations[spec.InstanceID] >= maxGeneration {
				return m.Snapshot(), pluginError("plugin_generation_exhausted")
			}
			proposed[spec.InstanceID] = &managedInstance{pkg: pkg, configuration: configuration, spec: spec,
				owner: OwnerReference{Pin: spec.Pin, InstanceID: spec.InstanceID, Epoch: m.epoch, Generation: m.generations[spec.InstanceID] + 1}, state: "validated"}
			additions[spec.InstanceID] = true
		}
	}
	m.mu.RLock()
	for id := range m.active {
		if proposed[id] == nil {
			m.mu.RUnlock()
			return m.Snapshot(), pluginError("plugin_upgrade_required")
		}
	}
	m.mu.RUnlock()
	registry, err := BuildInstanceRegistry(topology, request.Contracts, bindingsForSet(topology, proposed))
	if err != nil {
		return m.Snapshot(), err
	}
	if request.Topology != nil {
		if preflight, ok := m.driver.(DriverTopologyPreflight); ok {
			err = preflight.PreflightInstances(work, topology)
		}
	} else if preflight, ok := m.driver.(DriverPreflight); ok {
		err = preflight.Preflight(work, topology.Plan())
	}
	if err != nil {
		return m.Snapshot(), managerFailure(err, "plugin_driver_preflight_failed")
	}
	if work.Err() != nil {
		return m.Snapshot(), managerFailure(work.Err(), "plugin_operation_canceled")
	}
	for id := range additions {
		m.generations[id] = proposed[id].owner.Generation
	}
	started, err := m.startSet(work, topology, proposed, additions)
	if err == nil {
		m.mu.Lock()
		if m.closing || m.ctx.Err() != nil || work.Err() != nil {
			err = pluginError("plugin_operation_canceled")
		}
		for _, instance := range proposed {
			if !readyIn(proposed, topology, instance, map[string]bool{}) {
				err = pluginError("plugin_not_ready")
				break
			}
		}
		if err == nil {
			m.active, m.topology, m.plan, m.registry, m.roots = proposed, topology, topology.Plan(), registry, roots
			m.contracts = append([]ContractBinding(nil), request.Contracts...)
			m.order = topology.OwnershipOrder()
			m.revision++
			m.code = ""
		}
		m.mu.Unlock()
	}
	if err != nil {
		if m.cleanup(started) != nil {
			err = pluginError("plugin_cleanup_incomplete")
		}
		m.mu.Lock()
		m.code = failureCode(err, "plugin_activation_failed")
		m.mu.Unlock()
		return m.Snapshot(), err
	}
	for id := range additions {
		m.watch(proposed[id])
	}
	return m.Snapshot(), nil
}

func captureProcess(instance *managedInstance, process OwnedInstance) error {
	instance.process = process
	if process == nil {
		return pluginError("plugin_process_owner_invalid")
	}
	instance.done = process.Done()
	instance.lifetime = instance.done
	if lifetime, ok := process.(InstanceLifetime); ok {
		instance.lifetime = lifetime.LifetimeDone()
	}
	if instance.done == nil || instance.lifetime == nil {
		return pluginError("plugin_process_owner_invalid")
	}
	return nil
}
func parentReference(owner OwnerReference) *OwnerReference { copy := owner; return &copy }

// Each ownership group starts its parent processes before private children, then
// waits for readiness in dependency order. A parent's startup deadline includes
// this child startup work; no extra deadline is granted to the group.
func (m *Manager) startSet(ctx context.Context, topology InstanceTopology, instances map[string]*managedInstance, selected map[string]bool) ([]*managedInstance, error) {
	var started []*managedInstance
	for _, group := range topology.GroupOrder() {
		contexts := map[string]context.Context{}
		var cancels []context.CancelFunc
		stopContexts := func() {
			for _, cancel := range cancels {
				cancel()
			}
		}
		var failure error
		for _, id := range topology.StartOrder(group) {
			if !selected[id] {
				continue
			}
			instance := instances[id]
			startParent := ctx
			if ctx.Err() != nil {
				failure = ctx.Err()
				break
			}
			if parentID, private := topology.Parent(id); private {
				parent := instances[parentID]
				if !lifetimeIn(instances, parent, map[string]bool{}) {
					failure = pluginError("plugin_parent_unavailable")
					break
				}
				instance.parent, instance.parentLifetime = parentReference(parent.owner), parent.lifetime
				if parentContext := contexts[parentID]; parentContext != nil {
					startParent = parentContext
				}
			}
			instance.state = "starting"
			start, stop := context.WithTimeout(startParent, time.Duration(instance.pkg.Manifest().Lifecycle.StartDeadlineMS)*time.Millisecond)
			contexts[id] = start
			cancels = append(cancels, stop)
			process, err := m.driver.Start(start, startRequest(instance))
			ownerErr := captureProcess(instance, process)
			if process != nil {
				started = append(started, instance)
			}
			if err == nil {
				err = ownerErr
			}
			if err == nil {
				err = start.Err()
			}
			if err != nil {
				failure = err
				break
			}
		}
		if failure == nil {
			for _, id := range topology.ReadyOrder(group) {
				if !selected[id] {
					continue
				}
				instance, start := instances[id], contexts[id]
				failure = instance.process.WaitReady(start)
				if failure == nil {
					failure = start.Err()
				}
				if failure == nil && (!instanceAvailable(instance.process, instance.done) || !lifetimeIn(instances, instance, map[string]bool{})) {
					failure = pluginError("plugin_not_ready")
				}
				if failure != nil {
					break
				}
				instance.state = "ready"
			}
		}
		stopContexts()
		if failure != nil {
			return started, managerFailure(failure, "plugin_start_failed")
		}
	}
	return started, nil
}

func bindingsFor(instance *managedInstance) []ContributionBinding {
	var bindings []ContributionBinding
	for _, c := range instance.pkg.Manifest().Contributions {
		bindings = append(bindings, ContributionBinding{Pin: instance.owner.Pin, Kind: c.Kind, ID: c.ID,
			ContractRef: c.ContractRef, InstanceID: instance.owner.InstanceID, Epoch: instance.owner.Epoch, Generation: instance.owner.Generation})
	}
	return bindings
}
func startRequest(instance *managedInstance) StartRequest {
	return StartRequest{Package: instance.pkg, Configuration: instance.configuration, Owner: instance.owner, Contributions: bindingsFor(instance), Instance: instance.spec, Parent: copyParent(instance.parent), ParentLifetime: instance.parentLifetime}
}

// cleanup uses a fresh bounded cleanup context even after startup cancellation.
// Every started owner is visited in reverse order, including post-start failures.
func (m *Manager) cleanup(instances []*managedInstance) error {
	ctx, cancel := context.WithTimeout(context.Background(), m.options.CleanupTimeout)
	defer cancel()
	var failure error
	for i := len(instances) - 1; i >= 0; i-- {
		instance := instances[i]
		if instance.process == nil {
			continue
		}
		m.mu.RLock()
		alreadyRetained := false
		for _, retained := range m.retained {
			if retained.owner == instance.owner {
				alreadyRetained = true
				break
			}
		}
		m.mu.RUnlock()
		if alreadyRetained {
			failure = pluginError("plugin_cleanup_incomplete")
			continue
		}
		err := instance.process.Stop(ctx)
		if err == nil && !completed(instance.done) {
			err = pluginError("plugin_cleanup_incomplete")
		}
		if err != nil {
			m.mu.Lock()
			m.retained = append(m.retained, retainedInstance{process: instance.process, done: instance.done, owner: instance.owner, cause: err})
			m.code = "plugin_cleanup_incomplete"
			if active := m.active[instance.owner.InstanceID]; active != nil && active.owner == instance.owner {
				active.state, active.code = "failed", "plugin_cleanup_incomplete"
			}
			m.mu.Unlock()
			failure = pluginError("plugin_cleanup_incomplete")
		}
	}
	if failure != nil {
		m.mu.Lock()
		for _, instance := range instances {
			if root := m.active[instance.recoveryRoot]; root != nil && root.code != "plugin_cleanup_incomplete" {
				root.code = "plugin_cleanup_pending"
			}
		}
		m.mu.Unlock()
	}
	return failure
}

func copyParent(parent *OwnerReference) *OwnerReference {
	if parent == nil {
		return nil
	}
	return parentReference(*parent)
}
func ownLifetimeAlive(instance *managedInstance) bool {
	if instance == nil || instance.process == nil || instance.done == nil || instance.lifetime == nil || completed(instance.done) || completed(instance.lifetime) {
		return false
	}
	if instance.state != "starting" && instance.state != "ready" {
		return false
	}
	// Available may mean ready, so it cannot gate a parent whose required child
	// is still starting. Its early lifetime channel remains authoritative here.
	return instance.state == "starting" || instanceAvailable(instance.process, instance.done)
}
func lifetimeIn(instances map[string]*managedInstance, instance *managedInstance, visiting map[string]bool) bool {
	if !ownLifetimeAlive(instance) {
		return false
	}
	id := instance.owner.InstanceID
	if visiting[id] {
		return false
	}
	visiting[id] = true
	defer delete(visiting, id)
	if instance.parent == nil {
		return instance.spec.InstallationMode == "independent"
	}
	parent := instances[instance.parent.InstanceID]
	return parent != nil && parent.owner == *instance.parent && parent.lifetime == instance.parentLifetime && !completed(instance.parentLifetime) && lifetimeIn(instances, parent, visiting)
}
func requiredTargets(topology InstanceTopology, instance *managedInstance) []string {
	var targets []string
	manifest := instance.pkg.Manifest()
	for _, binding := range topology.Dependencies(instance.owner.InstanceID) {
		target, _ := topology.Instance(binding.DependencyID)
		for _, declaration := range manifest.Dependencies {
			if declaration.PackageID == target.Pin.PackageID && !declaration.Optional {
				targets = append(targets, binding.DependencyID)
				break
			}
		}
	}
	for _, binding := range topology.Children(instance.owner.InstanceID) {
		target, _ := topology.Instance(binding.ChildID)
		for _, declaration := range manifest.Children {
			if declaration.PackageID == target.Pin.PackageID && declaration.Required {
				targets = append(targets, binding.ChildID)
				break
			}
		}
	}
	return targets
}
func readyIn(instances map[string]*managedInstance, topology InstanceTopology, instance *managedInstance, visiting map[string]bool) bool {
	if instance == nil || instance.state != "ready" || !instanceAvailable(instance.process, instance.done) || !lifetimeIn(instances, instance, map[string]bool{}) {
		return false
	}
	id := instance.owner.InstanceID
	if visiting[id] {
		return false
	}
	visiting[id] = true
	defer delete(visiting, id)
	for _, target := range requiredTargets(topology, instance) {
		if !readyIn(instances, topology, instances[target], visiting) {
			return false
		}
	}
	return true
}
func (m *Manager) readyLocked(instance *managedInstance, visiting map[string]bool) bool {
	return readyIn(m.active, m.topology, instance, visiting)
}
func (m *Manager) watch(instance *managedInstance) {
	owner, done, lifetime := instance.owner, instance.done, instance.lifetime
	m.workers.Add(1)
	go func() {
		defer m.workers.Done()
		select {
		case <-m.ctx.Done():
			return
		case <-done:
		case <-lifetime:
		}
		select {
		case <-m.ctx.Done():
		case m.events <- instanceExit{owner: owner}:
		}
	}()
}

// subtreeLocked follows private ownership only. References to independent
// instances never turn their borrowers into process owners.
func (m *Manager) subtreeLocked(root string) []*managedInstance {
	selected := map[string]bool{root: true}
	var instances []*managedInstance
	for _, id := range m.order {
		if parent, ok := m.topology.Parent(id); ok && selected[parent] {
			selected[id] = true
		}
		if selected[id] {
			instances = append(instances, m.active[id])
		}
	}
	return instances
}
func (m *Manager) observeExits() {
	defer m.workers.Done()
	for {
		select {
		case <-m.ctx.Done():
			return
		case event := <-m.events:
			if m.acquire(m.ctx, false) != nil {
				return
			}
			m.mu.Lock()
			instance := m.active[event.owner.InstanceID]
			var affected []*managedInstance
			if instance != nil && instance.owner == event.owner && instance.state == "ready" && !ownLifetimeAlive(instance) {
				// A child's signal can arrive before the failed parent's process
				// wait. Recover the oldest failed private ancestor just once.
				for parentID, ok := m.topology.Parent(instance.owner.InstanceID); ok; parentID, ok = m.topology.Parent(parentID) {
					parent := m.active[parentID]
					if !ownLifetimeAlive(parent) {
						instance = parent
					}
				}
				affected = m.subtreeLocked(instance.owner.InstanceID)
				for _, child := range affected {
					child.state, child.code, child.recoveryRoot = "failed", "plugin_parent_unavailable", instance.owner.InstanceID
				}
				instance.code = failureCode(instance.process.ExitError(), "plugin_process_exited")
			}
			m.mu.Unlock()
			if len(affected) != 0 {
				if m.cleanup(affected) == nil {
					m.restart(instance)
				}
				m.resumeRestarts()
			}
			m.release()
		}
	}
}

func cloneInstances(instances map[string]*managedInstance) map[string]*managedInstance {
	out := make(map[string]*managedInstance, len(instances))
	for id, instance := range instances {
		out[id] = instance
	}
	return out
}
func (m *Manager) externalDependenciesReadyLocked(subtree []*managedInstance) bool {
	selected := map[string]bool{}
	for _, instance := range subtree {
		selected[instance.owner.InstanceID] = true
	}
	for _, instance := range subtree {
		if parent, ok := m.topology.Parent(instance.owner.InstanceID); ok && !selected[parent] && !lifetimeIn(m.active, m.active[parent], map[string]bool{}) {
			return false
		}
		for _, target := range requiredTargets(m.topology, instance) {
			if !selected[target] && !m.readyLocked(m.active[target], map[string]bool{}) {
				return false
			}
		}
	}
	return true
}

// A recovery spends the failed owner's restart budget. Recreating its private
// subtree advances every generation, but does not spend each child's separate
// unexpected-exit budget. Original owners must join before any replacement starts.
func (m *Manager) restart(instance *managedInstance) {
	work, cancel := context.WithTimeout(m.ctx, m.options.ActivationTimeout)
	defer cancel()
	rootID := instance.owner.InstanceID
	for {
		m.mu.Lock()
		instance = m.active[rootID]
		if instance == nil || m.closing || work.Err() != nil {
			m.mu.Unlock()
			return
		}
		if len(m.retained) != 0 {
			if instance.code != "plugin_cleanup_incomplete" {
				instance.code = "plugin_cleanup_pending"
			}
			m.mu.Unlock()
			return
		}
		subtree := m.subtreeLocked(rootID)
		if !m.externalDependenciesReadyLocked(subtree) {
			instance.code = "plugin_dependency_unavailable"
			m.mu.Unlock()
			return
		}
		if instance.restarts >= instance.pkg.Manifest().Lifecycle.RestartLimit {
			instance.code = "plugin_restart_exhausted"
			m.mu.Unlock()
			return
		}
		for _, child := range subtree {
			if m.generations[child.owner.InstanceID] >= maxGeneration {
				instance.code = "plugin_generation_exhausted"
				m.mu.Unlock()
				return
			}
		}
		proposed := cloneInstances(m.active)
		selected := map[string]bool{}
		for _, old := range subtree {
			id := old.owner.InstanceID
			m.generations[id]++
			next := &managedInstance{pkg: old.pkg, configuration: old.configuration, spec: old.spec, owner: old.owner, state: "validated", restarts: old.restarts, recoveryRoot: rootID}
			next.owner.Generation = m.generations[id]
			if id == rootID {
				next.restarts++
			}
			proposed[id], selected[id] = next, true
		}
		topology := m.topology
		m.mu.Unlock()
		started, err := m.startSet(work, topology, proposed, selected)
		var registry Registry
		if err == nil {
			registry, err = BuildInstanceRegistry(topology, m.contracts, bindingsForSet(topology, proposed))
		}
		m.mu.Lock()
		if err == nil {
			if m.closing || work.Err() != nil {
				err = pluginError("plugin_operation_canceled")
			}
			for id := range selected {
				if !readyIn(proposed, topology, proposed[id], map[string]bool{}) {
					err = pluginError("plugin_not_ready")
					break
				}
			}
		}
		for id := range selected {
			current := proposed[id]
			if err == nil {
				current.recoveryRoot = ""
			} else {
				current.state, current.code = "failed", "plugin_parent_unavailable"
			}
			m.active[id] = current
		}
		instance = m.active[rootID]
		if err == nil {
			m.registry = registry
			m.revision++
		} else {
			instance.code = failureCode(err, "plugin_start_failed")
		}
		m.mu.Unlock()
		if err == nil {
			for id := range selected {
				m.watch(proposed[id])
			}
			return
		}
		if m.cleanup(started) != nil {
			return
		}
	}
}
func (m *Manager) resumeRestarts() {
	for _, id := range m.topology.ReadinessOrder() {
		m.mu.RLock()
		instance := m.active[id]
		eligible := instance != nil && instance.state == "failed" && instance.recoveryRoot == id && (instance.code == "plugin_dependency_unavailable" || instance.code == "plugin_cleanup_incomplete" || instance.code == "plugin_cleanup_pending")
		m.mu.RUnlock()
		if eligible {
			m.restart(instance)
		}
	}
}

// retainedTopology removes only nodes no longer reachable from an explicit root.
// Present optional references retain their targets just like required references.
func retainedTopology(topology InstanceTopology, roots map[string]bool) (InstanceTopology, error) {
	if len(roots) == 0 {
		return InstanceTopology{}, nil
	}
	reached := map[string]bool{}
	var visit func(string)
	visit = func(id string) {
		if reached[id] {
			return
		}
		reached[id] = true
		for _, child := range topology.Children(id) {
			visit(child.ChildID)
		}
		for _, dependency := range topology.Dependencies(id) {
			visit(dependency.DependencyID)
		}
	}
	for id := range roots {
		visit(id)
	}
	input := InstanceTopologyInput{}
	retainedPins := map[PackagePin]bool{}
	for _, spec := range topology.Instances() {
		if !reached[spec.InstanceID] {
			continue
		}
		input.Instances = append(input.Instances, spec)
		retainedPins[spec.Pin] = true
		if roots[spec.InstanceID] {
			input.Roots = append(input.Roots, spec.InstanceID)
		}
		input.Children = append(input.Children, topology.Children(spec.InstanceID)...)
		input.Dependencies = append(input.Dependencies, topology.Dependencies(spec.InstanceID)...)
	}
	var selected []PackagePin
	var catalog []AdmittedPackage
	for _, pkg := range topology.Plan().Packages() {
		if retainedPins[pkg.Pin()] {
			selected = append(selected, pkg.Pin())
			catalog = append(catalog, pkg)
		}
	}
	return ResolveInstanceTopology(catalog, selected, input)
}

// ReleaseRoot is an explicit local owner operation, not a business-work drain or
// an upgrade. Its exact reference prevents a delayed command removing a replacement.
// Private descendants stop first; independently retained or shared targets remain.
func (m *Manager) ReleaseRoot(ctx context.Context, expected OwnerReference) (ManagerSnapshot, error) {
	if err := m.acquire(ctx, false); err != nil {
		return m.Snapshot(), err
	}
	defer m.release()
	m.mu.RLock()
	instance := m.active[expected.InstanceID]
	if instance == nil || instance.owner != expected || expected.Epoch != m.epoch {
		m.mu.RUnlock()
		return m.Snapshot(), pluginError("plugin_owner_stale")
	}
	if !m.roots[expected.InstanceID] {
		m.mu.RUnlock()
		return m.Snapshot(), pluginError("plugin_root_not_retained")
	}
	if len(m.retained) != 0 {
		m.mu.RUnlock()
		return m.Snapshot(), pluginError("plugin_cleanup_incomplete")
	}
	roots := map[string]bool{}
	for id := range m.roots {
		if id != expected.InstanceID {
			roots[id] = true
		}
	}
	topology := m.topology
	m.mu.RUnlock()
	next, err := retainedTopology(topology, roots)
	if err != nil {
		return m.Snapshot(), err
	}
	proposed := map[string]*managedInstance{}
	var removed []*managedInstance
	for _, id := range m.order {
		if _, keep := next.Instance(id); keep {
			proposed[id] = m.active[id]
		} else {
			removed = append(removed, m.active[id])
		}
	}
	var registry Registry
	if len(proposed) != 0 {
		registry, err = BuildInstanceRegistry(next, m.contracts, bindingsForSet(next, proposed))
	}
	if err != nil {
		return m.Snapshot(), err
	}
	if ctx.Err() != nil {
		return m.Snapshot(), managerFailure(ctx.Err(), "plugin_operation_canceled")
	}
	m.mu.Lock()
	if m.closing || m.ctx.Err() != nil {
		m.mu.Unlock()
		return m.Snapshot(), pluginError("manager_closed")
	}
	// Publish revocation before cleanup. An uncertain stopped owner is retained
	// for joining, never put back into the active authority set.
	m.active, m.topology, m.plan, m.registry, m.roots = proposed, next, next.Plan(), registry, roots
	m.order = next.OwnershipOrder()
	m.revision++
	m.code = ""
	m.mu.Unlock()
	err = m.cleanup(removed)
	return m.Snapshot(), err
}

func (m *Manager) Resolve(kind, id string) (RegisteredContribution, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closing || m.ctx.Err() != nil {
		return RegisteredContribution{}, pluginError("manager_closed")
	}
	entry, err := m.registry.Resolve(kind, id)
	if err != nil {
		return RegisteredContribution{}, err
	}
	if !m.ownerActiveLocked(entry.Owner) {
		return RegisteredContribution{}, pluginError("plugin_owner_unavailable")
	}
	return entry, nil
}

// ResolveFor establishes declared instance visibility and current lifecycle
// ownership. It does not manufacture the operation grants owned by later work.
func (m *Manager) ResolveFor(consumer OwnerReference, targetInstanceID, kind, id string) (RegisteredContribution, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.ownerActiveLocked(consumer) {
		return RegisteredContribution{}, pluginError("plugin_owner_stale")
	}
	entry, err := m.registry.ResolveFor(consumer.InstanceID, targetInstanceID, kind, id)
	if err != nil {
		return RegisteredContribution{}, err
	}
	if !m.ownerActiveLocked(entry.Owner) {
		return RegisteredContribution{}, pluginError("plugin_owner_unavailable")
	}
	return entry, nil
}
func (m *Manager) ownerActiveLocked(owner OwnerReference) bool {
	instance := m.active[owner.InstanceID]
	return !m.closing && m.ctx.Err() == nil && owner.Epoch == m.epoch && instance != nil && instance.owner == owner && m.readyLocked(instance, map[string]bool{})
}
func (m *Manager) CheckActive(owner OwnerReference) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.ownerActiveLocked(owner) {
		return pluginError("plugin_owner_stale")
	}
	return nil
}

func (m *Manager) Snapshot() ManagerSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := ManagerSnapshot{Epoch: m.epoch, Revision: m.revision, Closing: m.closing, Closed: m.closed,
		Instances: []InstanceSnapshot{}, OptionalUnavailable: m.plan.OptionalUnavailable(), InstanceUnavailable: m.topology.OptionalUnavailable(), RetainedCleanup: len(m.retained), Code: m.code}
	for _, id := range m.order {
		instance := m.active[id]
		state, code := instance.state, instance.code
		if state == "ready" && !m.readyLocked(instance, map[string]bool{}) {
			state, code = "degraded", "plugin_dependency_or_process_unavailable"
		}
		out.Instances = append(out.Instances, InstanceSnapshot{Owner: instance.owner, ConfigurationChecksum: instance.configuration.Checksum(), State: state, Code: code, RestartAttempts: instance.restarts,
			Instance: instance.spec, Parent: copyParent(instance.parent), RootRetained: m.roots[id], Consumers: m.topology.Consumers(id)})
	}
	return out
}

// RetryCleanup rejoins only retained original owners. It never adopts a PID or
// treats a later clean startup as proof about an earlier cleanup failure.
func (m *Manager) RetryCleanup(ctx context.Context) error {
	if err := m.acquire(ctx, true); err != nil {
		return err
	}
	defer m.release()
	cleanup, cancel := context.WithTimeout(ctx, m.options.CleanupTimeout)
	defer cancel()
	m.mu.Lock()
	retained := m.retained
	m.retained = nil
	m.mu.Unlock()
	for _, item := range retained {
		err := item.process.Stop(cleanup)
		if err == nil && !completed(item.done) {
			err = pluginError("plugin_cleanup_incomplete")
		}
		if err != nil {
			item.latest = err
			m.mu.Lock()
			m.retained = append(m.retained, item)
			m.mu.Unlock()
		}
	}
	m.mu.Lock()
	remaining, closing := len(m.retained), m.closing
	if remaining == 0 {
		m.code = ""
		if closing && completed(m.closeAttemptDone) {
			for _, instance := range m.active {
				instance.state, instance.code = "stopped", ""
			}
			m.closed = true
			m.doneOnce.Do(func() { close(m.done) })
		}
	}
	m.mu.Unlock()
	if remaining != 0 {
		return pluginError("plugin_cleanup_incomplete")
	}
	if !closing {
		m.resumeRestarts()
	}
	return nil
}

func (m *Manager) closeOnCancellation() {
	<-m.ctx.Done()
	m.mu.Lock()
	m.closing = true
	m.mu.Unlock()
	// An in-flight activation observes m.ctx and retains its own cleanup until it
	// releases this token. Do not abandon that owner on a separate timer.
	<-m.operation
	defer m.release()
	m.mu.RLock()
	var instances []*managedInstance
	retainedOwners := map[OwnerReference]bool{}
	for _, item := range m.retained {
		retainedOwners[item.owner] = true
	}
	for _, id := range m.order {
		if !retainedOwners[m.active[id].owner] {
			instances = append(instances, m.active[id])
		}
	}
	m.mu.RUnlock()
	_ = m.cleanup(instances)
	m.workers.Wait()
	m.mu.Lock()
	for _, instance := range m.active {
		instance.state, instance.code = "stopped", ""
	}
	if len(m.retained) != 0 {
		m.code = "plugin_cleanup_incomplete"
		for _, item := range m.retained {
			if instance := m.active[item.owner.InstanceID]; instance != nil && instance.owner == item.owner {
				instance.state, instance.code = "failed", "plugin_cleanup_incomplete"
			}
		}
	} else {
		m.closed = true
		m.doneOnce.Do(func() { close(m.done) })
	}
	m.mu.Unlock()
	close(m.closeAttemptDone)
}

// Close cancels admission, waits for the original cleanup attempt and reports
// retained uncertainty. Done closes only after every owned cleanup is proved.
func (m *Manager) Close(ctx context.Context) error {
	if ctx == nil {
		return pluginError("manager_context_invalid")
	}
	m.mu.Lock()
	m.closing = true
	m.mu.Unlock()
	m.cancel()
	select {
	case <-ctx.Done():
		return pluginError("plugin_cleanup_incomplete")
	case <-m.closeAttemptDone:
		m.mu.RLock()
		closed := m.closed
		m.mu.RUnlock()
		if !closed {
			return pluginError("plugin_cleanup_incomplete")
		}
		return nil
	}
}
func (m *Manager) Done() <-chan struct{} { return m.done }

func activationSupportForDriver(driver Driver, pkg AdmittedPackage, mode string, host Platform) error {
	native, ok := driver.(*NativeDriver)
	return validateActivationSupport(pkg, mode, host, ok && native.requiredCapabilityAdmission())
}
