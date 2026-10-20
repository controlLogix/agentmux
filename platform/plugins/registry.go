package plugins

import (
	"fmt"
	"io"
	"regexp"
	"sort"
)

// ContractBinding is an exact, owner-approved contribution contract. It is not a grant.
type ContractBinding struct {
	Kind        string `json:"kind"`
	ContractRef string `json:"contractRef"`
}

// ContributionBinding declares a contract-specific owner. The registry neither
// owns process handles nor assumes that different contribution kinds share an ABI.
type ContributionBinding struct {
	Pin         PackagePin `json:"pin"`
	Kind        string     `json:"kind"`
	ID          string     `json:"id"`
	ContractRef string     `json:"contractRef"`
	InstanceID  string     `json:"instanceId"`
	Epoch       string     `json:"epoch"`
	Generation  uint64     `json:"generation"`
}
type OwnerReference struct {
	Pin        PackagePin `json:"pin"`
	InstanceID string     `json:"instanceId"`
	Epoch      string     `json:"epoch"`
	Generation uint64     `json:"generation"`
}
type RegisteredContribution struct {
	Kind, ID, ContractRef string
	Owner                 OwnerReference
}

func (RegisteredContribution) String() string   { return "[registered plugin contribution]" }
func (RegisteredContribution) GoString() string { return "[registered plugin contribution]" }
func (RegisteredContribution) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[registered plugin contribution]")
}
func (RegisteredContribution) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"registered-plugin-contribution"}`), nil
}

// Registry is an immutable candidate snapshot. Resolving here does not establish
// current authority: the manager must compare the owner with its active generation
// at dispatch. A failed build never changes an existing snapshot.
type Registry struct {
	entries  map[contributionKey]RegisteredContribution
	pins     map[string]PackagePin
	scoped   map[instanceContributionKey]RegisteredContribution
	topology InstanceTopology
}
type contributionKey struct{ kind, id string }
type instanceContributionKey struct{ instance, kind, id string }

var registryIdentifier = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,95}$`)
var registryEpoch = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (Registry) String() string   { return "[plugin contribution registry]" }
func (Registry) GoString() string { return "[plugin contribution registry]" }
func (Registry) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[plugin contribution registry]")
}
func (Registry) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"plugin-contribution-registry"}`), nil
}

type contributionDeclaration struct {
	pin         PackagePin
	declaration Contribution
}

// ValidateContributionDeclarations performs read-only preflight without inventing
// an instance epoch or claiming that an owner is active.
func ValidateContributionDeclarations(plan Plan, contracts []ContractBinding) error {
	_, _, err := contributionDeclarations(plan, contracts)
	return err
}
func contributionDeclarations(plan Plan, contracts []ContractBinding) (map[string]PackagePin, map[contributionKey]contributionDeclaration, error) {
	if len(contracts) > 4096 {
		return nil, nil, pluginError("registry_limit")
	}
	known := map[contributionKey]bool{}
	for _, contract := range contracts {
		key := contributionKey{contract.Kind, contract.ContractRef}
		if !contributionKind(contract.Kind) || contract.ContractRef == "" || len(contract.ContractRef) > 4096 || known[key] {
			return nil, nil, pluginError("registry_contract_invalid")
		}
		known[key] = true
	}
	packages := plan.Packages()
	if len(packages) == 0 || len(packages) > 4096 {
		return nil, nil, pluginError("registry_package_invalid")
	}
	pins := map[string]PackagePin{}
	declared := map[contributionKey]contributionDeclaration{}
	for _, pkg := range packages {
		pin := pkg.Pin()
		manifest := pkg.Manifest()
		if pin.PackageID == "" || manifest.PackageID != pin.PackageID {
			return nil, nil, pluginError("registry_package_invalid")
		}
		if _, exists := pins[pin.PackageID]; exists {
			return nil, nil, pluginError("registry_package_duplicate")
		}
		pins[pin.PackageID] = pin
		for _, contribution := range manifest.Contributions {
			if len(declared) >= 4096 {
				return nil, nil, pluginError("registry_limit")
			}
			if !contributionKind(contribution.Kind) || !registryIdentifier.MatchString(contribution.ID) || protectedContribution(contribution.ID) {
				return nil, nil, pluginError("registry_contribution_unsupported")
			}
			if !known[contributionKey{contribution.Kind, contribution.ContractRef}] {
				return nil, nil, pluginError("registry_contract_unknown")
			}
			key := contributionKey{contribution.Kind, contribution.ID}
			if _, exists := declared[key]; exists {
				return nil, nil, pluginError("registry_handler_duplicate")
			}
			declared[key] = contributionDeclaration{pin, contribution}
		}
	}
	return pins, declared, nil
}

func BuildRegistry(plan Plan, contracts []ContractBinding, bindings []ContributionBinding) (Registry, error) {
	fail := func(code string) (Registry, error) { return Registry{}, pluginError(code) }
	if len(contracts) > 4096 || len(bindings) > 4096 {
		return fail("registry_limit")
	}
	pins, declared, err := contributionDeclarations(plan, contracts)
	if err != nil {
		return Registry{}, err
	}
	entries := map[contributionKey]RegisteredContribution{}
	instances := map[string]OwnerReference{}
	packageOwners := map[string]OwnerReference{}
	for _, binding := range bindings {
		key := contributionKey{binding.Kind, binding.ID}
		declaration, exists := declared[key]
		if !exists || binding.Pin != declaration.pin || binding.ContractRef != declaration.declaration.ContractRef || !registryIdentifier.MatchString(binding.InstanceID) || !registryEpoch.MatchString(binding.Epoch) || (binding.Generation == 0 || binding.Generation > 9007199254740991) {
			return fail("registry_binding_invalid")
		}
		if _, exists := entries[key]; exists {
			return fail("registry_handler_duplicate")
		}
		owner := OwnerReference{Pin: binding.Pin, InstanceID: binding.InstanceID, Epoch: binding.Epoch, Generation: binding.Generation}
		if previous, exists := instances[binding.InstanceID]; exists && previous != owner {
			return fail("registry_instance_duplicate")
		}
		if previous, exists := packageOwners[binding.Pin.PackageID]; exists && previous != owner {
			return fail("registry_owner_mismatch")
		}
		instances[binding.InstanceID] = owner
		packageOwners[binding.Pin.PackageID] = owner
		entries[key] = RegisteredContribution{binding.Kind, binding.ID, binding.ContractRef, owner}
	}
	if len(entries) != len(declared) {
		return fail("registry_binding_missing")
	}
	return Registry{entries: entries, pins: pins}, nil
}
func (r Registry) Entries() []RegisteredContribution {
	entries := make([]RegisteredContribution, 0, len(r.entries))
	if r.scoped != nil {
		for _, entry := range r.scoped {
			entries = append(entries, entry)
		}
	} else {
		for _, entry := range r.entries {
			entries = append(entries, entry)
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Kind != entries[j].Kind {
			return entries[i].Kind < entries[j].Kind
		}
		if entries[i].ID != entries[j].ID {
			return entries[i].ID < entries[j].ID
		}
		return entries[i].Owner.InstanceID < entries[j].Owner.InstanceID
	})
	return entries
}
func (r Registry) Resolve(kind, id string) (RegisteredContribution, error) {
	entry, ok := r.entries[contributionKey{kind, id}]
	if !ok {
		return RegisteredContribution{}, pluginError("registry_handler_unavailable")
	}
	return entry, nil
}
func (r Registry) ValidFor(plan Plan) bool {
	if r.entries == nil || r.pins == nil {
		return false
	}
	packages := plan.Packages()
	if len(packages) != len(r.pins) {
		return false
	}
	for _, pkg := range packages {
		if pin, ok := r.pins[pkg.Pin().PackageID]; !ok || pin != pkg.Pin() {
			return false
		}
	}
	return true
}
func contributionKind(kind string) bool {
	switch kind {
	case "tool", "cli", "mcp", "ag-ui", "decision-definition", "skill", "domain-service", "provider":
		return true
	}
	return false
}
func protectedContribution(id string) bool {
	switch id {
	case "boot", "kernel-lifecycle", "internal-communication", "exported-status":
		return true
	}
	return false
}

// ValidateInstanceContributionDeclarations checks each instance's declarations.
// Only independent instances export to the legacy global namespace.
func ValidateInstanceContributionDeclarations(t InstanceTopology, contracts []ContractBinding) error {
	_, _, err := instanceDeclarations(t, contracts)
	return err
}
func instanceDeclarations(t InstanceTopology, contracts []ContractBinding) (map[instanceContributionKey]contributionDeclaration, map[contributionKey]string, error) {
	if len(t.nodes) == 0 {
		return nil, nil, pluginError("registry_topology_invalid")
	}
	declared := map[instanceContributionKey]contributionDeclaration{}
	global := map[contributionKey]string{}
	for _, n := range t.Instances() {
		p, _ := t.Package(n.InstanceID)
		_, single, err := contributionDeclarations(Plan{packages: []AdmittedPackage{p}}, contracts)
		if err != nil {
			return nil, nil, err
		}
		for key, d := range single {
			if len(declared) >= 4096 {
				return nil, nil, pluginError("registry_limit")
			}
			declared[instanceContributionKey{n.InstanceID, key.kind, key.id}] = d
			if n.InstallationMode == "independent" {
				if _, ok := global[key]; ok {
					return nil, nil, pluginError("registry_handler_duplicate")
				}
				global[key] = n.InstanceID
			}
		}
	}
	return declared, global, nil
}
func BuildInstanceRegistry(t InstanceTopology, contracts []ContractBinding, bindings []ContributionBinding) (Registry, error) {
	if len(bindings) > 4096 {
		return Registry{}, pluginError("registry_limit")
	}
	declared, global, err := instanceDeclarations(t, contracts)
	if err != nil {
		return Registry{}, err
	}
	r := Registry{entries: map[contributionKey]RegisteredContribution{}, pins: map[string]PackagePin{}, scoped: map[instanceContributionKey]RegisteredContribution{}, topology: t}
	owners := map[string]OwnerReference{}
	for _, b := range bindings {
		key := instanceContributionKey{b.InstanceID, b.Kind, b.ID}
		d, ok := declared[key]
		if !ok || b.Pin != d.pin || b.ContractRef != d.declaration.ContractRef || !registryEpoch.MatchString(b.Epoch) || b.Generation == 0 || b.Generation > maxGeneration {
			return Registry{}, pluginError("registry_binding_invalid")
		}
		if _, ok := r.scoped[key]; ok {
			return Registry{}, pluginError("registry_handler_duplicate")
		}
		owner := OwnerReference{b.Pin, b.InstanceID, b.Epoch, b.Generation}
		if old, ok := owners[b.InstanceID]; ok && old != owner {
			return Registry{}, pluginError("registry_owner_mismatch")
		}
		owners[b.InstanceID] = owner
		entry := RegisteredContribution{b.Kind, b.ID, b.ContractRef, owner}
		r.scoped[key] = entry
		globalKey := contributionKey{b.Kind, b.ID}
		if global[globalKey] == b.InstanceID {
			r.entries[globalKey] = entry
		}
	}
	if len(r.scoped) != len(declared) {
		return Registry{}, pluginError("registry_binding_missing")
	}
	for _, p := range t.Plan().Packages() {
		r.pins[p.Pin().PackageID] = p.Pin()
	}
	return r, nil
}

// ResolveInstance selects an exact target without claiming caller visibility.
// Managers use ResolveFor at caller-facing boundaries and fence the returned owner.
func (r Registry) ResolveInstance(instanceID, kind, id string) (RegisteredContribution, error) {
	if r.scoped == nil {
		e, err := r.Resolve(kind, id)
		if err == nil && e.Owner.InstanceID == instanceID {
			return e, nil
		}
		return RegisteredContribution{}, pluginError("registry_handler_unavailable")
	}
	e, ok := r.scoped[instanceContributionKey{instanceID, kind, id}]
	if !ok {
		return RegisteredContribution{}, pluginError("registry_handler_unavailable")
	}
	return e, nil
}
func (r Registry) ResolveFor(requester, target, kind, id string) (RegisteredContribution, error) {
	if !r.topology.CanAccess(requester, target) {
		return RegisteredContribution{}, pluginError("registry_scope_unavailable")
	}
	return r.ResolveInstance(target, kind, id)
}
func (r Registry) ValidForTopology(t InstanceTopology) bool {
	if r.scoped == nil || !r.ValidFor(t.Plan()) || len(r.topology.nodes) != len(t.nodes) || len(r.topology.roots) != len(t.roots) {
		return false
	}
	for i, id := range t.roots {
		if r.topology.roots[i] != id {
			return false
		}
	}
	for id, n := range t.nodes {
		if r.topology.nodes[id] != n || len(r.topology.children[id]) != len(t.children[id]) || len(r.topology.dependencies[id]) != len(t.dependencies[id]) {
			return false
		}
		for i, e := range t.children[id] {
			if r.topology.children[id][i] != e {
				return false
			}
		}
		for i, e := range t.dependencies[id] {
			if r.topology.dependencies[id][i] != e {
				return false
			}
		}
	}
	return true
}
