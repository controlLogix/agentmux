package plugins

import (
	"fmt"
	"io"
	"sort"
)

// Placement is separate from installation mode and lifetime ownership. The first
// implementation admits only an explicitly selected process on this host.
type Placement struct {
	Kind string `json:"kind"`
}
type InstanceSpec struct {
	InstanceID       string     `json:"instanceId"`
	Pin              PackagePin `json:"pin"`
	InstallationMode string     `json:"installationMode"`
	Placement        Placement  `json:"placement"`
}
type ChildBinding struct {
	ParentID     string `json:"parentId"`
	ChildID      string `json:"childId"`
	Relationship string `json:"relationship"`
}
type DependencyBinding struct {
	ConsumerID   string `json:"consumerId"`
	DependencyID string `json:"dependencyId"`
}
type InstanceTopologyInput struct {
	Instances    []InstanceSpec      `json:"instances"`
	Roots        []string            `json:"roots"`
	Children     []ChildBinding      `json:"children"`
	Dependencies []DependencyBinding `json:"dependencies"`
}
type InstanceUnavailable struct {
	InstanceID   string `json:"instanceId"`
	PackageID    string `json:"packageId"`
	Relationship string `json:"relationship"`
	Reason       string `json:"reason"`
}

// InstanceTopology is an immutable owner-selected graph, not a capability grant.
// Its package closure does not imply lifetime ownership. Roots record independent
// retention claims; private parents and borrowed independent references are distinct.
type InstanceTopology struct {
	plan                 Plan
	nodes                map[string]InstanceSpec
	packages             map[string]AdmittedPackage
	roots                []string
	parents              map[string]string
	children             map[string][]ChildBinding
	dependencies         map[string][]DependencyBinding
	consumers            map[string][]string
	groups               map[string]string
	groupOrder           []string
	start, ready         map[string][]string
	ownership, readiness []string
	unavailable          []InstanceUnavailable
}

func (InstanceTopology) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[ordinary plugin instance topology]")
}
func (InstanceTopology) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"ordinary-plugin-instance-topology"}`), nil
}
func (t InstanceTopology) Plan() Plan { return t.plan }
func (t InstanceTopology) Instances() []InstanceSpec {
	out := make([]InstanceSpec, 0, len(t.nodes))
	for _, id := range sortedKeys(t.nodes) {
		out = append(out, t.nodes[id])
	}
	return out
}
func (t InstanceTopology) Instance(id string) (InstanceSpec, bool) {
	n, ok := t.nodes[id]
	return n, ok
}
func (t InstanceTopology) Package(id string) (AdmittedPackage, bool) {
	p, ok := t.packages[id]
	return p, ok
}
func (t InstanceTopology) Roots() []string                 { return append([]string(nil), t.roots...) }
func (t InstanceTopology) Parent(id string) (string, bool) { p, ok := t.parents[id]; return p, ok }
func (t InstanceTopology) Children(id string) []ChildBinding {
	return append([]ChildBinding(nil), t.children[id]...)
}
func (t InstanceTopology) Dependencies(id string) []DependencyBinding {
	return append([]DependencyBinding(nil), t.dependencies[id]...)
}
func (t InstanceTopology) Consumers(id string) []string {
	return append([]string(nil), t.consumers[id]...)
}
func (t InstanceTopology) GroupID(id string) string { return t.groups[id] }
func (t InstanceTopology) GroupOrder() []string     { return append([]string(nil), t.groupOrder...) }
func (t InstanceTopology) StartOrder(group string) []string {
	return append([]string(nil), t.start[group]...)
}
func (t InstanceTopology) ReadyOrder(group string) []string {
	return append([]string(nil), t.ready[group]...)
}
func (t InstanceTopology) OwnershipOrder() []string { return append([]string(nil), t.ownership...) }
func (t InstanceTopology) ReadinessOrder() []string { return append([]string(nil), t.readiness...) }
func (t InstanceTopology) OptionalUnavailable() []InstanceUnavailable {
	return append([]InstanceUnavailable(nil), t.unavailable...)
}

// CanAccess checks declared graph visibility only. Dispatch must additionally
// check current owner generations, ancestor liveness and operation authority.
func (t InstanceTopology) CanAccess(requester, target string) bool {
	if _, ok := t.nodes[requester]; !ok {
		return false
	}
	if _, ok := t.nodes[target]; !ok {
		return false
	}
	if requester == target {
		return true
	}
	for id := target; t.parents[id] != ""; {
		id = t.parents[id]
		if id == requester {
			return true
		}
	}
	for _, e := range t.children[requester] {
		if e.ChildID == target {
			return true
		}
	}
	for _, e := range t.dependencies[requester] {
		if e.DependencyID == target {
			return true
		}
	}
	return false
}
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// PlanInstances binds already admitted package pins to explicit runtime instances.
// It never chooses a version, creates an instance ID, or invents a missing edge.
func PlanInstances(plan Plan, input InstanceTopologyInput) (InstanceTopology, error) {
	fail := func(code string) (InstanceTopology, error) { return InstanceTopology{}, pluginError(code) }
	if len(input.Instances) == 0 || len(input.Instances) > 4096 || len(input.Roots) == 0 || len(input.Roots) > 4096 || len(input.Children) > 4096 || len(input.Dependencies) > 4096 {
		return fail("topology_limit")
	}
	t := InstanceTopology{plan: plan, nodes: map[string]InstanceSpec{}, packages: map[string]AdmittedPackage{}, parents: map[string]string{}, children: map[string][]ChildBinding{}, dependencies: map[string][]DependencyBinding{}, consumers: map[string][]string{}, groups: map[string]string{}, start: map[string][]string{}, ready: map[string][]string{}}
	catalog := map[PackagePin]AdmittedPackage{}
	for _, p := range plan.Packages() {
		catalog[p.Pin()] = p
	}
	if len(catalog) == 0 {
		return fail("topology_package_missing")
	}
	represented := map[PackagePin]bool{}
	for _, n := range input.Instances {
		p, ok := catalog[n.Pin]
		if !ok {
			return fail("topology_package_mismatch")
		}
		if !instanceIdentifier.MatchString(n.InstanceID) || t.nodes[n.InstanceID].InstanceID != "" {
			return fail("topology_instance_invalid")
		}
		if n.Placement.Kind != "local-process" || p.Manifest().Runtime.Kind != "process" {
			return fail("topology_placement_unsupported")
		}
		if n.InstallationMode != "independent" && n.InstallationMode != "private-child" {
			return fail("topology_mode_invalid")
		}
		supported := false
		for _, mode := range p.Manifest().InstallationModes {
			if mode == n.InstallationMode {
				supported = true
			}
		}
		if !supported {
			return fail("topology_mode_unsupported")
		}
		t.nodes[n.InstanceID] = n
		t.packages[n.InstanceID] = p
		represented[n.Pin] = true
	}
	if len(represented) != len(catalog) {
		return fail("topology_package_unbound")
	}
	roots := map[string]bool{}
	for _, id := range input.Roots {
		n, ok := t.nodes[id]
		if !ok || roots[id] || n.InstallationMode != "independent" {
			return fail("topology_root_invalid")
		}
		roots[id] = true
	}
	t.roots = sortedKeys(roots)
	childSlots := map[string]map[string]bool{}
	for _, e := range input.Children {
		parent, pok := t.packages[e.ParentID]
		child, cok := t.nodes[e.ChildID]
		if !pok || !cok || e.ParentID == e.ChildID {
			return fail("topology_child_invalid")
		}
		declared := false
		for _, d := range parent.Manifest().Children {
			if d.PackageID == child.Pin.PackageID && d.Relationship == e.Relationship {
				declared = true
			}
		}
		if !declared {
			return fail("topology_child_undeclared")
		}
		if childSlots[e.ParentID] == nil {
			childSlots[e.ParentID] = map[string]bool{}
		}
		if childSlots[e.ParentID][child.Pin.PackageID] {
			return fail("topology_child_ambiguous")
		}
		childSlots[e.ParentID][child.Pin.PackageID] = true
		switch e.Relationship {
		case "private":
			if child.InstallationMode != "private-child" || t.parents[e.ChildID] != "" || roots[e.ChildID] {
				return fail("topology_private_owner_invalid")
			}
			t.parents[e.ChildID] = e.ParentID
		case "independent-reference":
			if child.InstallationMode != "independent" {
				return fail("topology_reference_invalid")
			}
			t.consumers[e.ChildID] = append(t.consumers[e.ChildID], e.ParentID)
		default:
			return fail("topology_relationship_invalid")
		}
		t.children[e.ParentID] = append(t.children[e.ParentID], e)
	}
	for _, id := range sortedKeys(t.nodes) {
		if t.nodes[id].InstallationMode == "private-child" && t.parents[id] == "" {
			return fail("topology_private_orphan")
		}
		seen := map[string]bool{}
		cursor := id
		for t.parents[cursor] != "" {
			if seen[cursor] {
				return fail("topology_ownership_cycle")
			}
			seen[cursor] = true
			cursor = t.parents[cursor]
		}
		t.groups[id] = cursor
		for _, d := range t.packages[id].Manifest().Children {
			if !childSlots[id][d.PackageID] {
				if d.Required {
					return fail("topology_child_missing")
				}
				t.unavailable = append(t.unavailable, InstanceUnavailable{id, d.PackageID, d.Relationship, "optional_child_unbound"})
			}
		}
	}
	depSlots := map[string]map[string]bool{}
	for _, e := range input.Dependencies {
		consumer, cok := t.packages[e.ConsumerID]
		target, tok := t.nodes[e.DependencyID]
		if !cok || !tok || e.ConsumerID == e.DependencyID {
			return fail("topology_dependency_invalid")
		}
		declared := false
		for _, d := range consumer.Manifest().Dependencies {
			if d.PackageID == target.Pin.PackageID && compareVersion(target.Pin.Version, d.MinimumVersion) >= 0 && compareVersion(target.Pin.Version, d.ExclusiveMaximumVersion) < 0 {
				declared = true
			}
		}
		if !declared {
			return fail("topology_dependency_undeclared")
		}
		if target.InstallationMode == "private-child" && t.groups[e.ConsumerID] != t.groups[e.DependencyID] {
			return fail("topology_private_visibility")
		}
		if depSlots[e.ConsumerID] == nil {
			depSlots[e.ConsumerID] = map[string]bool{}
		}
		if depSlots[e.ConsumerID][target.Pin.PackageID] {
			return fail("topology_dependency_ambiguous")
		}
		depSlots[e.ConsumerID][target.Pin.PackageID] = true
		t.dependencies[e.ConsumerID] = append(t.dependencies[e.ConsumerID], e)
		if target.InstallationMode == "independent" {
			t.consumers[e.DependencyID] = append(t.consumers[e.DependencyID], e.ConsumerID)
		}
	}
	for _, id := range sortedKeys(t.nodes) {
		for _, d := range t.packages[id].Manifest().Dependencies {
			if !depSlots[id][d.PackageID] {
				if !d.Optional {
					return fail("topology_dependency_missing")
				}
				t.unavailable = append(t.unavailable, InstanceUnavailable{id, d.PackageID, "dependency", "optional_dependency_unbound"})
			}
		}
	}
	for id := range t.nodes {
		sort.Slice(t.children[id], func(i, j int) bool { return t.children[id][i].ChildID < t.children[id][j].ChildID })
		sort.Slice(t.dependencies[id], func(i, j int) bool { return t.dependencies[id][i].DependencyID < t.dependencies[id][j].DependencyID })
		sort.Strings(t.consumers[id])
		if len(t.consumers[id]) > 0 {
			unique := t.consumers[id][:1]
			for _, consumer := range t.consumers[id][1:] {
				if consumer != unique[len(unique)-1] {
					unique = append(unique, consumer)
				}
			}
			t.consumers[id] = unique
		}
	}
	// Reachability includes optional bound edges, but admission closure alone never
	// retains an instance. Every node must be reachable from an explicit root.
	reached := map[string]bool{}
	var reach func(string)
	reach = func(id string) {
		if reached[id] {
			return
		}
		reached[id] = true
		for _, e := range t.children[id] {
			reach(e.ChildID)
		}
		for _, e := range t.dependencies[id] {
			reach(e.DependencyID)
		}
	}
	for _, id := range t.roots {
		reach(id)
	}
	if len(reached) != len(t.nodes) {
		return fail("topology_instance_orphan")
	}
	readiness := map[string][]string{}
	groupDeps := map[string][]string{}
	for _, id := range sortedKeys(t.nodes) {
		for _, e := range t.children[id] {
			readiness[id] = append(readiness[id], e.ChildID)
		}
		for _, e := range t.dependencies[id] {
			readiness[id] = append(readiness[id], e.DependencyID)
		}
		for _, target := range readiness[id] {
			if t.groups[id] != t.groups[target] {
				groupDeps[t.groups[id]] = append(groupDeps[t.groups[id]], t.groups[target])
			}
		}
	}
	order, ok := topologyOrder(sortedKeys(t.nodes), readiness)
	if !ok {
		return fail("topology_readiness_cycle")
	}
	t.readiness = order
	groups := map[string]bool{}
	for _, group := range t.groups {
		groups[group] = true
	}
	t.groupOrder, ok = topologyOrder(sortedKeys(groups), groupDeps)
	if !ok {
		return fail("topology_group_cycle")
	}
	var walk func(string, string)
	walk = func(group, id string) {
		t.start[group] = append(t.start[group], id)
		for _, e := range t.children[id] {
			if e.Relationship == "private" {
				walk(group, e.ChildID)
			}
		}
	}
	for _, group := range t.groupOrder {
		walk(group, group)
		t.ownership = append(t.ownership, t.start[group]...)
	}
	for _, id := range order {
		group := t.groups[id]
		t.ready[group] = append(t.ready[group], id)
	}
	sort.Slice(t.unavailable, func(i, j int) bool {
		a, b := t.unavailable[i], t.unavailable[j]
		if a.InstanceID != b.InstanceID {
			return a.InstanceID < b.InstanceID
		}
		if a.Relationship != b.Relationship {
			return a.Relationship < b.Relationship
		}
		return a.PackageID < b.PackageID
	})
	return t, nil
}
func topologyOrder(ids []string, edges map[string][]string) ([]string, bool) {
	state := map[string]uint8{}
	var out []string
	var visit func(string) bool
	visit = func(id string) bool {
		if state[id] == 1 {
			return false
		}
		if state[id] == 2 {
			return true
		}
		state[id] = 1
		next := append([]string(nil), edges[id]...)
		sort.Strings(next)
		for _, target := range next {
			if !visit(target) {
				return false
			}
		}
		state[id] = 2
		out = append(out, id)
		return true
	}
	for _, id := range ids {
		if !visit(id) {
			return nil, false
		}
	}
	return out, true
}

// FlatInstanceTopology preserves the old one-instance-per-package activation.
// It does not infer bindings for newly declared children.
func FlatInstanceTopology(plan Plan, instances map[string]string) (InstanceTopology, error) {
	if len(instances) != len(plan.Packages()) {
		return InstanceTopology{}, pluginError("topology_binding_set_invalid")
	}
	input := InstanceTopologyInput{}
	versions := map[string]string{}
	for _, p := range plan.Packages() {
		versions[p.Pin().PackageID] = p.Pin().Version
	}
	for _, p := range plan.Packages() {
		if len(p.Manifest().Children) != 0 {
			return InstanceTopology{}, pluginError("topology_explicit_children_required")
		}
		id, ok := instances[p.Pin().PackageID]
		if !ok {
			return InstanceTopology{}, pluginError("topology_binding_set_invalid")
		}
		input.Instances = append(input.Instances, InstanceSpec{id, p.Pin(), "independent", Placement{"local-process"}})
		input.Roots = append(input.Roots, id)
		for _, d := range p.Manifest().Dependencies {
			if target, ok := instances[d.PackageID]; ok && compareVersion(versions[d.PackageID], d.MinimumVersion) >= 0 && compareVersion(versions[d.PackageID], d.ExclusiveMaximumVersion) < 0 {
				input.Dependencies = append(input.Dependencies, DependencyBinding{id, target})
			}
		}
	}
	return PlanInstances(plan, input)
}

// ResolveInstanceTopology resolves the package closure from explicit instance pins.
// These package roots are admission inputs only; input.Roots alone retains owners.
func ResolveInstanceTopology(catalog []AdmittedPackage, selected []PackagePin, input InstanceTopologyInput) (InstanceTopology, error) {
	if len(input.Instances) == 0 || len(input.Instances) > 4096 {
		return InstanceTopology{}, pluginError("topology_limit")
	}
	seen := map[PackagePin]bool{}
	var pins []PackagePin
	for _, n := range input.Instances {
		if !seen[n.Pin] {
			seen[n.Pin] = true
			pins = append(pins, n.Pin)
		}
	}
	plan, err := Resolve(catalog, pins, selected)
	if err != nil {
		return InstanceTopology{}, err
	}
	return PlanInstances(plan, input)
}
