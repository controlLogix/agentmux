package plugins

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func topologyFixture(t *testing.T) ([]AdmittedPackage, InstanceTopologyInput) {
	t.Helper()
	a, b, c, shared := fixtureManifest("alpha"), fixtureManifest("beta"), fixtureManifest("child"), fixtureManifest("shared")
	a.Children = []Child{{"child", "private", true}, {"shared", "independent-reference", true}}
	b.Children = append([]Child(nil), a.Children...)
	c.InstallationModes = []string{"private-child"}
	packages := []AdmittedPackage{fixturePackage(t, a, nil), fixturePackage(t, b, nil), fixturePackage(t, c, nil), fixturePackage(t, shared, nil)}
	input := InstanceTopologyInput{Roots: []string{"a", "b", "shared"}, Children: []ChildBinding{{"a", "ac", "private"}, {"b", "bc", "private"}, {"a", "shared", "independent-reference"}, {"b", "shared", "independent-reference"}}}
	for i, id := range []string{"a", "b", "ac", "bc", "shared"} {
		index := []int{0, 1, 2, 2, 3}[i]
		mode := "independent"
		if index == 2 {
			mode = "private-child"
		}
		input.Instances = append(input.Instances, InstanceSpec{id, packages[index].Pin(), mode, Placement{"local-process"}})
	}
	return packages, input
}
func TestInstanceTopologyPrivateCopiesSharedRetentionAndOrders(t *testing.T) {
	catalog, input := topologyFixture(t)
	topology, err := ResolveInstanceTopology(catalog, nil, input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(topology.GroupOrder(), []string{"shared", "a", "b"}) || !reflect.DeepEqual(topology.StartOrder("a"), []string{"a", "ac"}) || !reflect.DeepEqual(topology.ReadyOrder("a"), []string{"ac", "a"}) {
		t.Fatal("ownership/readiness orders conflated")
	}
	if !reflect.DeepEqual(topology.Consumers("shared"), []string{"a", "b"}) {
		t.Fatal("shared consumers lost")
	}
	if parent, ok := topology.Parent("ac"); !ok || parent != "a" {
		t.Fatal("private ownership lost")
	}
	if _, ok := topology.Parent("shared"); ok {
		t.Fatal("shared service borrowed a parent")
	}
	if topology.GroupID("ac") != "a" || topology.GroupID("bc") != "b" {
		t.Fatal("private instances conflated")
	}
	if !topology.CanAccess("a", "ac") || topology.CanAccess("b", "ac") || !topology.CanAccess("a", "shared") {
		t.Fatal("visibility widened")
	}
	p, _ := topology.Package("ac")
	p2, _ := topology.Package("bc")
	if p.Pin() != p2.Pin() {
		t.Fatal("same package identity changed")
	}
	input.Instances[0].Pin.ProvenanceChecksum = "changed"
	input.Children[0].ChildID = "changed"
	input.Roots[0] = "changed"
	nodes := topology.Instances()
	nodes[0].InstanceID = "changed"
	roots := topology.Roots()
	roots[0] = "changed"
	children := topology.Children("a")
	children[0].ChildID = "changed"
	order := topology.StartOrder("a")
	order[0] = "changed"
	if n, _ := topology.Instance("a"); n.InstanceID != "a" || topology.Roots()[0] != "a" || topology.StartOrder("a")[0] != "a" {
		t.Fatal("mutable topology")
	}
	encoded, _ := json.Marshal(topology)
	if strings.Contains(string(encoded), "original") || strings.Contains(string(encoded), p.Provenance().Path) {
		t.Fatal("source leak")
	}
	// Removing one consumer from a fresh candidate does not remove the separately
	// retained independent instance or silently promote admission roots to owners.
	_, input = topologyFixtureFromPackages(catalog)
	input.Roots = []string{"a", "shared"}
	input.Instances = append(input.Instances[:1], input.Instances[2:]...)
	input.Instances = append(input.Instances[:2], input.Instances[3:]...)
	input.Children = []ChildBinding{{"a", "ac", "private"}, {"a", "shared", "independent-reference"}}
	reduced, err := ResolveInstanceTopology(catalog, nil, input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reduced.Consumers("shared"), []string{"a"}) {
		t.Fatal("remaining consumer lost")
	}
}
func topologyFixtureFromPackages(catalog []AdmittedPackage) ([]AdmittedPackage, InstanceTopologyInput) {
	input := InstanceTopologyInput{Roots: []string{"a", "b", "shared"}, Children: []ChildBinding{{"a", "ac", "private"}, {"b", "bc", "private"}, {"a", "shared", "independent-reference"}, {"b", "shared", "independent-reference"}}}
	for i, id := range []string{"a", "b", "ac", "bc", "shared"} {
		index := []int{0, 1, 2, 2, 3}[i]
		mode := "independent"
		if index == 2 {
			mode = "private-child"
		}
		input.Instances = append(input.Instances, InstanceSpec{id, catalog[index].Pin(), mode, Placement{"local-process"}})
	}
	return catalog, input
}
func TestInstanceTopologyRefusesInvalidOwnershipBindings(t *testing.T) {
	catalog, base := topologyFixture(t)
	cases := []struct {
		name   string
		change func(*InstanceTopologyInput)
	}{
		{"duplicate-id", func(i *InstanceTopologyInput) { i.Instances[1].InstanceID = "a" }},
		{"pin", func(i *InstanceTopologyInput) { i.Instances[0].Pin.ProvenanceChecksum = "changed" }},
		{"placement", func(i *InstanceTopologyInput) { i.Instances[0].Placement.Kind = "remote-process" }},
		{"mode", func(i *InstanceTopologyInput) { i.Instances[2].InstallationMode = "independent" }},
		{"private-root", func(i *InstanceTopologyInput) { i.Roots = append(i.Roots, "ac") }},
		{"private-orphan", func(i *InstanceTopologyInput) { i.Children = i.Children[1:] }},
		{"multiple-parents", func(i *InstanceTopologyInput) { i.Children[1].ChildID = "ac" }},
		{"undeclared", func(i *InstanceTopologyInput) {
			i.Children = append(i.Children, ChildBinding{"shared", "ac", "private"})
		}},
		{"missing-required", func(i *InstanceTopologyInput) { i.Children = i.Children[:3] }},
		{"duplicate-slot", func(i *InstanceTopologyInput) { i.Children = append(i.Children, i.Children[0]) }},
		{"private-reference", func(i *InstanceTopologyInput) { i.Children[0].Relationship = "independent-reference" }},
		{"unretained", func(i *InstanceTopologyInput) { i.Roots = []string{"a", "shared"} }},
		{"unknown-root", func(i *InstanceTopologyInput) { i.Roots = append(i.Roots, "unknown") }},
		{"duplicate-root", func(i *InstanceTopologyInput) { i.Roots = append(i.Roots, "a") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(base)
			var input InstanceTopologyInput
			_ = json.Unmarshal(raw, &input)
			tc.change(&input)
			if _, err := ResolveInstanceTopology(catalog, nil, input); err == nil {
				t.Fatal("invalid topology accepted")
			}
		})
	}
}
func TestInstanceTopologyDependenciesOptionalAndCycles(t *testing.T) {
	a, b, c := fixtureManifest("alpha"), fixtureManifest("beta"), fixtureManifest("child")
	a.Children = []Child{{"child", "private", true}, {"absent", "independent-reference", false}}
	a.Dependencies = []Dependency{{"beta", "1.0.0", "2.0.0", false}, {"optional", "1.0.0", "2.0.0", true}}
	c.InstallationModes = []string{"private-child"}
	pa, pb, pc := fixturePackage(t, a, nil), fixturePackage(t, b, nil), fixturePackage(t, c, nil)
	input := InstanceTopologyInput{Roots: []string{"a"}, Instances: []InstanceSpec{{"a", pa.Pin(), "independent", Placement{"local-process"}}, {"b", pb.Pin(), "independent", Placement{"local-process"}}, {"c", pc.Pin(), "private-child", Placement{"local-process"}}}, Children: []ChildBinding{{"a", "c", "private"}}, Dependencies: []DependencyBinding{{"a", "b"}}}
	topology, err := ResolveInstanceTopology([]AdmittedPackage{pa, pb, pc}, nil, input)
	if err != nil {
		t.Fatal(err)
	}
	if len(topology.OptionalUnavailable()) != 2 || !reflect.DeepEqual(topology.GroupOrder(), []string{"b", "a"}) {
		t.Fatal("dependency/optional facts lost")
	}
	input.Dependencies = nil
	if _, err = ResolveInstanceTopology([]AdmittedPackage{pa, pb, pc}, nil, input); err == nil {
		t.Fatal("required dependency inferred")
	}
	// A private child's dependency on its parent is a real readiness cycle, not
	// the ordinary lifetime link (which alone must not produce a cycle).
	c.Dependencies = []Dependency{{"alpha", "1.0.0", "2.0.0", false}}
	pc = fixturePackage(t, c, nil)
	input.Instances[2].Pin = pc.Pin()
	input.Dependencies = []DependencyBinding{{"a", "b"}, {"c", "a"}}
	if _, err = ResolveInstanceTopology([]AdmittedPackage{pa, pb, pc}, nil, input); err == nil {
		t.Fatal("readiness cycle accepted")
	}
}
func TestInstanceTopologyFlatCompatibilityAndExplicitChildren(t *testing.T) {
	a, b := fixtureManifest("alpha"), fixtureManifest("beta")
	a.Dependencies = []Dependency{{"beta", "1.0.0", "2.0.0", false}}
	pa, pb := fixturePackage(t, a, nil), fixturePackage(t, b, nil)
	plan, err := Resolve([]AdmittedPackage{pa, pb}, []PackagePin{pa.Pin()}, []PackagePin{pb.Pin()})
	if err != nil {
		t.Fatal(err)
	}
	topology, err := FlatInstanceTopology(plan, map[string]string{"alpha": "a", "beta": "b"})
	if err != nil || !reflect.DeepEqual(topology.GroupOrder(), []string{"b", "a"}) || len(topology.Roots()) != 2 {
		t.Fatal("flat compatibility changed")
	}
	a.Children = []Child{{"missing", "private", false}}
	pa = fixturePackage(t, a, nil)
	plan, err = Resolve([]AdmittedPackage{pa, pb}, []PackagePin{pa.Pin()}, []PackagePin{pb.Pin()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = FlatInstanceTopology(plan, map[string]string{"alpha": "a", "beta": "b"}); err == nil {
		t.Fatal("legacy silently ignored children")
	}
	if err = ValidateActivationSupport(pa, "independent", Platform{"darwin", "arm64"}); err != nil {
		t.Fatal("package-level check refuses topology-owned declaration")
	}
}

func TestInstanceTopologyDeterministicAndSeparateRetentionRoots(t *testing.T) {
	catalog, input := topologyFixture(t)
	// The shared child is retained by consumers without becoming an implicit root.
	input.Roots = []string{"b", "a"}
	first, err := ResolveInstanceTopology(catalog, nil, input)
	if err != nil {
		t.Fatal(err)
	}
	for i, j := 0, len(input.Instances)-1; i < j; i, j = i+1, j-1 {
		input.Instances[i], input.Instances[j] = input.Instances[j], input.Instances[i]
	}
	for i, j := 0, len(input.Children)-1; i < j; i, j = i+1, j-1 {
		input.Children[i], input.Children[j] = input.Children[j], input.Children[i]
	}
	for i, j := 0, len(catalog)-1; i < j; i, j = i+1, j-1 {
		catalog[i], catalog[j] = catalog[j], catalog[i]
	}
	second, err := ResolveInstanceTopology(catalog, nil, input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.Instances(), second.Instances()) || !reflect.DeepEqual(first.OwnershipOrder(), second.OwnershipOrder()) || !reflect.DeepEqual(first.ReadinessOrder(), second.ReadinessOrder()) || !reflect.DeepEqual(first.Roots(), []string{"a", "b"}) {
		t.Fatal("input order changed topology or root claims")
	}
}
func TestInstanceTopologyRejectsOwnershipAndReferenceCycles(t *testing.T) {
	for _, relationship := range []string{"private", "independent-reference"} {
		t.Run(relationship, func(t *testing.T) {
			a, b, root := fixtureManifest("alpha"), fixtureManifest("beta"), fixtureManifest("root")
			a.Children = []Child{{"beta", relationship, true}}
			b.Children = []Child{{"alpha", relationship, true}}
			mode := "independent"
			if relationship == "private" {
				mode = "private-child"
				a.InstallationModes = []string{mode}
				b.InstallationModes = []string{mode}
			}
			pa, pb, pr := fixturePackage(t, a, nil), fixturePackage(t, b, nil), fixturePackage(t, root, nil)
			input := InstanceTopologyInput{Roots: []string{"r"}, Instances: []InstanceSpec{{"a", pa.Pin(), mode, Placement{"local-process"}}, {"b", pb.Pin(), mode, Placement{"local-process"}}, {"r", pr.Pin(), "independent", Placement{"local-process"}}}, Children: []ChildBinding{{"a", "b", relationship}, {"b", "a", relationship}}}
			if relationship == "independent-reference" {
				input.Roots = append(input.Roots, "a")
			}
			if _, err := ResolveInstanceTopology([]AdmittedPackage{pa, pb, pr}, nil, input); err == nil {
				t.Fatal("cycle accepted")
			}
		})
	}
}
func TestInstanceTopologyDependencyTargetsAreExplicitAndPrivateScoped(t *testing.T) {
	a, b, c := fixtureManifest("alpha"), fixtureManifest("beta"), fixtureManifest("child")
	a.Children = []Child{{"child", "private", true}}
	b.Dependencies = []Dependency{{"child", "1.0.0", "2.0.0", false}}
	c.InstallationModes = []string{"private-child"}
	pa, pb, pc := fixturePackage(t, a, nil), fixturePackage(t, b, nil), fixturePackage(t, c, nil)
	input := InstanceTopologyInput{Roots: []string{"a", "b"}, Instances: []InstanceSpec{{"a", pa.Pin(), "independent", Placement{"local-process"}}, {"b", pb.Pin(), "independent", Placement{"local-process"}}, {"c", pc.Pin(), "private-child", Placement{"local-process"}}}, Children: []ChildBinding{{"a", "c", "private"}}, Dependencies: []DependencyBinding{{"b", "c"}}}
	if _, err := ResolveInstanceTopology([]AdmittedPackage{pa, pb, pc}, nil, input); err == nil {
		t.Fatal("foreign private dependency accepted")
	}
	// Two independent instances of one dependency still require a single exact
	// target. The declaration is not permission to choose either target silently.
	c.InstallationModes = []string{"independent"}
	pc = fixturePackage(t, c, nil)
	a.Children = []Child{}
	pa = fixturePackage(t, a, nil)
	input.Children = nil
	input.Instances[0].Pin = pa.Pin()
	input.Instances[2] = InstanceSpec{"c", pc.Pin(), "independent", Placement{"local-process"}}
	input.Instances = append(input.Instances, InstanceSpec{"c-two", pc.Pin(), "independent", Placement{"local-process"}})
	input.Roots = append(input.Roots, "c", "c-two")
	input.Dependencies = append(input.Dependencies, DependencyBinding{"b", "c-two"})
	if _, err := ResolveInstanceTopology([]AdmittedPackage{pa, pb, pc}, nil, input); err == nil {
		t.Fatal("ambiguous dependency target accepted")
	}
}

func TestInstanceTopologyFlatKeepsIncompatibleOptionalDependencyUnavailable(t *testing.T) {
	a, b := fixtureManifest("alpha"), fixtureManifest("beta")
	a.Dependencies = []Dependency{{"beta", "1.0.0", "2.0.0", true}}
	b.Version = "2.0.0"
	pa, pb := fixturePackage(t, a, nil), fixturePackage(t, b, nil)
	plan, err := Resolve([]AdmittedPackage{pa, pb}, []PackagePin{pa.Pin(), pb.Pin()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	topology, err := FlatInstanceTopology(plan, map[string]string{"alpha": "a", "beta": "b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(topology.Dependencies("a")) != 0 || len(topology.OptionalUnavailable()) != 1 || len(topology.Plan().OptionalUnavailable()) != 1 {
		t.Fatal("optional incompatibility silently bound or lost")
	}
}
