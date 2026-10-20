package plugins

import (
	"reflect"
	"testing"
)

func scopedRegistryFixture(t *testing.T) (InstanceTopology, []ContractBinding, []ContributionBinding) {
	t.Helper()
	a, b, c, shared := fixtureManifest("alpha"), fixtureManifest("beta"), fixtureManifest("child"), fixtureManifest("shared")
	a.Children = []Child{{"child", "private", true}, {"shared", "independent-reference", true}}
	b.Children = append([]Child(nil), a.Children...)
	c.InstallationModes = []string{"private-child"}
	a.Contributions = []Contribution{{"tool", "alpha-tool", "tool-contract"}}
	b.Contributions = []Contribution{{"tool", "beta-tool", "tool-contract"}}
	c.Contributions = []Contribution{{"tool", "private-tool", "tool-contract"}}
	shared.Contributions = []Contribution{{"tool", "shared-tool", "tool-contract"}}
	packages := []AdmittedPackage{fixturePackage(t, a, nil), fixturePackage(t, b, nil), fixturePackage(t, c, nil), fixturePackage(t, shared, nil)}
	_, input := topologyFixtureFromPackages(packages)
	topology, err := ResolveInstanceTopology(packages, nil, input)
	if err != nil {
		t.Fatal(err)
	}
	var bindings []ContributionBinding
	for _, n := range topology.Instances() {
		p, _ := topology.Package(n.InstanceID)
		for _, c := range p.Manifest().Contributions {
			bindings = append(bindings, ContributionBinding{n.Pin, c.Kind, c.ID, c.ContractRef, n.InstanceID, registryTestEpoch, 1})
		}
	}
	return topology, []ContractBinding{{"tool", "tool-contract"}}, bindings
}
func TestInstanceRegistryScopesPrivateHandlersWithoutChangingIDs(t *testing.T) {
	topology, contracts, bindings := scopedRegistryFixture(t)
	if err := ValidateInstanceContributionDeclarations(topology, contracts); err != nil {
		t.Fatal(err)
	}
	registry, err := BuildInstanceRegistry(topology, contracts, bindings)
	if err != nil {
		t.Fatal(err)
	}
	if !registry.ValidForTopology(topology) || len(registry.Entries()) != 5 {
		t.Fatal("incomplete scoped registry")
	}
	for _, pair := range [][2]string{{"a", "ac"}, {"b", "bc"}, {"ac", "ac"}} {
		entry, err := registry.ResolveFor(pair[0], pair[1], "tool", "private-tool")
		if err != nil || entry.ID != "private-tool" || entry.Owner.InstanceID != pair[1] {
			t.Fatal("declared private handler missing")
		}
	}
	for _, pair := range [][2]string{{"a", "bc"}, {"b", "ac"}, {"shared", "ac"}, {"unknown", "ac"}} {
		if _, err := registry.ResolveFor(pair[0], pair[1], "tool", "private-tool"); err == nil {
			t.Fatal("private visibility escaped")
		}
	}
	if _, err := registry.Resolve("tool", "private-tool"); err == nil {
		t.Fatal("private handler exported globally")
	}
	if e, err := registry.Resolve("tool", "shared-tool"); err != nil || e.Owner.InstanceID != "shared" {
		t.Fatal("independent export disappeared")
	}
	entries := registry.Entries()
	entries[0].Owner.Generation = 99
	bindings[0].Generation = 99
	contracts[0].ContractRef = "changed"
	if registry.Entries()[0].Owner.Generation != 1 {
		t.Fatal("registry mutated")
	}
	// Plan.Packages is dependency-first, so build a modified snapshot through the
	// stable node accessor rather than assuming package ordering.
	input := InstanceTopologyInput{Instances: topology.Instances(), Roots: []string{"a", "b"}, Children: append(topology.Children("a"), topology.Children("b")...)}
	changed, err := PlanInstances(topology.Plan(), input)
	if err != nil {
		t.Fatal(err)
	}
	if registry.ValidForTopology(changed) {
		t.Fatal("changed retention claims accepted as same topology")
	}
}
func TestInstanceRegistryRefusesBindingsAndIndependentCollisions(t *testing.T) {
	topology, contracts, base := scopedRegistryFixture(t)
	for _, tc := range []struct {
		name   string
		change func([]ContributionBinding) []ContributionBinding
	}{
		{"missing", func(b []ContributionBinding) []ContributionBinding { return b[1:] }},
		{"duplicate", func(b []ContributionBinding) []ContributionBinding { return append(b, b[0]) }},
		{"cross-instance", func(b []ContributionBinding) []ContributionBinding { b[0].InstanceID = "bc"; return b }},
		{"wrong-full-pin", func(b []ContributionBinding) []ContributionBinding { b[0].Pin.ProvenanceChecksum = "changed"; return b }},
		{"unknown-epoch", func(b []ContributionBinding) []ContributionBinding { b[0].Epoch = ""; return b }},
		{"zero-generation", func(b []ContributionBinding) []ContributionBinding { b[0].Generation = 0; return b }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := BuildInstanceRegistry(topology, contracts, tc.change(append([]ContributionBinding(nil), base...))); err == nil {
				t.Fatal("invalid binding accepted")
			}
		})
	}
	manifest := fixtureManifest("same")
	manifest.Contributions = []Contribution{{"tool", "same-tool", "tool-contract"}}
	p := fixturePackage(t, manifest, nil)
	input := InstanceTopologyInput{Instances: []InstanceSpec{{"one", p.Pin(), "independent", Placement{"local-process"}}, {"two", p.Pin(), "independent", Placement{"local-process"}}}, Roots: []string{"one", "two"}}
	duplicate, err := ResolveInstanceTopology([]AdmittedPackage{p}, nil, input)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateInstanceContributionDeclarations(duplicate, contracts); err == nil {
		t.Fatal("independent duplicate global handler accepted")
	}
	if _, err := BuildInstanceRegistry(InstanceTopology{}, nil, nil); err == nil {
		t.Fatal("zero topology accepted")
	}
}
func TestInstanceRegistryFlatMatchesLegacyGlobalLookup(t *testing.T) {
	_, plan, contracts, bindings := registryFixture(t)
	topology, err := FlatInstanceTopology(plan, map[string]string{"registry": "registry-instance"})
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := BuildRegistry(plan, contracts, bindings)
	if err != nil {
		t.Fatal(err)
	}
	scoped, err := BuildInstanceRegistry(topology, contracts, bindings)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(legacy.Entries(), scoped.Entries()) {
		t.Fatal("legacy contribution metadata changed")
	}
	for _, b := range bindings {
		left, e := legacy.Resolve(b.Kind, b.ID)
		right, re := scoped.Resolve(b.Kind, b.ID)
		if e != nil || re != nil || left != right {
			t.Fatal("global lookup changed")
		}
	}
}
