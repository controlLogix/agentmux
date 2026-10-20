package plugins

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

var registryTestEpoch = strings.Repeat("a", 64)

func registryPlan(t *testing.T, packages ...AdmittedPackage) Plan {
	t.Helper()
	roots := make([]PackagePin, 0, len(packages))
	for _, pkg := range packages {
		roots = append(roots, pkg.Pin())
	}
	plan, err := Resolve(packages, roots, nil)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
func registryFixture(t *testing.T) (AdmittedPackage, Plan, []ContractBinding, []ContributionBinding) {
	t.Helper()
	manifest := fixtureManifest("registry")
	kinds := []string{"tool", "cli", "mcp", "ag-ui", "decision-definition", "skill", "domain-service", "provider"}
	var contracts []ContractBinding
	for _, kind := range kinds {
		ref := "contracts/" + kind + ".json"
		manifest.Contributions = append(manifest.Contributions, Contribution{Kind: kind, ID: "entry-" + kind, ContractRef: ref})
		contracts = append(contracts, ContractBinding{kind, ref})
	}
	pkg := fixturePackage(t, manifest, nil)
	var bindings []ContributionBinding
	for _, contribution := range manifest.Contributions {
		bindings = append(bindings, ContributionBinding{Pin: pkg.Pin(), Kind: contribution.Kind, ID: contribution.ID, ContractRef: contribution.ContractRef, InstanceID: "registry-instance", Epoch: registryTestEpoch, Generation: 7})
	}
	return pkg, registryPlan(t, pkg), contracts, bindings
}

func TestRegistryAllContributionKindsExactContractsAndCopiedSnapshot(t *testing.T) {
	pkg, plan, contracts, bindings := registryFixture(t)
	registry, err := BuildRegistry(plan, contracts, bindings)
	if err != nil {
		t.Fatal(err)
	}
	if !registry.ValidFor(plan) || len(registry.Entries()) != 8 {
		t.Fatal("incomplete candidate")
	}
	for _, contribution := range pkg.Manifest().Contributions {
		entry, err := registry.Resolve(contribution.Kind, contribution.ID)
		if err != nil || entry.Kind != contribution.Kind || entry.ID != contribution.ID || entry.ContractRef != contribution.ContractRef || entry.Owner != (OwnerReference{Pin: pkg.Pin(), InstanceID: "registry-instance", Epoch: registryTestEpoch, Generation: 7}) {
			t.Fatal("contribution changed")
		}
	}
	contracts[0].ContractRef = "changed"
	bindings[0].Generation = 100
	entries := registry.Entries()
	entries[0].Owner.Generation = 100
	for _, entry := range registry.Entries() {
		if entry.Owner.Generation != 7 {
			t.Fatal("mutable snapshot")
		}
	}
	if _, err := registry.Resolve("tool", "unknown"); err == nil {
		t.Fatal("unknown contribution resolved")
	}
	newer := fixturePackage(t, pkg.Manifest(), map[string][]byte{"changed.txt": []byte("new content")})
	if registry.ValidFor(registryPlan(t, newer)) {
		t.Fatal("registry bound to wrong package bytes")
	}
	if (Registry{}).ValidFor(plan) {
		t.Fatal("zero registry accepted")
	}
}

func TestRegistryBindingAndContractFailuresAreClosed(t *testing.T) {
	_, plan, contracts, bindings := registryFixture(t)
	cases := []struct {
		name   string
		change func([]ContributionBinding) []ContributionBinding
	}{
		{"missing", func(b []ContributionBinding) []ContributionBinding { return b[1:] }},
		{"duplicate", func(b []ContributionBinding) []ContributionBinding { return append(b, b[0]) }},
		{"wrong-pin", func(b []ContributionBinding) []ContributionBinding {
			b[0].Pin.PackageChecksum = checksum([]byte("wrong"))
			return b
		}},
		{"wrong-contract", func(b []ContributionBinding) []ContributionBinding { b[0].ContractRef = "private-marker"; return b }},
		{"wrong-kind", func(b []ContributionBinding) []ContributionBinding { b[0].Kind = "unknown"; return b }},
		{"extra", func(b []ContributionBinding) []ContributionBinding {
			extra := b[0]
			extra.ID = "extra"
			return append(b, extra)
		}},
		{"generation", func(b []ContributionBinding) []ContributionBinding { b[0].Generation = 0; return b }},
		{"generation-limit", func(b []ContributionBinding) []ContributionBinding { b[0].Generation = 9007199254740992; return b }},
		{"epoch", func(b []ContributionBinding) []ContributionBinding { b[0].Epoch = ""; return b }},
		{"owner", func(b []ContributionBinding) []ContributionBinding { b[0].Generation++; return b }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := BuildRegistry(plan, contracts, test.change(append([]ContributionBinding(nil), bindings...)))
			if err == nil {
				t.Fatal("invalid binding accepted")
			}
			encoded, _ := json.Marshal(err)
			if strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err)+string(encoded), "private-marker") {
				t.Fatal("private binding exposed")
			}
		})
	}
	unknown := append([]ContractBinding(nil), contracts...)
	unknown[0].ContractRef = "private-marker"
	if _, err := BuildRegistry(plan, unknown, bindings); err == nil {
		t.Fatal("unknown contract accepted")
	}
	if _, err := BuildRegistry(plan, append(contracts, contracts[0]), bindings); err == nil {
		t.Fatal("duplicate contract registration")
	}
	if _, err := BuildRegistry(Plan{}, nil, nil); err == nil {
		t.Fatal("unresolved plan accepted")
	}
}

func TestRegistryFailedCandidateKeepsPreviousAndFencesEpochs(t *testing.T) {
	pkg, plan, contracts, bindings := registryFixture(t)
	previous, err := BuildRegistry(plan, contracts, bindings)
	if err != nil {
		t.Fatal(err)
	}
	before := previous.Entries()
	duplicateManifest := pkg.Manifest()
	duplicateManifest.PackageID = "duplicate"
	duplicate := fixturePackage(t, duplicateManifest, nil)
	if _, err := BuildRegistry(registryPlan(t, pkg, duplicate), contracts, bindings); err == nil {
		t.Fatal("duplicate global handler accepted")
	}
	if !reflect.DeepEqual(previous.Entries(), before) || !previous.ValidFor(plan) {
		t.Fatal("failed candidate changed previous registry")
	}
	nextBindings := append([]ContributionBinding(nil), bindings...)
	for index := range nextBindings {
		nextBindings[index].Epoch = strings.Repeat("b", 64)
	}
	next, err := BuildRegistry(plan, contracts, nextBindings)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := previous.Resolve("tool", "entry-tool")
	current, _ := next.Resolve("tool", "entry-tool")
	if old.Owner == current.Owner {
		t.Fatal("manager restart epoch lost")
	}
	// These are immutable references, not dispatch authority. The manager performs
	// the active-generation/epoch check before invoking a contract-specific owner.
	var group sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for i := 0; i < 50; i++ {
				entry, err := previous.Resolve("tool", "entry-tool")
				if err != nil || entry.Owner != old.Owner {
					t.Error("snapshot changed")
				}
			}
		}()
	}
	group.Wait()
}

func TestRegistryRefusesProtectedMembershipAndDuplicateInstances(t *testing.T) {
	for _, id := range []string{"boot", "kernel-lifecycle", "internal-communication", "exported-status"} {
		m := fixtureManifest("ordinary")
		m.Contributions = []Contribution{{Kind: "domain-service", ID: id, ContractRef: "local"}}
		pkg := fixturePackage(t, m, nil)
		if _, err := BuildRegistry(registryPlan(t, pkg), []ContractBinding{{"domain-service", "local"}}, nil); err == nil {
			t.Fatal("protected contribution accepted")
		}
	}
	a, b := fixtureManifest("alpha"), fixtureManifest("beta")
	a.Contributions = []Contribution{{Kind: "tool", ID: "alpha-tool", ContractRef: "local"}}
	b.Contributions = []Contribution{{Kind: "tool", ID: "beta-tool", ContractRef: "local"}}
	pa, pb := fixturePackage(t, a, nil), fixturePackage(t, b, nil)
	bindings := []ContributionBinding{{Pin: pa.Pin(), Kind: "tool", ID: "alpha-tool", ContractRef: "local", InstanceID: "shared", Epoch: registryTestEpoch, Generation: 1}, {Pin: pb.Pin(), Kind: "tool", ID: "beta-tool", ContractRef: "local", InstanceID: "shared", Epoch: registryTestEpoch, Generation: 1}}
	if _, err := BuildRegistry(registryPlan(t, pa, pb), []ContractBinding{{"tool", "local"}}, bindings); err == nil {
		t.Fatal("instance reused by distinct packages")
	}
}

func TestRegistryPresentationDoesNotExposeContractMetadata(t *testing.T) {
	m := fixtureManifest("private")
	m.Contributions = []Contribution{{Kind: "tool", ID: "inspect", ContractRef: "private-marker"}}
	pkg := fixturePackage(t, m, nil)
	registry, err := BuildRegistry(registryPlan(t, pkg), []ContractBinding{{"tool", "private-marker"}}, []ContributionBinding{{Pin: pkg.Pin(), Kind: "tool", ID: "inspect", ContractRef: "private-marker", InstanceID: "private-instance", Epoch: registryTestEpoch, Generation: 1}})
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := registry.Resolve("tool", "inspect")
	for _, value := range []any{registry, entry} {
		encoded, _ := json.Marshal(value)
		if strings.Contains(fmt.Sprintf("%v %+v %#v %s %q", value, value, value, value, value)+string(encoded), "private-marker") {
			t.Fatal("contract metadata exposed")
		}
	}
}

func TestRegistryReadOnlyDeclarationPreflightAndWireFieldNames(t *testing.T) {
	_, plan, contracts, bindings := registryFixture(t)
	if err := ValidateContributionDeclarations(plan, contracts); err != nil {
		t.Fatal(err)
	}
	if err := ValidateContributionDeclarations(plan, nil); err == nil {
		t.Fatal("unknown declaration accepted")
	}
	raw, err := json.Marshal(bindings[0])
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("wire encoding")
	}
	for _, key := range []string{"pin", "kind", "id", "contractRef", "instanceId", "epoch", "generation"} {
		if _, ok := value[key]; !ok {
			t.Fatal("missing lowercamel binding field")
		}
	}
	if len(value) != 7 {
		t.Fatal("unexpected binding fields")
	}
	owner := OwnerReference{Pin: bindings[0].Pin, InstanceID: bindings[0].InstanceID, Epoch: bindings[0].Epoch, Generation: bindings[0].Generation}
	raw, err = json.Marshal(owner)
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("wire encoding")
	}
	// Decode into a fresh map because encoding/json preserves old map keys.
	value = nil
	_ = json.Unmarshal(raw, &value)
	if len(value) != 4 {
		t.Fatal("unexpected owner fields")
	}
	for _, key := range []string{"pin", "instanceId", "epoch", "generation"} {
		if _, ok := value[key]; !ok {
			t.Fatal("missing lowercamel owner field")
		}
	}
}
