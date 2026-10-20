package plugins

import (
	"reflect"
	"testing"
)

func TestExactResolutionOrderOptionalAndCopies(t *testing.T) {
	a := fixtureManifest("alpha")
	a.Dependencies = []Dependency{{PackageID: "beta", MinimumVersion: "1.0.0", ExclusiveMaximumVersion: "2.0.0"}, {PackageID: "optional", MinimumVersion: "1.0.0", ExclusiveMaximumVersion: "2.0.0", Optional: true}}
	pa, pb := fixturePackage(t, a, nil), fixturePackage(t, fixtureManifest("beta"), nil)
	plan, e := Resolve([]AdmittedPackage{pa, pb}, []PackagePin{pa.Pin()}, []PackagePin{pb.Pin()})
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(plan.Order(), []PackagePin{pb.Pin(), pa.Pin()}) || len(plan.OptionalUnavailable()) != 1 {
		t.Fatal("invalid plan")
	}
	reverse, e := Resolve([]AdmittedPackage{pb, pa}, []PackagePin{pa.Pin()}, []PackagePin{pb.Pin()})
	if e != nil || !reflect.DeepEqual(plan.Order(), reverse.Order()) {
		t.Fatal("nondeterministic plan")
	}
	order := plan.Order()
	order[0] = PackagePin{}
	if plan.Order()[0] != pb.Pin() {
		t.Fatal("mutable plan")
	}
}
func TestResolutionMissingIncompatibleCyclesAndConflicts(t *testing.T) {
	for _, kind := range []string{"missing", "incompatible", "cycle", "optional-cycle", "pin", "ambiguous", "conflict"} {
		t.Run(kind, func(t *testing.T) {
			a, b := fixtureManifest("alpha"), fixtureManifest("beta")
			a.Dependencies = []Dependency{{PackageID: "beta", MinimumVersion: "1.0.0", ExclusiveMaximumVersion: "2.0.0", Optional: kind == "optional-cycle"}}
			if kind == "incompatible" {
				b.Version = "2.0.0"
			}
			if kind == "cycle" || kind == "optional-cycle" {
				b.Dependencies = []Dependency{{PackageID: "alpha", MinimumVersion: "1.0.0", ExclusiveMaximumVersion: "2.0.0"}}
			}
			pa, pb := fixturePackage(t, a, nil), fixturePackage(t, b, nil)
			catalog := []AdmittedPackage{pa, pb}
			selected := []PackagePin{pb.Pin()}
			if kind == "missing" {
				catalog = []AdmittedPackage{pa}
				selected = nil
			}
			if kind == "pin" {
				selected = nil
			}
			if kind == "ambiguous" || kind == "conflict" {
				b.Version = "1.1.0"
				pc := fixturePackage(t, b, nil)
				catalog = append(catalog, pc)
				if kind == "ambiguous" {
					selected = nil
				} else {
					selected = append(selected, pc.Pin())
				}
			}
			if _, e := Resolve(catalog, []PackagePin{pa.Pin()}, selected); e == nil {
				t.Fatal("invalid graph accepted")
			}
		})
	}
}
