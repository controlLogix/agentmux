package plugins

import (
	"fmt"
	"io"
	"sort"
)

type Unavailable struct {
	PackageID    string `json:"packageId"`
	DependencyID string `json:"dependencyId"`
	Reason       string `json:"reason"`
}
type Plan struct {
	packages    []AdmittedPackage
	order       []PackagePin
	unavailable []Unavailable
}

func (p Plan) Packages() []AdmittedPackage { return append([]AdmittedPackage(nil), p.packages...) }
func (p Plan) Order() []PackagePin         { return append([]PackagePin(nil), p.order...) }
func (p Plan) OptionalUnavailable() []Unavailable {
	return append([]Unavailable(nil), p.unavailable...)
}
func (Plan) String() string   { return "[ordinary plugin resolution plan]" }
func (Plan) GoString() string { return "[ordinary plugin resolution plan]" }
func (Plan) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[ordinary plugin resolution plan]")
}
func (Plan) MarshalJSON() ([]byte, error) { return []byte(`{"kind":"ordinary-plugin-plan"}`), nil }

// Resolve checks an exact, owner-selected local package set. It never fetches,
// searches for a newer version, grants a capability or starts a process.
func Resolve(catalog []AdmittedPackage, roots []PackagePin, selected []PackagePin) (Plan, error) {
	fail := func(code string) (Plan, error) { return Plan{}, pluginError(code) }
	if len(catalog) > 4096 || len(roots) == 0 || len(roots) > 4096 || len(selected) > 4096 {
		return fail("resolution_limits_invalid")
	}
	byPin := map[PackagePin]AdmittedPackage{}
	byID := map[string][]PackagePin{}
	for _, p := range catalog {
		if len(p.files) == 0 || p.pin.PackageID == "" {
			return fail("package_not_admitted")
		}
		if _, ok := byPin[p.pin]; ok {
			return fail("duplicate_package_identity")
		}
		byPin[p.pin] = p
		byID[p.pin.PackageID] = append(byID[p.pin.PackageID], p.pin)
	}
	chosen := map[string]PackagePin{}
	for _, pin := range append(append([]PackagePin(nil), selected...), roots...) {
		if _, ok := byPin[pin]; !ok {
			return fail("selected_package_unavailable")
		}
		if old, ok := chosen[pin.PackageID]; ok && old != pin {
			return fail("conflicting_package_selection")
		}
		chosen[pin.PackageID] = pin
	}
	// A sole admitted candidate is not an implicit selection: dependency pins must
	// be supplied by the owner as well, preserving reproducibility across installs.
	state := map[string]int{}
	var result Plan
	var visit func(PackagePin) error
	visit = func(pin PackagePin) error {
		if state[pin.PackageID] == 1 {
			return pluginError("dependency_cycle")
		}
		if state[pin.PackageID] == 2 {
			return nil
		}
		state[pin.PackageID] = 1
		p := byPin[pin]
		deps := append([]Dependency(nil), p.manifest.manifest.Dependencies...)
		sort.Slice(deps, func(i, j int) bool { return deps[i].PackageID < deps[j].PackageID })
		for _, dep := range deps {
			target, ok := chosen[dep.PackageID]
			reason := "dependency_missing"
			if !ok && len(byID[dep.PackageID]) > 1 {
				reason = "dependency_selection_ambiguous"
			}
			if !ok && len(byID[dep.PackageID]) == 1 {
				reason = "dependency_pin_required"
			}
			if ok && (compareVersion(target.Version, dep.MinimumVersion) < 0 || compareVersion(target.Version, dep.ExclusiveMaximumVersion) >= 0) {
				ok = false
				reason = "dependency_version_incompatible"
			}
			if !ok {
				if !dep.Optional {
					return pluginError(reason)
				}
				result.unavailable = append(result.unavailable, Unavailable{PackageID: pin.PackageID, DependencyID: dep.PackageID, Reason: reason})
				continue
			}
			if err := visit(target); err != nil {
				return err
			}
		}
		state[pin.PackageID] = 2
		result.packages = append(result.packages, p)
		result.order = append(result.order, pin)
		return nil
	}
	ordered := append([]PackagePin(nil), roots...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].PackageID < ordered[j].PackageID })
	for _, pin := range ordered {
		if err := visit(pin); err != nil {
			return Plan{}, err
		}
	}
	sort.Slice(result.unavailable, func(i, j int) bool {
		a, b := result.unavailable[i], result.unavailable[j]
		if a.PackageID != b.PackageID {
			return a.PackageID < b.PackageID
		}
		return a.DependencyID < b.DependencyID
	})
	return result, nil
}
