package plugins

import (
	"context"
	"encoding/json"
	"testing"
)

func TestRequiredCapabilityActivationNeedsRegisteredNativeContext(t *testing.T) {
	pkg := nativeFixturePackage(t, "required_activation", func(manifest *Manifest) {
		manifest.RequestedCapabilities = []Capability{{Action: "read", ResourceClass: "storage", Required: true}}
	})
	host := Platform{OS: "darwin", Arch: "arm64"}
	if ValidateActivationSupport(pkg, "independent", host) == nil {
		t.Fatal("lifecycle-only validation accepted a required capability")
	}
	if err := ValidateContextActivationSupport(pkg, "independent", host); err != nil {
		t.Fatal("native context declaration refused", err)
	}
	for _, test := range []struct {
		name     string
		provider ContextProvider
		allowed  bool
	}{
		{"lifecycle-only", nil, false},
		{"generic-context", &contextProvider{}, false},
		{"nil-registered-context", (*nativeRegisteredContextProvider)(nil), false},
		{"registered-native-context", &nativeRegisteredContextProvider{}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			driver := &NativeDriver{contexts: test.provider, bindings: map[string]admittedNativeBinding{"required_activation": {binding: NativeBinding{InstanceID: "required_activation", Pin: pkg.Pin()}}}}
			if err := activationSupportForDriver(driver, pkg, "independent", host); (err == nil) != test.allowed {
				t.Fatal("manager capability preflight did not preserve its provider boundary", err)
			}
			if err := nativeExecutable(pkg, "independent", driver.requiredCapabilityAdmission()); (err == nil) != test.allowed {
				t.Fatal("native executable preflight did not preserve its provider boundary", err)
			}
		})
	}
}

func TestRequiredNativeCapabilityStillNeedsCurrentGrantAndPolicy(t *testing.T) {
	for _, change := range []string{"none", "missing-grant", "denied-policy"} {
		t.Run(change, func(t *testing.T) {
			f := newNativeAuthorityFixture(t)
			switch change {
			case "missing-grant":
				f.facts["grant"].(map[string]any)["actions"] = []string{"inspect"}
			case "denied-policy":
				f.facts["policy"].(map[string]any)["decisions"].([]any)[0].(map[string]any)["outcome"] = "deny"
			}
			_, err := f.authority.BindInstance(context.Background(), f.binding)
			if (err == nil) != (change == "none") {
				t.Fatal("required capability did not enforce the current signed grant and policy", err)
			}
		})
	}
}

func TestRequiredCapabilityRefusalPrecedesActivationWrites(t *testing.T) {
	for _, change := range []string{"none", "missing-grant", "denied-policy"} {
		t.Run(change, func(t *testing.T) {
			sequence := nativeRestartSequenceFixture(t, true)
			binding := sequence.wire.authority.binding
			binding.ProfileContext = cloneProfileContext(sequence.provider.profile.Context)
			declaration := sequence.provider.declarations[binding.Owner.InstanceID]
			var facts map[string]any
			if json.Unmarshal(declaration.Facts, &facts) != nil {
				t.Fatal("activation fixture facts invalid")
			}
			switch change {
			case "missing-grant":
				facts["grant"].(map[string]any)["actions"] = []string{"inspect"}
			case "denied-policy":
				facts["policy"].(map[string]any)["decisions"].([]any)[0].(map[string]any)["outcome"] = "deny"
			}
			declaration.Facts = contextJSON(facts)
			sequence.provider.declarations[binding.Owner.InstanceID] = declaration
			lease, err := sequence.provider.Open(context.Background(), binding)
			if change == "none" {
				if err != nil || lease == nil {
					t.Fatal("admitted required capability failed before activation", err)
				}
				lease.Invalidate()
				if lease.Close(context.Background()) != nil {
					t.Fatal("activation fixture context did not join")
				}
			} else if err == nil || lease != nil || sequence.nativeCalls != 0 || sequence.sets != 0 || sequence.opened != 0 {
				t.Fatal("required capability refusal occurred after activation work")
			}
		})
	}
}
