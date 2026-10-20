package plugins

import (
	"context"
	"encoding/json"
	"testing"
)

func TestNativeActivationDeclarationUsesActualBinding(t *testing.T) {
	f := newNativeAuthorityFixture(t)
	declaration := NativeActivationDeclaration{RecordRef: ContextReference{"native_record", "context_hub", 1}, IdentityRef: ContextReference{"plugin_identity", "context_hub", 1}, Pin: f.binding.Owner.Pin, ManifestDigest: f.binding.Package.manifest.Checksum(), ConfigurationChecksum: f.binding.Configuration.Checksum(), Facts: contextJSON(f.facts)}
	host := ContextReference{"host_identity", "context_hub", 1}
	for _, change := range []string{"none", "pin", "configuration", "identity-hub", "record-revision"} {
		t.Run(change, func(t *testing.T) {
			input := cloneNativeActivationDeclaration(declaration)
			switch change {
			case "pin":
				input.Pin.Version = "99.0.0"
			case "configuration":
				input.ConfigurationChecksum = nativeAuthorityDigest([]byte("other"))
			case "identity-hub":
				input.IdentityRef.OwnerHubID = "another_hub"
			case "record-revision":
				input.RecordRef.Revision = 2
			}
			binding := cloneContextBinding(f.binding)
			binding.Owner.Generation++
			raw, err := nativeActivationRecord(binding, input, host)
			if change != "none" {
				if err == nil || raw != nil {
					t.Fatal("changed declaration admitted")
				}
				return
			}
			if err != nil || !nativeCapabilityEqual(fieldsForClaim(raw, "owner"), contextJSON(binding.Owner)) || !nativeCapabilityEqual(fieldsForClaim(raw, "hostIdentityRef"), contextJSON(host)) || !nativeCapabilityEqual(fieldsForClaim(raw, "facts"), declaration.Facts) {
				t.Fatal("record changed admitted facts or failed to use actual owner", err)
			}
		})
	}
}

func TestNativeActivationUsesCompleteAllocatedOwner(t *testing.T) {
	for _, change := range []string{"none", "rebind", "private-storage", "owner", "configuration", "parent", "previous-ref", "result-ref", "result-facts", "expected-version"} {
		t.Run(change, func(t *testing.T) {
			f := newNativeAuthorityFixture(t)
			f.binding.Lifecycle = newNativeContextLifecycle(f.binding.Owner)
			ref := ContextReference{"native_record", "context_hub", 1}
			row := map[string]any{"ref": ref, "status": "active", "owner": f.binding.Owner, "identityRef": ContextReference{"plugin_identity", "context_hub", 1}, "hostIdentityRef": ContextReference{"host_identity", "context_hub", 1}, "manifestDigest": f.binding.Package.manifest.Checksum(), "configurationChecksum": f.binding.Configuration.Checksum(), "relationship": "independent", "parentOwner": nil, "facts": f.facts}
			var previous *ContextReference
			version := uint64(3)
			switch change {
			case "private-storage":
				row["privateStorageResources"] = []NativePrivateStorageResource{{ResourceID: "private_storage", Scope: json.RawMessage(`{"organizationId":"org_one","projectId":null,"workspaceId":null}`), BindingDigest: nativeAuthorityDigest([]byte("protected binding"))}}
			case "rebind":
				previousValue := ref
				previous = &previousValue
				ref.Revision++
				row["ref"] = ref
			case "owner":
				owner := f.binding.Owner
				owner.Generation++
				row["owner"] = owner
			case "configuration":
				row["configurationChecksum"] = nativeAuthorityDigest([]byte("different"))
			case "parent":
				row["parentOwner"] = f.binding.Owner
			case "previous-ref":
				previous = &ref
			case "expected-version":
				version = 0
			}
			f.mutate = func(claims map[string]any) {
				result := map[string]any{"enrollmentRef": ref, "facts": f.facts}
				if change == "result-ref" {
					result["enrollmentRef"] = ContextReference{"another_record", "context_hub", 1}
				}
				if change == "result-facts" {
					facts := map[string]any{}
					for key, value := range f.facts {
						facts[key] = value
					}
					facts["configurationRevision"] = uint64(8)
					result["facts"] = facts
				}
				claims["result"] = result
			}
			original := f.authority.client.options.Exchange
			f.authority.client.options.Exchange = nativeAuthorityTestExchange(func(ctx context.Context, reply string, raw []byte) ([]byte, error) {
				claims := fieldsForClaim(raw, "claims")
				input := fieldsForClaim(claims, "input")
				if !nativeCapabilityEqual(fieldsForClaim(input, "record"), contextJSON(row)) || !nativeCapabilityEqual(fieldsForClaim(claims, "owner"), contextJSON(f.binding.Owner)) || string(fieldsForClaim(input, "expectedVersion")) != "3" {
					t.Fatal("allocated owner or admitted record changed before signing")
				}
				var cancellation ContextReference
				if json.Unmarshal(fieldsForClaim(input, "cancellationRef"), &cancellation) != nil || !contextReferenceValid(cancellation) || cancellation.OwnerHubID != "context_hub" {
					t.Fatal("activation request lacks its own cancellation reference")
				}
				return original.Exchange(ctx, reply, raw)
			})
			committed, err := f.authority.ActivateInstance(context.Background(), f.binding, contextJSON(row), previous, version)
			if change == "none" || change == "rebind" || change == "private-storage" {
				if err != nil || committed != ref || f.exchangeCount != 1 {
					t.Fatal("complete initial activation refused", err)
				}
				if _, err := f.authority.instance(f.binding.Owner); err == nil {
					t.Fatal("activation replaced normal instance admission")
				}
			} else if err == nil || committed != (ContextReference{}) {
				t.Fatal("changed activation admitted")
			} else if change != "result-ref" && change != "result-facts" && f.exchangeCount != 0 {
				t.Fatal("invalid activation reached authority exchange")
			}
		})
	}
}

func TestNativeActivationPreservesPrivateStorageEnrollment(t *testing.T) {
	f := newNativeAuthorityFixture(t)
	resource := NativePrivateStorageResource{ResourceID: "private_storage", Scope: json.RawMessage(`{"organizationId":"org_one","projectId":null,"workspaceId":null}`), BindingDigest: nativeAuthorityDigest([]byte("protected storage binding"))}
	declaration := NativeActivationDeclaration{RecordRef: ContextReference{"native_record", "context_hub", 1}, IdentityRef: ContextReference{"plugin_identity", "context_hub", 1}, Pin: f.binding.Owner.Pin, ManifestDigest: f.binding.Package.manifest.Checksum(), ConfigurationChecksum: f.binding.Configuration.Checksum(), Facts: contextJSON(f.facts), PrivateStorageResources: []NativePrivateStorageResource{resource}}
	cloned := cloneNativeActivationDeclaration(declaration)
	cloned.PrivateStorageResources[0].Scope[0] = 'x'
	if declaration.PrivateStorageResources[0].Scope[0] != '{' {
		t.Fatal("private storage scope shared mutable bytes")
	}
	raw, err := nativeActivationRecord(f.binding, declaration, ContextReference{"host_identity", "context_hub", 1})
	if err != nil || !nativeCapabilityEqual(fieldsForClaim(raw, "privateStorageResources"), contextJSON(declaration.PrivateStorageResources)) {
		t.Fatal("protected private storage enrollment changed", err)
	}
	declaration.PrivateStorageResources = nil
	raw, err = nativeActivationRecord(f.binding, declaration, ContextReference{"host_identity", "context_hub", 1})
	if err != nil || len(fieldsForClaim(raw, "privateStorageResources")) != 0 {
		t.Fatal("private storage enrollment inferred")
	}
}
