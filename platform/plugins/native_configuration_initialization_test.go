package plugins

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestNativeConfigurationInitializationRequiresDistinctSignedPreparation(t *testing.T) {
	f := configurationWireFixture(t)
	f.binding.ConfigurationRef.Revision = 6
	cancellation := ContextReference{"initialization_cancel", "context_hub", 1}
	prepared := f.request(t, "configuration-set", 0)
	var envelope map[string]any
	json.Unmarshal(prepared, &envelope)
	operation := envelope["operation"].(map[string]any)
	operation["cancellationRef"] = cancellation
	operation["expectedVersion"] = uint64(6)
	attestation := envelope["ingressAttestation"].(map[string]any)
	claims := attestation["claims"].(map[string]any)
	claims["operation"] = operation
	signed, err := nativeAuthoritySign(contextJSON(claims), f.authority.response)
	if err != nil {
		t.Fatal(err)
	}
	envelope["ingressAttestation"] = json.RawMessage(signed)
	prepared = contextJSON(envelope)
	f.authority.mutate = func(claims map[string]any) {
		claims["result"] = map[string]any{"envelopeBytes": base64.StdEncoding.EncodeToString(prepared)}
	}
	original := f.authority.authority.client.options.Exchange
	f.authority.authority.client.options.Exchange = nativeAuthorityTestExchange(func(ctx context.Context, reply string, raw []byte) ([]byte, error) {
		claims := fieldsForClaim(raw, "claims")
		if string(fieldsForClaim(claims, "method")) != `"prepare-configuration-initialization"` || !nativeCapabilityEqual(fieldsForClaim(fieldsForClaim(claims, "input"), "payload"), fieldsForClaim(prepared, "payload")) {
			t.Fatal("initialization used read/watch authorization or changed actual configuration")
		}
		return original.Exchange(ctx, reply, raw)
	})
	raw, err := f.authority.authority.prepareConfigurationInitialization(context.Background(), f.authority.binding, f.binding.ConfigurationRef, contextJSON(f.authority.facts), cancellation)
	if err != nil || !nativeCapabilityEqual(raw, prepared) || f.authority.exchangeCount != 1 {
		t.Fatal("signed initialization preparation refused", err)
	}
	if raw, err := f.authority.authority.prepareConfigurationInitialization(context.Background(), f.authority.binding, ContextReference{"configuration_one", "context_hub", 7}, contextJSON(f.authority.facts), cancellation); raw != nil || err == nil || f.authority.exchangeCount != 1 {
		t.Fatal("initialization silently advanced admitted revision")
	}
}

func TestNativeConfigurationInitializationReplyMatchesExactSet(t *testing.T) {
	for _, change := range []string{"none", "bytes", "secrets", "revision", "schema"} {
		t.Run(change, func(t *testing.T) {
			f := configurationWireFixture(t)
			f.binding.ConfigurationRef.Revision = 6
			request := f.request(t, "configuration-set", 0)
			reply := f.reply(t, request, func(claims map[string]any) {
				state := claims["state"].(map[string]any)
				switch change {
				case "bytes":
					state["configurationBytes"] = base64.StdEncoding.EncodeToString([]byte(`{"changed":true}`))
					state["configurationChecksum"] = nativeAuthorityDigest([]byte(`{"changed":true}`))
				case "secrets":
					state["secretReferences"] = []ContextReference{{"another_secret", "context_hub", 1}}
				case "revision":
					state["revision"] = uint64(8)
					claims["configurationRef"] = ContextReference{"configuration_one", "context_hub", 8}
				case "schema":
					state["schemaRef"] = "other.json"
				}
			})
			snapshot, _, err := verifyNativeConfigurationResponse(context.Background(), reply, request, f.authority.binding, f.binding, f.keys)
			if change == "none" {
				if err != nil || snapshot.Configuration.Checksum() != f.authority.binding.Configuration.Checksum() || snapshot.Revision != 7 {
					t.Fatal("matching signed initialization refused", err)
				}
			} else if err == nil {
				t.Fatal("changed signed initialization disclosed")
			}
		})
	}
}
