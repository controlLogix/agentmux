package plugins

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestNativeEnrolledKeysPythonState(t *testing.T) {
	p := startNativePythonPeer(t, true)
	response := p.exchange(p.ctx, map[string]bool{"authorityState": true})
	var encoded string
	if json.Unmarshal(response["state"], &encoded) != nil {
		t.Fatal("authority record missing")
	}
	record, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var owner struct {
		State json.RawMessage `json:"state"`
	}
	if json.Unmarshal(record, &owner) != nil || nativeAuthoritySchema("record", record) != nil {
		t.Fatal("retained authority record invalid")
	}
	ref := func(id string) ContextReference { return ContextReference{ID: id, OwnerHubID: "hub-one", Revision: 1} }
	k := &NativeEnrolledKeys{options: NativeEnrolledKeyOptions{ProfileID: "profile-one", HubID: "hub-one", AuthorityID: "authority-one", OrganizationID: "org-one", HostTransportRef: ref("host-transport"), HostIdentityRef: ref("host"), IssuerRef: ref("issuer"), IssuerIdentityRef: ref("service"), IssuerInstanceID: "ingress-one"}, now: time.Now}
	service := NativeCapabilityServiceBinding{ProfileID: "profile-one", HubID: "hub-one", ServiceID: "storage-owner", ServiceInstanceID: "ingress-one", ServiceIdentityRef: ref("service"), SigningKeyRef: ref("issuer")}
	for _, purpose := range []string{"agentmux-native-authority-response-v1", "agentmux-capability-service-request-v1"} {
		key, err := k.resolve(owner.State, ref("issuer"), purpose, nil)
		if err != nil || !bytes.Equal(key.PublicKey, p.public) {
			t.Fatal("current issuer was refused", purpose, err)
		}
	}
	if _, err := k.resolve(owner.State, ref("host-transport"), "agentmux-native-authority-request-v1", nil); err != nil {
		t.Fatal("current host was refused", err)
	}
	t.Run("current authority collections remain closed", func(t *testing.T) {
		var state map[string]any
		_ = json.Unmarshal(owner.State, &state)
		collections := []string{"legacyAliases", "secretReferences", "ordinarySecretReferences", "applicationAccounts"}
		scope := map[string]any{"organizationId": "org-one", "projectId": "project-one", "workspaceId": nil}
		interval := map[string]any{"status": "active", "issuedAt": "2026-01-01T00:00:00Z", "expiresAt": "2099-01-01T00:00:00Z"}
		pkg := fixturePackage(t, fixtureManifest("native_schema_test"), map[string][]byte{"schemas/config.json": []byte(`{"type":"object"}`)})
		state["legacyAliases"] = []any{map[string]any{"ref": ref("alias"), "status": "active", "identityRef": ref("host"), "sourceHubId": "hub-one", "scope": scope, "instanceOwner": OwnerReference{Pin: pkg.Pin(), InstanceID: "plugin-one", Epoch: strings.Repeat("a", 64), Generation: 1}, "registrationGeneration": 1, "canonicalSession": "project-role-agent", "alias": "ordinary-account"}}
		secret := map[string]any{"ref": ref("secret"), "kind": "nats-account-issuer", "scope": scope, "profileId": "profile-one", "ownerIdentityRef": ref("service")}
		ordinary := map[string]any{"ref": ref("ordinary"), "generationRef": ref("generation"), "profileId": "profile-one", "scope": scope, "ownerIdentityRef": ref("service"), "ownerAudience": map[string]any{"hubId": "hub-one", "serviceId": "secret-owner"}, "callerIdentityRef": ref("host"), "consumerRef": ref("consumer"), "purposeRef": ref("purpose")}
		account := map[string]any{"ref": ref("application-account"), "profileId": "profile-one", "scope": scope, "accountPublicKey": "A" + strings.Repeat("A", 55), "administratorIdentityRef": ref("service"), "administratorTransportRef": ref("host-transport"), "administratorCredentialRef": ref("administrator-credential"), "accountIssuerRef": ref("secret")}
		for _, entry := range []map[string]any{secret, ordinary, account} {
			for key, value := range interval {
				entry[key] = value
			}
		}
		state["secretReferences"], state["ordinarySecretReferences"], state["applicationAccounts"] = []any{secret}, []any{ordinary}, []any{account}
		raw, _ := json.Marshal(state)
		if _, err := k.resolve(raw, ref("host-transport"), "agentmux-native-authority-request-v1", nil); err != nil {
			t.Fatal("current authority collections refused", err)
		}
		for _, name := range append(collections, "unknownAuthorityCollection") {
			state[name] = []any{map[string]any{}}
			invalid, _ := json.Marshal(state)
			if _, err := k.resolve(invalid, ref("host-transport"), "agentmux-native-authority-request-v1", nil); err == nil {
				t.Fatal("malformed or unknown authority collection accepted", name)
			}
			delete(state, name)
		}
	})
	if _, err := k.resolve(owner.State, service.SigningKeyRef, "agentmux-capability-service-response-v1", &service); err != nil {
		t.Fatal("current service was refused", err)
	}
	mutations := map[string]func(map[string]any){
		"issuer revocation": func(s map[string]any) { s["issuers"].([]any)[0].(map[string]any)["status"] = "revoked" },
		"issuer identity revocation": func(s map[string]any) {
			for _, v := range s["identities"].([]any) {
				r := v.(map[string]any)
				if r["ref"].(map[string]any)["id"] == "service" {
					r["status"] = "revoked"
				}
			}
		},
		"issuer instance mismatch": func(s map[string]any) { s["issuers"].([]any)[0].(map[string]any)["instanceId"] = "another-instance" },
		"issuer expiry": func(s map[string]any) {
			r := s["issuers"].([]any)[0].(map[string]any)
			r["issuedAt"] = "2026-01-01T00:00:00Z"
			r["expiresAt"] = "2026-01-02T00:00:00Z"
		},
		"issuer not active yet": func(s map[string]any) {
			r := s["issuers"].([]any)[0].(map[string]any)
			r["issuedAt"] = "2098-01-01T00:00:00Z"
			r["expiresAt"] = "2099-01-01T00:00:00Z"
		},
		"duplicate key reference": func(s map[string]any) { v := s["issuers"].([]any); s["issuers"] = append(v, v[0]) },
		"wrong profile":           func(s map[string]any) { s["profileId"] = "other-profile" },
		"wrong organization":      func(s map[string]any) { s["organizationId"] = "other-org" },
		"invalid public key":      func(s map[string]any) { s["issuers"].([]any)[0].(map[string]any)["publicKey"] = "broken" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var state map[string]any
			_ = json.Unmarshal(owner.State, &state)
			mutate(state)
			raw, _ := json.Marshal(state)
			if _, err := k.resolve(raw, ref("issuer"), "agentmux-native-authority-response-v1", nil); err == nil {
				t.Fatal("changed enrolled state was accepted")
			}
		})
	}
	for _, field := range []string{"identity", "instance", "hub", "profile", "key"} {
		t.Run("service "+field, func(t *testing.T) {
			changed := service
			switch field {
			case "identity":
				changed.ServiceIdentityRef = ref("host")
			case "instance":
				changed.ServiceInstanceID = "other-instance"
			case "hub":
				changed.HubID = "other-hub"
			case "profile":
				changed.ProfileID = "other-profile"
			case "key":
				changed.SigningKeyRef = ref("host-transport")
			}
			if _, err := k.resolve(owner.State, changed.SigningKeyRef, "agentmux-capability-service-response-v1", &changed); err == nil {
				t.Fatal("changed service association was accepted")
			}
		})
	}
	if _, err := k.resolve(owner.State, ref("issuer"), "unregistered-purpose", nil); err == nil {
		t.Fatal("unknown signing purpose accepted")
	}
}
func TestNativeEnrolledKeysRetainedStream(t *testing.T) {
	k := &NativeEnrolledKeys{options: NativeEnrolledKeyOptions{Stream: "IDENTITY", HubID: "hub-one", OrganizationID: "org-one", AuthorityID: "authority-one", StreamCreated: time.Now().UTC(), MaxBytes: 4194304, Replicas: 1}}
	info := nats.StreamInfo{Created: k.options.StreamCreated, Config: nats.StreamConfig{Name: "IDENTITY", Subjects: []string{k.subject()}, Storage: nats.FileStorage, Retention: nats.LimitsPolicy, Discard: nats.DiscardNew, MaxBytes: k.options.MaxBytes, MaxMsgSize: 65536, MaxMsgs: -1, MaxMsgsPerSubject: -1, DenyDelete: true, DenyPurge: true, Replicas: 1}, State: nats.StreamState{Msgs: 2, LastSeq: 2, FirstSeq: 1, Bytes: 2000}}
	raw, _ := json.Marshal(info)
	if _, err := k.validateStream(raw); err != nil {
		t.Fatal("retained stream refused", err)
	}
	for _, field := range []string{"created", "deny_delete", "deny_purge", "allow_msg_schedules", "allow_msg_counter", "allow_msg_ttl", "max_age", "messages", "last_seq", "first_seq", "num_deleted", "subjects"} {
		t.Run(field, func(t *testing.T) {
			var doc map[string]any
			_ = json.Unmarshal(raw, &doc)
			config := doc["config"].(map[string]any)
			state := doc["state"].(map[string]any)
			switch field {
			case "created":
				doc[field] = "2020-01-01T00:00:00Z"
			case "deny_delete", "deny_purge":
				config[field] = false
			case "allow_msg_schedules", "allow_msg_counter", "allow_msg_ttl":
				config[field] = true
			case "max_age":
				config[field] = 1
			case "first_seq":
				state[field] = 2
			case "subjects":
				config[field] = []string{"other"}
			default:
				state[field] = 1
			}
			changed, _ := json.Marshal(doc)
			if _, err := k.validateStream(changed); err == nil {
				t.Fatal("unsafe stream accepted")
			}
		})
	}
}

func TestNativeAuthorityPrivateInboxCredential(t *testing.T) {
	prefix := "_INBOX.host_native_000001"
	for _, subscriptions := range [][]string{{prefix + ".>"}, {"_INBOX.>"}, {prefix + ".>", "_INBOX.other.>"}} {
		raw, account := signedLifecycleFixture(t, func(_ map[string]any, claims map[string]any) {
			claims["nats"].(map[string]any)["sub"] = map[string]any{"allow": subscriptions}
		}, false)
		path := privateTestDirectory(t) + "/host.creds"
		if os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("private credential write failed")
		}
		_, err := readLifecycleCredentialPolicy(path, account, []string{"amx.control"}, []string{prefix + ".>"}, true)
		expected := len(subscriptions) == 1 && subscriptions[0] == prefix+".>"
		if (err == nil) != expected {
			t.Fatal("private inbox credential policy differed")
		}
	}
}
