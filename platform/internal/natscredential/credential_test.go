package natscredential

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

func credentialBytes(t *testing.T, subscribe []string, change func(map[string]any)) ([]byte, string, string) {
	t.Helper()
	account, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal("account allocation failed")
	}
	defer account.Wipe()
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal("user allocation failed")
	}
	defer user.Wipe()
	accountPublic, _ := account.PublicKey()
	userPublic, _ := user.PublicKey()
	seed, _ := user.Seed()
	claims := map[string]any{"iss": accountPublic, "sub": userPublic, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "nats": map[string]any{"type": "user", "version": 2, "pub": map[string]any{"allow": []string{"amx.command"}}, "sub": map[string]any{"allow": subscribe}}}
	if change != nil {
		change(claims)
	}
	header, _ := json.Marshal(map[string]string{"typ": "JWT", "alg": "ed25519-nkey"})
	body, _ := json.Marshal(claims)
	signed := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	signature, err := account.Sign([]byte(signed))
	if err != nil {
		t.Fatal("account signing failed")
	}
	token := signed + "." + base64.RawURLEncoding.EncodeToString(signature)
	return []byte("-----BEGIN NATS USER JWT-----\n" + token + "\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n" + string(seed) + "\n------END USER NKEY SEED------\n"), accountPublic, userPublic
}
func TestCredentialMaterialAndRedaction(t *testing.T) {
	prefix := "_INBOX.application_000001"
	raw, account, user := credentialBytes(t, []string{prefix + ".>"}, nil)
	credential, err := Validate(raw, Policy{AccountPublicKey: account, PublishSubjects: []string{"amx.command"}, SubscribeSubjects: []string{prefix + ".>"}, PrivateInbox: true})
	if err != nil || credential.PublicKey() != user {
		t.Fatal("enrolled credential refused")
	}
	seed := credential.Seed()
	before := bytes.Clone(seed)
	seed[0] ^= 1
	if !bytes.Equal(credential.Seed(), before) {
		t.Fatal("seed accessor shared mutable bytes")
	}
	encoded, _ := json.Marshal(credential)
	printed := fmt.Sprintf("%s %v %+v %#v", credential, credential, credential, credential) + string(encoded)
	if strings.Contains(printed, credential.JWT()) || strings.Contains(printed, string(before)) || bytes.Contains(encoded, raw) {
		t.Fatal("private material appeared in diagnostics")
	}
}
func TestCredentialPolicyAndSignedRefusals(t *testing.T) {
	prefix := "_INBOX.application_000001"
	changes := map[string]func(map[string]any){
		"valid":              nil,
		"expired":            func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() },
		"not yet active":     func(c map[string]any) { c["nbf"] = time.Now().Add(time.Hour).Unix() },
		"wrong seed subject": func(c map[string]any) { c["sub"] = c["iss"] },
		"response permission": func(c map[string]any) {
			c["nats"].(map[string]any)["resp"] = map[string]any{"max": 1, "ttl": 1000000000}
		},
		"bearer":            func(c map[string]any) { c["nats"].(map[string]any)["bearer_token"] = true },
		"unknown claim":     func(c map[string]any) { c["future"] = true },
		"broad publication": func(c map[string]any) { c["nats"].(map[string]any)["pub"] = map[string]any{"allow": []string{">"}} },
		"broad subscription": func(c map[string]any) {
			c["nats"].(map[string]any)["sub"] = map[string]any{"allow": []string{"_INBOX.>"}}
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			raw, account, _ := credentialBytes(t, []string{prefix + ".>"}, change)
			policy := Policy{AccountPublicKey: account, PublishSubjects: []string{"amx.command"}, SubscribeSubjects: []string{prefix + ".>"}, PrivateInbox: true}
			_, err := Validate(raw, policy)
			if (err == nil) != (name == "valid") {
				t.Fatal("signed policy result differed")
			}
		})
	}
	raw, account, _ := credentialBytes(t, []string{prefix + ".>"}, nil)
	policy := Policy{AccountPublicKey: account, PublishSubjects: []string{"amx.command"}, SubscribeSubjects: []string{prefix + ".>"}}
	if _, err := Validate(raw, policy); err == nil {
		t.Fatal("literal subscription mode accepted a wildcard")
	}
	policy.PrivateInbox = true
	policy.AccountPublicKey = "wrong-account"
	if _, err := Validate(raw, policy); err == nil {
		t.Fatal("wrong enrolled account accepted")
	}
	for _, raw := range [][]byte{nil, bytes.Repeat([]byte{'x'}, MaxBytes+1)} {
		if _, err := Validate(raw, policy); err == nil {
			t.Fatal("credential byte limit ignored")
		}
	}
}
