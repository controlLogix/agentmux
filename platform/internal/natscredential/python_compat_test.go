package natscredential

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The same account-signed decorated bytes go through both production validators.
// This single bounded Python process has no broker, files or network work.
func TestPythonCredentialCompatibility(t *testing.T) {
	python := os.Getenv("AGENTMUX_NATS_CREDENTIAL_PYTHON")
	if python == "" {
		t.Skip("prepared Python NATS and SDK runtime required")
	}
	prefix := "_INBOX.application_000001"
	type vector struct {
		Name      string   `json:"name"`
		Raw       []byte   `json:"raw"`
		Account   string   `json:"account"`
		Publish   []string `json:"publish"`
		Subscribe []string `json:"subscribe"`
		Private   bool     `json:"privateInbox"`
	}
	changes := map[string]func(map[string]any){
		"allowed": nil,
		"broad inbox": func(c map[string]any) {
			c["nats"].(map[string]any)["sub"] = map[string]any{"allow": []string{"_INBOX.>"}}
		},
		"response grant":    func(c map[string]any) { c["nats"].(map[string]any)["resp"] = map[string]any{"max": 1} },
		"expired":           func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() },
		"future activation": func(c map[string]any) { c["nbf"] = time.Now().Add(time.Hour).Unix() },
		"broad publication": func(c map[string]any) { c["nats"].(map[string]any)["pub"] = map[string]any{"allow": []string{">"}} },
		"unknown claim":     func(c map[string]any) { c["future"] = true },
	}
	var vectors []vector
	for name, change := range changes {
		raw, account, _ := credentialBytes(t, []string{prefix + ".>"}, change)
		vectors = append(vectors, vector{name, raw, account, []string{"amx.command"}, []string{prefix + ".>"}, true})
	}
	raw, account, _ := credentialBytes(t, []string{prefix + ".>"}, nil)
	_, otherAccount, _ := credentialBytes(t, []string{prefix + ".>"}, nil)
	vectors = append(vectors, vector{"wrong account", raw, otherAccount, []string{"amx.command"}, []string{prefix + ".>"}, true})
	token := strings.Split(string(raw), "\n")[1]
	parts := strings.Split(token, ".")
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	signature[0] ^= 1
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	vectors = append(vectors, vector{"wrong signature", bytes.Replace(raw, []byte(token), []byte(strings.Join(parts, ".")), 1), account, []string{"amx.command"}, []string{prefix + ".>"}, true})
	broad, broadAccount, _ := credentialBytes(t, []string{"_INBOX.>"}, nil)
	vectors = append(vectors, vector{"broad enrolled inbox", broad, broadAccount, []string{"amx.command"}, []string{"_INBOX.>"}, true})
	literal, literalAccount, _ := credentialBytes(t, []string{"amx.event"}, nil)
	vectors = append(vectors, vector{"literal", literal, literalAccount, []string{"amx.command"}, []string{"amx.event"}, false})
	_, seed, err := ParseDecorated(raw)
	if err != nil {
		t.Fatal("credential fixture extraction failed")
	}
	damagedSeed := bytes.Clone(seed)
	if damagedSeed[10] == 'A' {
		damagedSeed[10] = 'B'
	} else {
		damagedSeed[10] = 'A'
	}
	vectors = append(vectors, vector{"bad seed checksum", bytes.Replace(raw, seed, damagedSeed, 1), account, []string{"amx.command"}, []string{prefix + ".>"}, true})
	var expected []bool
	for _, v := range vectors {
		_, err := Validate(v.Raw, Policy{AccountPublicKey: v.Account, PublishSubjects: v.Publish, SubscribeSubjects: v.Subscribe, PrivateInbox: v.Private})
		expected = append(expected, err == nil)
		if (err == nil) != (v.Name == "allowed" || v.Name == "literal") {
			t.Fatal("Go credential control result differed", v.Name)
		}
	}
	input, _ := json.Marshal(vectors)
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal("repository location unavailable")
	}
	script := `import base64,json,sys
from native_security.nats_credentials import validate,CredentialError
results=[]
for row in json.load(sys.stdin):
 try:
  validate(base64.b64decode(row['raw'],validate=True),account_public_key=row['account'],publish_subjects=row['publish'],subscribe_subjects=row['subscribe'],private_inbox=row['privateInbox'])
  results.append(True)
 except CredentialError:
  results.append(False)
print(json.dumps(results))`
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, python, "-c", script)
	command.Dir = root
	command.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(root, "sdk/python")+string(os.PathListSeparator)+root, "PYTHONDONTWRITEBYTECODE=1")
	command.Stdin = bytes.NewReader(input)
	command.WaitDelay = 2 * time.Second
	output, err := command.Output()
	if err != nil {
		t.Fatal("Python credential validator did not complete")
	}
	var actual []bool
	if json.Unmarshal(output, &actual) != nil || len(actual) != len(expected) {
		t.Fatal("Python credential result document invalid")
	}
	for i := range expected {
		if actual[i] != expected[i] {
			t.Fatal("credential validation differed across languages", vectors[i].Name)
		}
	}
}
