package plugins

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

func privateTestDirectory(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("private fixture unavailable")
	}
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private fixture mode")
	}
	return dir
}
func TestOrdinaryOwnerPrivateFileAndStateRoot(t *testing.T) {
	dir := privateTestDirectory(t)
	path := filepath.Join(dir, "private")
	if os.WriteFile(path, []byte("private-marker"), 0600) != nil {
		t.Fatal("fixture write")
	}
	raw, err := ReadOwnerPrivateFile(path, 100)
	if err != nil || string(raw) != "private-marker" {
		t.Fatal("owner admission refused")
	}
	root, err := openLifecycleStateRoot(dir)
	if err != nil {
		t.Fatal("state root refused")
	}
	if closeAdmission(root, nil) != nil {
		t.Fatal("state root close")
	}
	if _, err := ReadOwnerPrivateFile(path, 1); err == nil {
		t.Fatal("oversize accepted")
	}
	if _, err := ReadOwnerPrivateFile(path, manifestLimit+1); err == nil {
		t.Fatal("unsupported bound")
	}
}
func TestOrdinaryPrivateFileUnsafeReplacementRefusals(t *testing.T) {
	for _, kind := range []string{"mode", "parent", "ancestor", "symlink", "hardlink", "fifo", "symlink-ancestor"} {
		t.Run(kind, func(t *testing.T) {
			dir := privateTestDirectory(t)
			parent := filepath.Join(dir, "parent")
			if os.Mkdir(parent, 0700) != nil {
				t.Fatal("fixture directory")
			}
			path := filepath.Join(parent, "private")
			if os.WriteFile(path, []byte("secret"), 0600) != nil {
				t.Fatal("fixture write")
			}
			switch kind {
			case "mode":
				_ = os.Chmod(path, 0644)
			case "parent":
				_ = os.Chmod(parent, 0755)
			case "ancestor":
				_ = os.Chmod(dir, 0777)
			case "symlink":
				_ = os.Rename(path, path+"-original")
				_ = os.Symlink(path+"-original", path)
			case "hardlink":
				_ = os.Link(path, path+"-second")
			case "fifo":
				_ = os.Remove(path)
				if syscall.Mkfifo(path, 0600) != nil {
					t.Fatal("fixture fifo")
				}
			case "symlink-ancestor":
				_ = os.Symlink(parent, filepath.Join(dir, "alias"))
				path = filepath.Join(dir, "alias", "private")
			}
			if _, err := ReadOwnerPrivateFile(path, 100); err == nil {
				t.Fatal("unsafe private file admitted")
			}
		})
	}
}
func aclTestCommand(t *testing.T, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "/bin/chmod", args...).Run(); err != nil {
		t.Fatal("owned ACL fixture command failed")
	}
}
func TestOrdinaryPrivateFileRejectsNativeAllowACL(t *testing.T) {
	for _, target := range []string{"file", "directory", "ancestor"} {
		t.Run(target, func(t *testing.T) {
			dir := privateTestDirectory(t)
			parent := filepath.Join(dir, "parent")
			if os.Mkdir(parent, 0700) != nil {
				t.Fatal("fixture parent")
			}
			path := filepath.Join(parent, "private")
			if os.WriteFile(path, []byte("private-marker"), 0600) != nil {
				t.Fatal("fixture file")
			}
			changed, grant := path, "everyone allow read"
			if target == "directory" {
				changed = parent
				grant = "everyone allow search"
			}
			if target == "ancestor" {
				changed = dir
				grant = "everyone allow delete_child"
			}
			aclTestCommand(t, "+a", grant, changed)
			t.Cleanup(func() { aclTestCommand(t, "-N", changed) })
			if _, err := ReadOwnerPrivateFile(path, 100); err == nil {
				t.Fatal("allow ACL accepted")
			}
		})
	}
}
func signedLifecycleFixture(t *testing.T, change func(map[string]any, map[string]any), wrongSeed bool) ([]byte, string) {
	t.Helper()
	account, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal("fixture key")
	}
	defer account.Wipe()
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal("fixture user")
	}
	defer user.Wipe()
	accountPub, _ := account.PublicKey()
	userPub, _ := user.PublicKey()
	header := map[string]any{"typ": "JWT", "alg": "ed25519-nkey"}
	claims := map[string]any{"iss": accountPub, "sub": userPub, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "nats": map[string]any{"type": "user", "version": 2, "pub": map[string]any{"allow": []string{"amx.control"}}, "sub": map[string]any{"allow": []string{"amx.event"}}}}
	if change != nil {
		change(header, claims)
	}
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	message := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	signature, err := account.Sign([]byte(message))
	if err != nil {
		t.Fatal("fixture signing")
	}
	token := message + "." + base64.RawURLEncoding.EncodeToString(signature)
	seed, _ := user.Seed()
	if wrongSeed {
		other, e := nkeys.CreateUser()
		if e != nil {
			t.Fatal("fixture other user")
		}
		seed, _ = other.Seed()
		other.Wipe()
	}
	raw := []byte("-----BEGIN NATS USER JWT-----\n" + token + "\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n" + string(seed) + "\n------END USER NKEY SEED------\n")
	return raw, accountPub
}
func TestOrdinaryLifecycleCredentialExactSignedPermissions(t *testing.T) {
	raw, account := signedLifecycleFixture(t, nil, false)
	dir := privateTestDirectory(t)
	path := filepath.Join(dir, "credentials")
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("fixture write")
	}
	credential, err := readLifecycleCredential(path, account, []string{"amx.control"}, []string{"amx.event"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(credential)
	if bytes.Contains(encoded, raw) || strings.Contains(fmt.Sprintf("%+v %#v", credential, credential), credential.seed) {
		t.Fatal("credential disclosed")
	}
}
func TestOrdinaryLifecycleCredentialRefusesAliasBroadenedExpiredAndWrongSeed(t *testing.T) {
	cases := map[string]func(map[string]any, map[string]any){"algorithm": func(h, c map[string]any) { h["alg"] = "none" }, "header-extra": func(h, c map[string]any) { h["kid"] = "unknown" }, "claim-alias": func(h, c map[string]any) { c["ISS"] = c["iss"]; delete(c, "iss") }, "permission-alias": func(h, c map[string]any) { n := c["nats"].(map[string]any); n["Pub"] = n["pub"]; delete(n, "pub") }, "broadened": func(h, c map[string]any) {
		c["nats"].(map[string]any)["pub"] = map[string]any{"allow": []string{"amx.control", ">"}}
	}, "denied": func(h, c map[string]any) {
		c["nats"].(map[string]any)["pub"] = map[string]any{"allow": []string{"amx.control"}, "deny": []string{"amx.control"}}
	}, "expired": func(h, c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, "future": func(h, c map[string]any) { c["nbf"] = time.Now().Add(time.Hour).Unix() }, "unknown": func(h, c map[string]any) { c["nats"].(map[string]any)["future-authority"] = true }, "bearer": func(h, c map[string]any) { c["nats"].(map[string]any)["bearer_token"] = true }, "wrong-seed": nil, "duplicate-blocks": nil, "false-marker": nil, "signature": nil}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			raw, account := signedLifecycleFixture(t, change, name == "wrong-seed")
			if name == "duplicate-blocks" {
				raw = append(raw, raw...)
			}
			if name == "signature" {
				token, _, err := parseLifecycleDecorated(raw)
				if err != nil {
					t.Fatal("fixture token")
				}
				parts := strings.Split(token, ".")
				sig, err := base64.RawURLEncoding.DecodeString(parts[2])
				if err != nil {
					t.Fatal("fixture signature")
				}
				sig[0] ^= 1
				parts[2] = base64.RawURLEncoding.EncodeToString(sig)
				raw = bytes.Replace(raw, []byte(token), []byte(strings.Join(parts, ".")), 1)
			}
			if name == "false-marker" {
				raw = bytes.Replace(raw, []byte("BEGIN NATS USER JWT"), []byte("BEGIN ACCOUNT JWT"), 1)
			}
			path := filepath.Join(privateTestDirectory(t), "credentials")
			if os.WriteFile(path, raw, 0600) != nil {
				t.Fatal("fixture write")
			}
			if _, err := readLifecycleCredential(path, account, []string{"amx.control"}, []string{"amx.event"}); err == nil {
				t.Fatal("invalid credential admitted")
			}
		})
	}
}
func TestOrdinaryLifecycleURLPortAndAuthority(t *testing.T) {
	for _, raw := range []string{"tls://127.0.0.1:4222", "tls://[::1]:4222", "tls://broker.example:4222"} {
		if _, err := validateLifecycleURL(raw); err != nil {
			t.Fatal("supported endpoint refused")
		}
	}
	for _, raw := range []string{"nats://127.0.0.1:4222", "nats://[::1]:4222", "tls://127.0.0.1:0", "nats://127.0.0.1:65536", "nats://127.0.0.1:01", "nats://user:secret@127.0.0.1:4222", "nats://broker.example:4222", "tls://broker.example:4222/path", "tls://broker.example:4222?x=secret"} {
		if _, err := validateLifecycleURL(raw); err == nil {
			t.Fatal("invalid endpoint accepted")
		}
	}
}
