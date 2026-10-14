//go:build linux || darwin

package protocol

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func aliasKey(t *testing.T, raw []byte, key, alias string) []byte {
	t.Helper()
	needle := []byte(`"` + key + `":`)
	if bytes.Count(raw, needle) == 0 {
		t.Fatal("fixture field not found")
	}
	return bytes.Replace(raw, needle, []byte(`"`+alias+`":`), 1)
}

func TestExactFieldNamesOnValidFrames(t *testing.T) {
	now := time.Now().UTC()
	members := []Member{}
	for _, role := range Roles() {
		members = append(members, Member{role, "ready", strings.Repeat("a", 32), 1, now.Format(time.RFC3339Nano)})
	}
	event := testEvent(now)
	event.Role, event.Members = "kernel-lifecycle", members
	command := Command{Version, "kernel-observation-command", testScope(), "boot", "announce"}
	snapshot := Snapshot{Version, "kernel-info", testScope(), "exported-status", strings.Repeat("a", 32), 1, now.Format(time.RFC3339Nano), now.Add(time.Second).Format(time.RFC3339Nano), "ready", members}
	frames := []struct {
		name   string
		value  any
		decode func([]byte) error
	}{
		{"event", event, func(b []byte) error {
			_, err := DecodeEvent(b, testScope(), "kernel-lifecycle", now, time.Second)
			return err
		}},
		{"command", command, func(b []byte) error { _, err := DecodeCommand(b, testScope(), "boot"); return err }},
		{"snapshot", snapshot, func(b []byte) error { _, err := DecodeSnapshot(b, testScope(), now, time.Second); return err }},
	}
	for _, frame := range frames {
		t.Run(frame.name, func(t *testing.T) {
			raw := mustJSON(frame.value)
			if err := frame.decode(raw); err != nil {
				t.Fatal("valid frame rejected")
			}
			keys := []string{"schemaVersion", "scope", "instanceId"}
			if frame.name != "command" {
				keys = append(keys, "role", "members", "observedAt")
			}
			for _, key := range keys {
				t.Run(key, func(t *testing.T) {
					alias := strings.ToUpper(key[:1]) + key[1:]
					mutated := aliasKey(t, raw, key, alias)
					// Go's default decoder accepts the alias and preserves the valid
					// frame. The closed decoder must reject the spelling itself.
					var baseline any
					switch frame.name {
					case "event":
						baseline = &Event{}
					case "command":
						baseline = &Command{}
					default:
						baseline = &Snapshot{}
					}
					if json.Unmarshal(mutated, baseline) != nil || !bytes.Equal(mustJSON(baseline), raw) {
						t.Fatal("alias control changed frame values")
					}
					if frame.decode(mutated) == nil {
						t.Fatal("field alias accepted")
					}
				})
			}
			if frame.name != "command" {
				mutated := bytes.Replace(raw, []byte(`"members":[{"role":`), []byte(`"members":[{"Role":`), 1)
				if bytes.Equal(mutated, raw) || frame.decode(mutated) == nil {
					t.Fatal("nested member alias accepted")
				}
			}
		})
	}
}

func TestExactCredentialNamesAndEnvironmentReload(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(dir, 0700) != nil {
		t.Fatal("private fixture directory unavailable")
	}
	path := filepath.Join(dir, "credentials.json")
	c := validCredentials()
	raw := mustJSON(c)
	for key, value := range map[string]string{"AGENTMUX_KERNEL_ROLE": c.Role, "AGENTMUX_KERNEL_API_MAJOR": "1", "AGENTMUX_NATS_CREDS_FILE": path, "AGENTMUX_INSTANCE_ID": c.Scope.InstanceID, "AGENTMUX_PROFILE_ID": c.Scope.ProfileID, "AGENTMUX_NATS_URL": c.NATSURL} {
		t.Setenv(key, value)
	}
	write := func(data []byte) {
		t.Helper()
		if os.WriteFile(path, data, 0600) != nil {
			t.Fatal("private fixture write failed")
		}
	}
	write(raw)
	if _, err := LoadEnvironment(); err != nil {
		t.Fatal("valid environment credentials rejected")
	}
	for _, key := range []string{"schemaVersion", "role", "username", "password", "natsUrl", "scope", "hubId", "instanceId", "profileId", "assemblyDigest", "releaseManifestDigest", "releaseVersion"} {
		t.Run(key, func(t *testing.T) {
			alias := strings.ToUpper(key[:1]) + key[1:]
			mutated := aliasKey(t, raw, key, alias)
			var baseline Credentials
			if json.Unmarshal(mutated, &baseline) != nil || baseline != c {
				t.Fatal("alias fixture changed valid credentials")
			}
			write(mutated)
			var out Credentials
			if StrictJSON(mutated, &out) == nil {
				t.Fatal("credential alias accepted")
			}
			if _, err := LoadEnvironment(); err == nil || err.Error() != "kernel_credentials_invalid" {
				t.Fatal("environment alias not rejected at parser")
			}
		})
	}
	for _, pair := range []string{`,"Role":"boot"}`, `,"Scope":` + string(mustJSON(c.Scope)) + `}`, `,"Password":"` + c.Password + `"}`} {
		write(append(append([]byte{}, raw[:len(raw)-1]...), []byte(pair)...))
		if _, err := LoadEnvironment(); err == nil {
			t.Fatal("literal field plus alias accepted")
		}
	}
	write(raw)
	if _, err := LoadEnvironment(); err != nil {
		t.Fatal("valid reload rejected after aliases")
	}
}

func TestClosedJSONMapsBoundsAndTextCompatibility(t *testing.T) {
	type item struct {
		Role string `json:"role"`
	}
	type document struct {
		Items   map[string]*item `json:"items"`
		Members [1]item          `json:"members"`
		Text    string           `json:"text,omitempty"`
	}
	var out document
	good := []byte(`{"items":{"Role":{"role":"boot"}},"members":[{"role":"boot"}],"text":"\ud800"}`)
	if DecodeClosedJSON(good, &out, 65536) != nil || out.Items["Role"].Role != "boot" || out.Text != "\ufffd" {
		t.Fatal("declared map or existing surrogate behavior changed")
	}
	for _, bad := range []string{`{"items":{"Role":{"Role":"boot"}}}`, `{"members":[{"Role":"boot"}]}`, `{"items":{},"Items":{}}`, `{"text":"a","te\u0078t":"b"}`, `{"text":"a"} {}`, strings.Repeat("[", 18) + "0" + strings.Repeat("]", 18)} {
		if DecodeClosedJSON([]byte(bad), &out, 65536) == nil {
			t.Fatal("closed JSON boundary accepted malformed data")
		}
	}
	large := []byte(`{"text":"` + strings.Repeat("a", 9000) + `"}`)
	if StrictJSON(large, &out) == nil || DecodeClosedJSON(large, &out, 65536) != nil {
		t.Fatal("wire and private config limits not separate")
	}
	for _, limit := range []int{-1, 0, 65537} {
		if DecodeClosedJSON(good, &out, limit) == nil {
			t.Fatal("invalid caller limit accepted")
		}
	}
	if DecodeClosedJSON(bytes.Repeat([]byte(" "), 65537), &out, 65536) == nil || DecodeClosedJSON([]byte{0xff}, &out, 65536) == nil || DecodeClosedJSON(good, nil, 65536) == nil {
		t.Fatal("hard size, UTF8 or destination guard failed")
	}
	var nilOut *document
	if DecodeClosedJSON(good, nilOut, 65536) == nil {
		t.Fatal("nil pointer destination accepted")
	}
}

func TestExactFrameNamesAfterRealBrokerDelivery(t *testing.T) {
	binary := os.Getenv("AGENTMUX_TEST_NATS")
	if binary == "" {
		t.Fatal("prepared NATS executable required")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("fixture port unavailable")
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if listener.Close() != nil {
		t.Fatal("fixture port close failed")
	}
	dir := t.TempDir()
	log, err := os.OpenFile(filepath.Join(dir, "broker.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("fixture log unavailable")
	}
	cmd := exec.Command(binary, "-a", "127.0.0.1", "-p", strconv.Itoa(port))
	cmd.Stdout, cmd.Stderr = log, log
	if cmd.Start() != nil {
		log.Close()
		t.Fatal("fixture broker start failed")
	}
	t.Cleanup(func() {
		if cmd.Process.Kill() != nil {
			t.Error("owned broker stop failed")
		}
		_ = cmd.Wait()
		if log.Close() != nil {
			t.Error("fixture log close failed")
		}
	})
	var conn *nats.Conn
	end := time.Now().Add(3 * time.Second)
	for time.Now().Before(end) {
		conn, err = nats.Connect("nats://127.0.0.1:"+strconv.Itoa(port), nats.NoReconnect(), nats.Timeout(100*time.Millisecond))
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("fixture broker unavailable")
	}
	defer conn.Close()
	sub, err := conn.SubscribeSync("amx.v1.h.fixture_hub.kernel.internal.boot.event")
	if err != nil || conn.FlushTimeout(time.Second) != nil {
		t.Fatal("fixture subscription unavailable")
	}
	defer sub.Unsubscribe()
	now := time.Now().UTC()
	raw := mustJSON(testEvent(now))
	for _, key := range []string{"", "role", "scope", "instanceId"} {
		data := raw
		if key != "" {
			data = aliasKey(t, raw, key, strings.ToUpper(key[:1])+key[1:])
		}
		if conn.Publish(sub.Subject, data) != nil || conn.FlushTimeout(time.Second) != nil {
			t.Fatal("fixture publish failed")
		}
		msg, err := sub.NextMsg(time.Second)
		if err != nil || !bytes.Equal(msg.Data, data) {
			t.Fatal("actual broker frame delivery changed")
		}
		_, err = DecodeEvent(msg.Data, testScope(), "boot", now, time.Second)
		if (key == "") != (err == nil) {
			t.Fatal("actual delivered frame casing admission failed")
		}
	}
}
