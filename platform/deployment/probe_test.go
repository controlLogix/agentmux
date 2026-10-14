package deployment

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/nats-io/nats.go"
)

func deploymentSecrets(t *testing.T) (communication.Credentials, string) {
	t.Helper()
	random := func() string {
		var b [24]byte
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal("fixture entropy failed")
		}
		return hex.EncodeToString(b[:])
	}
	c := communication.Credentials{}
	for _, name := range []string{communication.Administrator, communication.OrdinaryPlugin, "boot", "kernel-lifecycle", "internal-communication", "exported-status"} {
		c[name] = random()
	}
	return c, random()
}

type healthFixture struct {
	options        ProbeOptions
	config, binary string
	cmd            *exec.Cmd
	log            *os.File
	monitor        string
}

func newHealthFixture(t *testing.T, denyWrite bool) *healthFixture {
	t.Helper()
	binary := os.Getenv("AGENTMUX_TEST_NATS")
	if binary == "" {
		t.Fatal("prepared disposable NATS executable required")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("fixture port unavailable")
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	dir := t.TempDir()
	c, password := deploymentSecrets(t)
	p := StorageProfile{HubID: "fixture_hub", ServerName: "fixture_server", Domain: "fixture_domain", StoreDirectory: filepath.Join(dir, "store"), MaxMemoryBytes: 1024 * 1024, MaxFileBytes: 4 * 1024 * 1024, Listener: communication.Listener{Mode: communication.NativeLoopback, Port: port}}
	raw, err := BuildLocalConfig(p, c, password)
	if err != nil {
		t.Fatal(err)
	}
	if denyWrite {
		var cfg map[string]any
		json.Unmarshal(raw, &cfg)
		permissions := cfg["accounts"].(map[string]any)[HealthAccount].(map[string]any)["users"].([]any)[0].(map[string]any)["permissions"].(map[string]any)
		allow := permissions["publish"].(map[string]any)["allow"].([]any)
		permissions["publish"].(map[string]any)["allow"] = allow[1:]
		raw = fixtureConfigJSON(t, cfg)
	}
	monitorListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("fixture monitor port unavailable")
	}
	monitor := monitorListener.Addr().String()
	monitorListener.Close()
	var cfg map[string]any
	json.Unmarshal(raw, &cfg)
	cfg["http"] = monitor
	raw = fixtureConfigJSON(t, cfg)
	path := filepath.Join(dir, "nats.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal("fixture config write failed")
	}
	log, err := os.OpenFile(filepath.Join(dir, "broker.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal("fixture log unavailable")
	}
	f := &healthFixture{options: ProbeOptions{Endpoint: "nats://127.0.0.1:" + strconv.Itoa(port), Password: password, HubID: p.HubID, ServerName: p.ServerName, Domain: p.Domain, ServerVersion: "2.15.0", Timeout: 2 * time.Second}, config: path, binary: binary, log: log}
	f.monitor = "http://" + monitor + "/varz"
	t.Cleanup(func() { f.stop(t); log.Close() })
	f.start(t)
	return f
}

func fixtureConfigJSON(t *testing.T, cfg map[string]any) []byte {
	t.Helper()
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(cfg) != nil {
		t.Fatal("fixture encoding failed")
	}
	return buf.Bytes()
}

func (f *healthFixture) start(t *testing.T) {
	t.Helper()
	cmd := exec.Command(f.binary, "-c", f.config)
	cmd.Stdout = f.log
	cmd.Stderr = f.log
	if cmd.Start() != nil {
		t.Fatal("fixture broker start failed")
	}
	f.cmd = cmd
	end := time.Now().Add(10 * time.Second)
	for time.Now().Before(end) {
		nc, err := nats.Connect(f.options.Endpoint, nats.UserInfo(HealthUser, f.options.Password), nats.Timeout(100*time.Millisecond), nats.NoReconnect())
		if err == nil {
			nc.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("fixture broker unavailable")
}
func (f *healthFixture) stop(t *testing.T) {
	t.Helper()
	if f.cmd == nil {
		return
	}
	cmd := f.cmd
	f.cmd = nil
	_ = cmd.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Error("fixture broker required forced reap")
	}
}
func (f *healthFixture) connect(t *testing.T) (*nats.Conn, nats.JetStreamContext) {
	t.Helper()
	nc, err := nats.Connect(f.options.Endpoint, nats.UserInfo(HealthUser, f.options.Password), nats.Timeout(time.Second), nats.NoReconnect(), nats.ErrorHandler(func(*nats.Conn, *nats.Subscription, error) {}))
	if err != nil {
		t.Fatal("fixture connection failed")
	}
	t.Cleanup(nc.Close)
	js, err := nc.JetStream(nats.Domain(f.options.Domain))
	if err != nil {
		t.Fatal("fixture JS failed")
	}
	return nc, js
}

func TestHealthColdRepeatWarmAndRealRestart(t *testing.T) {
	f := newHealthFixture(t, false)
	ctx := context.Background()
	if _, err := Probe(ctx, f.options); err == nil {
		t.Fatal("warm probe created absent stream")
	}
	nc, js := f.connect(t)
	if _, err := js.StreamInfo(HealthStream(f.options.HubID)); err != nats.ErrStreamNotFound {
		t.Fatal("absent warm changed state")
	}
	nc.Close()
	first, err := ProvisionAndProbe(ctx, f.options)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Created || first.Sequence != 1 {
		t.Fatal("cold creation result invalid")
	}
	f.assertConnections(t, 0)
	second, err := ProvisionAndProbe(ctx, f.options)
	if err != nil {
		t.Fatal(err)
	}
	if second.Created || second.Sequence <= first.Sequence {
		t.Fatal("repeat recreated or lost data")
	}
	f.assertConnections(t, 0)
	nc, js = f.connect(t)
	originalRecord, err := js.GetMsg(first.Stream, first.Sequence)
	if err != nil {
		t.Fatal("original record unavailable")
	}
	nc.Close()
	f.stop(t)
	f.start(t)
	_, js = f.connect(t)
	retained, err := js.GetMsg(first.Stream, first.Sequence)
	if err != nil || !bytes.Equal(retained.Data, originalRecord.Data) || retained.Subject != originalRecord.Subject || !retained.Time.Equal(originalRecord.Time) {
		t.Fatal("record not retained across actual restart")
	}
	before, err := js.StreamInfo(first.Stream)
	if err != nil {
		t.Fatal("retained stream unavailable")
	}
	warm, err := Probe(ctx, f.options)
	if err != nil {
		t.Fatal(err)
	}
	after, err := js.StreamInfo(first.Stream)
	if err != nil {
		t.Fatal("warm stream unavailable")
	}
	if warm.Created || warm.Sequence <= second.Sequence || !reflect.DeepEqual(before.Config, after.Config) || !before.Created.Equal(after.Created) {
		t.Fatal("warm probe changed stream configuration")
	}
	f.assertConnections(t, 1)
}

func TestHealthIncompatibleStreamIsNotChanged(t *testing.T) {
	for _, change := range []string{"subjects", "storage", "no-ack", "limits", "retention", "dedupe", "transform"} {
		t.Run(change, func(t *testing.T) {
			f := newHealthFixture(t, false)
			_, js := f.connect(t)
			config := HealthConfig(f.options.HubID)
			switch change {
			case "subjects":
				config.Subjects = []string{"fixture.other"}
			case "storage":
				config.Storage = nats.MemoryStorage
			case "no-ack":
				config.NoAck = true
			case "limits":
				config.MaxMsgs++
			case "retention":
				config.Retention = nats.InterestPolicy
			case "dedupe":
				config.Duplicates = time.Minute
			case "transform":
				config.SubjectTransform = &nats.SubjectTransformConfig{Source: HealthSubject(f.options.HubID), Destination: "fixture.other"}
			}
			original, err := js.AddStream(&config)
			if err != nil {
				t.Fatal("incompatible fixture creation failed")
			}
			for _, cold := range []bool{false, true} {
				var err error
				if cold {
					_, err = ProvisionAndProbe(context.Background(), f.options)
				} else {
					_, err = Probe(context.Background(), f.options)
				}
				if err == nil {
					t.Fatal("incompatible stream accepted")
				}
			}
			after, err := js.StreamInfo(config.Name)
			if err != nil || !reflect.DeepEqual(original.Config, after.Config) || after.State.Msgs != 0 || !original.Created.Equal(after.Created) {
				t.Fatal("incompatible stream changed")
			}
		})
	}
}

func TestHealthWrongEndpointAuthAndIdentity(t *testing.T) {
	f := newHealthFixture(t, false)
	for _, kind := range []string{"endpoint", "auth", "domain", "server-name", "version"} {
		t.Run(kind, func(t *testing.T) {
			o := f.options
			o.Timeout = 300 * time.Millisecond
			switch kind {
			case "endpoint":
				listener, _ := net.Listen("tcp", "127.0.0.1:0")
				o.Endpoint = "nats://" + listener.Addr().String()
				listener.Close()
			case "auth":
				o.Password = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			case "domain":
				o.Domain = "wrong_domain"
			case "server-name":
				o.ServerName = "wrong_server"
			case "version":
				o.ServerVersion = "2.14.0"
			}
			started := time.Now()
			if _, err := ProvisionAndProbe(context.Background(), o); err == nil {
				t.Fatal("wrong connection accepted")
			}
			if time.Since(started) > time.Second {
				t.Fatal("total deadline exceeded")
			}
		})
	}
	_, js := f.connect(t)
	if _, err := js.StreamInfo(HealthStream(f.options.HubID)); err != nats.ErrStreamNotFound {
		t.Fatal("failed identity probe provisioned")
	}
	f.assertConnections(t, 1)
}

func TestHealthPrincipalCannotMutateOtherResources(t *testing.T) {
	f := newHealthFixture(t, false)
	if _, err := ProvisionAndProbe(context.Background(), f.options); err != nil {
		t.Fatal(err)
	}
	violations := make(chan error, 8)
	nc, err := nats.Connect(f.options.Endpoint, nats.UserInfo(HealthUser, f.options.Password), nats.Timeout(time.Second), nats.NoReconnect(), nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
		select {
		case violations <- err:
		default:
		}
	}))
	if err != nil {
		t.Fatal("fixture connection failed")
	}
	defer nc.Close()
	for _, subject := range []string{"$SYS.REQ.SERVER.PING", "$JS." + f.options.Domain + ".API.STREAM.CREATE.OTHER", "$JS." + f.options.Domain + ".API.STREAM.UPDATE." + HealthStream(f.options.HubID), "$JS." + f.options.Domain + ".API.STREAM.DELETE." + HealthStream(f.options.HubID)} {
		_, err := nc.Request(subject, []byte(`{}`), 100*time.Millisecond)
		if err == nil {
			t.Fatal("forbidden request succeeded")
		}
		select {
		case err := <-violations:
			if !errors.Is(err, nats.ErrPermissionViolation) {
				t.Fatal("denial was not an observed permission violation")
			}
		case <-time.After(time.Second):
			t.Fatal("permission denial not observed")
		}
	}
	_, js := f.connect(t)
	info, err := js.StreamInfo(HealthStream(f.options.HubID))
	if err != nil || !compatibleHealth(info.Config, f.options.HubID) || info.State.Msgs != 1 {
		t.Fatal("forbidden request changed health stream")
	}
}

func TestHealthRespectsEarlierTotalDeadline(t *testing.T) {
	f := newHealthFixture(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := ProvisionAndProbe(ctx, f.options); err == nil {
		t.Fatal("denied write succeeded")
	}
	if time.Since(started) > 500*time.Millisecond {
		t.Fatal("earlier deadline exceeded")
	}
	f.assertConnections(t, 0)
}

func TestHealthPartialProvisionFailureRetainsStream(t *testing.T) {
	f := newHealthFixture(t, true)
	f.options.Timeout = 300 * time.Millisecond
	if _, err := ProvisionAndProbe(context.Background(), f.options); err == nil {
		t.Fatal("denied write succeeded")
	}
	_, js := f.connect(t)
	info, err := js.StreamInfo(HealthStream(f.options.HubID))
	if err != nil || info.State.Msgs != 0 {
		t.Fatal("partial state not retained")
	}
	if !compatibleHealth(info.Config, f.options.HubID) {
		t.Fatal("partial stream invalid")
	}
	f.assertConnections(t, 1)
}

func (f *healthFixture) assertConnections(t *testing.T, want int) {
	t.Helper()
	client := http.Client{Timeout: 200 * time.Millisecond}
	end := time.Now().Add(time.Second)
	for time.Now().Before(end) {
		response, err := client.Get(f.monitor)
		if err == nil {
			var stats struct {
				Connections int `json:"connections"`
			}
			err = json.NewDecoder(response.Body).Decode(&stats)
			response.Body.Close()
			if err == nil && stats.Connections == want {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("owned probe connection not closed")
}
