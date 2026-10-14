package launcher

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/boot"
	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/lifecycle"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/kernel/status"
	"github.com/nats-io/nats.go"
)

type kernelObserverFixture struct {
	options  KernelStatusOptions
	secrets  communication.Credentials
	subjects protocol.SubjectSet
}

func kernelObserverSetup(t *testing.T, denied bool) kernelObserverFixture {
	t.Helper()
	binary := os.Getenv("AGENTMUX_TEST_NATS")
	if binary == "" {
		t.Fatal("prepared NATS executable required")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	secrets := communication.Credentials{}
	roles := protocol.Roles()
	names := append([]string{communication.Administrator, communication.OrdinaryPlugin}, roles[:]...)
	for _, name := range names {
		var b [24]byte
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal("fixture entropy unavailable")
		}
		secrets[name] = hex.EncodeToString(b[:])
	}
	config, err := communication.BuildConfig("observer_hub", port, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if denied {
		var tree map[string]any
		if json.Unmarshal(config, &tree) != nil {
			t.Fatal("fixture config parse failed")
		}
		account := tree["accounts"].(map[string]any)["APPLICATION"].(map[string]any)
		user := account["users"].([]any)[0].(map[string]any)
		user["permissions"].(map[string]any)["subscribe"] = map[string]any{"allow": []string{}, "deny": []string{">"}}
		var out strings.Builder
		encoder := json.NewEncoder(&out)
		encoder.SetEscapeHTML(false)
		encoder.Encode(tree)
		config = []byte(out.String())
	}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	path := filepath.Join(dir, "private.json")
	if os.WriteFile(path, config, 0600) != nil {
		t.Fatal("fixture config write failed")
	}
	log, err := os.OpenFile(filepath.Join(dir, "private.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-c", path)
	cmd.Stdout = log
	cmd.Stderr = log
	if cmd.Start() != nil {
		t.Fatal("fixture broker start failed")
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait(); log.Close() })
	endpoint := "nats://127.0.0.1:" + strconv.Itoa(port)
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := nats.Connect(endpoint, nats.UserInfo(communication.OrdinaryPlugin, secrets[communication.OrdinaryPlugin]), nats.NoReconnect(), nats.Timeout(50*time.Millisecond))
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture broker unavailable")
		}
		time.Sleep(10 * time.Millisecond)
	}
	w, _ := communication.Subjects("observer_hub")
	return kernelObserverFixture{KernelStatusOptions{Endpoint: endpoint, Password: secrets[communication.OrdinaryPlugin], Scope: protocol.Scope{HubID: "observer_hub", InstanceID: "observer_instance", ProfileID: "observer_profile", AssemblyDigest: "sha256:" + strings.Repeat("a", 64), ReleaseManifestDigest: "sha256:" + strings.Repeat("b", 64), ReleaseVersion: "1.0.0"}, Timeout: 4 * time.Second}, secrets, protocol.SubjectSet{Commands: w.Commands, Events: w.Events, Snapshot: w.Snapshot, Update: w.Update}}
}

func TestKernelObserverRealActorsAndLateSubscription(t *testing.T) {
	f := kernelObserverSetup(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, role := range protocol.Roles() {
		c := protocol.Config{Credentials: protocol.Credentials{SchemaVersion: protocol.Version, Role: role, Username: role, Password: f.secrets[role], NATSURL: f.options.Endpoint, Scope: f.options.Scope}}
		done := make(chan error, 1)
		go func() {
			var err error
			switch role {
			case "boot":
				err = boot.Run(ctx, c, f.subjects)
			case "kernel-lifecycle":
				err = lifecycle.Run(ctx, c, f.subjects)
			case "internal-communication":
				err = communication.Run(ctx, c, f.subjects)
			case "exported-status":
				err = status.Run(ctx, c, f.subjects)
			}
			done <- err
		}()
		t.Cleanup(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Error("actor cleanup failed")
				}
			case <-time.After(2 * time.Second):
				t.Error("actor cleanup deadline exceeded")
			}
		})
	}
	first, err := ObserveKernel(ctx, f.options)
	if err != nil {
		t.Fatal("actual actor snapshot unavailable:", err)
	}
	late, err := ObserveKernel(ctx, f.options)
	if err != nil {
		t.Fatal("late actor snapshot unavailable:", err)
	}
	if first.Incarnation != late.Incarnation || late.Revision <= first.Revision {
		t.Fatal("late full snapshot lost continuity")
	}
	if late.Scope != f.options.Scope || late.Role != "exported-status" {
		t.Fatal("snapshot not bound to expected protected scope")
	}
}

func observerFrame(f kernelObserverFixture) protocol.Snapshot {
	at := time.Now().UTC()
	members := make([]protocol.Member, 0, 4)
	for _, role := range protocol.Roles() {
		members = append(members, protocol.Member{Role: role, State: "unknown"})
	}
	return protocol.Snapshot{SchemaVersion: protocol.Version, Kind: "kernel-info", Scope: f.options.Scope, Role: "exported-status", Incarnation: strings.Repeat("a", 32), Revision: 1, ObservedAt: at.Format(time.RFC3339Nano), ValidUntil: at.Add(3 * time.Second).Format(time.RFC3339Nano), KernelReadiness: "not_ready", Members: members}
}
func kernelPublishFixture(t *testing.T, f kernelObserverFixture, payload []byte) {
	t.Helper()
	c, err := nats.Connect(f.options.Endpoint, nats.UserInfo("exported-status", f.secrets["exported-status"]), nats.NoReconnect())
	if err != nil {
		t.Fatal("fixture producer unavailable")
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				c.Publish(f.subjects.Snapshot, payload)
			}
		}
	}()
	t.Cleanup(func() { close(stop); <-done; c.Close() })
}

func TestKernelObserverRejectsInvalidAuthenticatedFrames(t *testing.T) {
	for _, name := range []string{"wrong-scope", "stale", "oversize", "duplicate", "unknown-field", "reply-shaped"} {
		t.Run(name, func(t *testing.T) {
			f := kernelObserverSetup(t, false)
			frame := observerFrame(f)
			switch name {
			case "wrong-scope":
				frame.Scope.ProfileID = "different_profile"
			case "stale":
				at := time.Now().Add(-10 * time.Second)
				frame.ObservedAt = at.UTC().Format(time.RFC3339Nano)
				frame.ValidUntil = at.Add(3 * time.Second).UTC().Format(time.RFC3339Nano)
			}
			payload, _ := json.Marshal(frame)
			switch name {
			case "oversize":
				payload = []byte(strings.Repeat("x", protocol.MaxPayload+1))
			case "duplicate":
				payload = append([]byte(`{"kind":"kernel-info",`), payload[1:]...)
			case "unknown-field":
				payload = append([]byte(`{"unexpected":true,`), payload[1:]...)
			}
			if name == "reply-shaped" {
				c, err := nats.Connect(f.options.Endpoint, nats.UserInfo("exported-status", f.secrets["exported-status"]), nats.NoReconnect())
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				go func() {
					ticker := time.NewTicker(20 * time.Millisecond)
					defer ticker.Stop()
					for {
						select {
						case <-ctx.Done():
							return
						case <-ticker.C:
							c.PublishRequest(f.subjects.Snapshot, "untrusted_reply", payload)
						}
					}
				}()
			} else {
				kernelPublishFixture(t, f, payload)
			}
			_, err := ObserveKernel(context.Background(), f.options)
			if err == nil || err.Error() != "kernel_status_invalid" {
				t.Fatalf("unsafe frame accepted: %v", err)
			}
		})
	}
}

func TestKernelObserverCurrentFullFrameControl(t *testing.T) {
	f := kernelObserverSetup(t, false)
	payload, _ := json.Marshal(observerFrame(f))
	kernelPublishFixture(t, f, payload)
	snapshot, err := ObserveKernel(context.Background(), f.options)
	if err != nil || snapshot.KernelReadiness != "not_ready" || snapshot.Revision != 1 {
		t.Fatal("valid full frame was rejected or promoted to ready")
	}
}

func TestKernelObserverOptionBounds(t *testing.T) {
	base := KernelStatusOptions{Endpoint: "nats://127.0.0.1:4222", Password: strings.Repeat("p", 48), Scope: protocol.Scope{HubID: "observer_hub", InstanceID: "observer_instance", ProfileID: "observer_profile", AssemblyDigest: "sha256:" + strings.Repeat("a", 64), ReleaseManifestDigest: "sha256:" + strings.Repeat("b", 64), ReleaseVersion: "1.0.0"}, Timeout: time.Second}
	for _, name := range []string{"missing-deadline", "over-five-seconds", "negative-deadline", "url-auth", "multiple-endpoints", "query", "empty-query", "path", "no-port", "bad-port", "bad-instance", "bad-profile", "bad-assembly", "bad-release", "short-password", "nil-context"} {
		t.Run(name, func(t *testing.T) {
			o := base
			ctx := context.Background()
			switch name {
			case "missing-deadline":
				o.Timeout = 0
			case "over-five-seconds":
				o.Timeout = 5*time.Second + 1
			case "negative-deadline":
				o.Timeout = -1
			case "url-auth":
				o.Endpoint = "nats://untrusted:untrusted@127.0.0.1:4222"
			case "multiple-endpoints":
				o.Endpoint += ",nats://127.0.0.1:4223"
			case "query":
				o.Endpoint += "?x=1"
			case "empty-query":
				o.Endpoint += "?"
			case "path":
				o.Endpoint += "/path"
			case "no-port":
				o.Endpoint = "nats://127.0.0.1"
			case "bad-port":
				o.Endpoint = "nats://127.0.0.1:99999"
			case "bad-instance":
				o.Scope.InstanceID = "bad.instance"
			case "bad-profile":
				o.Scope.ProfileID = "bad.profile"
			case "bad-assembly":
				o.Scope.AssemblyDigest = "untrusted"
			case "bad-release":
				o.Scope.ReleaseVersion = "latest"
			case "short-password":
				o.Password = "short"
			case "nil-context":
				ctx = nil
			}
			_, err := ObserveKernel(ctx, o)
			if err == nil || err.Error() != "kernel_status_invalid" {
				t.Fatal("invalid options did not fail with a safe code")
			}
		})
	}
}

func TestKernelObserverDenialAbsenceAndCancellation(t *testing.T) {
	t.Run("subscription-denied", func(t *testing.T) {
		f := kernelObserverSetup(t, true)
		_, err := ObserveKernel(context.Background(), f.options)
		if err == nil || err.Error() != "kernel_status_invalid" {
			t.Fatalf("subscription denial not explicit: %v", err)
		}
	})
	t.Run("authentication-denied", func(t *testing.T) {
		f := kernelObserverSetup(t, false)
		f.options.Password = strings.Repeat("z", 48)
		_, err := ObserveKernel(context.Background(), f.options)
		if err == nil || err.Error() != "kernel_status_invalid" {
			t.Fatalf("authentication denial not explicit: %v", err)
		}
	})
	t.Run("no-snapshot", func(t *testing.T) {
		f := kernelObserverSetup(t, false)
		f.options.Timeout = 80 * time.Millisecond
		_, err := ObserveKernel(context.Background(), f.options)
		if err == nil || err.Error() != "kernel_status_unavailable" {
			t.Fatalf("absence not explicit: %v", err)
		}
	})
	t.Run("parent-cancelled", func(t *testing.T) {
		f := kernelObserverSetup(t, false)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := ObserveKernel(ctx, f.options)
		if err == nil || err.Error() != "kernel_status_cancelled" {
			t.Fatalf("cancellation not explicit: %v", err)
		}
	})
}

func TestKernelObserverStalledGreetingCancellationClosesOwnedSocket(t *testing.T) {
	for _, handshake := range []string{"greeting", "tls"} {
		for _, parentCancelled := range []bool{false, true} {
			t.Run(handshake+"/"+strconv.FormatBool(parentCancelled), func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				accepted := make(chan net.Conn, 1)
				go func() {
					c, err := listener.Accept()
					if err == nil {
						accepted <- c
					}
				}()
				o := KernelStatusOptions{Endpoint: "nats://" + listener.Addr().String(), Password: strings.Repeat("p", 48), Scope: protocol.Scope{HubID: "observer_hub", InstanceID: "observer_instance", ProfileID: "observer_profile", AssemblyDigest: "sha256:" + strings.Repeat("a", 64), ReleaseManifestDigest: "sha256:" + strings.Repeat("b", 64), ReleaseVersion: "1.0.0"}, Timeout: 80 * time.Millisecond}
				if handshake == "tls" {
					o.Endpoint = "tls://" + listener.Addr().String()
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan error, 1)
				start := time.Now()
				go func() { _, err := ObserveKernel(ctx, o); done <- err }()
				var peer net.Conn
				select {
				case peer = <-accepted:
				case <-time.After(time.Second):
					t.Fatal("observer never connected")
				}
				defer peer.Close()
				if handshake == "tls" {
					peer.Write([]byte("INFO {\"server_id\":\"fixture\",\"version\":\"2.15.0\",\"proto\":1,\"tls_required\":true,\"max_payload\":1048576}\r\n"))
					peer.SetReadDeadline(time.Now().Add(60 * time.Millisecond))
					var firstByte [1]byte
					if _, err := peer.Read(firstByte[:]); err != nil || firstByte[0] != 0x16 {
						t.Fatal("observer did not enter the actual TLS handshake")
					}
				}
				if parentCancelled {
					cancel()
				}
				want := "kernel_status_unavailable"
				if parentCancelled {
					want = "kernel_status_cancelled"
				}
				select {
				case err := <-done:
					if err == nil || err.Error() != want {
						t.Fatalf("stalled greeting result: %v", err)
					}
				case <-time.After(500 * time.Millisecond):
					t.Fatal("greeting ignored context budget")
				}
				peer.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				_, err = io.Copy(io.Discard, peer)
				if err != nil {
					t.Fatal("observer left its socket open")
				}
				if time.Since(start) > time.Second {
					t.Fatal("owned cleanup unbounded")
				}
			})
		}
	}
}
