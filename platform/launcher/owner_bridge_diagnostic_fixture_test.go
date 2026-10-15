//go:build linux || darwin

package launcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/nats-io/nats.go"
)

// This exact fixture owns one broker, log and pinned HOST connection. All
// acquisition and cleanup use the original context; it has no engine authority.
func bridgeDiagnosticOwnedBroker(t *testing.T, ctx context.Context, f bridgeFixture) *nats.Conn {
	t.Helper()
	if ctx == nil || ctx.Err() != nil {
		t.Fatal("fixture original context unavailable")
	}
	f.controlledDocker(t)
	binary := os.Getenv("AGENTMUX_TEST_NATS")
	if binary == "" {
		t.Fatal("prepared broker unavailable")
	}
	var config map[string]any
	if json.Unmarshal(f.raw, &config) != nil {
		t.Fatal("fixture broker configuration invalid")
	}
	endpoint, err := url.Parse(f.config.Kernel.Endpoint)
	if err != nil {
		t.Fatal("fixture endpoint invalid")
	}
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "server-cert.pem"), filepath.Join(dir, "server-key.pem")
	if os.WriteFile(cert, f.config.LocalTLS.ServerCertificatePEM(), 0600) != nil || os.WriteFile(key, f.config.LocalTLS.ServerKeyPEM(), 0600) != nil {
		t.Fatal("fixture TLS files unavailable")
	}
	config["listen"] = endpoint.Host
	config["jetstream"].(map[string]any)["store_dir"] = filepath.Join(dir, "store")
	block := config["tls"].(map[string]any)
	block["cert_file"], block["key_file"] = cert, key
	var raw bytes.Buffer
	encoder := json.NewEncoder(&raw)
	encoder.SetEscapeHTML(false)
	path := filepath.Join(dir, "private.json")
	if encoder.Encode(config) != nil || os.WriteFile(path, raw.Bytes(), 0600) != nil {
		t.Fatal("fixture broker configuration unavailable")
	}
	log, err := os.OpenFile(filepath.Join(dir, "private.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("fixture owned log unavailable")
	}
	logConsumed := false
	t.Cleanup(func() {
		if !logConsumed {
			logConsumed = true
			if log.Close() != nil {
				t.Error("fixture log cleanup failed")
			}
		}
	})
	cmd := exec.CommandContext(ctx, binary, "-c", path)
	cmd.Stdout = log
	cmd.Stderr = log
	if cmd.Start() != nil {
		t.Fatal("fixture owned broker start failed")
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			signalErr := cmd.Process.Signal(syscall.SIGTERM)
			if signalErr != nil && !errors.Is(signalErr, os.ErrProcessDone) {
				t.Error("fixture owned broker stop failed")
			}
			waitErr := cmd.Wait()
			waited = true
			if waitErr != nil {
				var exit *exec.ExitError
				deadlineKill := false
				if ctx.Err() == context.DeadlineExceeded && errors.As(waitErr, &exit) {
					status, ok := exit.Sys().(syscall.WaitStatus)
					deadlineKill = ok && status.Signaled() && status.Signal() == syscall.SIGKILL
				}
				if !deadlineKill {
					t.Error("fixture owned broker wait failed")
				}
			}
		}
	})
	ready, stopReady := context.WithTimeout(ctx, 3*time.Second)
	defer stopReady()
	for ready.Err() == nil {
		dialer, err := f.config.Kernel.TLS.NewDialer(ctx, 50*time.Millisecond)
		if err != nil {
			t.Fatal("fixture owned TLS dialer unavailable")
		}
		dialerClosed := false
		var nc *nats.Conn
		// Retain the exact dialer immediately, including failed connect/close paths.
		t.Cleanup(func() {
			if !dialerClosed {
				if dialer.Close() != nil {
					t.Error("fixture owned TLS cleanup failed")
				} else {
					dialerClosed = true
				}
			}
			if nc != nil {
				nc.Close()
			}
		})
		nc, err = nats.Connect(f.config.Kernel.Endpoint, nats.UserInfo(deployment.OwnerBridgeServerUser, f.config.OwnerBridge.ServerPassword), nats.TLSHandshakeFirst(), nats.SetCustomDialer(dialer), nats.NoReconnect(), nats.IgnoreDiscoveredServers(), nats.Timeout(50*time.Millisecond), nats.ErrorHandler(ownerBridgeAsyncErrorHandler))
		if err == nil {
			return nc
		}
		if dialer.Close() != nil {
			t.Fatal("failed connection owned TLS cleanup failed")
		}
		dialerClosed = true
		if nc != nil {
			nc.Close()
			nc = nil
		}
		select {
		case <-ready.Done():
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatal("fixture owned broker not available within original context")
	return nil
}
