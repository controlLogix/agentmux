//go:build linux || darwin

package launcher

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
)

// This uses the existing inspected-Docker adapter and an actual owned TLS
// broker. It checks the established HOST service lifetime and reauthentication,
// not actual Compose recovery or protected child replacement.
func TestOwnerBridgeEstablishedServerRecovery(t *testing.T) {
	for _, change := range []string{"same-broker", "authentication", "permission", "container", "credential", "cancel"} {
		t.Run(change, func(t *testing.T) {
			f := newBridgeFixture(t)
			stop := f.startBroker(t)
			f.startActors(t)
			if _, err := deployment.ProvisionAndProbe(context.Background(), f.config.Health); err != nil {
				t.Fatal("actual initial persistence probe unavailable")
			}
			server, err := LoadOwnerBridgeServer(f.config, f.owner, f.enrollment)
			if err != nil {
				t.Fatal("actual enrolled server unavailable")
			}
			input := ownerObservationFixture(f.policy, f.profile, "reused")
			invocation := "attempt_" + strings.Repeat("a", 32)
			session := &Session{Status: input.status, observedAt: input.receivedAt, startupAttemptID: invocation}
			lifetime, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			lease, err := AcquireBootstrapLock(lifetime, f.profile.ProfileDirectory, f.profile.InstanceID, "owner-status-service")
			if err != nil {
				t.Fatal("exact owner service lease unavailable")
			}
			defer lease.Close()
			done := make(chan error, 1)
			ready := make(chan struct{})
			go func() { done <- server.serve(lifetime, invocation, session, nil, ready) }()
			joined := false
			t.Cleanup(func() {
				cancel()
				if !joined {
					select {
					case err := <-done:
						if bridgeObservationCleanupFailure(err) != nil {
							t.Error("server retained transport cleanup failure")
						}
					case <-time.After(time.Second):
						t.Error("exact server lifetime did not join")
					}
				}
			})
			select {
			case <-ready:
			case err := <-done:
				joined = true
				t.Fatal("actual initial service returned before its subscription", err)
			case <-lifetime.Done():
				t.Fatal("actual initial server subscription unavailable")
			}
			stop()
			// The HOST service must not return and cancel its owning runtime merely
			// because the broker has gone. Its original lease remains held.
			select {
			case <-done:
				joined = true
				t.Fatal("established service abandoned its owner on broker loss")
			case <-time.After(50 * time.Millisecond):
			}
			wait, stopWait := context.WithTimeout(lifetime, 30*time.Millisecond)
			other, err := AcquireBootstrapLock(wait, f.profile.ProfileDirectory, f.profile.InstanceID, "owner-status-service")
			stopWait()
			if err == nil || other != nil {
				t.Fatal("broker loss released the exact owner service lease")
			}
			if change == "cancel" {
				cancel()
				select {
				case err := <-done:
					joined = true
					if bridgeObservationCleanupFailure(err) != nil {
						t.Fatal("canceled reconnect retained incomplete owned cleanup")
					}
				case <-time.After(time.Second):
					t.Fatal("reconnect outlived its original canceled lifetime")
				}
				return
			}
			mutate := func(config map[string]any) {
				users := config["accounts"].(map[string]any)[deployment.OwnerBridgeAccount].(map[string]any)["users"].([]any)
				for _, entry := range users {
					user := entry.(map[string]any)
					if user["user"] == deployment.OwnerBridgeServerUser {
						if change == "authentication" {
							user["password"] = strings.Repeat("z", 48)
						} else if change == "permission" {
							user["permissions"].(map[string]any)["subscribe"] = map[string]any{"allow": []string{}, "deny": []string{">"}}
						}
					}
				}
			}
			if change == "container" {
				state := filepath.Join(t.TempDir(), "replacement")
				if os.WriteFile(state, []byte("replaced"), 0600) != nil {
					t.Fatal("replacement inspection state unavailable")
				}
				t.Setenv("AMX_OWNER_BRIDGE_RECOVERY_STATE", state)
			}
			if change == "credential" {
				changed := server.credential
				changed.Password = strings.Repeat("y", 48)
				releaseTestWrite(t, f.profile.ProfileDirectory, f.enrollment.Credentials.Server, mustStatusJSON(changed))
			}
			f.startBroker(t, mutate)
			if change != "same-broker" {
				select {
				case err := <-done:
					joined = true
					credentialRefused := change == "credential" && err != nil && err.Error() == "owner_bridge_credential_invalid"
					if !IsOwnerBridgeAuthorityError(err) && !credentialRefused {
						t.Fatal("reconnect authority change was retried or lost its terminal category", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("reconnect authority refusal did not finish within its connection budget")
				}
				return
			}
			if _, err := deployment.ProvisionAndProbe(lifetime, f.config.Health); err != nil {
				t.Fatal("actual recovered persistence probe unavailable")
			}
			client, err := LoadOwnerBridgeClient(f.config, f.enrollment)
			if err != nil {
				t.Fatal("actual enrolled observer unavailable")
			}
			out, err := client.Request(lifetime, "status", "attempt_"+strings.Repeat("b", 32))
			if err != nil || !bridgeObservationBound(out, f.enrollment, "attempt_"+strings.Repeat("b", 32), time.Now()) || out.Disposition != "reused" {
				t.Fatal("same owning service did not resume fresh authenticated status", err)
			}
			select {
			case <-done:
				joined = true
				t.Fatal("recovered service abandoned its original lifetime")
			default:
			}
		})
	}
}
