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

func TestBrokerRecoveryOnlyStartsExactStoppedContainer(t *testing.T) {
	for _, state := range []string{"stopped", "running", "absent", "replaced"} {
		t.Run(state, func(t *testing.T) {
			f := newBridgeFixture(t)
			f.startBroker(t)
			f.controlledDocker(t)
			if _, err := deployment.ProvisionAndProbe(context.Background(), f.config.Health); err != nil {
				t.Fatal(err)
			}
			r, err := newBrokerRecovery(f.config, f.profile, OwnedBroker{ContainerID: strings.Repeat("a", 64), State: "running"})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "state")
			if os.WriteFile(path, []byte(state), 0600) != nil {
				t.Fatal("state unavailable")
			}
			t.Setenv("AMX_OWNER_BRIDGE_RECOVERY_STATE", path)
			started, err := r.recover(context.Background())
			if state == "absent" || state == "replaced" {
				if err == nil || started {
					t.Fatal("missing or replaced container authorized recovery")
				}
			} else if err != nil || started != (state == "stopped") {
				t.Fatal("recovery result did not match inspected state", err)
			}
			command, readErr := os.ReadFile(path + ".started")
			if state == "stopped" {
				if readErr != nil || string(command) != strings.Repeat("a", 64) {
					t.Fatal("exact original container was not selected")
				}
				if startedAgain, err := r.recover(context.Background()); err != nil || startedAgain {
					t.Fatal("running broker was started twice", err)
				}
			} else if !os.IsNotExist(readErr) {
				t.Fatal("non-stopped state caused a mutation")
			}
		})
	}
}

func TestBrokerRecoveryRechecksSelectionAndActualLease(t *testing.T) {
	f := newBridgeFixture(t)
	f.controlledDocker(t)
	r, err := newBrokerRecovery(f.config, f.profile, OwnedBroker{ContainerID: strings.Repeat("a", 64), State: "running"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "state")
	if os.WriteFile(path, []byte("stopped"), 0600) != nil {
		t.Fatal("state unavailable")
	}
	t.Setenv("AMX_OWNER_BRIDGE_RECOVERY_STATE", path)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	lease, err := AcquireBootstrapLock(ctx, f.profile.ProfileDirectory, f.profile.InstanceID, f.profile.Docker.EngineID)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
	started, err := r.recover(ctx)
	cancel()
	if err == nil || started {
		t.Fatal("recovery bypassed the held bootstrap lease")
	}
	if _, err := os.Stat(path + ".started"); !os.IsNotExist(err) {
		t.Fatal("lease wait mutated a container")
	}
	changed := f.profile
	changed.Docker = cloneOperationDocker(f.profile.Docker)
	changed.Docker.EngineID = "different_engine"
	releaseTestWrite(t, f.profile.ProfileDirectory, "profile.json", mustStatusJSON(changed))
	if started, err := r.recover(context.Background()); err == nil || started {
		t.Fatal("changed selection authorized mutation")
	}
}

func TestBrokerRecoveryRefusesInvalidOrCancelledOwner(t *testing.T) {
	if _, err := newBrokerRecovery(BootstrapConfig{}, Profile{}, OwnedBroker{}); err == nil {
		t.Fatal("unbound owner admitted")
	}
	var absent *brokerRecovery
	if started, err := absent.recover(context.Background()); err == nil || started {
		t.Fatal("missing recovery owner admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if started, err := absent.recover(ctx); err == nil || started {
		t.Fatal("cancelled recovery admitted")
	}
}
