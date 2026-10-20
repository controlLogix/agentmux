//go:build darwin && arm64

package launcher

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Use the existing private enrollment and controlled Docker process. The
// unsigned runtime in this source fixture must never authorize an image pull.
func preparationAdmissionFixture(t *testing.T) (*EnrolledHostPolicy, hostPolicyRecord, string) {
	t.Helper()
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	selection, record := installedHostPolicyFixture(t)
	driver, _, log := setupDocker(t)
	host, err := LoadEnrolledHostPolicy(selection)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := LoadProfile(host.policy.Profile)
	if err != nil {
		t.Fatal(err)
	}
	p := profile.Declaration()
	c := driver.config
	p.Docker = &ProfileDocker{Backend: c.Backend, Executable: c.Executable, Context: c.Context, Endpoint: c.Endpoint, EngineID: c.EngineID, ClientVersion: c.Versions.Client, ServerVersion: c.Versions.Server, ComposeVersion: c.Versions.Compose}
	releaseTestWrite(t, p.ProfileDirectory, "profile.json", mustStatusJSON(p))
	record.PublicContextName = c.Context
	writeInstalledHostPolicy(t, selection.Path, record)
	host, err = LoadEnrolledHostPolicy(selection)
	if err != nil {
		t.Fatal(err)
	}
	return host, record, log
}

func TestBrokerPreparationRequiresCurrentOwnerAndEnrollment(t *testing.T) {
	for _, change := range []string{"owner", "record", "canceled", "environment"} {
		t.Run(change, func(t *testing.T) {
			host, _, log := preparationAdmissionFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			switch change {
			case "owner":
				host.selection.OwnerUID++
			case "record":
				host.record.InstanceID = "instance_" + strings.Repeat("f", 32)
			case "canceled":
				cancel()
			case "environment":
				t.Setenv("DOCKER_HOST", "unix:///different.sock")
			}
			result, err := host.PrepareBrokerImage(ctx, func(BrokerImagePreparationProgress) error { return nil })
			if err == nil || result.Outcome != "failed" || result.Readiness != "not_observed" || result.Diagnostic == nil || commands(log) != "" {
				t.Fatal("invalid authority or canceled preparation reached Docker")
			}
		})
	}
}

func TestBrokerPreparationHoldsActualLeaseAndRevalidatesBeforePull(t *testing.T) {
	for _, change := range []string{"unsigned runtime", "changed policy", "output refusal"} {
		t.Run(change, func(t *testing.T) {
			host, record, log := preparationAdmissionFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			held := false
			result, err := host.PrepareBrokerImage(ctx, func(progress BrokerImagePreparationProgress) error {
				if progress.Stage != "downloading" {
					return nil
				}
				probe, stop := context.WithTimeout(ctx, 40*time.Millisecond)
				defer stop()
				other, err := AcquireBootstrapLock(probe, record.ProfileDirectory, record.InstanceID, "fixture-engine")
				if other != nil {
					other.Close()
					t.Fatal("preparation did not hold the actual OS lease")
				}
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("actual lease contention was not observed")
				}
				held = true
				if change == "changed policy" {
					record.Limits.StartupMilliseconds++
					writeInstalledHostPolicy(t, host.selection.Path, record)
				}
				if change == "output refusal" {
					return errors.New("synthetic-private-writer-error")
				}
				return nil
			})
			if !held || err == nil || result.Outcome != "failed" || result.Diagnostic == nil || strings.Contains(commands(log), "image ") {
				t.Fatal("refused preparation reached image acquisition")
			}
			if change == "unsigned runtime" && err.Error() != "host_policy_executable_unqualified" {
				t.Fatal("protected runtime admission was not applied")
			}
			if strings.Contains(string(mustStatusJSON(result)), "synthetic-private") {
				t.Fatal("writer details escaped")
			}
			probe, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			lease, err := AcquireBootstrapLock(probe, record.ProfileDirectory, record.InstanceID, "fixture-engine")
			if err != nil {
				t.Fatal("settled preparation retained the lease")
			}
			if lease.Close() != nil {
				t.Fatal("lease probe cleanup failed")
			}
		})
	}
}

func TestBrokerPreparationCancellationWhileWaitingDoesNotPull(t *testing.T) {
	host, record, log := preparationAdmissionFixture(t)
	owner, cancelOwner := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelOwner()
	lease, err := AcquireBootstrapLock(owner, record.ProfileDirectory, record.InstanceID, "fixture-engine")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := host.PrepareBrokerImage(ctx, func(BrokerImagePreparationProgress) error { return nil })
	var waiting *StartingElsewhereError
	if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &waiting) || result.Stage != "waiting_for_owner" || strings.Contains(commands(log), "image ") {
		t.Fatal("canceled preparation proceeded past lease waiting")
	}
}
