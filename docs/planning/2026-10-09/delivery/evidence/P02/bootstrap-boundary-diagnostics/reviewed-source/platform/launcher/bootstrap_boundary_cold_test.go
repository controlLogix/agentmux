//go:build linux

package launcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Only a separately spawned copy of the actual test binary enters this fixed
// controlled Docker fixture. No real engine, broker or generic callback runs.
type bootstrapBoundaryDockerSpec struct {
	Profile       Profile
	Mode          string
	Log           string
	ComposeSHA256 string
}

func init() {
	name := os.Getenv("AMX_BOOTSTRAP_BOUNDARY_DOCKER_FIXTURE")
	if name == "" {
		return
	}
	raw, err := os.ReadFile(name)
	var spec bootstrapBoundaryDockerSpec
	if err != nil || json.Unmarshal(raw, &spec) != nil {
		os.Exit(9)
	}
	args := os.Args[1:]
	if len(args) < 3 || args[0] != "--context" || args[1] != spec.Profile.Docker.Context {
		os.Exit(9)
	}
	args = args[2:]
	log, err := os.OpenFile(spec.Log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		os.Exit(9)
	}
	line, _ := json.Marshal(args)
	_, err = log.Write(append(line, '\n'))
	closeErr := log.Close()
	if err != nil || closeErr != nil {
		os.Exit(9)
	}
	if spec.Mode == "initial_timeout" && args[0] == "context" {
		time.Sleep(10 * time.Second)
		os.Exit(9)
	}
	emit := func(v any) {
		if json.NewEncoder(os.Stdout).Encode(v) != nil {
			os.Exit(9)
		}
	}
	switch args[0] {
	case "context":
		emit(spec.Profile.Docker.Endpoint)
	case "version":
		emit(map[string]string{"Client": spec.Profile.Docker.ClientVersion, "Server": spec.Profile.Docker.ServerVersion})
	case "info":
		emit(map[string]string{"ID": spec.Profile.Docker.EngineID, "OS": "linux"})
	case "ps", "volume", "network": // An absent controlled roster; never borrowed real resources.
	case "compose":
		if len(args) == 3 && args[1] == "version" && args[2] == "--short" {
			if _, e := fmt.Fprintln(os.Stdout, spec.Profile.Docker.ComposeVersion); e != nil {
				os.Exit(9)
			}
			break
		}
		// Actual StartOwned reached its unchanged mutation guard. Verify the literal
		// configured stdin digest, then fail; no broker or container is created.
		body, readErr := io.ReadAll(io.LimitReader(os.Stdin, 4*1024*1024+1))
		sum := sha256.Sum256(body)
		if readErr != nil || len(body) > 4*1024*1024 || "sha256:"+hex.EncodeToString(sum[:]) != spec.ComposeSHA256 {
			os.Exit(9)
		}
		if !strings.Contains(strings.Join(args, " "), "up --detach --pull never --no-build") {
			os.Exit(9)
		}
		os.Exit(4)
	default:
		os.Exit(9)
	}
	os.Exit(0)
}
func TestBootstrapBoundaryActualColdMutationGuard(t *testing.T) {
	for _, mode := range []string{"initial_timeout", "cold_to_guard"} {
		t.Run(mode, func(t *testing.T) {
			// Genuine signed static image/private enrollment and actual Bootstrap API,
			// with fixed controlled Docker subprocesses; no enter/complete substitution.
			f := pendingRealBridgeFixture(t)
			directory := t.TempDir()
			log := filepath.Join(directory, "commands.private")
			name := filepath.Join(directory, "fixture.private")
			raw := mustStatusJSON(bootstrapBoundaryDockerSpec{f.profile, mode, log, releaseDigest(f.config.Compose)})
			if os.WriteFile(name, raw, 0600) != nil {
				t.Fatal("boundary_fixture_write_failed")
			}
			t.Setenv("AMX_BOOTSTRAP_BOUNDARY_DOCKER_FIXTURE", name)
			t.Setenv("DOCKER_HOST", "")
			t.Setenv("DOCKER_CONTEXT", "")
			ctx, cancel := context.WithTimeout(context.Background(), 14*time.Second)
			defer cancel()
			session, err := BootstrapForInvocation(ctx, ctx, f.config, "attempt_"+strings.Repeat("c", 32))
			if session != nil {
				defer func() {
					cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
					defer stop()
					if session.Close(cleanup) != nil {
						t.Error("exact_boundary_session_cleanup_failed")
					}
				}()
			}
			if err == nil {
				t.Fatal("controlled_boundary_failure_missing")
			}
			stage := bootstrapDiagnosticStage(err)
			want := "broker_start"
			code := "docker_command_failed"
			if mode == "initial_timeout" {
				want = "initial_warm_inspection"
				code = "docker_command_timeout_outcome_unknown"
			}
			if stage == nil || *stage != want || ProjectRequestDiagnostic(err).Code != code {
				t.Fatal("actual_boundary_stage_or_cause_mismatch")
			}
			ledger, readErr := os.ReadFile(log)
			if readErr != nil {
				t.Fatal("boundary_ledger_unavailable")
			}
			mutation := false
			for _, line := range strings.Split(strings.TrimSpace(string(ledger)), "\n") {
				var args []string
				if json.Unmarshal([]byte(line), &args) != nil {
					t.Fatal("boundary_ledger_invalid")
				}
				if len(args) > 0 && args[0] == "compose" && strings.Contains(strings.Join(args, " "), " up ") {
					mutation = true
				}
			}
			if mutation != (mode == "cold_to_guard") {
				t.Fatal("initial_timeout_mutated_or_allowed_cold_skipped_guard")
			}
			// Lease reacquisition proves actual Bootstrap and role cleanup released
			// exclusion; it grants no authority over any unrelated installation.
			for _, id := range append([]string{f.profile.Docker.EngineID}, bootstrapBoundaryRoleLeaseIDs(f.profile.Docker.EngineID)...) {
				lockCtx, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
				lease, e := AcquireBootstrapLock(lockCtx, f.profile.ProfileDirectory, f.profile.InstanceID, id)
				stop()
				if e != nil {
					t.Fatal("boundary_lease_not_released")
				}
				if lease.Close() != nil {
					t.Fatal("boundary_contender_close_failed")
				}
			}
		})
	}
}
func bootstrapBoundaryRoleLeaseIDs(engine string) []string {
	return []string{engine + ":runtime:boot", engine + ":runtime:kernel-lifecycle", engine + ":runtime:internal-communication", engine + ":runtime:exported-status"}
}
