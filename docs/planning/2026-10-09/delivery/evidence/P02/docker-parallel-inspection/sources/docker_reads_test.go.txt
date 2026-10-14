package launcher

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The disposable test executable acts as a bounded CLI, never a Docker daemon.
func init() {
	if os.Getenv("AMX_DOCKER_READS_FIXTURE") == "1" {
		dockerReadsFixture()
		os.Exit(0)
	}
}

func dockerReadsFixture() {
	args := os.Args[1:]
	if len(args) < 3 || args[0] != "--context" || args[1] != "read-fixture" {
		os.Exit(81)
	}
	args = args[2:]
	directory := os.Getenv("AMX_DOCKER_READS_DIRECTORY")
	mode := os.Getenv("AMX_DOCKER_READS_MODE")
	marker := func(name string) {
		if os.WriteFile(filepath.Join(directory, name), []byte(strconv.Itoa(os.Getpid())), 0600) != nil {
			os.Exit(82)
		}
	}
	wait := func(names ...string) {
		deadline := time.Now().Add(6 * time.Second)
		for {
			all := true
			for _, name := range names {
				if _, err := os.Stat(filepath.Join(directory, name)); err != nil {
					all = false
				}
			}
			if all {
				return
			}
			if time.Now().After(deadline) {
				os.Exit(83)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	if args[0] == "context" {
		marker("context.finished")
		if mode == "endpoint" {
			fmt.Println(`"unix:///tmp/foreign.sock"`)
		} else {
			fmt.Println(`"unix:///tmp/read.sock"`)
		}
		return
	}
	if _, err := os.Stat(filepath.Join(directory, "context.finished")); err != nil {
		os.Exit(84)
	}
	if args[0] == "version" || args[0] == "info" || args[0] == "compose" {
		name := args[0]
		marker("identity-" + name + ".started")
		wait("identity-version.started", "identity-info.started", "identity-compose.started")
		if mode == "cancel" {
			wait("never-release")
		}
		if mode == "fail-after-start" {
			if name == "version" {
				wait("release-failure")
				fmt.Fprintln(os.Stderr, "synthetic-private-diagnostic")
				os.Exit(85)
			}
			wait("never-release")
		}
		if mode == "backend" && name == "info" {
			fmt.Println(`{"ID":"foreign-engine","OS":"linux"}`)
			return
		}
		switch name {
		case "version":
			fmt.Println(`{"Client":"29.8.0","Server":"29.8.0"}`)
		case "info":
			fmt.Println(`{"ID":"read-engine","OS":"linux"}`)
		case "compose":
			if len(args) != 3 || args[1] != "version" || args[2] != "--short" {
				os.Exit(86)
			}
			fmt.Println("5.5.1")
		}
		return
	}
	if args[0] == "ps" {
		if len(args) != 6 {
			os.Exit(87)
		}
		var name string
		switch args[5] {
		case "label=com.docker.compose.project=read-fixture":
			name = "label"
		case "name=read-fixture_":
			name = "underscore"
		case "name=read-fixture-":
			name = "hyphen"
		default:
			os.Exit(88)
		}
		marker("roster-" + name + ".started")
		wait("roster-label.started", "roster-underscore.started", "roster-hyphen.started")
		switch mode {
		case "foreign":
			if name == "hyphen" {
				fmt.Println(strings.Repeat("a", 64))
			}
		case "invalid-id":
			if name == "underscore" {
				fmt.Println("not-a-full-id")
			}
		case "multiple":
			if name == "label" {
				fmt.Println(strings.Repeat("a", 64))
			}
			if name == "hyphen" {
				fmt.Println(strings.Repeat("b", 64))
			}
		}
		return
	}
	if args[0] == "container" {
		marker("container-inspected")
		var observation brokerInspection
		observation.ID = strings.Repeat("a", 64)
		observation.Config.Image = instanceImage()
		observation.Config.Labels = map[string]string{"agentmux.profile.id": instanceOwner().ProfileID, "agentmux.instance.id": "foreign", "agentmux.release.digest": instanceOwner().ReleaseDigest, "com.docker.compose.project": "read-fixture", "com.docker.compose.service": "nats", "com.docker.compose.oneoff": "False"}
		json.NewEncoder(os.Stdout).Encode(observation)
		return
	}
	marker("unexpected-command")
	os.Exit(89)
}

func setupParallelDocker(t *testing.T, mode string) (*Docker, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	t.Setenv("AMX_DOCKER_FIXTURE", "")
	t.Setenv("AMX_BROKER_INSPECT_FIXTURE", "")
	t.Setenv("AMX_DOCKER_READS_FIXTURE", "1")
	t.Setenv("AMX_DOCKER_READS_DIRECTORY", directory)
	t.Setenv("AMX_DOCKER_READS_MODE", mode)
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	t.Setenv("DOCKER_HOST", "")
	t.Setenv("DOCKER_CONTEXT", "")
	d, err := NewDocker(DockerConfig{Executable: exe, Context: "read-fixture", Endpoint: "unix:///tmp/read.sock", EngineID: "read-engine", Versions: DockerVersions{"29.8.0", "29.8.0", "5.5.1"}, Timeout: 2 * time.Second, Backend: NativeUnix})
	if err != nil {
		t.Fatal(err)
	}
	return d, directory
}

func TestDockerIndependentIdentityReadsOverlap(t *testing.T) {
	d, directory := setupParallelDocker(t, "concurrency")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	actual, err := d.Inspect(ctx)
	if err != nil || actual.EngineID != "read-engine" {
		t.Fatal("three independent identity commands did not overlap and complete")
	}
	for _, name := range []string{"context.finished", "identity-version.started", "identity-info.started", "identity-compose.started"} {
		if _, err := os.Stat(filepath.Join(directory, name)); err != nil {
			t.Fatal("actual CLI barrier evidence missing")
		}
	}
}

func TestDockerIndependentRosterReadsOverlapAndPreserveUnion(t *testing.T) {
	for _, row := range []struct{ mode, code string }{{"concurrency", ""}, {"foreign", "docker_broker_identity_mismatch"}, {"invalid-id", "docker_broker_id_invalid"}, {"multiple", "docker_broker_roster_mismatch"}, {"endpoint", "docker_endpoint_mismatch"}, {"backend", "docker_backend_mismatch"}} {
		t.Run(row.mode, func(t *testing.T) {
			d, directory := setupParallelDocker(t, row.mode)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			owner := instanceOwner()
			owner.Project = "read-fixture"
			actual, err := d.InspectOwnedBroker(ctx, owner, instanceImage(), 43210, sha256.Sum256(instanceConfig()))
			if row.code == "" {
				if err != nil || actual.State != "absent" {
					t.Fatal("three independent roster commands did not overlap and complete")
				}
			} else if err == nil || err.Error() != row.code || actual != (OwnedBroker{}) {
				t.Fatal("parallel reads lost an identity refusal or returned partial state")
			}
			if row.mode == "endpoint" || row.mode == "backend" {
				for _, name := range []string{"roster-label.started", "roster-underscore.started", "roster-hyphen.started", "container-inspected"} {
					if _, err := os.Stat(filepath.Join(directory, name)); !os.IsNotExist(err) {
						t.Fatal("resource observation preceded endpoint/engine admission")
					}
				}
				if row.mode == "endpoint" {
					for _, name := range []string{"identity-version.started", "identity-info.started", "identity-compose.started"} {
						if _, err := os.Stat(filepath.Join(directory, name)); !os.IsNotExist(err) {
							t.Fatal("identity observation preceded endpoint validation")
						}
					}
				}
			}
		})
	}
}

func TestDockerInspectionStagesPreserveSafeCodes(t *testing.T) {
	for _, row := range []struct{ mode, code, stage string }{
		{"endpoint", "docker_endpoint_mismatch", "endpoint"},
		{"malformed", "docker_invalid_observation", "endpoint"},
		{"error", "docker_command_failed", "endpoint"},
		{"version", "docker_backend_mismatch", "version"},
		{"server-version", "docker_backend_mismatch", "version"},
		{"compose-version", "docker_backend_mismatch", "compose_version"},
		{"engine", "docker_backend_mismatch", "engine"},
		{"os", "docker_backend_mismatch", "engine"},
		{"timeout", "docker_command_timeout_outcome_unknown", "endpoint"},
	} {
		t.Run(row.mode, func(t *testing.T) {
			d, _, _ := setupDocker(t)
			t.Setenv("AMX_DOCKER_MODE", row.mode)
			t.Setenv("GORACE", "atexit_sleep_ms=0")
			if row.mode == "timeout" {
				d.config.Timeout = 30 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result, err := d.Inspect(ctx)
			var stage interface{ inspectionStage() string }
			if err == nil || err.Error() != row.code || !errors.As(err, &stage) || stage.inspectionStage() != row.stage || result != (DockerInspection{}) {
				t.Fatal("safe inspection code or typed stage differs")
			}
			cause := errors.Unwrap(err)
			if cause == nil || cause.Error() != row.code {
				t.Fatal("typed stage discarded or changed its original safe cause")
			}
		})
	}
}
