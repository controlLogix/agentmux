package launcher

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func hostileDockerEnvironment(t *testing.T) {
	t.Helper()
	for key, value := range map[string]string{
		"COMPOSE_REMOVE_ORPHANS": "1", "compose_remove_orphans": "true",
		"COMPOSE_DISABLE_ENV_FILE": "0", "cOmPoSe_DiSaBlE_EnV_FiLe": "false",
		"COMPOSE_ENV_FILES": "synthetic.env", "compose_project_name": "foreign_project",
		"COMPOSE_PROFILES": "hostile_profile", "COMPOSE_FILE": "foreign.json",
		"COMPOSE_IGNORE_ORPHANS": "1", "COMPOSE_CONVERT_WINDOWS_PATHS": "1",
		"COMPOSE_UNKNOWN_FUTURE_FLAG": "hostile", "Docker_Host": "tcp://synthetic.invalid:2375",
		"DOCKER_HOST": "tcp://synthetic.invalid:2375", "docker_context": "foreign_context",
		"DOCKER_CONTEXT": "foreign_context", "DOCKER_CONFIG": "synthetic-docker-config",
		"WSL_INTEROP": "synthetic-interop", "PATH": "synthetic-host-path",
	} {
		t.Setenv(key, value)
	}
}

func checkDockerEnvironment(t *testing.T, environment []string) {
	t.Helper()
	values := map[string]string{}
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			t.Fatal("malformed child environment")
		}
		upper := strings.ToUpper(key)
		if upper == "DOCKER_HOST" || upper == "DOCKER_CONTEXT" {
			t.Fatal("ambient Docker selection inherited")
		}
		if strings.HasPrefix(upper, "COMPOSE_") {
			if upper != "COMPOSE_REMOVE_ORPHANS" && upper != "COMPOSE_DISABLE_ENV_FILE" {
				t.Fatal("ambient Compose control inherited")
			}
			if key != upper {
				t.Fatal("case variant Compose control inherited")
			}
			if _, exists := values[upper]; exists {
				t.Fatal("duplicate Compose control inherited")
			}
		}
		values[upper] = value
	}
	if values["COMPOSE_REMOVE_ORPHANS"] != "0" || values["COMPOSE_DISABLE_ENV_FILE"] != "1" {
		t.Fatal("safe Compose defaults missing")
	}
	for key, want := range map[string]string{"DOCKER_CONFIG": "synthetic-docker-config", "WSL_INTEROP": "synthetic-interop", "PATH": "synthetic-host-path"} {
		if values[key] != want {
			t.Fatal("required host environment changed")
		}
	}
}

func TestDockerEnvironmentFiltersCaseVariantsAndPreservesHost(t *testing.T) {
	hostileDockerEnvironment(t)
	checkDockerEnvironment(t, dockerEnvironment())
	if os.Getenv("COMPOSE_REMOVE_ORPHANS") != "1" && os.Getenv("compose_remove_orphans") != "true" {
		t.Fatal("helper changed parent environment")
	}
}

func TestDockerEnvironmentSubprocess(t *testing.T) {
	if os.Getenv("AMX_ENVIRONMENT_CHILD") == "1" {
		checkDockerEnvironment(t, os.Environ())
		return
	}
	hostileDockerEnvironment(t)
	t.Setenv("AMX_ENVIRONMENT_CHILD", "1")
	t.Setenv("AMX_DOCKER_FIXTURE", "0")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("fixture executable unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestDockerEnvironmentSubprocess$")
	cmd.Env = dockerEnvironment()
	// No Docker command or daemon is involved. The exact spawned test child
	// checks only known synthetic variables and does not print environment data.
	if err := cmd.Run(); err != nil {
		t.Fatal("child environment boundary failed")
	}
}
