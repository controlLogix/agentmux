//go:build darwin && cgo && agentmux_bootstrap_docker

package launcher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/controlLogix/agentmux/platform/internal/darwinfixtureidentity"
)

// Keep these forms identical to InspectOwnedTLSBroker and runFixedRead. A
// variable container slot admits only the full ID already required by Docker.
func composeDarwinInspectionCommands(docker *ProfileDocker, project, image string) ([]darwinfixtureidentity.InspectionCommand, error) {
	if docker == nil || docker.Backend != NativeUnix || !filepath.IsAbs(docker.Executable) || filepath.Clean(docker.Executable) != docker.Executable || !slug.MatchString(docker.Context) || !slug.MatchString(project) || !brokerImagePin.MatchString(image) {
		return nil, errors.New("fixture_inspection_selection_invalid")
	}
	prefix := []string{docker.Executable, "--context", docker.Context}
	var commands []darwinfixtureidentity.InspectionCommand
	literal := func(args ...string) {
		commands = append(commands, darwinfixtureidentity.InspectionCommand{Args: append(append([]string(nil), prefix...), args...), ContainerArgument: -1})
	}
	literal("context", "inspect", docker.Context, "--format", "{{json .Endpoints.docker.Host}}")
	literal("version", "--format", dockerVersionReadFormat)
	literal("info", "--format", dockerInfoReadFormat)
	literal("compose", "version", "--short")
	literal("ps", "--all", "--quiet", "--no-trunc", "--filter", "label=com.docker.compose.project="+project)
	literal("ps", "--all", "--quiet", "--no-trunc", "--filter", "name="+project+"_")
	literal("ps", "--all", "--quiet", "--no-trunc", "--filter", "name="+project+"-")
	literal("image", "inspect", image, "--format", "{{json .Id}}")
	literal("volume", "inspect", project+"_data", "--format", "{{json .Labels}}")
	commands = append(commands, darwinfixtureidentity.InspectionCommand{Args: append(append([]string(nil), prefix...), "container", "inspect", "", "--format", brokerInspectFormat), ContainerArgument: 5})
	for _, name := range []string{"private.conf", "server-cert.pem", "server-key.pem"} {
		commands = append(commands, darwinfixtureidentity.InspectionCommand{Args: append(append([]string(nil), prefix...), "cp", ":/etc/nats/"+name, "-"), ContainerArgument: 4})
	}
	return commands, nil
}

func TestComposeDarwinInspectionGrammarAcceptsActualProductionTLSReads(t *testing.T) {
	driver, log := instanceSetup(t, "running")
	argvLog := filepath.Join(t.TempDir(), "argv.jsonl")
	t.Setenv("AMX_BROKER_INSPECT_ARGV_LOG", argvLog)
	t.Setenv("AMX_BROKER_TLS_ARCHIVES", "1")
	_, err := driver.InspectOwnedTLSBroker(context.Background(), instanceOwner(), instanceImage(), 43210, sha256.Sum256(instanceConfig()), sha256.Sum256(tlsInstanceBody("server-cert.pem")), sha256.Sum256(tlsInstanceBody("server-key.pem")))
	if err != nil {
		t.Fatal("controlled production TLS inspection failed")
	}
	docker := &ProfileDocker{Executable: driver.config.Executable, Context: driver.config.Context, Backend: NativeUnix}
	allowed, err := composeDarwinInspectionCommands(docker, instanceOwner().Project, instanceImage())
	if err != nil {
		t.Fatal("selected production grammar refused")
	}
	raw, err := os.ReadFile(argvLog)
	if err != nil {
		t.Fatal("controlled original argv capture unavailable")
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte{'\n'})
	if len(lines) != 13 {
		t.Fatal("production TLS inspector changed its complete command set")
	}
	seen := make([]bool, len(allowed))
	for _, line := range lines {
		var args []string
		if json.Unmarshal(line, &args) != nil {
			t.Fatal("controlled argv capture malformed")
		}
		matches := 0
		for i, command := range allowed {
			if command.Matches(args) {
				matches++
				seen[i] = true
			}
		}
		if matches != 1 {
			t.Fatal("actual production argv did not match exactly one fixed inspection form")
		}
	}
	for _, present := range seen {
		if !present {
			t.Fatal("fixture grammar admits a command not exercised by the production inspector")
		}
	}
	noMutation(t, log)
}

func TestComposeDarwinInspectionGrammarRefusesOtherCommandsAndBindings(t *testing.T) {
	docker := &ProfileDocker{Executable: "/selected/docker", Context: "selected-context", Backend: NativeUnix}
	allowed, err := composeDarwinInspectionCommands(docker, "selected-project", instanceImage())
	if err != nil {
		t.Fatal("selected grammar refused")
	}
	prefix := []string{docker.Executable, "--context", docker.Context}
	for _, tail := range [][]string{
		{"compose", "up"}, {"container", "stop", instanceID()}, {"system", "prune"},
		{"cp", instanceID() + ":/etc/nats/unknown", "-"}, {"cp", instanceID() + ":/etc/nats/private.conf", "/tmp/output"},
		{"container", "inspect", "short-id", "--format", brokerInspectFormat},
		{"container", "inspect", strings.Repeat("A", 64), "--format", brokerInspectFormat},
		{"image", "inspect", "docker.io/library/nats:latest", "--format", "{{json .Id}}"},
		{"ps", "--all", "--quiet", "--no-trunc", "--filter", "name=foreign-project_"},
		{"volume", "inspect", "foreign-project_data", "--format", "{{json .Labels}}"},
	} {
		args := append(append([]string(nil), prefix...), tail...)
		for _, command := range allowed {
			if command.Matches(args) {
				t.Fatal("unselected command, target or output was admitted")
			}
		}
	}
	for _, mutate := range []func([]string) []string{
		func(args []string) []string { args[0] = "/other/docker"; return args },
		func(args []string) []string { args[1] = "--host"; return args },
		func(args []string) []string { args[2] = "foreign-context"; return args },
		func(args []string) []string { return append(args, "--unselected-option") },
	} {
		args := mutate(append(append([]string(nil), prefix...), "version", "--format", dockerVersionReadFormat))
		for _, command := range allowed {
			if command.Matches(args) {
				t.Fatal("mismatched executable, context or argument grammar was admitted")
			}
		}
	}
}
