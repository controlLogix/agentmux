//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestPreparedBrokerImageExactManifestAndPlatform(t *testing.T) {
	pin := "docker.io/library/nats@sha256:" + strings.Repeat("b", 64)
	encode := func(repository, architecture string) []byte {
		raw, err := json.Marshal(map[string]any{"ID": "sha256:" + strings.Repeat("a", 64), "RepoDigests": []string{repository + "@sha256:" + strings.Repeat("b", 64)}, "OS": "linux", "Architecture": architecture})
		if err != nil {
			t.Fatal("image control encoding failed")
		}
		return raw
	}
	for _, repository := range []string{"nats", "library/nats", "docker.io/library/nats"} {
		if !preparedBrokerImageMatches(encode(repository, "arm64"), pin) {
			t.Fatal("canonical Docker Hub alias rejected")
		}
	}
	valid := string(encode("nats", "arm64"))
	for name, raw := range map[string]string{
		"foreign repository":     string(encode("other/nats", "arm64")),
		"foreign architecture":   string(encode("nats", "amd64")),
		"foreign manifest":       strings.Replace(valid, strings.Repeat("b", 64), strings.Repeat("c", 64), 1),
		"foreign system":         strings.Replace(valid, `"linux"`, `"windows"`, 1),
		"invalid image identity": strings.Replace(valid, strings.Repeat("a", 64), "short", 1),
		"unknown field":          strings.TrimSuffix(valid, "}") + `,"extra":true}`,
		"duplicate field":        strings.TrimSuffix(valid, "}") + `,"OS":"linux"}`,
		"field alias":            strings.Replace(valid, `"OS":`, `"os":`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if preparedBrokerImageMatches([]byte(raw), pin) {
				t.Fatal("unbound image accepted")
			}
		})
	}
	for _, changed := range []string{"nats:latest", "docker.io/library/nats:latest", strings.Replace(pin, "/nats@", "/other@", 1), strings.ToUpper(pin)} {
		if preparedBrokerImageMatches([]byte(valid), changed) {
			t.Fatal("non-release image accepted")
		}
	}
}

func TestDockerPreparationUsesLiteralEndpointAndClosedOutput(t *testing.T) {
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	driver, _, log := setupDocker(t)
	pin := "docker.io/library/nats@sha256:" + strings.Repeat("b", 64)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := driver.pullPinnedBrokerImage(ctx, pin); err != nil {
		t.Fatal(err)
	}
	if err := driver.verifyPreparedBrokerImage(ctx, pin); err != nil {
		t.Fatal(err)
	}
	actual := commands(log)
	if !strings.Contains(actual, "literal-endpoint image pull --platform linux/arm64 "+pin+"\n") || !strings.Contains(actual, "literal-endpoint image inspect "+pin+" --format ") {
		t.Fatal("preparation did not bind both commands to the enrolled Unix endpoint")
	}
	if strings.Contains(actual, "compose") {
		t.Fatal("preparation invoked Compose")
	}
	t.Setenv("AMX_DOCKER_MODE", "pull-failed")
	err := driver.pullPinnedBrokerImage(ctx, pin)
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ProcessState == nil || !exit.ProcessState.Exited() || exit.ExitCode() != 4 {
		t.Fatal("original failed pull was not waited for")
	}
	for _, public := range []string{err.Error(), fmt.Sprintf("%+v", err), string(mustStatusJSON(ProjectRequestDiagnostic(err)))} {
		if strings.Contains(public, "synthetic-private") {
			t.Fatal("private pull output escaped")
		}
	}
	if ProjectRequestDiagnostic(err).Code != "docker_image_pull_failed" {
		t.Fatal("pull refusal invented an unobserved cause")
	}
	for _, mode := range []string{"image-architecture", "image-digest"} {
		t.Setenv("AMX_DOCKER_MODE", mode)
		if driver.verifyPreparedBrokerImage(ctx, pin) == nil {
			t.Fatal("verification accepted a different prepared image")
		}
	}
}

func TestDockerPreparationCancellationJoinsOriginalProcess(t *testing.T) {
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	driver, _, log := setupDocker(t)
	t.Setenv("AMX_DOCKER_MODE", "pull-wait")
	ctx, cancel := context.WithTimeout(context.Background(), 1250*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := driver.pullPinnedBrokerImage(ctx, "docker.io/library/nats@sha256:"+strings.Repeat("b", 64))
	var exit *exec.ExitError
	if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &exit) || exit.ProcessState == nil {
		t.Fatal("deadline did not retain the original reaped command result")
	}
	if diagnostic := ProjectRequestDiagnostic(err); diagnostic.Code != "docker_image_pull_timeout_outcome_unknown" || !ValidRequestDiagnostic(diagnostic) {
		t.Fatal("actual timed pull lost its closed operation category")
	}
	if time.Since(started) > time.Second || !strings.Contains(commands(log), "image pull") {
		t.Fatal("pull did not stop inside its reserved total budget")
	}
}

func TestDockerPreparationRefusesUnboundedOrChangedSelection(t *testing.T) {
	driver, _, log := setupDocker(t)
	pin := "docker.io/library/nats@sha256:" + strings.Repeat("b", 64)
	if driver.pullPinnedBrokerImage(context.Background(), pin) == nil {
		t.Fatal("unbounded pull accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if driver.pullPinnedBrokerImage(ctx, "nats:latest") == nil {
		t.Fatal("mutable image accepted")
	}
	t.Setenv("DOCKER_HOST", "unix:///different.sock")
	if driver.pullPinnedBrokerImage(ctx, pin) == nil {
		t.Fatal("ambient daemon override accepted")
	}
	if commands(log) != "" {
		t.Fatal("refused preparation ran a command")
	}
}

func TestBrokerPreparationCleanupRetainsOwnerAndRedactsCause(t *testing.T) {
	command := exec.Command("/synthetic-private-command")
	lease := &BootstrapLock{}
	failure := &brokerPreparationCleanupError{command: command, lease: lease, cause: errors.New("synthetic-private-cause")}
	if failure.command != command || failure.lease != lease || !errors.Is(failure, errRuntimeCleanup) {
		t.Fatal("original cleanup owner lost")
	}
	for _, public := range []string{failure.Error(), fmt.Sprintf("%+v", failure), string(mustStatusJSON(failure)), string(mustStatusJSON(ProjectRequestDiagnostic(failure)))} {
		if strings.Contains(public, "synthetic-private") {
			t.Fatal("private cleanup details escaped")
		}
	}
	if ProjectRequestDiagnostic(failure).Code != "owned_cleanup_incomplete" {
		t.Fatal("cleanup uncertainty hidden")
	}
}

func TestDockerPreparationDiagnosticGrammarAndPrecedence(t *testing.T) {
	pin := "docker.io/library/nats@sha256:" + strings.Repeat("b", 64)
	args := []string{"image", "pull", "--platform", "linux/arm64", pin}
	failure := dockerCommandError("/private/selected", args, fail57HostileError{}, false)
	timeout := dockerCommandError("/private/selected", args, context.DeadlineExceeded, true)
	for _, check := range []struct {
		failure error
		code    string
	}{
		{failure, "docker_image_pull_failed"},
		{timeout, "docker_image_pull_timeout_outcome_unknown"},
		{errors.Join(failure, errRuntimeCleanup), "owned_cleanup_incomplete"},
		{errors.Join(timeout, errRuntimeCleanup), "owned_cleanup_incomplete"},
		{errors.Join(timeout, errOwnerBridgeAuthority), "runtime_authority_rejected"},
		{errors.Join(failure, context.Canceled), "request_failed"},
		{refusal("prepared_image_mismatch"), "docker_prepared_image_mismatch"},
		{refusal("preparation_owner_required"), "broker_preparation_owner_required"},
		{refusal("preparation_platform_unqualified"), "broker_preparation_platform_unqualified"},
		{ErrBrokerPreparationOutput, "broker_preparation_output_failed"},
		{errors.New("docker_image_pull_failed"), "request_failed"},
		{errors.New("broker_preparation_output_failed"), "request_failed"},
	} {
		got := ProjectRequestDiagnostic(check.failure)
		if got.Code != check.code || !ValidRequestDiagnostic(got) {
			t.Fatalf("preparation diagnostic mismatch: got %s, want %s", got.Code, check.code)
		}
	}
	for _, changed := range [][]string{
		{"pull", pin}, {"image", "pull", pin}, {"image", "pull", "--platform", "linux/amd64", pin},
		{"image", "pull", "--platform", "linux/arm64", "nats:latest"},
		{"image", "pull", "--platform", "linux/arm64", pin, "extra"},
	} {
		if dockerCommandStage(changed) != "unknown" {
			t.Fatal("unapproved pull grammar acquired preparation authority")
		}
	}
}
