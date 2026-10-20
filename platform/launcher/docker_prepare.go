//go:build linux || darwin

package launcher

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

// The enrolled Unix endpoint is literal for the mutation and its image read.
// The enclosing preparation checks the context and engine before each call;
// changing a context file afterward cannot redirect the pull to another daemon.
func (d *Docker) pullPinnedBrokerImage(parent context.Context, image string) error {
	if d == nil || parent == nil || d.config.Backend != NativeUnix || !pinnedBrokerImage(image) {
		return refusal("preparation_selection_invalid")
	}
	if err := d.environment(); err != nil {
		return err
	}
	deadline, bounded := parent.Deadline()
	if !bounded {
		return refusal("preparation_deadline_missing")
	}
	// The caller already reserved final cleanup/output. This additional second
	// belongs to exec's original output-reader join, inside that work deadline.
	ctx, cancel := context.WithDeadline(parent, deadline.Add(-time.Second))
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	args := []string{"image", "pull", "--platform", "linux/arm64", image}
	command := exec.CommandContext(ctx, d.config.Executable, append([]string{"--host", d.config.Endpoint}, args...)...)
	command.Env = dockerEnvironment()
	command.Stdout, command.Stderr = io.Discard, io.Discard
	command.WaitDelay = time.Second
	err := command.Run()
	if errors.Is(err, exec.ErrWaitDelay) {
		return &brokerPreparationCleanupError{command: command, cause: err}
	}
	if err != nil {
		if ctx.Err() != nil {
			err = errors.Join(err, ctx.Err())
		}
		return dockerCommandError(d.config.Executable, args, err, ctx.Err() == context.DeadlineExceeded)
	}
	if err := ctx.Err(); err != nil {
		return dockerCommandError(d.config.Executable, args, err, true)
	}
	return nil
}

func (d *Docker) verifyPreparedBrokerImage(parent context.Context, image string) error {
	if d == nil || parent == nil || d.config.Backend != NativeUnix || !pinnedBrokerImage(image) {
		return refusal("preparation_selection_invalid")
	}
	if err := d.environment(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	args := []string{"image", "inspect", image, "--format", preparedBrokerImageFormat}
	command := exec.CommandContext(ctx, d.config.Executable, append([]string{"--host", d.config.Endpoint}, args...)...)
	command.Env = dockerEnvironment()
	command.WaitDelay = time.Second
	var output limitedOutput
	command.Stdout, command.Stderr = &output, io.Discard
	err := command.Run()
	if errors.Is(err, exec.ErrWaitDelay) {
		return &brokerPreparationCleanupError{command: command, cause: err}
	}
	if err != nil {
		if ctx.Err() != nil {
			err = errors.Join(err, ctx.Err())
		}
		return dockerCommandError(d.config.Executable, args, err, ctx.Err() == context.DeadlineExceeded)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if output.exceeded || !preparedBrokerImageMatches(output.Bytes(), image) {
		return refusal("prepared_image_mismatch")
	}
	return nil
}

func preparedBrokerImageMatches(raw []byte, image string) bool {
	if !pinnedBrokerImage(image) || !dockerInfoJSONUnique(raw) {
		return false
	}
	var actual struct {
		ID           string   `json:"ID"`
		OS           string   `json:"OS"`
		Architecture string   `json:"Architecture"`
		RepoDigests  []string `json:"RepoDigests"`
	}
	if protocol.DecodeClosedJSON(raw, &actual, 64*1024) != nil || !digest.MatchString(actual.ID) || actual.OS != "linux" || actual.Architecture != "arm64" || len(actual.RepoDigests) > 64 {
		return false
	}
	want := strings.TrimPrefix(image, "docker.io/library/nats@")
	for _, candidate := range actual.RepoDigests {
		repository, found, ok := strings.Cut(candidate, "@")
		if ok && found == want && (repository == "nats" || repository == "library/nats" || repository == "docker.io/library/nats") {
			return true
		}
	}
	return false
}
