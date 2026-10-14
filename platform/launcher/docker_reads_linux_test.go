//go:build linux

package launcher

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func dockerReadPidfds(t *testing.T, directory string) []int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	names := []string{"identity-version.started", "identity-info.started", "identity-compose.started"}
	for {
		all := true
		for _, name := range names {
			if _, err := os.Stat(filepath.Join(directory, name)); err != nil {
				all = false
			}
		}
		if all {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("all three controlled CLI processes did not reach their barriers")
		}
		time.Sleep(5 * time.Millisecond)
	}
	var descriptors []int
	t.Cleanup(func() {
		for _, fd := range descriptors {
			unix.Close(fd)
		}
	})
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		pid, err := strconv.Atoi(string(data))
		if err != nil || pid <= 0 {
			t.Fatal("controlled child identity invalid")
		}
		fd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			t.Fatal("exact controlled process exit observer unavailable")
		}
		descriptors = append(descriptors, fd)
	}
	return descriptors
}

func TestDockerParallelReadCancellationJoinsActualChildren(t *testing.T) {
	for _, mode := range []string{"cancel", "fail-after-start"} {
		t.Run(mode, func(t *testing.T) {
			d, directory := setupParallelDocker(t, mode)
			d.config.Timeout = 4 * time.Second
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			type result struct {
				observation DockerInspection
				err         error
			}
			results := make(chan result, 1)
			finished := make(chan struct{})
			t.Cleanup(func() {
				cancel()
				select {
				case <-finished:
				case <-time.After(5 * time.Second):
					t.Error("controlled inspection did not join")
				}
			})
			go func() { defer close(finished); observation, err := d.Inspect(ctx); results <- result{observation, err} }()
			pidfds := dockerReadPidfds(t, directory)
			if mode == "cancel" {
				cancel()
			} else if os.WriteFile(filepath.Join(directory, "release-failure"), nil, 0600) != nil {
				t.Fatal("failure barrier could not be released")
			}
			var actual result
			select {
			case actual = <-results:
			case <-time.After(2 * time.Second):
				t.Fatal("failed read did not cancel and join siblings before their independent timeouts")
			}
			want := "docker_command_timeout_outcome_unknown"
			if mode == "fail-after-start" {
				want = "docker_command_failed"
			}
			if actual.err == nil || actual.err.Error() != want || actual.observation != (DockerInspection{}) {
				t.Fatal("first read failure was masked or partial observation returned")
			}
			var stage interface{ inspectionStage() string }
			if !errors.As(actual.err, &stage) {
				t.Fatal("safe typed inspection stage missing")
			}
			if mode == "fail-after-start" && stage.inspectionStage() != "version" {
				t.Fatal("actual failing stage was replaced by an induced sibling cancellation")
			}
			for _, fd := range pidfds {
				poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
				if n, err := unix.Poll(poll, 0); err != nil || n != 1 || poll[0].Revents&unix.POLLIN == 0 {
					t.Fatal("inspection returned before an exact controlled CLI child exited")
				}
			}
		})
	}
}

func TestDockerParallelReadRejectsNonReadForms(t *testing.T) {
	d, directory := setupParallelDocker(t, "concurrency")
	for _, commands := range [][][]string{
		nil,
		{{"compose", "up", "--detach"}},
		{{"container", "stop", "owned"}},
		{{"version", "--format", "private-arbitrary-template"}},
		{{"ps", "--all", "--quiet", "--no-trunc", "--filter", "name=project;unsafe_"}},
		{{"compose", "version", "--short"}, {"compose", "version", "--short"}, {"compose", "version", "--short"}, {"compose", "version", "--short"}},
	} {
		output, err := d.parallelReads(context.Background(), commands...)
		if output != nil || err == nil || err.Error() != "docker_parallel_read_invalid" {
			t.Fatal("unsupported read batch accepted")
		}
	}
	files, err := os.ReadDir(directory)
	if err != nil || len(files) != 0 {
		t.Fatal("rejected batch launched a command")
	}
}
