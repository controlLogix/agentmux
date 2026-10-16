package launcher

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

const dockerVersionReadFormat = `{"Client":{{json .Client.Version}},"Server":{{json .Server.Version}}}`
const dockerInfoReadFormat = `{"ID":{{json .ID}},"OS":{{json .OSType}}}`

// The code stays unchanged for callers. The private stage contains only a
// fixed operation name; it never contains an argument, endpoint or output.
type dockerInspectionFailure struct {
	stage             string
	cause             error
	bootstrapBoundary bool
	failedRead        *bootstrapFailedRead
}

func (e *dockerInspectionFailure) Error() string                  { return e.cause.Error() }
func (e *dockerInspectionFailure) Format(state fmt.State, _ rune) { fmt.Fprint(state, e.Error()) }
func (e *dockerInspectionFailure) Unwrap() error                  { return e.cause }
func (e *dockerInspectionFailure) inspectionStage() string        { return e.stage }
func inspectionFailure(stage string, cause error) error {
	return &dockerInspectionFailure{stage: stage, cause: cause}
}
func dockerReadStage(args []string) string {
	switch args[0] {
	case "version":
		return "version"
	case "info":
		return "engine"
	case "compose":
		return "compose_version"
	case "ps":
		return "roster"
	}
	return "unknown"
}

// These are the only independent read forms admitted to a batch. Mutations,
// private configuration archives and arbitrary caller arguments stay outside it.
func parallelDockerReadAllowed(args []string) bool {
	if len(args) == 3 {
		return (args[0] == "version" && args[1] == "--format" && args[2] == dockerVersionReadFormat) ||
			(args[0] == "info" && args[1] == "--format" && args[2] == dockerInfoReadFormat) ||
			(args[0] == "compose" && args[1] == "version" && args[2] == "--short")
	}
	if len(args) != 6 || args[0] != "ps" || args[1] != "--all" || args[2] != "--quiet" || args[3] != "--no-trunc" || args[4] != "--filter" {
		return false
	}
	filter := args[5]
	if project, ok := strings.CutPrefix(filter, "label=com.docker.compose.project="); ok {
		return slug.MatchString(project)
	}
	if name, ok := strings.CutPrefix(filter, "name="); ok {
		if !strings.HasSuffix(name, "_") && !strings.HasSuffix(name, "-") {
			return false
		}
		return slug.MatchString(name[:len(name)-1])
	}
	return false
}

// Every read owns its normal bounded exec.Cmd. The first actual error cancels
// sibling reads, and the caller joins all commands before receiving an error.
// An error or expired caller context returns no successful subset of results.
func (d *Docker) parallelReads(parent context.Context, commands ...[]string) ([][]byte, error) {
	if parent == nil {
		return nil, refusal("inspection_context_missing")
	}
	if len(commands) < 1 || len(commands) > 3 {
		return nil, refusal("parallel_read_invalid")
	}
	for _, args := range commands {
		if !parallelDockerReadAllowed(args) {
			return nil, refusal("parallel_read_invalid")
		}
	}
	if parent.Err() != nil {
		return nil, refusal("command_timeout_outcome_unknown")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	outputs := make([][]byte, len(commands))
	var joined sync.WaitGroup
	var first sync.Once
	var failure error
	joined.Add(len(commands))
	for i, args := range commands {
		go func(i int, args []string) {
			defer joined.Done()
			output, err := d.runFixedRead(ctx, dockerReadStage(args), nil, args...)
			if err != nil {
				first.Do(func() { failure = inspectionFailure(dockerReadStage(args), err); cancel() })
				return
			}
			outputs[i] = output
		}(i, args)
	}
	joined.Wait()
	if failure != nil {
		return nil, failure
	}
	if parent.Err() != nil {
		return nil, refusal("command_timeout_outcome_unknown")
	}
	return outputs, nil
}
