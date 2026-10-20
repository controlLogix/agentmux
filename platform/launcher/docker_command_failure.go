package launcher

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// Keep the original outward refusal code while retaining the actual exec cause.
// Stage is a fixed operation, never an argument, endpoint or subprocess output.
type dockerCommandFailure struct {
	stage    string
	cause    error
	timedOut bool
	client   string
}

func (e *dockerCommandFailure) Error() string {
	if e != nil && e.timedOut {
		return "docker_command_timeout_outcome_unknown"
	}
	return "docker_command_failed"
}
func (e *dockerCommandFailure) Format(state fmt.State, _ rune) { fmt.Fprint(state, e.Error()) }
func (e *dockerCommandFailure) MarshalJSON() ([]byte, error)   { return json.Marshal(e.Error()) }
func (e *dockerCommandFailure) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

const preparedBrokerImageFormat = `{"ID":{{json .Id}},"RepoDigests":{{json .RepoDigests}},"OS":{{json .Os}},"Architecture":{{json .Architecture}}}`

func pinnedBrokerImage(image string) bool {
	value, ok := strings.CutPrefix(image, "docker.io/library/nats@")
	return ok && digest.MatchString(value)
}

func dockerCommandStage(args []string) string {
	if len(args) == 5 && args[0] == "image" && args[1] == "pull" &&
		args[2] == "--platform" && args[3] == "linux/arm64" && pinnedBrokerImage(args[4]) {
		return "pinned_image_pull"
	}
	if len(args) == 5 && args[0] == "image" && args[1] == "inspect" &&
		pinnedBrokerImage(args[2]) && args[3] == "--format" && args[4] == preparedBrokerImageFormat {
		return "prepared_image_read"
	}
	if len(args) == 3 {
		switch {
		case args[0] == "compose" && args[1] == "version" && args[2] == "--short":
			return "compose_version"
		case args[0] == "version" && args[1] == "--format" && args[2] == dockerVersionReadFormat:
			return "engine_read"
		case args[0] == "info" && args[1] == "--format" && args[2] == dockerInfoReadFormat:
			return "engine_read"
		}
	}
	if len(args) == 5 && args[0] == "image" && args[1] == "inspect" &&
		strings.HasPrefix(args[2], "docker.io/library/nats@") &&
		digest.MatchString(strings.TrimPrefix(args[2], "docker.io/library/nats@")) &&
		args[3] == "--format" && args[4] == "{{json .Id}}" {
		return "pinned_image_read"
	}
	if len(args) == 13 && args[0] == "compose" && args[1] == "--project-name" &&
		slug.MatchString(args[2]) && args[3] == "--file" && args[4] == "-" &&
		args[5] == "up" && args[6] == "--detach" && args[7] == "--wait" &&
		args[8] == "--wait-timeout" && args[9] == "60" && args[10] == "--pull" &&
		args[11] == "never" && args[12] == "--no-build" {
		return "compose_start"
	}
	return "unknown"
}

func dockerCommandError(client string, args []string, cause error, timedOut bool) error {
	return &dockerCommandFailure{stage: dockerCommandStage(args), cause: cause, timedOut: timedOut, client: client}
}

// Inspect only private wrappers produced on this driver path. Unknown wrappers,
// Error/Is/As methods and matching text supply no cause evidence.
func dockerInspectedFailure(failure error) error {
	for depth := 0; depth < 8; depth++ {
		stage, ok := failure.(*dockerInspectionFailure)
		if !ok || stage == nil {
			return failure
		}
		failure = stage.cause
	}
	return nil
}

func dockerFailureDetail(failure error) string {
	command, ok := dockerInspectedFailure(failure).(*dockerCommandFailure)
	if !ok || command == nil || command.timedOut {
		return ""
	}
	// ENOENT can mean a missing interpreter as well as a missing client. Do not
	// claim an executable-path inventory or plugin-discovery result from it.
	if actual, ok := command.cause.(*os.PathError); ok && actual != nil &&
		actual.Op == "fork/exec" && actual.Path == command.client {
		if number, ok := actual.Err.(syscall.Errno); ok {
			switch number {
			case syscall.ENOENT:
				return "docker_client_missing"
			case syscall.EACCES, syscall.EPERM:
				return "docker_client_permission_denied"
			}
		}
	}
	// These are operation failures, not proof of a missing plugin/image,
	// unavailable daemon, or denied daemon authorization.
	switch command.stage {
	case "compose_version":
		return "docker_compose_check_failed"
	case "engine_read":
		return "docker_engine_check_failed"
	case "pinned_image_read":
		return "docker_cache_check_failed"
	case "pinned_image_pull":
		return "docker_image_pull_failed"
	case "prepared_image_read":
		return "docker_prepared_image_check_failed"
	case "compose_start":
		return "docker_compose_start_failed"
	}
	return ""
}
