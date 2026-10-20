//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"time"

	protected "github.com/controlLogix/agentmux/platform/runtime"
)

// BrokerImagePreparationLimit includes admission, lock waiting, the original
// Docker wait/output joins and the final response. Startup has its own budget.
const BrokerImagePreparationLimit = 180 * time.Second

const brokerPreparationCleanupReserve = 2 * time.Second

// ErrBrokerPreparationOutput reports a failed public writer without retaining
// the writer's arbitrary error text or changing command ownership.
var ErrBrokerPreparationOutput = errors.New("broker_image_preparation_output_failed")

// BrokerImagePreparationProgress contains fixed public stages, never Docker
// output. A completed preparation makes no claim about application readiness.
type BrokerImagePreparationProgress struct {
	SchemaVersion string `json:"schemaVersion"`
	Kind          string `json:"kind"`
	Stage         string `json:"stage"`
	Message       string `json:"message"`
}

type BrokerImagePreparationResult struct {
	SchemaVersion string             `json:"schemaVersion"`
	Kind          string             `json:"kind"`
	Outcome       string             `json:"outcome"`
	Stage         string             `json:"stage"`
	Readiness     string             `json:"readiness"`
	Diagnostic    *RequestDiagnostic `json:"diagnostic,omitempty"`
}

func brokerPreparationProgress(stage string) BrokerImagePreparationProgress {
	message := "Checking the enrolled owner, release and selected local Docker engine."
	switch stage {
	case "waiting_for_owner":
		message = "Waiting for the enrolled instance's preparation or startup owner."
	case "downloading":
		message = "Preparing to download the release's pinned broker image. Cached layers may be reused."
	case "verifying":
		message = "Verifying the pinned image on the enrolled local engine."
	default:
		stage = "checking"
	}
	return BrokerImagePreparationProgress{"1.0.0", "broker-image-preparation-progress", stage, message}
}

// This private error retains an uncertain original command and lease. Error
// formatting cannot expose its arguments, configuration or subprocess output.
type brokerPreparationCleanupError struct {
	command *exec.Cmd
	lease   *BootstrapLock
	images  []*protected.InstalledHostImage
	cause   error
}

func (e *brokerPreparationCleanupError) Error() string {
	return "broker_image_preparation_cleanup_incomplete"
}
func (e *brokerPreparationCleanupError) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, e.Error())
}
func (e *brokerPreparationCleanupError) MarshalJSON() ([]byte, error) { return json.Marshal(e.Error()) }
func (e *brokerPreparationCleanupError) Unwrap() error {
	return errors.Join(errRuntimeCleanup, e.cause)
}

// PrepareBrokerImage is an explicit action by the already enrolled OS owner.
// No startup, warm-reuse or recovery caller invokes it. Only the signed release
// selects the image; the caller cannot supply an image, engine or Docker args.
// Progress must return promptly. The installed CLI supplies a bounded writer.
func (h *EnrolledHostPolicy) PrepareBrokerImage(parent context.Context, progress func(BrokerImagePreparationProgress) error) (result BrokerImagePreparationResult, failure error) {
	stage := "checking"
	result = BrokerImagePreparationResult{SchemaVersion: "1.0.0", Kind: "broker-image-preparation-result", Outcome: "failed", Stage: stage, Readiness: "not_observed"}
	defer func() {
		result.Stage = stage
		if failure != nil {
			diagnostic := ProjectRequestDiagnostic(failure)
			result.Diagnostic = &diagnostic
		}
	}()
	if h == nil || parent == nil || progress == nil {
		return result, hostPolicyError("context_invalid")
	}
	if err := parent.Err(); err != nil {
		return result, err
	}
	if uint32(os.Getuid()) != h.selection.OwnerUID || uint32(os.Geteuid()) != h.selection.OwnerUID {
		return result, refusal("preparation_owner_required")
	}
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		return result, refusal("preparation_platform_unqualified")
	}
	total, cancelTotal := context.WithTimeout(parent, BrokerImagePreparationLimit)
	defer cancelTotal()
	deadline, _ := total.Deadline()
	work, cancelWork := context.WithDeadline(total, deadline.Add(-brokerPreparationCleanupReserve))
	defer cancelWork()
	emit := func(next string) error {
		stage = next
		if err := work.Err(); err != nil {
			return err
		}
		if err := progress(brokerPreparationProgress(stage)); err != nil {
			return ErrBrokerPreparationOutput
		}
		return work.Err()
	}
	if err := emit("checking"); err != nil {
		return result, err
	}
	fresh, err := LoadEnrolledHostPolicy(h.selection)
	if err != nil || !reflect.DeepEqual(fresh.record, h.record) {
		return result, hostPolicyError("declarations_invalid")
	}
	config, owner, err := fresh.Load()
	if err != nil {
		return result, err
	}
	profile := owner.profile
	if profile == nil || profile.Mode != "local" || profile.Docker == nil || profile.Docker.Backend != NativeUnix {
		return result, hostPolicyError("profile_binding_invalid")
	}
	selected := *profile.Docker
	driver, err := NewDocker(DockerConfig{Executable: selected.Executable, Context: selected.Context,
		Endpoint: selected.Endpoint, EngineID: selected.EngineID, Backend: selected.Backend,
		Versions: DockerVersions{selected.ClientVersion, selected.ServerVersion, selected.ComposeVersion}, Timeout: 4 * time.Second})
	if err != nil {
		return result, err
	}
	if _, err := driver.Inspect(work); err != nil {
		return result, err
	}
	if err := emit("waiting_for_owner"); err != nil {
		return result, err
	}
	lease, err := AcquireBootstrapLock(work, profile.ProfileDirectory, profile.InstanceID, selected.EngineID)
	if err != nil {
		return result, err
	}
	var images []*protected.InstalledHostImage
	defer func() {
		var uncertain *brokerPreparationCleanupError
		if errors.As(failure, &uncertain) {
			uncertain.lease = lease
			uncertain.images = images
			return
		}
		var closeFailure error
		for _, image := range images {
			closeFailure = errors.Join(closeFailure, image.Close())
		}
		if closeFailure != nil {
			failure = &brokerPreparationCleanupError{lease: lease, images: images, cause: errors.Join(failure, closeFailure)}
			stage, result.Outcome = "cleanup", "failed"
			return
		}
		if err := lease.Close(); err != nil {
			failure = &brokerPreparationCleanupError{lease: lease, cause: errors.Join(failure, err)}
			stage = "cleanup"
			result.Outcome = "failed"
		}
	}()
	revalidate := func() error {
		current, err := LoadEnrolledHostPolicy(h.selection)
		if err != nil || !reflect.DeepEqual(current.record, h.record) {
			return hostPolicyError("declarations_invalid")
		}
		loaded, currentOwner, err := current.Load()
		if err != nil {
			return err
		}
		if !sameLocalBrokerEnrollment(config, loaded) || currentOwner.profile == nil || !reflect.DeepEqual(*currentOwner.profile, *profile) {
			return hostPolicyError("profile_binding_invalid")
		}
		// Keep the same protected installed-runtime admission as ensure, without
		// starting it. Handles remain owned until the original pull has joined.
		image, err := current.PrepareHost(work)
		if err != nil {
			if errors.Is(err, protected.ErrStartupCleanup) {
				return &brokerPreparationCleanupError{cause: err}
			}
			return err
		}
		images = append(images, image)
		if _, err := driver.Inspect(work); err != nil {
			return err
		}
		return work.Err()
	}
	if err := emit("downloading"); err != nil {
		return result, err
	}
	// Repeat complete admission after obtaining the actual lock and after the
	// last public progress callback, immediately before the sole mutation.
	stage = "checking"
	if err := revalidate(); err != nil {
		return result, err
	}
	stage = "downloading"
	if err := driver.pullPinnedBrokerImage(work, config.BrokerImage); err != nil {
		return result, err
	}
	if err := emit("verifying"); err != nil {
		return result, err
	}
	if err := revalidate(); err != nil {
		return result, err
	}
	if err := driver.verifyPreparedBrokerImage(work, config.BrokerImage); err != nil {
		return result, err
	}
	if err := work.Err(); err != nil {
		return result, err
	}
	stage, result.Outcome = "prepared", "prepared"
	return result, nil
}
