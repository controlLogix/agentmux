package launcher

import (
	"context"
	"errors"
	"os"
	"regexp"
	"time"
)

type DoctorStatus string
type DoctorCode string

const (
	DoctorPassed      DoctorStatus = "passed"
	DoctorUnknown     DoctorStatus = "unknown"
	DoctorUnavailable DoctorStatus = "unavailable"
	DoctorFailed      DoctorStatus = "failed"

	DoctorObserved            DoctorCode = "observed"
	DoctorNotProbed           DoctorCode = "not_probed"
	DoctorInvalidConfig       DoctorCode = "invalid_configuration"
	DoctorProfileUnvalidated  DoctorCode = "profile_not_validated"
	DoctorClientMissing       DoctorCode = "client_missing"
	DoctorClientPermission    DoctorCode = "client_permission_denied"
	DoctorClientInvalid       DoctorCode = "client_not_regular_executable"
	DoctorInspectionUnknown   DoctorCode = "inspection_unavailable"
	DoctorEnvironmentConflict DoctorCode = "environment_conflict"
	DoctorEndpointConflict    DoctorCode = "endpoint_conflict"
	DoctorBackendConflict     DoctorCode = "identity_or_version_conflict"
	DoctorInvalidObservation  DoctorCode = "invalid_observation"
	DoctorDeadline            DoctorCode = "deadline_exceeded"
	DoctorCancelled           DoctorCode = "cancelled"
	DoctorProbeVerified       DoctorCode = "probe_verified"
	DoctorProbeUnavailable    DoctorCode = "probe_unavailable"
	DoctorProbePermission     DoctorCode = "probe_permission_denied"
	DoctorProbeMismatch       DoctorCode = "probe_mismatch"
)

type DoctorProbeResult struct {
	Status DoctorStatus
	Code   DoctorCode
}

// DoctorProbe must perform only authenticated read-only observations and honor
// cancellation. A supplied callback is trusted integration code, not a plugin
// execution boundary. The doctor cannot terminate an arbitrary Go callback.
type DoctorProbe func(context.Context) DoctorProbeResult

type DoctorProbes struct {
	Broker, Persistence, ProtectedRoles DoctorProbe
}

type DoctorConfig struct {
	Docker DockerConfig
	// This is an internal caller assertion after private profile/release validation,
	// not an authorization flag accepted from external JSON or plugin input.
	ProfileValidated bool         `json:"-"`
	Probes           DoctorProbes `json:"-"`
	// Zero selects the five-second maximum. Smaller values support bounded callers.
	Timeout time.Duration
}

type DoctorCheck struct {
	Name      string       `json:"name"`
	Status    DoctorStatus `json:"status"`
	Code      DoctorCode   `json:"code"`
	ElapsedMS int64        `json:"elapsedMs"`
}

type DoctorObservation struct {
	Backend  DockerBackend  `json:"backend"`
	EngineID string         `json:"engineId"`
	Versions DockerVersions `json:"versions"`
}

type DoctorReport struct {
	Checks            []DoctorCheck      `json:"checks"`
	Observation       *DoctorObservation `json:"observation,omitempty"`
	DiagnosticsPassed bool               `json:"diagnosticsPassed"`
	ElapsedMS         int64              `json:"elapsedMs"`
	// Diagnostics never grant application readiness, authority or phase acceptance.
	Scope string `json:"scope"`
}

var doctorEngineID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

func doctorContextCode(ctx context.Context) DoctorCode {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return DoctorDeadline
	}
	return DoctorCancelled
}

func doctorInspectionResult(err error, ctx context.Context) DoctorProbeResult {
	if ctx.Err() != nil {
		return DoctorProbeResult{DoctorUnavailable, doctorContextCode(ctx)}
	}
	// These exact safe codes come from the frozen driver. Generic command failure
	// cannot distinguish a stopped daemon from permissions or a missing subcommand.
	switch err.Error() {
	case "docker_environment_conflict":
		return DoctorProbeResult{DoctorFailed, DoctorEnvironmentConflict}
	case "docker_endpoint_mismatch":
		return DoctorProbeResult{DoctorFailed, DoctorEndpointConflict}
	case "docker_backend_mismatch":
		return DoctorProbeResult{DoctorFailed, DoctorBackendConflict}
	case "docker_invalid_observation", "docker_output_limit":
		return DoctorProbeResult{DoctorUnknown, DoctorInvalidObservation}
	case "docker_command_timeout_outcome_unknown":
		return DoctorProbeResult{DoctorUnavailable, DoctorDeadline}
	default:
		return DoctorProbeResult{DoctorUnavailable, DoctorInspectionUnknown}
	}
}

func doctorProbeResult(result DoctorProbeResult) DoctorProbeResult {
	valid := (result.Status == DoctorPassed && result.Code == DoctorProbeVerified) ||
		(result.Status == DoctorUnknown && result.Code == DoctorNotProbed) ||
		(result.Status == DoctorUnavailable && result.Code == DoctorProbeUnavailable) ||
		(result.Status == DoctorFailed && result.Code == DoctorProbePermission) ||
		(result.Status == DoctorFailed && result.Code == DoctorProbeMismatch)
	if !valid {
		return DoctorProbeResult{DoctorUnknown, DoctorInvalidObservation}
	}
	return result
}

// RunDoctor inspects the explicit selection without changing Docker, profiles,
// legacy state or configuration. It does not call Compose lifecycle operations.
// Missing integration probes remain unknown. No endpoint, path, raw error,
// command body or subprocess output is returned in the report.
func RunDoctor(parent context.Context, config DoctorConfig) (report DoctorReport) {
	started := time.Now()
	report.Scope = "Read-only diagnostics; not application readiness or phase acceptance."
	for _, name := range []string{"profile", "client", "docker", "broker", "persistence", "protected-roles"} {
		report.Checks = append(report.Checks, DoctorCheck{Name: name, Status: DoctorUnknown, Code: DoctorNotProbed})
	}
	defer func() {
		report.ElapsedMS = time.Since(started).Milliseconds()
		report.DiagnosticsPassed = true
		for _, check := range report.Checks {
			if check.Status != DoctorPassed {
				report.DiagnosticsPassed = false
			}
		}
	}()
	set := func(index int, result DoctorProbeResult, begin time.Time) {
		report.Checks[index].Status = result.Status
		report.Checks[index].Code = result.Code
		report.Checks[index].ElapsedMS = time.Since(begin).Milliseconds()
	}
	if parent == nil || config.Timeout < 0 || config.Timeout > 5*time.Second {
		set(0, DoctorProbeResult{DoctorFailed, DoctorInvalidConfig}, started)
		return
	}
	budget := config.Timeout
	if budget == 0 {
		budget = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	if ctx.Err() != nil {
		set(0, DoctorProbeResult{DoctorUnavailable, doctorContextCode(ctx)}, started)
		return
	}
	if !config.ProfileValidated {
		set(0, DoctorProbeResult{DoctorUnknown, DoctorProfileUnvalidated}, started)
		return
	}
	if !doctorEngineID.MatchString(config.Docker.EngineID) || len(config.Docker.Versions.Client) > 64 ||
		len(config.Docker.Versions.Server) > 64 || len(config.Docker.Versions.Compose) > 64 {
		set(0, DoctorProbeResult{DoctorFailed, DoctorInvalidConfig}, started)
		return
	}
	driver, err := NewDocker(config.Docker)
	if err != nil {
		result := DoctorProbeResult{DoctorFailed, DoctorInvalidConfig}
		if err.Error() == "docker_environment_conflict" {
			result.Code = DoctorEnvironmentConflict
		}
		set(0, result, started)
		return
	}
	set(0, DoctorProbeResult{DoctorPassed, DoctorObserved}, started)
	begin := time.Now()
	client, err := os.Stat(config.Docker.Executable)
	if err != nil {
		result := DoctorProbeResult{DoctorUnavailable, DoctorInspectionUnknown}
		if errors.Is(err, os.ErrNotExist) {
			result.Code = DoctorClientMissing
		} else if errors.Is(err, os.ErrPermission) {
			result = DoctorProbeResult{DoctorFailed, DoctorClientPermission}
		}
		set(1, result, begin)
		return
	}
	if !client.Mode().IsRegular() || client.Mode().Perm()&0111 == 0 {
		set(1, DoctorProbeResult{DoctorFailed, DoctorClientInvalid}, begin)
		return
	}
	set(1, DoctorProbeResult{DoctorPassed, DoctorObserved}, begin)
	begin = time.Now()
	deadline, _ := ctx.Deadline()
	// The frozen driver permits one second to close inherited output pipes after
	// cancellation. Reserve that cleanup time within the doctor's total deadline.
	if time.Until(deadline) <= time.Second {
		set(2, DoctorProbeResult{DoctorUnavailable, DoctorDeadline}, begin)
		return
	}
	inspectionCtx, inspectionCancel := context.WithDeadline(ctx, deadline.Add(-time.Second))
	observation, err := driver.Inspect(inspectionCtx)
	if err != nil {
		set(2, doctorInspectionResult(err, inspectionCtx), begin)
		inspectionCancel()
		return
	}
	inspectionCancel()
	report.Observation = &DoctorObservation{observation.Backend, observation.EngineID, observation.Versions}
	set(2, DoctorProbeResult{DoctorPassed, DoctorObserved}, begin)
	for index, probe := range []DoctorProbe{config.Probes.Broker, config.Probes.Persistence, config.Probes.ProtectedRoles} {
		begin = time.Now()
		if ctx.Err() != nil {
			set(index+3, DoctorProbeResult{DoctorUnavailable, doctorContextCode(ctx)}, begin)
			break
		}
		if probe == nil {
			continue
		}
		result := doctorProbeResult(probe(ctx))
		if ctx.Err() != nil {
			result = DoctorProbeResult{DoctorUnavailable, doctorContextCode(ctx)}
		}
		set(index+3, result, begin)
	}
	return
}
