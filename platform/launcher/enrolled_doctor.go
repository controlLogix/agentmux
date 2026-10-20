//go:build linux || darwin

package launcher

import (
	"context"
	"time"
)

// Doctor validates the same private enrollment and release as startup, then
// performs read-only Docker diagnostics. It never starts a host or writes a
// health record. Service checks remain unknown until authenticated read-only
// probes are supplied by their owners.
func (h *EnrolledHostPolicy) Doctor(ctx context.Context) (DoctorReport, error) {
	if ctx == nil || ctx.Err() != nil {
		return DoctorReport{}, hostPolicyError("context_invalid")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, owner, err := h.Load()
	if err != nil {
		return DoctorReport{}, err
	}
	// LoadOwnerStatus retained this exact private declaration after binding it
	// to the enrolled owner. Do not reopen the profile to select another engine.
	profile := owner.profile
	if profile == nil || profile.Mode != "local" || profile.Docker == nil {
		return DoctorReport{}, hostPolicyError("profile_binding_invalid")
	}
	selection := *profile.Docker
	return RunDoctor(ctx, DoctorConfig{
		ProfileValidated: true,
		Docker: DockerConfig{Executable: selection.Executable, Context: selection.Context,
			Endpoint: selection.Endpoint, EngineID: selection.EngineID, Backend: selection.Backend,
			Versions: DockerVersions{selection.ClientVersion, selection.ServerVersion, selection.ComposeVersion},
			Timeout:  5 * time.Second},
	}), nil
}
