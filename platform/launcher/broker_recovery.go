//go:build linux || darwin

package launcher

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
)

// brokerRecovery belongs to the cold startup owner. It can restart only the
// same enrolled container; absence or replacement requires a new explicit start.
// It owns no loop or goroutine. The lifecycle controller bounds attempt count
// and joins each operation before releasing its own lifetime.
type brokerRecovery struct {
	config      BootstrapConfig
	profile     Profile
	containerID string
}

func newBrokerRecovery(c BootstrapConfig, p Profile, broker OwnedBroker) (*brokerRecovery, error) {
	if c.Kernel.authority == nil || c.admissionPolicy == nil || p.Docker == nil ||
		!fullID.MatchString(broker.ContainerID) || broker.State != "running" ||
		p.ProfileID != c.Kernel.Scope.ProfileID || p.InstanceID != c.Kernel.Scope.InstanceID ||
		p.ReleaseFingerprint != c.Kernel.Scope.ReleaseManifestDigest ||
		p.NATSEndpoint != c.Kernel.Endpoint || p.ConfigDigest != "sha256:"+hexDigest(c.Compose) ||
		!sameLocalBrokerEnrollment(c, c.Kernel.authority.config) {
		return nil, bootstrapError("broker_recovery_binding_invalid")
	}
	bound := c.Kernel.authority.config
	bound.Kernel.authority = c.Kernel.authority
	p.Docker = cloneOperationDocker(p.Docker)
	return &brokerRecovery{config: bound, profile: p, containerID: broker.ContainerID}, nil
}

func (r *brokerRecovery) inspect(ctx context.Context) (localBrokerAuthority, error) {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return localBrokerAuthority{}, bootstrapError("broker_recovery_context_invalid")
	}
	p, err := LoadProfile(r.config.ProfilePolicy)
	if err != nil || !reflect.DeepEqual(p.Declaration(), r.profile) {
		return localBrokerAuthority{}, localAuthorityFailure("broker_recovery_selection_changed", err)
	}
	facts, err := inspectLocalBrokerAuthority(ctx, r.config)
	if err != nil {
		return localBrokerAuthority{}, err
	}
	if facts.broker.ContainerID != r.containerID || (facts.state != "running" && facts.state != "stopped") {
		return localBrokerAuthority{}, bootstrapError("broker_recovery_identity_changed")
	}
	return facts, nil
}

// recover returns whether it issued one start. A running container is left
// alone, even if application traffic failed. Success is not kernel/application
// readiness: the controller must still obtain fresh scoped observations.
func (r *brokerRecovery) recover(parent context.Context) (started bool, failure error) {
	if parent == nil || parent.Err() != nil {
		return false, bootstrapError("broker_recovery_context_invalid")
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	facts, err := r.inspect(ctx)
	if err != nil || facts.state == "running" {
		return false, err
	}
	selection := r.profile.Docker
	lease, err := AcquireBootstrapLock(ctx, r.profile.ProfileDirectory, r.profile.InstanceID, selection.EngineID)
	if err != nil {
		return false, err
	}
	defer func() {
		if cleanup := lease.Close(); cleanup != nil {
			failure = &bootstrapFailureCause{code: "lease_close_failed", cause: errors.Join(failure, cleanup, errRuntimeCleanup), leases: []*BootstrapLock{lease}}
		}
	}()
	// Repeat complete enrollment, engine, resource and private-file checks after
	// acquiring the actual bootstrap lease, immediately before the mutation.
	facts, err = r.inspect(ctx)
	if err != nil || facts.state == "running" {
		return false, err
	}
	driver, err := NewDocker(DockerConfig{Executable: selection.Executable, Context: selection.Context,
		Endpoint: selection.Endpoint, EngineID: selection.EngineID, Backend: selection.Backend,
		Versions: DockerVersions{selection.ClientVersion, selection.ServerVersion, selection.ComposeVersion}, Timeout: 5 * time.Second})
	if err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	// No Compose up, pull, recreate, replacement container or volume operation.
	// The full ID came from the owning startup and both fresh inspections.
	if _, err := driver.run(ctx, nil, "container", "start", r.containerID); err != nil {
		return true, err
	}
	facts, err = r.inspect(ctx)
	if err != nil {
		return true, err
	}
	if facts.state != "running" {
		return true, bootstrapError("broker_recovery_not_running")
	}
	observed, err := deployment.Observe(ctx, deployment.ObserveOptions{ProbeOptions: r.config.Health, ReadExistingRecord: true})
	if err != nil {
		return true, err
	}
	if !observed.BrokerVerified || observed.PersistenceEvidence != deployment.PersistenceRecordSeen {
		return true, bootstrapError("broker_recovery_persistence_unavailable")
	}
	return true, nil
}
