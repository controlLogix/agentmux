//go:build linux || darwin

package launcher

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/assembly"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

// BootstrapConfig is supplied by the enrolled host, not an ordinary plugin or
// an unauthenticated remote request. Its private bytes must never be displayed.
type BootstrapConfig struct {
	ProfilePolicy      ProfilePolicy
	Assembly           []byte
	PackageDirectory   string
	ReleaseTrust       assembly.Trust
	Compose            []byte
	BrokerImage        string
	BrokerConfigDigest [32]byte
	Health             deployment.ProbeOptions
	Kernel             KernelStatusOptions
	Roles              [4]protected.RoleOptions
	Deadlines          protected.Deadlines
	StartupTimeout     time.Duration
	OwnerBridge        *deployment.OwnerBridgeSettings
	LocalTLS           *deployment.LocalTLSMaterial
	admissionPolicy    *HostPolicy
	brokerUsers        map[string]string
}

// BootstrapStatus is an infrastructure observation, not the complete L04 reply.
// Work, connected hubs and application services require their separate owners.
type BootstrapStatus struct {
	Disposition string
	Profile     ProfileSummary
	Kernel      protocol.Snapshot
	Persistence deployment.Observation
}

// Session holds only the new protected processes. The bootstrap lease is
// released on readiness; each child retains its own inherited lifetime lease.
// A reused session owns no process or lease and never stops an existing runtime.
type Session struct {
	Status           BootstrapStatus
	group            *protected.Group
	lock             *BootstrapLock
	mu               sync.Mutex
	cleanupFailure   error
	cleanupState     *sessionCleanupState
	retiredGroup     *protected.Group
	startupAttemptID string
	observedAt       time.Time
	healthProof      *completedHealthProbe
}

// Only the owning bootstrap can retain a successful scoped write probe. A warm
// observer has no such proof; a stored record alone cannot create one.
type completedHealthProbe struct {
	result      deployment.ProbeResult
	scope       protocol.Scope
	endpoint    string
	completedAt time.Time
}

func bootstrapError(code string) error { return errors.New("bootstrap_" + code) }

func validateBootstrapRoles(c BootstrapConfig, p Profile) error {
	root, err := openProfileDirectory(c.ProfilePolicy)
	if err != nil {
		return bootstrapError("role_profile_invalid")
	}
	defer root.Close()
	expectedEnvCount := 4
	if c.LocalTLS != nil {
		expectedEnvCount = 5
		if c.Kernel.TLS == nil || p.ServerTrustRef == "" || p.ServerTrustDigest == "" {
			return bootstrapError("role_server_trust_invalid")
		}
		raw, err := hostPrivateRead(root, p.ServerTrustRef, p.OwnerUID, protocol.MaxPayload)
		sum := sha256.Sum256(raw)
		var record protocol.ServerTrustRecord
		if err != nil || "sha256:"+hex.EncodeToString(sum[:]) != p.ServerTrustDigest || protocol.DecodeClosedJSON(raw, &record, protocol.MaxPayload) != nil {
			return bootstrapError("role_server_trust_invalid")
		}
		trust, err := protocol.ValidateServerTrustRecord(record, c.Kernel.Scope, p.NATSEndpoint)
		if err != nil || !reflect.DeepEqual(trust.Policy(), c.Kernel.TLS.Policy()) {
			return bootstrapError("role_server_trust_invalid")
		}
	}
	seen := map[string]bool{}
	for _, option := range c.Roles {
		valid := false
		for _, role := range protocol.Roles() {
			if option.ID == role {
				valid = true
			}
		}
		if !valid || seen[option.ID] || len(option.Args) != 0 || len(option.Env) != expectedEnvCount || option.Env["AGENTMUX_NATS_URL"] != p.NATSEndpoint || option.Env["AGENTMUX_INSTANCE_ID"] != p.InstanceID || option.Env["AGENTMUX_PROFILE_ID"] != p.ProfileID {
			return bootstrapError("role_binding_invalid")
		}
		if c.LocalTLS != nil && option.Env["AGENTMUX_NATS_SERVER_TRUST_FILE"] != filepath.Join(p.ProfileDirectory, p.ServerTrustRef) {
			return bootstrapError("role_server_trust_invalid")
		}
		seen[option.ID] = true
		path := option.Env["AGENTMUX_NATS_CREDS_FILE"]
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || !canonicalProfilePath(filepath.Dir(path)) {
			return bootstrapError("role_file_invalid")
		}
		rel, err := filepath.Rel(p.ProfileDirectory, path)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return bootstrapError("role_file_invalid")
		}
		data, err := hostPrivateRead(root, filepath.ToSlash(rel), p.OwnerUID, protocol.MaxPayload)
		if err != nil {
			return bootstrapError("role_file_invalid")
		}
		var credentials protocol.Credentials
		if protocol.StrictJSON(data, &credentials) != nil || credentials.SchemaVersion != protocol.Version || credentials.Role != option.ID || credentials.Username != option.ID || credentials.Scope != c.Kernel.Scope || credentials.NATSURL != p.NATSEndpoint || !regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`).MatchString(credentials.Password) || credentials.Password != c.brokerUsers[option.ID] {
			return bootstrapError("role_credentials_invalid")
		}
	}
	return nil
}

// Close stops only this session's children. It retains the lease if reaping is
// incomplete, so another terminal cannot start a second runtime prematurely.
func (s *Session) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		return bootstrapError("owned_shutdown_incomplete")
	}
	if !s.mu.TryLock() {
		if err := lockOwnerObservation(ctx, &s.mu); err != nil {
			return bootstrapError("owned_shutdown_incomplete")
		}
	}
	defer s.mu.Unlock()
	defer s.cleanupState.notify()
	if s.group != nil {
		if err := s.group.Stop(ctx); err != nil {
			s.cleanupFailure = bootstrapError("owned_shutdown_incomplete")
			select {
			case <-s.group.Done():
			default:
				return s.cleanupFailure
			}
		}
		s.retiredGroup = s.group
		if s.group.CleanupError() != nil {
			s.cleanupFailure = bootstrapError("owned_cleanup_incomplete")
		}
		s.group = nil
	}
	if s.lock != nil {
		if err := s.lock.Close(); err != nil {
			return bootstrapError("lease_close_failed")
		}
		s.lock = nil
	}
	if s.cleanupFailure != nil {
		return s.cleanupFailure
	}
	if s.retiredGroup != nil && s.retiredGroup.CleanupError() != nil {
		return bootstrapError("owned_cleanup_incomplete")
	}
	return nil
}

// CleanupError reports observed cleanup failure even after every child exits.
func (s *Session) CleanupError() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cleanupFailure != nil {
		return s.cleanupFailure
	}
	if s.group != nil && s.group.CleanupError() != nil {
		return bootstrapError("owned_cleanup_incomplete")
	}
	if s.retiredGroup != nil && s.retiredGroup.CleanupError() != nil {
		return bootstrapError("owned_cleanup_incomplete")
	}
	return nil
}

// Bootstrap uses a bounded startup context and a separate host-owned lifetime
// context. A terminal integration must keep the owning host alive after startup;
// this function does not detach a daemon or install a terminal hook.
func Bootstrap(ctx, lifetime context.Context, c BootstrapConfig) (result *Session, failure error) {
	var attempt [16]byte
	if _, err := rand.Read(attempt[:]); err != nil {
		return nil, bootstrapError("attempt_unavailable")
	}
	return BootstrapForInvocation(ctx, lifetime, c, "attempt_"+hex.EncodeToString(attempt[:]))
}

// BootstrapForInvocation binds a real authenticated host invocation to the
// owning startup result. The identifier is correlation data, never authority;
// the caller must still supply the separately enrolled host configuration.
func BootstrapForInvocation(ctx, lifetime context.Context, c BootstrapConfig, attemptID string) (result *Session, failure error) {
	return bootstrapForOperation(ctx, lifetime, c, attemptID, nil)
}

// Only the enrolled host's retained operation can observe this private entry.
// Public bootstrap callers cannot supply a pending-state callback or flag.
func bootstrapForOperation(ctx, lifetime context.Context, c BootstrapConfig, attemptID string, operation *bootstrapOperation) (result *Session, failure error) {
	if operation != nil {
		defer func() {
			if err := operation.complete(result, failure); err != nil {
				failure = errors.Join(failure, err)
			}
		}()
	}
	if !regexp.MustCompile(`^attempt_[0-9a-f]{32}$`).MatchString(attemptID) {
		return nil, bootstrapError("invocation_invalid")
	}
	if ctx == nil || lifetime == nil || lifetime.Err() != nil || c.StartupTimeout <= 0 || c.StartupTimeout > 60*time.Second || c.Deadlines.StartTimeout <= 0 || c.Deadlines.StartTimeout > 30*time.Second || c.Deadlines.StopGrace <= 0 || c.Deadlines.StopGrace > 10*time.Second || c.Deadlines.ReapTimeout <= 0 || c.Deadlines.ReapTimeout > 10*time.Second {
		return nil, bootstrapError("context_invalid")
	}
	if c.Health.Timeout <= 0 || c.Health.Timeout > 5*time.Second || c.Kernel.Timeout <= 0 || c.Kernel.Timeout > 5*time.Second {
		return nil, bootstrapError("probe_limits_invalid")
	}
	ctx, cancel := context.WithTimeout(ctx, c.StartupTimeout)
	defer cancel()
	// This identifies the current launch or reuse invocation. It is separate
	// from the lock owner's arbitration metadata and the kernel incarnation.
	// Include profile and executable validation in the warm observation budget.
	// A blocked filesystem syscall remains an explicitly unsupported timing case.
	warm, cancelWarm := context.WithTimeout(ctx, 4*time.Second)
	defer cancelWarm()
	profile, err := LoadProfile(c.ProfilePolicy)
	if err != nil {
		return nil, err
	}
	declaration := profile.Declaration()
	selection, local := profile.LocalDocker()
	if !local {
		return nil, bootstrapError("local_profile_required")
	}
	composeHash := sha256.Sum256(c.Compose)
	if declaration.ConfigDigest != "sha256:"+hex.EncodeToString(composeHash[:]) || declaration.ReleaseFingerprint != c.ReleaseTrust.ReleaseManifestDigest || c.Kernel.Scope.InstanceID != declaration.InstanceID || c.Kernel.Scope.ProfileID != declaration.ProfileID || c.Kernel.Scope.AssemblyDigest != c.ReleaseTrust.AssemblyDigest || c.Kernel.Scope.ReleaseManifestDigest != c.ReleaseTrust.ReleaseManifestDigest || c.Kernel.Scope.ReleaseVersion != c.ReleaseTrust.ReleaseVersion || c.Health.HubID != c.Kernel.Scope.HubID || c.Health.Endpoint != declaration.NATSEndpoint || c.Kernel.Endpoint != declaration.NATSEndpoint {
		return nil, bootstrapError("enrollment_binding_mismatch")
	}
	// Loading validates the loopback endpoint. Only the enrolled port is used.
	endpoint, err := url.Parse(declaration.NATSEndpoint)
	if err != nil {
		return nil, bootstrapError("local_port_invalid")
	}
	_, portString, err := net.SplitHostPort(endpoint.Host)
	if err != nil {
		return nil, bootstrapError("local_port_invalid")
	}
	port, err := strconv.Atoi(portString)
	if err != nil || port < 1 || port > 65535 {
		return nil, bootstrapError("local_port_invalid")
	}
	driver, err := NewDocker(DockerConfig{Executable: selection.Executable, Context: selection.Context, Endpoint: selection.Endpoint, EngineID: selection.EngineID, Versions: DockerVersions{selection.ClientVersion, selection.ServerVersion, selection.ComposeVersion}, Timeout: 60 * time.Second, Backend: selection.Backend})
	if err != nil {
		return nil, err
	}
	owner := OwnershipPreflight{Project: declaration.ComposeProject, InstanceID: declaration.InstanceID, ProfileID: declaration.ProfileID, ReleaseDigest: declaration.ReleaseFingerprint, ConfigDigest: composeHash}
	if err := validateCompose(c.Compose, owner); err != nil {
		return nil, err
	}
	var document composeDocument
	if json.Unmarshal(c.Compose, &document) != nil || len(document.Services) != 1 {
		return nil, bootstrapError("broker_config_binding_invalid")
	}
	for _, service := range document.Services {
		if service.Image != c.BrokerImage || len(service.Ports) != 1 || service.Ports[0] != "127.0.0.1:"+strconv.Itoa(port)+":4222" {
			return nil, bootstrapError("broker_config_binding_invalid")
		}
		private, bindingErr := bootstrapComposeBrokerBytes(c)
		if bindingErr != nil {
			return nil, bindingErr
		}
		c.brokerUsers, err = bootstrapBrokerCredentials(private, c)
		if err != nil {
			return nil, err
		}
	}
	if err := validateBootstrapRoles(c, declaration); err != nil {
		return nil, err
	}
	// Preserve the existing pure policy/role denial checks. No subprocess,
	// lease, connection or protected preparation precedes this transport gate.
	if c.LocalTLS == nil || c.Kernel.TLS == nil || c.Health.TLS == nil || c.admissionPolicy == nil || c.Kernel.authority == nil {
		return nil, bootstrapError("local_tls_required")
	}
	prepared, err := protected.Prepare(warm, c.Assembly, c.PackageDirectory, c.ReleaseTrust, protected.Limits{})
	if err != nil {
		return nil, bootstrapError("assembly_preparation_failed")
	}
	defer prepared.Close()
	if operation != nil {
		if err := operation.enter(ctx, c, declaration, attemptID); err != nil {
			return nil, err
		}
		// Receipt I/O follows genuine admission and runs outside the operation's
		// state lock. A departing frontend does not cancel this owned startup.
		if err := operation.emitBootstrapAccepted(ctx); err != nil {
			return nil, err
		}
	}
	// This proof exists only between this invocation's complete broker inspection
	// and its next kernel observation. It is never retained by a Session.
	var operationProof *kernelObservationProof
	inspect := func(observationContext context.Context) (OwnedBroker, error) {
		operationProof = nil
		authority, proof, err := inspectLocalBrokerOperation(observationContext, c)
		if err != nil {
			return OwnedBroker{}, err
		}
		operationProof = proof
		return authority.broker, nil
	}
	observe := func(observationContext context.Context) (*Session, error) {
		proof := operationProof
		operationProof = nil
		p, err := deployment.Observe(observationContext, deployment.ObserveOptions{ProbeOptions: c.Health, ReadExistingRecord: true})
		if err != nil {
			return nil, err
		}
		kernelOptions := c.Kernel
		if deadline, ok := observationContext.Deadline(); ok {
			remaining := time.Until(deadline) - 50*time.Millisecond
			if remaining <= 0 {
				return nil, bootstrapError("observation_deadline")
			}
			if kernelOptions.Timeout > remaining {
				kernelOptions.Timeout = remaining
			}
		}
		k, err := observeKernelWithProof(observationContext, kernelOptions, proof)
		if err != nil {
			return nil, err
		}
		if k.KernelReadiness != "ready" || !p.BrokerVerified || p.PersistenceEvidence != deployment.PersistenceRecordSeen {
			return nil, bootstrapError("existing_runtime_not_ready")
		}
		return &Session{Status: BootstrapStatus{Disposition: "reused", Profile: profile.Summary(), Kernel: k, Persistence: p}, startupAttemptID: attemptID, observedAt: time.Now().UTC()}, nil
	}
	// All initial warm inspection shares one budget, reserving exec pipe cleanup.
	broker, err := inspect(warm)
	if err != nil {
		cancelWarm()
		return nil, bootstrapBoundaryFailure("initial_warm_inspection", err)
	}
	if broker.State == "running" {
		if reused, err := observe(warm); err == nil {
			cancelWarm()
			return reused, nil
		} else if err.Error() != "kernel_status_unavailable" && err.Error() != "bootstrap_existing_runtime_not_ready" {
			cancelWarm()
			return nil, err
		}
	}
	cancelWarm()
	operationProof = nil
	// A concurrent owner may still be starting the protected roles. Wait for
	// its bootstrap lease, then inspect again before any mutation. A runtime
	// that remains degraded after that wait is refused by the second observation.
	lease, err := AcquireBootstrapLock(ctx, declaration.ProfileDirectory, declaration.InstanceID, selection.EngineID)
	if err != nil {
		return nil, err
	}
	session := &Session{lock: lease, startupAttemptID: attemptID}
	session.cleanupState = newSessionCleanupState(lease.file)
	keep := false
	defer func() {
		if !keep {
			cleanup, cancel := context.WithTimeout(context.Background(), c.Deadlines.StopGrace+c.Deadlines.ReapTimeout)
			defer cancel()
			if err := session.Close(cleanup); err != nil {
				result = session
				failure = retainBootstrapCleanup(session, failure, err)
			}
		}
	}()
	owner.LockHeld = true
	broker, err = inspect(ctx)
	if err != nil {
		return nil, bootstrapBoundaryFailure("post_lease_inspection", err)
	}
	if broker.State == "running" {
		if reused, err := observe(ctx); err == nil {
			return reused, nil
		} else if err.Error() != "kernel_status_unavailable" {
			return nil, err
		}
	}
	operationProof = nil
	var roleLeases []*BootstrapLock
	defer func() {
		for _, lease := range roleLeases {
			lease.Close()
		}
	}()
	for i, role := range c.Roles {
		lease, err := AcquireBootstrapLock(ctx, declaration.ProfileDirectory, declaration.InstanceID, selection.EngineID+":runtime:"+role.ID)
		if err != nil {
			return nil, err
		}
		roleLeases = append(roleLeases, lease)
		c.Roles[i].LifetimeLease = lease.file
	}
	if broker.State != "running" {
		if err := driver.StartOwned(ctx, owner, c.Compose); err != nil {
			return nil, bootstrapBoundaryFailure("broker_start", err)
		}
		broker, err = inspect(ctx)
		if err != nil {
			return nil, err
		}
		if broker.State != "running" {
			return nil, bootstrapError("broker_not_running")
		}
	}
	// Provisioning and child startup change the observed deployment. Do not
	// carry a pre-mutation inspection into their later readiness observation.
	operationProof = nil
	probe, err := deployment.ProvisionAndProbe(ctx, c.Health)
	if err != nil {
		return nil, err
	}
	session.healthProof = &completedHealthProbe{result: probe, scope: c.Kernel.Scope, endpoint: c.Health.Endpoint, completedAt: time.Now().UTC()}
	group, err := prepared.Start(lifetime, c.Roles, c.Deadlines)
	session.group = group
	session.cleanupState.recordGroup(group)
	if group != nil {
		go func() {
			<-group.Done()
			session.mu.Lock()
			defer session.mu.Unlock()
			if group.CleanupError() != nil {
				session.cleanupFailure = bootstrapError("owned_cleanup_incomplete")
			}
			session.retiredGroup = group
			session.group = nil
			defer session.cleanupState.notify()
			if session.lock != nil {
				if session.lock.Close() == nil {
					session.lock = nil
				} else {
					session.cleanupFailure = bootstrapError("lease_close_failed")
				}
			}
		}()
	}
	if err != nil {
		return nil, bootstrapError("protected_start_failed")
	}
	for _, lease := range roleLeases {
		lease.Close()
	}
	roleLeases = nil
	for {
		broker, err = inspect(ctx)
		if err != nil {
			return nil, err
		}
		if broker.State != "running" {
			return nil, bootstrapError("broker_not_running")
		}
		ready, err := observe(ctx)
		if err == nil {
			session.mu.Lock()
			if lifetime.Err() != nil {
				session.mu.Unlock()
				return nil, bootstrapError("lifetime_cancelled")
			}
			select {
			case <-group.Done():
				session.mu.Unlock()
				return nil, bootstrapError("protected_process_exited")
			default:
			}
			session.Status = ready.Status
			session.Status.Disposition = "started"
			session.observedAt = ready.observedAt
			if session.lock == nil {
				session.mu.Unlock()
				return nil, bootstrapError("protected_process_exited")
			}
			if err := session.lock.Close(); err != nil {
				session.mu.Unlock()
				return nil, bootstrapError("lease_close_failed")
			}
			session.lock = nil
			session.mu.Unlock()
			keep = true
			return session, nil
		}
		if err.Error() != "kernel_status_unavailable" && err.Error() != "bootstrap_existing_runtime_not_ready" {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, bootstrapError("readiness_deadline")
		case <-group.Done():
			return nil, bootstrapError("protected_process_exited")
		case <-time.After(25 * time.Millisecond):
		}
	}
}
