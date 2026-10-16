//go:build linux || darwin

package launcher

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/localtls"
	"github.com/nats-io/nats.go"
)

const ownerBridgeReplyLimit = 64 * 1024

var ownerBridgeNonce = regexp.MustCompile(`^request_[0-9a-f]{32}$`)
var ownerBridgeInvocation = regexp.MustCompile(`^attempt_[0-9a-f]{32}$`)
var ownerBridgeTimestamp = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$`)

type OwnerBridgeCredentialRefs struct {
	Server string `json:"server"`
	Client string `json:"client"`
}
type OwnerBridgeEnrollment struct {
	Owner       OwnerEnrollment           `json:"owner"`
	Credentials OwnerBridgeCredentialRefs `json:"credentials"`
}

// OwnerBridgeCredential is enrolled in a private contained file. Neither the
// request body nor a caller-selected subject can choose its principal.
type OwnerBridgeCredential struct {
	SchemaVersion string          `json:"schemaVersion"`
	Role          string          `json:"role"`
	Scope         protocol.Scope  `json:"scope"`
	Owner         OwnerEnrollment `json:"owner"`
	Password      string          `json:"password"`
}

func (OwnerBridgeCredential) String() string   { return "[private owner bridge credential]" }
func (OwnerBridgeCredential) GoString() string { return "[private owner bridge credential]" }

type ownerBridgeRequest struct {
	SchemaVersion string         `json:"schemaVersion"`
	Kind          string         `json:"kind"`
	Operation     string         `json:"operation"`
	RequestID     string         `json:"requestId"`
	InvocationID  string         `json:"invocationId"`
	Scope         protocol.Scope `json:"scope"`
	SentAt        string         `json:"sentAt"`
}
type ownerBridgeReply struct {
	SchemaVersion string                   `json:"schemaVersion"`
	Kind          string                   `json:"kind"`
	RequestID     string                   `json:"requestId"`
	InvocationID  string                   `json:"invocationId"`
	Scope         protocol.Scope           `json:"scope"`
	SentAt        string                   `json:"sentAt"`
	Observation   StartupStatusObservation `json:"observation"`
}
type OwnerBridgeClient struct {
	config     BootstrapConfig
	enrollment OwnerBridgeEnrollment
	credential OwnerBridgeCredential
	subjects   deployment.OwnerBridgeSubjectSet
}
type OwnerBridgeServer struct {
	config     BootstrapConfig
	enrollment OwnerBridgeEnrollment
	owner      *OwnerStatus
	credential OwnerBridgeCredential
	subjects   deployment.OwnerBridgeSubjectSet
	receipt    *ownerBridgeReceiptState
	history    *ownerBridgeHistoryState
}

func (*OwnerBridgeClient) String() string   { return "[private owner bridge client]" }
func (*OwnerBridgeClient) GoString() string { return "[private owner bridge client]" }
func (*OwnerBridgeServer) String() string   { return "[private owner bridge server]" }
func (*OwnerBridgeServer) GoString() string { return "[private owner bridge server]" }

var errOwnerBridgeAuthority = errors.New("owner_bridge_authority_rejected")

func bridgeError(code string) error {
	if code == "authority_rejected" {
		return errOwnerBridgeAuthority
	}
	return errors.New("owner_bridge_" + code)
}
func IsOwnerBridgeAuthorityError(err error) bool { return errors.Is(err, errOwnerBridgeAuthority) }
func bridgeTime(t time.Time) string {
	return t.UTC().Truncate(time.Microsecond).Format("2006-01-02T15:04:05.999999Z")
}
func bridgeFresh(s string, now time.Time) bool {
	t, e := time.Parse("2006-01-02T15:04:05.999999Z", s)
	return e == nil && ownerBridgeTimestamp.MatchString(s) && !t.After(now) && now.Sub(t) <= 5*time.Second
}

func loadBridgeCredential(c BootstrapConfig, e OwnerBridgeEnrollment, role string) (OwnerBridgeCredential, deployment.OwnerBridgeSubjectSet, error) {
	empty := OwnerBridgeCredential{}
	subjects, err := deployment.OwnerBridgeSubjects(c.Kernel.Scope)
	if err != nil || c.OwnerBridge == nil || c.OwnerBridge.Scope != c.Kernel.Scope || e.Owner.InstanceID != c.Kernel.Scope.InstanceID || e.Owner.ProfileID != c.Kernel.Scope.ProfileID || e.Owner.Identity.OwnerHubID != c.Kernel.Scope.HubID || e.Owner.ReleaseFingerprint != c.ProfilePolicy.InstalledReleaseFingerprint || e.Owner.ReleaseFingerprint != c.Kernel.Scope.ReleaseManifestDigest {
		return empty, subjects, bridgeError("enrollment_invalid")
	}
	profile, err := LoadProfile(c.ProfilePolicy)
	if err != nil {
		return empty, subjects, bridgeError("enrollment_invalid")
	}
	p := profile.Declaration()
	if p.Docker == nil || p.Mode != "local" || p.ConfigDigest != "sha256:"+hexDigest(c.Compose) || p.NATSEndpoint != c.Kernel.Endpoint || p.NATSEndpoint != c.Health.Endpoint {
		return empty, subjects, bridgeError("enrollment_invalid")
	}
	if _, err = LoadOwnerStatus(OwnerPolicy{Profile: c.ProfilePolicy, Enrollment: e.Owner, KernelScope: c.Kernel.Scope, ServerName: c.Health.ServerName, Domain: c.Health.Domain, PublicEndpoint: c.Kernel.Endpoint, PublicContextName: p.Docker.Context}); err != nil {
		return empty, subjects, bridgeError("enrollment_invalid")
	}
	name, password := e.Credentials.Client, c.OwnerBridge.ClientPassword
	if role == deployment.OwnerBridgeServerUser {
		name, password = e.Credentials.Server, c.OwnerBridge.ServerPassword
	}
	if name == "" || !filepath.IsLocal(name) || filepath.Clean(name) != name || name == "." || e.Credentials.Server == e.Credentials.Client || !kernelStatusPassword.MatchString(password) {
		return empty, subjects, bridgeError("credential_invalid")
	}
	root, err := openProfileDirectory(c.ProfilePolicy)
	if err != nil {
		return empty, subjects, bridgeError("credential_invalid")
	}
	defer root.Close()
	raw, err := hostPrivateRead(root, name, c.ProfilePolicy.OwnerUID, protocol.MaxPayload)
	if err != nil {
		return empty, subjects, bridgeError("credential_invalid")
	}
	var credential OwnerBridgeCredential
	if _, err = releaseFields(raw, "schemaVersion", "role", "scope", "owner", "password"); err != nil || protocol.StrictJSON(raw, &credential) != nil || credential.SchemaVersion != protocol.Version || credential.Role != role || credential.Scope != c.Kernel.Scope || !reflect.DeepEqual(credential.Owner, e.Owner) || credential.Password != password {
		return empty, subjects, bridgeError("credential_invalid")
	}
	// Check the actual selected factory, not merely the passwords in policy.
	var doc composeDocument
	count := 1
	if c.LocalTLS != nil {
		count = 3
	}
	if json.Unmarshal(c.Compose, &doc) != nil || len(doc.Configs) != count || len(doc.Services) != 1 {
		return empty, subjects, bridgeError("factory_invalid")
	}
	for _, service := range doc.Services {
		if len(service.Configs) != count {
			return empty, subjects, bridgeError("factory_invalid")
		}
		var content string
		found := 0
		for _, ref := range service.Configs {
			if ref.Target == deployment.PrivateConfigTarget {
				content = doc.Configs[ref.Source].Content
				found++
			}
		}
		if found != 1 {
			return empty, subjects, bridgeError("factory_invalid")
		}
		raw := []byte(strings.ReplaceAll(content, "$$", "$"))
		if sha256.Sum256(raw) != c.BrokerConfigDigest {
			return empty, subjects, bridgeError("factory_invalid")
		}
		if _, err := bootstrapBrokerCredentials(raw, c); err != nil {
			return empty, subjects, bridgeError("factory_invalid")
		}
	}
	return credential, subjects, nil
}

func LoadOwnerBridgeClient(c BootstrapConfig, e OwnerBridgeEnrollment) (*OwnerBridgeClient, error) {
	credential, subjects, err := loadBridgeCredential(c, e, deployment.OwnerBridgeClientUser)
	if err != nil {
		return nil, err
	}
	return &OwnerBridgeClient{c, e, credential, subjects}, nil
}
func LoadOwnerBridgeServer(c BootstrapConfig, owner *OwnerStatus, e OwnerBridgeEnrollment) (*OwnerBridgeServer, error) {
	if owner == nil || !reflect.DeepEqual(owner.policy.Enrollment, e.Owner) || owner.policy.KernelScope != c.Kernel.Scope || owner.policy.PublicEndpoint != c.Kernel.Endpoint || owner.policy.ServerName != c.Health.ServerName || owner.policy.Domain != c.Health.Domain {
		return nil, bridgeError("owner_invalid")
	}
	credential, subjects, err := loadBridgeCredential(c, e, deployment.OwnerBridgeServerUser)
	if err != nil {
		return nil, err
	}
	return &OwnerBridgeServer{config: c, enrollment: e, owner: owner, credential: credential, subjects: subjects}, nil
}

func bridgeConnect(parent context.Context, c BootstrapConfig, credential OwnerBridgeCredential) (*nats.Conn, *localtls.Dialer, error) {
	return bridgeConnectWithin(parent, parent, c, credential)
}

// A live socket follows its owned lifetime; connection work is also bounded
// by the startup or terminal-failure budget supplied by the same Run.
func bridgeConnectWithin(parent, budget context.Context, c BootstrapConfig, credential OwnerBridgeCredential) (*nats.Conn, *localtls.Dialer, error) {
	if parent == nil || budget == nil || parent.Err() != nil || budget.Err() != nil {
		return nil, nil, bridgeError("deadline")
	}
	if c.Kernel.authority == nil || c.Kernel.TLS == nil {
		return nil, nil, bridgeError("authority_rejected")
	}
	bound := c.Kernel.authority.config
	if c.Kernel.Endpoint != bound.Kernel.Endpoint || c.Kernel.Scope != bound.Kernel.Scope || c.Kernel.Password != bound.Kernel.Password || bound.Kernel.TLS == nil || !reflect.DeepEqual(c.Kernel.TLS.Policy(), bound.Kernel.TLS.Policy()) {
		return nil, nil, bridgeError("authority_rejected")
	}
	ctx, cancel := context.WithTimeout(budget, 5*time.Second)
	defer cancel()
	authority, err := inspectLocalBrokerAuthority(ctx, c)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, bridgeError("deadline")
		}
		return nil, nil, bridgeAuthorityFailure(err)
	}
	if authority.state == "absent" || authority.state == "stopped" {
		return nil, nil, bridgeError("connection_unavailable")
	}
	if authority.state != "running" || authority.trust == nil || !reflect.DeepEqual(authority.trust.Policy(), c.Kernel.TLS.Policy()) || authority.trust.Policy().Endpoint != c.Kernel.Endpoint {
		return nil, nil, bridgeError("authority_rejected")
	}
	deadline, _ := ctx.Deadline()
	remaining := time.Until(deadline)
	if ctx.Err() != nil || remaining <= 0 {
		return nil, nil, bridgeError("deadline")
	}
	dialer, err := authority.trust.NewDialer(parent, remaining)
	if err != nil {
		return nil, nil, bridgeError("authority_rejected")
	}
	// This temporary budget covers inspection, TLS and INFO/CONNECT together.
	// Stop or join its callback before returning a live parent-owned connection.
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { dialer.Close(); close(stopped) })
	nc, err := nats.Connect(c.Kernel.Endpoint, nats.UserInfo(credential.Role, credential.Password), nats.TLSHandshakeFirst(), nats.NoReconnect(), nats.IgnoreDiscoveredServers(), nats.NoEcho(), nats.Timeout(remaining), nats.SetCustomDialer(dialer), nats.ErrorHandler(ownerBridgeAsyncErrorHandler))
	if !stop() {
		<-stopped
	}
	if ctx.Err() != nil {
		return nil, nil, closeBridgeConnection(nc, dialer, bridgeError("deadline"))
	}
	if err != nil {
		code := "connection_unavailable"
		if localtls.IsAuthorityError(err) || errors.Is(err, nats.ErrAuthorization) || errors.Is(err, nats.ErrPermissionViolation) || errors.Is(err, nats.ErrAuthExpired) || errors.Is(err, nats.ErrAuthRevoked) || errors.Is(err, nats.ErrAccountAuthExpired) {
			code = "authority_rejected"
		} else if errors.Is(err, localtls.ErrDeadline) {
			code = "deadline"
		}
		return nil, nil, closeBridgeConnection(nc, dialer, bridgeError(code))
	}
	if nc.ConnectedServerName() != c.Health.ServerName || nc.ConnectedServerVersion() != c.Health.ServerVersion {
		return nil, nil, closeBridgeConnection(nc, dialer, bridgeError("authority_rejected"))
	}
	return nc, dialer, nil
}

// Install fixed handling before NATS starts callbacks. The library still
// records protocol errors in LastError; request boundaries inspect those
// sentinels instead of publishing arbitrary error text to the terminal.
func ownerBridgeAsyncErrorHandler(*nats.Conn, *nats.Subscription, error) {}

func ownerBridgeAuthorityLastError(nc *nats.Conn) error {
	err := nc.LastError()
	if errors.Is(err, nats.ErrPermissionViolation) || errors.Is(err, nats.ErrAuthorization) || errors.Is(err, nats.ErrAuthExpired) || errors.Is(err, nats.ErrAuthRevoked) || errors.Is(err, nats.ErrAccountAuthExpired) {
		return bridgeError("authority_rejected")
	}
	return nil
}

func closeBridgeConnection(nc *nats.Conn, dialer *localtls.Dialer, failure error) error {
	failure, _ = closeOwnedTransport(dialer, failure, "owner_bridge_owned_connection_cleanup_failed")
	if nc != nil {
		nc.Close()
	}
	return failure
}

// Request is one bounded request. It uses no generic publish API, automatic
// inbox, caller-selected reply subject or caller-supplied observation.
func (c *OwnerBridgeClient) Request(parent context.Context, operation, invocationID string) (result StartupStatusObservation, failure error) {
	empty := StartupStatusObservation{}
	if c == nil || parent == nil || (operation != "ensure" && operation != "status") || !ownerBridgeInvocation.MatchString(invocationID) {
		return empty, bridgeError("request_invalid")
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		return empty, bridgeError("deadline")
	}
	// Reopen the enrollment on every request so revoked or changed credentials
	// do not survive in a cached client handle.
	credential, _, err := loadBridgeCredential(c.config, c.enrollment, deployment.OwnerBridgeClientUser)
	if err != nil {
		return empty, err
	}
	id, err := hostInvocationID("request_")
	if err != nil {
		return empty, bridgeError("nonce_failed")
	}
	nc, dialer, err := bridgeConnect(ctx, c.config, credential)
	if err != nil {
		return empty, err
	}
	defer nc.Close()
	defer func() {
		if cleanup, failed := closeOwnedTransport(dialer, failure, "owner_bridge_owned_connection_cleanup_failed"); failed {
			result = empty
			failure = cleanup
		}
	}()
	sub, err := nc.SubscribeSync(c.subjects.ReplyPrefix + id[len("request_"):])
	if err != nil {
		return empty, bridgeError("subscribe_failed")
	}
	defer sub.Unsubscribe()
	sub.SetPendingLimits(4, 4*ownerBridgeReplyLimit)
	flushErr := nc.FlushWithContext(ctx)
	if authority := ownerBridgeAuthorityLastError(nc); authority != nil {
		return empty, authority
	}
	if flushErr != nil {
		return empty, bridgeError("connection_unavailable")
	}
	request := ownerBridgeRequest{protocol.Version, "host-owner-status-request", operation, id, invocationID, c.config.Kernel.Scope, bridgeTime(time.Now())}
	raw, _ := json.Marshal(request)
	var msg *nats.Msg
	for sent := 0; sent < 10; sent++ {
		if authority := ownerBridgeAuthorityLastError(nc); authority != nil {
			return empty, authority
		}
		if ctx.Err() != nil {
			return empty, bridgeError("deadline")
		}
		// Core NATS may have no service subscriber during host startup. Repeat
		// only the identical read-only request; the owner's nonce guard accepts
		// it at most once. Every wait stays within the original total deadline.
		publishErr := nc.Publish(c.subjects.Request, raw)
		if publishErr == nil {
			publishErr = nc.FlushWithContext(ctx)
		}
		if authority := ownerBridgeAuthorityLastError(nc); authority != nil {
			return empty, authority
		}
		if publishErr != nil {
			return empty, bridgeError("connection_unavailable")
		}
		wait, stopWait := context.WithTimeout(ctx, 500*time.Millisecond)
		msg, err = sub.NextMsgWithContext(wait)
		stopWait()
		if authority := ownerBridgeAuthorityLastError(nc); authority != nil {
			return empty, authority
		}
		if err == nil {
			break
		}
		if ctx.Err() != nil || !errors.Is(err, context.DeadlineExceeded) {
			return empty, bridgeError("reply_unavailable")
		}
	}
	if authority := ownerBridgeAuthorityLastError(nc); authority != nil {
		return empty, authority
	}
	if msg == nil || err != nil {
		return empty, bridgeError("reply_unavailable")
	}
	var reply ownerBridgeReply
	if len(msg.Header) != 0 || msg.Reply != "" || msg.Subject != sub.Subject || decodeBridgeReply(msg.Data, &reply) != nil || reply.RequestID != id || reply.InvocationID != invocationID || reply.Scope != c.config.Kernel.Scope || !bridgeFresh(reply.SentAt, time.Now()) || !bridgeObservationBound(reply.Observation, c.enrollment, invocationID, time.Now()) {
		return empty, bridgeError("reply_invalid")
	}
	if authority := ownerBridgeAuthorityLastError(nc); authority != nil {
		return empty, authority
	}
	if ctx.Err() != nil {
		return empty, bridgeError("deadline")
	}
	return reply.Observation, nil
}

func decodeBridgeReply(raw []byte, out *ownerBridgeReply) error {
	if validateOwnerBridgeJSON(raw, "host-owner-status-reply", ownerBridgeReplyLimit) != nil {
		return bridgeError("reply_invalid")
	}
	if len(raw) > ownerBridgeReplyLimit {
		return bridgeError("reply_invalid")
	}
	if _, err := releaseFields(raw, "schemaVersion", "kind", "requestId", "invocationId", "scope", "sentAt", "observation"); err != nil {
		return bridgeError("reply_invalid")
	}
	if protocol.DecodeClosedJSON(raw, out, ownerBridgeReplyLimit) != nil || out.SchemaVersion != protocol.Version || out.Kind != "host-owner-status-reply" {
		return bridgeError("reply_invalid")
	}
	return nil
}
func bridgeObservationBound(out StartupStatusObservation, e OwnerBridgeEnrollment, id string, now time.Time) bool {
	if out.SchemaVersion != protocol.Version || out.StartupAttemptID == nil || out.Caller.PrincipalID != e.Owner.PrincipalID || out.Caller.Identity != e.Owner.Identity || !reflect.DeepEqual(out.Caller.Scope, e.Owner.Scope) || out.Instance.InstanceID == nil || *out.Instance.InstanceID != e.Owner.InstanceID || out.Instance.ProfileID == nil || *out.Instance.ProfileID != e.Owner.ProfileID || !bridgeFresh(out.ObservedAt, now) || out.SourceRevision == 0 || !kernelStatusID.MatchString(out.ObservationID) {
		return false
	}
	if out.Disposition == "starting" {
		// The authenticated owning operation supplies its actual cold attempt.
		// The outer reply still correlates the current request's invocation/nonce.
		return ownerBridgeInvocation.MatchString(*out.StartupAttemptID) && bridgeStartingUnknown(out)
	}
	return *out.StartupAttemptID == id && (out.Disposition == "started" || out.Disposition == "reused" || out.Disposition == "failed")
}

func bridgeStartingUnknown(out StartupStatusObservation) bool {
	if out.Instance.Mode != "local" || out.Instance.RunningVersion != nil || out.Instance.Dashboard != nil || (out.Instance.Readiness != "not_ready" && out.Instance.Readiness != "unknown") {
		return false
	}
	services := map[string]bool{"boot": false, "kernel-lifecycle": false, "internal-communication": false, "exported-status": false, "work": false, "hub_federation": false}
	if len(out.Instance.Services) != len(services) {
		return false
	}
	for _, service := range out.Instance.Services {
		seen, known := services[service.ServiceID]
		if !known || seen || service.Availability != "unavailable" || service.Readiness != "unknown" || service.ObservedAt != nil || service.SourceRevision != nil || service.UnavailableReason == nil {
			return false
		}
		services[service.ServiceID] = true
	}
	p := out.Persistence
	return p.Availability == "unavailable" && p.Readiness == "unknown" && p.Backend == nil && p.Profile == nil && p.ServerID == nil && p.DomainID == nil && p.ObservedAt == nil && p.StoragePressure.State == "unknown" && p.StoragePressure.PercentUsed == nil && p.ReplicationHealth.State == "unknown" && p.ReplicationHealth.Replicas == nil && out.Work.State == "unavailable" && out.Work.Active == nil && out.Work.Projects == nil && out.Work.Reserved == nil && out.Work.SourceCursor == nil && out.Work.ObservedAt == nil && out.Hubs.InventoryState == "unavailable" && len(out.Hubs.Entries) == 0
}

type bridgeReplay struct {
	mu  sync.Mutex
	ids map[string]time.Time
}

func (r *bridgeReplay) accept(id string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, t := range r.ids {
		if now.Sub(t) > 10*time.Second {
			delete(r.ids, key)
		}
	}
	if _, ok := r.ids[id]; ok || len(r.ids) >= 128 {
		return false
	}
	r.ids[id] = now
	return true
}
func validateBridgeRequest(msg *nats.Msg, scope protocol.Scope, subjects deployment.OwnerBridgeSubjectSet, now time.Time) (ownerBridgeRequest, error) {
	var request ownerBridgeRequest
	if msg == nil || len(msg.Data) > protocol.MaxPayload || msg.Subject != subjects.Request || len(msg.Header) != 0 {
		return request, bridgeError("request_invalid")
	}
	if validateOwnerBridgeJSON(msg.Data, "host-owner-status-request", protocol.MaxPayload) != nil {
		return request, bridgeError("request_invalid")
	}
	if _, err := releaseFields(msg.Data, "schemaVersion", "kind", "operation", "requestId", "invocationId", "scope", "sentAt"); err != nil || protocol.StrictJSON(msg.Data, &request) != nil || request.SchemaVersion != protocol.Version || request.Kind != "host-owner-status-request" || (request.Operation != "ensure" && request.Operation != "status") || !ownerBridgeNonce.MatchString(request.RequestID) || !ownerBridgeInvocation.MatchString(request.InvocationID) || request.Scope != scope || !bridgeFresh(request.SentAt, now) {
		return request, bridgeError("request_invalid")
	}
	if msg.Reply != "" && msg.Reply != subjects.ReplyPrefix+request.RequestID[len("request_"):] {
		return request, bridgeError("request_invalid")
	}
	return request, nil
}

// Run owns one host-service lease and only the Session returned by its own
// bootstrap. A reused Session never adopts or stops another owner's children.
// Ordinary status traffic stays on the isolated HOST account.
func (s *OwnerBridgeServer) Run(startup, lifetime context.Context, coldInvocationID string) (failure error) {
	defer func() {
		if s != nil {
			failure = s.finishBootstrapReceipt(startup, failure)
		}
	}()
	if s != nil && s.receipt != nil && !s.receipt.matches(s, coldInvocationID) {
		return bridgeError("receipt_binding_invalid")
	}
	if s == nil || startup == nil || lifetime == nil || startup.Err() != nil || lifetime.Err() != nil || !ownerBridgeInvocation.MatchString(coldInvocationID) {
		return bridgeError("context_invalid")
	}
	if _, _, err := loadBridgeCredential(s.config, s.enrollment, deployment.OwnerBridgeServerUser); err != nil {
		return err
	}
	leaseCtx, cancel := context.WithTimeout(startup, 5*time.Second)
	lease, err := AcquireBootstrapLock(leaseCtx, s.config.ProfilePolicy.Directory, s.config.Kernel.Scope.InstanceID, "owner-status-service")
	cancel()
	if err != nil {
		return bridgeError("service_owned_elsewhere")
	}
	leaseTransferred := false
	defer func() {
		if !leaseTransferred && lease.Close() != nil {
			failure = errors.Join(failure, bridgeError("lease_cleanup_failed"))
		}
	}()
	// The operation owns exactly one Bootstrap call. Its cancellation is joined
	// before any lease release or Session cleanup. Synchronous private filesystem
	// calls must finish on the supported local filesystem; they are not preemptible.
	bootstrapCtx, cancelBootstrap := context.WithTimeout(startup, 60*time.Second)
	runtimeLifetime, cancelRuntime := context.WithCancel(lifetime)
	operation, err := newBootstrapOperation(bootstrapCtx, runtimeLifetime, s, lease, coldInvocationID)
	if err != nil {
		cancelBootstrap()
		cancelRuntime()
		return err
	}
	cleanupEnvelope := newOwnerBridgeCleanupEnvelope(s.config.Deadlines.StopGrace + s.config.Deadlines.ReapTimeout)
	defer cleanupEnvelope.close()
	returned := make(chan struct{})
	if s.history != nil {
		s.history.returned = returned
	}
	go func() {
		defer close(returned)
		actualSession, actualFailure := bootstrapForOperation(bootstrapCtx, runtimeLifetime, s.config, coldInvocationID, operation)
		s.recordBootstrapHistoryTerminal(bootstrapCtx, operation, actualSession, actualFailure)
	}()
	defer func() {
		cancelBootstrap()
		cancelRuntime()
		<-operation.done
		<-returned
		session, completedFailure := joinedBridgeBootstrapResult(operation, failure)
		failure = completedFailure
		// Optional history cleanup shares actual teardown, not healthy runtime life.
		s.finalizeBootstrapHistory(cleanupEnvelope.context(), operation)
		if session != nil {
			failure, leaseTransferred = closeOwnedSessionContext(cleanupEnvelope.context(), session, lease, failure, s.config.Deadlines.StopGrace+s.config.Deadlines.ReapTimeout)
		}
	}()
	return s.serveOperation(bootstrapCtx, runtimeLifetime, operation)
}

// Legacy completed-session fixture entry; production uses the actual operation.
func (s *OwnerBridgeServer) serve(lifetime context.Context, coldInvocationID string, session *Session, bootErr error, ready chan<- struct{}) error {
	return s.serveLoop(lifetime, nil, coldInvocationID, session, bootErr, ready, nil)
}
func (s *OwnerBridgeServer) serveOperation(startup, lifetime context.Context, operation *bootstrapOperation) error {
	return s.serveLoop(lifetime, startup, operation.attemptID, nil, nil, nil, operation)
}

func (s *OwnerBridgeServer) serveLoop(lifetime, startup context.Context, coldInvocationID string, session *Session, bootErr error, ready chan<- struct{}, operation *bootstrapOperation) (failure error) {
	var operationDone, startupDone <-chan struct{}
	var failureDeadline time.Time
	if operation != nil {
		operationDone, startupDone = operation.done, startup.Done()
	}
	if bootErr != nil {
		failureDeadline = time.Now().Add(5 * time.Second)
	}
	complete := func() {
		session, bootErr = operation.resultContext(context.Background())
		operationDone, startupDone = nil, nil
		if bootErr != nil {
			failureDeadline = operation.completedTime().Add(5 * time.Second)
		}
	}
	var nc *nats.Conn
	var dialer *localtls.Dialer
	for {
		if operationDone != nil {
			select {
			case <-operationDone:
				complete()
			default:
			}
		}
		budget := lifetime
		cancelBudget := func() {}
		if operationDone != nil {
			budget = startup
		}
		if !failureDeadline.IsZero() {
			budget, cancelBudget = context.WithDeadline(lifetime, failureDeadline)
		}
		var err error
		nc, dialer, err = bridgeConnectWithin(lifetime, budget, s.config, s.credential)
		cancelBudget()
		if err == nil {
			break
		}
		if errors.Is(err, ErrTransportCleanup) || IsOwnerBridgeAuthorityError(err) {
			return err
		}
		if operationDone == nil {
			return err
		}
		if err.Error() != "owner_bridge_connection_unavailable" && !(err.Error() == "owner_bridge_deadline" && startup.Err() != nil) {
			return err
		}
		if startup.Err() != nil {
			<-operationDone
			complete()
			continue
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-lifetime.Done():
			timer.Stop()
			return err
		case <-operationDone:
			timer.Stop()
			complete()
		case <-startupDone:
			timer.Stop()
			<-operationDone
			complete()
		case <-timer.C:
		}
	}
	connectionLost := make(chan struct{}, 1)
	nc.SetClosedHandler(func(*nats.Conn) {
		select {
		case connectionLost <- struct{}{}:
		default:
		}
	})
	defer nc.Close()
	defer nc.SetClosedHandler(nil)
	defer func() {
		failure, _ = closeOwnedTransport(dialer, failure, "owner_bridge_owned_connection_cleanup_failed")
	}()
	messages := make(chan *nats.Msg, 128)
	sub, err := nc.ChanSubscribe(s.subjects.Request, messages)
	if err != nil {
		return bridgeError("subscribe_failed")
	}
	defer sub.Unsubscribe()
	sub.SetPendingLimits(128, 128*protocol.MaxPayload)
	flush, cancelFlush := context.WithTimeout(lifetime, 5*time.Second)
	err = nc.FlushWithContext(flush)
	cancelFlush()
	if err != nil {
		return bridgeError("connection_unavailable")
	}
	if ready != nil {
		close(ready)
	}
	replay := bridgeReplay{ids: map[string]time.Time{}}
	for {
		if operationDone != nil {
			select {
			case <-operationDone:
				complete()
			default:
			}
		}
		var timeout <-chan time.Time
		var timer *time.Timer
		if !failureDeadline.IsZero() {
			if !time.Now().Before(failureDeadline) {
				return bridgeError("startup_failed")
			}
			timer = time.NewTimer(time.Until(failureDeadline))
			timeout = timer.C
		}
		var msg *nats.Msg
		select {
		case <-connectionLost:
			if timer != nil {
				timer.Stop()
			}
			return bridgeError("connection_lost")
		case <-lifetime.Done():
			if timer != nil {
				timer.Stop()
			}
			return nil
		case <-operationDone:
			if timer != nil {
				timer.Stop()
			}
			complete()
			continue
		case <-startupDone:
			if timer != nil {
				timer.Stop()
			}
			<-operationDone
			complete()
			continue
		case <-timeout:
			return bridgeError("startup_failed")
		case msg = <-messages:
			if timer != nil {
				timer.Stop()
			}
		}
		if nc.IsClosed() {
			return bridgeError("connection_lost")
		}
		request, err := validateBridgeRequest(msg, s.config.Kernel.Scope, s.subjects, time.Now())
		if err != nil || !replay.accept(request.RequestID, time.Now()) {
			continue
		}
		if _, _, err := loadBridgeCredential(s.config, s.enrollment, deployment.OwnerBridgeServerUser); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(lifetime, 5*time.Second)
		if !failureDeadline.IsZero() {
			cancel()
			ctx, cancel = context.WithDeadline(lifetime, failureDeadline)
		}
		if operationDone != nil {
			select {
			case <-operation.enteredDone:
			case <-operationDone:
				complete()
			case <-ctx.Done():
				cancel()
				continue
			}
			// Completion can race entry; the actual result, never a cached flag, wins.
			select {
			case <-operation.done:
				if operationDone != nil {
					complete()
				}
			default:
			}
		}
		var observation StartupStatusObservation
		if operationDone != nil {
			observation, err = s.owner.mapStartingContext(ctx, operation)
			if err != nil {
				select {
				case <-operation.done:
					complete()
					observation, err = s.observeBridgeRequest(ctx, request, coldInvocationID, session, bootErr)
				default:
					completed, completionErr := operation.awaitCanceledCoreCompletion(ctx, err)
					if completionErr != nil {
						err = completionErr
					}
					if completed {
						complete()
						observation, err = s.observeBridgeRequest(ctx, request, coldInvocationID, session, bootErr)
					}
				}
			}
		} else {
			observation, err = s.observeBridgeRequest(ctx, request, coldInvocationID, session, bootErr)
		}
		if cleanup := bridgeObservationCleanupFailure(err); cleanup != nil {
			cancel()
			return cleanup
		}
		if err == nil && bridgeObservationBound(observation, s.enrollment, request.InvocationID, time.Now()) {
			reply := ownerBridgeReply{protocol.Version, "host-owner-status-reply", request.RequestID, request.InvocationID, s.config.Kernel.Scope, bridgeTime(time.Now()), observation}
			raw, e := json.Marshal(reply)
			if e == nil && len(raw) <= ownerBridgeReplyLimit && ctx.Err() == nil && (failureDeadline.IsZero() || time.Now().Before(failureDeadline)) && validateOwnerBridgeJSON(raw, "host-owner-status-reply", ownerBridgeReplyLimit) == nil {
				if nc.Publish(s.subjects.ReplyPrefix+request.RequestID[len("request_"):], raw) != nil {
					cancel()
					return bridgeError("reply_failed")
				}
				flushErr := nc.FlushWithContext(ctx)
				replyErr := ownerBridgeReplyFlushResult(lifetime, ctx, flushErr, ownerBridgeAuthorityLastError(nc), bootErr)
				if replyErr != nil {
					cancel()
					return replyErr
				}
				if flushErr != nil {
					cancel()
					return nil
				}
				if bootErr != nil {
					cancel()
					return bridgeError("startup_failed")
				}
			}
		}
		cancel()
	}
}

// Only direct context cancellation identifies an interrupted flush wait. A
// closed connection has no causal marker and remains a transport failure even
// when lifetime cancellation happens concurrently.
func ownerBridgeReplyFlushResult(lifetime, request context.Context, flushErr, authorityErr, bootErr error) error {
	if cleanup := bridgeObservationCleanupFailure(errors.Join(flushErr, authorityErr, bootErr)); cleanup != nil {
		return cleanup
	}
	if authorityErr != nil {
		return errors.Join(authorityErr, bootErr)
	}
	if flushErr == nil {
		return nil
	}
	if flushErr == context.Canceled && request.Err() == context.Canceled && lifetime.Err() == context.Canceled {
		return bootErr
	}
	return errors.Join(bridgeError("reply_failed"), bootErr)
}

func (s *OwnerBridgeServer) observeBridgeRequest(ctx context.Context, request ownerBridgeRequest, coldInvocationID string, session *Session, bootErr error) (StartupStatusObservation, error) {
	retained := false
	var receipt time.Time
	var kernel protocol.Snapshot
	if request.InvocationID == coldInvocationID && session != nil && bootErr == nil {
		if err := lockOwnerObservation(ctx, &session.mu); err != nil {
			return StartupStatusObservation{}, err
		}
		retained = !session.observedAt.IsZero() && time.Since(session.observedAt) <= 3*time.Second
		receipt = session.observedAt
		kernel = session.Status.Kernel
		kernel.Members = append([]protocol.Member(nil), kernel.Members...)
		session.mu.Unlock()
	}
	if !retained {
		return s.refresh(ctx, request.InvocationID, session, bootErr)
	}
	observation, err := session.OwnerObservationContext(ctx, s.owner)
	if err == nil && bridgeRetainedExpired(observation, receipt, kernel, s.config.Kernel.Scope, time.Now()) {
		return s.refresh(ctx, request.InvocationID, session, bootErr)
	}
	return observation, err
}

func bridgeRetainedExpired(out StartupStatusObservation, receipt time.Time, snapshot protocol.Snapshot, scope protocol.Scope, now time.Time) bool {
	if receipt.IsZero() || receipt.After(now) {
		return false
	}
	raw := mustStatusJSON(snapshot)
	if _, err := protocol.DecodeSnapshot(raw, scope, receipt, 3*time.Second); err != nil {
		return false
	}
	for _, issue := range out.Errors {
		if issue.Code == "observation_unavailable" && now.Sub(receipt) > 3*time.Second {
			return true
		}
		if issue.Code == "kernel_observation_invalid" {
			// The identical scoped frame must have been valid at the retained
			// receipt. Changing only time must now invalidate it; malformed or
			// wrong-scope producer data never authorizes a refresh.
			_, after := protocol.DecodeSnapshot(raw, scope, now, 3*time.Second)
			return after != nil
		}
	}
	return false
}

func (s *OwnerBridgeServer) refresh(ctx context.Context, id string, session *Session, bootErr error) (StartupStatusObservation, error) {
	p, err := LoadProfile(s.config.ProfilePolicy)
	if err != nil {
		return StartupStatusObservation{}, bridgeError("profile_invalid")
	}
	declaration := p.Declaration()
	if declaration.ConfigDigest != "sha256:"+hexDigest(s.config.Compose) || declaration.ReleaseFingerprint != s.config.Kernel.Scope.ReleaseManifestDigest || declaration.NATSEndpoint != s.config.Kernel.Endpoint || declaration.InstanceID != s.config.Kernel.Scope.InstanceID || declaration.ProfileID != s.config.Kernel.Scope.ProfileID {
		return StartupStatusObservation{}, bridgeError("profile_binding_invalid")
	}
	if bootErr != nil {
		out, err := s.owner.mapObservationContext(ctx, ownerStatusObservation{status: BootstrapStatus{Disposition: "failed", Profile: p.Summary()}, attemptID: id, receivedAt: time.Now().UTC()})
		if err == nil {
			out.Errors = append(out.Errors, StartupStatusError{Component: "instance", Code: "host_startup_failed", Message: "The owning host could not complete startup.", Retryable: true})
		}
		return out, err
	}
	facts, operationProof, inspectErr := inspectLocalBrokerOperation(ctx, s.config)
	if ctx.Err() != nil {
		return StartupStatusObservation{}, bridgeError("deadline")
	}
	if inspectErr != nil || facts.trust == nil || s.config.Kernel.TLS == nil || !reflect.DeepEqual(facts.trust.Policy(), s.config.Kernel.TLS.Policy()) {
		return StartupStatusObservation{}, bridgeError("authority_rejected")
	}
	if facts.state != "running" && facts.state != "absent" && facts.state != "stopped" {
		return StartupStatusObservation{}, bridgeError("authority_rejected")
	}
	input := ownerStatusObservation{status: BootstrapStatus{Disposition: "failed", Profile: p.Summary()}, attemptID: id}
	if facts.state == "running" && bootErr == nil {
		persistence, pErr := deployment.Observe(ctx, deployment.ObserveOptions{ProbeOptions: s.config.Health, ReadExistingRecord: true})
		kernel, kErr := observeKernelWithProof(ctx, s.config.Kernel, operationProof)
		if cleanup := bridgeObservationCleanupFailure(pErr, kErr); cleanup != nil {
			return StartupStatusObservation{}, cleanup
		}
		if pErr == nil && kErr == nil && persistence.BrokerVerified && persistence.PersistenceEvidence == deployment.PersistenceRecordSeen && kernel.KernelReadiness == "ready" {
			input.status.Disposition = "reused"
			input.status.Persistence = persistence
			input.status.Kernel = kernel
		}
	}
	input.receivedAt = time.Now().UTC()
	if input.status.Disposition == "reused" && session != nil {
		if err = lockOwnerObservation(ctx, &session.mu); err != nil {
			return StartupStatusObservation{}, err
		}
		// Only the actual owning started Session can preserve this original
		// outcome. Fresh read-only state does not invent another cold launch.
		if session.startupAttemptID == id && session.Status.Disposition == "started" && session.group != nil {
			input.status.Disposition = "started"
			if session.healthProof != nil {
				proof := *session.healthProof
				input.healthProof = &proof
			}
		}
		session.mu.Unlock()
	}
	out, err := s.owner.mapObservationContext(ctx, input)
	if err != nil {
		return out, err
	}
	if bootErr != nil {
		out.Errors = append(out.Errors, StartupStatusError{Component: "instance", Code: "host_startup_failed", Message: "The owning host could not complete startup.", Retryable: true})
	}
	if session != nil {
		if err = lockOwnerObservation(ctx, &session.mu); err != nil {
			return StartupStatusObservation{}, err
		}
		failed := session.cleanupFailure != nil || session.retiredGroup != nil
		if session.group != nil {
			for _, child := range session.group.Status() {
				failed = failed || child.Exited
			}
		}
		session.mu.Unlock()
		if failed {
			out.Disposition = "failed"
			out.Instance.Readiness = "not_ready"
			out.Instance.RunningVersion = nil
			for i, service := range out.Instance.Services {
				for _, role := range protocol.Roles() {
					if service.ServiceID == role {
						out.Instance.Services[i] = unknownStatusService(role, "probe_failed")
					}
				}
			}
			out.Errors = append(out.Errors, StartupStatusError{Component: "instance", Code: "owned_runtime_exited", Message: "The owned runtime is unavailable.", Retryable: true})
		}
	}
	return out, nil
}

func hexDigest(raw []byte) string { digest := sha256.Sum256(raw); return fmt.Sprintf("%x", digest) }

// Keep only actual observation cleanup owners on the Run failure path. Ordinary
// missing readiness still maps to an honest status; no cleanup cause is sent
// in a NATS reply or reduced to an unavailable result.
func bridgeObservationCleanupFailure(causes ...error) error {
	joined := errors.Join(causes...)
	var health *deployment.ProbeCleanupError
	var raw *deployment.RawTransportCleanupError
	var kernel *TransportCleanupError
	if !errors.As(joined, &health) && !errors.As(joined, &raw) && !errors.As(joined, &kernel) {
		return nil
	}
	return &bridgeCompletionCause{code: "owner_bridge_owned_connection_cleanup_failed", cause: joined}
}
