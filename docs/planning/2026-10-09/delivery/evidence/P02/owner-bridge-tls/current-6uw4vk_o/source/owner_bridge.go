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
	return &OwnerBridgeServer{c, e, owner, credential, subjects}, nil
}

func bridgeConnect(parent context.Context, c BootstrapConfig, credential OwnerBridgeCredential) (*nats.Conn, *localtls.Dialer, error) {
	if parent == nil || parent.Err() != nil {
		return nil, nil, bridgeError("deadline")
	}
	if c.Kernel.authority == nil || c.Kernel.TLS == nil {
		return nil, nil, bridgeError("authority_rejected")
	}
	bound := c.Kernel.authority.config
	if c.Kernel.Endpoint != bound.Kernel.Endpoint || c.Kernel.Scope != bound.Kernel.Scope || c.Kernel.Password != bound.Kernel.Password || bound.Kernel.TLS == nil || !reflect.DeepEqual(c.Kernel.TLS.Policy(), bound.Kernel.TLS.Policy()) {
		return nil, nil, bridgeError("authority_rejected")
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	authority, err := inspectLocalBrokerAuthority(ctx, c)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, bridgeError("deadline")
		}
		return nil, nil, bridgeError("authority_rejected")
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
	nc, err := nats.Connect(c.Kernel.Endpoint, nats.UserInfo(credential.Role, credential.Password), nats.TLSHandshakeFirst(), nats.NoReconnect(), nats.IgnoreDiscoveredServers(), nats.NoEcho(), nats.Timeout(remaining), nats.SetCustomDialer(dialer))
	if !stop() {
		<-stopped
	}
	if ctx.Err() != nil {
		return nil, nil, closeBridgeConnection(nc, dialer, bridgeError("deadline"))
	}
	if err != nil {
		code := "connection_unavailable"
		if localtls.IsAuthorityError(err) || errors.Is(err, nats.ErrAuthorization) || errors.Is(err, nats.ErrPermissionViolation) || errors.Is(err, nats.ErrAuthExpired) || errors.Is(err, nats.ErrAuthRevoked) {
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
	if nc.FlushWithContext(ctx) != nil {
		return empty, bridgeError("connection_unavailable")
	}
	request := ownerBridgeRequest{protocol.Version, "host-owner-status-request", operation, id, invocationID, c.config.Kernel.Scope, bridgeTime(time.Now())}
	raw, _ := json.Marshal(request)
	var msg *nats.Msg
	for sent := 0; sent < 10; sent++ {
		if ctx.Err() != nil {
			return empty, bridgeError("deadline")
		}
		// Core NATS may have no service subscriber during host startup. Repeat
		// only the identical read-only request; the owner's nonce guard accepts
		// it at most once. Every wait stays within the original total deadline.
		if nc.Publish(c.subjects.Request, raw) != nil || nc.FlushWithContext(ctx) != nil {
			return empty, bridgeError("connection_unavailable")
		}
		wait, stopWait := context.WithTimeout(ctx, 500*time.Millisecond)
		msg, err = sub.NextMsgWithContext(wait)
		stopWait()
		if err == nil {
			break
		}
		if ctx.Err() != nil || !errors.Is(err, context.DeadlineExceeded) {
			return empty, bridgeError("reply_unavailable")
		}
	}
	if msg == nil || err != nil {
		return empty, bridgeError("reply_unavailable")
	}
	var reply ownerBridgeReply
	if len(msg.Header) != 0 || msg.Reply != "" || msg.Subject != sub.Subject || decodeBridgeReply(msg.Data, &reply) != nil || reply.RequestID != id || reply.InvocationID != invocationID || reply.Scope != c.config.Kernel.Scope || !bridgeFresh(reply.SentAt, time.Now()) || !bridgeObservationBound(reply.Observation, c.enrollment, invocationID, time.Now()) {
		return empty, bridgeError("reply_invalid")
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
	return out.SchemaVersion == protocol.Version && out.StartupAttemptID != nil && *out.StartupAttemptID == id && out.Caller.PrincipalID == e.Owner.PrincipalID && out.Caller.Identity == e.Owner.Identity && reflect.DeepEqual(out.Caller.Scope, e.Owner.Scope) && out.Instance.InstanceID != nil && *out.Instance.InstanceID == e.Owner.InstanceID && out.Instance.ProfileID != nil && *out.Instance.ProfileID == e.Owner.ProfileID && bridgeFresh(out.ObservedAt, now) && out.SourceRevision > 0 && kernelStatusID.MatchString(out.ObservationID) && (out.Disposition == "started" || out.Disposition == "reused" || out.Disposition == "failed")
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
	if msg == nil || len(msg.Data) > protocol.MaxPayload || msg.Subject != subjects.Request || msg.Reply != "" || len(msg.Header) != 0 {
		return request, bridgeError("request_invalid")
	}
	if validateOwnerBridgeJSON(msg.Data, "host-owner-status-request", protocol.MaxPayload) != nil {
		return request, bridgeError("request_invalid")
	}
	if _, err := releaseFields(msg.Data, "schemaVersion", "kind", "operation", "requestId", "invocationId", "scope", "sentAt"); err != nil || protocol.StrictJSON(msg.Data, &request) != nil || request.SchemaVersion != protocol.Version || request.Kind != "host-owner-status-request" || (request.Operation != "ensure" && request.Operation != "status") || !ownerBridgeNonce.MatchString(request.RequestID) || !ownerBridgeInvocation.MatchString(request.InvocationID) || request.Scope != scope || !bridgeFresh(request.SentAt, now) {
		return request, bridgeError("request_invalid")
	}
	return request, nil
}

// Run owns one host-service lease and only the Session returned by its own
// bootstrap. A reused Session never adopts or stops another owner's children.
// Ordinary status traffic stays on the isolated HOST account.
func (s *OwnerBridgeServer) Run(startup, lifetime context.Context, coldInvocationID string) (failure error) {
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
	defer func() {
		if lease.Close() != nil {
			failure = errors.Join(failure, bridgeError("lease_cleanup_failed"))
		}
	}()
	session, bootErr := BootstrapForInvocation(startup, lifetime, s.config, coldInvocationID)
	if session != nil {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if session.Close(ctx) != nil {
				failure = errors.Join(failure, bridgeError("runtime_cleanup_failed"))
			}
		}()
	}
	// A broker that never started cannot transport a reply. This returns a safe
	// host failure; it does not manufacture a started observation.
	return s.serve(lifetime, coldInvocationID, session, bootErr, nil)
}

// The transport loop is separate for isolated broker tests. Production reaches
// it only after Run acquired the service lease and performed actual bootstrap.
func (s *OwnerBridgeServer) serve(lifetime context.Context, coldInvocationID string, session *Session, bootErr error, ready chan<- struct{}) (failure error) {
	if bootErr != nil {
		bounded, cancel := context.WithTimeout(lifetime, 5*time.Second)
		defer cancel()
		lifetime = bounded
	}
	nc, dialer, err := bridgeConnect(lifetime, s.config, s.credential)
	if err != nil {
		return err
	}
	defer nc.Close()
	defer func() {
		failure, _ = closeOwnedTransport(dialer, failure, "owner_bridge_owned_connection_cleanup_failed")
	}()
	sub, err := nc.SubscribeSync(s.subjects.Request)
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
		msg, err := sub.NextMsgWithContext(lifetime)
		if err != nil {
			if bootErr != nil {
				return bridgeError("startup_failed")
			}
			if lifetime.Err() != nil {
				return nil
			}
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
		var observation StartupStatusObservation
		retained := false
		var retainedReceipt time.Time
		var retainedKernel protocol.Snapshot
		if request.InvocationID == coldInvocationID && session != nil && bootErr == nil {
			if err = lockOwnerObservation(ctx, &session.mu); err == nil {
				retained = !session.observedAt.IsZero() && time.Since(session.observedAt) <= 3*time.Second
				retainedReceipt = session.observedAt
				retainedKernel = session.Status.Kernel
				retainedKernel.Members = append([]protocol.Member(nil), retainedKernel.Members...)
				session.mu.Unlock()
			}
		}
		if retained {
			observation, err = session.OwnerObservationContext(ctx, s.owner)
			// Selection and mapping can cross the freshness boundary. Retry only
			// proven expiry with genuine new facts in the remaining request budget.
			if err == nil && bridgeRetainedExpired(observation, retainedReceipt, retainedKernel, s.config.Kernel.Scope, time.Now()) {
				observation, err = s.refresh(ctx, request.InvocationID, session, bootErr)
			}
		} else {
			observation, err = s.refresh(ctx, request.InvocationID, session, bootErr)
		}
		if err == nil && bridgeObservationBound(observation, s.enrollment, request.InvocationID, time.Now()) {
			reply := ownerBridgeReply{protocol.Version, "host-owner-status-reply", request.RequestID, request.InvocationID, s.config.Kernel.Scope, bridgeTime(time.Now()), observation}
			raw, e := json.Marshal(reply)
			if e == nil && len(raw) <= ownerBridgeReplyLimit && ctx.Err() == nil && validateOwnerBridgeJSON(raw, "host-owner-status-reply", ownerBridgeReplyLimit) == nil {
				if nc.Publish(s.subjects.ReplyPrefix+request.RequestID[len("request_"):], raw) != nil || nc.FlushWithContext(ctx) != nil {
					cancel()
					return bridgeError("reply_failed")
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
	facts, inspectErr := inspectLocalBrokerAuthority(ctx, s.config)
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
		kernel, kErr := ObserveKernel(ctx, s.config.Kernel)
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
