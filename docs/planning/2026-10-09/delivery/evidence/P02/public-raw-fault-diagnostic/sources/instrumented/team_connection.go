package deployment

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

type TeamAuthKind string

const (
	TeamJWT   TeamAuthKind = "jwt-user-credentials"
	TeamBasic TeamAuthKind = "basic-compatible"
)

// TeamScope binds a connection to separately enrolled policy. It grants no
// permissions; broker ACLs and application authorization remain authoritative.
type TeamScope struct {
	OrganizationID string         `json:"organizationId"`
	ProjectID      string         `json:"projectId"`
	Kernel         protocol.Scope `json:"kernel"`
}
type TeamCredentialReference struct {
	ID       string       `json:"id"`
	AuthKind TeamAuthKind `json:"authKind"`
}
type TeamConnectionPolicy struct {
	Endpoint, TLSServerName                                   string
	TLSRootsPEM                                               []byte
	ExpectedServerName, ExpectedDomain, ExpectedServerVersion string
	Scope                                                     TeamScope
	CredentialRef                                             TeamCredentialReference
	Timeout                                                   time.Duration
	ObserveDomain                                             bool
}

// Secret fields are private and never part of an observation or JSON output.
type TeamCredential struct {
	reference               TeamCredentialReference
	scope                   TeamScope
	username, password, jwt string
	key                     nkeys.KeyPair
}

func (TeamCredential) String() string   { return "[private team credential]" }
func (TeamCredential) GoString() string { return "[private team credential]" }

// Resolver implementations are trusted host code and must honor ctx. The
// connection does not leave a background goroutine to hide a blocked resolver.
// Resolve transfers a fresh JWT key to this operation; Observe wipes it after
// owned connection cleanup. Do not return a cached mutable JWT key.
type TeamCredentialResolver interface {
	Resolve(context.Context, TeamCredentialReference) (TeamCredential, error)
}

func NewTeamBasicCredential(reference TeamCredentialReference, scope TeamScope, username, password string) (TeamCredential, error) {
	if reference.AuthKind != TeamBasic || !identifier.MatchString(reference.ID) || username == "" || len(username) > 256 || strings.ContainsAny(username, "\x00\r\n") || !secret.MatchString(password) {
		return TeamCredential{}, teamError("credential_invalid")
	}
	return TeamCredential{reference: reference, scope: scope, username: username, password: password}, nil
}

// Parse standard decorated credentials without treating JWT payload claims as
// authorization. The actual configured broker must verify the signed JWT.
func NewTeamJWTCredential(reference TeamCredentialReference, scope TeamScope, decorated []byte) (TeamCredential, error) {
	if reference.AuthKind != TeamJWT || !identifier.MatchString(reference.ID) || len(decorated) == 0 || len(decorated) > 64*1024 {
		return TeamCredential{}, teamError("credential_invalid")
	}
	jwt, err := nkeys.ParseDecoratedJWT(decorated)
	if err != nil {
		return TeamCredential{}, teamError("credential_invalid")
	}
	key, err := nkeys.ParseDecoratedNKey(decorated)
	if err != nil {
		return TeamCredential{}, teamError("credential_invalid")
	}
	public, err := key.PublicKey()
	if err != nil || !nkeys.IsValidPublicUserKey(public) {
		key.Wipe()
		return TeamCredential{}, teamError("credential_invalid")
	}
	return TeamCredential{reference: reference, scope: scope, jwt: jwt, key: key}, nil
}

type TeamConnection struct {
	policy   TeamConnectionPolicy
	roots    *x509.CertPool
	address  string
	resolver TeamCredentialResolver
}

func teamError(code string) error { return errors.New("team_" + code) }

func NewTeamConnection(policy TeamConnectionPolicy, resolver TeamCredentialResolver) (*TeamConnection, error) {
	u, err := url.Parse(policy.Endpoint)
	if err != nil || u.Scheme != "tls" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(policy.Endpoint, "?#\x00\r\n") {
		return nil, teamError("endpoint_invalid")
	}
	host, port, err := net.SplitHostPort(u.Host)
	number, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || portErr != nil || number == 0 || host == "" || strings.ContainsAny(host, "% \\\t\r\n") || policy.TLSServerName == "" || strings.ContainsAny(policy.TLSServerName, "%:/ \\\t\r\n\x00") {
		return nil, teamError("endpoint_invalid")
	}
	s := policy.Scope
	digest := regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	if !identifier.MatchString(s.OrganizationID) || !identifier.MatchString(s.ProjectID) || !identifier.MatchString(s.Kernel.HubID) || !identifier.MatchString(s.Kernel.InstanceID) || !identifier.MatchString(s.Kernel.ProfileID) || !digest.MatchString(s.Kernel.AssemblyDigest) || !digest.MatchString(s.Kernel.ReleaseManifestDigest) || !probeVersion.MatchString(s.Kernel.ReleaseVersion) || !identifier.MatchString(policy.ExpectedServerName) || !identifier.MatchString(policy.ExpectedDomain) || !probeVersion.MatchString(policy.ExpectedServerVersion) || !identifier.MatchString(policy.CredentialRef.ID) || (policy.CredentialRef.AuthKind != TeamJWT && policy.CredentialRef.AuthKind != TeamBasic) || policy.Timeout <= 0 || policy.Timeout > 5*time.Second || resolver == nil || len(policy.TLSRootsPEM) == 0 || len(policy.TLSRootsPEM) > 64*1024 {
		return nil, teamError("policy_invalid")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(policy.TLSRootsPEM) {
		return nil, teamError("trust_invalid")
	}
	policy.TLSRootsPEM = nil
	return &TeamConnection{policy: policy, roots: roots, address: u.Host, resolver: resolver}, nil
}

type TeamConnectionObservation struct {
	TLSVerified            bool               `json:"tlsVerified"`
	Authenticated          bool               `json:"authenticated"`
	ServerIdentityVerified bool               `json:"serverIdentityVerified"`
	BrokerVerified         bool               `json:"brokerVerified"`
	ServerName             string             `json:"serverName,omitempty"`
	ServerVersion          string             `json:"serverVersion,omitempty"`
	DomainAvailability     string             `json:"domainAvailability"`
	Domain                 string             `json:"domain,omitempty"`
	KernelAvailability     string             `json:"kernelAvailability"`
	Snapshot               *protocol.Snapshot `json:"snapshot,omitempty"`
	Code                   string             `json:"code"`
}

// Observe closes every owned connection before returning. It never starts a
// broker, provisions storage, publishes health records or claims R3/federation.
func (connection *TeamConnection) Observe(parent context.Context) (out TeamConnectionObservation, err error) {
	return connection.observeChecked(parent, nil)
}

// The internal callback controls a cancellation boundary in regressions only.
// Public observations always pass nil and cannot inject operations or options.
func (connection *TeamConnection) observeChecked(parent context.Context, afterDomain func()) (out TeamConnectionObservation, err error) {
	out.DomainAvailability, out.KernelAvailability, out.Code = "unavailable", "unavailable", "not_observed"
	if connection == nil || parent == nil {
		return out, teamError("context_invalid")
	}
	p := connection.policy
	ctx, cancel := context.WithTimeout(parent, p.Timeout)
	defer cancel()
	if ctx.Err() != nil {
		return out, teamError("deadline")
	}
	credential, resolveErr := connection.resolver.Resolve(ctx, p.CredentialRef)
	if credential.key != nil {
		defer credential.key.Wipe()
	}
	if resolveErr != nil {
		return out, teamError("credential_unavailable")
	}
	if ctx.Err() != nil {
		return out, teamError("deadline")
	}
	if credential.reference != p.CredentialRef || credential.scope != p.Scope {
		return out, teamError("credential_binding_invalid")
	}
	dialer := &observeDialer{ctx: ctx, address: connection.address}
	var nc *nats.Conn
	defer func() {
		var failed bool
		rawPublicCapture(dialer, out, err)
		err, failed = closeRawTransport(dialer, err, "team_connection_cleanup_failed")
		if failed {
			out = TeamConnectionObservation{DomainAvailability: "unavailable", KernelAvailability: "unavailable", Code: "cleanup_failed"}
		}
		if nc != nil {
			nc.Close()
		}
	}()
	wire, _ := communication.Subjects(p.Scope.Kernel.HubID)
	deadline, _ := ctx.Deadline()
	options := []nats.Option{nats.Secure(&tls.Config{RootCAs: connection.roots.Clone(), ServerName: p.TLSServerName, MinVersion: tls.VersionTLS12}), nats.Timeout(time.Until(deadline)), nats.NoReconnect(), nats.IgnoreDiscoveredServers(), nats.NoEcho(), nats.PermissionErrOnSubscribe(true), nats.SetCustomDialer(dialer), nats.ErrorHandler(func(*nats.Conn, *nats.Subscription, error) {})}
	if p.CredentialRef.AuthKind == TeamBasic {
		if credential.username == "" || !secret.MatchString(credential.password) {
			return out, teamError("credential_invalid")
		}
		options = append(options, nats.UserInfo(credential.username, credential.password))
	} else {
		if credential.jwt == "" || credential.key == nil {
			return out, teamError("credential_invalid")
		}
		options = append(options, nats.UserJWT(func() (string, error) { return credential.jwt, nil }, credential.key.Sign))
	}
	var connectErr error
	nc, connectErr = nats.Connect(p.Endpoint, options...)
	if connectErr != nil {
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			return out, teamError("deadline")
		}
		return out, teamError("authentication_or_connection_unavailable")
	}
	out.TLSVerified, out.Authenticated = true, true
	if nc.ConnectedServerName() != p.ExpectedServerName || nc.ConnectedServerVersion() != p.ExpectedServerVersion {
		return out, teamError("server_identity_mismatch")
	}
	out.ServerIdentityVerified = true
	out.ServerName, out.ServerVersion = nc.ConnectedServerName(), nc.ConnectedServerVersion()
	// The synchronous subscription API reports its own permission errors even
	// when the SDK's asynchronous callback has no subscription handle.
	sub, subscribeErr := nc.SubscribeSync(wire.Snapshot)
	if subscribeErr == nil {
		defer sub.Unsubscribe()
		if sub.SetPendingLimits(1, protocol.MaxPayload) != nil || sub.AutoUnsubscribe(1) != nil || nc.FlushWithContext(ctx) != nil {
			subscribeErr = teamError("subscription_unavailable")
		}
	}
	var message *nats.Msg
	messageErr := subscribeErr
	if subscribeErr == nil {
		// Consume the bounded snapshot before a possibly unavailable INFO
		// request. This also releases the subscription after its first frame.
		snapshotBudget := time.Until(deadline) / 2
		if snapshotBudget > time.Second {
			snapshotBudget = time.Second
		}
		snapshotContext, stopSnapshot := context.WithTimeout(ctx, snapshotBudget)
		message, messageErr = sub.NextMsgWithContext(snapshotContext)
		stopSnapshot()
	}
	if messageErr == nil {
		if message == nil || message.Subject != wire.Snapshot || message.Reply != "" {
			return out, teamError("snapshot_invalid")
		}
		snapshot, decodeErr := protocol.DecodeSnapshot(message.Data, p.Scope.Kernel, time.Now(), 3*time.Second)
		if decodeErr != nil {
			return out, teamError("snapshot_or_scope_invalid")
		}
		out.Snapshot = &snapshot
		out.KernelAvailability, out.Code = "available", "read_only_observed"
	}
	// Account INFO is a read-only request, but its publish permission is not
	// assumed. A failed request cannot erase independently received kernel data.
	if p.ObserveDomain {
		domainBudget := time.Until(deadline) / 3
		if domainBudget > time.Second {
			domainBudget = time.Second
		}
		accountContext, stopAccount := context.WithTimeout(ctx, domainBudget)
		js, jsErr := nc.JetStream(nats.Domain(p.ExpectedDomain))
		if jsErr == nil {
			account, accountErr := js.AccountInfo(nats.Context(accountContext))
			if accountErr == nil {
				if account.Domain != p.ExpectedDomain {
					stopAccount()
					return out, teamError("domain_mismatch")
				}
				out.DomainAvailability, out.Domain, out.BrokerVerified = "available", account.Domain, true
			}
		}
		stopAccount()
	}
	if afterDomain != nil {
		afterDomain()
	}
	if parent.Err() != nil {
		out.Code = "observation_cancelled"
		return out, teamError("deadline")
	}
	if messageErr != nil {
		out.Code = "kernel_unavailable"
		if parent.Err() != nil {
			return out, teamError("deadline")
		}
		return out, nil
	}
	if ctx.Err() != nil {
		out.Code = "observation_cancelled"
		return out, teamError("deadline")
	}
	return out, nil
}

// Prevent accidental default formatting from exposing the selected endpoint.
func (*TeamConnection) String() string              { return "[enrolled team connection]" }
func (connection *TeamConnection) GoString() string { return fmt.Sprint(connection) }
