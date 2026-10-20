//go:build (darwin && arm64) || ((linux || darwin) && agentmux_application_services)

package launcher

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
	"github.com/nats-io/nkeys"
)

// ApplicationServiceProcessSelection is supplied by the admitted host. The
// package and service-selection pins do not come from an application request.
type ApplicationServiceProcessSelection struct {
	InstallationID, Path, SHA256 string
	HostAccountPublicKey         string // Stale callers are refused; never a HOST identity.
}

func (ApplicationServiceProcessSelection) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "[private application service process selection]")
}

type applicationServiceStart struct {
	SchemaVersion        string                          `json:"schemaVersion"`
	Kind                 string                          `json:"kind"`
	LifetimeID           string                          `json:"lifetimeId"`
	Selection            string                          `json:"selection"`
	SelectionSHA256      string                          `json:"selectionSHA256"`
	HostPolicy           string                          `json:"hostPolicy"`
	OwnerUID             uint32                          `json:"ownerUid"`
	Workspaces           []string                        `json:"workspaces"`
	KernelScope          protocol.Scope                  `json:"kernelScope"`
	ProtectedHostAccount applicationProtectedHostAccount `json:"protectedHostAccount"`
	LeaseFD              int                             `json:"leaseFd"`
}

type applicationProtectedHostAccount struct {
	Kind    string                         `json:"kind"`
	Account string                         `json:"account"`
	Broker  applicationProtectedHostBroker `json:"broker"`
}

type applicationProtectedHostBroker struct {
	Endpoint     string `json:"endpoint"`
	ServerName   string `json:"serverName"`
	ConfigSHA256 string `json:"configSha256"`
}

// Only the fully reconstructed local factory establishes this description.
// An account name, public key or descriptor supplied by a client cannot do so.
func admitApplicationServiceProtectedHost(config BootstrapConfig) (applicationProtectedHostAccount, error) {
	var empty applicationProtectedHostAccount
	if config.OwnerBridge == nil || config.OwnerBridge.Scope != config.Kernel.Scope || config.Kernel.TLS == nil || config.LocalTLS == nil || config.Kernel.Endpoint != config.Health.Endpoint || config.Kernel.TLS.Policy().Endpoint != config.Kernel.Endpoint || !releaseIdentifier.MatchString(config.Health.ServerName) {
		return empty, serviceProcessError("protected_host_unadmitted", nil)
	}
	if _, err := deployment.OwnerBridgeSubjects(config.Kernel.Scope); err != nil {
		return empty, serviceProcessError("protected_host_unadmitted", err)
	}
	raw, err := bootstrapComposeBrokerBytes(config)
	if err != nil {
		return empty, serviceProcessError("protected_host_unadmitted", err)
	}
	defer clear(raw)
	if _, err := bootstrapBrokerCredentials(raw, config); err != nil {
		return empty, serviceProcessError("protected_host_unadmitted", err)
	}
	return applicationProtectedHostAccount{Kind: "named-password", Account: deployment.OwnerBridgeAccount,
		Broker: applicationProtectedHostBroker{Endpoint: config.Kernel.Endpoint, ServerName: config.Health.ServerName, ConfigSHA256: "sha256:" + hex.EncodeToString(config.BrokerConfigDigest[:])}}, nil
}

type applicationServiceSelectionHeader struct {
	SchemaVersion     string                           `json:"schemaVersion"`
	HostPolicy        string                           `json:"hostPolicy"`
	OwnerUID          uint32                           `json:"ownerUid"`
	Workspaces        []string                         `json:"workspaces"`
	KernelScope       protocol.Scope                   `json:"kernelScope"`
	AuthorityID       string                           `json:"authorityId"`
	OrganizationID    string                           `json:"organizationId"`
	AuthoritySwitch   any                              `json:"authoritySwitch"`
	OIDCBrowser       map[string]any                   `json:"oidcBrowser,omitempty"`
	Identity          map[string]any                   `json:"identity"`
	Definitions       map[string]any                   `json:"definitions"`
	Integration       map[string]any                   `json:"integration,omitempty"`
	Configuration     map[string]any                   `json:"configuration,omitempty"`
	Dashboard         map[string]any                   `json:"dashboard,omitempty"`
	Orchestration     map[string]any                   `json:"orchestration,omitempty"`
	Storage           *applicationServiceStorageHeader `json:"storage,omitempty"`
	Policy            map[string]any                   `json:"policy,omitempty"`
	Task              map[string]any                   `json:"task,omitempty"`
	Workspace         map[string]any                   `json:"workspace,omitempty"`
	Artifact          map[string]any                   `json:"artifact,omitempty"`
	Process           map[string]any                   `json:"process,omitempty"`
	FederationPolicy  map[string]any                   `json:"federationPolicy,omitempty"`
	PeerControl       map[string]any                   `json:"peerControl,omitempty"`
	CoreWorkTransport map[string]any                   `json:"coreWorkTransport,omitempty"`
}

// Python admits the complete nested provider selection before readiness. This
// header keeps the native boundary closed without copying protected inputs to
// process arguments, environment variables or start messages.
type applicationServiceStorageHeader struct {
	Scope          any            `json:"scope"`
	Receivers      any            `json:"receivers"`
	PrivateStorage any            `json:"privateStorage,omitempty"`
	Board          any            `json:"board,omitempty"`
	Messages       map[string]any `json:"messages,omitempty"`
	Knowledge      map[string]any `json:"knowledge,omitempty"`
	Code           map[string]any `json:"code,omitempty"`
	Work           map[string]any `json:"work,omitempty"`
}

type applicationServicePackage interface {
	Recheck(context.Context) error
	Close() error
}

func bindSelectedApplicationService(raw []byte, selected ApplicationServiceProcessSelection, host HostPolicySelection, scope protocol.Scope, attestor *ApplicationAttestorHostSelection, requireAuthoritySwitch bool) error {
	sum := sha256.Sum256(raw)
	var header applicationServiceSelectionHeader
	if "sha256:"+hex.EncodeToString(sum[:]) != selected.SHA256 || protocol.DecodeClosedJSON(raw, &header, 65536) != nil ||
		header.SchemaVersion != protocol.Version || header.HostPolicy != host.Path || header.OwnerUID != host.OwnerUID ||
		!reflect.DeepEqual(header.Workspaces, host.WorkspaceRoots) || header.KernelScope != scope || header.AuthorityID == "" || header.OrganizationID == "" ||
		(requireAuthoritySwitch && header.AuthoritySwitch == nil) || len(header.Identity) == 0 || len(header.Definitions) == 0 {
		return serviceProcessError("selection_binding_invalid", nil)
	}
	if attestor != nil {
		return bindApplicationServiceIdentity(header, *attestor)
	}
	return nil
}

func bindApplicationServiceSelection(raw []byte, selected ApplicationServiceProcessSelection, host HostPolicySelection, scope protocol.Scope, attestor *ApplicationAttestorHostSelection) error {
	return bindSelectedApplicationService(raw, selected, host, scope, attestor, true)
}

func bindApplicationServiceIdentity(header applicationServiceSelectionHeader, attestor ApplicationAttestorHostSelection) error {
	refused := serviceProcessError("identity_connection_binding_invalid", nil)
	connection, connectionOK := header.Identity["connection"].(map[string]any)
	credentials, credentialsOK := header.Identity["credentials"].(map[string]any)
	if !connectionOK || !credentialsOK || header.KernelScope != attestor.Signer.KernelScope || header.AuthorityID != attestor.Signer.AuthorityID || header.OrganizationID != attestor.Signer.Scope.OrganizationID {
		return refused
	}
	text := func(object map[string]any, key string) string {
		value, _ := object[key].(string)
		return value
	}
	selected := ApplicationAttestorConnectionSelection{Endpoint: text(connection, "endpoint"), ServerName: text(connection, "serverName"), RootsPEM: text(connection, "rootsPEM"), LeafCertificateSHA256: text(connection, "leafCertificateSHA256")}
	if _, err := selected.clientTrust(); err != nil || selected != attestor.Connection {
		return refused
	}
	account, user, reply := text(credentials, "accountPublicKey"), text(credentials, "userPublicKey"), text(credentials, "replyPrefix")
	// Equal endpoints alone do not connect NATS accounts. This bounded route
	// uses one admitted application account with separate least-privilege users.
	if !nkeys.IsValidPublicAccountKey(account) || account != attestor.AccountPublicKey || !nkeys.IsValidPublicUserKey(user) || user == attestor.UserPublicKey || !applicationReplyPrefix.MatchString(reply) || reply == attestor.Signer.ReplyPrefix {
		return refused
	}
	return nil
}

func (host *EnrolledHostPolicy) prepareApplicationServices(ctx context.Context, selected ApplicationServiceProcessSelection, attestor *ApplicationAttestorHostSelection, requireAuthoritySwitch bool) (applicationServiceStart, *protected.InstalledClientAdmission, error) {
	var empty applicationServiceStart
	if host == nil || ctx == nil || ctx.Err() != nil || !protected.ValidClientInstallationID(selected.InstallationID) ||
		!filepath.IsAbs(selected.Path) || filepath.Clean(selected.Path) != selected.Path || !kernelStatusDigest.MatchString(selected.SHA256) || selected.HostAccountPublicKey != "" {
		return empty, nil, serviceProcessError("selection_invalid", nil)
	}
	config, _, err := host.Load()
	if err != nil {
		return empty, nil, serviceProcessError("host_invalid", err)
	}
	protectedHost, err := admitApplicationServiceProtectedHost(config)
	if err != nil {
		return empty, nil, err
	}
	root, err := openPrivateHostRoot(filepath.Dir(selected.Path), host.selection.OwnerUID, host.selection.WorkspaceRoots)
	if err != nil {
		return empty, nil, serviceProcessError("selection_invalid", err)
	}
	raw, readErr := readApplicationPrivateFile(ctx, root, filepath.Base(selected.Path), host.selection.OwnerUID, 65536)
	closeErr := root.Close()
	if readErr != nil || closeErr != nil {
		clear(raw)
		failure := serviceProcessError("selection_invalid", errors.Join(readErr, closeErr), root)
		if closeErr != nil {
			failure = errors.Join(failure, serviceProcessOwnershipError(root))
		}
		return empty, nil, failure
	}
	defer clear(raw)
	if err := bindSelectedApplicationService(raw, selected, host.selection, config.Kernel.Scope, attestor, requireAuthoritySwitch); err != nil {
		return empty, nil, err
	}
	// The Python receiving host validates the complete nested service schema
	// before opening connections, histories or keys. This layer binds its exact
	// bytes to the independently admitted host before any process is created.
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return empty, nil, serviceProcessError("lifetime_unavailable", err)
	}
	request := applicationServiceStart{protocol.Version, "application-services-start", "service_" + hex.EncodeToString(nonce[:]), selected.Path, selected.SHA256,
		host.selection.Path, host.selection.OwnerUID, append([]string(nil), host.selection.WorkspaceRoots...), config.Kernel.Scope, protectedHost, 3}
	admission, err := protected.PrepareInstalledClient(ctx, selected.InstallationID)
	if err != nil {
		// A refused admission can itself retain private descriptor owners after
		// a cleanup failure, even when no package owner was returned.
		return empty, nil, errors.Join(serviceProcessError("package_invalid", err), serviceProcessOwnershipError(err))
	}
	return request, admission, nil
}

// StartApplicationServices returns a retained owner on every partial-start
// failure. The caller must keep it and finish Stop before attempting replacement.
func (host *EnrolledHostPolicy) StartApplicationServices(ctx context.Context, selected ApplicationServiceProcessSelection, hostLifetime <-chan struct{}) (*ApplicationServiceProcess, error) {
	return host.startApplicationServices(ctx, selected, hostLifetime, nil)
}

func (host *EnrolledHostPolicy) startApplicationServices(ctx context.Context, selected ApplicationServiceProcessSelection, hostLifetime <-chan struct{}, attestor *ApplicationAttestorHostSelection) (*ApplicationServiceProcess, error) {
	if ctx == nil || hostLifetime == nil || serviceChannelClosed(hostLifetime) {
		return nil, serviceProcessError("lifetime_invalid", nil)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	request, admission, err := host.prepareApplicationServices(ctx, selected, attestor, true)
	if err != nil {
		return nil, err
	}
	lease, err := AcquireBootstrapLock(ctx, host.record.ProfileDirectory, host.record.InstanceID, "application-services")
	if err != nil {
		closeErr := admission.Close()
		failure := serviceProcessError("lease_unavailable", errors.Join(err, closeErr), admission)
		if closeErr != nil {
			failure = errors.Join(failure, serviceProcessOwnershipError(admission))
		}
		return nil, failure
	}
	return startApplicationServiceProcess(ctx, request, admission, lease, hostLifetime,
		newInstalledApplicationServiceChild(selected.InstallationID, lease.file))
}

// RunWithApplicationServices owns the selected service process and the attestor
// under the actual host lifetime. The ordinary attestor-only route is unchanged.
func (host *EnrolledHostPolicy) RunWithApplicationServices(parent context.Context, invocationID string, attestor ApplicationAttestorHostSelection, selected ApplicationServiceProcessSelection) error {
	if !protected.ValidClientInstallationID(selected.InstallationID) || !applicationFileReference(selected.Path) ||
		!kernelStatusDigest.MatchString(selected.SHA256) || selected.HostAccountPublicKey != "" {
		return serviceProcessError("selection_invalid", nil)
	}
	return host.runWithApplicationAttestor(parent, invocationID, attestor, func(server *OwnerBridgeServer) error {
		server.application.services = func(ctx context.Context, lifetime <-chan struct{}) (applicationHostServiceOwner, error) {
			owner, err := host.startApplicationServices(ctx, selected, lifetime, &attestor)
			if owner == nil {
				return nil, err
			}
			return owner, err
		}
		return nil
	})
}
