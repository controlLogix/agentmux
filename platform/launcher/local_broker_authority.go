//go:build linux || darwin

package launcher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net"
	"net/url"
	"reflect"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/controlLogix/agentmux/platform/localtls"
)

// These types are deliberately private. An ordinary caller cannot supply an
// inspection callback or assert that a broker owns its selected deployment.
type localBrokerBinding struct{ config BootstrapConfig }
type localBrokerAuthority struct {
	state  string
	broker OwnedBroker
	trust  *localtls.ClientTrust
}

func attachLocalBrokerAuthority(c *BootstrapConfig) error {
	if c == nil || c.admissionPolicy == nil || c.LocalTLS == nil || c.Kernel.TLS == nil || c.Health.TLS == nil || c.Kernel.Endpoint != c.Kernel.TLS.Policy().Endpoint || c.Health.Endpoint != c.Kernel.Endpoint || !reflect.DeepEqual(c.Health.TLS.Policy(), c.Kernel.TLS.Policy()) {
		return bootstrapError("local_broker_authority_invalid")
	}
	bound := *c
	policy := copyLocalAdmissionPolicy(*c.admissionPolicy)
	bound.admissionPolicy = &policy
	bound.Kernel.authority = nil
	bound.Compose = bytes.Clone(c.Compose)
	bound.Assembly = bytes.Clone(c.Assembly)
	bound.ProfilePolicy.WorkspaceRoots = append([]string(nil), c.ProfilePolicy.WorkspaceRoots...)
	if c.OwnerBridge != nil {
		bridge := *c.OwnerBridge
		bound.OwnerBridge = &bridge
	}
	for i, role := range c.Roles {
		bound.Roles[i].Args = append([]string(nil), role.Args...)
		bound.Roles[i].Env = make(map[string]string, len(role.Env))
		for key, value := range role.Env {
			bound.Roles[i].Env[key] = value
		}
	}
	c.Kernel.authority = &localBrokerBinding{config: bound}
	return nil
}

func copyLocalAdmissionPolicy(p HostPolicy) HostPolicy {
	p.Profile.WorkspaceRoots = append([]string(nil), p.Profile.WorkspaceRoots...)
	p.ExternalRelease.PublicKey = bytes.Clone(p.ExternalRelease.PublicKey)
	if p.OwnerBridge != nil {
		bridge := *p.OwnerBridge
		p.OwnerBridge = &bridge
	}
	return p
}

// Re-read the complete private enrollment without network effects before
// inspecting Docker. TLS authenticates the socket separately after this check.
func inspectLocalBrokerAuthority(ctx context.Context, c BootstrapConfig) (localBrokerAuthority, error) {
	empty := localBrokerAuthority{}
	if ctx == nil || ctx.Err() != nil || c.admissionPolicy == nil || c.LocalTLS == nil || c.Kernel.TLS == nil {
		return empty, bootstrapError("local_broker_authority_invalid")
	}
	current, err := LoadBootstrapConfig(*c.admissionPolicy)
	if err != nil || current.LocalTLS == nil || current.Kernel.TLS == nil || !sameLocalBrokerEnrollment(c, current) {
		return empty, localAuthorityFailure("local_broker_authority_invalid", err)
	}
	profile, err := LoadProfile(current.ProfilePolicy)
	if err != nil {
		return empty, localAuthorityFailure("local_broker_authority_invalid", err)
	}
	p := profile.Declaration()
	selection, local := profile.LocalDocker()
	endpoint, parseErr := url.Parse(current.Kernel.Endpoint)
	if !local || parseErr != nil || endpoint.Scheme != "tls" || endpoint.User != nil || endpoint.Path != "" {
		return empty, bootstrapError("local_broker_authority_invalid")
	}
	_, portText, err := net.SplitHostPort(endpoint.Host)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || port < 1 || port > 65535 {
		return empty, bootstrapError("local_broker_authority_invalid")
	}
	driver, err := NewDocker(DockerConfig{Executable: selection.Executable, Context: selection.Context, Endpoint: selection.Endpoint, EngineID: selection.EngineID, Versions: DockerVersions{selection.ClientVersion, selection.ServerVersion, selection.ComposeVersion}, Timeout: 4 * time.Second, Backend: selection.Backend})
	if err != nil || ctx.Err() != nil {
		return empty, localAuthorityFailure("local_broker_authority_invalid", err)
	}
	owner := OwnershipPreflight{Project: p.ComposeProject, InstanceID: p.InstanceID, ProfileID: p.ProfileID, ReleaseDigest: p.ReleaseFingerprint, ConfigDigest: sha256.Sum256(current.Compose)}
	broker, err := driver.InspectOwnedTLSBroker(ctx, owner, current.BrokerImage, port, current.BrokerConfigDigest, sha256.Sum256(current.LocalTLS.ServerCertificatePEM()), sha256.Sum256(current.LocalTLS.ServerKeyPEM()))
	if err != nil || ctx.Err() != nil {
		return empty, localAuthorityFailure("local_broker_authority_unavailable", err)
	}
	if broker.State != "absent" && broker.State != "stopped" && broker.State != "running" {
		return empty, bootstrapError("local_broker_authority_invalid")
	}
	return localBrokerAuthority{state: broker.State, broker: broker, trust: current.Kernel.TLS}, nil
}

func sameLocalBrokerEnrollment(a, b BootstrapConfig) bool {
	if a.LocalTLS == nil || b.LocalTLS == nil || a.Kernel.TLS == nil || b.Kernel.TLS == nil || a.Health.TLS == nil || b.Health.TLS == nil {
		return false
	}
	return reflect.DeepEqual(a.ProfilePolicy, b.ProfilePolicy) && a.PackageDirectory == b.PackageDirectory && a.ReleaseTrust == b.ReleaseTrust && bytes.Equal(a.Assembly, b.Assembly) && bytes.Equal(a.Compose, b.Compose) && a.BrokerImage == b.BrokerImage && a.BrokerConfigDigest == b.BrokerConfigDigest && reflect.DeepEqual(a.OwnerBridge, b.OwnerBridge) && a.Kernel.Endpoint == b.Kernel.Endpoint && a.Kernel.Scope == b.Kernel.Scope && a.Kernel.Password == b.Kernel.Password && reflect.DeepEqual(a.Kernel.TLS.Policy(), b.Kernel.TLS.Policy()) && reflect.DeepEqual(a.Health.TLS.Policy(), b.Health.TLS.Policy()) && a.Health.Endpoint == b.Health.Endpoint && a.Health.HubID == b.Health.HubID && a.Health.ServerName == b.Health.ServerName && a.Health.ServerVersion == b.Health.ServerVersion && a.Health.Domain == b.Health.Domain && a.Health.Password == b.Health.Password && bytes.Equal(a.LocalTLS.RootsPEM(), b.LocalTLS.RootsPEM()) && bytes.Equal(a.LocalTLS.ServerCertificatePEM(), b.LocalTLS.ServerCertificatePEM()) && bytes.Equal(a.LocalTLS.ServerKeyPEM(), b.LocalTLS.ServerKeyPEM())
}

// kernelObservationProof is confined to one startup observation operation. It
// never grants authority to a caller-selected endpoint or another invocation.
type kernelObservationProof struct {
	binding   *localBrokerBinding
	parent    context.Context
	done      <-chan struct{}
	deadline  time.Time
	authority localBrokerAuthority
	completed time.Time
	used      atomic.Bool
}

func inspectLocalBrokerOperation(ctx context.Context, c BootstrapConfig) (localBrokerAuthority, *kernelObservationProof, error) {
	empty := localBrokerAuthority{}
	if ctx == nil {
		return empty, nil, bootstrapError("local_broker_authority_invalid")
	}
	deadline, bounded := ctx.Deadline()
	if !reflect.TypeOf(ctx).Comparable() || ctx.Done() == nil || !bounded || !deadline.After(time.Now()) || c.Kernel.authority == nil || !sameLocalBrokerEnrollment(c, c.Kernel.authority.config) {
		return empty, nil, bootstrapError("local_broker_authority_invalid")
	}
	authority, err := inspectLocalBrokerAuthority(ctx, c)
	if err != nil {
		return empty, nil, err
	}
	return authority, &kernelObservationProof{binding: c.Kernel.authority, parent: ctx, done: ctx.Done(), deadline: deadline, authority: authority, completed: time.Now()}, nil
}

// consume rechecks private enrollment, but does not repeat the Docker archive
// inspection. Expired proofs require a new inspection in the remaining budget.
func (p *kernelObservationProof) consume(parent context.Context, binding *localBrokerBinding) (localBrokerAuthority, bool, error) {
	empty := localBrokerAuthority{}
	if p == nil || !p.used.CompareAndSwap(false, true) || parent == nil || binding == nil || binding.config.admissionPolicy == nil || p.binding != binding || p.parent == nil || !reflect.TypeOf(parent).Comparable() || p.parent != parent || p.done == nil || p.done != parent.Done() || p.parent.Err() != nil || parent.Err() != nil {
		return empty, false, kernelStatusError("authority_rejected")
	}
	deadline, bound := parent.Deadline()
	if !bound || !deadline.Equal(p.deadline) {
		return empty, false, kernelStatusError("authority_rejected")
	}
	current, err := LoadBootstrapConfig(*binding.config.admissionPolicy)
	if err != nil || !sameLocalBrokerEnrollment(binding.config, current) || parent.Err() != nil {
		return empty, false, kernelStatusError("authority_rejected")
	}
	age := time.Since(p.completed)
	if age < 0 || age > 4*time.Second {
		return empty, true, nil
	}
	return p.authority, false, nil
}
