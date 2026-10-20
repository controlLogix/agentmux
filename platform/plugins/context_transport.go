package plugins

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

type NATSContextOptions struct {
	HubID                 string                    `json:"hubId"`
	AccountPublicKey      string                    `json:"accountPublicKey"`
	ServerURL             string                    `json:"serverURL"`
	CAFile                string                    `json:"caFile"`
	ServerCredentialsFile string                    `json:"serverCredentialsFile"`
	Bindings              []ContextTransportBinding `json:"bindings"`
}

type ContextTransportBinding struct {
	InstanceID            string `json:"instanceId"`
	ClientCredentialsFile string `json:"clientCredentialsFile"`
}

func (NATSContextOptions) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private context transport options]")
}
func (NATSContextOptions) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-context-transport-options"}`), nil
}

type contextProvider struct {
	mu      sync.Mutex
	owners  map[string]*contextLease
	opening map[string]bool
	options NATSContextOptions
	ports   ContextPorts
	server  lifecycleCredential
	clients map[string]lifecycleCredential
	ca      []byte
	tls     *tls.Config
	connect func(context.Context, ContextTransport) (contextConnection, error)
}

func (*contextProvider) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[plugin context provider]")
}
func (*contextProvider) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"plugin-context-provider"}`), nil
}

// This constructor reads private credential snapshots, but it starts no service
// and publishes no readiness. Each successful Open owns its own connection.
func NewNATSContextProvider(ctx context.Context, options NATSContextOptions, ports ContextPorts) (ContextProvider, error) {
	if ctx == nil || ctx.Err() != nil || !contextPortsValid(ports) {
		return nil, pluginError("context_ports_unavailable")
	}
	if !registryIdentifier.MatchString(options.HubID) || len(options.Bindings) == 0 || len(options.Bindings) > 64 {
		return nil, pluginError("context_transport_options_invalid")
	}
	if secure, err := validateLifecycleURL(options.ServerURL); err != nil || !secure || options.CAFile == "" {
		return nil, pluginError("context_transport_options_invalid")
	}
	ca, err := ReadOwnerPrivateFile(options.CAFile, 1<<20)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, pluginError("context_ca_invalid")
	}
	u, _ := url.Parse(options.ServerURL)
	p := &contextProvider{options: options, ports: ports, clients: map[string]lifecycleCredential{}, ca: bytes.Clone(ca),
		tls: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: u.Hostname()}}
	p.options.Bindings = append([]ContextTransportBinding(nil), options.Bindings...)
	p.ports.EventCodes = append([]string(nil), ports.EventCodes...)
	p.ports.SpanCodes = append([]string(nil), ports.SpanCodes...)
	p.ports.MetricCodes = append([]string(nil), ports.MetricCodes...)
	var publish, subscribe []string
	keys := map[string]bool{}
	for _, binding := range options.Bindings {
		if ctx.Err() != nil || !registryIdentifier.MatchString(binding.InstanceID) || p.clients[binding.InstanceID].public != "" {
			return nil, pluginError("context_transport_binding_invalid")
		}
		transport := contextSubjects(options, binding.InstanceID)
		credential, err := readContextCredential(binding.ClientCredentialsFile, options.AccountPublicKey,
			[]string{transport.RequestSubject, transport.ResultSubject}, []string{transport.ReplySubject, transport.InvokeSubject, transport.CancelSubject})
		if err != nil {
			return nil, err
		}
		if keys[credential.public] {
			return nil, pluginError("context_identity_reused")
		}
		keys[credential.public] = true
		p.clients[binding.InstanceID] = credential
		publish = append(publish, transport.ReplySubject, transport.InvokeSubject, transport.CancelSubject)
		subscribe = append(subscribe, transport.RequestSubject, transport.ResultSubject)
	}
	p.server, err = readContextCredential(options.ServerCredentialsFile, options.AccountPublicKey, publish, subscribe)
	if err != nil {
		return nil, err
	}
	if keys[p.server.public] {
		return nil, pluginError("context_identity_reused")
	}
	p.connect = p.connectNATS
	return p, nil
}

// Context credentials retain the existing narrow signed-JWT profile. Reusing
// its parser does not widen the permissions accepted by lifecycle-only callers.
func readContextCredential(path, account string, publish, subscribe []string) (lifecycleCredential, error) {
	credential, err := readLifecycleCredential(path, account, publish, subscribe)
	if err != nil {
		return lifecycleCredential{}, managerFailure(err, "context_credential_invalid")
	}
	return credential, nil
}

func contextSubjects(options NATSContextOptions, instance string) ContextTransport {
	prefix := "amx.v1.h." + options.HubID + ".plugins." + instance + "."
	return ContextTransport{SchemaVersion: "1.0.0", ServerURL: options.ServerURL,
		RequestSubject: prefix + "context.request", ReplySubject: prefix + "context.reply",
		InvokeSubject: prefix + "operation.invoke", ResultSubject: prefix + "operation.result", CancelSubject: prefix + "operation.cancel"}
}

func (p *contextProvider) Open(ctx context.Context, binding ContextBinding) (ContextLease, error) {
	if ctx == nil || ctx.Err() != nil || !contextPortsValid(p.ports) {
		return nil, pluginError("context_authority_unavailable")
	}
	if !validProfileContext(binding.ProfileContext) {
		return nil, pluginError("context_profile_invalid")
	}
	binding = cloneContextBinding(binding)
	if !contextOwnerValid(binding.Owner) || binding.Owner.Pin != binding.Package.Pin() || !binding.Configuration.BelongsTo(binding.Package) ||
		binding.LifetimeDone == nil || completed(binding.LifetimeDone) || nilContextDependency(binding.Lifecycle) || binding.Lifecycle.Snapshot().Owner != binding.Owner || binding.Lifecycle.DrainDone() == nil || completed(binding.Lifecycle.DrainDone()) || p.clients[binding.Owner.InstanceID].public == "" {
		return nil, pluginError("context_binding_invalid")
	}
	if binding.Parent != nil {
		if !contextOwnerValid(*binding.Parent) || binding.Parent.InstanceID == binding.Owner.InstanceID || binding.Parent.Epoch != binding.Owner.Epoch ||
			binding.ParentLifetime == nil || completed(binding.ParentLifetime) {
			return nil, pluginError("context_parent_invalid")
		}
	} else if binding.ParentLifetime != nil {
		return nil, pluginError("context_parent_invalid")
	}
	p.mu.Lock()
	if p.owners[binding.Owner.InstanceID] != nil || p.opening[binding.Owner.InstanceID] {
		p.mu.Unlock()
		return nil, pluginError("context_instance_owned")
	}
	if p.owners == nil {
		p.owners = map[string]*contextLease{}
		p.opening = map[string]bool{}
	}
	p.opening[binding.Owner.InstanceID] = true
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.opening, binding.Owner.InstanceID)
		p.mu.Unlock()
	}()
	admit, stopAdmission := context.WithTimeout(ctx, contextCallBudget)
	defer stopAdmission()
	admission, err := p.ports.Authority.BindInstance(admit, cloneContextBinding(binding))
	if err != nil {
		return nil, pluginError("context_authority_unavailable")
	}
	admission = cloneInstanceAdmission(admission)
	descriptor, handles, expiry, err := contextDescriptor(p.options.HubID, binding, admission, p.ports.Now())
	if err != nil {
		return nil, err
	}
	if admit.Err() != nil || completed(binding.LifetimeDone) || completed(binding.ParentLifetime) || completed(binding.Lifecycle.DrainDone()) {
		return nil, pluginError("context_owner_stale")
	}
	if p.ports.Authority.Recheck(admit, binding.Owner, cloneInstanceAdmission(admission), nil) != nil || admit.Err() != nil {
		return nil, pluginError("context_authority_unavailable")
	}
	transport := contextSubjects(p.options, binding.Owner.InstanceID)
	connection, err := p.connect(ctx, transport)
	if connection == nil {
		return nil, pluginError("context_transport_unavailable")
	}
	// Startup cancellation must not become the successful lease's lifetime.
	lifetime, cancel := context.WithCancel(context.Background())
	l := &contextLease{binding: cloneContextBinding(binding), ports: p.ports, admission: admission, grantUntil: expiry, elapsedOrigin: time.Now(),
		bootstrap: ContextBootstrap{descriptor, bytes.Clone(p.clients[binding.Owner.InstanceID].raw), bytes.Clone(p.ca), transport},
		handles:   handles, transport: connection, ctx: lifetime, cancel: cancel,
		done: make(chan struct{}), joined: make(chan struct{}), workJoined: make(chan struct{}), serviceRun: make(chan struct{}), resultRun: make(chan struct{}), monitorRun: make(chan struct{}),
		permits: make(chan struct{}, contextServiceLimit), admissions: make(chan struct{}, contextOperationLimit), operations: map[string]*contextOperation{}, requests: map[string]bool{}}
	p.mu.Lock()
	p.owners[binding.Owner.InstanceID] = l
	p.mu.Unlock()
	l.onJoined = func() {
		p.mu.Lock()
		if p.owners[binding.Owner.InstanceID] == l {
			delete(p.owners, binding.Owner.InstanceID)
		}
		p.mu.Unlock()
	}
	configurationAdmission, cancelConfiguration := context.WithTimeout(ctx, contextCallBudget)
	var configurationLease ContextConfigurationLease
	var configurationErr error
	var initial *nativeConfigurationInitialRead
	native, nativeOpening := p.ports.Configuration.(*NativeConfigurationOwner)
	if nativeOpening {
		configurationLease, initial, configurationErr = native.openForContext(configurationAdmission, cloneContextBinding(binding), admission)
		if configurationErr == nil && initial == nil {
			configurationErr = pluginError("context_configuration_unavailable")
		}
	} else {
		configurationLease, configurationErr = p.ports.Configuration.Open(configurationAdmission, cloneContextBinding(binding))
	}
	if !nilContextDependency(configurationLease) {
		l.configurationLease = configurationLease
		l.configurationDone = configurationLease.Done()
		if terminal, ok := configurationLease.(contextConfigurationUnavailable); ok {
			l.configurationDone = terminal.unavailableDone()
			if l.configurationDone == nil {
				configurationErr = pluginError("context_configuration_unavailable")
			}
		}
		if configurationErr == nil {
			l.configuration, configurationErr = newContextConfigurationWithInitial(configurationAdmission, binding, admission, configurationLease, initial)
		}
	} else {
		configurationErr = pluginError("context_configuration_unavailable")
	}
	if configurationAdmission.Err() != nil {
		configurationErr = pluginError("context_configuration_unavailable")
	}
	cancelConfiguration()
	l.start()
	if configurationErr != nil || err != nil || ctx.Err() != nil || completed(binding.LifetimeDone) || completed(binding.ParentLifetime) || completed(binding.Lifecycle.DrainDone()) || completed(connection.Done()) {
		l.Invalidate()
		return l, pluginError("context_transport_unavailable")
	}
	return l, nil
}

type contextNATS struct {
	conn     *nats.Conn
	requests *nats.Subscription
	results  *nats.Subscription
	done     chan struct{}
	once     sync.Once
}

func (c *contextNATS) lost()                 { c.once.Do(func() { close(c.done) }) }
func (c *contextNATS) Done() <-chan struct{} { return c.done }
func (c *contextNATS) Close() {
	if c.conn != nil {
		c.conn.Close()
	} else {
		c.lost()
	}
}
func (c *contextNATS) Publish(ctx context.Context, subject string, raw []byte) error {
	if ctx == nil || ctx.Err() != nil || c.conn == nil || completed(c.done) || len(raw) > contextWireLimit ||
		c.conn.Publish(subject, raw) != nil || c.conn.FlushWithContext(ctx) != nil {
		return pluginError("context_transport_unavailable")
	}
	return nil
}
func (c *contextNATS) Receive(ctx context.Context, result bool) ([]byte, error) {
	sub := c.requests
	if result {
		sub = c.results
	}
	if sub == nil {
		return nil, pluginError("context_transport_unavailable")
	}
	message, err := sub.NextMsgWithContext(ctx)
	if err != nil || len(message.Data) > contextWireLimit {
		return nil, pluginError("context_transport_unavailable")
	}
	// Fixed reply subjects are part of the admitted credential profile. Ignore
	// caller-selected NATS reply subjects and headers entirely.
	return bytes.Clone(message.Data), nil
}
func (p *contextProvider) connectNATS(ctx context.Context, transport ContextTransport) (contextConnection, error) {
	if ctx.Err() != nil {
		return nil, pluginError("context_transport_unavailable")
	}
	budget := 2 * time.Second
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < budget {
		budget = time.Until(deadline)
	}
	if budget <= 0 {
		return nil, pluginError("context_transport_unavailable")
	}
	c := &contextNATS{done: make(chan struct{})}
	var err error
	c.conn, err = nats.Connect(p.options.ServerURL, nats.UserJWTAndSeed(p.server.jwt, p.server.seed),
		nats.Secure(p.tls.Clone()), nats.NoReconnect(), nats.IgnoreDiscoveredServers(), nats.Timeout(budget), nats.FlusherTimeout(100*time.Millisecond),
		nats.ClosedHandler(func(*nats.Conn) { c.lost() }), nats.ErrorHandler(func(*nats.Conn, *nats.Subscription, error) { c.lost() }))
	if err != nil {
		c.lost()
		return c, pluginError("context_transport_unavailable")
	}
	c.requests, err = c.conn.SubscribeSync(transport.RequestSubject)
	if err == nil {
		c.results, err = c.conn.SubscribeSync(transport.ResultSubject)
	}
	if err == nil {
		err = c.requests.SetPendingLimits(contextServiceLimit, 4*contextWireLimit)
	}
	if err == nil {
		err = c.results.SetPendingLimits(contextOperationLimit, 4*contextWireLimit)
	}
	if err == nil {
		flush, cancel := context.WithTimeout(ctx, budget)
		err = c.conn.FlushWithContext(flush)
		cancel()
	}
	if err != nil {
		return c, pluginError("context_transport_unavailable")
	}
	return c, nil
}

func contextDescriptor(hub string, binding ContextBinding, admission ContextInstanceAdmission, now time.Time) ([]byte, map[string]string, time.Time, error) {
	fail := func() ([]byte, map[string]string, time.Time, error) {
		return nil, nil, time.Time{}, pluginError("context_admission_invalid")
	}
	if !validProfileContext(binding.ProfileContext) {
		return fail()
	}
	if !contextReferenceValid(admission.ScopeRef) || admission.ConfigurationRevision > maxGeneration || len(admission.SecretReferences) > 64 || len(admission.DomainBindings) > 64 || now.IsZero() {
		return fail()
	}
	for _, reference := range admission.SecretReferences {
		if !contextReferenceValid(reference) {
			return fail()
		}
	}
	seen := map[string]bool{}
	for _, domain := range admission.DomainBindings {
		if !registryIdentifier.MatchString(domain.ID) || !registryIdentifier.MatchString(domain.ContractID) || seen[domain.ID] {
			return fail()
		}
		seen[domain.ID] = true
		declared := false
		for _, capability := range binding.Package.Manifest().RequestedCapabilities {
			if capability.Action == domain.Action && capability.ResourceClass == domain.ResourceClass {
				declared = true
				break
			}
		}
		if !declared {
			return fail()
		}
	}
	var grant struct {
		SubjectInstanceID string            `json:"subjectInstanceId"`
		IssuedAt          string            `json:"issuedAt"`
		ExpiresAt         string            `json:"expiresAt"`
		ParentGrantRef    *ContextReference `json:"parentGrantRef"`
	}
	if strictDocument(admission.EffectiveGrant) != nil || json.Unmarshal(admission.EffectiveGrant, &grant) != nil || grant.SubjectInstanceID != binding.Owner.InstanceID {
		return fail()
	}
	issued, e1 := time.Parse(time.RFC3339Nano, grant.IssuedAt)
	expiry, e2 := time.Parse(time.RFC3339Nano, grant.ExpiresAt)
	if e1 != nil || e2 != nil || issued.After(now) || !now.Before(expiry) || !issued.Before(expiry) || (binding.Parent != nil && grant.ParentGrantRef == nil) {
		return fail()
	}
	var parent any
	if binding.Parent != nil {
		parent = map[string]any{"instanceId": binding.Parent.InstanceID, "relationship": "private"}
	}
	services := map[string]any{}
	handles := map[string]string{}
	for _, name := range []string{"logger", "config", "lifecycle", "clock", "tracing", "metrics", "domainGateway"} {
		nonce, err := randomControlID()
		if err != nil {
			return nil, nil, time.Time{}, err
		}
		handle := "service_" + nonce
		handles[name] = handle
		interfaceID := "plugin-" + name
		if name == "domainGateway" {
			interfaceID = "plugin-domain-gateway"
		}
		services[name] = map[string]any{"interfaceId": interfaceID, "apiMajor": 1, "scopeRef": admission.ScopeRef, "handleId": handle, "transport": "nats"}
	}
	document := map[string]any{"schemaVersion": "1.0.0", "instanceId": binding.Owner.InstanceID,
		"packageId": binding.Owner.Pin.PackageID, "packageVersion": binding.Owner.Pin.Version, "packageDigest": binding.Owner.Pin.PackageChecksum,
		"hubId": hub, "parent": parent, "effectiveGrant": json.RawMessage(admission.EffectiveGrant), "services": services,
		"secretReferences": admission.SecretReferences, "configurationRevision": admission.ConfigurationRevision}
	if binding.ProfileContext != nil {
		document["profileContext"] = cloneProfileContext(binding.ProfileContext)
	}
	descriptor := contextJSON(document)
	if validateContextJSON("plugin-context", descriptor) != nil {
		return fail()
	}
	return descriptor, handles, expiry, nil
}
