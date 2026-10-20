package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"
)

// ContextProvider binds services to an original process owner. Its authority and
// service owners are trusted host dependencies, never values supplied by a child.
type ContextProvider interface {
	Open(context.Context, ContextBinding) (ContextLease, error)
}

type ContextBinding struct {
	// ProfileContext is host-supplied display metadata, separate from authority.
	ProfileContext            *ProfileContext
	Owner                     OwnerReference
	Parent                    *OwnerReference
	Package                   AdmittedPackage
	Configuration             ValidatedConfiguration
	LifetimeDone              <-chan struct{}
	ParentLifetime            <-chan struct{}
	Lifecycle                 ContextLifecycleSource
	ConfigurationEventSources []NativeConfigurationEventSource
}

// Done closes when authority is lost. Close separately joins all owned work;
// callers must retain a lease whose Close has not completed successfully.
type ContextLease interface {
	Owner() OwnerReference
	Descriptor() []byte
	Bootstrap() ContextBootstrap
	Dispatch(context.Context, []byte) ([]byte, error)
	Done() <-chan struct{}
	Invalidate()
	Close(context.Context) error
}

type ContextReference struct {
	ID         string `json:"id"`
	OwnerHubID string `json:"ownerHubId"`
	Revision   uint64 `json:"revision"`
}

// The authority owner supplies a real current grant. These values are not an
// enrollment mechanism, and a valid JSON object does not establish authority.
type ContextInstanceAdmission struct {
	EffectiveGrant        []byte
	ScopeRef              ContextReference
	ConfigurationRevision uint64
	SecretReferences      []ContextReference
	DomainBindings        []ContextDomainBinding
}

type ContextDomainBinding struct {
	ID            string
	ContractID    string
	Action        string
	ResourceClass string
}

type ContextOperationAdmission struct {
	Operation    []byte
	AuthorityRef ContextReference
	// Retained by the native authority consumer for fresh remote verification.
	// It is never exposed through a child descriptor or diagnostic record.
	originalEnvelope []byte
}

type ContextDomainCall struct {
	RequestID  string
	BindingID  string
	ContractID string
	Payload    []byte
}

// The authority owner signs the actual downstream payload and selects a
// registered destination. A changed payload cannot reuse an earlier signature.
type ContextApprovedEnvelope struct {
	BindingID    string
	Envelope     []byte
	delivery     *nativeCapabilityDelivery
	subscription *nativeSubscriptionApproval
}

// Clone preserves private authority preparation while copying disclosed bytes.
func (a ContextApprovedEnvelope) Clone() ContextApprovedEnvelope {
	a.Envelope = bytes.Clone(a.Envelope)
	if a.delivery != nil {
		d := *a.delivery
		d.operation = cloneOperationAdmission(d.operation)
		d.serviceRequest = bytes.Clone(d.serviceRequest)
		a.delivery = &d
	}
	if a.subscription != nil {
		s := *a.subscription
		s.operation = cloneOperationAdmission(s.operation)
		a.subscription = &s
	}
	return a
}

// Implementations authenticate enrolled callers, verify signed payloads and
// resolve current grants. JSON shape checks in the context layer do none of
// those things. Downstream admission must resolve the effective actor and
// delegation, preserve causation, and keep deadlines within the original call.
// Each method must honor its context; unfinished calls keep their lease owned.
type ContextAuthority interface {
	BindInstance(context.Context, ContextBinding) (ContextInstanceAdmission, error)
	AdmitOperation(context.Context, OwnerReference, []byte) (ContextOperationAdmission, error)
	Recheck(context.Context, OwnerReference, ContextInstanceAdmission, *ContextOperationAdmission) error
	PrepareDomainCall(context.Context, OwnerReference, ContextOperationAdmission, ContextDomainCall) (ContextApprovedEnvelope, error)
}

// Diagnostic records contain server-assigned identity and declared codes only.
// Configuration, payloads, credentials and arbitrary child text are excluded.
type ContextTags struct {
	Owner                    OwnerReference    `json:"owner"`
	HubID                    string            `json:"hubId"`
	OperationID              string            `json:"operationId,omitempty"`
	PrincipalID              string            `json:"principalId,omitempty"`
	CallerKind               string            `json:"callerKind,omitempty"`
	AuthenticatedIdentityRef *ContextReference `json:"authenticatedIdentityRef,omitempty"`
	EffectiveActorRef        *ContextReference `json:"effectiveActorRef,omitempty"`
	DelegationRef            *ContextReference `json:"delegationRef,omitempty"`
	OrganizationID           string            `json:"organizationId,omitempty"`
	ProjectID                *string           `json:"projectId,omitempty"`
	WorkspaceID              *string           `json:"workspaceId,omitempty"`
	TraceID                  string            `json:"traceId,omitempty"`
	CausationID              string            `json:"causationId,omitempty"`
}

type ContextLogRecord struct {
	Tags      ContextTags
	EventCode string
}

type ContextTraceRecord struct {
	Tags        ContextTags
	SpanHandle  string
	SpanCode    string
	Action      string
	OutcomeCode string
}

type ContextMetricRecord struct {
	Tags       ContextTags
	MetricCode string
	Value      float64
}

// Every port must be present. In particular, absence of an authority or an
// observability owner cannot be turned into successful service readiness.
type ContextPorts struct {
	Authority             ContextAuthority
	Log                   func(context.Context, ContextLogRecord) error
	Trace                 func(context.Context, ContextTraceRecord) error
	Metric                func(context.Context, ContextMetricRecord) error
	Domain                func(context.Context, ContextApprovedEnvelope) ([]byte, error)
	Subscribe             func(context.Context, ContextApprovedEnvelope) (ContextSubscriptionLease, error)
	SubscriptionAuthority ContextSubscriptionAuthority
	Configuration         ContextConfigurationOwner
	Now                   func() time.Time
	EventCodes            []string
	SpanCodes             []string
	MetricCodes           []string
}

type ContextTransport struct {
	SchemaVersion         string `json:"schemaVersion"`
	ServerURL             string `json:"serverURL"`
	RequestSubject        string `json:"requestSubject"`
	ReplySubject          string `json:"replySubject"`
	InvokeSubject         string `json:"invokeSubject"`
	ResultSubject         string `json:"resultSubject"`
	CancelSubject         string `json:"cancelSubject"`
	ServerName            string `json:"serverName,omitempty"`
	LeafCertificateSHA256 string `json:"leafCertificateSha256,omitempty"`
}

// ContextBootstrap is an explicit private disclosure to the staging owner.
// Generic formatting and JSON serialization reveal none of its private bytes.
type ContextBootstrap struct {
	descriptor, credentials, ca []byte
	transport                   ContextTransport
}

func (b ContextBootstrap) Descriptor() []byte          { return bytes.Clone(b.descriptor) }
func (b ContextBootstrap) Credentials() []byte         { return bytes.Clone(b.credentials) }
func (b ContextBootstrap) CA() []byte                  { return bytes.Clone(b.ca) }
func (b ContextBootstrap) Transport() ContextTransport { return b.transport }
func (ContextBootstrap) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private plugin context bootstrap]")
}
func (ContextBootstrap) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-plugin-context-bootstrap"}`), nil
}

func (ContextBinding) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[plugin context binding]")
}
func (ContextBinding) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"plugin-context-binding"}`), nil
}
func (ContextInstanceAdmission) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[plugin instance admission]")
}
func (ContextInstanceAdmission) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"plugin-instance-admission"}`), nil
}
func (ContextOperationAdmission) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[plugin operation admission]")
}
func (ContextOperationAdmission) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"plugin-operation-admission"}`), nil
}
func (ContextDomainCall) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[plugin domain call]")
}
func (ContextDomainCall) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"plugin-domain-call"}`), nil
}
func (ContextApprovedEnvelope) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[approved plugin domain envelope]")
}
func (ContextApprovedEnvelope) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"approved-plugin-domain-envelope"}`), nil
}

const contextWireLimit = 1 << 20
const contextServiceLimit = 64
const contextOperationLimit = 64
const contextSpanLimit = 64
const contextCallBudget = 5 * time.Second

type contextConnection interface {
	Publish(context.Context, string, []byte) error
	Receive(context.Context, bool) ([]byte, error)
	Close()
	Done() <-chan struct{}
}

type contextLease struct {
	binding    ContextBinding
	ports      ContextPorts
	admission  ContextInstanceAdmission
	bootstrap  ContextBootstrap
	grantUntil time.Time
	// elapsedOrigin retains the process monotonic reading; wall-clock ports never set it.
	elapsedOrigin      time.Time
	handles            map[string]string
	transport          contextConnection
	ctx                context.Context
	cancel             context.CancelFunc
	done               chan struct{}
	joined             chan struct{}
	once               sync.Once
	workers            sync.WaitGroup
	serviceRun         chan struct{}
	resultRun          chan struct{}
	monitorRun         chan struct{}
	permits            chan struct{}
	admissions         chan struct{}
	mu                 sync.Mutex
	operations         map[string]*contextOperation
	subscriptions      map[string]*contextSubscription
	configuration      *contextConfiguration
	configurationLease ContextConfigurationLease
	configurationDone  <-chan struct{}
	workJoined         chan struct{}
	cleanupRun         chan struct{}
	cleanupError       error
	requests           map[string]bool
	closing            bool
	failure            error
	onJoined           func()
}

func (*contextLease) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[owned plugin context lease]")
}
func (*contextLease) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"owned-plugin-context-lease"}`), nil
}
func (l *contextLease) Owner() OwnerReference { return l.binding.Owner }
func (l *contextLease) Descriptor() []byte    { return l.bootstrap.Descriptor() }
func (l *contextLease) Bootstrap() ContextBootstrap {
	return ContextBootstrap{l.bootstrap.Descriptor(), l.bootstrap.Credentials(), l.bootstrap.CA(), l.bootstrap.Transport()}
}
func (l *contextLease) Done() <-chan struct{} { return l.done }

func (l *contextLease) Invalidate() {
	l.once.Do(func() {
		l.mu.Lock()
		l.closing = true
		l.mu.Unlock()
		close(l.done)
		l.cancel()
	})
}

func (l *contextLease) Close(ctx context.Context) error {
	if ctx == nil {
		return pluginError("context_close_invalid")
	}
	l.Invalidate()
	if l.closeOwnedSubscriptions(ctx) != nil {
		return pluginError("context_cleanup_incomplete")
	}
	select {
	case <-l.workJoined:
	case <-ctx.Done():
		return pluginError("context_cleanup_incomplete")
	}
	l.mu.Lock()
	if completed(l.joined) {
		err := l.failure
		l.mu.Unlock()
		return err
	}
	if l.cleanupRun == nil || completed(l.cleanupRun) {
		l.cleanupRun = make(chan struct{})
		run := l.cleanupRun
		go func() {
			var err error
			if l.configurationLease != nil {
				err = l.configurationLease.Close(ctx)
				if err == nil && !completed(l.configurationLease.Done()) {
					err = pluginError("context_cleanup_incomplete")
				}
			}
			l.mu.Lock()
			l.cleanupError = err
			if err == nil {
				if l.onJoined != nil {
					l.onJoined()
				}
				close(l.joined)
			}
			close(run)
			l.mu.Unlock()
		}()
	}
	run := l.cleanupRun
	l.mu.Unlock()
	select {
	case <-run:
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.cleanupError != nil {
			return pluginError("context_cleanup_incomplete")
		}
		return l.failure
	case <-ctx.Done():
		return pluginError("context_cleanup_incomplete")
	}
}

func (l *contextLease) rememberFailure() {
	l.mu.Lock()
	if l.failure == nil {
		l.failure = pluginError("context_resource_cleanup_failed")
	}
	l.mu.Unlock()
}

func cloneContextBinding(b ContextBinding) ContextBinding {
	b.Parent = copyParent(b.Parent)
	b.ProfileContext = cloneProfileContext(b.ProfileContext)
	b.ConfigurationEventSources = append([]NativeConfigurationEventSource(nil), b.ConfigurationEventSources...)
	return b
}
func cloneInstanceAdmission(a ContextInstanceAdmission) ContextInstanceAdmission {
	a.EffectiveGrant = bytes.Clone(a.EffectiveGrant)
	a.SecretReferences = append([]ContextReference{}, a.SecretReferences...)
	a.DomainBindings = append([]ContextDomainBinding{}, a.DomainBindings...)
	return a
}
func cloneOperationAdmission(a ContextOperationAdmission) ContextOperationAdmission {
	a.Operation = bytes.Clone(a.Operation)
	a.originalEnvelope = bytes.Clone(a.originalEnvelope)
	return a
}
func contextOwnerValid(owner OwnerReference) bool {
	return configurationPin(owner.Pin) && registryIdentifier.MatchString(owner.InstanceID) &&
		registryEpoch.MatchString(owner.Epoch) && owner.Generation > 0 && owner.Generation <= maxGeneration
}
func contextReferenceValid(ref ContextReference) bool {
	return registryIdentifier.MatchString(ref.ID) && registryIdentifier.MatchString(ref.OwnerHubID) && ref.Revision <= maxGeneration
}
func contextCodesValid(codes []string) bool {
	if len(codes) == 0 || len(codes) > 256 {
		return false
	}
	seen := map[string]bool{}
	for _, code := range codes {
		if !registryIdentifier.MatchString(code) || seen[code] {
			return false
		}
		seen[code] = true
	}
	return true
}
func contextPortsValid(p ContextPorts) bool {
	if p.Authority == nil {
		return false
	}
	v := reflect.ValueOf(p.Authority)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan:
		if v.IsNil() {
			return false
		}
	}
	return p.Log != nil && p.Trace != nil && p.Metric != nil && p.Domain != nil && p.Subscribe != nil && !nilContextDependency(p.SubscriptionAuthority) && !nilContextDependency(p.Configuration) && p.Now != nil &&
		contextCodesValid(p.EventCodes) && contextCodesValid(p.SpanCodes) && contextCodesValid(p.MetricCodes)
}
func contextJSON(value any) []byte {
	raw, _ := json.Marshal(value)
	return raw
}
