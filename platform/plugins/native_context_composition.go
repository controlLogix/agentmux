package plugins

import (
	"context"
	"errors"
	"fmt"
	"github.com/controlLogix/agentmux/platform/localtls"
	"io"
	"reflect"
	"sync"
	"time"
)

// NativeContextProfile comes from the retained registered host, not composition
// JSON. InstanceID identifies the host; plugin owners keep their own instance IDs.
type NativeContextProfile struct {
	ProfileID, InstanceID, HubID string
	Context                      *ProfileContext
}

func (NativeContextProfile) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "[private native context profile]")
}
func (NativeContextProfile) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-native-context-profile"}`), nil
}

// NativeContextProfileOwner remains borrowed until composition Close succeeds.
// Each read must recheck the original registration and host-policy admissions.
type NativeContextProfileOwner interface {
	NativeContextProfile(context.Context) (NativeContextProfile, error)
}

type NativeContextServiceRoute struct {
	BindingID, RequestContractID, ReplyContractID string
	Service                                       NativeCapabilityServiceBinding
	Transport                                     NativeAuthorityNATSOptions
}

type NativeContextConfigurationInput struct {
	Binding   NativeConfigurationBinding
	Transport NativeAuthorityNATSOptions
}

type NativeContextSubscriptionInput struct {
	BindingID string
	Source    NativeConfigurationEventSource
	Service   NativeConfigurationServiceBinding
	Transport NativeAuthorityNATSOptions
}

// NativeContextCompositionOptions are trusted host inputs. Enrolled keys and
// transports are always constructed here; callers cannot substitute authority.
// Ports supplies the real subscription owner and event authority. This owner
// supplies authority, configuration, capability delivery, observability and time;
// callers cannot replace those ports with callbacks.
type NativeContextCompositionOptions struct {
	Driver                 NativeDriverOptions
	ContextTransport       NATSContextOptions
	ContextTrust           *localtls.ClientTrust
	LifecycleTrust         *localtls.ClientTrust
	Enrollment             NativeEnrolledKeyOptions
	Authority              NativeAuthorityClientOptions
	AuthorityTransport     NativeAuthorityNATSOptions
	Destinations           map[string]string
	ActivationDeclarations map[string]NativeActivationDeclaration
	Observability          *NativeObservability
	Services               []NativeContextServiceRoute
	Configurations         map[string]NativeContextConfigurationInput
	Subscriptions          []NativeContextSubscriptionInput
	Ports                  ContextPorts
}

func (NativeContextCompositionOptions) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "[private native context composition options]")
}
func (NativeContextCompositionOptions) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-native-context-composition-options"}`), nil
}

type nativeContextCompositionFailure struct {
	cause error
	owner *NativeContextComposition
}

func (*nativeContextCompositionFailure) Error() string {
	return "native_context_composition_unavailable"
}
func (e *nativeContextCompositionFailure) Format(s fmt.State, _ rune) { io.WriteString(s, e.Error()) }
func (e *nativeContextCompositionFailure) MarshalJSON() ([]byte, error) {
	return []byte(`"native_context_composition_unavailable"`), nil
}
func (e *nativeContextCompositionFailure) Unwrap() error { return e.cause }

// NativeContextComposition owns the actual driver, signed authority, capability
// gateway and original transports. Construction does not activate plugins or
// establish business readiness. An error with an owner requires explicit Close.
type NativeContextComposition struct {
	mu                                           sync.Mutex
	profileOwner                                 NativeContextProfileOwner
	profile                                      NativeContextProfile
	authorityTransport                           *NativeAuthorityNATSExchange
	serviceTransports                            []*NativeAuthorityNATSExchange
	authority                                    *NativeContextAuthority
	gateway                                      *NativeCapabilityGateway
	configurationOwner                           *NativeConfigurationOwner
	configurationTransports                      []*NativeAuthorityNATSExchange
	subscriptionOwner                            *NativeConfigurationSubscriptions
	subscriptionTransports                       []*NativeAuthorityNATSExchange
	observability                                *NativeObservability
	observabilityJoined                          bool
	contextProvider                              *PinnedNATSContextProvider
	lifetime                                     context.Context
	cancel                                       context.CancelFunc
	driver                                       *NativeDriver
	ready, closing, closed                       bool
	driverJoined, gatewayJoined, authorityClosed bool
	serviceClosed                                map[*NativeAuthorityNATSExchange]bool
	closeFailure                                 error
	failure                                      error
}

func (*NativeContextComposition) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "[private native context composition]")
}
func (*NativeContextComposition) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-native-context-composition"}`), nil
}

func nativeContextCompositionValid(profile NativeContextProfile, o NativeContextCompositionOptions) bool {
	if o.ContextTrust == nil || o.LifecycleTrust == nil {
		return false
	}
	if !registryIdentifier.MatchString(profile.ProfileID) || !registryIdentifier.MatchString(profile.InstanceID) || !registryIdentifier.MatchString(profile.HubID) || profile.Context == nil || !validProfileContext(profile.Context) {
		return false
	}
	if o.Enrollment.ProfileID != profile.ProfileID || o.Enrollment.HubID != profile.HubID || o.Driver.HubID != profile.HubID || o.ContextTransport.HubID != profile.HubID || o.Authority.ProfileID != profile.ProfileID || o.Authority.HubID != profile.HubID || o.Authority.AuthorityID != o.Enrollment.AuthorityID || o.Authority.RequestSigningRef != o.Enrollment.HostTransportRef || o.Authority.ResponseSigningRef != o.Enrollment.IssuerRef || o.Authority.ReplyPrefix != o.AuthorityTransport.ReplyPrefix {
		return false
	}
	if o.Driver.LifecycleTrust != nil || o.Driver.ProfileContext != nil || !nilContextDependency(o.Authority.Keys) || !nilContextDependency(o.Authority.Exchange) || !nilContextDependency(o.Ports.Authority) || !nilContextDependency(o.Ports.Configuration) || o.Ports.Domain != nil || o.Ports.Now != nil {
		return false
	}
	p := o.Ports
	if o.Observability == nil || p.Log != nil || p.Trace != nil || p.Metric != nil || len(p.EventCodes) != 0 || len(p.SpanCodes) != 0 || len(p.MetricCodes) != 0 || p.Subscribe != nil || !nilContextDependency(p.SubscriptionAuthority) || len(o.Subscriptions) == 0 || len(o.Subscriptions) > 64 {
		return false
	}
	o.Observability.mu.Lock()
	validObservability := !o.Observability.closing && o.Observability.failure == nil && o.Observability.options.HubID == profile.HubID && len(o.Observability.options.Bindings) == len(o.Driver.Bindings)
	for _, binding := range o.Driver.Bindings {
		validObservability = validObservability && o.Observability.options.Bindings[binding.InstanceID] == binding.Pin
	}
	o.Observability.mu.Unlock()
	if !validObservability {
		return false
	}
	if len(o.Driver.Bindings) == 0 || len(o.Driver.Bindings) > 64 || len(o.ActivationDeclarations) != len(o.Driver.Bindings) || len(o.Configurations) != len(o.Driver.Bindings) || len(o.Destinations) != len(o.Driver.Bindings) || len(o.ContextTransport.Bindings) != len(o.Driver.Bindings) || len(o.Services) == 0 || len(o.Services) > 64 {
		return false
	}
	bindings := map[string]bool{}
	for _, binding := range o.Driver.Bindings {
		if !registryIdentifier.MatchString(binding.InstanceID) || bindings[binding.InstanceID] || !registryIdentifier.MatchString(o.Destinations[binding.InstanceID]) {
			return false
		}
		if _, ok := o.Configurations[binding.InstanceID]; !ok {
			return false
		}
		declaration, ok := o.ActivationDeclarations[binding.InstanceID]
		if !ok || declaration.Pin != binding.Pin || declaration.ManifestDigest != binding.Pin.ManifestChecksum || !contextReferenceValid(declaration.RecordRef) || !contextReferenceValid(declaration.IdentityRef) || declaration.RecordRef.OwnerHubID != profile.HubID || declaration.IdentityRef.OwnerHubID != profile.HubID || nativeAuthoritySchema("facts", declaration.Facts) != nil {
			return false
		}
		bindings[binding.InstanceID] = true
	}
	contextBindings := map[string]bool{}
	for _, binding := range o.ContextTransport.Bindings {
		if !bindings[binding.InstanceID] || contextBindings[binding.InstanceID] {
			return false
		}
		contextBindings[binding.InstanceID] = true
	}
	for _, service := range o.Services {
		if service.Transport.ReplyPrefix != o.Authority.ReplyPrefix {
			return false
		}
	}
	for _, configuration := range o.Configurations {
		if configuration.Transport.ReplyPrefix != o.Authority.ReplyPrefix {
			return false
		}
	}

	for _, subscription := range o.Subscriptions {
		if subscription.Transport.ReplyPrefix != o.Authority.ReplyPrefix || subscription.Service.ProfileID != profile.ProfileID || subscription.Service.HubID != profile.HubID || subscription.Source.ConfigurationRef.OwnerHubID != profile.HubID || !registryIdentifier.MatchString(subscription.BindingID) || nativeAuthoritySchema("configuration-event-source", contextJSON(subscription.Source)) != nil {
			return false
		}
	}
	return true
}

func NewNativeContextComposition(ctx context.Context, profileOwner NativeContextProfileOwner, options NativeContextCompositionOptions) (*NativeContextComposition, error) {
	if ctx == nil || ctx.Err() != nil || nilContextDependency(profileOwner) {
		return nil, pluginError("context_host_binding_invalid")
	}
	profile, err := profileOwner.NativeContextProfile(ctx)
	if err != nil {
		return nil, &nativeContextCompositionFailure{cause: err}
	}
	if !nativeContextCompositionValid(profile, options) {
		return nil, pluginError("context_host_binding_invalid")
	}
	profile.Context = cloneProfileContext(profile.Context)
	lifetime, cancel := context.WithCancel(context.Background())
	r := &NativeContextComposition{profileOwner: profileOwner, profile: profile, serviceClosed: map[*NativeAuthorityNATSExchange]bool{}, lifetime: lifetime, cancel: cancel, observability: options.Observability}
	fail := func(err error) (*NativeContextComposition, error) {
		r.failure = err
		return r, &nativeContextCompositionFailure{cause: err, owner: r}
	}
	authorityTransportOptions := options.AuthorityTransport
	authorityTransportOptions.Lifetime = r.lifetime
	r.authorityTransport, err = NewNativeAuthorityNATSExchange(ctx, authorityTransportOptions)
	if err != nil {
		return fail(err)
	}
	keys, err := NewNativeEnrolledKeys(r.authorityTransport, options.Enrollment)
	if err != nil {
		return fail(err)
	}
	authorityOptions := options.Authority
	authorityOptions.Keys = keys
	authorityOptions.Exchange = r.authorityTransport
	r.authority, err = NewNativeContextAuthority(authorityOptions, options.Destinations)
	if err != nil {
		return fail(err)
	}
	routes := make([]NativeCapabilityRoute, 0, len(options.Services))
	for _, route := range options.Services {
		transportOptions := route.Transport
		transportOptions.Lifetime = r.lifetime
		transport, err := NewNativeAuthorityNATSExchange(ctx, transportOptions)
		if transport != nil {
			r.serviceTransports = append(r.serviceTransports, transport)
		}
		if err != nil {
			return fail(err)
		}
		routes = append(routes, NativeCapabilityRoute{BindingID: route.BindingID, RequestContractID: route.RequestContractID, ReplyContractID: route.ReplyContractID, Service: route.Service, Keys: keys, Exchange: transport})
	}
	r.gateway, err = NewNativeCapabilityGateway(r.authority, routes)
	if err != nil {
		return fail(err)
	}
	configurationBindings := map[string]NativeConfigurationClientBinding{}
	for instance, input := range options.Configurations {
		transportOptions := input.Transport
		transportOptions.Lifetime = r.lifetime
		transport, err := NewNativeAuthorityNATSExchange(ctx, transportOptions)
		if transport != nil {
			r.configurationTransports = append(r.configurationTransports, transport)
		}
		if err != nil {
			return fail(err)
		}
		configurationBindings[instance] = NativeConfigurationClientBinding{Binding: input.Binding, Exchange: transport, ReplyPrefix: input.Transport.ReplyPrefix}
	}
	r.configurationOwner, err = NewNativeConfigurationOwner(r.authority, keys, configurationBindings)
	if err != nil {
		return fail(err)
	}

	subscriptionRoutes := make([]NativeConfigurationSubscriptionRoute, 0, len(options.Subscriptions))
	for _, input := range options.Subscriptions {
		transportOptions := input.Transport
		transportOptions.Lifetime = r.lifetime
		transport, openErr := NewNativeAuthorityNATSExchange(ctx, transportOptions)
		if transport != nil {
			r.subscriptionTransports = append(r.subscriptionTransports, transport)
		}
		if openErr != nil {
			return fail(openErr)
		}
		subscriptionRoutes = append(subscriptionRoutes, NativeConfigurationSubscriptionRoute{BindingID: input.BindingID, Source: input.Source, Service: input.Service, Exchange: transport})
	}
	r.subscriptionOwner, err = NewNativeConfigurationSubscriptions(r.authority, keys, subscriptionRoutes)
	if err != nil {
		return fail(err)
	}

	ports := options.Ports
	ports.Log, ports.Trace, ports.Metric = r.observability.Log, r.observability.Trace, r.observability.Metric
	ports.EventCodes = append([]string(nil), r.observability.options.EventCodes...)
	ports.SpanCodes = append([]string(nil), r.observability.options.SpanCodes...)
	ports.MetricCodes = append([]string(nil), r.observability.options.MetricCodes...)
	ports.Authority = r.authority
	ports.SubscriptionAuthority = r.authority
	ports.Subscribe = r.subscriptionOwner.Subscribe
	ports.Configuration = r.configurationOwner
	ports.Domain = r.gateway.Domain
	ports.Now = time.Now
	r.contextProvider, err = NewPinnedNATSContextProvider(ctx, options.ContextTransport, options.ContextTrust, ports)
	if err != nil {
		return fail(err)
	}
	driverOptions := options.Driver
	driverOptions.ProfileContext = cloneProfileContext(profile.Context)
	driverOptions.LifecycleTrust = options.LifecycleTrust
	declarations := make(map[string]NativeActivationDeclaration, len(options.ActivationDeclarations))
	for instance, declaration := range options.ActivationDeclarations {
		declarations[instance] = cloneNativeActivationDeclaration(declaration)
	}
	r.driver, err = NewNativeDriverWithContext(ctx, driverOptions, &nativeRegisteredContextProvider{profileOwner: profileOwner, profile: profile, provider: r.contextProvider, authority: r.authority, activationKeys: keys, configurationOwner: r.configurationOwner, configurations: configurationBindings, declarations: declarations, activating: map[string]bool{}, activationFailed: map[string]bool{}})
	if err != nil {
		return fail(err)
	}
	current, err := profileOwner.NativeContextProfile(ctx)
	if err != nil {
		return fail(err)
	}
	if !reflect.DeepEqual(current, profile) || ctx.Err() != nil {
		return fail(pluginError("context_host_binding_changed"))
	}
	r.ready = true
	return r, nil
}

type nativeRegisteredContextProvider struct {
	activationMu                 sync.Mutex
	profileOwner                 NativeContextProfileOwner
	profile                      NativeContextProfile
	provider                     ContextProvider
	authority                    *NativeContextAuthority
	activationKeys               nativeActivationKeySource
	configurationOwner           *NativeConfigurationOwner
	configurations               map[string]NativeConfigurationClientBinding
	declarations                 map[string]NativeActivationDeclaration
	activating, activationFailed map[string]bool
}

func (p *nativeRegisteredContextProvider) Open(ctx context.Context, binding ContextBinding) (ContextLease, error) {
	current, err := p.profileOwner.NativeContextProfile(ctx)
	if err != nil {
		return nil, &nativeContextCompositionFailure{cause: err}
	}
	if !reflect.DeepEqual(current, p.profile) || !reflect.DeepEqual(binding.ProfileContext, p.profile.Context) {
		return nil, pluginError("context_host_binding_changed")
	}
	p.activationMu.Lock()
	declaration := p.declarations[binding.Owner.InstanceID]
	binding.ConfigurationEventSources = append([]NativeConfigurationEventSource(nil), declaration.ConfigurationEventSources...)
	p.activationMu.Unlock()
	if err := p.activate(ctx, binding); err != nil {
		return nil, err
	}
	current, err = p.profileOwner.NativeContextProfile(ctx)
	if err != nil {
		return nil, &nativeContextCompositionFailure{cause: err}
	}
	if !reflect.DeepEqual(current, p.profile) {
		return nil, pluginError("context_host_binding_changed")
	}
	return p.provider.Open(ctx, binding)
}

// Driver is borrowed by the existing Manager. The composition remains its owner.
func (r *NativeContextComposition) Driver() (Driver, error) {
	if r == nil {
		return nil, pluginError("context_authority_unavailable")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.ready || r.closing || r.failure != nil {
		return nil, &nativeContextCompositionFailure{cause: r.failure, owner: r}
	}
	return r.driver, nil
}
func (r *NativeContextComposition) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if ctx == nil {
		return &nativeContextCompositionFailure{owner: r}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closing = true
	r.ready = false
	if r.closed {
		return r.closeFailure
	}
	// Join driver contexts and capability calls before their original transports.
	if r.driver != nil && !r.driverJoined {
		if err := r.driver.Close(ctx); err != nil {
			return &nativeContextCompositionFailure{cause: err, owner: r}
		}
		r.driverJoined = true
	}
	if r.gateway != nil && !r.gatewayJoined {
		if err := r.gateway.Close(ctx); err != nil {
			return &nativeContextCompositionFailure{cause: err, owner: r}
		}
		r.gatewayJoined = true
	}
	if r.subscriptionOwner != nil {
		if err := r.subscriptionOwner.Close(ctx); err != nil {
			return &nativeContextCompositionFailure{cause: err, owner: r}
		}
	}
	if r.configurationOwner != nil {
		if err := r.configurationOwner.Close(ctx); err != nil {
			return &nativeContextCompositionFailure{cause: err, owner: r}
		}
	}

	if r.contextProvider != nil {
		if err := r.contextProvider.Close(ctx); err != nil {
			return &nativeContextCompositionFailure{cause: err, owner: r}
		}
	}
	if r.observability != nil && !r.observabilityJoined {
		err := r.observability.Close(ctx)
		r.observability.mu.Lock()
		joined := r.observability.closed && completed(r.observability.done)
		r.observability.mu.Unlock()
		if !joined {
			return &nativeContextCompositionFailure{cause: err, owner: r}
		}
		r.observabilityJoined = true
		if err != nil {
			r.closeFailure = &nativeContextCompositionFailure{cause: err, owner: r}
		}
	}
	if r.cancel != nil {
		r.cancel()
	}
	var failures []error
	transports := append(append(append([]*NativeAuthorityNATSExchange{}, r.serviceTransports...), r.configurationTransports...), r.subscriptionTransports...)
	for i := len(transports) - 1; i >= 0; i-- {
		transport := transports[i]
		if r.serviceClosed[transport] {
			continue
		}
		if err := transport.Close(ctx); err != nil {
			failures = append(failures, err)
		} else {
			r.serviceClosed[transport] = true
		}
	}
	if r.authorityTransport != nil && !r.authorityClosed {
		if err := r.authorityTransport.Close(ctx); err != nil {
			failures = append(failures, err)
		} else {
			r.authorityClosed = true
		}
	}
	if len(failures) > 0 {
		return &nativeContextCompositionFailure{cause: errors.Join(failures...), owner: r}
	}
	if r.authority != nil {
		clear(r.authority.client.private)
	}
	r.closed = true
	if r.failure != nil {
		r.closeFailure = &nativeContextCompositionFailure{cause: errors.Join(r.closeFailure, r.failure), owner: r}
	}
	return r.closeFailure
}

// CleanupComplete reports whether this original composition has joined its
// workers and finished closing its transports. Historical errors remain errors.
func (r *NativeContextComposition) CleanupComplete() bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}
