//go:build linux || darwin

package launcher

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"

	"github.com/controlLogix/agentmux/platform/internal/natscredential"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/plugins"
	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"
)

type NativeContextObservabilitySelection struct {
	Path        string   `json:"path"`
	MaxBytes    int64    `json:"maxBytes"`
	EventCodes  []string `json:"eventCodes"`
	SpanCodes   []string `json:"spanCodes"`
	MetricCodes []string `json:"metricCodes"`
}
type NativeContextHostRequest struct {
	ProfileID       string                              `json:"profileId"`
	RepositoryRoot  string                              `json:"repositoryRoot"`
	SelectionPath   string                              `json:"selectionPath"`
	SelectionSHA256 string                              `json:"selectionSHA256"`
	Observability   NativeContextObservabilitySelection `json:"observability"`
}
type nativeSelectedMaterial struct {
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	UserPublicKey string `json:"userPublicKey,omitempty"`
}
type nativeSelectedBinding struct {
	InstanceID  string                 `json:"instanceId"`
	Pin         plugins.PackagePin     `json:"pin"`
	Credentials nativeSelectedMaterial `json:"credentials"`
	Workspace   *string                `json:"workspace"`
}
type nativeSelectedTransport struct {
	Connection            ApplicationAttestorConnectionSelection `json:"connection"`
	CAFile                nativeSelectedMaterial                 `json:"caFile"`
	AccountPublicKey      string                                 `json:"accountPublicKey"`
	ControllerCredentials nativeSelectedMaterial                 `json:"controllerCredentials"`
	ServerCredentials     nativeSelectedMaterial                 `json:"serverCredentials"`
	StateDirectory        string                                 `json:"stateDirectory"`
	Bindings              []nativeSelectedBinding                `json:"bindings"`
}
type nativeSelectedConfiguration struct {
	ConfigurationRef plugins.ContextReference                  `json:"configurationRef"`
	AuthorityRef     plugins.ContextReference                  `json:"authorityRef"`
	Service          plugins.NativeConfigurationServiceBinding `json:"service"`
	Scope            OwnerScope                                `json:"scope"`
	Resources        []plugins.SchemaResource                  `json:"resources"`
}
type nativeSelectedSubscription struct {
	BindingID string                                    `json:"bindingId"`
	Source    plugins.NativeConfigurationEventSource    `json:"source"`
	Service   plugins.NativeConfigurationServiceBinding `json:"service"`
	Scope     OwnerScope                                `json:"scope"`
}
type nativeSelectedCapability struct {
	BindingID         string                                 `json:"bindingId"`
	RequestContractID string                                 `json:"requestContractId"`
	ReplyContractID   string                                 `json:"replyContractId"`
	Service           plugins.NativeCapabilityServiceBinding `json:"service"`
	Scope             OwnerScope                             `json:"scope"`
}
type nativeHostSelectionDocument struct {
	SchemaVersion string                                 `json:"schemaVersion"`
	HostPolicy    string                                 `json:"hostPolicy"`
	OwnerUID      uint32                                 `json:"ownerUid"`
	Workspaces    []string                               `json:"workspaces"`
	KernelScope   protocol.Scope                         `json:"kernelScope"`
	Connection    ApplicationAttestorConnectionSelection `json:"connection"`
	Credentials   struct {
		nativeSelectedMaterial
		AccountPublicKey string `json:"accountPublicKey"`
		ReplyPrefix      string `json:"replyPrefix"`
	} `json:"credentials"`
	Keys          plugins.NativeEnrolledKeyOptions `json:"keys"`
	RequestSigner struct {
		Ref       plugins.ContextReference `json:"ref"`
		KeyFile   nativeSelectedMaterial   `json:"keyFile"`
		PublicKey string                   `json:"publicKey"`
	} `json:"requestSigner"`
	Destinations           map[string]string                              `json:"destinations"`
	CapabilityRoutes       []nativeSelectedCapability                     `json:"capabilityRoutes"`
	ActivationDeclarations map[string]plugins.NativeActivationDeclaration `json:"activationDeclarations"`
	Lifecycle              *nativeSelectedTransport                       `json:"lifecycle"`
	ContextTransport       *nativeSelectedTransport                       `json:"contextTransport"`
	SubscriptionRoutes     []nativeSelectedSubscription                   `json:"subscriptionRoutes"`
	ConfigurationRoutes    map[string]nativeSelectedConfiguration         `json:"configurationRoutes"`
}

// NativeContextHost owns the central registration, admitted selection files,
// observability descriptor and composition. A constructor error may retain this
// original owner; callers must Close it rather than resolve a replacement.
type NativeContextHost struct {
	mu            sync.Mutex
	resolution    *CentralProfileResolution
	composition   *plugins.NativeContextComposition
	observability *plugins.NativeObservability
	options       plugins.NativeContextCompositionOptions
	failure       error
	closeFailure  error
	closed        bool
}

func (*NativeContextHost) Format(s fmt.State, _ rune) {
	io.WriteString(s, "[private native context host]")
}
func (*NativeContextHost) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-native-context-host"}`), nil
}
func (h *NativeContextHost) NativeContextProfile(ctx context.Context) (plugins.NativeContextProfile, error) {
	h.mu.Lock()
	resolution, closed := h.resolution, h.closed
	h.mu.Unlock()
	if resolution == nil || closed {
		return plugins.NativeContextProfile{}, centralProfileError("native_context_closed")
	}
	return resolution.NativeContextProfile(ctx)
}
func (h *NativeContextHost) Driver() (plugins.Driver, error) {
	h.mu.Lock()
	composition, closed := h.composition, h.closed
	h.mu.Unlock()
	if composition == nil || closed {
		return nil, centralProfileError("native_context_unavailable")
	}
	return composition.Driver()
}
func (h *NativeContextHost) DriverOptions() plugins.NativeDriverOptions {
	h.mu.Lock()
	defer h.mu.Unlock()
	result := h.options.Driver
	result.Bindings = append([]plugins.NativeBinding(nil), result.Bindings...)
	return result
}

// CleanupComplete does not erase a historical cleanup failure.
func (h *NativeContextHost) CleanupComplete() bool {
	if h == nil {
		return true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closed
}
func (h *NativeContextHost) Close(ctx context.Context) error {
	if h == nil {
		return nil
	}
	if ctx == nil {
		return centralProfileError("native_context_cleanup_incomplete")
	}
	h.mu.Lock()
	composition, observability, resolution, closed, previous := h.composition, h.observability, h.resolution, h.closed, h.closeFailure
	h.mu.Unlock()
	if closed {
		return previous
	}
	var failures []error
	if composition != nil {
		err := composition.Close(ctx)
		if !composition.CleanupComplete() {
			return centralProfileErrorWithCause("native_context_cleanup_incomplete", err)
		}
		failures = append(failures, err)
	} else if observability != nil {
		err := observability.Close(ctx)
		if !observability.CleanupComplete() {
			return centralProfileErrorWithCause("native_context_cleanup_incomplete", err)
		}
		failures = append(failures, err)
	}
	if resolution != nil {
		failures = append(failures, resolution.Close())
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	clear(h.options.Authority.RequestSigningSeed)
	h.closed = true
	h.closeFailure = errors.Join(failures...)
	return h.closeFailure
}

func PrepareNativeContextHost(ctx context.Context, request NativeContextHostRequest) (*NativeContextHost, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, centralProfileError("native_context_unavailable")
	}
	h := &NativeContextHost{}
	fail := func(err error) (*NativeContextHost, error) {
		h.failure = err
		return h, centralProfileErrorWithCause("native_context_unavailable", err)
	}
	var err error
	h.resolution, err = ResolveCentralProfile(ctx, request.ProfileID, request.RepositoryRoot)
	if err != nil {
		return fail(err)
	}
	r := h.resolution
	r.mu.Lock()
	if err = r.recheck(ctx); err != nil {
		r.mu.Unlock()
		return fail(err)
	}
	host, err := r.dependencies.host(HostPolicySelection{Path: filepath.Join(r.directory, "host-policy.json"), OwnerUID: r.uid, WorkspaceRoots: r.selected.Workspaces})
	if err != nil || host == nil {
		r.mu.Unlock()
		return fail(centralProfileErrorWithCause("native_context_host_invalid", err))
	}
	config, _, err := host.Load()
	if err != nil {
		r.mu.Unlock()
		return fail(err)
	}
	raw, err := r.nativeContextMaterial(ctx, nativeSelectedMaterial{Path: request.SelectionPath, SHA256: request.SelectionSHA256}, 65536)
	if err == nil {
		h.options, err = prepareNativeContextSelection(ctx, r, raw, config.Kernel.Scope, config.Kernel.Endpoint)
	}
	if err != nil {
		r.mu.Unlock()
		return fail(err)
	}
	h.observability, err = prepareNativeContextObservability(ctx, r, request.Observability, h.options.Driver)
	if err == nil {
		err = r.recheckFiles(ctx)
	}
	r.mu.Unlock()
	if err != nil {
		return fail(err)
	}
	h.options.Observability = h.observability
	h.composition, err = plugins.NewNativeContextComposition(ctx, h, h.options)
	clear(h.options.Authority.RequestSigningSeed)
	h.options.Authority.RequestSigningSeed = nil
	if err != nil {
		return fail(err)
	}
	return h, nil
}
func (r *CentralProfileResolution) nativeContextMaterial(ctx context.Context, pin nativeSelectedMaterial, limit int64) ([]byte, error) {
	if !centralSelectionPath(pin.Path, r.selected.Workspaces) || !digest.MatchString(pin.SHA256) {
		return nil, centralProfileError("native_context_material_invalid")
	}
	directory, err := r.openDirectory(ctx, filepath.Dir(pin.Path), true)
	if err != nil {
		return nil, err
	}
	raw, err := r.readFile(ctx, directory, filepath.Base(pin.Path), r.uid, 0600, limit)
	if err != nil || centralDigest(raw) != pin.SHA256 {
		return nil, centralProfileErrorWithCause("native_context_material_changed", err)
	}
	return raw, nil
}
func nativeScopedCommand(hub string, scope OwnerScope, domain, entity string) string {
	project, workspace := "_", "_"
	if scope.ProjectID != nil {
		project = *scope.ProjectID
	}
	if scope.WorkspaceID != nil {
		workspace = *scope.WorkspaceID
	}
	return "amx.v1.h." + hub + ".o." + scope.OrganizationID + ".p." + project + ".w." + workspace + "." + domain + "." + entity + ".command"
}

func nativeCapabilitySelectionValid(routes []nativeSelectedCapability, keys plugins.NativeEnrolledKeyOptions) bool {
	destinations := map[string]string{
		"capability-storage-read": "storage-owner", "capability-storage-write": "storage-owner",
		"capability-artifact-read": "artifact-owner", "capability-secret-use": "secret-owner",
		"capability-workspace-read": "workspace-owner", "capability-process-start": "process-owner",
		"capability-process-cancel": "process-owner", "capability-policy-evaluate": "policy-owner",
		"capability-decision-request": "decision-owner", "capability-outcome-query": "outcome-owner",
	}
	seen := map[string]bool{}
	for _, route := range routes {
		service, scope := route.Service, route.Scope
		expectedReply := route.RequestContractID + "-reply"
		switch route.RequestContractID {
		case "capability-storage-read", "capability-artifact-read", "capability-workspace-read":
			expectedReply = "capability-content-reply"
		}
		destination, known := destinations[route.RequestContractID]
		if !known || destination != service.ServiceID || expectedReply != route.ReplyContractID || seen[route.BindingID] || scope.OrganizationID != keys.OrganizationID || scope.WorkspaceID != nil && scope.ProjectID == nil || service.ProfileID != keys.ProfileID || service.HubID != keys.HubID || service.ServiceIdentityRef.OwnerHubID != keys.HubID || service.SigningKeyRef.OwnerHubID != keys.HubID {
			return false
		}
		seen[route.BindingID] = true
	}
	return true
}

func prepareNativeContextSelection(ctx context.Context, r *CentralProfileResolution, raw []byte, scope protocol.Scope, kernelEndpoint string) (plugins.NativeContextCompositionOptions, error) {
	var out plugins.NativeContextCompositionOptions
	fail := func() (plugins.NativeContextCompositionOptions, error) {
		clear(out.Authority.RequestSigningSeed)
		return plugins.NativeContextCompositionOptions{}, centralProfileError("native_context_selection_invalid")
	}
	var selected nativeHostSelectionDocument
	if plugins.ValidateNativeHostSelection(raw) != nil || json.Unmarshal(raw, &selected) != nil || selected.HostPolicy != filepath.Join(r.directory, "host-policy.json") || selected.OwnerUID != r.uid || !reflect.DeepEqual(selected.Workspaces, r.selected.Workspaces) || selected.KernelScope != scope || scope.ProfileID != r.record.ProfileID || scope.InstanceID != r.record.InstanceID || scope.HubID != r.selected.HubID || selected.Keys.ProfileID != scope.ProfileID || selected.Keys.HubID != scope.HubID || selected.RequestSigner.Ref != selected.Keys.HostTransportRef || selected.Lifecycle == nil || selected.ContextTransport == nil || len(selected.Destinations) == 0 || len(selected.ActivationDeclarations) != len(selected.Destinations) || len(selected.ConfigurationRoutes) != len(selected.Destinations) {
		return fail()
	}
	if !nativeCapabilitySelectionValid(selected.CapabilityRoutes, selected.Keys) {
		return fail()
	}
	for _, endpoint := range []string{selected.Connection.Endpoint, selected.Lifecycle.Connection.Endpoint, selected.ContextTransport.Connection.Endpoint} {
		if endpoint == kernelEndpoint {
			return fail()
		}
	}
	trust, err := selected.Connection.clientTrust()
	if err != nil {
		return fail()
	}
	seed, err := r.nativeContextMaterial(ctx, selected.RequestSigner.KeyFile, 32)
	if err != nil || len(seed) != ed25519.SeedSize {
		return fail()
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(selected.RequestSigner.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(public) != selected.RequestSigner.PublicKey || !bytes.Equal(public, ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)) {
		clear(seed)
		return fail()
	}
	out.Authority = plugins.NativeAuthorityClientOptions{ProfileID: selected.Keys.ProfileID, HubID: selected.Keys.HubID, AuthorityID: selected.Keys.AuthorityID, RequestSigningRef: selected.RequestSigner.Ref, ResponseSigningRef: selected.Keys.IssuerRef, RequestSigningSeed: seed, ReplyPrefix: selected.Credentials.ReplyPrefix}
	out.Enrollment = selected.Keys
	out.Destinations = selected.Destinations
	out.ActivationDeclarations = selected.ActivationDeclarations
	authoritySubject := "amx.v1.h." + scope.HubID + ".o." + selected.Keys.OrganizationID + ".identity." + selected.Keys.AuthorityID + ".command"
	subjects := map[string]bool{authoritySubject: true}
	prefixes := []string{"$JS.API."}
	if selected.Keys.Domain != "" {
		prefixes = append(prefixes, "$JS."+selected.Keys.Domain+".API.")
	}
	for _, prefix := range prefixes {
		subjects[prefix+"STREAM.INFO."+selected.Keys.Stream] = true
		subjects[prefix+"STREAM.MSG.GET."+selected.Keys.Stream] = true
	}
	for _, route := range selected.CapabilityRoutes {
		subjects[nativeScopedCommand(scope.HubID, route.Scope, "capability", route.Service.ServiceID)] = true
	}
	for _, route := range selected.ConfigurationRoutes {
		subjects[nativeScopedCommand(scope.HubID, route.Scope, "configuration", route.ConfigurationRef.ID)] = true
	}
	for _, route := range selected.SubscriptionRoutes {
		subjects[nativeScopedCommand(scope.HubID, route.Scope, "configuration", route.Source.ConfigurationRef.ID)] = true
	}
	publish := make([]string, 0, len(subjects))
	for subject := range subjects {
		publish = append(publish, subject)
	}
	sort.Strings(publish)
	if len(publish) > 16 || !nkeys.IsValidPublicAccountKey(selected.Credentials.AccountPublicKey) {
		return fail()
	}
	users := map[string]bool{}
	credential := func(pin nativeSelectedMaterial, account string, pub, sub []string, private bool) bool {
		if !nkeys.IsValidPublicUserKey(pin.UserPublicKey) || users[pin.UserPublicKey] {
			return false
		}
		material, err := r.nativeContextMaterial(ctx, pin, 65536)
		if err != nil {
			return false
		}
		defer clear(material)
		admitted, err := natscredential.Validate(material, natscredential.Policy{AccountPublicKey: account, PublishSubjects: pub, SubscribeSubjects: sub, PrivateInbox: private})
		if err != nil || admitted.PublicKey() != pin.UserPublicKey {
			return false
		}
		users[pin.UserPublicKey] = true
		return true
	}
	if !credential(selected.Credentials.nativeSelectedMaterial, selected.Credentials.AccountPublicKey, publish, []string{selected.Credentials.ReplyPrefix + ".>"}, true) {
		return fail()
	}
	out.AuthorityTransport = plugins.NativeAuthorityNATSOptions{ServerURL: selected.Connection.Endpoint, Subject: authoritySubject, CredentialsFile: selected.Credentials.Path, AccountPublicKey: selected.Credentials.AccountPublicKey, ReplyPrefix: selected.Credentials.ReplyPrefix, PublishSubjects: publish, Trust: trust}
	transport := func(role string, input *nativeSelectedTransport) bool {
		if !nkeys.IsValidPublicAccountKey(input.AccountPublicKey) || len(input.Bindings) != len(selected.Destinations) {
			return false
		}
		trust, err := input.Connection.clientTrust()
		if err != nil {
			return false
		}
		ca, err := r.nativeContextMaterial(ctx, input.CAFile, 16384)
		if err != nil || !bytes.Equal(ca, []byte(input.Connection.RootsPEM)) {
			return false
		}
		var pub, sub []string
		seen := map[string]bool{}
		for _, binding := range input.Bindings {
			declaration, exists := selected.ActivationDeclarations[binding.InstanceID]
			if !exists || selected.Destinations[binding.InstanceID] == "" || seen[binding.InstanceID] {
				return false
			}
			seen[binding.InstanceID] = true
			prefix := "amx.v1.h." + scope.HubID + ".plugins." + binding.InstanceID + "."
			var outgoing, incoming []string
			if role == "lifecycle" {
				if declaration.Pin != binding.Pin || declaration.ManifestDigest != binding.Pin.ManifestChecksum || declaration.IdentityRef.OwnerHubID != scope.HubID {
					return false
				}
				outgoing, incoming = []string{prefix + "lifecycle.control"}, []string{prefix + "lifecycle.event"}
				value := plugins.NativeBinding{InstanceID: binding.InstanceID, Pin: binding.Pin, CredentialsFile: binding.Credentials.Path}
				if binding.Workspace != nil {
					if !containsCentralRoot(r.selected.Workspaces, *binding.Workspace) {
						return false
					}
					value.Workspace = *binding.Workspace
				}
				out.Driver.Bindings = append(out.Driver.Bindings, value)
			} else {
				outgoing = []string{prefix + "context.reply", prefix + "operation.invoke", prefix + "operation.cancel"}
				incoming = []string{prefix + "context.request", prefix + "operation.result"}
				out.ContextTransport.Bindings = append(out.ContextTransport.Bindings, plugins.ContextTransportBinding{InstanceID: binding.InstanceID, ClientCredentialsFile: binding.Credentials.Path})
			}
			if !credential(binding.Credentials, input.AccountPublicKey, incoming, outgoing, false) {
				return false
			}
			pub = append(pub, outgoing...)
			sub = append(sub, incoming...)
		}
		if role == "lifecycle" {
			if !credential(input.ControllerCredentials, input.AccountPublicKey, pub, sub, false) || !centralSelectionPath(input.StateDirectory, r.selected.Workspaces) {
				return false
			}
			if _, err := r.openDirectory(ctx, input.StateDirectory, true); err != nil {
				return false
			}
			out.Driver.HubID = scope.HubID
			out.Driver.AccountPublicKey = input.AccountPublicKey
			out.Driver.ServerURL = input.Connection.Endpoint
			out.Driver.CAFile = input.CAFile.Path
			out.Driver.ControllerCredentialsFile = input.ControllerCredentials.Path
			out.Driver.StateDirectory = input.StateDirectory
			out.LifecycleTrust = trust
		} else {
			if !credential(input.ServerCredentials, input.AccountPublicKey, pub, sub, false) {
				return false
			}
			out.ContextTransport.HubID = scope.HubID
			out.ContextTransport.AccountPublicKey = input.AccountPublicKey
			out.ContextTransport.ServerURL = input.Connection.Endpoint
			out.ContextTransport.CAFile = input.CAFile.Path
			out.ContextTransport.ServerCredentialsFile = input.ServerCredentials.Path
			out.ContextTrust = trust
		}
		return true
	}
	if !transport("lifecycle", selected.Lifecycle) || !transport("context", selected.ContextTransport) {
		return fail()
	}
	for _, route := range selected.CapabilityRoutes {
		value := out.AuthorityTransport
		value.Subject = nativeScopedCommand(scope.HubID, route.Scope, "capability", route.Service.ServiceID)
		out.Services = append(out.Services, plugins.NativeContextServiceRoute{BindingID: route.BindingID, RequestContractID: route.RequestContractID, ReplyContractID: route.ReplyContractID, Service: route.Service, Transport: value})
	}
	out.Configurations = map[string]plugins.NativeContextConfigurationInput{}
	for instance, route := range selected.ConfigurationRoutes {
		declaration, exists := selected.ActivationDeclarations[instance]
		if !exists {
			return fail()
		}
		var facts struct {
			Grant struct {
				Subject string     `json:"subjectInstanceId"`
				Scope   OwnerScope `json:"scope"`
			} `json:"grant"`
			Bindings []struct {
				ID        string   `json:"id"`
				Contract  string   `json:"contractId"`
				Action    string   `json:"action"`
				Class     string   `json:"resourceClass"`
				Resources []string `json:"resourceIds"`
			} `json:"domainBindings"`
		}
		if json.Unmarshal(declaration.Facts, &facts) != nil || facts.Grant.Subject != instance || !reflect.DeepEqual(facts.Grant.Scope, route.Scope) || route.Scope.OrganizationID != selected.Keys.OrganizationID || route.Service.ProfileID != scope.ProfileID || route.Service.HubID != scope.HubID || route.ConfigurationRef.OwnerHubID != scope.HubID || route.AuthorityRef.ID != selected.Keys.AuthorityID || route.AuthorityRef.OwnerHubID != scope.HubID {
			return fail()
		}
		value := out.AuthorityTransport
		value.Subject = nativeScopedCommand(scope.HubID, route.Scope, "configuration", route.ConfigurationRef.ID)
		out.Configurations[instance] = plugins.NativeContextConfigurationInput{Binding: plugins.NativeConfigurationBinding{ConfigurationRef: route.ConfigurationRef, AuthorityRef: route.AuthorityRef, Service: route.Service, Resources: route.Resources}, Transport: value}
	}
	seenSubscriptions := map[string]bool{}
	for _, route := range selected.SubscriptionRoutes {
		key := route.BindingID + ":" + route.Source.ConfigurationRef.ID
		if seenSubscriptions[key] || route.Service.ProfileID != scope.ProfileID || route.Service.HubID != scope.HubID || route.Source.ConfigurationRef.OwnerHubID != scope.HubID || route.Scope.OrganizationID != selected.Keys.OrganizationID {
			return fail()
		}
		seenSubscriptions[key] = true
		matches := 0
		for instance, declaration := range selected.ActivationDeclarations {
			var facts struct {
				Grant struct {
					Subject string     `json:"subjectInstanceId"`
					Scope   OwnerScope `json:"scope"`
				} `json:"grant"`
				Bindings []struct {
					ID        string   `json:"id"`
					Contract  string   `json:"contractId"`
					Action    string   `json:"action"`
					Class     string   `json:"resourceClass"`
					Resources []string `json:"resourceIds"`
				} `json:"domainBindings"`
			}
			if json.Unmarshal(declaration.Facts, &facts) != nil {
				return fail()
			}
			if facts.Grant.Subject != instance || !reflect.DeepEqual(facts.Grant.Scope, route.Scope) {
				continue
			}
			for _, binding := range facts.Bindings {
				if binding.ID != route.BindingID || binding.Contract != "configuration-change-subscribe" || binding.Action != "subscribe" || binding.Class != "configuration" {
					continue
				}
				for _, resource := range binding.Resources {
					if resource != route.Source.ConfigurationRef.ID {
						continue
					}
					for _, pin := range declaration.ConfigurationEventSources {
						if pin == route.Source {
							matches++
						}
					}
				}
			}
		}
		if matches != 1 {
			return fail()
		}
		value := out.AuthorityTransport
		value.Subject = nativeScopedCommand(scope.HubID, route.Scope, "configuration", route.Source.ConfigurationRef.ID)
		out.Subscriptions = append(out.Subscriptions, plugins.NativeContextSubscriptionInput{BindingID: route.BindingID, Source: route.Source, Service: route.Service, Transport: value})
	}

	if len(out.Subscriptions) == 0 || len(out.Services) == 0 {
		return fail()
	}
	if err := r.recheckFiles(ctx); err != nil {
		return fail()
	}
	return out, nil
}

func prepareNativeContextObservability(ctx context.Context, r *CentralProfileResolution, input NativeContextObservabilitySelection, driver plugins.NativeDriverOptions) (*plugins.NativeObservability, error) {
	if !centralSelectionPath(input.Path, r.selected.Workspaces) {
		return nil, centralProfileError("native_context_observability_invalid")
	}
	directory, err := r.openDirectory(ctx, filepath.Dir(input.Path), true)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(directory.file.Fd()), filepath.Base(input.Path), unix.O_WRONLY|unix.O_APPEND|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, centralProfileError("native_context_observability_invalid")
	}
	file := os.NewFile(uintptr(fd), "native-context-observability")
	bindings := map[string]plugins.PackagePin{}
	for _, binding := range driver.Bindings {
		bindings[binding.InstanceID] = binding.Pin
	}
	owner, admitErr := plugins.NewNativeObservability(ctx, file, plugins.NativeObservabilityOptions{HubID: driver.HubID, Bindings: bindings, EventCodes: input.EventCodes, SpanCodes: input.SpanCodes, MetricCodes: input.MetricCodes, MaxBytes: input.MaxBytes})
	closeErr := file.Close()
	if admitErr != nil || closeErr != nil {
		return owner, centralProfileErrorWithCause("native_context_observability_invalid", errors.Join(admitErr, closeErr))
	}
	return owner, nil
}
