package plugins

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/localtls"
	"github.com/nats-io/nats.go"
)

type nativeIdentityForeignService struct {
	Owner       OwnerReference `json:"owner"`
	ClockHandle string         `json:"clockHandle"`
}

type nativeIdentitySubscriptionInput struct {
	BindingID string                          `json:"bindingId"`
	Filter    nativeConfigurationSubscription `json:"filter"`
}

// The production registered provider copies retained event sources from the
// activation declaration before opening the pinned provider. This direct live
// fixture supplies the same enrolled source for its subscribing instance.
type nativeIdentitySourceProvider struct {
	ContextProvider
	sources map[string][]NativeConfigurationEventSource
}

func (p nativeIdentitySourceProvider) Open(ctx context.Context, binding ContextBinding) (ContextLease, error) {
	binding.ConfigurationEventSources = append([]NativeConfigurationEventSource(nil), p.sources[binding.Owner.InstanceID]...)
	return p.ContextProvider.Open(ctx, binding)
}

type nativeIdentityConfigurationOwner struct {
	*contextMemoryConfigurationOwner
	revisions map[string]uint64
}

func (o *nativeIdentityConfigurationOwner) Open(ctx context.Context, binding ContextBinding) (ContextConfigurationLease, error) {
	lease, err := o.contextMemoryConfigurationOwner.Open(ctx, binding)
	if err != nil {
		return lease, err
	}
	owned := lease.(*contextMemoryConfigurationLease)
	owned.mu.Lock()
	if revision := o.revisions[binding.Owner.InstanceID]; revision != 0 {
		owned.current.Revision = revision
	}
	owned.mu.Unlock()
	return owned, nil
}

// Identity and subscription calls use the real enrolled authority and TLS
// broker. Configuration reads still use the existing controlled owner.
func TestNativeLiveAuthenticatedContextIsolation(t *testing.T) {
	directory := os.Getenv("AMX_NATIVE_CONTEXT_IDENTITY_LIVE_DIR")
	if directory == "" {
		t.Skip("coordinated identity context fixture required")
	}
	info, err := os.Lstat(directory)
	if os.Getenv("AMX_NATIVE_CONTEXT_IDENTITY_LIVE") != "1" || runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" || err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !filepath.IsAbs(directory) {
		t.Fatal("native identity fixture prerequisites invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var subscriptionSource nativeSubscriptionLiveSource
	nativeLiveWait(t, ctx, directory, "identity-source-ready.json", func(raw []byte) bool {
		if nativeLiveDecode(raw, &subscriptionSource) != nil {
			t.Fatal("identity subscription source handoff invalid")
		}
		return true
	})
	pkg := nativeFixturePackage(t, "identity_context", func(m *Manifest) {
		m.RequestedCapabilities = []Capability{{Action: "inspect", ResourceClass: "task"}, {Action: "subscribe", ResourceClass: "configuration"}}
		m.Runtime.Args = []string{"-test.run=^TestNativeChild$", "-test.timeout=0"}
		m.Lifecycle.DrainDeadlineMS = 8000
	})
	if subscriptionSource.Source.SchemaRef != pkg.Manifest().ConfigurationSchemaRef || subscriptionSource.Source.ConfigurationRef.Revision != 0 || subscriptionSource.Cursor.Sequence != 0 || subscriptionSource.Cursor.SourceDigest != subscriptionSource.Source.SourceDigest || subscriptionSource.Cursor.StreamCreated != subscriptionSource.Source.StreamCreated {
		t.Fatal("identity subscription source pin invalid")
	}
	var owners []OwnerReference
	var configurations []ValidatedConfiguration
	var declarations []map[string]any
	epoch, err := randomControlID()
	if err != nil {
		t.Fatal("owner allocation failed")
	}
	for _, name := range []string{"a", "b"} {
		owner := OwnerReference{Pin: pkg.Pin(), InstanceID: "plugin-" + name, Epoch: epoch, Generation: 1}
		input := map[string]any{"behavior": "identity-isolation", "project": "project-" + name, "private": "configuration-private-" + name, "reasoning": "private-reasoning-" + name, "fixtureDirectory": directory}
		if name == "b" {
			filter := nativeConfigurationSubscription{ResourceRef: subscriptionSource.Source.ConfigurationRef, EventContractID: "configuration-change", Cursor: subscriptionSource.Cursor}
			filter.Filter.Owner = owner
			filter.Filter.SchemaRef = subscriptionSource.Source.SchemaRef
			filter.FilterDigest = nativeAuthorityDigestMustCanonical(contextJSON(map[string]any{"resourceRef": filter.ResourceRef, "eventContractId": filter.EventContractID, "filter": filter.Filter}))
			input["subscription"] = nativeIdentitySubscriptionInput{BindingID: "configuration-events", Filter: filter}
		}
		configuration, err := PrepareConfiguration(pkg, nil, contextJSON(input))
		if err != nil {
			t.Fatal(err)
		}
		owners = append(owners, owner)
		configurations = append(configurations, configuration)
		declarations = append(declarations, map[string]any{"owner": owner, "manifestDigest": pkg.manifest.Checksum(), "configurationChecksum": configuration.Checksum()})
	}
	nativeLiveWrite(t, directory, "identity-configuration-b.json", map[string]string{"configurationBytes": base64.StdEncoding.EncodeToString(configurations[1].Bytes())})
	nativeLiveWrite(t, directory, "go-identity-declarations.json", declarations)
	var ready struct {
		nativeSubscriptionLiveReady
		Driver        NativeDriverOptions `json:"driver"`
		Context       NATSContextOptions  `json:"context"`
		Envelopes     []string            `json:"envelopes"`
		Observability string              `json:"observability"`
	}
	nativeLiveWait(t, ctx, directory, "identity-ready.json", func(raw []byte) bool {
		if nativeLiveDecode(raw, &ready) != nil {
			t.Fatal("identity fixture handoff invalid")
		}
		return true
	})
	if len(ready.Envelopes) != 2 || len(ready.Driver.Bindings) != 2 || len(ready.Context.Bindings) != 2 {
		t.Fatal("identity fixture omitted an instance")
	}
	ca, err := ReadOwnerPrivateFile(ready.CAFile, nativeAuthorityLimit)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := localtls.NewClientTrust(localtls.Policy{Endpoint: ready.ServerURL, ServerName: ready.TLSName, RootsPEM: ca, LeafCertificateSHA256: ready.LeafCertificateSHA256})
	if err != nil {
		t.Fatal(err)
	}
	seed, err := ReadOwnerPrivateFile(ready.HostSigningSeedFile, 32)
	if err != nil || len(seed) != 32 {
		t.Fatal("host signing seed unavailable")
	}
	defer clear(seed)
	transport, err := NewNativeAuthorityNATSExchange(ctx, NativeAuthorityNATSOptions{ServerURL: ready.ServerURL, Subject: ready.AuthoritySubject, CredentialsFile: ready.CredentialsFile, Trust: trust, AccountPublicKey: ready.AccountPublicKey, ReplyPrefix: ready.ReplyPrefix, PublishSubjects: ready.PublishSubjects})
	transportErr := err
	var subscriptionTransport *NativeAuthorityNATSExchange
	var subscriptions *NativeConfigurationSubscriptions
	var provider *PinnedNATSContextProvider
	var driver *NativeDriver
	var observation *NativeObservability
	var dispatchers sync.WaitGroup
	var processes []OwnedInstance
	configurationOwner := &nativeIdentityConfigurationOwner{contextMemoryConfigurationOwner: newContextMemoryConfigurationOwner(),
		revisions: map[string]uint64{"plugin-a": 7, "plugin-b": 1}}
	// Retain the original Go owners and borrowed Python services if a join fails.
	defer func() {
		cancel()
		dispatchers.Wait()
		for attempt := uint64(0); ; attempt++ {
			closeCtx, stop := context.WithTimeout(context.Background(), 8*time.Second)
			joined := true
			if driver != nil {
				joined = driver.Close(closeCtx) == nil
			}
			if joined && provider != nil {
				joined = provider.Close(closeCtx) == nil
			}
			if joined && subscriptions != nil {
				joined = subscriptions.Close(closeCtx) == nil
			}
			if joined && subscriptionTransport != nil {
				joined = subscriptionTransport.Close(closeCtx) == nil
			}
			if joined && observation != nil {
				joined = observation.Close(closeCtx) == nil
			}
			if joined && transport != nil {
				joined = transport.Close(closeCtx) == nil
			}
			stop()
			if joined {
				if !t.Failed() {
					for _, process := range processes {
						if !completed(process.Done()) || process.ExitError() == nil || process.ExitError().Error() != "native_process_exited" {
							t.Error("original identity child did not exit successfully")
						}
					}
					configurationOwner.mu.Lock()
					for _, lease := range configurationOwner.leases {
						if !completed(lease.Done()) {
							t.Error("original controlled configuration lease did not join")
						}
					}
					configurationOwner.mu.Unlock()
					entries, e := os.ReadDir(ready.Driver.StateDirectory)
					if e != nil {
						t.Error("original native state unavailable after join")
					}
					for _, entry := range entries {
						if strings.HasPrefix(entry.Name(), "instance-") {
							t.Error("original identity child stage remained")
						}
					}
				}
				nativeLiveWrite(t, directory, "identity-cleanup.json", map[string]any{"phase": "joined"})
				return
			}
			nativeSubscriptionLiveCleanupState(directory, map[string]any{"phase": "cleanup-required", "attempt": attempt})
			for {
				raw, e := ReadOwnerPrivateFile(filepath.Join(directory, "fixture-cleanup.json"), 8192)
				var recovery struct {
					Attempt uint64 `json:"attempt"`
				}
				if e == nil && nativeLiveDecode(raw, &recovery) == nil && recovery.Attempt > attempt {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
	}()
	if transportErr != nil {
		t.Fatal("original authority TLS transport unavailable")
	}
	keys, err := NewNativeEnrolledKeys(transport, ready.Enrollment)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewNativeContextAuthority(NativeAuthorityClientOptions{ProfileID: ready.Enrollment.ProfileID, HubID: ready.Enrollment.HubID, AuthorityID: ready.Enrollment.AuthorityID, RequestSigningRef: ready.Enrollment.HostTransportRef, ResponseSigningRef: ready.Enrollment.IssuerRef, RequestSigningSeed: seed, ReplyPrefix: ready.ReplyPrefix, Keys: keys, Exchange: transport}, map[string]string{"plugin-a": "task-owner", "plugin-b": "task-owner"})
	if err != nil {
		t.Fatal(err)
	}
	subscriptionOptions := NativeAuthorityNATSOptions{ServerURL: ready.ServerURL, Subject: ready.ConfigurationSubject, CredentialsFile: ready.CredentialsFile, Trust: trust, AccountPublicKey: ready.AccountPublicKey, ReplyPrefix: ready.ReplyPrefix, PublishSubjects: ready.PublishSubjects}
	subscriptionTransport, err = NewNativeAuthorityNATSExchange(ctx, subscriptionOptions)
	if err != nil {
		t.Fatal("original configuration subscription transport unavailable")
	}
	subscriptions, err = NewNativeConfigurationSubscriptions(authority, keys, []NativeConfigurationSubscriptionRoute{{BindingID: ready.BindingID, Source: ready.Source, Service: ready.Service, Exchange: subscriptionTransport}})
	if err != nil {
		t.Fatal("original configuration subscription owner unavailable")
	}
	file, err := os.OpenFile(ready.Observability, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	observation, err = NewNativeObservability(ctx, file, NativeObservabilityOptions{HubID: ready.Enrollment.HubID, Bindings: map[string]PackagePin{"plugin-a": pkg.Pin(), "plugin-b": pkg.Pin()}, EventCodes: []string{"operation_started", "cancellation_observed"}, SpanCodes: []string{"domain_request"}, MetricCodes: []string{"calls"}, MaxBytes: 65536})
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan ContextTags, 2)
	canceled := make(chan struct{}, 1)
	ports := ContextPorts{Authority: authority, Configuration: configurationOwner, Now: time.Now, EventCodes: []string{"operation_started", "cancellation_observed"}, SpanCodes: []string{"domain_request"}, MetricCodes: []string{"calls"}, Trace: observation.Trace, Metric: observation.Metric,
		Log: func(ctx context.Context, r ContextLogRecord) error {
			if err := observation.Log(ctx, r); err != nil {
				return err
			}
			if r.EventCode == "operation_started" {
				select {
				case started <- r.Tags:
				case <-ctx.Done():
					return pluginError("context_operation_canceled")
				}
			} else {
				select {
				case canceled <- struct{}{}:
				case <-ctx.Done():
					return pluginError("context_operation_canceled")
				}
			}
			return nil
		},
		Domain: func(context.Context, ContextApprovedEnvelope) ([]byte, error) {
			return nil, pluginError("context_domain_unavailable")
		},
		Subscribe: subscriptions.Subscribe, SubscriptionAuthority: authority}
	provider, err = NewPinnedNATSContextProvider(ctx, ready.Context, trust, ports)
	if err != nil {
		t.Fatal(err)
	}
	ready.Driver.LifecycleTrust = trust
	driver, err = NewNativeDriverWithContext(ctx, ready.Driver, nativeIdentitySourceProvider{ContextProvider: provider,
		sources: map[string][]NativeConfigurationEventSource{"plugin-b": {ready.Source}}})
	if err != nil {
		t.Fatal(err)
	}
	var originals [][]byte
	for i, owner := range owners {
		if ready.Driver.Bindings[i].InstanceID != owner.InstanceID || ready.Driver.Bindings[i].Pin != pkg.Pin() || ready.Context.Bindings[i].InstanceID != owner.InstanceID {
			t.Fatal("fixture replaced an original owner")
		}
		original, e := ReadOwnerPrivateFile(ready.Envelopes[i], nativeAuthorityLimit)
		if e != nil {
			t.Fatal(e)
		}
		originals = append(originals, original)
		start, stop := context.WithTimeout(ctx, time.Duration(pkg.Manifest().Lifecycle.StartDeadlineMS)*time.Millisecond)
		process, e := driver.Start(start, StartRequest{Owner: owner, Package: pkg, Configuration: configurations[i]})
		if process != nil {
			processes = append(processes, process)
		}
		if e == nil {
			e = process.WaitReady(start)
		}
		stop()
		if e != nil {
			t.Fatal("authenticated native instance startup failed")
		}
	}
	foreignServices := map[string]nativeIdentityForeignService{}
	provider.base.mu.Lock()
	for i, owner := range owners {
		other := provider.base.owners[owners[1-i].InstanceID]
		foreignServices[owner.InstanceID] = nativeIdentityForeignService{Owner: other.binding.Owner, ClockHandle: other.handles["clock"]}
	}
	provider.base.mu.Unlock()
	nativeLiveWrite(t, directory, "identity-foreign-services.json", foreignServices)
	for i, owner := range owners {
		if _, e := driver.Dispatch(ctx, owner, originals[1-i]); e == nil {
			t.Fatal("cross-project envelope substitution accepted")
		}
		var changed map[string]any
		_ = json.Unmarshal(originals[i], &changed)
		changed["payload"].(map[string]any)["taskId"] = "task-other"
		if _, e := driver.Dispatch(ctx, owner, contextJSON(changed)); e == nil {
			t.Fatal("changed signed payload accepted")
		}
		wrong := owner
		wrong.Generation++
		if _, e := driver.Dispatch(ctx, wrong, originals[i]); e == nil {
			t.Fatal("wrong generation accepted")
		}
	}
	nativeIdentityCredentialBoundary(t, ctx, ready.Context, trust)
	work, stopA := context.WithCancel(ctx)
	defer stopA()
	type result struct {
		index int
		raw   []byte
		err   error
	}
	results := make(chan result, 2)
	for i, owner := range owners {
		dispatchers.Add(1)
		go func(i int, owner OwnerReference) {
			defer dispatchers.Done()
			request := ctx
			if i == 0 {
				request = work
			}
			raw, e := driver.Dispatch(request, owner, originals[i])
			results <- result{i, raw, e}
		}(i, owner)
	}
	seen := map[string]bool{}
	for range owners {
		select {
		case tags := <-started:
			if tags.ProjectID == nil || tags.AuthenticatedIdentityRef == nil || tags.EffectiveActorRef == nil {
				t.Fatal("operation attribution omitted")
			}
			suffix := strings.TrimPrefix(tags.Owner.InstanceID, "plugin-")
			if *tags.ProjectID != "project-"+suffix || tags.PrincipalID != "user-"+suffix || tags.AuthenticatedIdentityRef.ID != "human-"+suffix || tags.EffectiveActorRef.ID != "human-"+suffix || seen[suffix] {
				t.Fatal("concurrent operation identity crossed instances")
			}
			seen[suffix] = true
		case <-ctx.Done():
			t.Fatal("concurrent calls did not both enter")
		}
	}
	stopA()
	for range owners {
		select {
		case got := <-results:
			if got.index == 0 {
				if got.err == nil {
					t.Fatal("canceled operation succeeded")
				}
			} else {
				var value struct{ Caller, Project string }
				if got.err != nil || json.Unmarshal(got.raw, &value) != nil || value.Caller != "user-b" || value.Project != "project-b" {
					t.Fatal("other project did not complete independently")
				}
			}
		case <-ctx.Done():
			t.Fatal("original dispatches did not join")
		}
	}
	subscriptions.mu.Lock()
	remainingSubscriptions := len(subscriptions.leases)
	subscriptions.mu.Unlock()
	if remainingSubscriptions != 0 {
		t.Fatal("revoked original subscription did not join")
	}
	nativeLiveWrite(t, directory, "identity-subscription.json", map[string]any{"phase": "joined"})
	select {
	case <-canceled:
	case <-ctx.Done():
		t.Fatal("child did not observe original cancellation")
	}
	nativeLiveWrite(t, directory, "go-identity-result.json", map[string]any{"phase": "revoke"})
	nativeLiveWait(t, ctx, directory, "identity-revoked.json", func(raw []byte) bool {
		var value struct {
			Revoked bool `json:"revoked"`
		}
		return nativeLiveDecode(raw, &value) == nil && value.Revoked
	})
	originalContextLive := func() bool {
		provider.base.mu.Lock()
		lease := provider.base.owners[owners[1].InstanceID]
		provider.base.mu.Unlock()
		return lease != nil && !completed(lease.Done()) && processes[1].(InstanceAvailability).Available()
	}
	if !originalContextLive() {
		t.Fatal("revocation probe lost its live original context")
	}
	if _, e := driver.Dispatch(ctx, owners[1], originals[1]); e == nil || e.Error() != "context_authority_unavailable" {
		t.Fatal("revoked operation did not receive an authority refusal")
	}
	if !originalContextLive() {
		t.Fatal("revocation probe closed its original context")
	}
	if observation.Close(ctx) != nil {
		t.Fatal("original diagnostic writer did not join")
	}
	raw, err := ReadOwnerPrivateFile(ready.Observability, 65536)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{[]byte("configuration-private"), []byte("private-reasoning"), seed} {
		if bytes.Contains(raw, secret) {
			t.Fatal("private data disclosed in diagnostics")
		}
	}
	kinds := map[string]map[string]bool{}
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
		var record nativeObservation
		if json.Unmarshal(line, &record) != nil {
			t.Fatal("diagnostic record invalid")
		}
		if record.Tags.OperationID == "" {
			continue
		}
		suffix := strings.TrimPrefix(record.Tags.Owner.InstanceID, "plugin-")
		if record.Tags.ProjectID == nil || *record.Tags.ProjectID != "project-"+suffix || record.Tags.PrincipalID != "user-"+suffix || record.Tags.AuthenticatedIdentityRef == nil || record.Tags.AuthenticatedIdentityRef.ID != "human-"+suffix || record.Tags.EffectiveActorRef == nil || record.Tags.EffectiveActorRef.ID != "human-"+suffix {
			t.Fatal("diagnostic attribution crossed projects")
		}
		if kinds[suffix] == nil {
			kinds[suffix] = map[string]bool{}
		}
		kinds[suffix][record.Kind] = true
	}
	for _, suffix := range []string{"a", "b"} {
		for _, kind := range []string{"log", "trace", "metric"} {
			if !kinds[suffix][kind] {
				t.Fatal("operation diagnostic capability was not exercised")
			}
		}
	}
	nativeLiveWrite(t, directory, "go-identity-result.json", map[string]any{"phase": "complete", "isolation": true, "revocation": true, "subscription": true})
}

func nativeIdentityCredentialBoundary(t *testing.T, ctx context.Context, options NATSContextOptions, trust *localtls.ClientTrust) {
	t.Helper()
	denied := make(chan error, 2)
	dialer, err := trust.NewDialer(ctx, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer nativeIdentityJoinTLS(t, dialer, os.Getenv("AMX_NATIVE_CONTEXT_IDENTITY_LIVE_DIR"))
	nc, err := nats.Connect(options.ServerURL, nats.UserCredentials(options.Bindings[0].ClientCredentialsFile), nats.NoReconnect(), nats.TLSHandshakeFirst(), nats.IgnoreDiscoveredServers(), nats.Timeout(time.Second), nats.SetCustomDialer(dialer), nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
		select {
		case denied <- err:
		default:
		}
	}))
	if err != nil {
		t.Fatal("original context credential connection failed")
	}
	defer nc.Close()
	other := contextSubjects(options, options.Bindings[1].InstanceID)
	if nc.Publish(other.RequestSubject, []byte(`{}`)) != nil {
		t.Fatal("cross-instance permission probe failed")
	}
	if _, err = nc.SubscribeSync(other.ReplySubject); err != nil || nc.FlushTimeout(time.Second) != nil {
		t.Fatal("cross-instance permission probe failed")
	}
	for range 2 {
		select {
		case err := <-denied:
			if !errors.Is(err, nats.ErrPermissionViolation) {
				t.Fatal("credential probe failed without a permission refusal")
			}
		case <-ctx.Done():
			t.Fatal("context credential crossed instances")
		}
	}
}

func nativeChildIdentityCalls(t *testing.T, bootstrap NativeBootstrap, configuration []byte, nc *nats.Conn, dialer *localtls.Dialer, call func(string, string, *string, any) contextServiceReply, replies, invokes, cancels *nats.Subscription) func() {
	t.Helper()
	var fixture struct {
		Directory    string                           `json:"fixtureDirectory"`
		Subscription *nativeIdentitySubscriptionInput `json:"subscription"`
	}
	_ = json.Unmarshal(configuration, &fixture)
	contextRaw, err := ReadOwnerPrivateFile(bootstrap.Context.ContextFile, manifestLimit)
	var descriptor struct {
		Services map[string]struct {
			HandleID string `json:"handleId"`
		} `json:"services"`
	}
	if err != nil || json.Unmarshal(contextRaw, &descriptor) != nil || descriptor.Services["domainGateway"].HandleID == "" {
		t.Fatal("identity domain gateway descriptor unavailable")
	}
	callRevokedSubscription := func(method, operation, subscription string) contextServiceReply {
		request := contextServiceRequest{SchemaVersion: "1.0.0", Kind: "plugin-context-request", RequestID: contextTestNonce("request"), Owner: bootstrap.Prepare.Owner, HandleID: descriptor.Services["domainGateway"].HandleID, Service: "domainGateway", Method: method, OperationHandle: &operation, Parameters: contextJSON(map[string]any{"subscriptionHandle": subscription})}
		if nc.Publish(bootstrap.Context.Transport.RequestSubject, contextJSON(request)) != nil || nc.FlushTimeout(time.Second) != nil {
			t.Fatal("post-revocation subscription request failed")
		}
		message, err := replies.NextMsg(7 * time.Second)
		var reply contextServiceReply
		if err != nil || decodeContextJSON("plugin-context-reply", message.Data, &reply) != nil || reply.RequestID != request.RequestID || reply.Owner != request.Owner {
			t.Fatal("post-revocation subscription reply invalid")
		}
		return reply
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		message, err := invokes.NextMsg(30 * time.Second)
		if err != nil {
			t.Error("identity invocation unavailable")
			return
		}
		var invocation struct {
			Owner     OwnerReference         `json:"owner"`
			Handle    string                 `json:"operationHandle"`
			Operation contextOperationClaims `json:"operation"`
		}
		if decodeContextJSON("plugin-context-operation", message.Data, &invocation) != nil || invocation.Owner != bootstrap.Prepare.Owner {
			t.Error("identity invocation changed owner")
			return
		}
		handle := invocation.Handle
		raw, err := ReadOwnerPrivateFile(filepath.Join(fixture.Directory, "identity-foreign-services.json"), 8192)
		var foreignServices map[string]nativeIdentityForeignService
		if err != nil || nativeLiveDecode(raw, &foreignServices) != nil {
			t.Error("foreign service probe inputs unavailable")
			return
		}
		foreign, exists := foreignServices[bootstrap.Prepare.Owner.InstanceID]
		if !exists || !contextOwnerValid(foreign.Owner) || foreign.Owner == bootstrap.Prepare.Owner || foreign.Owner.Pin != bootstrap.Prepare.Owner.Pin || foreign.ClockHandle == "" {
			t.Error("foreign service probe replaced an owner")
			return
		}
		// The original child owns both request and reply. A second subscriber
		// would copy these replies into the child's pending service queue.
		for _, owner := range []OwnerReference{bootstrap.Prepare.Owner, foreign.Owner} {
			request := contextServiceRequest{SchemaVersion: "1.0.0", Kind: "plugin-context-request", RequestID: contextTestNonce("request"), Owner: owner, HandleID: foreign.ClockHandle, Service: "clock", Method: "now", Parameters: contextJSON(map[string]any{})}
			if nc.Publish(bootstrap.Context.Transport.RequestSubject, contextJSON(request)) != nil || nc.FlushTimeout(time.Second) != nil {
				t.Error("foreign service probe request failed")
				return
			}
			message, err := replies.NextMsg(time.Second)
			var reply contextServiceReply
			if err != nil || decodeContextJSON("plugin-context-reply", message.Data, &reply) != nil || reply.RequestID != request.RequestID || reply.Owner != bootstrap.Prepare.Owner || reply.Outcome != "rejected" {
				t.Error("foreign owner or service handle accepted")
				return
			}
		}
		if call("logger", "record", &handle, map[string]any{"eventCode": "operation_started", "projectId": "forged"}).Outcome != "rejected" {
			t.Error("forged logger attribution accepted")
			return
		}
		config := call("config", "read", &handle, map[string]any{})
		var snapshot struct {
			Bytes    string `json:"configurationBytes"`
			Revision uint64 `json:"configurationRevision"`
		}
		_ = json.Unmarshal(config.Value, &snapshot)
		decoded, e := base64.StdEncoding.DecodeString(snapshot.Bytes)
		expectedRevision := uint64(7)
		if fixture.Subscription != nil {
			expectedRevision = 1
		}
		if config.Code != "ok" || e != nil || !bytes.Equal(decoded, configuration) || snapshot.Revision != expectedRevision {
			t.Error("configuration crossed original instance")
			return
		}
		if call("metrics", "add", &handle, map[string]any{"metricCode": "calls", "value": 1}).Code != "ok" {
			t.Error("identity metric refused")
			return
		}
		span := call("tracing", "start", &handle, map[string]any{"spanCode": "domain_request"})
		var value struct {
			Handle string `json:"spanHandle"`
		}
		_ = json.Unmarshal(span.Value, &value)
		if span.Code != "ok" || value.Handle == "" || call("tracing", "finish", &handle, map[string]any{"spanHandle": value.Handle, "outcomeCode": "completed"}).Code != "ok" {
			t.Error("identity trace refused")
			return
		}
		if call("logger", "record", &handle, map[string]any{"eventCode": "operation_started"}).Code != "ok" {
			t.Error("identity log refused")
			return
		}
		reply := call("clock", "wait", &handle, map[string]any{"durationMs": 2000})
		if bootstrap.Prepare.Owner.InstanceID == "plugin-a" {
			if reply.Outcome != "rejected" {
				t.Error("canceled clock survived")
				return
			}
			message, e := cancels.NextMsg(time.Second)
			var canceled struct {
				Handle string `json:"operationHandle"`
			}
			if e != nil || decodeContextJSON("plugin-context-operation", message.Data, &canceled) != nil || canceled.Handle != handle {
				t.Error("cancellation crossed operation")
				return
			}
			if call("logger", "record-instance", nil, map[string]any{"eventCode": "cancellation_observed"}).Code != "ok" {
				t.Error("cancellation receipt refused")
			}
			return
		}
		if reply.Code != "ok" {
			t.Error("other operation was canceled")
			return
		}
		if fixture.Subscription == nil {
			t.Error("approved subscription input missing")
			return
		}
		type subscriptionReply struct {
			Handle string `json:"subscriptionHandle"`
		}
		subscriptions := make([]subscriptionReply, 2)
		for i := range subscriptions {
			subscribe := call("domainGateway", "subscribe", &handle, map[string]any{"bindingId": fixture.Subscription.BindingID, "contractId": "configuration-change-subscribe", "payload": fixture.Subscription.Filter})
			_ = json.Unmarshal(subscribe.Value, &subscriptions[i])
			if subscribe.Code != "ok" || subscriptions[i].Handle == "" {
				nativeLiveWrite(t, fixture.Directory, "identity-subscription.json", map[string]any{"phase": "subscribe-refused", "code": subscribe.Code})
				t.Error("authenticated child subscription refused")
				return
			}
		}
		nativeLiveWrite(t, fixture.Directory, "identity-subscription.json", map[string]any{"phase": "opened"})
		next := call("domainGateway", "next", &handle, map[string]any{"subscriptionHandle": subscriptions[0].Handle})
		var changed struct {
			ConfigurationRef      ContextReference `json:"configurationRef"`
			Owner                 OwnerReference   `json:"owner"`
			SchemaRef             string           `json:"schemaRef"`
			ConfigurationChecksum string           `json:"configurationChecksum"`
		}
		if next.Code != "ok" || json.Unmarshal(next.Value, &changed) != nil || changed.ConfigurationRef.ID != fixture.Subscription.Filter.ResourceRef.ID || changed.ConfigurationRef.OwnerHubID != fixture.Subscription.Filter.ResourceRef.OwnerHubID || changed.ConfigurationRef.Revision != 1 || changed.Owner != bootstrap.Prepare.Owner || changed.SchemaRef != fixture.Subscription.Filter.Filter.SchemaRef || changed.ConfigurationChecksum != checksum(configuration) {
			t.Error("authenticated child received a changed configuration event")
			return
		}
		if unsubscribed := call("domainGateway", "unsubscribe", &handle, map[string]any{"subscriptionHandle": subscriptions[0].Handle}); unsubscribed.Code != "ok" {
			t.Error("consumed authenticated child subscription did not join")
			return
		}
		nativeLiveWrite(t, fixture.Directory, "identity-subscription.json", map[string]any{"phase": "event-complete"})
		revocation, stopRevocation := context.WithTimeout(context.Background(), 30*time.Second)
		defer stopRevocation()
		nativeLiveWait(t, revocation, fixture.Directory, "identity-subscription-revoked.json", func(raw []byte) bool {
			var value struct {
				Revoked bool `json:"revoked"`
			}
			return nativeLiveDecode(raw, &value) == nil && value.Revoked
		})
		if refused := callRevokedSubscription("next", handle, subscriptions[1].Handle); refused.Outcome != "rejected" || refused.Code != "context_domain_unavailable" || string(refused.Value) != "null" {
			t.Error("revoked configuration event reached authenticated child")
			return
		}
		nativeLiveWrite(t, fixture.Directory, "identity-subscription.json", map[string]any{"phase": "revocation-refused"})
		unsubscribed := callRevokedSubscription("unsubscribe", handle, subscriptions[1].Handle)
		if unsubscribed.Code != "ok" && (unsubscribed.Outcome != "rejected" || unsubscribed.Code != "context_domain_unavailable" || string(unsubscribed.Value) != "null") {
			t.Error("revoked authenticated child subscription did not join")
			return
		}
		if unsubscribed.Code == "context_domain_unavailable" {
			nativeLiveWrite(t, fixture.Directory, "identity-subscription.json", map[string]any{"phase": "cleanup-already-joined"})
		}
		result := contextOperationResult{SchemaVersion: "1.0.0", Kind: "plugin-operation-result", Owner: invocation.Owner, OperationHandle: handle, Outcome: "completed", Value: contextJSON(map[string]any{"caller": invocation.Operation.Caller.PrincipalID, "project": invocation.Operation.Scope.ProjectID})}
		if nc.Publish(bootstrap.Context.Transport.ResultSubject, contextJSON(result)) != nil || nc.FlushTimeout(time.Second) != nil {
			t.Error("identity result failed")
		}
	}()
	return func() {
		nc.Close()
		nativeIdentityJoinTLS(t, dialer, fixture.Directory)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("identity child worker did not join")
			<-done
		}
	}
}

func nativeIdentityJoinTLS(t *testing.T, dialer *localtls.Dialer, directory string) {
	t.Helper()
	if dialer == nil {
		return
	}
	for attempt := uint64(0); dialer.Close() != nil; attempt++ {
		if attempt == 0 {
			t.Error("original identity TLS sockets remain owned pending recovery")
		}
		nativeSubscriptionLiveCleanupState(directory, map[string]any{"phase": "cleanup-required", "attempt": attempt})
		for {
			raw, err := ReadOwnerPrivateFile(filepath.Join(directory, "fixture-cleanup.json"), 8192)
			var recovery struct {
				Attempt uint64 `json:"attempt"`
			}
			if err == nil && nativeLiveDecode(raw, &recovery) == nil && recovery.Attempt > attempt {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}
