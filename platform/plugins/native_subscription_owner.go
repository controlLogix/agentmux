package plugins

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// A route names an explicitly selected source and borrows the original enrolled
// transport. The composition closes transports only after this owner joins.
type NativeConfigurationSubscriptionRoute struct {
	BindingID string
	Source    NativeConfigurationEventSource
	Service   NativeConfigurationServiceBinding
	Exchange  *NativeAuthorityNATSExchange
}
type nativeSubscriptionExchange interface {
	ExchangeSubscription(context.Context, string, []byte) ([]byte, error)
	ConfigurationReusable() bool
}
type nativeSubscriptionRoute struct {
	bindingID string
	source    NativeConfigurationEventSource
	service   NativeConfigurationServiceBinding
	exchange  nativeSubscriptionExchange
}

type NativeConfigurationSubscriptions struct {
	mu        sync.Mutex
	authority *NativeContextAuthority
	keys      nativeSubscriptionServiceKeys
	routes    map[string]nativeSubscriptionRoute
	leases    map[*nativeRemoteSubscription]bool
	lifetime  context.Context
	cancel    context.CancelFunc
	closing   bool
}

func (*NativeConfigurationSubscriptions) Format(s fmt.State, _ rune) {
	io.WriteString(s, "[private configuration subscription owner]")
}
func (*NativeConfigurationSubscriptions) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-configuration-subscriptions"}`), nil
}
func nativeSubscriptionRouteKey(binding, resource string) string { return binding + "\x00" + resource }
func NewNativeConfigurationSubscriptions(authority *NativeContextAuthority, keys *NativeEnrolledKeys, routes []NativeConfigurationSubscriptionRoute) (*NativeConfigurationSubscriptions, error) {
	if authority == nil || keys == nil {
		return nil, pluginError("context_subscription_unavailable")
	}
	inputs := make([]nativeSubscriptionRoute, 0, len(routes))
	for _, r := range routes {
		inputs = append(inputs, nativeSubscriptionRoute{r.BindingID, r.Source, r.Service, r.Exchange})
	}
	return newNativeConfigurationSubscriptions(authority, keys, inputs)
}
func newNativeConfigurationSubscriptions(authority *NativeContextAuthority, keys nativeSubscriptionServiceKeys, routes []nativeSubscriptionRoute) (*NativeConfigurationSubscriptions, error) {
	if authority == nil || authority.client == nil || nilContextDependency(keys) || len(routes) == 0 || len(routes) > 64 {
		return nil, pluginError("context_subscription_unavailable")
	}
	lifetime, cancel := context.WithCancel(context.Background())
	h := &NativeConfigurationSubscriptions{authority: authority, keys: keys, routes: map[string]nativeSubscriptionRoute{}, leases: map[*nativeRemoteSubscription]bool{}, lifetime: lifetime, cancel: cancel}
	for _, r := range routes {
		key := nativeSubscriptionRouteKey(r.bindingID, r.source.ConfigurationRef.ID)
		if !registryIdentifier.MatchString(r.bindingID) || !contextReferenceValid(r.source.ConfigurationRef) || r.source.ConfigurationRef.OwnerHubID != authority.client.options.HubID || r.service.ProfileID != authority.client.options.ProfileID || r.service.HubID != authority.client.options.HubID || !registryIdentifier.MatchString(r.service.ServiceInstanceID) || !contextReferenceValid(r.service.SigningKeyRef) || !contextReferenceValid(r.service.ServiceIdentityRef) || r.service.SigningKeyRef.OwnerHubID != r.service.HubID || r.service.ServiceIdentityRef.OwnerHubID != r.service.HubID || nilContextDependency(r.exchange) || h.routes[key].bindingID != "" {
			cancel()
			return nil, pluginError("context_subscription_unavailable")
		}
		if created, err := nativeAuthorityTime(r.source.StreamCreated); err != nil || created.After(time.Now()) {
			cancel()
			return nil, pluginError("context_subscription_unavailable")
		}
		h.routes[key] = r
	}
	return h, nil
}
func (h *NativeConfigurationSubscriptions) Subscribe(ctx context.Context, approved ContextApprovedEnvelope) (ContextSubscriptionLease, error) {
	fail := pluginError("context_subscription_unavailable")
	if h == nil || ctx == nil || ctx.Err() != nil {
		return nil, fail
	}
	proof := approved.subscription
	if proof == nil || proof.authority != h.authority || approved.BindingID != proof.bindingID || nativeAuthorityDigest(approved.Envelope) != proof.envelopeDigest {
		return nil, fail
	}
	state, err := h.authority.instance(proof.owner)
	if err != nil {
		return nil, fail
	}
	routeKey := nativeSubscriptionRouteKey(approved.BindingID, proof.filter.ResourceRef.ID)
	h.mu.Lock()
	route, ok := h.routes[routeKey]
	if h.closing || !ok || len(h.leases) >= 64 || route.source.ConfigurationRef.OwnerHubID != proof.filter.ResourceRef.OwnerHubID || proof.filter.ResourceRef.Revision < route.source.ConfigurationRef.Revision || route.source.SourceDigest != proof.filter.Cursor.SourceDigest || route.source.StreamCreated != proof.filter.Cursor.StreamCreated || route.source.SchemaRef != proof.filter.Filter.SchemaRef {
		h.mu.Unlock()
		return nil, fail
	}
	nonce, err := randomControlID()
	if err != nil {
		h.mu.Unlock()
		return nil, fail
	}
	lifetime, cancel := context.WithCancel(context.Background())
	l := &nativeRemoteSubscription{host: h, route: route, approved: approved.Clone(), binding: cloneContextBinding(state.binding), ctx: lifetime, cancel: cancel, openID: "request_" + nonce, cursor: proof.filter.Cursor, openDone: make(chan struct{}), monitorDone: make(chan struct{}), done: make(chan struct{}), activeDone: make(chan struct{})}
	close(l.activeDone)
	h.leases[l] = true
	h.mu.Unlock()
	go l.monitor()
	response, _, err := l.exchange(ctx, "open")
	if err == nil && response.Outcome != "opened" {
		err = fail
	}
	l.mu.Lock()
	if err == nil {
		l.leaseID = response.LeaseID
		l.until, _ = nativeAuthorityTime(response.ValidUntil)
		if ctx.Err() != nil || l.ctx.Err() != nil || !nativeAuthorityLive(l.binding) {
			err = fail
		}
	}
	l.mu.Unlock()
	close(l.openDone)
	if err != nil {
		l.cancel()
		l.startClose()
		return l, err
	}
	return l, nil
}
func (h *NativeConfigurationSubscriptions) Close(ctx context.Context) error {
	if h == nil {
		return nil
	}
	if ctx == nil {
		return pluginError("context_subscription_cleanup_incomplete")
	}
	h.mu.Lock()
	h.closing = true
	h.cancel()
	leases := make([]*nativeRemoteSubscription, 0, len(h.leases))
	for l := range h.leases {
		leases = append(leases, l)
	}
	h.mu.Unlock()
	for _, l := range leases {
		if err := l.Close(ctx); err != nil {
			return err
		}
	}
	return nil
}

type nativeRemoteSubscription struct {
	mu                                                sync.Mutex
	host                                              *NativeConfigurationSubscriptions
	route                                             nativeSubscriptionRoute
	approved                                          ContextApprovedEnvelope
	binding                                           ContextBinding
	ctx                                               context.Context
	cancel                                            context.CancelFunc
	openID                                            string
	leaseID                                           *string
	cursor                                            NativeConfigurationEventCursor
	until                                             time.Time
	openDone, monitorDone, done, activeDone, closeRun chan struct{}
	active                                            bool
	closing                                           bool
	closeErr                                          error
	openSent                                          bool
	openKey                                           NativeAuthorityKey
}

func (*nativeRemoteSubscription) Format(s fmt.State, _ rune) {
	io.WriteString(s, "[owned configuration subscription]")
}
func (*nativeRemoteSubscription) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"owned-configuration-subscription"}`), nil
}
func (l *nativeRemoteSubscription) Done() <-chan struct{} { return l.done }
func (l *nativeRemoteSubscription) monitor() {
	defer close(l.monitorDone)
	select {
	case <-l.openDone:
	case <-l.ctx.Done():
	case <-l.host.lifetime.Done():
	case <-l.binding.LifetimeDone:
	case <-l.binding.ParentLifetime:
	}
	l.mu.Lock()
	until := l.until
	l.mu.Unlock()
	timer := time.NewTimer(max(time.Until(until), 0))
	defer timer.Stop()
	select {
	case <-l.ctx.Done():
	case <-l.host.lifetime.Done():
	case <-l.binding.LifetimeDone:
	case <-l.binding.ParentLifetime:
	case <-timer.C:
	}
	l.cancel()
	l.startClose()
}
func (l *nativeRemoteSubscription) exchange(ctx context.Context, action string) (nativeSubscriptionResponse, []byte, error) {
	fail := func() (nativeSubscriptionResponse, []byte, error) {
		return nativeSubscriptionResponse{}, nil, pluginError("context_subscription_unavailable")
	}
	work, cancel := context.WithTimeout(ctx, contextCallBudget)
	defer cancel()
	var callbackDone chan struct{}
	var stop func() bool
	if action != "close" {
		callbackDone = make(chan struct{})
		stop = context.AfterFunc(l.ctx, func() { cancel(); close(callbackDone) })
		defer func() {
			if !stop() {
				<-callbackDone
			}
		}()
	}
	l.mu.Lock()
	cursor := l.cursor
	leaseID := l.leaseID
	until := l.until
	l.mu.Unlock()
	if action != "close" && !until.IsZero() {
		var capCancel context.CancelFunc
		work, capCancel = context.WithDeadline(work, until)
		defer capCancel()
	}
	client := l.host.authority.client
	var key NativeAuthorityKey
	var err error
	if action == "close" {
		l.mu.Lock()
		key = l.openKey
		l.mu.Unlock()
	} else {
		key, err = client.key(work, client.options.RequestSigningRef, "agentmux-native-authority-request-v1")
	}
	if err != nil || !bytes.Equal(key.PublicKey, client.private.Public().(ed25519.PublicKey)) {
		return fail()
	}
	deadline, _ := work.Deadline()
	if action != "close" {
		deadline = minTime(deadline, key.ExpiresAt)
	}
	if action == "open" {
		end, err := nativeSubscriptionEnvelopeDeadline(l.approved.Envelope)
		if err != nil {
			return fail()
		}
		deadline = minTime(deadline, end)
	}
	now := client.now()
	if !now.Before(deadline) || work.Err() != nil {
		return fail()
	}
	nonce, err := randomControlID()
	if err != nil {
		return fail()
	}
	claims, err := l.controlClaims(action, nonce, leaseID, cursor, now, deadline)
	if err != nil {
		return fail()
	}

	raw, err := nativeAuthoritySign(contextJSON(claims), client.private)
	if err != nil || nativeAuthoritySchema("configuration-subscription-control", raw) != nil {
		return fail()
	}
	if action == "open" {
		l.mu.Lock()
		l.openKey = key
		l.openSent = true
		l.mu.Unlock()
	}
	response, err := l.route.exchange.ExchangeSubscription(work, claims.ReplySubject, raw)
	if err != nil {
		return fail()
	}
	return verifyNativeSubscriptionResponse(work, response, raw, l.route.service, l.host.keys, client.sequence.Load())
}

func (l *nativeRemoteSubscription) controlClaims(action, nonce string, leaseID *string, cursor NativeConfigurationEventCursor, now, deadline time.Time) (nativeSubscriptionControl, error) {
	client := l.host.authority.client
	requestID := "request_" + nonce
	if action == "open" {
		requestID = l.openID
		nonce = l.openID[len("request_"):]
	}
	// The lease belongs to the prepared downstream subscription operation. Keep
	// the original upstream operation separately for per-event admission.
	var operationID string
	if json.Unmarshal(fieldsForClaim(fieldsForClaim(l.approved.Envelope, "operation"), "operationId"), &operationID) != nil || !registryIdentifier.MatchString(operationID) {
		return nativeSubscriptionControl{}, pluginError("context_subscription_unavailable")
	}
	claims := nativeSubscriptionControl{Purpose: "agentmux-configuration-subscription-control-v1", Action: action, RequestID: requestID, OpenRequestID: l.openID, LeaseID: leaseID, ProfileID: client.options.ProfileID, HubID: client.options.HubID, AuthorityID: client.options.AuthorityID, ReplySubject: client.replySubject(nonce), Owner: l.approved.subscription.owner, OperationID: operationID, ApprovedEnvelopeDigest: nativeAuthorityDigestMustCanonical(l.approved.Envelope), FilterDigest: l.approved.subscription.filter.FilterDigest, Cursor: cursor, SigningKeyRef: client.options.RequestSigningRef, IssuedAt: nativeAuthorityStamp(now), ExpiresAt: nativeAuthorityStamp(deadline)}
	if action == "open" {
		claims.SubscriptionEnvelopeBytes = base64.StdEncoding.EncodeToString(l.approved.Envelope)
	}
	return claims, nil
}
func (l *nativeRemoteSubscription) Next(ctx context.Context) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, pluginError("context_subscription_unavailable")
	}
	l.mu.Lock()
	if l.closing || l.active || !completed(l.openDone) || completed(l.done) {
		l.mu.Unlock()
		return nil, pluginError("context_subscription_unavailable")
	}
	l.active = true
	l.activeDone = make(chan struct{})
	l.mu.Unlock()
	work, cancel := context.WithCancel(ctx)
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(l.ctx, func() { cancel(); close(callbackDone) })
	response, event, err := l.exchange(work, "next")
	if err == nil && response.Outcome == "event" {
		_, err = l.host.authority.AdmitDomainEvent(work, l.approved.subscription.owner, cloneOperationAdmission(l.approved.subscription.operation), l.approved.Clone(), event)
	}
	if !stop() {
		<-callbackDone
	}
	if work.Err() != nil {
		err = pluginError("context_subscription_unavailable")
	}
	cancel()
	l.mu.Lock()
	if err == nil && response.Outcome == "event" && !l.closing && ctx.Err() == nil && l.ctx.Err() == nil {
		l.cursor = response.Cursor
	} else {
		err = pluginError("context_subscription_unavailable")
	}
	l.active = false
	close(l.activeDone)
	l.mu.Unlock()
	if err != nil {
		l.cancel()
		l.startClose()
		return nil, err
	}
	return bytes.Clone(event), nil
}
func (l *nativeRemoteSubscription) startClose() {
	l.mu.Lock()
	l.closing = true
	l.cancel()
	if completed(l.done) || l.closeRun != nil && !completed(l.closeRun) {
		l.mu.Unlock()
		return
	}
	l.closeRun = make(chan struct{})
	run := l.closeRun
	l.mu.Unlock()
	go l.closeOriginal(run)
}
func (l *nativeRemoteSubscription) closeOriginal(run chan struct{}) {
	defer close(run)
	work, cancel := context.WithTimeout(context.Background(), contextCallBudget)
	defer cancel()
	l.mu.Lock()
	active := l.activeDone
	l.mu.Unlock()
	for _, joined := range []<-chan struct{}{l.openDone, active, l.monitorDone} {
		select {
		case <-joined:
		case <-work.Done():
			l.mu.Lock()
			l.closeErr = pluginError("context_subscription_cleanup_incomplete")
			l.mu.Unlock()
			return
		}
	}
	l.mu.Lock()
	sent := l.openSent
	l.mu.Unlock()
	if !sent {
		l.mu.Lock()
		l.closeErr = nil
		close(l.done)
		l.mu.Unlock()
		l.host.mu.Lock()
		delete(l.host.leases, l)
		l.host.mu.Unlock()
		return
	}

	response, _, err := l.exchange(work, "close")
	l.mu.Lock()
	if err != nil || response.Outcome != "closed" || response.Joined == nil || !*response.Joined {
		l.closeErr = pluginError("context_subscription_cleanup_incomplete")
		l.mu.Unlock()
		return
	}
	l.closeErr = nil
	close(l.done)
	l.mu.Unlock()
	l.host.mu.Lock()
	delete(l.host.leases, l)
	l.host.mu.Unlock()
}
func (l *nativeRemoteSubscription) Close(ctx context.Context) error {
	if ctx == nil {
		return pluginError("context_subscription_cleanup_incomplete")
	}
	l.startClose()
	l.mu.Lock()
	run := l.closeRun
	l.mu.Unlock()
	select {
	case <-run:
	case <-ctx.Done():
		return pluginError("context_subscription_cleanup_incomplete")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !completed(l.done) {
		return pluginError("context_subscription_cleanup_incomplete")
	}
	return l.closeErr
}
