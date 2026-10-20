package plugins

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"
)

// nativeCapabilityDelivery is private host preparation, not child authority.
type nativeCapabilityDelivery struct {
	authority                               *NativeContextAuthority
	owner                                   OwnerReference
	operation                               ContextOperationAdmission
	replySubject, requestID, envelopeDigest string
	serviceRequest                          []byte
}

func nativeAuthorityDigestMustCanonical(raw []byte) string {
	canonical, err := nativeAuthorityCanonical(raw)
	if err != nil {
		return ""
	}
	return nativeAuthorityDigest(canonical)
}

// NativeCapabilityServiceBinding is an enrolled host binding, never a label
// discovered from a response. Keys must verify every part against current trust.
type NativeCapabilityServiceBinding struct {
	ProfileID          string           `json:"profileId"`
	HubID              string           `json:"hubId"`
	ServiceID          string           `json:"serviceId"`
	ServiceInstanceID  string           `json:"serviceInstanceId"`
	ServiceIdentityRef ContextReference `json:"serviceIdentityRef"`
	SigningKeyRef      ContextReference `json:"signingKeyRef"`
}
type NativeCapabilityServiceKeys interface {
	// Resolve the current exact enrolled service association and the
	// agentmux-capability-service-response-v1 signing purpose.
	CurrentServiceKey(context.Context, NativeCapabilityServiceBinding) (NativeAuthorityKey, error)
}

// ExchangeCapability returns the signed wrapper, not its private payload. The
// original transport remains owned by the host until gateway Close joins calls.
type NativeCapabilityExchange interface {
	ExchangeCapability(context.Context, string, []byte) ([]byte, error)
}
type NativeCapabilityRoute struct {
	BindingID, RequestContractID, ReplyContractID string
	Service                                       NativeCapabilityServiceBinding
	Keys                                          NativeCapabilityServiceKeys
	Exchange                                      NativeCapabilityExchange
}
type NativeCapabilityGateway struct {
	authority *NativeContextAuthority
	routes    map[string]NativeCapabilityRoute
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	closing   bool
	active    int
	joined    chan struct{}
	once      sync.Once
}

func (NativeCapabilityGateway) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private native capability gateway]")
}
func (NativeCapabilityGateway) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-native-capability-gateway"}`), nil
}
func NewNativeCapabilityGateway(authority *NativeContextAuthority, routes []NativeCapabilityRoute) (*NativeCapabilityGateway, error) {
	fail := pluginError("capability_service_configuration_invalid")
	if authority == nil || len(routes) == 0 || len(routes) > 64 {
		return nil, fail
	}
	owned := map[string]NativeCapabilityRoute{}
	for _, r := range routes {
		s := r.Service
		if !registryIdentifier.MatchString(r.BindingID) || !registryIdentifier.MatchString(r.RequestContractID) || !registryIdentifier.MatchString(r.ReplyContractID) || owned[r.BindingID].BindingID != "" || s.ProfileID != authority.client.options.ProfileID || s.HubID != authority.client.options.HubID || !registryIdentifier.MatchString(s.ServiceID) || !registryIdentifier.MatchString(s.ServiceInstanceID) || !contextReferenceValid(s.ServiceIdentityRef) || !contextReferenceValid(s.SigningKeyRef) || s.ServiceIdentityRef.OwnerHubID != s.HubID || s.SigningKeyRef.OwnerHubID != s.HubID || nilContextDependency(r.Keys) || nilContextDependency(r.Exchange) {
			return nil, fail
		}
		owned[r.BindingID] = r
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &NativeCapabilityGateway{authority: authority, routes: owned, ctx: ctx, cancel: cancel, joined: make(chan struct{})}, nil
}
func (g *NativeCapabilityGateway) finish() {
	g.mu.Lock()
	g.active--
	if g.closing && g.active == 0 {
		g.once.Do(func() { close(g.joined) })
	}
	g.mu.Unlock()
}
func (g *NativeCapabilityGateway) Close(ctx context.Context) error {
	if ctx == nil {
		return pluginError("capability_cleanup_incomplete")
	}
	g.mu.Lock()
	g.closing = true
	g.cancel()
	if g.active == 0 {
		g.once.Do(func() { close(g.joined) })
	}
	g.mu.Unlock()
	select {
	case <-g.joined:
		return nil
	case <-ctx.Done():
		return pluginError("capability_cleanup_incomplete")
	}
}
func nativeCapabilityEqual(a, b []byte) bool {
	left, e1 := nativeAuthorityCanonicalLimit(a, nativeCapabilityRequestLimit)
	right, e2 := nativeAuthorityCanonicalLimit(b, nativeCapabilityRequestLimit)
	return e1 == nil && e2 == nil && bytes.Equal(left, right)
}
func (g *NativeCapabilityGateway) Domain(ctx context.Context, approved ContextApprovedEnvelope) ([]byte, error) {
	fail := func() ([]byte, error) { return nil, pluginError("capability_outcome_unavailable") }
	if ctx == nil || ctx.Err() != nil {
		return fail()
	}
	approved = approved.Clone()
	delivery := approved.delivery
	if delivery == nil || delivery.authority != g.authority || delivery.envelopeDigest == "" || nativeAuthorityDigest(approved.Envelope) != delivery.envelopeDigest {
		return fail()
	}
	route, ok := g.routes[approved.BindingID]
	if !ok {
		return fail()
	}
	g.mu.Lock()
	if g.closing || g.active >= contextServiceLimit {
		g.mu.Unlock()
		return fail()
	}
	g.active++
	g.mu.Unlock()
	defer g.finish()
	work, cancel := context.WithTimeout(ctx, contextCallBudget)
	canceled := make(chan struct{})
	stop := context.AfterFunc(g.ctx, func() { cancel(); close(canceled) })
	defer func() {
		if !stop() {
			<-canceled
		}
		cancel()
	}()
	state, err := g.authority.instance(delivery.owner)
	if err != nil {
		return fail()
	}
	if g.authority.Recheck(work, delivery.owner, state.facts.admission, &delivery.operation) != nil {
		return fail()
	}
	var envelope struct {
		ContractID           string          `json:"contractId"`
		DestinationHubID     string          `json:"destinationHubId"`
		DestinationServiceID string          `json:"destinationServiceId"`
		Operation            json.RawMessage `json:"operation"`
		Payload              json.RawMessage `json:"payload"`
		Attestation          json.RawMessage `json:"ingressAttestation"`
	}
	if json.Unmarshal(approved.Envelope, &envelope) != nil || envelope.ContractID != route.RequestContractID || envelope.DestinationHubID != route.Service.HubID || envelope.DestinationServiceID != route.Service.ServiceID {
		return fail()
	}
	resource, err := nativeAuthorityReference(fieldsForClaim(envelope.Payload, "resourceRef"))
	if err != nil || resource.OwnerHubID != route.Service.HubID || !slices.Contains(state.facts.resources[approved.BindingID], resource.ID) {
		return fail()
	}
	operationIDRaw := fieldsForClaim(envelope.Operation, "operationId")
	scope := fieldsForClaim(envelope.Operation, "scope")
	var operationID, deadlineText, attestationExpiry string
	if json.Unmarshal(operationIDRaw, &operationID) != nil || json.Unmarshal(fieldsForClaim(envelope.Operation, "deadline"), &deadlineText) != nil || json.Unmarshal(fieldsForClaim(fieldsForClaim(envelope.Attestation, "claims"), "expiresAt"), &attestationExpiry) != nil {
		return fail()
	}
	operationDeadline, err := nativeAuthorityTime(deadlineText)
	if err != nil {
		return fail()
	}
	attestationDeadline, err := nativeAuthorityTime(attestationExpiry)
	if err != nil {
		return fail()
	}
	client := g.authority.client
	request := bytes.Clone(delivery.serviceRequest)
	if nativeCapabilitySchema("capability-service-request", request) != nil {
		return fail()
	}
	requestClaimsRaw := fieldsForClaim(request, "claims")
	var requestClaims map[string]json.RawMessage
	_ = json.Unmarshal(requestClaimsRaw, &requestClaims)
	expectedClaims := map[string]any{"purpose": "agentmux-capability-service-request-v1", "requestId": delivery.requestID, "profileId": client.options.ProfileID, "hubId": client.options.HubID, "authorityId": client.options.AuthorityID, "serviceId": route.Service.ServiceID, "requestContractId": route.RequestContractID, "replyContractId": route.ReplyContractID, "operationId": operationID, "owner": delivery.owner, "resourceRef": resource, "scope": json.RawMessage(scope), "replySubject": delivery.replySubject, "signingKeyRef": client.options.ResponseSigningRef, "hostTransportRef": client.options.RequestSigningRef, "nativeFactsDigest": state.facts.digest, "envelopeBytes": base64.StdEncoding.EncodeToString(approved.Envelope)}
	for field, want := range expectedClaims {
		if !nativeCapabilityEqual(requestClaims[field], contextJSON(want)) {
			return fail()
		}
	}
	var requestIssuedText, requestUntilText, requestSignature string
	if json.Unmarshal(requestClaims["issuedAt"], &requestIssuedText) != nil || json.Unmarshal(requestClaims["validUntil"], &requestUntilText) != nil || json.Unmarshal(fieldsForClaim(request, "signature"), &requestSignature) != nil {
		return fail()
	}
	requestIssued, e1 := nativeAuthorityTime(requestIssuedText)
	requestUntil, e2 := nativeAuthorityTime(requestUntilText)
	if e1 != nil || e2 != nil {
		return fail()
	}
	requestSignatureBytes, err := base64.RawURLEncoding.Strict().DecodeString(requestSignature)
	if err != nil || len(requestSignatureBytes) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(requestSignatureBytes) != requestSignature {
		return fail()
	}
	requestSigned, err := nativeAuthorityCanonicalLimit(requestClaimsRaw, nativeCapabilityRequestLimit)
	if err != nil {
		return fail()
	}
	key, err := client.key(work, client.options.ResponseSigningRef, "agentmux-capability-service-request-v1")
	if err != nil || !ed25519.Verify(key.PublicKey, requestSigned, requestSignatureBytes) {
		return fail()
	}
	now := client.now()
	deadline, _ := work.Deadline()
	deadline = minTime(deadline, minTime(operationDeadline, minTime(attestationDeadline, key.ExpiresAt))).Truncate(time.Microsecond)
	if requestIssued.After(now) || requestIssued.Before(key.NotBefore) || !requestIssued.Before(requestUntil) || requestUntil.Sub(requestIssued) > contextCallBudget || requestUntil.After(deadline) || !now.Before(requestUntil) || work.Err() != nil {
		return fail()
	}
	deadline = requestUntil
	requestCanonical, err := nativeAuthorityCanonicalLimit(request, nativeCapabilityRequestLimit)
	if err != nil {
		return fail()
	}
	response, err := route.Exchange.ExchangeCapability(work, delivery.replySubject, request)
	if err != nil || work.Err() != nil || nativeCapabilitySchema("capability-service-response", response) != nil {
		return fail()
	}
	claimsRaw := fieldsForClaim(response, "claims")
	var claims map[string]json.RawMessage
	_ = json.Unmarshal(claimsRaw, &claims)
	for _, name := range []string{"requestId", "profileId", "hubId", "authorityId", "serviceId", "requestContractId", "replyContractId", "operationId", "owner", "resourceRef", "scope", "replySubject"} {
		if !nativeCapabilityEqual(claims[name], contextJSON(requestClaims[name])) {
			return fail()
		}
	}
	var responseDigest, envelopeDigest, serviceInstance, issuedText, untilText, signature string
	if json.Unmarshal(claims["requestDigest"], &responseDigest) != nil || responseDigest != nativeAuthorityDigest(requestCanonical) || json.Unmarshal(claims["envelopeDigest"], &envelopeDigest) != nil || envelopeDigest != delivery.envelopeDigest || json.Unmarshal(claims["serviceInstanceId"], &serviceInstance) != nil || serviceInstance != route.Service.ServiceInstanceID {
		return fail()
	}
	signer, e1 := nativeAuthorityReference(claims["signingKeyRef"])
	identity, e2 := nativeAuthorityReference(claims["serviceIdentityRef"])
	authority, e3 := nativeAuthorityReference(claims["authorityRef"])
	if e1 != nil || e2 != nil || e3 != nil || signer != route.Service.SigningKeyRef || identity != route.Service.ServiceIdentityRef || authority.ID != client.options.AuthorityID || authority.OwnerHubID != client.options.HubID || authority.Revision < delivery.operation.AuthorityRef.Revision {
		return fail()
	}
	if json.Unmarshal(claims["issuedAt"], &issuedText) != nil || json.Unmarshal(claims["validUntil"], &untilText) != nil || json.Unmarshal(fieldsForClaim(response, "signature"), &signature) != nil {
		return fail()
	}
	issued, e1 := nativeAuthorityTime(issuedText)
	until, e2 := nativeAuthorityTime(untilText)
	if e1 != nil || e2 != nil {
		return fail()
	}
	signatureBytes, err := base64.RawURLEncoding.Strict().DecodeString(signature)
	if err != nil || len(signatureBytes) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signatureBytes) != signature {
		return fail()
	}
	signed, err := nativeAuthorityCanonical(claimsRaw)
	if err != nil {
		return fail()
	}
	serviceKey, err := route.Keys.CurrentServiceKey(work, route.Service)
	observed := client.now()
	if err == nil && serviceKey.AuthoritySequence <= maxGeneration {
		client.observeSequence(serviceKey.AuthoritySequence)
	}
	if err != nil || serviceKey.AuthoritySequence > maxGeneration || len(serviceKey.PublicKey) != ed25519.PublicKeySize || work.Err() != nil || observed.Before(serviceKey.NotBefore) || !observed.Before(serviceKey.ExpiresAt) || !ed25519.Verify(serviceKey.PublicKey, signed, signatureBytes) {
		return fail()
	}
	observed = client.now()
	if issued.Before(now.Truncate(time.Microsecond)) || issued.After(observed) || issued.Before(serviceKey.NotBefore) || !issued.Before(until) || !observed.Before(until) || until.After(deadline) || until.After(serviceKey.ExpiresAt) {
		return fail()
	}
	authoritySequence, err := g.authority.recheckWithSequence(work, delivery.owner, state.facts.admission, &delivery.operation)
	if err != nil || work.Err() != nil || !client.now().Before(until) {
		return fail()
	}
	// The authority recheck may await I/O. Do not keep service-key trust from
	// before that wait as the final disclosure gate.
	serviceKey, err = route.Keys.CurrentServiceKey(work, route.Service)
	observed = client.now()
	if err == nil && serviceKey.AuthoritySequence <= maxGeneration {
		client.observeSequence(serviceKey.AuthoritySequence)
	}
	if err != nil || serviceKey.AuthoritySequence > maxGeneration || authoritySequence < client.sequence.Load() || len(serviceKey.PublicKey) != ed25519.PublicKeySize || observed.Before(serviceKey.NotBefore) || !observed.Before(serviceKey.ExpiresAt) || issued.Before(serviceKey.NotBefore) || until.After(serviceKey.ExpiresAt) || !ed25519.Verify(serviceKey.PublicKey, signed, signatureBytes) || work.Err() != nil || !nativeAuthorityLive(state.binding) || !client.now().Before(until) {
		return fail()
	}
	if authoritySequence < client.sequence.Load() {
		return fail()
	}
	return bytes.Clone(claims["payload"]), nil
}
