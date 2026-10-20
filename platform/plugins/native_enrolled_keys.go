package plugins

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

// NativeEnrolledKeyOptions comes from trusted provisioning and recovery, never
// from a response. MinimumSequence must include the host's retained recovery floor.
type NativeEnrolledKeyOptions struct {
	ProfileID         string           `json:"profileId"`
	HubID             string           `json:"hubId"`
	AuthorityID       string           `json:"authorityId"`
	OrganizationID    string           `json:"organizationId"`
	Stream            string           `json:"stream"`
	Domain            string           `json:"domain"`
	StreamCreated     time.Time        `json:"streamCreated"`
	MinimumSequence   uint64           `json:"minimumSequence"`
	MaxBytes          int64            `json:"maxBytes"`
	Replicas          int              `json:"replicas"`
	HostTransportRef  ContextReference `json:"hostTransportRef"`
	HostIdentityRef   ContextReference `json:"hostIdentityRef"`
	IssuerRef         ContextReference `json:"issuerRef"`
	IssuerIdentityRef ContextReference `json:"issuerIdentityRef"`
	IssuerInstanceID  string           `json:"issuerInstanceId"`
}

// NativeEnrolledKeys reads the existing identity aggregate through a borrowed
// TLS transport. The host closes that original transport after callers join.
// Successful lookups are never cached as permission for a later request.
type NativeEnrolledKeys struct {
	transport *NativeAuthorityNATSExchange
	options   NativeEnrolledKeyOptions
	mu        sync.Mutex
	sequence  uint64
	digest    string
	now       func() time.Time
}

func (NativeEnrolledKeys) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private enrolled key source]")
}
func (NativeEnrolledKeys) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-enrolled-key-source"}`), nil
}

var nativeIdentityStream = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func NewNativeEnrolledKeys(transport *NativeAuthorityNATSExchange, options NativeEnrolledKeyOptions) (*NativeEnrolledKeys, error) {
	fail := pluginError("context_authority_configuration_invalid")
	for _, value := range []string{options.ProfileID, options.HubID, options.AuthorityID, options.OrganizationID, options.IssuerInstanceID} {
		if !registryIdentifier.MatchString(value) {
			return nil, fail
		}
	}
	for _, ref := range []ContextReference{options.HostTransportRef, options.HostIdentityRef, options.IssuerRef, options.IssuerIdentityRef} {
		if !contextReferenceValid(ref) || ref.OwnerHubID != options.HubID {
			return nil, fail
		}
	}
	if transport == nil || (options.Domain != "" && !registryIdentifier.MatchString(options.Domain)) || !nativeIdentityStream.MatchString(options.Stream) || options.StreamCreated.IsZero() || options.MinimumSequence > 9007199254740991 || options.MaxBytes <= 131072 || options.MaxBytes > 107374182400 || (options.Replicas != 1 && options.Replicas != 3) {
		return nil, fail
	}
	transport.mu.Lock()
	valid := !transport.closing && transport.conn != nil && transport.conn.IsConnected() && !transport.failed.Load()
	if valid {
		state, err := transport.conn.TLSConnectionState()
		valid = err == nil && state.HandshakeComplete && len(state.VerifiedChains) > 0
	}
	transport.mu.Unlock()
	if !valid {
		return nil, fail
	}
	return &NativeEnrolledKeys{transport: transport, options: options, sequence: options.MinimumSequence, now: time.Now}, nil
}
func (k *NativeEnrolledKeys) subject() string {
	o := k.options
	return "amx.v1.h." + o.HubID + ".o." + o.OrganizationID + ".p._.w._.ledger.identity." + o.AuthorityID
}
func (k *NativeEnrolledKeys) request(ctx context.Context, subject string, payload []byte) (result []byte, requestError error) {
	t := k.transport
	fail := pluginError("context_authority_unavailable")
	t.mu.Lock()
	if t.closing || t.active >= contextServiceLimit || t.failed.Load() || t.conn == nil || !t.conn.IsConnected() {
		t.mu.Unlock()
		return nil, fail
	}
	t.active++
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		t.active--
		if t.closing && t.active == 0 {
			t.joinOnce.Do(func() { close(t.joined) })
		}
		t.mu.Unlock()
	}()
	nonce, err := randomControlID()
	if err != nil {
		return nil, fail
	}
	reply := t.replyPrefix + "." + nonce
	sub, err := t.conn.SubscribeSync(reply)
	if err != nil {
		return nil, fail
	}
	defer func() {
		if sub.Unsubscribe() != nil {
			t.failed.Store(true)
			result = nil
			requestError = fail
		}
	}()
	if sub.SetPendingLimits(1, nativeCapabilityRequestLimit) != nil || t.conn.FlushWithContext(ctx) != nil || t.conn.PublishRequest(subject, reply, payload) != nil {
		return nil, fail
	}
	msg, err := sub.NextMsgWithContext(ctx)
	if err != nil || ctx.Err() != nil || t.failed.Load() || msg.Subject != reply || len(msg.Header) != 0 || len(msg.Data) > nativeCapabilityRequestLimit || strictDocument(msg.Data) != nil {
		return nil, fail
	}
	var body struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(msg.Data, &body) != nil || (len(body.Error) > 0 && !bytes.Equal(body.Error, []byte("null"))) {
		return nil, fail
	}
	return bytes.Clone(msg.Data), nil
}
func (k *NativeEnrolledKeys) api() string {
	if k.options.Domain != "" {
		return "$JS." + k.options.Domain + ".API."
	}
	return "$JS.API."
}
func (k *NativeEnrolledKeys) stream(ctx context.Context) (*nats.StreamInfo, error) {
	fail := pluginError("context_authority_unavailable")
	raw, err := k.request(ctx, k.api()+"STREAM.INFO."+k.options.Stream, []byte(`{}`))
	if err != nil {
		return nil, fail
	}
	return k.validateStream(raw)
}
func (k *NativeEnrolledKeys) validateStream(raw []byte) (*nats.StreamInfo, error) {
	fail := pluginError("context_authority_unavailable")
	var info nats.StreamInfo
	var extra struct {
		Config struct {
			Schedules bool `json:"allow_msg_schedules"`
			Counter   bool `json:"allow_msg_counter"`
		} `json:"config"`
	}
	if json.Unmarshal(raw, &info) != nil || json.Unmarshal(raw, &extra) != nil {
		return nil, fail
	}
	c, s, o := info.Config, info.State, k.options
	if c.Name != o.Stream || len(c.Subjects) != 1 || c.Subjects[0] != k.subject() || !info.Created.Equal(o.StreamCreated) || c.Storage != nats.FileStorage || c.Retention != nats.LimitsPolicy || c.Discard != nats.DiscardNew || c.MaxAge != 0 || c.MaxBytes != o.MaxBytes || c.MaxMsgSize != 65536 || c.MaxMsgs != -1 || c.MaxMsgsPerSubject != -1 || !c.DenyDelete || !c.DenyPurge || c.AllowRollup || c.AllowMsgTTL || c.Replicas != o.Replicas || c.Mirror != nil || len(c.Sources) != 0 || c.SubjectTransform != nil || c.RePublish != nil || c.NoAck || c.Sealed || extra.Config.Schedules || extra.Config.Counter || s.LastSeq == 0 || s.LastSeq > 9007199254740991 || s.Msgs != s.LastSeq || s.FirstSeq != 1 || s.NumDeleted != 0 || len(s.Deleted) != 0 || s.Bytes > s.Msgs*131072 {
		return nil, fail
	}
	return &info, nil
}
func (k *NativeEnrolledKeys) current(ctx context.Context) ([]byte, error) {
	raw, _, err := k.currentWithSequence(ctx)
	return raw, err
}
func (k *NativeEnrolledKeys) currentWithSequence(ctx context.Context) ([]byte, uint64, error) {
	fail := pluginError("context_authority_unavailable")
	before, err := k.stream(ctx)
	if err != nil {
		return nil, 0, fail
	}
	payload, _ := json.Marshal(map[string]string{"last_by_subj": k.subject()})
	raw, err := k.request(ctx, k.api()+"STREAM.MSG.GET."+k.options.Stream, payload)
	if err != nil {
		return nil, 0, fail
	}
	var response struct {
		Message struct {
			Subject  string `json:"subject"`
			Sequence uint64 `json:"seq"`
			Data     string `json:"data"`
			Headers  string `json:"hdrs"`
		} `json:"message"`
	}
	if json.Unmarshal(raw, &response) != nil {
		return nil, 0, fail
	}
	m := response.Message
	record, err := base64.StdEncoding.Strict().DecodeString(m.Data)
	if err != nil || base64.StdEncoding.EncodeToString(record) != m.Data || len(record) > nativeAuthorityLimit || m.Subject != k.subject() || m.Sequence < before.State.LastSeq || m.Sequence > 9007199254740991 {
		return nil, 0, fail
	}
	after, err := k.stream(ctx)
	if err != nil || after.State.LastSeq != m.Sequence {
		return nil, 0, fail
	}
	if nativeAuthoritySchema("record", record) != nil {
		return nil, 0, fail
	}
	var owner struct {
		Hub       string          `json:"ownerHubId"`
		Domain    string          `json:"ownerDomain"`
		ID        string          `json:"entityId"`
		Kind      string          `json:"entityKind"`
		Version   uint64          `json:"entityVersion"`
		Previous  uint64          `json:"previousRevision"`
		State     json.RawMessage `json:"state"`
		Operation struct {
			Scope struct {
				Organization string  `json:"organizationId"`
				Project      *string `json:"projectId"`
				Workspace    *string `json:"workspaceId"`
			} `json:"scope"`
		} `json:"operation"`
	}
	if json.Unmarshal(record, &owner) != nil || owner.Hub != k.options.HubID || owner.Domain != "identity" || owner.ID != k.options.AuthorityID || owner.Kind != "identity-authority" || owner.Version != m.Sequence || owner.Previous != m.Sequence-1 || owner.Operation.Scope.Organization != k.options.OrganizationID || owner.Operation.Scope.Project != nil || owner.Operation.Scope.Workspace != nil || nativeAuthoritySchema("state", owner.State) != nil {
		return nil, 0, fail
	}
	canonical, err := nativeAuthorityCanonical(record)
	if err != nil {
		return nil, 0, fail
	}
	digest := nativeAuthorityDigest(canonical)
	k.mu.Lock()
	defer k.mu.Unlock()
	if m.Sequence < k.sequence || (m.Sequence == k.sequence && k.digest != "" && k.digest != digest) {
		return nil, 0, fail
	}
	k.sequence, k.digest = m.Sequence, digest
	return bytes.Clone(owner.State), m.Sequence, nil
}

type nativeEnrolledEntry struct {
	Ref         ContextReference `json:"ref"`
	IdentityRef ContextReference `json:"identityRef"`
	IssuerRef   ContextReference `json:"issuerRef"`
	InstanceID  string           `json:"instanceId"`
	PublicKey   string           `json:"publicKey"`
	Kind        string           `json:"kind"`
	Method      string           `json:"method"`
	Status      string           `json:"status"`
	IssuedAt    string           `json:"issuedAt"`
	ExpiresAt   string           `json:"expiresAt"`
}

func (k *NativeEnrolledKeys) resolve(raw []byte, ref ContextReference, purpose string, service *NativeCapabilityServiceBinding) (NativeAuthorityKey, error) {
	fail := pluginError("context_authority_unavailable")
	if nativeAuthoritySchema("state", raw) != nil {
		return NativeAuthorityKey{}, fail
	}
	var state map[string]json.RawMessage
	if json.Unmarshal(raw, &state) != nil {
		return NativeAuthorityKey{}, fail
	}
	var profile, org string
	_ = json.Unmarshal(state["profileId"], &profile)
	_ = json.Unmarshal(state["organizationId"], &org)
	if profile != k.options.ProfileID || org != k.options.OrganizationID {
		return NativeAuthorityKey{}, fail
	}
	index := map[string]map[ContextReference]nativeEnrolledEntry{}
	seen := map[string]bool{}
	now := k.now()
	for _, collection := range []string{"identities", "issuers", "transports", "memberships", "grants", "approvals"} {
		var entries []nativeEnrolledEntry
		if json.Unmarshal(state[collection], &entries) != nil {
			return NativeAuthorityKey{}, fail
		}
		index[collection] = map[ContextReference]nativeEnrolledEntry{}
		for _, entry := range entries {
			id := entry.Ref.OwnerHubID + "/" + entry.Ref.ID
			if entry.Ref.OwnerHubID != k.options.HubID || seen[id] {
				return NativeAuthorityKey{}, fail
			}
			seen[id] = true
			if collection == "issuers" || collection == "transports" || collection == "grants" || collection == "approvals" {
				start, e1 := nativeAuthorityTime(entry.IssuedAt)
				end, e2 := nativeAuthorityTime(entry.ExpiresAt)
				if e1 != nil || e2 != nil || !start.Before(end) {
					return NativeAuthorityKey{}, fail
				}
			}
			index[collection][entry.Ref] = entry
		}
	}
	var entry nativeEnrolledEntry
	switch purpose {
	case "agentmux-native-authority-request-v1":
		if service != nil || ref != k.options.HostTransportRef {
			return NativeAuthorityKey{}, fail
		}
		entry = index["transports"][ref]
		if entry.IdentityRef != k.options.HostIdentityRef || entry.IssuerRef != k.options.IssuerRef || entry.Method != "nats-credential-mapping" {
			return NativeAuthorityKey{}, fail
		}
		issuer := index["issuers"][entry.IssuerRef]
		if !nativeEnrolledActive(issuer, now) || issuer.IdentityRef != k.options.IssuerIdentityRef || issuer.InstanceID != k.options.IssuerInstanceID || !nativeEnrolledIdentity(index["identities"][issuer.IdentityRef]) {
			return NativeAuthorityKey{}, fail
		}
	case "agentmux-native-authority-response-v1", "agentmux-capability-service-request-v1":
		if service != nil || ref != k.options.IssuerRef {
			return NativeAuthorityKey{}, fail
		}
		entry = index["issuers"][ref]
		if entry.IdentityRef != k.options.IssuerIdentityRef || entry.InstanceID != k.options.IssuerInstanceID {
			return NativeAuthorityKey{}, fail
		}
	case "agentmux-capability-service-response-v1", "agentmux-configuration-response-v1", "agentmux-configuration-subscription-response-v1":
		if service == nil || service.ProfileID != profile || service.HubID != k.options.HubID || ref != service.SigningKeyRef {
			return NativeAuthorityKey{}, fail
		}
		entry = index["issuers"][ref]
		if entry.IdentityRef != service.ServiceIdentityRef || entry.InstanceID != service.ServiceInstanceID {
			return NativeAuthorityKey{}, fail
		}
	default:
		return NativeAuthorityKey{}, fail
	}
	if !nativeEnrolledActive(entry, now) || !nativeEnrolledIdentity(index["identities"][entry.IdentityRef]) {
		return NativeAuthorityKey{}, fail
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(entry.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(public) != entry.PublicKey {
		return NativeAuthorityKey{}, fail
	}
	start, _ := nativeAuthorityTime(entry.IssuedAt)
	end, _ := nativeAuthorityTime(entry.ExpiresAt)
	if purpose == "agentmux-native-authority-request-v1" {
		issuer := index["issuers"][entry.IssuerRef]
		issuerStart, _ := nativeAuthorityTime(issuer.IssuedAt)
		issuerEnd, _ := nativeAuthorityTime(issuer.ExpiresAt)
		if issuerStart.After(start) {
			start = issuerStart
		}
		end = minTime(end, issuerEnd)
	}
	observed := k.now()
	if observed.Before(start) || !observed.Before(end) {
		return NativeAuthorityKey{}, fail
	}
	return NativeAuthorityKey{PublicKey: bytes.Clone(public), NotBefore: start, ExpiresAt: end}, nil
}
func nativeEnrolledActive(entry nativeEnrolledEntry, now time.Time) bool {
	start, e1 := nativeAuthorityTime(entry.IssuedAt)
	end, e2 := nativeAuthorityTime(entry.ExpiresAt)
	return entry.Status == "active" && e1 == nil && e2 == nil && !now.Before(start) && now.Before(end)
}
func nativeEnrolledIdentity(entry nativeEnrolledEntry) bool {
	return entry.Status == "active" && entry.Kind == "service"
}
func (k *NativeEnrolledKeys) Current(ctx context.Context, profile, hub string, ref ContextReference, purpose string) (NativeAuthorityKey, error) {
	if ctx == nil || ctx.Err() != nil || profile != k.options.ProfileID || hub != k.options.HubID {
		return NativeAuthorityKey{}, pluginError("context_authority_unavailable")
	}
	work, cancel := context.WithTimeout(ctx, contextCallBudget)
	defer cancel()
	state, sequence, err := k.currentWithSequence(work)
	if err != nil {
		return NativeAuthorityKey{}, err
	}
	key, err := k.resolve(state, ref, purpose, nil)
	k.mu.Lock()
	stale := sequence < k.sequence
	k.mu.Unlock()
	if work.Err() != nil || stale {
		return NativeAuthorityKey{}, pluginError("context_authority_unavailable")
	}
	key.AuthoritySequence = sequence
	return key, err
}
func (k *NativeEnrolledKeys) CurrentServiceKey(ctx context.Context, binding NativeCapabilityServiceBinding) (NativeAuthorityKey, error) {
	return k.currentBoundServiceKey(ctx, binding, "agentmux-capability-service-response-v1")
}

// CurrentConfigurationKey checks the exact enrolled configuration service
// identity and instance using the same fresh retained identity aggregate.
func (k *NativeEnrolledKeys) CurrentConfigurationKey(ctx context.Context, binding NativeConfigurationServiceBinding) (NativeAuthorityKey, error) {
	// Only the existing enrolled issuer/identity/instance key association is
	// shared with capability replies. No capability grant or route is reused.
	service := NativeCapabilityServiceBinding{ProfileID: binding.ProfileID, HubID: binding.HubID, ServiceID: "configuration-owner", ServiceInstanceID: binding.ServiceInstanceID, ServiceIdentityRef: binding.ServiceIdentityRef, SigningKeyRef: binding.SigningKeyRef}
	return k.currentBoundServiceKey(ctx, service, "agentmux-configuration-response-v1")
}

func (k *NativeEnrolledKeys) CurrentConfigurationSubscriptionKey(ctx context.Context, binding NativeConfigurationServiceBinding) (NativeAuthorityKey, error) {
	service := NativeCapabilityServiceBinding{ProfileID: binding.ProfileID, HubID: binding.HubID, ServiceID: "configuration-owner", ServiceInstanceID: binding.ServiceInstanceID, ServiceIdentityRef: binding.ServiceIdentityRef, SigningKeyRef: binding.SigningKeyRef}
	return k.currentBoundServiceKey(ctx, service, "agentmux-configuration-subscription-response-v1")
}

func (k *NativeEnrolledKeys) currentBoundServiceKey(ctx context.Context, binding NativeCapabilityServiceBinding, purpose string) (NativeAuthorityKey, error) {
	if ctx == nil || ctx.Err() != nil || !registryIdentifier.MatchString(binding.ServiceID) || !registryIdentifier.MatchString(binding.ServiceInstanceID) || !contextReferenceValid(binding.ServiceIdentityRef) || !contextReferenceValid(binding.SigningKeyRef) {
		return NativeAuthorityKey{}, pluginError("context_authority_unavailable")
	}
	work, cancel := context.WithTimeout(ctx, contextCallBudget)
	defer cancel()
	state, sequence, err := k.currentWithSequence(work)
	if err != nil {
		return NativeAuthorityKey{}, err
	}
	key, err := k.resolve(state, binding.SigningKeyRef, purpose, &binding)
	k.mu.Lock()
	stale := sequence < k.sequence
	k.mu.Unlock()
	if work.Err() != nil || stale {
		return NativeAuthorityKey{}, pluginError("context_authority_unavailable")
	}
	key.AuthoritySequence = sequence
	return key, err
}
