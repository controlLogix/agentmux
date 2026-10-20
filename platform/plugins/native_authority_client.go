package plugins

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sync/atomic"
	"time"
)

// NativeAuthorityExchange owns its connection and callbacks. Exchange must
// honor cancellation and return only after this request's local work joins.
// It must not retry, log private frames, or use a child-selected destination.
type NativeAuthorityExchange interface {
	Exchange(context.Context, string, []byte) ([]byte, error)
}

// NativeAuthorityKeySource resolves CURRENT enrolled/pinned trust for this
// exact profile, hub, key reference and purpose. It is not a key URL fetcher.
// Production enrollment must implement this interface; fixtures are not trust.
type NativeAuthorityKeySource interface {
	Current(context.Context, string, string, ContextReference, string) (NativeAuthorityKey, error)
}
type NativeAuthorityKey struct {
	PublicKey            ed25519.PublicKey
	NotBefore, ExpiresAt time.Time
	// AuthoritySequence is the exact retained identity record used for this key.
	// Zero means no ledger sequence was supplied by this key source.
	AuthoritySequence uint64
}

type NativeAuthorityClientOptions struct {
	ProfileID, HubID, AuthorityID         string
	RequestSigningRef, ResponseSigningRef ContextReference
	RequestSigningSeed                    []byte
	ReplyPrefix                           string
	Keys                                  NativeAuthorityKeySource
	Exchange                              NativeAuthorityExchange
}

func (NativeAuthorityClientOptions) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private native authority options]")
}
func (NativeAuthorityClientOptions) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-native-authority-options"}`), nil
}

type nativeAuthorityClient struct {
	options  NativeAuthorityClientOptions
	private  ed25519.PrivateKey
	now      func() time.Time
	sequence atomic.Uint64
}

func newNativeAuthorityClient(options NativeAuthorityClientOptions) (*nativeAuthorityClient, error) {
	if !registryIdentifier.MatchString(options.ProfileID) || !registryIdentifier.MatchString(options.HubID) || !registryIdentifier.MatchString(options.AuthorityID) ||
		!contextReferenceValid(options.RequestSigningRef) || !contextReferenceValid(options.ResponseSigningRef) || options.RequestSigningRef.OwnerHubID != options.HubID || options.ResponseSigningRef.OwnerHubID != options.HubID ||
		len(options.RequestSigningSeed) != ed25519.SeedSize || nilContextDependency(options.Keys) || nilContextDependency(options.Exchange) {
		return nil, pluginError("context_authority_configuration_invalid")
	}
	if options.ReplyPrefix != "" && !nativeAuthorityReplyPrefix.MatchString(options.ReplyPrefix) {
		return nil, pluginError("context_authority_configuration_invalid")
	}
	private := ed25519.NewKeyFromSeed(bytes.Clone(options.RequestSigningSeed))
	options.RequestSigningSeed = nil
	return &nativeAuthorityClient{options: options, private: private, now: time.Now}, nil
}
func nativeAuthorityDigest(raw []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) }
func nativeAuthorityStamp(t time.Time) string {
	return t.UTC().Truncate(time.Microsecond).Format("2006-01-02T15:04:05.999999Z")
}

var nativeAuthorityTimestamp = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$`)

func nativeAuthorityTime(raw string) (time.Time, error) {
	t, e := time.Parse(time.RFC3339Nano, raw)
	if e != nil || !nativeAuthorityTimestamp.MatchString(raw) {
		return time.Time{}, pluginError("context_authority_wire_invalid")
	}
	return t, nil
}
func nativeAuthoritySign(claims []byte, key ed25519.PrivateKey) ([]byte, error) {
	return nativeAuthoritySignLimit(claims, key, nativeAuthorityLimit)
}

func nativeAuthoritySignLimit(claims []byte, key ed25519.PrivateKey, limit int) ([]byte, error) {
	canonical, err := nativeAuthorityCanonicalLimit(claims, limit)
	if err != nil {
		return nil, err
	}
	// Sign canonical bytes, but preserve admitted number tokens on the wire.
	// A finite float such as 1e20 canonicalizes to an integer-looking token
	// outside the SDK's raw safe-integer range; reparsing that would reject it.
	raw, err := json.Marshal(map[string]any{"schemaVersion": "1.0.0", "algorithm": "Ed25519", "canonicalization": "RFC8785-JCS-UTF8", "claims": json.RawMessage(claims), "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, canonical))})
	if err != nil || len(raw) > limit {
		return nil, pluginError("context_authority_wire_invalid")
	}
	return raw, nil
}
func (c *nativeAuthorityClient) key(ctx context.Context, ref ContextReference, purpose string) (NativeAuthorityKey, error) {
	k, err := c.options.Keys.Current(ctx, c.options.ProfileID, c.options.HubID, ref, purpose)
	now := c.now()
	if err != nil || ctx.Err() != nil || len(k.PublicKey) != ed25519.PublicKeySize || k.AuthoritySequence > maxGeneration || k.NotBefore.After(now) || !now.Before(k.ExpiresAt) {
		return NativeAuthorityKey{}, pluginError("context_authority_unavailable")
	}
	c.observeSequence(k.AuthoritySequence)
	k.PublicKey = bytes.Clone(k.PublicKey)
	return k, nil
}

type nativeAuthorityReply struct {
	Purpose           string           `json:"purpose"`
	RequestID         string           `json:"requestId"`
	Method            string           `json:"method"`
	ProfileID         string           `json:"profileId"`
	HubID             string           `json:"hubId"`
	AuthorityID       string           `json:"authorityId"`
	Owner             OwnerReference   `json:"owner"`
	RequestDigest     string           `json:"requestDigest"`
	SigningKeyRef     ContextReference `json:"signingKeyRef"`
	AuthorityRef      ContextReference `json:"authorityRef"`
	AuthoritySequence uint64           `json:"authoritySequence"`
	IssuedAt          string           `json:"issuedAt"`
	ValidUntil        string           `json:"validUntil"`
	Outcome           string           `json:"outcome"`
	Result            json.RawMessage  `json:"result"`
}

func (c *nativeAuthorityClient) call(ctx context.Context, owner OwnerReference, method string, input any) ([]byte, time.Time, error) {
	raw, until, _, err := c.callWithSequence(ctx, owner, method, input)
	return raw, until, err
}
func (c *nativeAuthorityClient) callWithSequence(ctx context.Context, owner OwnerReference, method string, input any) ([]byte, time.Time, uint64, error) {
	fail := func() ([]byte, time.Time, uint64, error) {
		return nil, time.Time{}, 0, pluginError("context_authority_unavailable")
	}
	ownerRaw, _ := json.Marshal(owner)
	if ctx == nil || ctx.Err() != nil || nativeAuthoritySchema("owner", ownerRaw) != nil {
		return fail()
	}
	switch method {
	case "activate-instance", "bind-instance", "admit-operation", "recheck", "prepare-domain-call", "prepare-configuration-request", "prepare-configuration-initialization", "prepare-subscription-call", "admit-domain-event":
	default:
		return fail()
	}
	work, cancel := context.WithTimeout(ctx, contextCallBudget)
	defer cancel()
	now := c.now()
	deadline, _ := work.Deadline()
	key, err := c.key(work, c.options.RequestSigningRef, "agentmux-native-authority-request-v1")
	if err != nil || !bytes.Equal(key.PublicKey, c.private.Public().(ed25519.PublicKey)) {
		return fail()
	}
	now = c.now()
	if work.Err() != nil || now.Before(key.NotBefore) || !now.Before(key.ExpiresAt) {
		return fail()
	}
	if key.ExpiresAt.Before(deadline) {
		deadline = key.ExpiresAt
	}
	deadline = deadline.Truncate(time.Microsecond)
	if !now.Before(deadline) {
		return fail()
	}
	nonce, err := randomControlID()
	if err != nil {
		return fail()
	}
	requestID := "request_" + nonce
	replySubject := c.replySubject(nonce)
	claims, err := json.Marshal(map[string]any{"purpose": "agentmux-native-authority-request-v1", "requestId": requestID, "replySubject": replySubject, "method": method, "profileId": c.options.ProfileID, "hubId": c.options.HubID, "authorityId": c.options.AuthorityID, "owner": owner, "signingKeyRef": c.options.RequestSigningRef, "issuedAt": nativeAuthorityStamp(now), "expiresAt": nativeAuthorityStamp(deadline), "input": input})
	if err != nil {
		return fail()
	}
	canonical, err := nativeAuthorityCanonical(claims)
	if err != nil {
		return fail()
	}
	request, err := nativeAuthoritySign(claims, c.private)
	if err != nil || nativeAuthoritySchema("request", request) != nil {
		return fail()
	}
	if work.Err() != nil || !c.now().Before(deadline) {
		return fail()
	}
	raw, err := c.options.Exchange.Exchange(work, replySubject, request)
	if err != nil || work.Err() != nil || nativeAuthoritySchema("response", raw) != nil {
		return fail()
	}
	fields, err := nativeAuthorityObject(raw, "schemaVersion", "algorithm", "canonicalization", "claims", "signature")
	if err != nil {
		return fail()
	}
	var version, algorithm, codec, signature string
	if json.Unmarshal(fields["schemaVersion"], &version) != nil || version != "1.0.0" || json.Unmarshal(fields["algorithm"], &algorithm) != nil || algorithm != "Ed25519" || json.Unmarshal(fields["canonicalization"], &codec) != nil || codec != "RFC8785-JCS-UTF8" || json.Unmarshal(fields["signature"], &signature) != nil {
		return fail()
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(sig) != signature {
		return fail()
	}
	if _, err = nativeAuthorityObject(fields["claims"], "purpose", "requestId", "method", "profileId", "hubId", "authorityId", "owner", "requestDigest", "signingKeyRef", "authorityRef", "authoritySequence", "issuedAt", "validUntil", "outcome", "result"); err != nil {
		return fail()
	}
	var reply nativeAuthorityReply
	if json.Unmarshal(fields["claims"], &reply) != nil {
		return fail()
	}
	if reply.Purpose != "agentmux-native-authority-response-v1" || reply.RequestID != requestID || reply.Method != method || reply.ProfileID != c.options.ProfileID || reply.HubID != c.options.HubID || reply.AuthorityID != c.options.AuthorityID || reply.Owner != owner || reply.RequestDigest != nativeAuthorityDigest(canonical) || reply.SigningKeyRef != c.options.ResponseSigningRef || !contextReferenceValid(reply.AuthorityRef) || reply.AuthorityRef.ID != c.options.AuthorityID || reply.AuthorityRef.OwnerHubID != c.options.HubID || reply.AuthoritySequence == 0 || reply.AuthoritySequence > maxGeneration {
		return fail()
	}
	// Typed equality alone must not admit extra nested fields or missing zeroes.
	for _, name := range []string{"signingKeyRef", "authorityRef"} {
		if _, err = nativeAuthorityObject(fieldsForClaim(fields["claims"], name), "id", "ownerHubId", "revision"); err != nil {
			return fail()
		}
	}
	ownerBytes, _ := json.Marshal(owner)
	ownerCanonical, _ := nativeAuthorityCanonical(ownerBytes)
	gotOwner, err := nativeAuthorityCanonical(fieldsForClaim(fields["claims"], "owner"))
	if err != nil || !bytes.Equal(ownerCanonical, gotOwner) {
		return fail()
	}
	signed, err := nativeAuthorityCanonical(fields["claims"])
	if err != nil {
		return fail()
	}
	key, err = c.key(work, c.options.ResponseSigningRef, reply.Purpose)
	if err != nil || !ed25519.Verify(key.PublicKey, signed, sig) {
		return fail()
	}
	// Both the verified reply and current key read contribute to this host's
	// known authority floor. A newer read cannot renew an older allow.
	c.observeSequence(reply.AuthoritySequence)
	if reply.AuthoritySequence < c.sequence.Load() {
		return fail()
	}
	observed := c.now()
	issued, e1 := nativeAuthorityTime(reply.IssuedAt)
	until, e2 := nativeAuthorityTime(reply.ValidUntil)
	if e1 != nil || e2 != nil || issued.After(observed) || issued.Before(now.Truncate(time.Microsecond)) || issued.Before(key.NotBefore) || !issued.Before(until) || !observed.Before(until) || until.After(deadline) || until.After(key.ExpiresAt) || work.Err() != nil {
		return fail()
	}
	if reply.Outcome != "allowed" {
		return fail()
	}
	if bytes.Equal(reply.Result, []byte("null")) {
		return fail()
	}
	if reply.AuthoritySequence < c.sequence.Load() {
		return fail()
	}
	return bytes.Clone(reply.Result), until, reply.AuthoritySequence, nil
}
func fieldsForClaim(raw []byte, name string) json.RawMessage {
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	return fields[name]
}

func (c *nativeAuthorityClient) replySubject(nonce string) string {
	prefix := c.options.ReplyPrefix
	if prefix == "" {
		prefix = "_INBOX"
	}
	return prefix + "." + nonce
}

func (c *nativeAuthorityClient) observeSequence(sequence uint64) {
	for current := c.sequence.Load(); sequence > current; current = c.sequence.Load() {
		if c.sequence.CompareAndSwap(current, sequence) {
			return
		}
	}
}
