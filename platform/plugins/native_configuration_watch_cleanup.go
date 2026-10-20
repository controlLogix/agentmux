package plugins

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

const nativeConfigurationJoinedProofLimit = 12288

type nativeConfigurationWatchCleanup interface{ Close(context.Context) error }
type nativeConfigurationWatchPreparer interface {
	prepareConfigurationWatchCleanup(context.Context, []byte, NativeConfigurationClientBinding, NativeConfigurationKeySource) (nativeConfigurationWatchCleanup, error)
}
type nativeConfigurationWatchExchange interface {
	ExchangeConfigurationWatchClose(context.Context, string, []byte) ([]byte, error)
}

type nativeConfigurationWatchCloseClaims struct {
	Purpose             string           `json:"purpose"`
	RequestID           string           `json:"requestId"`
	ProfileID           string           `json:"profileId"`
	HubID               string           `json:"hubId"`
	AuthorityID         string           `json:"authorityId"`
	ReplySubject        string           `json:"replySubject"`
	Owner               OwnerReference   `json:"owner"`
	ConfigurationRef    ContextReference `json:"configurationRef"`
	OperationID         string           `json:"operationId"`
	CancellationRef     ContextReference `json:"cancellationRef"`
	WatchRequestDigest  string           `json:"watchRequestDigest"`
	SigningKeyRef       ContextReference `json:"signingKeyRef"`
	IssuedAt            string           `json:"issuedAt"`
	ExpiresAt           string           `json:"expiresAt,omitempty"`
	JoinedResponseBytes string           `json:"joinedResponseBytes,omitempty"`
}
type nativeConfigurationWatchCloseResponse struct {
	nativeConfigurationWatchCloseClaims
	RequestDigest        string           `json:"requestDigest"`
	RequestSigningKeyRef ContextReference `json:"requestSigningKeyRef"`
	RequestPublicKey     string           `json:"requestPublicKey"`
	WatchExpiresAt       string           `json:"watchExpiresAt"`
	AuthorityRef         ContextReference `json:"authorityRef"`
	ValidUntil           string           `json:"validUntil"`
	Joined               bool             `json:"joined"`
	ReceiptConfirmed     bool             `json:"receiptConfirmed"`
}

// This owner keeps the original request and host key through both replies.
// Cleanup authorizes only joining that watch; it never renews read authority.
type nativeConfigurationWatchClose struct {
	client         *nativeAuthorityClient
	input          NativeConfigurationClientBinding
	keys           NativeConfigurationKeySource
	exchange       nativeConfigurationWatchExchange
	original       nativeConfigurationWatchCloseClaims
	floor          uint64
	proof          []byte
	publicKey      ed25519.PublicKey
	watchExpiresAt time.Time
}

func (a *NativeContextAuthority) prepareConfigurationWatchCleanup(ctx context.Context, raw []byte, input NativeConfigurationClientBinding, keys NativeConfigurationKeySource) (nativeConfigurationWatchCleanup, error) {
	fail := pluginError("context_configuration_unavailable")
	exchange, ok := input.Exchange.(nativeConfigurationWatchExchange)
	if !ok || a == nil || a.client == nil || ctx == nil || ctx.Err() != nil || nilContextDependency(keys) || string(fieldsForClaim(raw, "contractId")) != `"configuration-watch"` {
		return nil, fail
	}
	var envelope struct {
		Operation struct {
			OperationID     string           `json:"operationId"`
			CancellationRef ContextReference `json:"cancellationRef"`
		} `json:"operation"`
		Payload struct {
			Owner            OwnerReference   `json:"owner"`
			ConfigurationRef ContextReference `json:"configurationRef"`
		} `json:"payload"`
		IngressAttestation struct {
			Claims struct {
				TransportRef ContextReference `json:"authenticatedTransportRef"`
			} `json:"claims"`
		} `json:"ingressAttestation"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.IngressAttestation.Claims.TransportRef != a.client.options.RequestSigningRef || !registryIdentifier.MatchString(envelope.Operation.OperationID) || !contextReferenceValid(envelope.Operation.CancellationRef) {
		return nil, fail
	}
	watchExpiry, err := nativeConfigurationRequest(raw, envelope.Payload.Owner, input.Binding)
	if err != nil {
		return nil, fail
	}
	key, err := a.client.key(ctx, a.client.options.RequestSigningRef, "agentmux-native-authority-request-v1")
	if err != nil || !bytes.Equal(key.PublicKey, a.client.private.Public().(ed25519.PublicKey)) {
		return nil, fail
	}
	c := nativeConfigurationWatchCloseClaims{Purpose: "agentmux-configuration-watch-close-v1", ProfileID: a.client.options.ProfileID, HubID: a.client.options.HubID, AuthorityID: a.client.options.AuthorityID, Owner: envelope.Payload.Owner, ConfigurationRef: envelope.Payload.ConfigurationRef, OperationID: envelope.Operation.OperationID, CancellationRef: envelope.Operation.CancellationRef, WatchRequestDigest: nativeAuthorityDigestMustCanonical(raw), SigningKeyRef: a.client.options.RequestSigningRef}
	if !nativeConfigurationWatchRepresentable(c) {
		return nil, fail
	}
	return &nativeConfigurationWatchClose{client: a.client, input: input, keys: keys, exchange: exchange, original: c, floor: max(a.client.sequence.Load(), key.AuthoritySequence, input.Binding.AuthorityRef.Revision), publicKey: bytes.Clone(key.PublicKey), watchExpiresAt: watchExpiry}, nil
}

// The shared schemas permit 96-character identifiers, a 64-character inbox
// prefix, microsecond timestamps and safe-integer revisions. Reserve those
// lengths before sending a watch, so its exact owner can always be acknowledged.
func nativeConfigurationWatchRepresentable(original nativeConfigurationWatchCloseClaims) bool {
	proof, confirmation, err := nativeConfigurationWatchSizingFrames(original)
	return err == nil && len(proof) <= nativeConfigurationJoinedProofLimit && base64.StdEncoding.EncodedLen(len(proof)) <= 16384 && len(confirmation) <= nativeAuthorityLimit
}

func nativeConfigurationWatchSizingFrames(original nativeConfigurationWatchCloseClaims) ([]byte, []byte, error) {
	const longestStamp = "9999-12-31T23:59:59.999999Z"
	worstRef := ContextReference{ID: strings.Repeat("a", 96), OwnerHubID: strings.Repeat("a", 96), Revision: maxGeneration}
	c := original
	c.Purpose = "agentmux-configuration-watch-close-response-v1"
	c.RequestID = "request_" + strings.Repeat("a", 64)
	c.ReplySubject = "_INBOX." + strings.Repeat("a", 64) + "." + strings.Repeat("a", 64)
	c.IssuedAt = longestStamp
	c.ExpiresAt = ""
	c.JoinedResponseBytes = ""
	c.SigningKeyRef = worstRef
	response := nativeConfigurationWatchCloseResponse{nativeConfigurationWatchCloseClaims: c, RequestDigest: "sha256:" + strings.Repeat("a", 64), RequestSigningKeyRef: original.SigningKeyRef, RequestPublicKey: strings.Repeat("a", 43), WatchExpiresAt: longestStamp, AuthorityRef: worstRef, ValidUntil: longestStamp, Joined: false, ReceiptConfirmed: false}
	encode := func(claims any) ([]byte, error) {
		return nativeAuthorityCanonical(contextJSON(map[string]any{"schemaVersion": "1.0.0", "algorithm": "Ed25519", "canonicalization": "RFC8785-JCS-UTF8", "claims": claims, "signature": strings.Repeat("a", 86)}))
	}
	proof, err := encode(response)
	if err != nil {
		return nil, nil, err
	}
	c = original
	c.RequestID = response.RequestID
	c.ReplySubject = response.ReplySubject
	c.IssuedAt, c.ExpiresAt = longestStamp, longestStamp
	c.JoinedResponseBytes = base64.StdEncoding.EncodeToString(proof)
	confirmation, err := encode(c)
	return proof, confirmation, err
}

func (w *nativeConfigurationWatchClose) Close(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return pluginError("context_cleanup_incomplete")
	}
	// A lost confirmation reply leaves the exact verified first response here.
	// The next attempt sends it again, even if the server retired its entry.
	for range 2 {
		work, cancel := context.WithTimeout(ctx, contextCallBudget)
		nonce, err := randomControlID()
		if err != nil {
			cancel()
			return pluginError("context_cleanup_incomplete")
		}
		c := w.original
		c.RequestID = "request_" + nonce
		c.ReplySubject = w.input.ReplyPrefix + "." + nonce
		c.IssuedAt = nativeAuthorityStamp(w.client.now())
		deadline, _ := work.Deadline()
		c.ExpiresAt = nativeAuthorityStamp(deadline)
		if len(w.proof) != 0 {
			c.JoinedResponseBytes = base64.StdEncoding.EncodeToString(w.proof)
		}
		request, err := nativeAuthoritySign(contextJSON(c), w.client.private)
		if err == nil {
			request, err = nativeAuthorityCanonical(request)
		}
		if err != nil || nativeAuthoritySchema("configuration-watch-close", request) != nil {
			cancel()
			return pluginError("context_cleanup_incomplete")
		}
		raw, err := w.exchange.ExchangeConfigurationWatchClose(work, c.ReplySubject, request)
		var response nativeConfigurationWatchCloseResponse
		if err == nil {
			response, err = w.verify(work, raw, request, c)
		}
		cancel()
		if err != nil || !response.Joined {
			return pluginError("context_cleanup_incomplete")
		}
		if len(w.proof) != 0 && response.ReceiptConfirmed {
			return nil
		}
		if len(w.proof) == 0 {
			w.proof = bytes.Clone(raw)
		}
	}
	return pluginError("context_cleanup_incomplete")
}

func (w *nativeConfigurationWatchClose) verify(ctx context.Context, raw, request []byte, wanted nativeConfigurationWatchCloseClaims) (nativeConfigurationWatchCloseResponse, error) {
	var c nativeConfigurationWatchCloseResponse
	fail := pluginError("context_cleanup_incomplete")
	if ctx == nil || ctx.Err() != nil || len(raw) > nativeConfigurationJoinedProofLimit || nativeAuthoritySchema("configuration-watch-close-response", raw) != nil {
		return c, fail
	}
	canonical, err := nativeAuthorityCanonical(raw)
	if err != nil || !bytes.Equal(canonical, raw) || json.Unmarshal(fieldsForClaim(raw, "claims"), &c) != nil {
		return c, fail
	}
	if c.Purpose != "agentmux-configuration-watch-close-response-v1" || c.RequestID != wanted.RequestID || c.ProfileID != wanted.ProfileID || c.HubID != wanted.HubID || c.AuthorityID != wanted.AuthorityID || c.ReplySubject != wanted.ReplySubject || c.Owner != wanted.Owner || c.ConfigurationRef != wanted.ConfigurationRef || c.OperationID != wanted.OperationID || c.CancellationRef != wanted.CancellationRef || c.WatchRequestDigest != wanted.WatchRequestDigest || c.RequestDigest != nativeAuthorityDigestMustCanonical(request) || c.RequestSigningKeyRef != wanted.SigningKeyRef || c.SigningKeyRef != w.input.Binding.Service.SigningKeyRef || c.AuthorityRef.ID != wanted.AuthorityID || c.AuthorityRef.OwnerHubID != wanted.HubID || c.AuthorityRef.Revision < w.floor || c.ReceiptConfirmed && (wanted.JoinedResponseBytes == "" || !c.Joined) {
		return c, fail
	}
	watchExpiry, expiryErr := nativeAuthorityTime(c.WatchExpiresAt)
	if expiryErr != nil || !watchExpiry.Equal(w.watchExpiresAt) || c.RequestPublicKey != base64.RawURLEncoding.EncodeToString(w.publicKey) {
		return c, fail
	}
	issued, e1 := nativeAuthorityTime(c.IssuedAt)
	until, e2 := nativeAuthorityTime(c.ValidUntil)
	start, e3 := nativeAuthorityTime(wanted.IssuedAt)
	end, e4 := nativeAuthorityTime(wanted.ExpiresAt)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || issued.Before(start) || issued.After(time.Now()) || !issued.Before(until) || !time.Now().Before(until) || until.After(end) {
		return c, fail
	}
	var encoded string
	if json.Unmarshal(fieldsForClaim(raw, "signature"), &encoded) != nil {
		return c, fail
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	signed, canonicalErr := nativeAuthorityCanonical(fieldsForClaim(raw, "claims"))
	if err != nil || canonicalErr != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != encoded {
		return c, fail
	}
	for range 2 {
		key, err := w.keys.CurrentConfigurationKey(ctx, w.input.Binding.Service)
		now := time.Now()
		if err != nil || ctx.Err() != nil || len(key.PublicKey) != ed25519.PublicKeySize || issued.Before(key.NotBefore) || now.Before(key.NotBefore) || !now.Before(key.ExpiresAt) || !now.Before(until) || until.After(key.ExpiresAt) || key.AuthoritySequence > c.AuthorityRef.Revision || !ed25519.Verify(key.PublicKey, signed, signature) {
			return c, fail
		}
	}
	return c, nil
}
