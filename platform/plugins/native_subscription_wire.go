package plugins

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"
)

type nativeSubscriptionControl struct {
	Purpose                   string                         `json:"purpose"`
	Action                    string                         `json:"action"`
	RequestID                 string                         `json:"requestId"`
	OpenRequestID             string                         `json:"openRequestId"`
	LeaseID                   *string                        `json:"leaseId"`
	ProfileID                 string                         `json:"profileId"`
	HubID                     string                         `json:"hubId"`
	AuthorityID               string                         `json:"authorityId"`
	ReplySubject              string                         `json:"replySubject"`
	Owner                     OwnerReference                 `json:"owner"`
	OperationID               string                         `json:"operationId"`
	ApprovedEnvelopeDigest    string                         `json:"approvedEnvelopeDigest"`
	FilterDigest              string                         `json:"filterDigest"`
	Cursor                    NativeConfigurationEventCursor `json:"cursor"`
	SigningKeyRef             ContextReference               `json:"signingKeyRef"`
	IssuedAt                  string                         `json:"issuedAt"`
	ExpiresAt                 string                         `json:"expiresAt,omitempty"`
	SubscriptionEnvelopeBytes string                         `json:"subscriptionEnvelopeBytes,omitempty"`
}
type nativeSubscriptionResponse struct {
	nativeSubscriptionControl
	RequestDigest      string                         `json:"requestDigest"`
	AuthorityRef       ContextReference               `json:"authorityRef"`
	PreviousCursor     NativeConfigurationEventCursor `json:"previousCursor"`
	ValidUntil         string                         `json:"validUntil"`
	Outcome            string                         `json:"outcome"`
	EventEnvelopeBytes string                         `json:"eventEnvelopeBytes,omitempty"`
	Joined             *bool                          `json:"joined,omitempty"`
}
type nativeSubscriptionServiceKeys interface {
	CurrentConfigurationSubscriptionKey(context.Context, NativeConfigurationServiceBinding) (NativeAuthorityKey, error)
}

func verifyNativeSubscriptionResponse(ctx context.Context, raw, request []byte, service NativeConfigurationServiceBinding, keys nativeSubscriptionServiceKeys, floor uint64) (nativeSubscriptionResponse, []byte, error) {
	var response nativeSubscriptionResponse
	fail := func() (nativeSubscriptionResponse, []byte, error) {
		return nativeSubscriptionResponse{}, nil, pluginError("context_subscription_unavailable")
	}
	if ctx == nil || ctx.Err() != nil || nativeAuthoritySchema("configuration-subscription-response", raw) != nil || nativeAuthoritySchema("configuration-subscription-control", request) != nil {
		return fail()
	}
	canonical, err := nativeAuthorityCanonical(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		return fail()
	}
	var wanted nativeSubscriptionControl
	if json.Unmarshal(fieldsForClaim(raw, "claims"), &response) != nil || json.Unmarshal(fieldsForClaim(request, "claims"), &wanted) != nil {
		return fail()
	}
	c := response
	if c.Purpose != "agentmux-configuration-subscription-response-v1" || c.Action != wanted.Action || c.RequestID != wanted.RequestID || c.OpenRequestID != wanted.OpenRequestID || c.ProfileID != wanted.ProfileID || c.HubID != wanted.HubID || c.AuthorityID != wanted.AuthorityID || c.ReplySubject != wanted.ReplySubject || c.Owner != wanted.Owner || c.OperationID != wanted.OperationID || c.ApprovedEnvelopeDigest != wanted.ApprovedEnvelopeDigest || c.FilterDigest != wanted.FilterDigest || c.PreviousCursor != wanted.Cursor || c.Cursor.SourceDigest != wanted.Cursor.SourceDigest || c.Cursor.StreamCreated != wanted.Cursor.StreamCreated || c.RequestDigest != nativeAuthorityDigestMustCanonical(request) || c.SigningKeyRef != service.SigningKeyRef || c.ProfileID != service.ProfileID || c.HubID != service.HubID || c.AuthorityRef.ID != wanted.AuthorityID || c.AuthorityRef.OwnerHubID != wanted.HubID || c.AuthorityRef.Revision < floor {
		return fail()
	}
	if wanted.LeaseID != nil && (c.LeaseID == nil || *c.LeaseID != *wanted.LeaseID) {
		return fail()
	}
	if c.Outcome != "event" && c.Cursor != wanted.Cursor {
		return fail()
	}
	issued, e1 := nativeAuthorityTime(c.IssuedAt)
	until, e2 := nativeAuthorityTime(c.ValidUntil)
	requestStart, e3 := nativeAuthorityTime(wanted.IssuedAt)
	requestEnd, e4 := nativeAuthorityTime(wanted.ExpiresAt)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || issued.Before(requestStart) || issued.After(time.Now()) || !issued.Before(until) || !time.Now().Before(until) || until.After(requestEnd) {
		return fail()
	}
	var encoded string
	if json.Unmarshal(fieldsForClaim(raw, "signature"), &encoded) != nil {
		return fail()
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != encoded {
		return fail()
	}
	signed, err := nativeAuthorityCanonical(fieldsForClaim(raw, "claims"))
	if err != nil {
		return fail()
	}
	for range 2 {
		key, err := keys.CurrentConfigurationSubscriptionKey(ctx, service)
		now := time.Now()
		if err != nil || ctx.Err() != nil || len(key.PublicKey) != ed25519.PublicKeySize || key.AuthoritySequence > c.AuthorityRef.Revision || issued.Before(key.NotBefore) || now.Before(key.NotBefore) || !now.Before(key.ExpiresAt) || !now.Before(until) || until.After(key.ExpiresAt) || !ed25519.Verify(key.PublicKey, signed, signature) {
			return fail()
		}
	}
	var event []byte
	if c.Outcome == "event" {
		if wanted.Cursor.Sequence >= maxGeneration || c.Cursor.Sequence != wanted.Cursor.Sequence+1 {
			return fail()
		}
		event, err = base64.StdEncoding.Strict().DecodeString(c.EventEnvelopeBytes)
		if err != nil || base64.StdEncoding.EncodeToString(event) != c.EventEnvelopeBytes || len(event) > nativeAuthorityLimit || nativeAuthoritySchema("envelope", event) != nil || string(fieldsForClaim(event, "kind")) != `"event"` || string(fieldsForClaim(event, "contractId")) != `"configuration-change"` || nativeAuthoritySchema("configuration-change", fieldsForClaim(event, "payload")) != nil {
			return fail()
		}
		var payload struct {
			ConfigurationRef ContextReference `json:"configurationRef"`
		}
		if json.Unmarshal(fieldsForClaim(event, "payload"), &payload) != nil || payload.ConfigurationRef.Revision != c.Cursor.Sequence {
			return fail()
		}
	}
	return response, bytes.Clone(event), nil
}
