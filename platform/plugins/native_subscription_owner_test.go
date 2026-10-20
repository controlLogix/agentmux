package plugins

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type nativeSubscriptionTestKeys struct {
	public   ed25519.PublicKey
	revoked  atomic.Bool
	sequence atomic.Uint64
}

func (k *nativeSubscriptionTestKeys) CurrentConfigurationSubscriptionKey(context.Context, NativeConfigurationServiceBinding) (NativeAuthorityKey, error) {
	if k.revoked.Load() {
		return NativeAuthorityKey{}, errors.New("fixture issuer revoked")
	}
	sequence := k.sequence.Load()
	if sequence == 0 {
		sequence = 3
	}
	return NativeAuthorityKey{PublicKey: k.public, NotBefore: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(time.Hour), AuthoritySequence: sequence}, nil
}

type nativeSubscriptionTestTransport struct {
	mu                sync.Mutex
	t                 *testing.T
	authority         *nativeAuthorityFixture
	approved          ContextApprovedEnvelope
	event             []byte
	mode              string
	open              *nativeSubscriptionControl
	closeClaims       []nativeSubscriptionControl
	nextActive        bool
	nextEntered       chan struct{}
	closeEntered      chan struct{}
	closeRelease      chan struct{}
	authoritySequence uint64
	nextCalls         atomic.Int32
}

func (*nativeSubscriptionTestTransport) ConfigurationReusable() bool { return true }
func (f *nativeSubscriptionTestTransport) ExchangeSubscription(ctx context.Context, reply string, raw []byte) ([]byte, error) {
	if nativeAuthoritySchema("configuration-subscription-control", raw) != nil {
		f.t.Fatal("invalid Go control frame")
	}
	var c nativeSubscriptionControl
	json.Unmarshal(fieldsForClaim(raw, "claims"), &c)
	var encoded string
	json.Unmarshal(fieldsForClaim(raw, "signature"), &encoded)
	signature, _ := base64.RawURLEncoding.DecodeString(encoded)
	claims, _ := nativeAuthorityCanonical(fieldsForClaim(raw, "claims"))
	if !ed25519.Verify(f.authority.keys.request, claims, signature) || c.ReplySubject != reply {
		f.t.Fatal("Go control signature or reply binding failed")
	}
	if c.ApprovedEnvelopeDigest != nativeAuthorityDigestMustCanonical(f.approved.Envelope) || string(contextJSON(c.OperationID)) != string(fieldsForClaim(fieldsForClaim(f.approved.Envelope, "operation"), "operationId")) {
		f.t.Fatal("Go control did not bind prepared downstream operation")
	}
	f.mu.Lock()
	mode := f.mode
	outcome := "opened"
	cursor := c.Cursor
	switch c.Action {
	case "open":
		if c.RequestID != c.OpenRequestID || c.LeaseID != nil {
			f.t.Fatal("invalid original open identity")
		}
		copy := c
		f.open = &copy
		if mode == "lost-open" {
			f.mu.Unlock()
			return nil, errors.New("open reply lost")
		}
	case "next":
		f.nextCalls.Add(1)
		if f.open == nil || c.OpenRequestID != f.open.OpenRequestID || c.LeaseID == nil || *c.LeaseID != "lease_one" {
			f.t.Fatal("next replaced original allocation")
		}
		if mode == "blocked-next" {
			f.nextActive = true
			close(f.nextEntered)
			f.mu.Unlock()
			<-ctx.Done()
			f.mu.Lock()
			f.nextActive = false
			f.mu.Unlock()
			return nil, ctx.Err()
		}
		outcome = "event"
		cursor.Sequence++
		if mode == "gap" {
			cursor.Sequence++
		}
		if mode == "source" {
			cursor.SourceDigest = nativeAuthorityDigest([]byte("replacement"))
		}
		if mode == "resync" {
			outcome = "resync-required"
			cursor = c.Cursor
		}
	case "close":
		if f.open == nil || c.OpenRequestID != f.open.OpenRequestID || f.nextActive {
			f.t.Fatal("close lost allocation or abandoned original next")
		}
		f.closeClaims = append(f.closeClaims, c)
		outcome = "closed"
		if mode == "blocked-close" {
			close(f.closeEntered)
			f.mu.Unlock()
			select {
			case <-f.closeRelease:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			f.mu.Lock()
		}
	}
	f.mu.Unlock()
	var response map[string]any
	json.Unmarshal(contextJSON(c), &response)
	delete(response, "expiresAt")
	delete(response, "subscriptionEnvelopeBytes")
	response["purpose"] = "agentmux-configuration-subscription-response-v1"
	response["requestDigest"] = nativeAuthorityDigestMustCanonical(raw)
	response["signingKeyRef"] = f.authority.responseRef
	f.mu.Lock()
	sequence := f.authoritySequence
	f.mu.Unlock()
	if sequence == 0 {
		sequence = 3
	}
	response["authorityRef"] = ContextReference{"native_authority", "context_hub", sequence}
	response["issuedAt"] = nativeAuthorityStamp(time.Now())
	response["validUntil"] = c.ExpiresAt
	response["previousCursor"] = c.Cursor
	response["cursor"] = cursor
	response["outcome"] = outcome
	response["leaseId"] = "lease_one"
	if outcome == "event" {
		response["eventEnvelopeBytes"] = base64.StdEncoding.EncodeToString(f.event)
	}
	if outcome == "closed" {
		response["joined"] = mode != "close-unjoined"
	}
	result, err := nativeAuthoritySign(contextJSON(response), f.authority.response)
	if err != nil {
		f.t.Fatal(err)
	}
	return nativeAuthorityCanonical(result)
}
func nativeRemoteSubscriptionFixture(t *testing.T, mode string) (*NativeConfigurationSubscriptions, *nativeSubscriptionTestTransport, ContextApprovedEnvelope) {
	t.Helper()
	a, operation, call, event := nativeSubscriptionAuthorityFixture(t)
	a.authority.client.options.ReplyPrefix = "_INBOX.fixtureprefix123456"
	nativeSubscriptionTestReplies(t, a, operation, call, event, "")
	approved, err := a.authority.PrepareDomainCall(context.Background(), a.binding.Owner, operation, call)
	if err != nil {
		t.Fatal(err)
	}
	transport := &nativeSubscriptionTestTransport{t: t, authority: a, approved: approved.Clone(), event: event, mode: mode, nextEntered: make(chan struct{}), closeEntered: make(chan struct{}), closeRelease: make(chan struct{})}
	keys := &nativeSubscriptionTestKeys{public: a.response.Public().(ed25519.PublicKey)}
	route := nativeSubscriptionRoute{bindingID: call.BindingID, source: a.binding.ConfigurationEventSources[0], service: NativeConfigurationServiceBinding{ProfileID: "profile", HubID: "context_hub", ServiceInstanceID: "fixture_issuer", ServiceIdentityRef: ContextReference{"fixture_service", "context_hub", 1}, SigningKeyRef: a.responseRef}, exchange: transport}
	h, err := newNativeConfigurationSubscriptions(a.authority, keys, []nativeSubscriptionRoute{route})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		transport.mu.Lock()
		transport.mode = ""
		transport.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := h.Close(ctx); err != nil {
			t.Errorf("retained subscription cleanup: %v", err)
		}
	})
	return h, transport, approved
}
func TestNativeRemoteSubscriptionVerifiesEventBeforeCursorAdvance(t *testing.T) {
	h, transport, approved := nativeRemoteSubscriptionFixture(t, "")
	lease, err := h.Subscribe(context.Background(), approved)
	if err != nil {
		t.Fatal(err)
	}
	l := lease.(*nativeRemoteSubscription)
	event, err := l.Next(context.Background())
	if err != nil || !bytes.Equal(event, transport.event) {
		t.Fatal("verified original event was not returned", err)
	}
	l.mu.Lock()
	cursor := l.cursor
	l.mu.Unlock()
	if cursor.Sequence != 7 {
		t.Fatal("verified cursor did not advance")
	}
	if err := l.Close(context.Background()); err != nil || !completed(l.Done()) {
		t.Fatal("original lease did not join", err)
	}
}
func TestNativeRemoteSubscriptionRefusesUnverifiedProgress(t *testing.T) {
	for _, mode := range []string{"gap", "source", "resync", "denied-event"} {
		t.Run(mode, func(t *testing.T) {
			h, transport, approved := nativeRemoteSubscriptionFixture(t, mode)
			lease, err := h.Subscribe(context.Background(), approved)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "denied-event" {
				prior := transport.authority.mutate
				transport.authority.mutate = func(claims map[string]any) {
					prior(claims)
					if claims["method"] == "admit-domain-event" {
						claims["outcome"] = "denied"
						claims["result"] = nil
					}
				}
			}
			l := lease.(*nativeRemoteSubscription)
			if data, err := l.Next(context.Background()); err == nil || data != nil {
				t.Fatal("unverified event escaped")
			}
			l.mu.Lock()
			cursor := l.cursor
			l.mu.Unlock()
			if cursor.Sequence != 6 {
				t.Fatal("unverified delivery advanced cursor")
			}
			if err := l.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestNativeRemoteSubscriptionLostOpenClosesByOriginalRequest(t *testing.T) {
	h, transport, approved := nativeRemoteSubscriptionFixture(t, "lost-open")
	lease, err := h.Subscribe(context.Background(), approved)
	if err == nil || lease == nil {
		t.Fatal("lost open discarded its original owner")
	}
	if err := lease.Close(context.Background()); err != nil || !completed(lease.Done()) {
		t.Fatal("lost open did not join", err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.closeClaims) != 1 || transport.closeClaims[0].LeaseID != nil || transport.closeClaims[0].OpenRequestID != transport.open.OpenRequestID {
		t.Fatal("lost open cleanup used a replacement allocation")
	}
}
func TestNativeRemoteSubscriptionCloseRetainsPendingOriginal(t *testing.T) {
	h, transport, approved := nativeRemoteSubscriptionFixture(t, "blocked-close")
	t.Cleanup(func() { close(transport.closeRelease) })
	lease, err := h.Subscribe(context.Background(), approved)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := lease.Close(ctx); err == nil || completed(lease.Done()) {
		t.Fatal("pending close released original owner")
	}
	<-transport.closeEntered
	h.mu.Lock()
	retained := len(h.leases)
	h.mu.Unlock()
	if retained != 1 {
		t.Fatal("pending original allocation was removed")
	}
	transport.closeRelease <- struct{}{}
	if err := lease.Close(context.Background()); err != nil || !completed(lease.Done()) {
		t.Fatal("released original did not join", err)
	}
}
func TestNativeRemoteSubscriptionCloseCancelsAndJoinsOriginalNext(t *testing.T) {
	h, transport, approved := nativeRemoteSubscriptionFixture(t, "blocked-next")
	lease, err := h.Subscribe(context.Background(), approved)
	if err != nil {
		t.Fatal(err)
	}
	nextDone := make(chan error, 1)
	go func() { _, err := lease.Next(context.Background()); nextDone <- err }()
	<-transport.nextEntered
	if err := lease.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-nextDone; err == nil {
		t.Fatal("closing original next returned success")
	}
	if !completed(lease.Done()) {
		t.Fatal("next worker was abandoned")
	}
}
func TestNativeRemoteSubscriptionCleanupUsesOriginalKeyAfterRevocation(t *testing.T) {
	h, transport, approved := nativeRemoteSubscriptionFixture(t, "")
	lease, err := h.Subscribe(context.Background(), approved)
	if err != nil {
		t.Fatal(err)
	}
	transport.authority.keys.revoked = true
	if _, err := lease.Next(context.Background()); err == nil {
		t.Fatal("revoked host started another read")
	}
	if err := lease.Close(context.Background()); err != nil || !completed(lease.Done()) {
		t.Fatal("original cleanup key was replaced by a fresh authority lookup", err)
	}
}
func TestNativeRemoteSubscriptionUnjoinedCloseKeepsOwnerForRetry(t *testing.T) {
	h, transport, approved := nativeRemoteSubscriptionFixture(t, "close-unjoined")
	lease, err := h.Subscribe(context.Background(), approved)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(context.Background()); err == nil || completed(lease.Done()) {
		t.Fatal("unjoined remote owner released")
	}
	h.mu.Lock()
	retained := len(h.leases)
	h.mu.Unlock()
	if retained != 1 {
		t.Fatal("unjoined remote owner was lost")
	}
	transport.mu.Lock()
	transport.mode = ""
	transport.mu.Unlock()
	if err := lease.Close(context.Background()); err != nil {
		t.Fatal("same original allocation could not finish cleanup", err)
	}
}

func TestNativeRemoteSubscriptionCloseRequiresCurrentSigningAuthority(t *testing.T) {
	h, transport, approved := nativeRemoteSubscriptionFixture(t, "")
	lease, err := h.Subscribe(context.Background(), approved)
	if err != nil {
		t.Fatal(err)
	}
	h.keys.(*nativeSubscriptionTestKeys).sequence.Store(4)
	if err := lease.Close(context.Background()); err == nil || completed(lease.Done()) {
		t.Fatal("stale signing authority released original allocation")
	}
	transport.mu.Lock()
	transport.authoritySequence = 4
	transport.mu.Unlock()
	if err := lease.Close(context.Background()); err != nil || !completed(lease.Done()) {
		t.Fatal("current signed cleanup did not join original allocation", err)
	}
}

func TestNativeRemoteSubscriptionUnsentOpenNeedsNoRemoteJoin(t *testing.T) {
	h, transport, approved := nativeRemoteSubscriptionFixture(t, "")
	transport.authority.keys.revoked = true
	lease, err := h.Subscribe(context.Background(), approved)
	if err == nil || lease == nil {
		t.Fatal("refused open discarded original local owner")
	}
	if err := lease.Close(context.Background()); err != nil || !completed(lease.Done()) {
		t.Fatal("known unsent open invented remote cleanup", err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.open != nil || len(transport.closeClaims) != 0 {
		t.Fatal("unsent open contacted a replacement remote allocation")
	}
}
