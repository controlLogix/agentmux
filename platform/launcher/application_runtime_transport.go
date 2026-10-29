//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/controlLogix/agentmux/platform/internal/natscredential"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/localtls"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// ApplicationObservationSigner is supplied by explicit application enrollment.
// It owns the application-attestor key and pinned receipt issuer. Implementations
// sign only this producer's opaque evidence, never client-supplied observations.
// The interface is an in-process adapter; the public boundary remains NATS JSON.
type ApplicationObservationSigner interface {
	Refresh(context.Context, *ApplicationRuntimeEvidence, string, string) ([]byte, error)
	End(context.Context, *ApplicationRuntimeEvidence, string, string) ([]byte, error)
	VerifyReceipt(context.Context, []byte, []byte) error
}

// ApplicationAttestorNATSEnrollment comes from the protected application store.
// It is separate from HOST enrollment and grants no authority by construction.
// The broker validates the JWT; the identity owner checks current purpose grants.
type ApplicationAttestorNATSEnrollment struct {
	Scope                       protocol.Scope
	OrganizationID, AuthorityID string
	UserPublicKey               string
	AccountPublicKey            string
	ReplyPrefix                 string
	Credentials                 []byte
	Trust                       *localtls.ClientTrust
	ServerName                  string // TLS DNS identity; not the NATS INFO label.
	InitialGeneration           uint64
	Signer                      ApplicationObservationSigner
}

func (*ApplicationAttestorNATSEnrollment) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "[private application attestor enrollment]")
}
func (*ApplicationAttestorNATSEnrollment) MarshalJSON() ([]byte, error) {
	return nil, applicationEvidenceError("serialization_forbidden", nil)
}

type applicationAttestorNATS struct {
	enrollment ApplicationAttestorNATSEnrollment
	connection *nats.Conn
	dialer     *localtls.Dialer
	key        nkeys.KeyPair
}

type applicationAttestorCleanup struct {
	transport *applicationAttestorNATS
	cause     error
}

func (e *applicationAttestorCleanup) Error() string {
	return "application_runtime_transport_cleanup_failed"
}
func (e *applicationAttestorCleanup) Format(s fmt.State, _ rune)   { fmt.Fprint(s, e.Error()) }
func (e *applicationAttestorCleanup) MarshalJSON() ([]byte, error) { return json.Marshal(e.Error()) }
func (e *applicationAttestorCleanup) Unwrap() error                { return errors.Join(e.cause, ErrTransportCleanup) }
func (e *applicationAttestorCleanup) Close() error {
	if e == nil || e.transport == nil {
		return nil
	}
	return e.transport.close(nil)
}

func applicationAttestorSubject(e ApplicationAttestorNATSEnrollment) (string, error) {
	s := e.Scope
	if !kernelStatusID.MatchString(s.HubID) || !kernelStatusID.MatchString(s.InstanceID) || !kernelStatusID.MatchString(s.ProfileID) || !kernelStatusDigest.MatchString(s.AssemblyDigest) || !kernelStatusDigest.MatchString(s.ReleaseManifestDigest) || !kernelStatusVersion.MatchString(s.ReleaseVersion) || !kernelStatusID.MatchString(e.OrganizationID) || !kernelStatusID.MatchString(e.AuthorityID) || e.InitialGeneration == 0 || e.InitialGeneration > applicationMaxGeneration || e.Trust == nil || e.ServerName == "" || nilApplicationSigner(e.Signer) || len(e.Credentials) == 0 || len(e.Credentials) > 65536 || !nkeys.IsValidPublicUserKey(e.UserPublicKey) || !nkeys.IsValidPublicAccountKey(e.AccountPublicKey) || !applicationReplyPrefix.MatchString(e.ReplyPrefix) {
		return "", applicationEvidenceError("enrollment_invalid", nil)
	}
	return "amx.v1.h." + s.HubID + ".o." + e.OrganizationID + ".identity." + e.AuthorityID + ".command", nil
}

// Broker enrollment grants this principal only its own reply namespace. A
// request can choose neither the prefix nor another principal's reply subject.
var applicationReplyPrefix = regexp.MustCompile(`^_INBOX\.[A-Za-z0-9_-]{16,64}$`)
var applicationReplySuffix = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func validApplicationReplySubject(prefix, subject string) bool {
	return applicationReplyPrefix.MatchString(prefix) && strings.HasPrefix(subject, prefix+".") && applicationReplySuffix.MatchString(strings.TrimPrefix(subject, prefix+"."))
}

func applicationAttestorInbox(e ApplicationAttestorNATSEnrollment, connection *nats.Conn) (string, error) {
	if connection == nil || !applicationReplyPrefix.MatchString(e.ReplyPrefix) || connection.Opts.InboxPrefix != e.ReplyPrefix {
		return "", applicationEvidenceError("reply_enrollment_invalid", nil)
	}
	subject := connection.NewInbox()
	if !validApplicationReplySubject(e.ReplyPrefix, subject) {
		return "", applicationEvidenceError("reply_enrollment_invalid", nil)
	}
	return subject, nil
}

func nilApplicationSigner(s ApplicationObservationSigner) bool {
	if s == nil {
		return true
	}
	value := reflect.ValueOf(s)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	}
	return false
}

// Actual JWT account and permissions are verified before opening a connection.
// The enrollment declaration alone cannot prove narrow broker capabilities.
func admitApplicationAttestorCredential(e ApplicationAttestorNATSEnrollment) (natscredential.Credential, error) {
	subject, err := applicationAttestorSubject(e)
	if err != nil {
		return natscredential.Credential{}, err
	}
	credential, err := natscredential.Validate(e.Credentials, natscredential.Policy{AccountPublicKey: e.AccountPublicKey, PublishSubjects: []string{subject}, SubscribeSubjects: []string{e.ReplyPrefix + ".>"}, PrivateInbox: true})
	if err != nil || credential.PublicKey() != e.UserPublicKey {
		return natscredential.Credential{}, applicationEvidenceError("credential_invalid", err)
	}
	return credential, nil
}

func connectApplicationAttestor(parent, budget context.Context, e ApplicationAttestorNATSEnrollment) (transport *applicationAttestorNATS, failure error) {
	if parent == nil || budget == nil || parent.Err() != nil || budget.Err() != nil {
		return nil, applicationEvidenceError("context_invalid", nil)
	}
	if _, err := applicationAttestorSubject(e); err != nil {
		return nil, err
	}
	if e.ServerName != e.Trust.Policy().ServerName {
		return nil, applicationEvidenceError("connection_invalid", nil)
	}
	ctx, cancel := context.WithTimeout(budget, applicationEvidenceLimit)
	defer cancel()
	credential, err := admitApplicationAttestorCredential(e)
	if err != nil {
		return nil, err
	}
	seed := credential.Seed()
	key, err := nkeys.FromSeed(seed)
	clear(seed)
	if err != nil {
		return nil, applicationEvidenceError("credential_invalid", err)
	}
	jwt := credential.JWT()
	retained := false
	defer func() {
		if !retained {
			key.Wipe()
		}
	}()
	deadline, _ := ctx.Deadline()
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return nil, applicationEvidenceError("deadline", ctx.Err())
	}
	dialer, err := e.Trust.NewDialer(parent, remaining)
	if err != nil {
		return nil, applicationEvidenceError("transport_unavailable", err)
	}
	t := &applicationAttestorNATS{enrollment: e, dialer: dialer, key: key}
	// The callbacks retain only this admitted key. No file, URL, discovery or
	// environment callback can change credential selection during connection.
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { dialer.Close(); close(stopped) })
	t.connection, err = nats.Connect(e.Trust.Policy().Endpoint, nats.UserJWT(func() (string, error) { return jwt, nil }, key.Sign), nats.CustomInboxPrefix(e.ReplyPrefix), nats.TLSHandshakeFirst(), nats.NoReconnect(), nats.IgnoreDiscoveredServers(), nats.NoEcho(), nats.Timeout(remaining), nats.SetCustomDialer(dialer), nats.ErrorHandler(ownerBridgeAsyncErrorHandler))
	if !stop() {
		<-stopped
	}
	if err != nil || ctx.Err() != nil || t.connection == nil {
		failure = applicationEvidenceError("transport_unavailable", err)
		// The selected CA, TLS DNS name and leaf pin authenticate this application
		// broker. Its INFO server_name is not inherited from the kernel listener.
	} else if t.connection.ConnectedServerVersion() != "2.15.0" || ownerBridgeAuthorityLastError(t.connection) != nil {
		failure = applicationEvidenceError("authority_rejected", nil)
	}
	if failure != nil {
		retained = true // close retains the exact key/dialer if cleanup remains uncertain.
		return nil, t.close(failure)
	}
	retained = true
	return t, nil
}

func (t *applicationAttestorNATS) close(cause error) error {
	if t == nil {
		return cause
	}
	var uncertain bool
	cause, uncertain = closeOwnedTransport(t.dialer, cause, "")
	if t.connection != nil {
		t.connection.Close()
	}
	if !uncertain && t.key != nil {
		t.key.Wipe()
		t.key = nil
	}
	if uncertain {
		return &applicationAttestorCleanup{t, cause}
	}
	return cause
}

// exchange performs one correlated update, with no retry or reconnect. A flush
// proves only transport progress; only the enrolled verifier admits the receipt.
func (t *applicationAttestorNATS) exchange(parent context.Context, evidence *ApplicationRuntimeEvidence, end bool) (failure error) {
	if t == nil || t.connection == nil || parent == nil || evidence == nil || evidence.producer == nil {
		return applicationEvidenceError("transport_invalid", nil)
	}
	subject, err := applicationAttestorSubject(t.enrollment)
	if err != nil || t.enrollment.Scope != evidence.scope {
		return applicationEvidenceError("enrollment_invalid", err)
	}
	ctx, cancel := context.WithTimeout(parent, applicationEvidenceLimit)
	defer cancel()
	if !end {
		var expiryCancel context.CancelFunc
		ctx, expiryCancel = context.WithDeadline(ctx, evidence.expiresAt)
		defer expiryCancel()
	}
	if ctx.Err() != nil {
		return applicationEvidenceError("deadline", ctx.Err())
	}
	reply, err := applicationAttestorInbox(t.enrollment, t.connection)
	if err != nil {
		return err
	}
	subscription, err := t.connection.SubscribeSync(reply)
	if err != nil {
		return applicationEvidenceError("subscription_failed", err)
	}
	defer func() {
		if err := subscription.Unsubscribe(); err != nil {
			failure = errors.Join(failure, applicationEvidenceError("subscription_cleanup_failed", err))
		}
	}()
	if err = subscription.SetPendingLimits(1, 65536); err != nil {
		return applicationEvidenceError("subscription_failed", err)
	}
	if err = t.connection.FlushWithContext(ctx); err != nil {
		return applicationEvidenceError("transport_unavailable", err)
	}
	requestID, err := hostInvocationID("observation_")
	if err != nil {
		return applicationEvidenceError("request_unavailable", err)
	}
	var request []byte
	if end {
		request, err = t.enrollment.Signer.End(ctx, evidence, requestID, reply)
	} else {
		if err = evidence.Recheck(ctx); err == nil {
			request, err = t.enrollment.Signer.Refresh(ctx, evidence, requestID, reply)
		}
	}
	if err != nil {
		return applicationEvidenceError("signing_unavailable", err)
	}
	if err = admitApplicationObservationUpdate(request, t.enrollment, evidence, requestID, reply, end, time.Now().UTC()); err != nil {
		return err
	}
	if !end {
		if err = evidence.Recheck(ctx); err != nil {
			return err
		}
	}
	if err = ownerBridgeAuthorityLastError(t.connection); err != nil {
		return applicationEvidenceError("authority_rejected", err)
	}
	if err = t.connection.PublishRequest(subject, reply, request); err != nil {
		return applicationEvidenceError("publication_uncertain", err)
	}
	if err = t.connection.FlushWithContext(ctx); err != nil {
		return applicationEvidenceError("publication_uncertain", err)
	}
	response, err := subscription.NextMsgWithContext(ctx)
	if err != nil {
		return applicationEvidenceError("receipt_unavailable", err)
	}
	if response.Subject != reply || response.Reply != "" || len(response.Data) == 0 || len(response.Data) > 65536 || len(response.Header) != 0 {
		return applicationEvidenceError("receipt_invalid", nil)
	}
	if err = t.enrollment.Signer.VerifyReceipt(ctx, response.Data, request); err != nil {
		return applicationEvidenceError("receipt_invalid", err)
	}
	if err = ownerBridgeAuthorityLastError(t.connection); err != nil {
		return applicationEvidenceError("authority_rejected", err)
	}
	if ctx.Err() != nil {
		return applicationEvidenceError("deadline", ctx.Err())
	}
	if !end {
		return evidence.Recheck(ctx)
	}
	return nil
}

func admitApplicationObservationUpdate(raw []byte, enrollment ApplicationAttestorNATSEnrollment, evidence *ApplicationRuntimeEvidence, requestID, reply string, end bool, now time.Time) error {
	if evidence == nil || evidence.producer == nil || len(raw) == 0 || len(raw) > 65536 || !validApplicationReplySubject(enrollment.ReplyPrefix, reply) {
		return applicationEvidenceError("update_invalid", nil)
	}
	wrapper, err := releaseFields(raw, "schemaVersion", "algorithm", "canonicalization", "claims", "signature")
	if err != nil {
		return applicationEvidenceError("update_invalid", err)
	}
	var version, algorithm, codec, signature string
	if json.Unmarshal(wrapper["schemaVersion"], &version) != nil || json.Unmarshal(wrapper["algorithm"], &algorithm) != nil || json.Unmarshal(wrapper["canonicalization"], &codec) != nil || json.Unmarshal(wrapper["signature"], &signature) != nil || version != "1.0.0" || algorithm != "Ed25519" || codec != "RFC8785-JCS-UTF8" {
		return applicationEvidenceError("update_invalid", nil)
	}
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || len(sig) != 64 || base64.RawURLEncoding.EncodeToString(sig) != signature {
		return applicationEvidenceError("update_invalid", err)
	}
	fields, err := releaseFields(wrapper["claims"], "purpose", "requestId", "hubId", "profileId", "authorityId", "action", "generation", "lifetimeId", "transportRef", "observationBytes", "replySubject", "issuedAt", "expiresAt")
	if err != nil {
		return applicationEvidenceError("update_invalid", err)
	}
	wantAction := "refresh"
	if end {
		wantAction = "end"
	}
	expected := map[string]string{"purpose": "agentmux-application-observation-update-v1", "requestId": requestID, "hubId": evidence.scope.HubID, "profileId": evidence.scope.ProfileID, "authorityId": enrollment.AuthorityID, "action": wantAction, "lifetimeId": evidence.lifetimeID, "replySubject": reply}
	for key, want := range expected {
		var got string
		if json.Unmarshal(fields[key], &got) != nil || got != want {
			return applicationEvidenceError("update_binding_invalid", nil)
		}
	}
	var generation uint64
	var issued, expires, observation string
	if json.Unmarshal(fields["generation"], &generation) != nil || generation != evidence.generation || json.Unmarshal(fields["issuedAt"], &issued) != nil || json.Unmarshal(fields["expiresAt"], &expires) != nil || json.Unmarshal(fields["observationBytes"], &observation) != nil {
		return applicationEvidenceError("update_binding_invalid", nil)
	}
	start, e1 := time.Parse(time.RFC3339Nano, issued)
	expiry, e2 := time.Parse(time.RFC3339Nano, expires)
	if e1 != nil || e2 != nil || start.After(now) || !now.Before(expiry) || expiry.Sub(start) > 5*time.Second || (!end && expiry.After(evidence.expiresAt)) {
		return applicationEvidenceError("update_expired", nil)
	}
	nested, err := base64.StdEncoding.DecodeString(observation)
	if err != nil || base64.StdEncoding.EncodeToString(nested) != observation || len(nested) > 65536 {
		return applicationEvidenceError("observation_invalid", err)
	}
	return admitApplicationRuntimeObservation(nested, evidence, now, end)
}

func admitApplicationRuntimeObservation(raw []byte, e *ApplicationRuntimeEvidence, now time.Time, end bool) error {
	wrapper, err := releaseFields(raw, "schemaVersion", "algorithm", "canonicalization", "claims", "signature")
	if err != nil {
		return applicationEvidenceError("observation_invalid", err)
	}
	fields, err := releaseFields(wrapper["claims"], "purpose", "hubId", "profileId", "instanceId", "generation", "lifetimeId", "releaseDigest", "policyRef", "workspaceRef", "scope", "signingKeyRef", "issuedAt", "expiresAt")
	if err != nil {
		return applicationEvidenceError("observation_invalid", err)
	}
	for key, want := range map[string]string{"purpose": "agentmux-application-runtime-observation-v1", "hubId": e.scope.HubID, "profileId": e.scope.ProfileID, "instanceId": e.scope.InstanceID, "lifetimeId": e.lifetimeID, "releaseDigest": e.scope.ReleaseManifestDigest} {
		var got string
		if json.Unmarshal(fields[key], &got) != nil || got != want {
			return applicationEvidenceError("observation_binding_invalid", nil)
		}
	}
	var generation uint64
	var issued, expires string
	if json.Unmarshal(fields["generation"], &generation) != nil || generation != e.generation || json.Unmarshal(fields["issuedAt"], &issued) != nil || json.Unmarshal(fields["expiresAt"], &expires) != nil {
		return applicationEvidenceError("observation_binding_invalid", nil)
	}
	start, e1 := time.Parse(time.RFC3339Nano, issued)
	expiry, e2 := time.Parse(time.RFC3339Nano, expires)
	if e1 != nil || e2 != nil || !expiry.After(start) || expiry.Sub(start) > applicationEvidenceValidity {
		return applicationEvidenceError("observation_expired", nil)
	}
	// An end carries the prior signed observation so the owner can check its
	// exact pinned tuple. Expired evidence may end a lease, never refresh one.
	if !end && (start.Before(e.issuedAt) || start.After(now) || !now.Before(expiry) || expiry.After(e.expiresAt)) {
		return applicationEvidenceError("observation_expired", nil)
	}
	return nil
}
