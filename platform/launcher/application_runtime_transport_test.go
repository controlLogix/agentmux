//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/localtls"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func applicationTransportTestFrame(t *testing.T) ([]byte, ApplicationAttestorNATSEnrollment, *ApplicationRuntimeEvidence, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	scope := protocol.Scope{HubID: "fixture_hub", ProfileID: "fixture_profile", InstanceID: "fixture_instance", ReleaseManifestDigest: "sha256:" + strings.Repeat("a", 64)}
	evidence := &ApplicationRuntimeEvidence{producer: &applicationRuntimeProducer{}, scope: scope, generation: 2, lifetimeID: strings.Repeat("d", 64), issuedAt: now, expiresAt: now.Add(2 * time.Second)}
	enrollment := ApplicationAttestorNATSEnrollment{Scope: scope, AuthorityID: "fixture_authority", ReplyPrefix: "_INBOX.abcdefghijklmnop"}
	reference := map[string]any{"id": "fixture_ref", "ownerHubId": scope.HubID, "revision": 1}
	observation := map[string]any{"purpose": "agentmux-application-runtime-observation-v1", "hubId": scope.HubID, "profileId": scope.ProfileID, "instanceId": scope.InstanceID, "generation": uint64(2), "lifetimeId": evidence.lifetimeID, "releaseDigest": scope.ReleaseManifestDigest, "policyRef": reference, "workspaceRef": nil, "scope": map[string]any{"organizationId": "fixture_org", "projectId": nil, "workspaceId": nil}, "signingKeyRef": reference, "issuedAt": bridgeTime(now), "expiresAt": bridgeTime(evidence.expiresAt)}
	wrap := func(claims map[string]any) []byte {
		raw, err := json.Marshal(map[string]any{"schemaVersion": "1.0.0", "algorithm": "Ed25519", "canonicalization": "RFC8785-JCS-UTF8", "claims": claims, "signature": base64.RawURLEncoding.EncodeToString(make([]byte, 64))})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	request := map[string]any{"purpose": "agentmux-application-observation-update-v1", "requestId": "fixture_request", "hubId": scope.HubID, "profileId": scope.ProfileID, "authorityId": enrollment.AuthorityID, "action": "refresh", "generation": uint64(2), "lifetimeId": evidence.lifetimeID, "transportRef": reference, "observationBytes": base64.StdEncoding.EncodeToString(wrap(observation)), "replySubject": "_INBOX.abcdefghijklmnop.fixture_reply", "issuedAt": bridgeTime(now), "expiresAt": bridgeTime(evidence.expiresAt)}
	return wrap(request), enrollment, evidence, now
}

func TestApplicationObservationUpdatePinsRuntimeAndDoesNotExtendEvidence(t *testing.T) {
	raw, enrollment, evidence, now := applicationTransportTestFrame(t)
	admit := func(raw []byte, end bool) error {
		return admitApplicationObservationUpdate(raw, enrollment, evidence, "fixture_request", "_INBOX.abcdefghijklmnop.fixture_reply", end, now)
	}
	if err := admit(raw, false); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"hubId", "profileId", "authorityId", "generation", "lifetimeId", "action", "requestId", "replySubject", "expiresAt"} {
		t.Run(key, func(t *testing.T) {
			var frame map[string]any
			if json.Unmarshal(raw, &frame) != nil {
				t.Fatal("fixture invalid")
			}
			claims := frame["claims"].(map[string]any)
			switch key {
			case "generation":
				claims[key] = 3
			case "expiresAt":
				claims[key] = bridgeTime(now.Add(4 * time.Second))
			default:
				claims[key] = "changed"
			}
			changed, _ := json.Marshal(frame)
			if admit(changed, false) == nil {
				t.Fatal("changed runtime binding admitted")
			}
		})
	}
	for _, key := range []string{"hubId", "profileId", "instanceId", "generation", "lifetimeId", "releaseDigest", "expiresAt"} {
		t.Run("nested-"+key, func(t *testing.T) {
			var frame map[string]any
			json.Unmarshal(raw, &frame)
			claims := frame["claims"].(map[string]any)
			decoded, _ := base64.StdEncoding.DecodeString(claims["observationBytes"].(string))
			var nested map[string]any
			json.Unmarshal(decoded, &nested)
			observed := nested["claims"].(map[string]any)
			switch key {
			case "generation":
				observed[key] = 3
			case "expiresAt":
				observed[key] = bridgeTime(now.Add(4 * time.Second))
			default:
				observed[key] = "changed"
			}
			changed, _ := json.Marshal(nested)
			claims["observationBytes"] = base64.StdEncoding.EncodeToString(changed)
			changed, _ = json.Marshal(frame)
			if admit(changed, false) == nil {
				t.Fatal("changed nested evidence admitted")
			}
		})
	}
	if admit(append(raw, raw...), false) == nil || admit(make([]byte, 65537), false) == nil {
		t.Fatal("invalid bounds admitted")
	}
	// End remains possible after evidence expiry, but cannot introduce new facts.
	var frame map[string]any
	json.Unmarshal(raw, &frame)
	claims := frame["claims"].(map[string]any)
	claims["action"] = "end"
	ended, _ := json.Marshal(frame)
	evidence.expiresAt = now.Add(-time.Second)
	if err := admit(ended, true); err != nil {
		t.Fatal("exact end refused", err)
	}
	claims["observationBytes"] = "eA=="
	ended, _ = json.Marshal(frame)
	if admit(ended, true) == nil {
		t.Fatal("end carried invalid observation")
	}
}

func TestApplicationAttestorUnconfiguredCannotStartIOOrExposeCredentials(t *testing.T) {
	var server *OwnerBridgeServer
	if _, err := server.WithApplicationAttestor(ApplicationAttestorNATSEnrollment{}); err == nil {
		t.Fatal("unowned attestor admitted")
	}
	e := &ApplicationAttestorNATSEnrollment{Credentials: []byte("PRIVATE_CREDENTIAL")}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, e), "PRIVATE_CREDENTIAL") {
			t.Fatal("credential exposed")
		}
	}
	if _, err := json.Marshal(e); err == nil {
		t.Fatal("credential serialized")
	}
	if _, err := connectApplicationAttestor(context.Background(), context.Background(), *e); err == nil {
		t.Fatal("unenrolled transport admitted")
	}
	if err := runApplicationAttestor(context.Background(), nil, *e); err == nil {
		t.Fatal("unowned publisher admitted")
	}
	var transport *applicationAttestorNATS
	if err := transport.exchange(context.Background(), nil, false); err == nil {
		t.Fatal("unowned publication admitted")
	}
}

func TestApplicationAttestorHostAbsentAndCancellationJoin(t *testing.T) {
	server := &OwnerBridgeServer{}
	select {
	case <-server.startApplicationAttestor(context.Background(), nil):
	default:
		t.Fatal("absent application gained a worker")
	}
	if done, err := server.ApplicationAttestorResult(); done || err == nil {
		t.Fatal("unconfigured application claimed an outcome")
	}
	lifetime, cancel := context.WithCancel(context.Background())
	cancel()
	server.application = &applicationAttestorHost{done: make(chan struct{})}
	joined := server.startApplicationAttestor(lifetime, &bootstrapOperation{done: make(chan struct{})})
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("cancelled application worker did not join")
	}
	if done, err := server.ApplicationAttestorResult(); !done || err == nil {
		t.Fatal("cancelled worker lost its result")
	}
	select {
	case <-server.startApplicationAttestor(lifetime, nil):
	default:
		t.Fatal("same application worker was started twice")
	}
}

func TestApplicationAttestorReplyNamespaceUsesEnrolledConnectionPrefix(t *testing.T) {
	prefix := "_INBOX.abcdefghijklmnop"
	enrollment := ApplicationAttestorNATSEnrollment{ReplyPrefix: prefix}
	connection := &nats.Conn{Opts: nats.Options{InboxPrefix: prefix}}
	first, err := applicationAttestorInbox(enrollment, connection)
	if err != nil || !validApplicationReplySubject(prefix, first) {
		t.Fatal("enrolled connection inbox refused", err)
	}
	second, err := applicationAttestorInbox(enrollment, connection)
	if err != nil || first == second {
		t.Fatal("request nonce was reused")
	}
	for _, subject := range []string{"_INBOX.OTHERPRINCIPAL000.reply", prefix, prefix + ".", prefix + ".>", prefix + ".*", prefix + ".reply.extra", prefix + ".reply\n"} {
		if validApplicationReplySubject(prefix, subject) {
			t.Fatal("unowned or malformed reply subject admitted")
		}
	}
	for _, candidate := range []string{"", "_INBOX", "_INBOX.short", prefix + ".", prefix + ">", prefix + ".*", "_INBOX." + strings.Repeat("a", 65)} {
		if _, err := applicationAttestorInbox(ApplicationAttestorNATSEnrollment{ReplyPrefix: candidate}, connection); err == nil {
			t.Fatal("invalid enrollment prefix admitted")
		}
	}
	connection.Opts.InboxPrefix = "_INBOX.OTHERPRINCIPAL000"
	if _, err := applicationAttestorInbox(enrollment, connection); err == nil {
		t.Fatal("connection admitted another principal's prefix")
	}
	connection.Opts.InboxPrefix = ""
	if _, err := applicationAttestorInbox(enrollment, connection); err == nil {
		t.Fatal("ambient default inbox admitted")
	}
	raw, selected, evidence, now := applicationTransportTestFrame(t)
	selected.ReplyPrefix = "_INBOX.OTHERPRINCIPAL000"
	if admitApplicationObservationUpdate(raw, selected, evidence, "fixture_request", prefix+".fixture_reply", false, now) == nil {
		t.Fatal("signed reply escaped enrollment")
	}
}

func TestApplicationAttestorCredentialRequiresAccountAndExactPrivateGrants(t *testing.T) {
	now := time.Now()
	selection, material, _ := applicationSignerTestSelection(now)
	signer, err := applicationSignerFromMaterial(material, selection, now)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	account, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	defer account.Wipe()
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer user.Wipe()
	accountPublic, _ := account.PublicKey()
	userPublic, _ := user.PublicKey()
	seed, _ := user.Seed()
	defer clear(seed)
	enrolled := ApplicationAttestorNATSEnrollment{Scope: selection.KernelScope, OrganizationID: selection.Scope.OrganizationID, AuthorityID: selection.AuthorityID, UserPublicKey: userPublic, AccountPublicKey: accountPublic, ReplyPrefix: selection.ReplyPrefix, Trust: &localtls.ClientTrust{}, ServerName: "fixture_server", InitialGeneration: 1, Signer: signer, Credentials: []byte("pending")}
	subject, err := applicationAttestorSubject(enrolled)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(publish, subscribe []string, response any) []byte {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"ed25519-nkey"}`))
		natsClaims := map[string]any{"type": "user", "version": 2, "pub": map[string]any{"allow": publish}, "sub": map[string]any{"allow": subscribe}}
		if response != nil {
			natsClaims["resp"] = response
		}
		claims, _ := json.Marshal(map[string]any{"iss": accountPublic, "sub": userPublic, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "nats": natsClaims})
		body := header + "." + base64.RawURLEncoding.EncodeToString(claims)
		signature, err := account.Sign([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		jwt := body + "." + base64.RawURLEncoding.EncodeToString(signature)
		return []byte("-----BEGIN NATS USER JWT-----\n" + jwt + "\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n" + string(seed) + "\n------END USER NKEY SEED------\n")
	}
	enrolled.Credentials = encode([]string{subject}, []string{enrolled.ReplyPrefix + ".>"}, nil)
	credential, err := admitApplicationAttestorCredential(enrolled)
	if err != nil || credential.PublicKey() != userPublic {
		t.Fatal("exact private credential refused", err)
	}
	for _, fault := range []string{"global-inbox", "other-inbox", "extra-publication", "extra-subscription", "response-grant", "wrong-account", "wrong-user"} {
		t.Run(fault, func(t *testing.T) {
			changed := enrolled
			switch fault {
			case "global-inbox":
				changed.Credentials = encode([]string{subject}, []string{"_INBOX.>"}, nil)
			case "other-inbox":
				changed.Credentials = encode([]string{subject}, []string{"_INBOX.OTHERPRINCIPAL000.>"}, nil)
			case "extra-publication":
				changed.Credentials = encode([]string{subject, "unrelated.service"}, []string{enrolled.ReplyPrefix + ".>"}, nil)
			case "extra-subscription":
				changed.Credentials = encode([]string{subject}, []string{enrolled.ReplyPrefix + ".>", "unrelated.service"}, nil)
			case "response-grant":
				changed.Credentials = encode([]string{subject}, []string{enrolled.ReplyPrefix + ".>"}, map[string]any{"max": 1, "ttl": 1000000000})
			case "wrong-account":
				other, _ := nkeys.CreateAccount()
				defer other.Wipe()
				changed.AccountPublicKey, _ = other.PublicKey()
			case "wrong-user":
				other, _ := nkeys.CreateUser()
				defer other.Wipe()
				changed.UserPublicKey, _ = other.PublicKey()
			}
			if _, err := admitApplicationAttestorCredential(changed); err == nil {
				t.Fatal("broader or mismatched credential admitted")
			}
		})
	}
}
