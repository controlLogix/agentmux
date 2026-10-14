package deployment

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

type teamResolverFunc func(context.Context, TeamCredentialReference) (TeamCredential, error)

func (f teamResolverFunc) Resolve(ctx context.Context, ref TeamCredentialReference) (TeamCredential, error) {
	return f(ctx, ref)
}

func teamTestPolicy(t *testing.T) TeamConnectionPolicy {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("fixture trust entropy unavailable")
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Disposable team fixture CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal("fixture trust creation failed")
	}
	return TeamConnectionPolicy{Endpoint: "tls://127.0.0.1:4222", TLSServerName: "localhost", TLSRootsPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ExpectedServerName: "fixture_server", ExpectedDomain: "fixture_domain", ExpectedServerVersion: "2.15.0", Scope: TeamScope{OrganizationID: "fixture_org", ProjectID: "fixture_project", Kernel: protocol.Scope{HubID: "fixture_hub", InstanceID: "fixture_instance", ProfileID: "fixture_profile", AssemblyDigest: "sha256:" + strings.Repeat("a", 64), ReleaseManifestDigest: "sha256:" + strings.Repeat("b", 64), ReleaseVersion: "1.0.0"}}, CredentialRef: TeamCredentialReference{ID: "fixture_credential", AuthKind: TeamBasic}, Timeout: time.Second}
}

func TestTeamPolicyAndCredentialAdmissionBeforeNetwork(t *testing.T) {
	p := teamTestPolicy(t)
	called := 0
	resolver := teamResolverFunc(func(ctx context.Context, ref TeamCredentialReference) (TeamCredential, error) {
		called++
		scope := p.Scope
		scope.ProjectID = "wrong_project"
		return NewTeamBasicCredential(ref, scope, "fixture_user", strings.Repeat("c", 48))
	})
	connection, err := NewTeamConnection(p, resolver)
	if err != nil {
		t.Fatal("valid explicit TLS policy rejected")
	}
	out, err := connection.Observe(context.Background())
	if err == nil || err.Error() != "team_credential_binding_invalid" || out.TLSVerified || out.Authenticated || called != 1 {
		t.Fatal("self-selected credential scope reached network or passed admission")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := connection.Observe(ctx); err == nil || err.Error() != "team_deadline" || called != 1 {
		t.Fatal("cancelled call invoked resolver")
	}
	p.Endpoint = "nats://127.0.0.1:4222"
	if _, err := NewTeamConnection(p, resolver); err == nil {
		t.Fatal("plaintext team endpoint admitted")
	}
}

func TestTeamCredentialFormattingDoesNotExposeSecrets(t *testing.T) {
	p := teamTestPolicy(t)
	password := strings.Repeat("c", 48)
	credential, err := NewTeamBasicCredential(p.CredentialRef, p.Scope, "fixture_private_user", password)
	if err != nil {
		t.Fatal("explicit compatible credential rejected")
	}
	raw, err := json.Marshal(credential)
	if err != nil {
		t.Fatal("credential redaction failed")
	}
	for _, value := range []string{string(raw), fmt.Sprint(credential), fmt.Sprintf("%#v", credential)} {
		if strings.Contains(value, password) || strings.Contains(value, "fixture_private_user") {
			t.Fatal("default credential output exposed private authentication")
		}
	}
}

func TestTeamCancellationAfterUnavailableSetupRetainsValidatedFacts(t *testing.T) {
	for _, snapshotAvailable := range []bool{false, true} {
		name := "unavailable-snapshot"
		if snapshotAvailable {
			name = "validated-snapshot"
		}
		t.Run(name, func(t *testing.T) {
			f := newJWTWorkerFixture(t)
			f.policy.ObserveDomain = true
			// This genuinely signed user can authenticate but cannot subscribe to the
			// selected snapshot or publish account INFO requests. The broker enforces it.
			subjects := []string{"fixture.never"}
			if snapshotAvailable {
				wire, _ := communication.Subjects(f.policy.Scope.Kernel.HubID)
				subjects = []string{wire.Snapshot, "_INBOX.>"}
				f.publishSnapshots(t, f.policy.Scope.Kernel)
			}
			token := jwtWorkerUser(t, f.account, f.user, []string{"fixture.never"}, subjects)
			resolver := jwtWorkerResolver{token: token, seed: f.seed, scope: f.policy.Scope}
			connection, err := NewTeamConnection(f.policy, resolver)
			if err != nil {
				t.Fatal("enrolled fixture connection policy rejected")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			out, err := connection.observeChecked(ctx, cancel)
			if err == nil || err.Error() != "team_deadline" || out.Code != "observation_cancelled" || !out.TLSVerified || !out.Authenticated || !out.ServerIdentityVerified || out.BrokerVerified || out.DomainAvailability != "unavailable" || (out.Snapshot != nil) != snapshotAvailable {
				t.Fatal("caller cancellation was hidden or discarded independently validated connection facts")
			}
			if snapshotAvailable && (out.KernelAvailability != "available" || out.Snapshot.Scope != f.policy.Scope.Kernel) {
				t.Fatal("caller cancellation discarded independently validated scoped snapshot")
			}
			if !snapshotAvailable && out.KernelAvailability != "unavailable" {
				t.Fatal("denied snapshot became available during cancellation")
			}
		})
	}
}
