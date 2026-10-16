//go:build darwin && cgo && agentmux_bootstrap_docker

package launcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
	"github.com/nats-io/nats.go"
)

// This fixture consumes a separately reviewed, installed signed release. It
// never builds, signs, installs, elevates, contacts Docker or adopts a PID.
func sessionLifecycleFixture(t *testing.T) (*Session, *OwnerStatus, *protected.Group) {
	t.Helper()
	if os.Getuid() == 0 || os.Getuid() != os.Geteuid() || runtime.GOARCH != "arm64" {
		t.Fatal("ordinary native Mac ARM64 lifecycle fixture required")
	}
	planRaw := bootstrapDarwinPrivatePrerequisite(t, "AMX_DARWIN_ROLE_RELEASE_PLAN", "AMX_DARWIN_REVIEWED_ROLE_RELEASE_PLAN")
	var plan darwinPreparedReleasePlan
	if protocol.DecodeClosedJSON(planRaw, &plan, 64*1024) != nil || darwinPreparePlanCode(plan.StageDirectory, plan) != "" ||
		plan.SchemaVersion != "1.0.0" || plan.Purpose != "prepare_only_signed_native_darwin_arm64_release" ||
		plan.OwnerUID != 0 || plan.Group != "wheel" || plan.DirectoryMode != "0755" ||
		filepath.Dir(plan.ReleaseDirectory) != bootstrapDarwinReleaseBase || !fullID.MatchString(filepath.Base(plan.ReleaseDirectory)) ||
		plan.PublicTrust.PackageDirectory != plan.ReleaseDirectory {
		t.Fatal("reviewed nine-member role release plan refused")
	}
	rawPolicy := bootstrapDarwinPrivatePrerequisite(t, "AMX_DARWIN_ROLE_RELEASE_POLICY", "AMX_DARWIN_REVIEWED_ROLE_RELEASE_POLICY")
	var policy ReleasePolicy
	if protocol.DecodeClosedJSON(rawPolicy, &policy, 64*1024) != nil || !reflect.DeepEqual(policy, plan.PublicTrust) {
		t.Fatal("external role trust does not match reviewed release plan")
	}
	bootstrapAssertDarwinDirectory(t, policy.PackageDirectory)
	installed, err := LoadInstalledRelease(policy)
	if err != nil || installed.Trust().AssemblyDigest != plan.AssemblyDigest || installed.BrokerPins().NATSVersion != "2.15.0" {
		t.Fatal("actual signed installed release refused")
	}
	for _, member := range installed.VerifiedAssembly().Members() {
		if member.BinaryDigest != plan.KernelDigest {
			t.Fatal("installed role differs from reviewed native image")
		}
	}
	profilePolicy, profile := profileFixture(t)
	profilePolicy.InstalledReleaseFingerprint = installed.Trust().ReleaseManifestDigest
	profile.ReleaseFingerprint = installed.Trust().ReleaseManifestDigest
	profile.OrganizationID = "fixture_org"
	profile.ProjectID = "fixture_project"
	scope := protocol.Scope{HubID: installed.Trust().ReleaseAuthority.OwnerHubID, InstanceID: profile.InstanceID,
		ProfileID: profile.ProfileID, AssemblyDigest: installed.Trust().AssemblyDigest,
		ReleaseManifestDigest: installed.Trust().ReleaseManifestDigest, ReleaseVersion: installed.Trust().ReleaseVersion}
	pki := newObserverTLSFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("native lifecycle broker port unavailable")
	}
	address := listener.Addr().String()
	if listener.Close() != nil {
		t.Fatal("native lifecycle port reservation close failed")
	}
	profile.NATSEndpoint = "tls://" + address
	pki.policy.Endpoint = profile.NATSEndpoint
	trustRecord := protocol.ServerTrustRecord{SchemaVersion: protocol.Version, Endpoint: profile.NATSEndpoint,
		ServerName: pki.policy.ServerName, RootsPEM: string(pki.policy.RootsPEM), LeafCertificateSHA256: pki.policy.LeafCertificateSHA256, Scope: scope}
	trust, err := protocol.ValidateServerTrustRecord(trustRecord, scope, profile.NATSEndpoint)
	if err != nil {
		t.Fatal("scope-bound lifecycle server trust refused")
	}
	profile.ServerTrustRef = localServerTrustFile
	profile.ServerTrustDigest = releaseDigest(mustStatusJSON(trustRecord))
	trustPath := filepath.Join(profile.ProfileDirectory, localServerTrustFile)
	releaseTestWrite(t, profile.ProfileDirectory, localServerTrustFile, mustStatusJSON(trustRecord))
	credentials := communication.Credentials{}
	roles := protocol.Roles()
	for _, role := range append([]string{communication.Administrator, communication.OrdinaryPlugin}, roles[:]...) {
		secret, err := hostInvocationID("")
		if err != nil {
			t.Fatal("lifecycle credential entropy unavailable")
		}
		credentials[role] = secret
	}
	_, portText, err := net.SplitHostPort(address)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil {
		t.Fatal("native lifecycle broker port invalid")
	}
	raw, err := communication.BuildConfig(scope.HubID, port, credentials)
	if err != nil {
		t.Fatal("actual scoped broker permission factory refused")
	}
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	releaseTestWrite(t, dir, "server.crt", pki.certPEM)
	releaseTestWrite(t, dir, "server.key", pki.keyPEM)
	var config map[string]any
	if json.Unmarshal(raw, &config) != nil {
		t.Fatal("native broker configuration unavailable")
	}
	config["tls"] = map[string]any{"cert_file": cert, "key_file": key, "min_version": "1.3", "handshake_first": true}
	var configBytes bytes.Buffer
	encoder := json.NewEncoder(&configBytes)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(config) != nil {
		t.Fatal("native broker JSON encoding failed")
	}
	releaseTestWrite(t, dir, "broker.json", configBytes.Bytes())
	binary := os.Getenv("AGENTMUX_TEST_NATS")
	if !bootstrapFixtureAbsolute(binary) || releaseDigest(darwinPrepareRead(t, binary, 128*1024*1024)) != os.Getenv("AMX_DARWIN_LIFECYCLE_NATS_SHA256") {
		t.Fatal("separately pinned cached native broker required")
	}
	bootstrapCheckNativeKernel(t, binary, "arm64")
	versionCtx, versionCancel := context.WithTimeout(context.Background(), 3*time.Second)
	version, versionErr := exec.CommandContext(versionCtx, binary, "-v").Output()
	versionCancel()
	if versionErr != nil || strings.TrimSpace(string(version)) != "nats-server: v2.15.0" {
		t.Fatal("cached native broker version refused")
	}
	log, err := os.OpenFile(filepath.Join(dir, "broker.private.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("private lifecycle broker log unavailable")
	}
	broker := exec.Command(binary, "-c", filepath.Join(dir, "broker.json"))
	broker.Stdout, broker.Stderr, broker.WaitDelay = log, log, time.Second
	if broker.Start() != nil {
		if log.Close() != nil {
			t.Error("private broker log close after start failure failed")
		}
		t.Fatal("owned native TLS broker start failed")
	}
	brokerDone := make(chan error, 1)
	go func() { brokerDone <- broker.Wait() }()
	t.Cleanup(func() {
		var waitErr error
		joined := false
		select {
		case waitErr = <-brokerDone:
			joined = true
			t.Error("owned native broker exited before cleanup")
		default:
			signalErr := broker.Process.Signal(syscall.SIGTERM)
			if signalErr != nil && !errors.Is(signalErr, os.ErrProcessDone) {
				t.Error("owned broker termination failed")
			}
			select {
			case waitErr = <-brokerDone:
				joined = true
			case <-time.After(time.Second):
				t.Error("owned broker graceful shutdown incomplete")
				if killErr := broker.Process.Kill(); killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
					t.Error("owned broker kill failed")
				}
				select {
				case waitErr = <-brokerDone:
					joined = true
				case <-time.After(2 * time.Second):
					t.Error("owned native broker reaping incomplete; exact owner retained")
				}
			}
		}
		if !joined {
			return
		}
		if waitErr != nil {
			t.Error("owned native broker completion failed")
		}
		if log.Close() != nil {
			t.Error("private broker log close failed")
		}
	})
	// Admit the actual TLS listener before starting roles; their first connection
	// must not depend on scheduler timing during native broker startup.
	brokerReady := false
	brokerDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(brokerDeadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		dialer, dialErr := trust.NewDialer(ctx, 100*time.Millisecond)
		if dialErr != nil {
			cancel()
			t.Fatal("native broker TLS dialer unavailable")
		}
		nc, connectErr := nats.Connect(profile.NATSEndpoint,
			nats.UserInfo(communication.OrdinaryPlugin, credentials[communication.OrdinaryPlugin]),
			nats.TLSHandshakeFirst(), nats.SetCustomDialer(dialer), nats.NoReconnect(),
			nats.IgnoreDiscoveredServers(), nats.Timeout(100*time.Millisecond))
		if nc != nil {
			nc.Close()
		}
		closeErr := dialer.Close()
		cancel()
		if closeErr != nil {
			t.Fatal("native broker readiness transport cleanup failed")
		}
		if connectErr == nil {
			brokerReady = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !brokerReady {
		t.Fatal("actual native TLS broker did not become ready")
	}
	var options [4]protected.RoleOptions
	for i, role := range roles {
		name := role + ".json"
		credential := protocol.Credentials{SchemaVersion: protocol.Version, Role: role, Username: role,
			Password: credentials[role], NATSURL: profile.NATSEndpoint, Scope: scope}
		releaseTestWrite(t, profile.ProfileDirectory, name, mustStatusJSON(credential))
		options[i] = protected.RoleOptions{ID: role, Env: map[string]string{
			"AGENTMUX_NATS_URL": profile.NATSEndpoint, "AGENTMUX_NATS_CREDS_FILE": filepath.Join(profile.ProfileDirectory, name),
			"AGENTMUX_NATS_SERVER_TRUST_FILE": trustPath, "AGENTMUX_INSTANCE_ID": profile.InstanceID, "AGENTMUX_PROFILE_ID": profile.ProfileID}}
	}
	// No fixture-only arguments: each installed image runs its real protected role.
	prepared, err := protected.Prepare(context.Background(), installed.Assembly(), policy.PackageDirectory, installed.Trust(), protected.Limits{})
	if err != nil {
		t.Fatal("actual protected signed role preparation failed")
	}
	t.Cleanup(func() {
		if prepared.Close() != nil {
			t.Error("signed role descriptors did not close")
		}
	})
	group, err := prepared.Start(context.Background(), options, protected.Deadlines{StartTimeout: 3 * time.Second, StopGrace: 50 * time.Millisecond, ReapTimeout: 2 * time.Second})
	if group != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if group.Stop(ctx) != nil {
				t.Error("actual signed role cleanup failed")
			}
			select {
			case <-group.Done():
			default:
				t.Error("signed role children not reaped")
			}
			if group.CleanupError() != nil {
				t.Error("signed role resource cleanup failed")
			}
		})
	}
	if err != nil || group == nil {
		t.Fatal("actual four-role signed supervisor start failed")
	}
	observed := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		snapshot, observeErr := ObserveKernel(ctx, KernelStatusOptions{Endpoint: profile.NATSEndpoint,
			Password: credentials[communication.OrdinaryPlugin], Scope: scope, Timeout: 500 * time.Millisecond, TLS: trust})
		cancel()
		if errors.Is(observeErr, ErrTransportCleanup) {
			var retained *TransportCleanupError
			if !errors.As(observeErr, &retained) || retained == nil || retained.dialer == nil {
				t.Fatal("lifecycle readiness cleanup owner unavailable")
			}
			t.Cleanup(func() {
				if retained.Close() != nil {
					t.Error("lifecycle readiness retained transport cleanup failed")
				}
			})
			t.Fatal("lifecycle readiness owned transport cleanup failed")
		}
		if observeErr == nil && snapshot.KernelReadiness == "ready" && len(snapshot.Members) == 4 {
			observed = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !observed {
		t.Fatal("actual signed roles did not publish scope-bound TLS readiness")
	}
	seen := map[int]bool{}
	states := group.Status()
	if len(states) != 4 {
		t.Fatal("signed supervisor did not retain four children")
	}
	for _, state := range states {
		if state.Exited || state.PID <= 0 || seen[state.PID] {
			t.Fatal("signed children are not distinct and live")
		}
		seen[state.PID] = true
	}
	if err := EnrollProfile(profilePolicy, profile); err != nil {
		t.Fatal("lifecycle profile enrollment failed")
	}
	project := profile.ProjectID
	enrollment := OwnerEnrollment{SchemaVersion: protocol.Version, OwnerUID: profile.OwnerUID, PrincipalID: "fixture_owner",
		Identity: OwnerIdentityReference{ID: "fixture_owner_record", OwnerHubID: scope.HubID, Revision: 1},
		Scope:    OwnerScope{OrganizationID: profile.OrganizationID, ProjectID: &project}, InstanceID: profile.InstanceID,
		ProfileID: profile.ProfileID, ReleaseFingerprint: profile.ReleaseFingerprint}
	writeOwnerFixture(t, profile.ProfileDirectory, mustStatusJSON(enrollment))
	ownerPolicy := OwnerPolicy{Profile: profilePolicy, Enrollment: enrollment, KernelScope: scope,
		ServerName: "fixture_server", Domain: "fixture_domain", PublicEndpoint: profile.NATSEndpoint, PublicContextName: profile.Docker.Context}
	owner, err := LoadOwnerStatus(ownerPolicy)
	if err != nil {
		t.Fatal("actual private lifecycle owner admission failed")
	}
	// Only startup readiness above is live. This cached L04 frame deliberately
	// remains synthetic, so lifecycle overrides cannot be mistaken for live status.
	input := ownerObservationFixture(ownerPolicy, profile, "started")
	return &Session{Status: input.status, group: group, startupAttemptID: input.attemptID, observedAt: input.receivedAt}, owner, group
}
