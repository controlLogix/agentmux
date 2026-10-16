//go:build darwin && cgo && agentmux_bootstrap_docker && !agentmux_darwin_identity_candidate && !agentmux_darwin_identity_protected_candidate

package launcher

import (
	"bytes"
	"context"
	"crypto/tls"
	"debug/macho"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	identity "github.com/controlLogix/agentmux/platform/internal/darwinfixtureidentity"
	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/localtls"
	"github.com/controlLogix/agentmux/platform/privatefs"
	protected "github.com/controlLogix/agentmux/platform/runtime"
	"github.com/nats-io/nats.go"
	"golang.org/x/sys/unix"
)

const darwinLiveFreshness = 3 * time.Second
const darwinLiveReconnectBound = 24 * time.Second

// Failure-only roots keep the entire exact fixture reachable until this test
// process exits. This is not a registry for lookup, adoption, or cleanup retry.
var darwinLiveUnconfirmedOwners struct {
	sync.Mutex
	fixtures map[*darwinLiveFixture]struct{}
}

// This fixture consumes the same separately reviewed installed release and NATS
// pins as the cached L04 fixture. It never calls that fixture or invents a status
// frame. All assertions read actual public NATS messages from real role images.
// AGENTMUX_TEST_LIFECYCLE_OUTPUT must be an existing private retained directory.
type darwinLiveFixture struct {
	t              *testing.T
	directory      string
	planRaw        []byte
	policyRaw      []byte
	plan           darwinPreparedReleasePlan
	policy         ReleasePolicy
	installed      InstalledRelease
	scope          protocol.Scope
	wire           protocol.SubjectSet
	endpoint       string
	credentials    communication.Credentials
	trust          *localtls.ClientTrust
	options        [4]protected.RoleOptions
	brokerPath     string
	brokerDigest   string
	brokerConfig   string
	brokers        []*darwinLiveBroker
	groups         []*protected.Group
	readers        []*darwinLiveReader
	strongRetained bool
	groupRecorded  map[*protected.Group]bool
	messageCounter int
}

type darwinLiveBroker struct {
	command        *exec.Cmd
	done           chan struct{}
	waitErr        error // Read only after done closes; exactly one goroutine calls Wait.
	captures       [2]darwinLiveBrokerCapture
	startAttempted bool
	started        bool
	joined         bool
	plannedStop    bool
	finalized      bool
	completionOK   bool
	capturePrefix  string
}

type darwinLiveBrokerCapture struct {
	file               *os.File
	openAttempted      bool
	closeAttempted     bool
	closeFailed        bool
	readFile           *os.File
	readCloseAttempted bool
	readCloseFailed    bool
}

type darwinLiveReader struct {
	nc          *nats.Conn
	dialer      *localtls.Dialer
	cancel      context.CancelFunc
	closed      bool
	closeFailed bool
}

func (f *darwinLiveFixture) retainUnconfirmedOwners() {
	uncertain := false
	for _, group := range f.groups {
		select {
		case <-group.Done():
			// Joined resource failures remain accounting history, not authority
			// to retry a consumed descriptor or reopen any installation path.
			if group.CleanupError() != nil {
				uncertain = true
			}
		default:
			uncertain = true
		}
	}
	for _, broker := range f.brokers {
		// Finalization also accounts for the exact capture close attempts.
		if !broker.finalized || !broker.completionOK {
			uncertain = true
		}
	}
	for _, reader := range f.readers {
		if !reader.closed || reader.closeFailed {
			uncertain = true
		}
	}
	if !uncertain {
		return
	}
	darwinLiveUnconfirmedOwners.Lock()
	defer darwinLiveUnconfirmedOwners.Unlock()
	if darwinLiveUnconfirmedOwners.fixtures == nil {
		darwinLiveUnconfirmedOwners.fixtures = map[*darwinLiveFixture]struct{}{}
	}
	darwinLiveUnconfirmedOwners.fixtures[f] = struct{}{}
	f.strongRetained = true
}

func newDarwinLiveFixture(t *testing.T) *darwinLiveFixture {
	t.Helper()
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" || os.Getuid() == 0 || os.Getuid() != os.Geteuid() {
		t.Fatal("live signed roles require ordinary native Mac ARM64")
	}
	// This is the normal constructor only, never a diagnostic admission selector.
	if creator, err := identity.NewCreator(); err != nil || creator == nil {
		t.Fatal("normal native identity admission refused live signed fixture")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal("live fixture executable unavailable")
	}
	darwinLiveRequireSDK265(t, self)
	f := &darwinLiveFixture{t: t, groupRecorded: map[*protected.Group]bool{}}
	f.planRaw = bootstrapDarwinPrivatePrerequisite(t, "AMX_DARWIN_ROLE_RELEASE_PLAN", "AMX_DARWIN_REVIEWED_ROLE_RELEASE_PLAN")
	f.policyRaw = bootstrapDarwinPrivatePrerequisite(t, "AMX_DARWIN_ROLE_RELEASE_POLICY", "AMX_DARWIN_REVIEWED_ROLE_RELEASE_POLICY")
	if protocol.DecodeClosedJSON(f.planRaw, &f.plan, 64*1024) != nil ||
		darwinPreparePlanCode(f.plan.StageDirectory, f.plan) != "" ||
		f.plan.SchemaVersion != "1.0.0" || f.plan.Purpose != "prepare_only_signed_native_darwin_arm64_release" ||
		f.plan.OwnerUID != 0 || f.plan.Group != "wheel" || f.plan.DirectoryMode != "0755" ||
		filepath.Dir(f.plan.ReleaseDirectory) != bootstrapDarwinReleaseBase || !fullID.MatchString(filepath.Base(f.plan.ReleaseDirectory)) ||
		f.plan.PublicTrust.PackageDirectory != f.plan.ReleaseDirectory ||
		filepath.Base(f.plan.SDKRoot) != "MacOSX26.5.sdk" ||
		protocol.DecodeClosedJSON(f.policyRaw, &f.policy, 64*1024) != nil || !reflect.DeepEqual(f.policy, f.plan.PublicTrust) {
		t.Fatal("external signed live release plan or public trust refused")
	}
	f.installed, err = LoadInstalledRelease(f.policy)
	if err != nil || f.installed.Trust().AssemblyDigest != f.plan.AssemblyDigest ||
		f.installed.BrokerPins().NATSVersion != "2.15.0" || len(f.installed.VerifiedAssembly().Members()) != 4 {
		t.Fatal("actual installed signed four-role release refused")
	}
	for _, member := range f.installed.VerifiedAssembly().Members() {
		if member.BinaryDigest != f.plan.KernelDigest {
			t.Fatal("actual role image differs from reviewed release")
		}
		darwinLiveRequireSDK265(t, member.Path)
	}
	base := os.Getenv("AGENTMUX_TEST_LIFECYCLE_OUTPUT")
	if !bootstrapFixtureAbsolute(base) {
		t.Fatal("private retained live lifecycle output prerequisite required")
	}
	darwinPreparePrivateDirectory(t, base)
	f.directory, err = os.MkdirTemp(base, "signed-live-")
	if err != nil {
		t.Fatal("fresh retained live lifecycle directory unavailable")
	}
	t.Logf("retainedSignedLiveFixture=%s", f.directory)
	// Retain all exact owners and private captures on failure. Never remove a
	// protected release, discover a process, or recycle a numeric descriptor.
	t.Cleanup(func() {
		// This still runs if a later observation or receipt write calls Fatal.
		defer f.retainUnconfirmedOwners()
		groupsComplete, brokersComplete := true, true
		for i := len(f.groups) - 1; i >= 0; i-- {
			if !f.stopGroup(f.groups[i], false) {
				groupsComplete = false
				t.Error("live role cleanup incomplete; exact Group retained")
			}
		}
		for i := len(f.brokers) - 1; i >= 0; i-- {
			if !f.stopBroker(f.brokers[i], false) {
				brokersComplete = false
			}
		}
		f.retainUnconfirmedOwners()
		f.checkReleaseUnchanged()
		darwinPrepareWrite(t, filepath.Join(f.directory, "fixture-result.private.json"), mustStatusJSON(map[string]any{
			"testPassed": !t.Failed(), "ownedGroupsComplete": groupsComplete, "ownedBrokersComplete": brokersComplete,
			"groupGenerations": len(f.groups), "brokerGenerations": len(f.brokers),
			"releasePlanSHA256": releaseDigest(f.planRaw), "publicPolicySHA256": releaseDigest(f.policyRaw),
			"productionRoleTimingUnmodified": true, "cachedL04Used": false, "phaseAccepted": false,
			"failureOnlyStrongRetentionActive": f.strongRetained,
		}), 0600)
	})
	f.scope = protocol.Scope{HubID: f.installed.Trust().ReleaseAuthority.OwnerHubID,
		InstanceID: "live_instance_" + bootstrapFixtureRandom(t, 16), ProfileID: "live_profile_" + bootstrapFixtureRandom(t, 16),
		AssemblyDigest: f.installed.Trust().AssemblyDigest, ReleaseManifestDigest: f.installed.Trust().ReleaseManifestDigest,
		ReleaseVersion: f.installed.Trust().ReleaseVersion}
	wire, err := communication.Subjects(f.scope.HubID)
	if err != nil {
		t.Fatal("signed live subject scope refused")
	}
	f.wire = protocol.SubjectSet{Commands: wire.Commands, Events: wire.Events, Snapshot: wire.Snapshot, Update: wire.Update}
	f.credentials = communication.Credentials{}
	roles := protocol.Roles()
	for _, role := range append([]string{communication.Administrator, communication.OrdinaryPlugin}, roles[:]...) {
		secret, err := hostInvocationID("")
		if err != nil {
			t.Fatal("live broker credential entropy unavailable")
		}
		f.credentials[role] = secret
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("owned native loopback port unavailable")
	}
	address := listener.Addr().String()
	if listener.Close() != nil {
		t.Fatal("owned native port reservation close failed")
	}
	f.endpoint = "tls://" + address
	pki := newObserverTLSFixture(t)
	record := protocol.ServerTrustRecord{SchemaVersion: protocol.Version, Endpoint: f.endpoint, ServerName: pki.policy.ServerName,
		RootsPEM: string(pki.policy.RootsPEM), LeafCertificateSHA256: pki.policy.LeafCertificateSHA256, Scope: f.scope}
	f.trust, err = protocol.ValidateServerTrustRecord(record, f.scope, f.endpoint)
	if err != nil {
		t.Fatal("live role scope-bound TLS trust refused")
	}
	trustPath := filepath.Join(f.directory, "server-trust.private.json")
	darwinPrepareWrite(t, trustPath, mustStatusJSON(record), 0600)
	_, portText, splitErr := net.SplitHostPort(address)
	port, portErr := strconv.Atoi(portText)
	if splitErr != nil || portErr != nil {
		t.Fatal("live broker loopback port invalid")
	}
	rawConfig, err := communication.BuildConfig(f.scope.HubID, port, f.credentials)
	var config map[string]any
	if err != nil || json.Unmarshal(rawConfig, &config) != nil {
		t.Fatal("live broker scoped permission config refused")
	}
	cert, key := filepath.Join(f.directory, "server.private.crt"), filepath.Join(f.directory, "server.private.key")
	darwinPrepareWrite(t, cert, pki.certPEM, 0600)
	darwinPrepareWrite(t, key, pki.keyPEM, 0600)
	config["tls"] = map[string]any{"cert_file": cert, "key_file": key, "min_version": "1.3", "handshake_first": true}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(config) != nil {
		t.Fatal("live broker config encoding failed")
	}
	f.brokerConfig = filepath.Join(f.directory, "broker.private.json")
	darwinPrepareWrite(t, f.brokerConfig, encoded.Bytes(), 0600)
	f.brokerPath, f.brokerDigest = os.Getenv("AGENTMUX_TEST_NATS"), os.Getenv("AMX_DARWIN_LIFECYCLE_NATS_SHA256")
	f.checkBrokerPin()
	versionCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	versionCommand := exec.CommandContext(versionCtx, f.brokerPath, "-v")
	versionCommand.WaitDelay = time.Second
	versionCommand.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	version, versionErr := versionCommand.Output()
	cancel()
	if versionErr != nil || strings.TrimSpace(string(version)) != "nats-server: v2.15.0" {
		t.Fatal("pinned native broker version refused")
	}
	for i, role := range roles {
		credentialPath := filepath.Join(f.directory, role+".private.json")
		credential := protocol.Credentials{SchemaVersion: protocol.Version, Role: role, Username: role,
			Password: f.credentials[role], NATSURL: f.endpoint, Scope: f.scope}
		darwinPrepareWrite(t, credentialPath, mustStatusJSON(credential), 0600)
		f.options[i] = protected.RoleOptions{ID: role, Env: map[string]string{
			"AGENTMUX_NATS_URL": f.endpoint, "AGENTMUX_NATS_CREDS_FILE": credentialPath,
			"AGENTMUX_NATS_SERVER_TRUST_FILE": trustPath, "AGENTMUX_INSTANCE_ID": f.scope.InstanceID, "AGENTMUX_PROFILE_ID": f.scope.ProfileID}}
	}
	f.startBroker()
	return f
}

// Read the actual Mach-O SDK binding, not an ambient SDKROOT assertion. This
// refuses unknown or mixed SDK commands rather than falling back to SDK27.
func darwinLiveRequireSDK265(t *testing.T, path string) {
	t.Helper()
	image, err := macho.Open(path)
	if err != nil {
		t.Fatal("live native Mach-O SDK evidence unavailable")
	}
	valid, count := image.Cpu == macho.CpuArm64 && image.Type == macho.TypeExec, 0
	for _, load := range image.Loads {
		raw := load.Raw()
		if len(raw) < 8 {
			valid = false
			continue
		}
		switch image.ByteOrder.Uint32(raw[:4]) {
		case 0x32: // LC_BUILD_VERSION: platform, minos, sdk, ntools.
			count++
			valid = valid && len(raw) >= 24 && image.ByteOrder.Uint32(raw[8:12]) == 1 && image.ByteOrder.Uint32(raw[16:20]) == 0x001a0500
		case 0x24: // LC_VERSION_MIN_MACOSX: version, sdk.
			count++
			valid = valid && len(raw) >= 16 && image.ByteOrder.Uint32(raw[12:16]) == 0x001a0500
		}
	}
	closeErr := image.Close()
	if !valid || count != 1 || closeErr != nil {
		t.Fatal("live executable is not bound to native macOS SDK26.5")
	}
}

func (f *darwinLiveFixture) checkReleaseUnchanged() {
	f.t.Helper()
	if !bytes.Equal(f.planRaw, bootstrapDarwinPrivatePrerequisite(f.t, "AMX_DARWIN_ROLE_RELEASE_PLAN", "AMX_DARWIN_REVIEWED_ROLE_RELEASE_PLAN")) ||
		!bytes.Equal(f.policyRaw, bootstrapDarwinPrivatePrerequisite(f.t, "AMX_DARWIN_ROLE_RELEASE_POLICY", "AMX_DARWIN_REVIEWED_ROLE_RELEASE_POLICY")) {
		f.t.Fatal("external signed release inputs changed")
	}
	again, err := LoadInstalledRelease(f.policy)
	if err != nil || !reflect.DeepEqual(again.Trust(), f.installed.Trust()) || !bytes.Equal(again.Assembly(), f.installed.Assembly()) {
		f.t.Fatal("installed signed live release changed")
	}
}

func (f *darwinLiveFixture) checkBrokerPin() {
	f.t.Helper()
	if !bootstrapFixtureAbsolute(f.brokerPath) || !releaseHash.MatchString(f.brokerDigest) ||
		releaseDigest(darwinPrepareRead(f.t, f.brokerPath, 128*1024*1024)) != f.brokerDigest {
		f.t.Fatal("separately pinned native NATS prerequisite refused")
	}
	bootstrapCheckNativeKernel(f.t, f.brokerPath, "arm64")
}

func (f *darwinLiveFixture) startBroker() *darwinLiveBroker {
	f.t.Helper()
	if len(f.brokers) > 0 && (!f.brokers[len(f.brokers)-1].finalized || !f.brokers[len(f.brokers)-1].completionOK) {
		f.t.Fatal("previous exact broker must join and close before replacement")
	}
	f.checkBrokerPin()
	prefix := filepath.Join(f.directory, "broker-"+strconv.Itoa(len(f.brokers)))
	command := exec.Command(f.brokerPath, "-c", f.brokerConfig)
	command.WaitDelay = time.Second
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	b := &darwinLiveBroker{command: command, done: make(chan struct{}), capturePrefix: prefix}
	// Register both capture slots before acquisition or a fatal receipt write.
	// A failed Start owns no process: cleanup must never signal or Wait it.
	f.brokers = append(f.brokers, b)
	for i, suffix := range []string{".stdout.private", ".stderr.private"} {
		b.captures[i].openAttempted = true
		file, err := os.OpenFile(prefix+suffix, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		b.captures[i].file = file
		if err != nil {
			f.t.Fatal("private broker capture unavailable; registered owner retained for cleanup")
		}
	}
	command.Stdout, command.Stderr = b.captures[0].file, b.captures[1].file
	darwinPrepareWrite(f.t, prefix+".invocation.private.json", mustStatusJSON(map[string]any{
		"argv": command.Args, "executableSHA256": f.brokerDigest,
		"stdout": b.captures[0].file.Name(), "stderr": b.captures[1].file.Name(), "endpoint": f.endpoint,
		"role": "owned_test_broker", "rootAuthorized": false, "dockerContacted": false,
	}), 0600)
	b.startAttempted = true
	if command.Start() != nil {
		f.t.Fatal("owned live TLS broker start failed")
	}
	b.started = true
	go func() { b.waitErr = command.Wait(); close(b.done) }()
	reader := f.reader(time.Now().Add(3 * time.Second))
	reader.close(f.t)
	return b
}

func (f *darwinLiveFixture) stopBroker(b *darwinLiveBroker, deliberate bool) bool {
	f.t.Helper()
	if b.finalized {
		return b.completionOK
	}
	if !b.started {
		return f.finalizeBroker(b, deliberate)
	}
	select {
	case <-b.done:
		if !b.plannedStop {
			f.t.Error("owned broker exited without the planned fault")
		}
	default:
		b.plannedStop = true
		if err := b.command.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			f.t.Error("exact owned broker TERM failed")
		}
		// One absolute shutdown budget; escalation never creates another budget.
		deadline := time.NewTimer(3 * time.Second)
		grace := time.NewTimer(time.Second)
		defer deadline.Stop()
		defer grace.Stop()
		select {
		case <-b.done:
		case <-grace.C:
			if err := b.command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				f.t.Error("exact owned broker KILL failed")
			}
			select {
			case <-b.done:
			case <-deadline.C:
				f.retainUnconfirmedOwners()
				f.t.Error("owned broker Wait incomplete; owner and captures retained")
				return false
			}
		}
	}
	b.joined = true // Only the closed sole-Wait channel permits this transition.
	return f.finalizeBroker(b, deliberate)
}

func (f *darwinLiveFixture) finalizeBroker(b *darwinLiveBroker, deliberate bool) bool {
	f.t.Helper()
	if b.started && !b.joined {
		f.retainUnconfirmedOwners()
		f.t.Error("broker capture finalization requires its sole Wait result")
		return false
	}
	if b.waitErr != nil {
		f.t.Error("owned broker completion failed")
	}
	closeOK := true
	for i := range b.captures {
		capture := &b.captures[i]
		if capture.file != nil && !capture.closeAttempted {
			capture.closeAttempted = true // Consume once, including failed Close.
			capture.closeFailed = capture.file.Close() != nil
		}
		if capture.closeFailed {
			closeOK = false
			f.t.Error("broker capture close failed; exact accounting owner retained")
		}
	}
	b.completionOK = (!b.started || (b.joined && b.waitErr == nil)) && closeOK
	b.finalized = true
	// Publish any failure retention before later observations or writes can Fatal.
	if !b.completionOK {
		f.retainUnconfirmedOwners()
	}
	// Direct file captures have no copy workers. Inspect only after sole Wait
	// for a started process, or after a confirmed no-start, and close attempts.
	captureRecords := []map[string]any{}
	for i := range b.captures {
		capture := &b.captures[i]
		record := map[string]any{"openAttempted": capture.openAttempted, "openConfirmed": capture.file != nil,
			"closeAttempted": capture.closeAttempted, "closeFailed": capture.closeFailed}
		if capture.file != nil {
			raw := f.readBrokerCapture(capture)
			record["path"], record["sha256"], record["bytes"] = capture.file.Name(), releaseDigest(raw), len(raw)
			record["readCloseAttempted"], record["readCloseFailed"] = capture.readCloseAttempted, capture.readCloseFailed
		}
		captureRecords = append(captureRecords, record)
	}
	var exitCode any
	if b.joined && b.command.ProcessState != nil {
		exitCode = b.command.ProcessState.ExitCode()
	}
	darwinPrepareWrite(f.t, b.capturePrefix+".completion.private.json", mustStatusJSON(map[string]any{
		"startAttempted": b.startAttempted, "started": b.started, "waitJoined": b.joined,
		"waitSucceeded": b.joined && b.waitErr == nil, "exitCode": exitCode,
		"captureCloseSucceeded": closeOK, "captures": captureRecords,
		"outputCopyWorkers": 0, "plannedStop": b.plannedStop, "deliberateLoss": deliberate,
	}), 0600)
	return b.completionOK
}

// Zero bytes are valid only for these registered, completed broker captures.
// Staged executable/manifest inputs keep their existing nonempty requirement.
func (f *darwinLiveFixture) readBrokerCapture(capture *darwinLiveBrokerCapture) []byte {
	f.t.Helper()
	var owner *darwinLiveBroker
	for _, broker := range f.brokers {
		for i := range broker.captures {
			if &broker.captures[i] == capture {
				owner = broker
			}
		}
	}
	if owner == nil || !owner.finalized || (owner.started && !owner.joined) ||
		capture.file == nil || !capture.closeAttempted || capture.readFile != nil {
		f.t.Fatal("capture read requires its exact completed broker owner")
	}
	const maximum = 8 * 1024 * 1024
	fd, err := unix.Open(capture.file.Name(), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		f.t.Fatal("bounded private broker capture unavailable")
	}
	file := os.NewFile(uintptr(fd), "private-broker-capture-read")
	capture.readFile = file // Retain the exact read owner before admission can fail.
	closeRead := func() error {
		capture.readCloseAttempted = true
		closeErr := file.Close()
		capture.readCloseFailed = closeErr != nil
		if closeErr != nil {
			owner.completionOK = false
			f.retainUnconfirmedOwners()
		}
		return closeErr
	}
	var before, after unix.Stat_t
	admitted := unix.Fstat(fd, &before) == nil && before.Mode&unix.S_IFMT == unix.S_IFREG &&
		before.Uid == uint32(os.Geteuid()) && before.Nlink == 1 && before.Mode&0077 == 0 && before.Mode&06000 == 0 &&
		before.Size >= 0 && before.Size <= maximum && privatefs.CheckDescriptor(file, privatefs.PrivateObject) == nil
	if !admitted {
		closeErr := closeRead()
		f.t.Fatalf("private broker capture refused; descriptorCloseSucceeded=%t", closeErr == nil)
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	stable := unix.Fstat(fd, &after) == nil && before.Dev == after.Dev && before.Ino == after.Ino &&
		before.Uid == after.Uid && before.Gid == after.Gid && before.Mode == after.Mode && before.Nlink == after.Nlink &&
		before.Size == after.Size && before.Mtim == after.Mtim && before.Ctim == after.Ctim
	closeErr := closeRead()
	if readErr != nil || closeErr != nil || !stable || int64(len(raw)) != before.Size {
		f.t.Fatal("private broker capture changed or read descriptor close failed")
	}
	return raw
}

func (f *darwinLiveFixture) reader(deadline time.Time) *darwinLiveReader {
	f.t.Helper()
	// deadline bounds connection attempts, not the admitted observer's lifetime.
	ctx, cancel := context.WithCancel(context.Background())
	dialer, err := f.trust.NewDialer(ctx, 100*time.Millisecond)
	if err != nil {
		cancel()
		f.t.Fatal("owned live TLS observer admission failed")
	}
	r := &darwinLiveReader{dialer: dialer, cancel: cancel}
	f.readers = append(f.readers, r)
	f.t.Cleanup(func() { r.close(f.t) })
	for time.Now().Before(deadline) {
		r.nc, err = nats.Connect(f.endpoint, nats.UserInfo(communication.OrdinaryPlugin, f.credentials[communication.OrdinaryPlugin]),
			nats.TLSHandshakeFirst(), nats.SetCustomDialer(dialer), nats.NoReconnect(), nats.IgnoreDiscoveredServers(), nats.Timeout(100*time.Millisecond))
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || r.nc == nil {
		r.close(f.t)
		f.t.Fatal("actual scope-bound TLS observer unavailable")
	}
	state, err := r.nc.TLSConnectionState()
	if err != nil || state.Version != tls.VersionTLS13 || r.nc.ConnectedUrl() != f.endpoint || len(r.nc.DiscoveredServers()) != 0 {
		f.t.Fatal("live observer used an unreviewed endpoint or TLS connection")
	}
	return r
}

func (r *darwinLiveReader) close(t *testing.T) {
	t.Helper()
	if r.closed {
		return
	}
	r.closed = true
	if r.nc != nil {
		r.nc.Close()
	}
	if r.dialer.Close() != nil {
		r.closeFailed = true
		t.Error("owned live TLS observer cleanup failed")
	}
	r.cancel()
}

func (f *darwinLiveFixture) subscribe(r *darwinLiveReader, subject string) *nats.Subscription {
	f.t.Helper()
	sub, err := r.nc.SubscribeSync(subject)
	if err != nil || r.nc.FlushTimeout(time.Second) != nil {
		f.t.Fatal("actual permitted kernel subscription failed")
	}
	return sub
}

func (f *darwinLiveFixture) startGroup() *protected.Group {
	f.t.Helper()
	for _, previous := range f.groups {
		select {
		case <-previous.Done():
		default:
			f.t.Fatal("whole-group recovery cannot overlap an old owned group")
		}
		if previous.CleanupError() != nil {
			f.t.Fatal("whole-group recovery cannot hide old resource cleanup failure")
		}
	}
	f.checkReleaseUnchanged()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	prepared, err := protected.Prepare(ctx, f.installed.Assembly(), f.policy.PackageDirectory, f.installed.Trust(), protected.Limits{})
	cancel()
	if err != nil {
		f.t.Fatal("live signed role preparation failed")
	}
	// Lifetime is independent of the finite prepare/start call. The exact Group
	// is retained before assertions; no role options or timing overrides are used.
	group, startErr := prepared.Start(context.Background(), f.options,
		protected.Deadlines{StartTimeout: 5 * time.Second, StopGrace: time.Second, ReapTimeout: 2 * time.Second})
	if group != nil {
		f.groups = append(f.groups, group)
	}
	closeErr := prepared.Close()
	if startErr != nil || closeErr != nil || group == nil {
		f.t.Fatal("actual signed four-role start or image cleanup failed")
	}
	f.assertLive(group)
	return group
}

func (f *darwinLiveFixture) assertLive(group *protected.Group) map[string]int {
	f.t.Helper()
	states := group.Status()
	roles, pids := map[string]int{}, map[int]bool{}
	for _, state := range states {
		if state.Exited || state.PID <= 0 || pids[state.PID] || roles[state.Role] != 0 {
			f.t.Fatal("signed role roster is not four distinct live owned children")
		}
		roles[state.Role], pids[state.PID] = state.PID, true
	}
	for _, role := range protocol.Roles() {
		if roles[role] == 0 {
			f.t.Fatal("signed supervisor omitted a protected role")
		}
	}
	if len(states) != 4 || group.CleanupError() != nil {
		f.t.Fatal("signed role count or resource cleanup history differs")
	}
	return roles // Observations only; never process adoption or signaling authority.
}

func (f *darwinLiveFixture) stopGroup(group *protected.Group, requireQuiet bool) bool {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	err := group.Stop(ctx)
	cancel()
	if err != nil {
		f.t.Error("exact signed role shutdown incomplete")
	}
	select {
	case <-group.Done():
	default:
		f.retainUnconfirmedOwners()
		f.t.Error("signed role sole Wait results are incomplete")
		return false
	}
	cleanupOK := group.CleanupError() == nil
	if !cleanupOK {
		f.t.Error("signed role resource cleanup history failed")
	}
	quiet, complete := true, true
	outputs := map[string][]byte{}
	states := group.Status()
	for _, state := range states {
		if !state.Exited {
			f.t.Error("owned signed role remained live after shutdown")
			complete = false
			continue
		}
		out, truncated := group.Output(state.Role)
		outputs[state.Role] = out
		if truncated || (requireQuiet && len(out) != 0) {
			f.t.Error("joined signed role diagnostics were truncated or unexpectedly nonempty")
			quiet = false
		}
		f.t.Logf("joinedRole=%s outputSHA256=%s bytes=%d exitCode=%d", state.Role, releaseDigest(out), len(out), state.ExitCode)
	}
	if !f.groupRecorded[group] {
		index := -1
		for i, candidate := range f.groups {
			if candidate == group {
				index = i
			}
		}
		if index < 0 {
			f.t.Fatal("group capture requires this fixture's exact retained owner")
		}
		for role, out := range outputs {
			darwinPrepareWrite(f.t, filepath.Join(f.directory, "group-"+strconv.Itoa(index)+"-"+role+".output.private"), out, 0600)
		}
		f.groupRecorded[group] = true
	}
	return err == nil && cleanupOK && quiet && complete
}

func (f *darwinLiveFixture) snapshot(sub *nats.Subscription, deadline time.Time, predicate func(protocol.Snapshot) bool) (protocol.Snapshot, []byte) {
	f.t.Helper()
	for time.Now().Before(deadline) {
		message, err := sub.NextMsg(min(time.Second, time.Until(deadline)))
		if errors.Is(err, nats.ErrTimeout) {
			continue
		}
		if err != nil {
			f.t.Fatal("live kernel observer stopped before required observation")
		}
		frame, err := protocol.DecodeSnapshot(message.Data, f.scope, time.Now(), darwinLiveFreshness)
		if err != nil {
			f.t.Fatal("actual signed process snapshot violated scope or production freshness")
		}
		if predicate(frame) {
			f.messageCounter++
			// Store the exact public message, not a reconstructed ready/status frame.
			darwinPrepareWrite(f.t, filepath.Join(f.directory, "public-frame-"+strconv.Itoa(f.messageCounter)+".json"), message.Data, 0600)
			return frame, append([]byte(nil), message.Data...)
		}
	}
	f.t.Fatal("live protected observation exceeded its original absolute deadline")
	return protocol.Snapshot{}, nil
}

func darwinLiveReady(after time.Time) func(protocol.Snapshot) bool {
	return func(frame protocol.Snapshot) bool {
		observed, err := time.Parse(time.RFC3339Nano, frame.ObservedAt)
		if frame.KernelReadiness != "ready" || err != nil || observed.Before(after) {
			return false
		}
		seen := map[string]bool{}
		for _, member := range frame.Members {
			observed, err := time.Parse(time.RFC3339Nano, member.ObservedAt)
			if member.State != "ready" || member.Incarnation == "" || err != nil || observed.Before(after) || seen[member.Role] {
				return false
			}
			seen[member.Role] = true
		}
		for _, role := range protocol.Roles() {
			if !seen[role] {
				return false
			}
		}
		return len(seen) == 4
	}
}
