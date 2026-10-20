//go:build linux || darwin

package launcher

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/boot"
	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/lifecycle"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/kernel/status"
	"github.com/nats-io/nats.go"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type bridgeFixture struct {
	config     BootstrapConfig
	policy     OwnerPolicy
	profile    Profile
	enrollment OwnerBridgeEnrollment
	owner      *OwnerStatus
	raw        []byte
	users      communication.Credentials
}

func newBridgeFixture(t *testing.T) bridgeFixture {
	t.Helper()
	host := bridgeHostFixture(t)
	// This admitted fixture performs real inspection subprocesses before TLS.
	// The configured three-second probe stays inside the product's five-second
	// total cap; earlier caller deadlines still bound every operation.
	host.policy.ProbeTimeout = 3 * time.Second
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("fixture port unavailable")
	}
	address := listener.Addr().String()
	listener.Close()
	host.profile.NATSEndpoint = "tls://" + address
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("controlled inspection executable unavailable")
	}
	host.profile.Docker.Executable = executable
	host.profile.Docker.Context = "bridge_fixture"
	host.profile.Docker.Endpoint = "unix:///private/bridge.sock"
	host.profile.Docker.EngineID = "bridge_engine"
	scope := host.policy.OwnerBridge.Scope
	trustRecord := protocol.ServerTrustRecord{SchemaVersion: protocol.Version, Endpoint: host.profile.NATSEndpoint, ServerName: host.material.ServerName(), RootsPEM: string(host.material.RootsPEM()), LeafCertificateSHA256: host.material.LeafCertificateSHA256(), Scope: scope}
	trustRaw := mustStatusJSON(trustRecord)
	host.profile.ServerTrustDigest = releaseDigest(trustRaw)
	releaseTestWrite(t, host.profile.ProfileDirectory, localServerTrustFile, trustRaw)
	for _, role := range protocol.Roles() {
		credential := protocol.Credentials{SchemaVersion: protocol.Version, Role: role, Username: role, Password: host.credentials[role], NATSURL: host.profile.NATSEndpoint, Scope: scope}
		releaseTestWrite(t, host.profile.ProfileDirectory, role+".json", mustStatusJSON(credential))
	}
	release, err := LoadInstalledRelease(host.policy.ExternalRelease)
	if err != nil {
		t.Fatal("actual signed fixture release rejected")
	}
	_, portText, _ := net.SplitHostPort(address)
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal("fixture port invalid")
	}
	compose, err := deployment.RenderSecureCompose(deployment.ComposeSpec{Project: host.profile.ComposeProject, InstanceID: host.profile.InstanceID, ProfileID: host.profile.ProfileID, ReleaseDigest: host.profile.ReleaseFingerprint, Image: release.BrokerPins().Image, HostPort: port, BrokerConfig: host.broker}, host.material)
	if err != nil {
		t.Fatal("actual secure renderer rejected fixture")
	}
	host.profile.ConfigDigest = releaseDigest(compose)
	releaseTestWrite(t, host.profile.ProfileDirectory, "profile.json", mustStatusJSON(host.profile))
	config, err := LoadBootstrapConfig(host.policy)
	if err != nil {
		t.Fatal("actual secure private admission rejected", err)
	}
	ownerEnrollment := OwnerEnrollment{SchemaVersion: protocol.Version, OwnerUID: host.profile.OwnerUID, PrincipalID: "bridge_owner", Identity: OwnerIdentityReference{ID: "bridge_identity", OwnerHubID: scope.HubID, Revision: 1}, Scope: OwnerScope{OrganizationID: "bridge_org"}, InstanceID: host.profile.InstanceID, ProfileID: host.profile.ProfileID, ReleaseFingerprint: host.profile.ReleaseFingerprint}
	writeOwnerFixture(t, host.profile.ProfileDirectory, mustStatusJSON(ownerEnrollment))
	policy := OwnerPolicy{Profile: host.policy.Profile, Enrollment: ownerEnrollment, KernelScope: scope, ServerName: host.metadata.ServerName, Domain: host.metadata.Domain, PublicEndpoint: host.profile.NATSEndpoint, PublicContextName: host.profile.Docker.Context}
	owner, err := LoadOwnerStatus(policy)
	if err != nil {
		t.Fatal("actual fixture owner rejected")
	}
	enrollment := OwnerBridgeEnrollment{Owner: ownerEnrollment, Credentials: OwnerBridgeCredentialRefs{Server: "host-server.json", Client: "host-client.json"}}
	for role, name := range map[string]string{deployment.OwnerBridgeServerUser: enrollment.Credentials.Server, deployment.OwnerBridgeClientUser: enrollment.Credentials.Client} {
		password := config.OwnerBridge.ClientPassword
		if role == deployment.OwnerBridgeServerUser {
			password = config.OwnerBridge.ServerPassword
		}
		credential := OwnerBridgeCredential{protocol.Version, role, scope, ownerEnrollment, password}
		releaseTestWrite(t, host.profile.ProfileDirectory, name, mustStatusJSON(credential))
	}
	return bridgeFixture{config, policy, host.profile, enrollment, owner, host.broker, host.credentials}
}

func TestOwnerBridgeSchemaCopiesAndFullAdmission(t *testing.T) {
	for urn, raw := range ownerBridgeSchemaResources {
		name := strings.TrimPrefix(urn, "urn:agentmux:contract:1:")
		actual, err := os.ReadFile(filepath.Join("..", "..", "contracts", "v1", "schemas", name+".schema.json"))
		if err != nil || !bytes.Equal(actual, []byte(raw)) {
			t.Fatal("embedded schema drifted from authoritative source")
		}
	}
	if _, err := (ownerBridgeDenyLoader{}).Load("file:///untrusted.json"); err == nil {
		t.Fatal("external schema loading enabled")
	}
	f := newBridgeFixture(t)
	id := "attempt_" + strings.Repeat("a", 32)
	input := ownerObservationFixture(f.policy, f.profile, "reused")
	input.attemptID = id
	out, err := f.owner.mapObservation(input)
	if err != nil {
		t.Fatal("otherwise-valid observation unavailable")
	}
	reply := ownerBridgeReply{protocol.Version, "host-owner-status-reply", "request_" + strings.Repeat("b", 32), id, f.config.Kernel.Scope, bridgeTime(time.Now()), out}
	valid := mustStatusJSON(reply)
	if decodeBridgeReply(valid, &ownerBridgeReply{}) != nil {
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		compiler.UseLoader(ownerBridgeDenyLoader{})
		for urn, raw := range ownerBridgeSchemaResources {
			value, _ := jsonschema.UnmarshalJSON(strings.NewReader(raw))
			compiler.AddResource(urn, value)
		}
		schema, compileErr := compiler.Compile("urn:agentmux:contract:1:host-owner-status-reply")
		if compileErr != nil {
			t.Fatal("fixed public schema compilation failed", compileErr)
		}
		value, _ := jsonschema.UnmarshalJSON(bytes.NewReader(valid))
		t.Fatal("otherwise-valid reply rejected", schema.Validate(value))
	}
	failed, err := f.owner.mapObservation(ownerStatusObservation{status: BootstrapStatus{Disposition: "failed", Profile: (LoadedProfile{f.profile}).Summary()}, receivedAt: time.Now().UTC(), attemptID: id})
	if err != nil || !bridgeObservationBound(failed, f.enrollment, id, time.Now()) {
		t.Fatal("failure mapper/binding boundary invalid", err)
	}
	failureReply := reply
	failureReply.Observation = failed
	if err := decodeBridgeReply(mustStatusJSON(failureReply), &ownerBridgeReply{}); err != nil {
		t.Fatal("otherwise-valid failed observation rejected", err)
	}
	mutations := map[string]func(map[string]any){
		"error_nul":              func(o map[string]any) { o["errors"].([]any)[0].(map[string]any)["message"] = "unsafe\x00text" },
		"error_cr":               func(o map[string]any) { o["errors"].([]any)[0].(map[string]any)["message"] = "unsafe\rtext" },
		"missing_nullable":       func(o map[string]any) { delete(o["work"].(map[string]any), "active") },
		"missing_scope_nullable": func(o map[string]any) { delete(o["caller"].(map[string]any)["scope"].(map[string]any), "workspaceId") },
		"enum":                   func(o map[string]any) { o["persistence"].(map[string]any)["availability"] = "invented" },
		"fraction_revision":      func(o map[string]any) { o["sourceRevision"] = 1.5 },
		"unsafe_revision":        func(o map[string]any) { o["sourceRevision"] = uint64(9007199254740992) },
		"conditional_service": func(o map[string]any) {
			service := o["instance"].(map[string]any)["services"].([]any)[0].(map[string]any)
			service["availability"] = "unavailable"
			service["readiness"] = "ready"
			service["unavailableReason"] = "probe_failed"
		},
		"conditional_work": func(o map[string]any) { o["work"].(map[string]any)["active"] = 1 },
		"conditional_pressure": func(o map[string]any) {
			o["persistence"].(map[string]any)["storagePressure"].(map[string]any)["percentUsed"] = 1
		},
		"conditional_replication": func(o map[string]any) {
			o["persistence"].(map[string]any)["replicationHealth"].(map[string]any)["replicas"] = 1
		},
		"conditional_hubs":        func(o map[string]any) { o["hubs"].(map[string]any)["entries"] = []any{map[string]any{}} },
		"conditional_disposition": func(o map[string]any) { o["disposition"] = "failed"; o["errors"] = []any{} },
		"private_endpoint": func(o map[string]any) {
			o["instance"].(map[string]any)["endpoint"] = "nats://user:password@127.0.0.1:4222"
		},
		"error_newline": func(o map[string]any) { o["errors"].([]any)[0].(map[string]any)["message"] = "unsafe\ntext" },
		"error_count": func(o map[string]any) {
			row := o["errors"].([]any)[0]
			rows := []any{}
			for i := 0; i < 33; i++ {
				rows = append(rows, row)
			}
			o["errors"] = rows
		},
	}
	corpus := []map[string]any{{"name": "positive", "accepted": true, "value": json.RawMessage(valid)}}
	var unicodePositive map[string]any
	json.Unmarshal(valid, &unicodePositive)
	unicodePositive["observation"].(map[string]any)["errors"].([]any)[0].(map[string]any)["message"] = "Allowed café 😀."
	unicodeRaw := mustStatusJSON(unicodePositive)
	if decodeBridgeReply(unicodeRaw, &ownerBridgeReply{}) != nil {
		t.Fatal("valid unicode excluded by schema engine")
	}
	corpus = append(corpus, map[string]any{"name": "unicode_positive", "accepted": true, "value": json.RawMessage(unicodeRaw)})
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var tree map[string]any
			json.Unmarshal(valid, &tree)
			mutate(tree["observation"].(map[string]any))
			raw := mustStatusJSON(tree)
			if decodeBridgeReply(raw, &ownerBridgeReply{}) == nil {
				t.Fatal("full L04 shape violation admitted")
			}
			corpus = append(corpus, map[string]any{"name": name, "accepted": false, "value": json.RawMessage(raw)})
		})
	}
	if dir := os.Getenv("AGENTMUX_OWNER_BRIDGE_OUTPUTS"); dir != "" {
		if os.WriteFile(filepath.Join(dir, "admission-corpus.json"), mustStatusJSON(corpus), 0600) != nil {
			t.Fatal("safe admission evidence unavailable")
		}
	}
}

func TestOwnerBridgeRegexpTimeoutFailsClosed(t *testing.T) {
	pattern, err := compileOwnerBridgeRegexp(`^(a+)+$`)
	if err != nil {
		t.Fatal("controlled pathological regex unavailable")
	}
	before := time.Now()
	if pattern.MatchString(strings.Repeat("a", 32768) + "!") {
		t.Fatal("regex timeout was treated as a match")
	}
	if time.Since(before) > time.Second {
		t.Fatal("controlled regex timeout exceeded safe test bound")
	}
	for _, value := range []string{"bad\rtext", "bad\ntext", "bad\x00text"} {
		pattern, err := compileOwnerBridgeRegexp(`^[^\r\n\u0000]+$`)
		if err != nil || pattern.MatchString(value) {
			t.Fatal("accepted ECMAScript exclusion semantics changed")
		}
	}
}

func (f bridgeFixture) startActors(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	wire, _ := communication.Subjects(f.config.Kernel.Scope.HubID)
	subjects := protocol.SubjectSet{Commands: wire.Commands, Events: wire.Events, Snapshot: wire.Snapshot, Update: wire.Update}
	for _, role := range protocol.Roles() {
		config := protocol.Config{Credentials: protocol.Credentials{SchemaVersion: protocol.Version, Role: role, Username: role, Password: f.users[role], NATSURL: f.config.Kernel.Endpoint, Scope: f.config.Kernel.Scope}, ServerTrust: f.config.Kernel.TLS}
		done := make(chan error, 1)
		go func() {
			var err error
			switch role {
			case "boot":
				err = boot.Run(ctx, config, subjects)
			case "kernel-lifecycle":
				err = lifecycle.Run(ctx, config, subjects)
			case "internal-communication":
				err = communication.Run(ctx, config, subjects)
			case "exported-status":
				err = status.Run(ctx, config, subjects)
			}
			done <- err
		}()
		t.Cleanup(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Error("owned actor cleanup failed")
				}
			case <-time.After(2 * time.Second):
				t.Error("owned actor cleanup exceeded deadline")
			}
		})
	}
	deadline := time.Now().Add(4 * time.Second)
	for {
		frame, err := ObserveKernel(ctx, f.config.Kernel)
		if err == nil && frame.KernelReadiness == "ready" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("real scoped actor readiness unavailable", err, frame.KernelReadiness)
		}
	}
}

type bridgeDockerSpec struct {
	Profile          Profile
	Raw              []byte
	Image            string
	Certificate, Key []byte
}

func init() {
	if name := os.Getenv("AMX_OWNER_BRIDGE_DOCKER_FIXTURE"); name != "" {
		bridgeDockerProcess(name)
		os.Exit(0)
	}
}
func bridgeDockerProcess(name string) {
	raw, err := os.ReadFile(name)
	var spec bridgeDockerSpec
	if err != nil || json.Unmarshal(raw, &spec) != nil {
		os.Exit(3)
	}
	p := spec.Profile
	args := os.Args[1:]
	if len(args) < 3 || args[0] != "--context" || args[1] != p.Docker.Context {
		os.Exit(3)
	}
	args = args[2:]
	id := strings.Repeat("a", 64)
	fault := os.Getenv("AMX_OWNER_BRIDGE_DOCKER_FAULT")
	recoveryState := os.Getenv("AMX_OWNER_BRIDGE_RECOVERY_STATE")
	state := "running"
	if recoveryState != "" {
		current, err := os.ReadFile(recoveryState)
		if err != nil {
			os.Exit(3)
		}
		state = string(current)
		if state == "replaced" {
			id = strings.Repeat("b", 64)
		}
	}
	labels := map[string]string{"agentmux.profile.id": p.ProfileID, "agentmux.instance.id": p.InstanceID, "agentmux.release.digest": p.ReleaseFingerprint, "com.docker.compose.project": p.ComposeProject}
	emit := func(v any) { json.NewEncoder(os.Stdout).Encode(v) }
	switch args[0] {
	case "context":
		if fault == "context" {
			emit("unix:///foreign/docker.sock")
			return
		}
		emit(p.Docker.Endpoint)
	case "version":
		if fault == "version" {
			emit(map[string]string{"Client": "0.0.0", "Server": "0.0.0"})
			return
		}
		emit(map[string]string{"Client": p.Docker.ClientVersion, "Server": p.Docker.ServerVersion})
	case "info":
		if fault == "engine" {
			emit(map[string]string{"ID": "foreign_engine", "OS": "linux"})
			return
		}
		emit(map[string]string{"ID": p.Docker.EngineID, "OS": "linux"})
	case "compose":
		if len(args) != 3 || args[1] != "version" {
			os.Exit(3)
		}
		fmt.Println(p.Docker.ComposeVersion)
	case "ps":
		if state != "absent" {
			fmt.Println(id)
		}
	case "image":
		if fault == "image" {
			emit("sha256:" + strings.Repeat("f", 64))
			return
		}
		emit("sha256:" + strings.Repeat("e", 64))
	case "volume":
		emit(labels)
	case "container":
		if len(args) > 1 && args[1] == "start" {
			if recoveryState == "" || state != "stopped" || len(args) != 3 || args[2] != id {
				os.Exit(3)
			}
			if err := os.WriteFile(recoveryState+".started", []byte(id), 0600); err != nil {
				os.Exit(3)
			}
			if err := os.WriteFile(recoveryState, []byte("running"), 0600); err != nil {
				os.Exit(3)
			}
			fmt.Println(id)
			return
		}
		u, _ := url.Parse(p.NATSEndpoint)
		_, port, _ := net.SplitHostPort(u.Host)
		a := brokerInspection{ID: id, Image: "sha256:" + strings.Repeat("e", 64)}
		a.Config.Image = spec.Image
		a.Config.Labels = labels
		a.Config.Labels["com.docker.compose.service"] = "nats"
		a.Config.Labels["com.docker.compose.oneoff"] = "False"
		a.State.Status = "running"
		a.State.Running = true
		if state == "stopped" {
			a.State.Status, a.State.Running = "exited", false
		}
		a.HostConfig.PortBindings = map[string][]brokerPort{"4222/tcp": {{HostIP: "127.0.0.1", HostPort: port}}}
		a.NetworkSettings.Ports = a.HostConfig.PortBindings
		if fault == "port" {
			a.HostConfig.PortBindings = map[string][]brokerPort{"4222/tcp": {{HostIP: "0.0.0.0", HostPort: port}}}
			a.NetworkSettings.Ports = a.HostConfig.PortBindings
		}
		a.Mounts = []brokerMount{{Type: "volume", Name: p.ComposeProject + "_data", Destination: "/data", RW: true}}
		emit(a)
	case "cp":
		body, name := spec.Raw, "private.conf"
		if strings.Contains(strings.Join(args, " "), deployment.PrivateServerCertTarget) {
			body, name = spec.Certificate, "server-cert.pem"
		}
		if strings.Contains(strings.Join(args, " "), deployment.PrivateServerKeyTarget) {
			body, name = spec.Key, "server-key.pem"
		}
		if (fault == "config" && name == "private.conf") || (fault == "cert" && name == "server-cert.pem") || (fault == "key" && name == "server-key.pem") {
			body = append(append([]byte(nil), body...), byte('x'))
		}
		writer := tar.NewWriter(os.Stdout)
		writer.WriteHeader(&tar.Header{Name: name, Mode: 0400, Size: int64(len(body)), Typeflag: tar.TypeReg})
		writer.Write(body)
		writer.Close()
	default:
		os.Exit(3)
	}
}
func (f bridgeFixture) controlledDocker(t *testing.T) {
	t.Helper()
	name := filepath.Join(t.TempDir(), "private-inspection.json")
	if os.WriteFile(name, mustStatusJSON(bridgeDockerSpec{f.profile, f.raw, f.config.BrokerImage, f.config.LocalTLS.ServerCertificatePEM(), f.config.LocalTLS.ServerKeyPEM()}), 0600) != nil {
		t.Fatal("private controlled inspector unavailable")
	}
	t.Setenv("AMX_OWNER_BRIDGE_DOCKER_FIXTURE", name)
	// This inspector re-executes the race-built test binary, not Docker. Remove
	// only its exit delay; keep race checks and inherited detector options. The
	// parent detector is already initialized, and protected role/host environments
	// do not inherit this test-only setting. Setenv restores the environment.
	t.Setenv("GORACE", strings.TrimSpace(os.Getenv("GORACE")+" atexit_sleep_ms=0"))
}

func TestOwnerBridgeControlledDockerRaceExitDelayIsScoped(t *testing.T) {
	const inherited = "history_size=2 exitcode=66"
	t.Setenv("GORACE", inherited)
	f := newBridgeFixture(t)
	t.Run("controlled_inspector", func(t *testing.T) {
		f.controlledDocker(t)
		if os.Getenv("AMX_OWNER_BRIDGE_DOCKER_FIXTURE") == "" {
			t.Fatal("controlled inspector was not selected")
		}
		if os.Getenv("GORACE") != inherited+" atexit_sleep_ms=0" {
			t.Fatal("controlled inspector lost inherited race options or kept its exit delay")
		}
	})
	if os.Getenv("GORACE") != inherited {
		t.Fatal("controlled inspector leaked its race exit setting")
	}
}

func TestOwnerBridgeDelayedOriginalInvocationRefreshesActualFacts(t *testing.T) {
	f := newBridgeFixture(t)
	f.startBroker(t)
	f.startActors(t)
	f.controlledDocker(t)
	probe, err := deployment.ProvisionAndProbe(context.Background(), f.config.Health)
	if err != nil {
		t.Fatal("real FILE probe failed")
	}
	server, err := LoadOwnerBridgeServer(f.config, f.owner, f.enrollment)
	if err != nil {
		t.Fatal("server rejected")
	}
	client, err := LoadOwnerBridgeClient(f.config, f.enrollment)
	if err != nil {
		t.Fatal("client rejected")
	}
	invocation := "attempt_" + strings.Repeat("d", 32)
	input := ownerObservationFixture(f.policy, f.profile, "reused")
	session := &Session{Status: input.status, observedAt: time.Now().Add(-10 * time.Second), startupAttemptID: invocation, healthProof: &completedHealthProbe{result: probe, scope: f.config.Kernel.Scope, endpoint: f.config.Kernel.Endpoint, completedAt: time.Now().Add(-10 * time.Second)}}
	// The stale cached frame and proof timestamp are controlled negative inputs.
	// The refresh reads real actors and FILE storage; Docker facts come from a
	// real controlled inspection subprocess, not an actual Docker engine.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	ready := make(chan struct{})
	go func() { done <- server.serve(ctx, invocation, session, nil, ready) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("transport cleanup incomplete")
		}
	}()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("service unavailable")
	}
	for i := 0; i < 2; i++ {
		out, err := client.Request(context.Background(), "status", invocation)
		if err != nil || out.Disposition != "reused" || out.Persistence.Availability != "available" || out.Persistence.Readiness != "unknown" || out.Instance.RunningVersion == nil || *out.StartupAttemptID != invocation {
			t.Fatal("same delayed invocation remained stale or invented cold proof", err, out.Disposition, out.Persistence.Availability, out.Persistence.Readiness)
		}
		if dir := os.Getenv("AGENTMUX_OWNER_BRIDGE_OUTPUTS"); dir != "" {
			os.WriteFile(filepath.Join(dir, "delayed-"+strconv.Itoa(i)+".json"), mustStatusJSON(out), 0600)
		}
	}
	if time.Since(session.observedAt) < 9*time.Second {
		t.Fatal("cached receipt was retimestamped")
	}
}

func TestOwnerBridgeTerminalFailureReleasesServiceLease(t *testing.T) {
	f := newBridgeFixture(t)
	f.startBroker(t)
	// This is an actual Bootstrap guard failure before Docker or role startup.
	// The reachable TLS fixture broker transports the authenticated failure.
	f.config.StartupTimeout = 0
	server, err := LoadOwnerBridgeServer(f.config, f.owner, f.enrollment)
	if err != nil {
		t.Fatal("server enrollment failed")
	}
	client, err := LoadOwnerBridgeClient(f.config, f.enrollment)
	if err != nil {
		t.Fatal("client enrollment failed")
	}
	invocation := "attempt_" + strings.Repeat("c", 32)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	// The actual BootstrapForInvocation fails its startup bounds before Docker;
	// the real reachable broker still transports the authenticated failure.
	go func() { done <- server.Run(ctx, ctx, invocation) }()
	out, err := client.Request(ctx, "ensure", invocation)
	if err != nil {
		t.Fatal("actual failed bootstrap could not deliver authenticated failure", err)
	}
	if out.Disposition != "failed" || out.Instance.RunningVersion != nil || out.Persistence.Readiness == "ready" {
		t.Fatal("failed bootstrap invented ready result")
	}
	select {
	case err := <-done:
		if !errors.Is(err, bridgeError("startup_failed")) && (err == nil || err.Error() != "owner_bridge_startup_failed") {
			t.Fatal("terminal failure not returned")
		}
	case <-time.After(time.Second):
		t.Fatal("failed service retained lease indefinitely")
	}
	leaseCtx, cancelLease := context.WithTimeout(context.Background(), time.Second)
	defer cancelLease()
	lease, err := AcquireBootstrapLock(leaseCtx, f.config.ProfilePolicy.Directory, f.config.Kernel.Scope.InstanceID, "owner-status-service")
	if err != nil {
		t.Fatal("later ensure cannot acquire service lease")
	}
	if lease.Close() != nil {
		t.Fatal("recovered owned lease cleanup failed")
	}
	if dir := os.Getenv("AGENTMUX_OWNER_BRIDGE_OUTPUTS"); dir != "" {
		os.WriteFile(filepath.Join(dir, "terminal-failed.json"), mustStatusJSON(out), 0600)
	}
}

func TestOwnerBridgeDelayedSubscriptionRepeatsExactRequest(t *testing.T) {
	f := newBridgeFixture(t)
	f.startBroker(t)
	client, err := LoadOwnerBridgeClient(f.config, f.enrollment)
	if err != nil {
		t.Fatal("private client admission failed")
	}
	server, err := LoadOwnerBridgeServer(f.config, f.owner, f.enrollment)
	if err != nil {
		t.Fatal("private server admission failed")
	}
	watch, err := f.rawTLSClient(t, deployment.OwnerBridgeServerUser)
	if err != nil {
		t.Fatal("authenticated request observer unavailable")
	}
	defer watch.Close()
	requests, err := watch.SubscribeSync(client.subjects.Request)
	if err != nil {
		t.Fatal("fixed request observer unavailable")
	}
	defer requests.Unsubscribe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if watch.FlushWithContext(ctx) != nil {
		t.Fatal("request observer flush failed")
	}
	invocation := "attempt_" + strings.Repeat("e", 32)
	type outcome struct {
		out StartupStatusObservation
		err error
	}
	clientDone := make(chan outcome, 1)
	go func() { out, err := client.Request(ctx, "status", invocation); clientDone <- outcome{out, err} }()
	// The first publication is observed before the service subscribes. This
	// forces the Core NATS startup race without a timing guess or fake broker.
	first, err := requests.NextMsgWithContext(ctx)
	if err != nil {
		cancel()
		<-clientDone
		t.Fatal("first authenticated request not observed")
	}
	request, err := validateBridgeRequest(first, f.config.Kernel.Scope, client.subjects, time.Now())
	if err != nil {
		cancel()
		<-clientDone
		t.Fatal("initial request shape invalid")
	}
	replies, err := f.rawTLSClient(t, deployment.OwnerBridgeClientUser)
	if err != nil {
		cancel()
		<-clientDone
		t.Fatal("authenticated reply observer unavailable")
	}
	defer replies.Close()
	replySub, err := replies.SubscribeSync(client.subjects.ReplyPrefix + request.RequestID[len("request_"):])
	if err != nil {
		cancel()
		<-clientDone
		t.Fatal("fixed reply observer unavailable")
	}
	defer replySub.Unsubscribe()
	if replies.FlushWithContext(ctx) != nil {
		cancel()
		<-clientDone
		t.Fatal("reply observer flush failed")
	}
	// This cached frame is a controlled transport input, not cold startup proof.
	input := ownerObservationFixture(f.policy, f.profile, "reused")
	session := &Session{Status: input.status, observedAt: input.receivedAt, startupAttemptID: invocation}
	serverCtx, stopServer := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.serve(serverCtx, invocation, session, nil, nil) }()
	defer func() {
		stopServer()
		select {
		case <-serverDone:
		case <-time.After(time.Second):
			t.Error("owned delayed service not joined")
		}
	}()
	result := <-clientDone
	if result.err != nil || result.out.Disposition != "reused" {
		t.Fatal("delayed subscription lost bounded request", result.err)
	}
	reply, err := replySub.NextMsgWithContext(ctx)
	var decoded ownerBridgeReply
	if err != nil || decodeBridgeReply(reply.Data, &decoded) != nil || decoded.RequestID != request.RequestID || decoded.InvocationID != invocation {
		t.Fatal("delayed reply lost exact correlation")
	}
	count := 1
	for {
		msg, err := requests.NextMsg(100 * time.Millisecond)
		if errors.Is(err, nats.ErrTimeout) {
			break
		}
		if err != nil || !bytes.Equal(msg.Data, first.Data) || msg.Reply != first.Reply || len(msg.Header) != 0 {
			t.Fatal("retry changed immutable request")
		}
		count++
		if count > 10 {
			t.Fatal("retry exceeded bounded publication count")
		}
	}
	if count < 2 {
		t.Fatal("controlled missing subscription did not require retransmission")
	}
	if _, err := replySub.NextMsg(100 * time.Millisecond); !errors.Is(err, nats.ErrTimeout) {
		t.Fatal("same nonce produced more than one accepted output")
	}
}

func (f bridgeFixture) startBroker(t *testing.T, changes ...func(map[string]any)) func() {
	t.Helper()
	f.controlledDocker(t)
	binary := os.Getenv("AGENTMUX_TEST_NATS")
	if binary == "" {
		t.Fatal("prepared NATS executable required")
	}
	var config map[string]any
	json.Unmarshal(f.raw, &config)
	u, err := url.Parse(f.config.Kernel.Endpoint)
	if err != nil {
		t.Fatal("fixture TLS endpoint invalid")
	}
	config["listen"] = u.Host
	config["jetstream"].(map[string]any)["store_dir"] = filepath.Join(t.TempDir(), "store")
	dir := t.TempDir()
	if retained := os.Getenv("AGENTMUX_OWNER_BRIDGE_FIXTURE_ROOT"); retained != "" {
		var err error
		dir, err = os.MkdirTemp(retained, "broker-")
		if err != nil {
			t.Fatal("private fixture retention unavailable")
		}
	}
	path := filepath.Join(dir, "private.json")
	certPath, keyPath := filepath.Join(dir, "server-cert.pem"), filepath.Join(dir, "server-key.pem")
	if os.WriteFile(certPath, f.config.LocalTLS.ServerCertificatePEM(), 0600) != nil || os.WriteFile(keyPath, f.config.LocalTLS.ServerKeyPEM(), 0600) != nil {
		t.Fatal("private native TLS files unavailable")
	}
	// Native fixture paths/listener/store differ from the inspected container
	// bytes. Both use the actual same admitted leaf/key, but this adapter is not
	// proof that an actual Docker container is running this native broker.
	block := config["tls"].(map[string]any)
	block["cert_file"], block["key_file"] = certPath, keyPath
	for _, change := range changes {
		change(config)
	}
	var configBytes bytes.Buffer
	encoder := json.NewEncoder(&configBytes)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(config) != nil || os.WriteFile(path, configBytes.Bytes(), 0600) != nil {
		t.Fatal("private broker config unavailable")
	}
	log, err := os.OpenFile(filepath.Join(dir, "private.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("fixture private log unavailable")
	}
	cmd := exec.Command(binary, "-c", path)
	cmd.Stdout = log
	cmd.Stderr = log
	if cmd.Start() != nil {
		t.Fatal("fixture broker start failed")
	}
	var stopped sync.Once
	stop := func() { stopped.Do(func() { cmd.Process.Kill(); cmd.Wait(); log.Close() }) }
	t.Cleanup(stop)
	deadline := time.Now().Add(3 * time.Second)
	for {
		dialer, err := f.config.Kernel.TLS.NewDialer(context.Background(), 50*time.Millisecond)
		if err != nil {
			t.Fatal("fixture pinned TLS dialer unavailable")
		}
		nc, err := nats.Connect(f.config.Kernel.Endpoint, nats.UserInfo(deployment.OwnerBridgeClientUser, f.config.OwnerBridge.ClientPassword), nats.TLSHandshakeFirst(), nats.SetCustomDialer(dialer), nats.NoReconnect(), nats.Timeout(50*time.Millisecond))
		dialer.Close()
		if err == nil {
			nc.Close()
			return stop
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture broker unavailable")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (f bridgeFixture) rawTLSClient(t *testing.T, role string, extra ...nats.Option) (*nats.Conn, error) {
	return f.rawTLSClientContext(t, context.Background(), role, extra...)
}

func (f bridgeFixture) rawTLSClientContext(t *testing.T, parent context.Context, role string, extra ...nats.Option) (*nats.Conn, error) {
	t.Helper()
	password := f.config.OwnerBridge.ClientPassword
	if role == deployment.OwnerBridgeServerUser {
		password = f.config.OwnerBridge.ServerPassword
	}
	return f.rawTLSIdentity(t, parent, role, password, extra...)
}

func (f bridgeFixture) rawTLSIdentity(t *testing.T, parent context.Context, user, password string, extra ...nats.Option) (*nats.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	dialer, err := f.config.Kernel.TLS.NewDialer(ctx, time.Second)
	if err != nil {
		cancel()
		return nil, err
	}
	callbacksDone := make(chan struct{})
	options := []nats.Option{nats.UserInfo(user, password), nats.TLSHandshakeFirst(), nats.SetCustomDialer(dialer), nats.NoReconnect(), nats.IgnoreDiscoveredServers(), nats.Timeout(time.Second), nats.ErrorHandler(ownerBridgeAsyncErrorHandler), nats.ClosedHandler(func(*nats.Conn) { close(callbacksDone) })}
	options = append(options, extra...)
	nc, err := nats.Connect(f.config.Kernel.Endpoint, options...)
	closeExact := func() {
		if nc != nil {
			nc.Close()
		}
		if dialer.Close() != nil {
			// Keep the exact dialer in this cleanup closure. A later retry cannot
			// erase the original failure or turn this test into a passing result.
			t.Error("actual scoped TLS client owned cleanup incomplete")
		}
		cancel()
		if nc != nil {
			select {
			case <-callbacksDone:
			case <-time.After(time.Second):
				t.Error("actual scoped TLS client callbacks did not join")
			}
		}
	}
	t.Cleanup(closeExact)
	if err != nil {
		closeExact()
		return nil, err
	}
	return nc, nil
}

func TestOwnerBridgeEnrollmentRealPrivateFiles(t *testing.T) {
	f := newBridgeFixture(t)
	if _, err := LoadOwnerBridgeClient(f.config, f.enrollment); err != nil {
		t.Fatal("valid contained client credential rejected")
	}
	if _, err := LoadOwnerBridgeServer(f.config, f.owner, f.enrollment); err != nil {
		t.Fatal("valid contained server credential rejected")
	}
	cases := []string{"password", "role", "scope", "owner", "alias", "unknown", "duplicate", "mode", "symlink", "hardlink", "outside", "factory"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			f := newBridgeFixture(t)
			path := filepath.Join(f.policy.Profile.Directory, f.enrollment.Credentials.Client)
			raw, _ := os.ReadFile(path)
			var record map[string]any
			json.Unmarshal(raw, &record)
			switch name {
			case "password":
				record["password"] = strings.Repeat("z", 32)
			case "role":
				record["role"] = deployment.OwnerBridgeServerUser
			case "scope":
				record["scope"].(map[string]any)["hubId"] = "other_hub"
			case "owner":
				record["owner"].(map[string]any)["principalId"] = "other_owner"
			case "alias":
				record["Scope"] = record["scope"]
				delete(record, "scope")
			case "unknown":
				record["username"] = "administrator"
			case "duplicate":
				raw = append([]byte(`{"role":"runtime-client",`), raw[1:]...)
			case "mode":
				os.Chmod(path, 0644)
			case "symlink":
				os.Rename(path, path+"-target")
				os.Symlink(path+"-target", path)
			case "hardlink":
				os.Link(path, path+"-link")
			case "outside":
				f.enrollment.Credentials.Client = "../outside.json"
			case "factory":
				f.config.OwnerBridge.ClientPassword = strings.Repeat("z", 32)
			}
			if name == "password" || name == "role" || name == "scope" || name == "owner" || name == "alias" || name == "unknown" {
				raw = mustStatusJSON(record)
				os.WriteFile(path, raw, 0600)
			}
			if name == "duplicate" {
				os.WriteFile(path, raw, 0600)
			}
			if _, err := LoadOwnerBridgeClient(f.config, f.enrollment); err == nil {
				t.Fatal("unsafe credential admitted")
			}
		})
	}
}

func TestOwnerBridgeRequestRefusalAndReplay(t *testing.T) {
	f := newBridgeFixture(t)
	subjects, _ := deployment.OwnerBridgeSubjects(f.config.Kernel.Scope)
	now := time.Now()
	request := ownerBridgeRequest{protocol.Version, "host-owner-status-request", "status", "request_" + strings.Repeat("a", 32), "attempt_" + strings.Repeat("b", 32), f.config.Kernel.Scope, bridgeTime(now)}
	msg := &nats.Msg{Subject: subjects.Request, Data: mustStatusJSON(request)}
	if _, err := validateBridgeRequest(msg, f.config.Kernel.Scope, subjects, now); err != nil {
		t.Fatal("valid fixed request rejected")
	}
	for _, name := range []string{"stale", "future", "scope", "operation", "nonce", "invocation", "subject", "reply", "header", "duplicate", "alias", "oversize"} {
		t.Run(name, func(t *testing.T) {
			r := request
			m := &nats.Msg{Subject: subjects.Request}
			switch name {
			case "stale":
				r.SentAt = bridgeTime(now.Add(-6 * time.Second))
			case "future":
				r.SentAt = bridgeTime(now.Add(time.Second))
			case "scope":
				r.Scope.ProfileID = "other_profile"
			case "operation":
				r.Operation = "stop"
			case "nonce":
				r.RequestID = "request_*"
			case "invocation":
				r.InvocationID = "attempt_fake"
			case "subject":
				m.Subject = subjects.ReplyPrefix + "x"
			case "reply":
				m.Reply = "private.arbitrary"
			case "header":
				m.Header = nats.Header{"x": []string{"y"}}
			}
			m.Data = mustStatusJSON(r)
			if name == "duplicate" {
				m.Data = append([]byte(`{"kind":"host-owner-status-request",`), m.Data[1:]...)
			}
			if name == "alias" {
				m.Data = []byte(strings.Replace(string(m.Data), `"scope":`, `"Scope":`, 1))
			}
			if name == "oversize" {
				m.Data = append(m.Data, []byte(strings.Repeat(" ", protocol.MaxPayload))...)
			}
			if _, err := validateBridgeRequest(m, f.config.Kernel.Scope, subjects, now); err == nil {
				t.Fatal("unsafe request admitted")
			}
		})
	}
	replay := bridgeReplay{ids: map[string]time.Time{}}
	if !replay.accept(request.RequestID, now) || replay.accept(request.RequestID, now) {
		t.Fatal("replay admitted")
	}
	for i := 0; i < 127; i++ {
		id, _ := hostInvocationID("request_")
		if !replay.accept(id, now) {
			t.Fatal("bounded replay capacity wrong")
		}
	}
	id, _ := hostInvocationID("request_")
	if replay.accept(id, now) {
		t.Fatal("replay cache grew without bound")
	}
	if !replay.accept(id, now.Add(11*time.Second)) {
		t.Fatal("expired replay window did not clear")
	}
}

func TestOwnerBridgeActualNATSCorrelatedL04AndRefusals(t *testing.T) {
	f := newBridgeFixture(t)
	f.startBroker(t)
	f.startActors(t)
	if _, err := deployment.ProvisionAndProbe(context.Background(), f.config.Health); err != nil {
		t.Fatal("actual FILE probe unavailable")
	}
	client, err := LoadOwnerBridgeClient(f.config, f.enrollment)
	if err != nil {
		t.Fatal("client enrollment failed")
	}
	server, err := LoadOwnerBridgeServer(f.config, f.owner, f.enrollment)
	if err != nil {
		t.Fatal("server enrollment failed")
	}
	// Only transport and authentication are under test. This cached frame is
	// explicit synthetic input, not a real protected bootstrap or write proof.
	invocation := "attempt_" + strings.Repeat("a", 32)
	input := ownerObservationFixture(f.policy, f.profile, "reused")
	input.attemptID = invocation
	session := &Session{Status: input.status, observedAt: input.receivedAt, startupAttemptID: invocation}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	ready := make(chan struct{})
	go func() { done <- server.serve(ctx, invocation, session, nil, ready) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("owned transport did not close")
		}
	}()
	// Flush a server-side connection until the fixed service subscription exists.
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("service subscription unavailable")
	}
	for _, operation := range []string{"ensure", "status"} {
		out, err := client.Request(context.Background(), operation, invocation)
		if err != nil || out.Disposition != "reused" || out.Persistence.Readiness != "unknown" || out.Work.Active != nil {
			t.Fatal("authenticated request did not retain exact L04 unknown/write semantics", operation, err, out.Disposition, out.Persistence.Readiness)
		}
		if dest := os.Getenv("AGENTMUX_OWNER_BRIDGE_OUTPUTS"); dest != "" {
			if os.WriteFile(filepath.Join(dest, operation+".json"), mustStatusJSON(out), 0600) != nil {
				t.Fatal("safe output evidence unavailable")
			}
		}
	}
	rawClient, err := f.rawTLSClient(t, deployment.OwnerBridgeClientUser)
	if err != nil {
		t.Fatal("raw client authentication failed")
	}
	defer rawClient.Close()
	id, _ := hostInvocationID("request_")
	replySubject := client.subjects.ReplyPrefix + id[len("request_"):]
	subscription, err := rawClient.SubscribeSync(replySubject)
	if err != nil {
		t.Fatal("fixed reply subscription failed")
	}
	defer subscription.Unsubscribe()
	rawClient.Flush()
	request := ownerBridgeRequest{protocol.Version, "host-owner-status-request", "status", id, invocation, f.config.Kernel.Scope, bridgeTime(time.Now())}
	raw := mustStatusJSON(request)
	rawClient.Publish(client.subjects.Request, raw)
	rawClient.Flush()
	// A fresh reply includes the owned deployment checks within the same
	// five-second service budget; this raw transport control waits that budget.
	if _, err := subscription.NextMsg(5 * time.Second); err != nil {
		t.Fatal("actual valid request refused")
	}
	rawClient.Publish(client.subjects.Request, raw)
	rawClient.Flush()
	if _, err := subscription.NextMsg(70 * time.Millisecond); err == nil {
		t.Fatal("actual replay received another reply")
	}
	for _, fault := range []string{"stale", "scope", "reflect", "header"} {
		id, _ := hostInvocationID("request_")
		request.RequestID = id
		request.SentAt = bridgeTime(time.Now())
		request.Scope = f.config.Kernel.Scope
		message := &nats.Msg{Subject: client.subjects.Request}
		switch fault {
		case "stale":
			request.SentAt = bridgeTime(time.Now().Add(-6 * time.Second))
		case "scope":
			request.Scope.HubID = "other_hub"
		case "reflect":
			message.Reply = replySubject
		case "header":
			message.Header = nats.Header{"untrusted": []string{"value"}}
		}
		message.Data = mustStatusJSON(request)
		subject := client.subjects.ReplyPrefix + id[len("request_"):]
		sub, err := rawClient.SubscribeSync(subject)
		if err != nil {
			t.Fatal("refusal subscription failed")
		}
		rawClient.Flush()
		rawClient.PublishMsg(message)
		rawClient.Flush()
		_, replyErr := sub.NextMsg(70 * time.Millisecond)
		sub.Unsubscribe()
		if replyErr == nil {
			t.Fatal("actual malformed or reflective request received reply")
		}
	}
	for _, operation := range []string{"stop", "", "publish"} {
		if _, err := client.Request(context.Background(), operation, invocation); err == nil {
			t.Fatal("generic operation admitted")
		}
	}
	short, cancelShort := context.WithTimeout(context.Background(), 35*time.Millisecond)
	defer cancelShort()
	f.owner.mu.Lock()
	before := time.Now()
	_, deadlineErr := client.Request(short, "status", invocation)
	f.owner.mu.Unlock()
	if deadlineErr == nil || time.Since(before) > 300*time.Millisecond {
		t.Fatal("earlier request deadline ignored")
	}
}

func TestOwnerBridgeActualNATSRejectsForgedReply(t *testing.T) {
	for _, fault := range []string{"correlation", "scope", "identity", "stale", "alias", "oversize", "missing_nullable", "invalid_enum", "invalid_range", "invalid_conditional"} {
		t.Run(fault, func(t *testing.T) {
			f := newBridgeFixture(t)
			f.startBroker(t)
			client, err := LoadOwnerBridgeClient(f.config, f.enrollment)
			if err != nil {
				t.Fatal("client rejected")
			}
			nc, err := f.rawTLSClient(t, deployment.OwnerBridgeServerUser)
			if err != nil {
				t.Fatal("fixture server auth failed")
			}
			defer nc.Close()
			var received atomic.Int32
			sub, err := nc.Subscribe(client.subjects.Request, func(msg *nats.Msg) {
				received.Add(1)
				var request ownerBridgeRequest
				if protocol.StrictJSON(msg.Data, &request) != nil {
					return
				}
				input := ownerObservationFixture(f.policy, f.profile, "reused")
				input.attemptID = request.InvocationID
				out, e := f.owner.mapObservation(input)
				if e != nil {
					return
				}
				reply := ownerBridgeReply{protocol.Version, "host-owner-status-reply", request.RequestID, request.InvocationID, f.config.Kernel.Scope, bridgeTime(time.Now()), out}
				switch fault {
				case "correlation":
					reply.RequestID = "request_" + strings.Repeat("f", 32)
				case "scope":
					reply.Scope.HubID = "other_hub"
				case "identity":
					reply.Observation.Caller.PrincipalID = "other_owner"
				case "stale":
					reply.SentAt = bridgeTime(time.Now().Add(-6 * time.Second))
				}
				raw := mustStatusJSON(reply)
				if strings.HasPrefix(fault, "missing_") || strings.HasPrefix(fault, "invalid_") {
					var tree map[string]any
					json.Unmarshal(raw, &tree)
					observation := tree["observation"].(map[string]any)
					switch fault {
					case "missing_nullable":
						delete(observation["work"].(map[string]any), "active")
					case "invalid_enum":
						observation["persistence"].(map[string]any)["availability"] = "invented"
					case "invalid_range":
						pressure := observation["persistence"].(map[string]any)["storagePressure"].(map[string]any)
						pressure["state"] = "known"
						pressure["percentUsed"] = 101
					case "invalid_conditional":
						observation["work"].(map[string]any)["active"] = 1
					}
					raw = mustStatusJSON(tree)
				}
				if fault == "alias" {
					raw = []byte(strings.Replace(string(raw), `"observation":`, `"Observation":`, 1))
				}
				if fault == "oversize" {
					raw = append(raw, []byte(strings.Repeat(" ", ownerBridgeReplyLimit))...)
				}
				nc.Publish(client.subjects.ReplyPrefix+request.RequestID[len("request_"):], raw)
			})
			if err != nil {
				t.Fatal("fixture subscribe failed")
			}
			defer sub.Unsubscribe()
			nc.Flush()
			if _, err := client.Request(context.Background(), "status", "attempt_"+strings.Repeat("a", 32)); err == nil {
				t.Fatal("forged or malformed owner reply accepted")
			}
			if received.Load() != 1 {
				t.Fatal("invalid reply did not stop the exact authenticated request")
			}
			if fault == "correlation" {
				// Past one retry interval, an invalid reply must still have ended
				// the operation with no surviving retry timer or publication.
				timer := time.NewTimer(600 * time.Millisecond)
				<-timer.C
				if received.Load() != 1 {
					t.Fatal("invalid reply left a retry publication running")
				}
			}
		})
	}
}

func TestOwnerBridgeActualNATSConnectedIdentity(t *testing.T) {
	f := newBridgeFixture(t)
	f.startBroker(t)
	credential := OwnerBridgeCredential{Role: deployment.OwnerBridgeClientUser, Password: f.config.OwnerBridge.ClientPassword}
	for _, fault := range []string{"name", "version"} {
		t.Run(fault, func(t *testing.T) {
			config := f.config
			if fault == "name" {
				config.Health.ServerName = "other_server"
			} else {
				config.Health.ServerVersion = "2.14.0"
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			nc, dialer, err := bridgeConnect(ctx, config, credential)
			if nc != nil {
				nc.Close()
			}
			if dialer != nil {
				dialer.Close()
			}
			if err == nil {
				t.Fatal("wrong selected broker identity admitted")
			}
		})
	}
}

func TestOwnerBridgeActualNATSPrincipalIsolation(t *testing.T) {
	f := newBridgeFixture(t)
	f.startBroker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ownerBridgePrincipalIsolation(t, f, ctx)
}

func ownerBridgePrincipalIsolation(t *testing.T, f bridgeFixture, ctx context.Context) {
	t.Helper()
	subjects, err := deployment.OwnerBridgeSubjects(f.config.Kernel.Scope)
	if err != nil {
		t.Fatal("actual HOST subject contract unavailable")
	}
	kernel, err := communication.Subjects(f.config.Kernel.Scope.HubID)
	if err != nil {
		t.Fatal("actual protected subject contract unavailable")
	}
	otherScope := f.config.Kernel.Scope
	otherScope.HubID = "other_hub"
	other, err := deployment.OwnerBridgeSubjects(otherScope)
	if err != nil {
		t.Fatal("other-hub subject contract unavailable")
	}
	nonce := strings.Repeat("a", 32)
	t.Run("legitimate-request-reply", func(t *testing.T) {
		server, err := f.rawTLSClientContext(t, ctx, deployment.OwnerBridgeServerUser)
		if err != nil {
			t.Fatal("actual HOST server authentication failed")
		}
		client, err := f.rawTLSClientContext(t, ctx, deployment.OwnerBridgeClientUser)
		if err != nil {
			t.Fatal("actual HOST client authentication failed")
		}
		request, err := server.SubscribeSync(subjects.Request)
		if err != nil {
			t.Fatal("legitimate request subscription failed")
		}
		defer request.Unsubscribe()
		reply, err := client.SubscribeSync(subjects.ReplyPrefix + nonce)
		if err != nil {
			t.Fatal("legitimate reply subscription failed")
		}
		defer reply.Unsubscribe()
		if server.FlushTimeout(time.Second) != nil || client.FlushTimeout(time.Second) != nil {
			t.Fatal("legitimate subscriptions unavailable")
		}
		if client.Publish(subjects.Request, []byte("synthetic-request")) != nil || client.FlushTimeout(time.Second) != nil {
			t.Fatal("legitimate request publication failed")
		}
		message, err := request.NextMsg(time.Second)
		if err != nil || string(message.Data) != "synthetic-request" {
			t.Fatal("legitimate HOST request not delivered")
		}
		if server.Publish(subjects.ReplyPrefix+nonce, []byte("synthetic-reply")) != nil || server.FlushTimeout(time.Second) != nil {
			t.Fatal("legitimate reply publication failed")
		}
		message, err = reply.NextMsg(time.Second)
		if err != nil || string(message.Data) != "synthetic-reply" {
			t.Fatal("legitimate HOST reply not delivered")
		}
	})
	type deniedSubject struct{ name, subject string }
	shared := []deniedSubject{{"system-management", "$SYS.REQ.SERVER.PING"}, {"jetstream-management", "$JS.API.INFO"}, {"jetstream-domain", "$JS." + f.config.Health.Domain + ".API.INFO"}, {"health-record", deployment.HealthSubject(f.config.Kernel.Scope.HubID)}, {"other-hub-request", other.Request}, {"other-hub-reply", other.ReplyPrefix + nonce}, {"kernel-snapshot", kernel.Snapshot}, {"kernel-update", kernel.Update}}
	// Existing business transport: hub/names.py nats_subject(role:calc/worker),
	// documented in PROTOCOL.md11 and exercised by test_nats_federation.py.
	// This does not register or invent a new SDK business route.
	shared = append(shared, deniedSubject{"legacy-business-work", "am.work.calc.worker"})
	for _, role := range protocol.Roles() {
		shared = append(shared, deniedSubject{"kernel-command-" + role, kernel.Commands[role]}, deniedSubject{"kernel-event-" + role, kernel.Events[role]})
	}
	for _, role := range []string{deployment.OwnerBridgeClientUser, deployment.OwnerBridgeServerUser} {
		t.Run(role, func(t *testing.T) {
			publish := append([]deniedSubject{}, shared...)
			subscribe := append([]deniedSubject{}, shared...)
			if role == deployment.OwnerBridgeServerUser {
				publish = append(publish, deniedSubject{"inverted-request", subjects.Request})
				subscribe = append(subscribe, deniedSubject{"inverted-reply", subjects.ReplyPrefix + nonce})
			} else {
				publish = append(publish, deniedSubject{"inverted-reply", subjects.ReplyPrefix + nonce})
				subscribe = append(subscribe, deniedSubject{"inverted-request", subjects.Request})
			}
			subscribe = append(subscribe, deniedSubject{"all-subjects", ">"}, deniedSubject{"generic-inbox", "_INBOX.>"})
			for _, direction := range []struct {
				name  string
				cases []deniedSubject
			}{{"publish", publish}, {"subscribe", subscribe}} {
				for _, target := range direction.cases {
					t.Run(direction.name+"-"+target.name, func(t *testing.T) {
						faults := make(chan error, 1)
						nc, err := f.rawTLSClientContext(t, ctx, role, nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
							select {
							case faults <- err:
							default:
							}
						}))
						if err != nil {
							t.Fatal("isolated principal authentication failed")
						}
						if direction.name == "publish" {
							if nc.Publish(target.subject, []byte(`{}`)) != nil {
								t.Fatal("publication failed before broker authorization")
							}
						} else {
							sub, err := nc.SubscribeSync(target.subject)
							if err != nil {
								t.Fatal("subscription failed before broker authorization")
							}
							defer sub.Unsubscribe()
						}
						if nc.FlushTimeout(time.Second) != nil {
							t.Fatal("actual broker authorization flush failed")
						}
						select {
						case rejection := <-faults:
							if !errors.Is(rejection, nats.ErrPermissionViolation) {
								t.Fatal("operation did not receive actual broker permission refusal")
							}
						case <-time.After(time.Second):
							t.Fatal("HOST principal acquired unrelated authority")
						}
					})
				}
			}
		})
	}
	t.Run("account-crossover-credentials", func(t *testing.T) {
		accounts := make(map[string]string, len(f.users)+1)
		for user, password := range f.users {
			accounts[user] = password
		}
		accounts[deployment.HealthUser] = f.config.Health.Password
		connect := func(t *testing.T, user, password string) (*nats.Conn, error) {
			return f.rawTLSIdentity(t, ctx, user, password)
		}
		for user, password := range accounts {
			t.Run(user, func(t *testing.T) {
				if _, err := connect(t, user, password); err != nil {
					t.Fatal("legitimate other-account credential was not verified")
				}
				for _, role := range []string{deployment.OwnerBridgeClientUser, deployment.OwnerBridgeServerUser} {
					own := f.config.OwnerBridge.ClientPassword
					if role == deployment.OwnerBridgeServerUser {
						own = f.config.OwnerBridge.ServerPassword
					}
					if nc, err := connect(t, role, password); nc != nil || !errors.Is(err, nats.ErrAuthorization) {
						t.Fatal("other-account password authenticated a HOST principal")
					}
					if nc, err := connect(t, user, own); nc != nil || !errors.Is(err, nats.ErrAuthorization) {
						t.Fatal("HOST password authenticated another account")
					}
				}
			})
		}
	})
	if ctx.Err() != nil {
		t.Fatal("actual principal isolation matrix exceeded its shared deadline")
	}
}
