package plugins

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/localtls"
	"github.com/nats-io/nats.go"
)

// This test binary is also the native plugin. It uses the published bootstrap
// and NATS messages, so the live check crosses the actual process boundary.
func TestNativeChild(t *testing.T) {
	path := os.Getenv("AGENTMUX_PLUGIN_BOOTSTRAP")
	if path == "" {
		return
	}
	raw, err := ReadOwnerPrivateFile(path, 1<<20)
	if err != nil {
		os.Exit(20)
	}
	var bootstrap NativeBootstrap
	if json.Unmarshal(raw, &bootstrap) != nil {
		os.Exit(21)
	}
	configuration, err := ReadOwnerPrivateFile(bootstrap.ConfigurationFile, 1<<20)
	if err != nil || checksum(configuration) != bootstrap.Prepare.ConfigurationChecksum {
		os.Exit(22)
	}
	var config struct {
		Behavior         string `json:"behavior"`
		FixtureDirectory string `json:"fixtureDirectory"`
	}
	if json.Unmarshal(configuration, &config) != nil {
		os.Exit(23)
	}
	if config.Behavior == "identity-isolation" || config.Behavior == "storage-contract" {
		info, err := os.Lstat(config.FixtureDirectory)
		if len(config.FixtureDirectory) > 4096 || !filepath.IsAbs(config.FixtureDirectory) || err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			t.Fatal("identity fixture recovery location invalid")
		}
	}
	if config.Behavior == "stubborn" {
		signal.Ignore(syscall.SIGTERM)
	}
	tlsOptions, dialer, err := nativeChildTLSOptions(bootstrap.ServerURL, bootstrap.CAFile, bootstrap.ServerName, bootstrap.LeafCertificateSHA256)
	if err != nil {
		t.Fatal("child lifecycle TLS enrollment invalid")
	}
	if dialer != nil {
		defer func() {
			if config.Behavior == "identity-isolation" || config.Behavior == "storage-contract" {
				nativeIdentityJoinTLS(t, dialer, config.FixtureDirectory)
				return
			}
			if dialer.Close() != nil {
				t.Error("child lifecycle TLS sockets did not close")
			}
		}()
	}
	options := append([]nats.Option{nats.UserCredentials(bootstrap.CredentialsFile), nats.NoReconnect(), nats.IgnoreDiscoveredServers(), nats.Timeout(2 * time.Second)}, tlsOptions...)
	nc, err := nats.Connect(bootstrap.ServerURL, options...)
	if err != nil {
		t.Fatal("child lifecycle transport unavailable")
	}
	defer nc.Close()
	sub, err := nc.SubscribeSync(bootstrap.ControlSubject)
	if err != nil || nc.FlushTimeout(time.Second) != nil {
		t.Fatal("child lifecycle subscriptions unavailable")
	}
	report := LifecycleReport{SchemaVersion: bootstrap.Prepare.SchemaVersion, Kind: "ordinary-plugin-report", CommandID: bootstrap.Prepare.CommandID, Owner: bootstrap.Prepare.Owner, ConfigurationChecksum: bootstrap.Prepare.ConfigurationChecksum, ContributionsChecksum: bootstrap.Prepare.ContributionsChecksum, ParentOwner: bootstrap.Prepare.ParentOwner, ContextChecksum: bootstrap.Prepare.ContextChecksum}
	emit := func(status string) {
		report.Status = status
		report.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
		encoded, _ := json.Marshal(report)
		if nc.Publish(bootstrap.EventSubject, encoded) != nil || nc.FlushTimeout(time.Second) != nil {
			t.Fatal("child lifecycle report unavailable")
		}
	}
	if bootstrap.Context != nil {
		stopContext := nativeChildContext(t, bootstrap, configuration)
		defer stopContext()
	} else if bootstrap.Prepare.SchemaVersion == "1.2.0" {
		t.Fatal("context bootstrap missing")
	}
	emit("registered")
	for {
		message, err := sub.NextMsg(12 * time.Second)
		if config.Behavior == "storage-contract" && err == nats.ErrTimeout && nc.IsConnected() {
			continue
		}
		if err != nil {
			t.Fatal("child lifecycle control unavailable")
		}
		var control LifecycleControl
		if json.Unmarshal(message.Data, &control) != nil || control.Owner != bootstrap.Prepare.Owner {
			continue
		}
		if control.Action == "stop" {
			if config.Behavior != "stubborn" {
				return
			}
			continue
		}
		if !reflect.DeepEqual(control, bootstrap.Prepare) {
			continue
		}
		if config.Behavior == "wrong-owner" {
			report.Owner.Generation++
		}
		if config.Behavior == "wrong-parent" && report.ParentOwner != nil {
			parent := *report.ParentOwner
			parent.Generation++
			report.ParentOwner = &parent
		}
		emit("ready")
		if config.Behavior == "crash" {
			time.Sleep(300 * time.Millisecond)
			os.Exit(28)
		}
	}
}

type nativeBrokerFixture struct {
	options NativeDriverOptions
	root    string
	stop    func()
}

func liveNativeBroker(t *testing.T, packages []AdmittedPackage, instanceIDs ...string) nativeBrokerFixture {
	return liveNativeBrokerWithContext(t, packages, nil, instanceIDs...)
}

func liveNativeBrokerWithContext(t *testing.T, packages []AdmittedPackage, contextOptions *NATSContextOptions, instanceIDs ...string) nativeBrokerFixture {
	t.Helper()
	if len(instanceIDs) != 0 && len(instanceIDs) != len(packages) {
		t.Fatal("fixture instance binding count")
	}
	nsc, server := os.Getenv("AGENTMUX_PLUGIN_NSC"), os.Getenv("AGENTMUX_PLUGIN_NATS")
	if nsc == "" || server == "" {
		t.Skip("prepared native NATS and nsc paths required")
	}
	root := privateTestDirectory(t)
	call := func(args ...string) []byte {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		base := []string{"--config-dir", filepath.Join(root, "cfg"), "--data-dir", filepath.Join(root, "store"), "--keystore-dir", filepath.Join(root, "keys")}
		cmd := exec.CommandContext(ctx, nsc, append(base, args...)...)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		raw, err := cmd.Output()
		if err != nil {
			t.Fatal("private nsc fixture command failed")
		}
		return raw
	}
	call("add", "operator", "--sys", "--name", "ordinarytest")
	call("add", "account", "--name", "PLUGINS")
	var claims struct {
		Subject string `json:"sub"`
	}
	if json.Unmarshal(call("describe", "account", "PLUGINS", "--json"), &claims) != nil || claims.Subject == "" {
		t.Fatal("fixture account identity")
	}
	write := func(name string, raw []byte) string {
		path := filepath.Join(root, name)
		if os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("private fixture write")
		}
		return path
	}
	options := NativeDriverOptions{HubID: "fixture", AccountPublicKey: claims.Subject, StateDirectory: filepath.Join(root, "state")}
	if os.Mkdir(options.StateDirectory, 0700) != nil {
		t.Fatal("fixture state")
	}
	controller := []string{"add", "user", "-a", "PLUGINS", "-n", "controller"}
	for index, pkg := range packages {
		id := pkg.Pin().PackageID
		if len(instanceIDs) != 0 {
			id = instanceIDs[index]
		}
		control, event, _ := lifecycleSubjects("fixture", id)
		call("add", "user", "-a", "PLUGINS", "-n", id, "--allow-pub", event, "--allow-sub", control)
		creds := write(id+".creds", call("generate", "creds", "-a", "PLUGINS", "-n", id))
		options.Bindings = append(options.Bindings, NativeBinding{Pin: pkg.Pin(), InstanceID: id, CredentialsFile: creds})
		controller = append(controller, "--allow-pub", control, "--allow-sub", event)
	}
	call(controller...)
	options.ControllerCredentialsFile = write("controller.creds", call("generate", "creds", "-a", "PLUGINS", "-n", "controller"))
	if contextOptions != nil {
		*contextOptions = NATSContextOptions{HubID: options.HubID, AccountPublicKey: options.AccountPublicKey}
		serverArgs := []string{"add", "user", "-a", "PLUGINS", "-n", "context_server"}
		for _, binding := range options.Bindings {
			transport := contextSubjects(*contextOptions, binding.InstanceID)
			name := "context_" + binding.InstanceID
			call("add", "user", "-a", "PLUGINS", "-n", name, "--allow-pub", transport.RequestSubject, "--allow-pub", transport.ResultSubject, "--allow-sub", transport.ReplySubject, "--allow-sub", transport.InvokeSubject, "--allow-sub", transport.CancelSubject)
			path := write(name+".creds", call("generate", "creds", "-a", "PLUGINS", "-n", name))
			contextOptions.Bindings = append(contextOptions.Bindings, ContextTransportBinding{InstanceID: binding.InstanceID, ClientCredentialsFile: path})
			serverArgs = append(serverArgs, "--allow-sub", transport.RequestSubject, "--allow-sub", transport.ResultSubject, "--allow-pub", transport.ReplySubject, "--allow-pub", transport.InvokeSubject, "--allow-pub", transport.CancelSubject)
		}
		call(serverArgs...)
		contextOptions.ServerCredentialsFile = write("context_server.creds", call("generate", "creds", "-a", "PLUGINS", "-n", "context_server"))
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("fixture TLS key")
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ordinary fixture"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal("fixture TLS certificate")
	}
	options.CAFile = write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("fixture TLS key encoding")
	}
	keyPath := write("server.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("fixture port")
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if listener.Close() != nil {
		t.Fatal("fixture listener close")
	}
	options.ServerURL = fmt.Sprintf("tls://127.0.0.1:%d", port)
	config := call("generate", "config", "--mem-resolver", "--sys-account", "SYS")
	// Context messages contain private configuration and operation payloads.
	// Keep broker payload tracing off for that fixture; permission errors remain
	// visible through the client's error callback and the private broker log.
	config = append(config, []byte(fmt.Sprintf("\nlisten: \"127.0.0.1:%d\"\ntrace: %t\ntls { cert_file: %q, key_file: %q }\n", port, contextOptions == nil, options.CAFile, keyPath))...)
	configPath := write("server.conf", config)
	log, err := os.OpenFile(filepath.Join(root, "server.private.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("fixture log")
	}
	command := exec.Command(server, "-c", configPath)
	command.Stdout = log
	command.Stderr = log
	if command.Start() != nil {
		_ = log.Close()
		t.Fatal("fixture server start")
	}
	done := make(chan struct{})
	go func() { _ = command.Wait(); close(done) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = command.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				_ = command.Process.Kill()
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Error("fixture server ownership unresolved")
				}
			}
			if log.Close() != nil {
				t.Error("fixture log close")
			}
		})
	}
	t.Cleanup(stop)
	ready := false
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		connection, e := nats.Connect(options.ServerURL, nats.UserCredentials(options.ControllerCredentialsFile), nats.RootCAs(options.CAFile), nats.NoReconnect(), nats.Timeout(200*time.Millisecond))
		if e == nil {
			ready = connection.FlushTimeout(time.Second) == nil
			connection.Close()
			if ready {
				break
			}
		}
		select {
		case <-done:
			t.Fatal("fixture broker exited; inspect private log")
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("fixture authenticated broker readiness failed")
	}
	if contextOptions != nil {
		contextOptions.ServerURL, contextOptions.CAFile = options.ServerURL, options.CAFile
	}
	return nativeBrokerFixture{options, root, stop}
}

func nativeFixturePackage(t *testing.T, id string, edits ...func(*Manifest)) AdmittedPackage {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal("native fixture executable")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("native fixture bytes")
	}
	m := fixtureManifest(id)
	m.Runtime.Args = []string{"-test.run=^TestNativeChild$", "-test.timeout=15s"}
	m.Lifecycle = Lifecycle{StartDeadlineMS: 2500, DrainDeadlineMS: 1200, RestartLimit: 1}
	m.Contributions = []Contribution{{Kind: "tool", ID: id, ContractRef: "urn:fixture:tool"}}
	for _, edit := range edits {
		edit(&m)
	}
	return fixturePackage(t, m, map[string][]byte{"bin/run": raw})
}
func nativeRequest(packages []AdmittedPackage, behaviors map[string]string) ActivationRequest {
	r := ActivationRequest{Catalog: packages, Instances: map[string]string{}, Contracts: []ContractBinding{{Kind: "tool", ContractRef: "urn:fixture:tool"}}}
	for _, pkg := range packages {
		r.Roots = append(r.Roots, pkg.Pin())
		r.Instances[pkg.Pin().PackageID] = pkg.Pin().PackageID
		raw, _ := json.Marshal(map[string]string{"behavior": behaviors[pkg.Pin().PackageID]})
		r.Configurations = append(r.Configurations, ConfigurationInput{Pin: pkg.Pin(), Resources: []SchemaResource{{Ref: "schemas/config.json", File: "schemas/config.json"}}, Raw: raw})
	}
	return r
}
func closeNativeFixture(t *testing.T, manager *Manager, driver *NativeDriver) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := manager.Close(ctx); err != nil {
		t.Error(err)
	}
	if err := driver.Close(ctx); err != nil {
		t.Error(err)
	}
}

func TestNativeLiveActivationRollbackAndTransport(t *testing.T) {
	if os.Getenv("AGENTMUX_PLUGIN_NATS") == "" {
		t.Skip("prepared native NATS required")
	}
	good, bad := nativeFixturePackage(t, "good"), nativeFixturePackage(t, "bad")
	fixture := liveNativeBroker(t, []AdmittedPackage{good, bad})
	driver, err := NewNativeDriver(context.Background(), fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(context.Background(), driver, ManagerOptions{Platform: Platform{"darwin", "arm64"}, InstallationMode: "independent", ActivationTimeout: 5 * time.Second, CleanupTimeout: 3 * time.Second})
	if err != nil {
		_ = driver.Close(context.Background())
		t.Fatal(err)
	}
	defer closeNativeFixture(t, manager, driver)
	if _, err = manager.Activate(context.Background(), nativeRequest([]AdmittedPackage{good}, map[string]string{"good": "normal"})); err != nil {
		t.Fatal(err)
	}
	entry, err := manager.Resolve("tool", "good")
	if err != nil {
		t.Fatal(err)
	}
	// The remote broker must reject cross-instance publication and control reads.
	denied := make(chan error, 4)
	attacker, err := nats.Connect(fixture.options.ServerURL, nats.UserCredentials(fixture.options.Bindings[1].CredentialsFile), nats.RootCAs(fixture.options.CAFile), nats.NoReconnect(), nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, e error) { denied <- e }))
	if err != nil {
		t.Fatal("negative lifecycle client unavailable")
	}
	goodControl, goodEvent, _ := lifecycleSubjects("fixture", "good")
	if attacker.Publish(goodEvent, []byte(`{"status":"ready"}`)) != nil {
		attacker.Close()
		t.Fatal("negative publish did not reach broker")
	}
	_, err = attacker.SubscribeSync(goodControl)
	if err != nil {
		attacker.Close()
		t.Fatal("negative subscription did not reach broker")
	}
	if attacker.FlushTimeout(time.Second) != nil {
		attacker.Close()
		t.Fatal("negative client flush")
	}
	for range 2 {
		select {
		case e := <-denied:
			if !strings.Contains(e.Error(), "Permissions Violation") {
				attacker.Close()
				t.Fatal("unexpected negative broker result")
			}
		case <-time.After(time.Second):
			attacker.Close()
			t.Fatal("broker did not enforce lifecycle subject boundary")
		}
	}
	attacker.Close()
	if _, err = NewNativeDriver(context.Background(), fixture.options); err == nil {
		t.Fatal("duplicate manager lock admitted")
	}
	if _, err = manager.Activate(context.Background(), nativeRequest([]AdmittedPackage{good, bad}, map[string]string{"good": "normal", "bad": "wrong-owner"})); err == nil {
		t.Fatal("wrong owner readiness admitted")
	}
	if manager.CheckActive(entry.Owner) != nil {
		t.Fatal("failed addition replaced active owner")
	}
	driver.mu.Lock()
	count := len(driver.owners)
	driver.mu.Unlock()
	if count != 1 {
		t.Fatal("failed addition retained a live owner")
	}
	fixture.stop()
	trace, err := os.ReadFile(filepath.Join(fixture.root, "server.private.log"))
	if err != nil || !bytes.Contains(trace, []byte("Permissions Violation")) || !bytes.Contains(trace, []byte(goodEvent)) {
		t.Fatal("private broker trace did not record the negative check")
	}
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		if manager.CheckActive(entry.Owner) != nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if manager.CheckActive(entry.Owner) == nil {
		t.Fatal("lost transport still authorized")
	}
}

func TestNativeLiveRestartAndForcedStop(t *testing.T) {
	if os.Getenv("AGENTMUX_PLUGIN_NATS") == "" {
		t.Skip("prepared native NATS required")
	}
	crash, stubborn := nativeFixturePackage(t, "crash"), nativeFixturePackage(t, "stubborn")
	fixture := liveNativeBroker(t, []AdmittedPackage{crash, stubborn})
	driver, err := NewNativeDriver(context.Background(), fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(context.Background(), driver, ManagerOptions{Platform: Platform{"darwin", "arm64"}, InstallationMode: "independent", ActivationTimeout: 5 * time.Second, CleanupTimeout: 3 * time.Second})
	if err != nil {
		_ = driver.Close(context.Background())
		t.Fatal(err)
	}
	defer closeNativeFixture(t, manager, driver)
	if _, err = manager.Activate(context.Background(), nativeRequest([]AdmittedPackage{crash, stubborn}, map[string]string{"crash": "crash", "stubborn": "stubborn"})); err != nil {
		t.Fatal(err)
	}
	entry, err := manager.Resolve("tool", "crash")
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(5 * time.Second)
	exhausted := false
	for time.Now().Before(until) {
		for _, instance := range manager.Snapshot().Instances {
			if instance.Owner.Pin.PackageID == "crash" && instance.Code == "plugin_restart_exhausted" && instance.RestartAttempts == 1 && instance.Owner.Generation > entry.Owner.Generation {
				exhausted = true
			}
		}
		if exhausted {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !exhausted || manager.CheckActive(entry.Owner) == nil {
		t.Fatal("restart budget or stale owner failure")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if err = manager.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err = driver.Close(ctx); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(fixture.options.StateDirectory)
	if err != nil {
		t.Fatal("fixture state read")
	}
	for _, file := range files {
		if strings.HasPrefix(file.Name(), "instance-") {
			t.Fatal("owned stage remained")
		}
	}
}

// The child checks the actual private descriptor and uses only its published
// handles. Test authority admits fixture claims; it does not verify signatures.
func nativeChildContext(t *testing.T, bootstrap NativeBootstrap, configuration []byte) func() {
	t.Helper()
	var behavior struct {
		Behavior         string `json:"behavior"`
		FixtureDirectory string `json:"fixtureDirectory"`
	}
	_ = json.Unmarshal(configuration, &behavior)
	private := bootstrap.Context
	raw, err := ReadOwnerPrivateFile(private.ContextFile, manifestLimit)
	if err != nil || checksum(raw) != bootstrap.Prepare.ContextChecksum || validateContextJSON("plugin-context", raw) != nil {
		t.Fatal("child context descriptor invalid")
	}
	var descriptor struct {
		InstanceID            string `json:"instanceId"`
		PackageID             string `json:"packageId"`
		PackageVersion        string `json:"packageVersion"`
		PackageDigest         string `json:"packageDigest"`
		ConfigurationRevision uint64 `json:"configurationRevision"`
		Services              map[string]struct {
			HandleID string `json:"handleId"`
		} `json:"services"`
	}
	if json.Unmarshal(raw, &descriptor) != nil || descriptor.InstanceID != bootstrap.Prepare.Owner.InstanceID || descriptor.PackageID != bootstrap.Prepare.Owner.Pin.PackageID || descriptor.PackageVersion != bootstrap.Prepare.Owner.Pin.Version || descriptor.PackageDigest != bootstrap.Prepare.Owner.Pin.PackageChecksum || len(descriptor.Services) != 7 {
		t.Fatal("child context owner mismatch")
	}
	tlsOptions, dialer, err := nativeChildTLSOptions(private.Transport.ServerURL, private.CAFile, private.Transport.ServerName, private.Transport.LeafCertificateSHA256)
	if err != nil {
		t.Fatal("child context TLS enrollment invalid")
	}
	options := append([]nats.Option{nats.UserCredentials(private.CredentialsFile), nats.NoReconnect(), nats.IgnoreDiscoveredServers(), nats.Timeout(time.Second)}, tlsOptions...)
	nc, err := nats.Connect(private.Transport.ServerURL, options...)
	if err != nil && dialer != nil {
		if behavior.Behavior == "identity-isolation" || behavior.Behavior == "storage-contract" {
			nativeIdentityJoinTLS(t, dialer, behavior.FixtureDirectory)
		} else if dialer.Close() != nil {
			t.Error("child refused context TLS sockets did not close")
		}
	}

	if err != nil {
		t.Fatal("child context transport unavailable")
	}
	handedOff := false
	defer func() {
		if !handedOff {
			nc.Close()
			if behavior.Behavior == "identity-isolation" || behavior.Behavior == "storage-contract" {
				nativeIdentityJoinTLS(t, dialer, behavior.FixtureDirectory)
			} else if dialer != nil && dialer.Close() != nil {
				t.Error("child original context TLS sockets did not close")
			}
		}
	}()
	replies, e1 := nc.SubscribeSync(private.Transport.ReplySubject)
	invokes, e2 := nc.SubscribeSync(private.Transport.InvokeSubject)
	cancels, e3 := nc.SubscribeSync(private.Transport.CancelSubject)
	if e1 != nil || e2 != nil || e3 != nil || nc.FlushTimeout(time.Second) != nil {
		nc.Close()
		t.Fatal("child context subscriptions unavailable")
	}
	call := func(service, method string, operation *string, parameters any) contextServiceReply {
		request := contextServiceRequest{SchemaVersion: "1.0.0", Kind: "plugin-context-request", RequestID: contextTestNonce("request"), Owner: bootstrap.Prepare.Owner, HandleID: descriptor.Services[service].HandleID, Service: service, Method: method, OperationHandle: operation, Parameters: contextJSON(parameters)}
		if nc.Publish(private.Transport.RequestSubject, contextJSON(request)) != nil || nc.FlushTimeout(time.Second) != nil {
			t.Fatal("child context request failed")
		}
		message, err := replies.NextMsg(3 * time.Second)
		var reply contextServiceReply
		if err != nil || decodeContextJSON("plugin-context-reply", message.Data, &reply) != nil || reply.RequestID != request.RequestID || reply.Owner != request.Owner {
			t.Fatal("child context reply invalid")
		}
		return reply
	}
	before := time.Now()
	clockReply := call("clock", "now", nil, map[string]any{})
	var clockValue struct {
		Now string `json:"now"`
	}
	_ = json.Unmarshal(clockReply.Value, &clockValue)
	now, err := time.Parse(time.RFC3339Nano, clockValue.Now)
	if clockReply.Code != "ok" || err != nil || now.Before(before.Add(-time.Second)) || now.After(time.Now().Add(time.Second)) {
		t.Fatal("child clock value invalid")
	}
	elapsedReply := call("clock", "elapsed", nil, map[string]any{})
	var elapsed struct {
		Milliseconds int64 `json:"elapsedMs"`
	}
	if elapsedReply.Code != "ok" || json.Unmarshal(elapsedReply.Value, &elapsed) != nil || elapsed.Milliseconds < 0 || uint64(elapsed.Milliseconds) > maxGeneration {
		t.Fatal("child elapsed clock value invalid")
	}
	if call("lifecycle", "report-health", nil, map[string]any{"health": "healthy"}).Code != "ok" {
		t.Fatal("child health report failed")
	}
	status := call("lifecycle", "status", nil, map[string]any{})
	var state ContextLifecycleSnapshot
	if status.Code != "ok" || json.Unmarshal(status.Value, &state) != nil || state.Owner != bootstrap.Prepare.Owner || state.State != "starting" || state.Ready || state.Health != "healthy" {
		t.Fatal("child lifecycle value invalid")
	}
	if behavior.Behavior == "identity-isolation" {
		handedOff = true
		return nativeChildIdentityCalls(t, bootstrap, configuration, nc, dialer, call, replies, invokes, cancels)
	}
	if behavior.Behavior == "storage-contract" {
		// The storage contract uses host-constructed typed handles bound to
		// this real process. Child gateway RPC coverage remains separate.
		handedOff = true
		return func() {
			for _, subscription := range []*nats.Subscription{replies, invokes, cancels} {
				if err := subscription.Unsubscribe(); err != nil && nc.IsConnected() {
					t.Error("storage child context subscription cleanup failed")
				}
			}
			nc.Close()
			nativeIdentityJoinTLS(t, dialer, behavior.FixtureDirectory)
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		type invocation struct {
			Owner     OwnerReference         `json:"owner"`
			Handle    string                 `json:"operationHandle"`
			Operation contextOperationClaims `json:"operation"`
		}
		read := func() (invocation, bool) {
			message, err := invokes.NextMsg(10 * time.Second)
			if err != nil {
				return invocation{}, false
			}
			var invoke invocation
			if decodeContextJSON("plugin-context-operation", message.Data, &invoke) != nil || invoke.Owner != bootstrap.Prepare.Owner || invoke.Handle == "" {
				t.Error("child invocation invalid")
				return invocation{}, false
			}
			return invoke, true
		}
		// Both callers must be outstanding before either can complete.
		first, ok := read()
		if !ok {
			return
		}
		second, ok := read()
		if !ok {
			return
		}
		if first.Handle == second.Handle || first.Operation.Caller.PrincipalID == second.Operation.Caller.PrincipalID {
			t.Error("child caller handles mixed")
			return
		}
		ready := call("lifecycle", "status", nil, map[string]any{})
		if ready.Code != "ok" || json.Unmarshal(ready.Value, &state) != nil || state.Owner != bootstrap.Prepare.Owner || state.State != "ready" || !state.Ready || state.Health != "healthy" {
			t.Error("child lifecycle readiness mismatch")
			return
		}
		subscribe := func(handle, mode string) string {
			reply := call("domainGateway", "subscribe", &handle, map[string]any{"bindingId": "events", "contractId": "status-events", "payload": map[string]any{"mode": mode}})
			var value struct {
				Handle string `json:"subscriptionHandle"`
			}
			if reply.Code != "ok" || json.Unmarshal(reply.Value, &value) != nil || value.Handle == "" {
				t.Error("child subscription admission failed")
				return ""
			}
			return value.Handle
		}
		for _, invoke := range []invocation{first, second} {
			handle := invoke.Handle
			if call("logger", "record", &handle, map[string]any{"eventCode": "operation_started", "projectId": "forged_project"}).Outcome != "rejected" {
				t.Error("forged logger tags accepted")
				return
			}
			for _, entry := range []struct {
				service, method string
				parameters      any
			}{
				{"logger", "record", map[string]any{"eventCode": "operation_started"}},
				{"metrics", "add", map[string]any{"metricCode": "calls", "value": 1}},
				{"clock", "wait", map[string]any{"durationMs": 1}},
				{"domainGateway", "request", map[string]any{"bindingId": "owner", "contractId": "status-query", "payload": map[string]any{"private": "domain-secret"}}},
			} {
				if call(entry.service, entry.method, &handle, entry.parameters).Code != "ok" {
					t.Error("child operation service failed")
					return
				}
			}
			subscription := subscribe(handle, "event")
			if subscription == "" {
				return
			}
			event := call("domainGateway", "next", &handle, map[string]any{"subscriptionHandle": subscription})
			var delivered struct {
				Event string `json:"event"`
			}
			if event.Code != "ok" || json.Unmarshal(event.Value, &delivered) != nil || delivered.Event != "status_changed" {
				t.Error("child subscription event invalid")
				return
			}
			if call("domainGateway", "unsubscribe", &handle, map[string]any{"subscriptionHandle": subscription}).Code != "ok" {
				t.Error("child subscription cleanup failed")
				return
			}
			config := call("config", "read", &handle, map[string]any{})
			var snapshot struct {
				Bytes    string `json:"configurationBytes"`
				Revision uint64 `json:"configurationRevision"`
			}
			_ = json.Unmarshal(config.Value, &snapshot)
			decoded, err := base64.StdEncoding.DecodeString(snapshot.Bytes)
			if config.Code != "ok" || err != nil || !bytes.Equal(decoded, configuration) || snapshot.Revision != descriptor.ConfigurationRevision {
				t.Error("child configuration snapshot mismatch")
				return
			}
			span := call("tracing", "start", &handle, map[string]any{"spanCode": "domain_request"})
			var started struct {
				Handle string `json:"spanHandle"`
			}
			_ = json.Unmarshal(span.Value, &started)
			if span.Code != "ok" || started.Handle == "" || call("tracing", "finish", &handle, map[string]any{"spanHandle": started.Handle, "outcomeCode": "completed"}).Code != "ok" {
				t.Error("child trace failed")
				return
			}
			result := contextOperationResult{SchemaVersion: "1.0.0", Kind: "plugin-operation-result", Owner: invoke.Owner, OperationHandle: handle, Outcome: "completed", Value: contextJSON(map[string]any{"caller": invoke.Operation.Caller.PrincipalID})}
			if nc.Publish(private.Transport.ResultSubject, contextJSON(result)) != nil || nc.FlushTimeout(time.Second) != nil {
				t.Error("child result failed")
				return
			}
		}
		invoke, ok := read()
		if !ok {
			return
		}
		if call("logger", "record-instance", nil, map[string]any{"eventCode": "config_ready"}).Code != "ok" {
			t.Error("child configuration readiness failed")
			return
		}
		changed := call("config", "wait-change", &invoke.Handle, map[string]any{"afterRevision": descriptor.ConfigurationRevision})
		var update struct {
			Bytes    string `json:"configurationBytes"`
			Revision uint64 `json:"configurationRevision"`
			Checksum string `json:"checksum"`
		}
		if changed.Code != "ok" || json.Unmarshal(changed.Value, &update) != nil {
			t.Error("child configuration notification failed")
			return
		}
		updatedBytes, updateErr := base64.StdEncoding.DecodeString(update.Bytes)
		if updateErr != nil || !bytes.Equal(updatedBytes, configuration) || update.Revision != descriptor.ConfigurationRevision+1 || update.Checksum != checksum(configuration) {
			t.Error("child changed snapshot invalid")
			return
		}
		if call("logger", "record-instance", nil, map[string]any{"eventCode": "config_observed"}).Code != "ok" {
			t.Error("child configuration receipt failed")
			return
		}
		pending := subscribe(invoke.Handle, "wait")
		if pending == "" {
			return
		}
		if call("tracing", "start", &invoke.Handle, map[string]any{"spanCode": "domain_request"}).Code != "ok" {
			t.Error("child cancellation trace failed")
			return
		}
		if call("logger", "record-instance", nil, map[string]any{"eventCode": "cancellation_ready"}).Code != "ok" {
			t.Error("child cancellation readiness failed")
			return
		}
		// The host waits until the original subscription owner enters Next,
		// then cancels this operation. No event may escape that cancellation.
		reply := call("domainGateway", "next", &invoke.Handle, map[string]any{"subscriptionHandle": pending})
		if reply.Outcome != "rejected" || (reply.Code != "context_operation_canceled" && reply.Code != "context_domain_unavailable") {
			t.Error("child canceled subscription survived")
			return
		}
		message, err := cancels.NextMsg(time.Second)
		var canceled struct {
			Handle string `json:"operationHandle"`
		}
		if err != nil || decodeContextJSON("plugin-context-operation", message.Data, &canceled) != nil || canceled.Handle != invoke.Handle {
			t.Error("child cancellation handle mismatch")
			return
		}
		if call("logger", "record-instance", nil, map[string]any{"eventCode": "cancellation_observed"}).Code != "ok" {
			t.Error("child cancellation receipt failed")
			return
		}
		drain := call("lifecycle", "wait-stopping", nil, map[string]any{})
		if drain.Code != "ok" || json.Unmarshal(drain.Value, &state) != nil || state.Owner != bootstrap.Prepare.Owner || state.State != "draining" || state.Ready {
			t.Error("child drain signal invalid")
			return
		}
		if call("logger", "record-instance", nil, map[string]any{"eventCode": "drain_observed"}).Code != "ok" {
			t.Error("child drain receipt failed")
		}
	}()
	handedOff = true
	return func() {
		if dialer != nil {
			defer func() {
				if dialer.Close() != nil {
					t.Error("child context TLS sockets did not close")
				}
			}()
		}
		// A normal stop lets the worker observe drain and publish its receipt
		// before closing the original connection. Earlier failures have a bound.
		select {
		case <-done:
			nc.Close()
		case <-time.After(2 * time.Second):
			nc.Close()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Error("child context worker did not join")
			}
		}
	}
}

// These owners expose actual fixture state and joined resource lifetimes. They
// do not claim a production configuration ledger or signed domain event source.
type nativeContextConfigurationOwner struct {
	*contextMemoryConfigurationOwner
	armed   atomic.Bool
	waiting chan struct{}
}

func (o *nativeContextConfigurationOwner) Open(ctx context.Context, binding ContextBinding) (ContextConfigurationLease, error) {
	lease, err := o.contextMemoryConfigurationOwner.Open(ctx, binding)
	if err != nil {
		return lease, err
	}
	return contextConfigurationInterceptLease{ContextConfigurationLease: lease, snapshot: func(ctx context.Context) (ContextConfigurationSnapshot, <-chan struct{}, error) {
		snapshot, changed, err := lease.Snapshot(ctx)
		if err == nil && snapshot.Revision == 7 && o.armed.Load() {
			select {
			case o.waiting <- struct{}{}:
			default:
			}
		}
		return snapshot, changed, err
	}}, nil
}

type nativeContextSubscription struct {
	*contextMemorySubscription
	waiting chan struct{}
}

func (s *nativeContextSubscription) Next(ctx context.Context) ([]byte, error) {
	if s.waiting != nil {
		select {
		case s.waiting <- struct{}{}:
		default:
		}
	}
	return s.contextMemorySubscription.Next(ctx)
}

func TestNativeLiveContextServicesAndCancellation(t *testing.T) {
	if os.Getenv("AGENTMUX_PLUGIN_NATS") == "" {
		t.Skip("prepared native NATS required")
	}
	pkg := nativeFixturePackage(t, "context_native", func(m *Manifest) {
		// A race-enabled child waits one second at exit. Keep cooperative
		// shutdown long enough to observe its clean exit before TERM.
		m.Lifecycle.DrainDeadlineMS = 8000
		m.RequestedCapabilities = []Capability{{Action: "inspect", ResourceClass: "status", Required: false}, {Action: "subscribe", ResourceClass: "status", Required: false}}
	})
	var options NATSContextOptions
	fixture := liveNativeBrokerWithContext(t, []AdmittedPackage{pkg}, &options)
	denied := make(chan error, 2)
	attacker, err := nats.Connect(options.ServerURL, nats.UserCredentials(options.Bindings[0].ClientCredentialsFile), nats.RootCAs(options.CAFile), nats.NoReconnect(), nats.Timeout(time.Second), nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
		select {
		case denied <- err:
		default:
		}
	}))
	if err != nil {
		t.Fatal("context permission client unavailable")
	}
	defer attacker.Close()
	control, event, _ := lifecycleSubjects(options.HubID, options.Bindings[0].InstanceID)
	if attacker.Publish(control, []byte(`{}`)) != nil {
		t.Fatal("context forbidden publish did not reach broker")
	}
	if _, err := attacker.SubscribeSync(event); err != nil || attacker.FlushTimeout(time.Second) != nil {
		t.Fatal("context forbidden subscription did not reach broker")
	}
	for range 2 {
		select {
		case err := <-denied:
			if !strings.Contains(err.Error(), "Permissions Violation") {
				t.Fatal("unexpected context permission result")
			}
		case <-time.After(time.Second):
			t.Fatal("context credentials crossed lifecycle boundary")
		}
	}
	attacker.Close()
	// Reuse the existing fixture authority and record owners, but replace its
	// in-memory connection with the public native NATS provider constructor.
	records := newContextTestFixture(t, nil)
	records.authority.instance.EffectiveGrant = bytes.ReplaceAll(records.authority.instance.EffectiveGrant, []byte("context_instance"), []byte("context_native"))
	records.authority.instance.EffectiveGrant = bytes.ReplaceAll(records.authority.instance.EffectiveGrant, []byte(`"actions":["inspect"]`), []byte(`"actions":["inspect","subscribe"]`))
	ports := records.provider.ports
	ports.EventCodes = append(ports.EventCodes, "cancellation_ready", "cancellation_observed", "config_ready", "config_observed", "drain_observed")
	records.authority.instance.DomainBindings = append(records.authority.instance.DomainBindings, ContextDomainBinding{ID: "events", ContractID: "status-events", Action: "subscribe", ResourceClass: "status"})
	configurationOwner := &nativeContextConfigurationOwner{contextMemoryConfigurationOwner: newContextMemoryConfigurationOwner(), waiting: make(chan struct{}, 1)}
	ports.Configuration = configurationOwner
	entered, observed := make(chan struct{}, 1), make(chan struct{}, 1)
	configReady, configObserved, drainObserved := make(chan struct{}, 1), make(chan struct{}, 1), make(chan struct{}, 1)
	subscriptionWaiting := make(chan struct{}, 1)
	var subscriptionsMu sync.Mutex
	var subscriptions []*nativeContextSubscription
	ports.Subscribe = func(_ context.Context, approved ContextApprovedEnvelope) (ContextSubscriptionLease, error) {
		var envelope struct {
			Payload struct {
				Mode string `json:"mode"`
			} `json:"payload"`
		}
		if json.Unmarshal(approved.Envelope, &envelope) != nil || approved.BindingID != "events" || (envelope.Payload.Mode != "event" && envelope.Payload.Mode != "wait") {
			return nil, pluginError("context_domain_unavailable")
		}
		subscription := &nativeContextSubscription{contextMemorySubscription: newContextMemorySubscription()}
		if envelope.Payload.Mode == "event" {
			subscription.events <- contextJSON(map[string]any{"bindingId": approved.BindingID, "payload": map[string]any{"event": "status_changed"}})
		} else {
			subscription.waiting = subscriptionWaiting
		}
		subscriptionsMu.Lock()
		subscriptions = append(subscriptions, subscription)
		subscriptionsMu.Unlock()
		return subscription, nil
	}
	originalLog := ports.Log
	ports.Log = func(ctx context.Context, r ContextLogRecord) error {
		err := originalLog(ctx, r)
		switch r.EventCode {
		case "config_ready":
			configurationOwner.armed.Store(true)
			select {
			case configReady <- struct{}{}:
			default:
			}
		case "config_observed":
			select {
			case configObserved <- struct{}{}:
			default:
			}
		case "drain_observed":
			select {
			case drainObserved <- struct{}{}:
			default:
			}
		}
		if r.EventCode == "cancellation_ready" {
			select {
			case entered <- struct{}{}:
			default:
			}
		}
		if r.EventCode == "cancellation_observed" {
			select {
			case observed <- struct{}{}:
			default:
			}
		}
		return err
	}
	provider, err := NewNATSContextProvider(context.Background(), options, ports)
	if err != nil {
		t.Fatal(err)
	}
	driver, err := NewNativeDriverWithContext(context.Background(), fixture.options, provider)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if err := driver.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	configuration, err := PrepareConfiguration(pkg, nil, []byte(`{"behavior":"normal"}`))
	if err != nil {
		t.Fatal(err)
	}
	owner := OwnerReference{Pin: pkg.Pin(), InstanceID: "context_native", Epoch: strings.Repeat("a", 64), Generation: 1}
	startup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	process, err := driver.Start(startup, StartRequest{Owner: owner, Package: pkg, Configuration: configuration})
	if err == nil {
		err = process.WaitReady(startup)
	}
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan contextDispatchResult, 2)
	var dispatchers sync.WaitGroup
	work, stop := context.WithTimeout(context.Background(), 8*time.Second)
	defer func() { stop(); dispatchers.Wait() }()
	for _, name := range []string{"a", "b"} {
		dispatchers.Add(1)
		go func(name string) {
			defer dispatchers.Done()
			raw, err := driver.Dispatch(work, owner, contextTestEnvelope(name))
			results <- contextDispatchResult{raw, err}
		}(name)
	}
	callers := map[string]bool{}
	for range 2 {
		select {
		case result := <-results:
			if result.err != nil {
				t.Fatal(result.err)
			}
			var value struct {
				Caller string `json:"caller"`
			}
			if json.Unmarshal(result.raw, &value) != nil {
				t.Fatal("native result invalid")
			}
			callers[value.Caller] = true
		case <-work.Done():
			t.Fatal("native operations did not join")
		}
	}
	if !callers["caller_a"] || !callers["caller_b"] {
		t.Fatal("native caller results mixed")
	}
	cancellation, stopCall := context.WithCancel(work)
	defer stopCall()
	var envelope map[string]any
	_ = json.Unmarshal(contextTestEnvelope("a"), &envelope)
	envelope["operation"].(map[string]any)["operationId"] = "operation_cancel"
	dispatchers.Add(1)
	go func() {
		defer dispatchers.Done()
		raw, err := driver.Dispatch(cancellation, owner, contextJSON(envelope))
		results <- contextDispatchResult{raw, err}
	}()
	select {
	case <-configReady:
	case <-work.Done():
		t.Fatal("child configuration wait readiness missing")
	}
	select {
	case <-configurationOwner.waiting:
	case <-work.Done():
		t.Fatal("child did not read original configuration before waiting")
	}
	currentConfiguration := configurationOwner.Lease(owner)
	if currentConfiguration == nil {
		t.Fatal("native configuration owner missing")
	}
	currentConfiguration.Update(configuration, 8, []ContextReference{})
	select {
	case <-configObserved:
	case <-work.Done():
		t.Fatal("child did not observe configuration revision")
	}
	select {
	case <-entered:
	case <-work.Done():
		t.Fatal("native cancellation span missing")
	}
	select {
	case <-subscriptionWaiting:
	case <-work.Done():
		t.Fatal("native subscription did not enter receive")
	}
	stopCall()
	select {
	case result := <-results:
		if result.err == nil || result.err.Error() != "context_operation_canceled" {
			t.Fatal("native cancellation result invalid")
		}
	case <-work.Done():
		t.Fatal("native canceled dispatch did not join")
	}
	select {
	case <-observed:
	case <-work.Done():
		t.Fatal("child did not observe cancellation")
	}
	// Stop drives this exact instance's drain signal. The child joins its
	// service worker before closing the connection and exiting normally.
	drain, cancelDrain := context.WithTimeout(context.Background(), 10*time.Second)
	stopErr := process.Stop(drain)
	cancelDrain()
	if stopErr != nil {
		t.Fatal(stopErr)
	}
	if exitErr := process.ExitError(); exitErr == nil || exitErr.Error() != "native_process_exited" {
		t.Fatal("native child did not exit successfully after drain")
	}
	select {
	case <-drainObserved:
	default:
		t.Fatal("child did not acknowledge native drain")
	}
	joined, cancelJoined := context.WithTimeout(context.Background(), 4*time.Second)
	closeErr := driver.Close(joined)
	cancelJoined()
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if !completed(currentConfiguration.Done()) {
		t.Fatal("native configuration lease did not join")
	}
	subscriptionsMu.Lock()
	ownedSubscriptions := append([]*nativeContextSubscription{}, subscriptions...)
	subscriptionsMu.Unlock()
	if len(ownedSubscriptions) != 3 {
		t.Fatal("native subscription admissions missing")
	}
	for _, subscription := range ownedSubscriptions {
		if !completed(subscription.Done()) {
			t.Fatal("native subscription owner did not join")
		}
	}
	records.mu.Lock()
	defer records.mu.Unlock()
	if len(records.logs) != 7 || len(records.metrics) != 2 || len(records.traces) != 6 || records.domains != 2 {
		t.Fatal("native service effects missing or forged log accepted")
	}
	eventCounts := map[string]int{}
	for _, record := range records.logs {
		if record.Tags.Owner != owner {
			t.Fatal("native diagnostic owner mismatch")
		}
		eventCounts[record.EventCode]++
	}
	expectedEvents := map[string]int{"operation_started": 2, "config_ready": 1, "config_observed": 1, "cancellation_ready": 1, "cancellation_observed": 1, "drain_observed": 1}
	if !reflect.DeepEqual(eventCounts, expectedEvents) {
		t.Fatal("native diagnostic events missing or repeated")
	}
	var tagsToCheck []ContextTags
	for _, record := range records.logs {
		if record.EventCode == "operation_started" {
			tagsToCheck = append(tagsToCheck, record.Tags)
		}
	}
	for _, record := range records.metrics {
		tagsToCheck = append(tagsToCheck, record.Tags)
	}
	for _, record := range records.traces {
		tagsToCheck = append(tagsToCheck, record.Tags)
	}
	for _, tags := range tagsToCheck {
		suffix := strings.TrimPrefix(tags.PrincipalID, "caller_")
		if tags.Owner != owner || tags.ProjectID == nil || *tags.ProjectID != "project_"+suffix || tags.TraceID != "trace_"+suffix {
			t.Fatal("native log scope mixed")
		}
		contextTestActorTags(t, tags, suffix)
	}
	if records.traces[5].OutcomeCode != "canceled" {
		t.Fatal("native canceled span retained")
	}
	for _, secret := range []string{"payload-secret", "domain-secret", "forged_project"} {
		if strings.Contains(fmt.Sprint(records.logs, records.metrics, records.traces), secret) {
			t.Fatal("private data in native diagnostics")
		}
	}
	brokerLog, err := os.ReadFile(filepath.Join(fixture.root, "server.private.log"))
	if err != nil {
		t.Fatal("private broker log unavailable")
	}
	for _, secret := range []string{"payload-secret", "domain-secret", "forged_project"} {
		if bytes.Contains(brokerLog, []byte(secret)) {
			t.Fatal("private context data in broker diagnostics")
		}
	}
}

// Both native child channels use the exact disclosed TLS policy. The original
// header-first fixture remains supported only when both explicit pins are absent.
func nativeChildTLSOptions(endpoint, caFile, serverName, leaf string) ([]nats.Option, *localtls.Dialer, error) {
	if serverName == "" && leaf == "" {
		return []nats.Option{nats.RootCAs(caFile)}, nil, nil
	}
	if serverName == "" || leaf == "" {
		return nil, nil, pluginError("native_child_tls_enrollment_invalid")
	}
	roots, err := ReadOwnerPrivateFile(caFile, localtls.MaxRootsPEM)
	if err != nil {
		return nil, nil, pluginError("native_child_tls_enrollment_invalid")
	}
	trust, err := localtls.NewClientTrust(localtls.Policy{Endpoint: endpoint, ServerName: serverName, RootsPEM: roots, LeafCertificateSHA256: leaf})
	if err != nil {
		return nil, nil, pluginError("native_child_tls_enrollment_invalid")
	}
	dialer, err := trust.NewDialer(context.Background(), time.Second)
	if err != nil {
		return nil, nil, pluginError("native_child_tls_enrollment_invalid")
	}
	return []nats.Option{nats.TLSHandshakeFirst(), nats.SetCustomDialer(dialer)}, dialer, nil
}
