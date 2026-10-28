//go:build darwin

package appruntime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"
)

func natsServer(t *testing.T) string {
	t.Helper()
	path := os.Getenv("AGENTMUX_NATS_SERVER")
	if path == "" {
		path = "/opt/homebrew/Cellar/nats-server/2.15.0/bin/nats-server"
	}
	if _, err := AdmitNATSServer(context.Background(), path); err != nil {
		t.Skip("pinned nats-server " + NATSVersion + " unavailable")
	}
	return path
}

func netListen(address string) (net.Listener, error) { return net.Listen("tcp", address) }

func runtimeDir(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(base, "application-runtime")
}

func TestJWTSignatureAndSubjectBinding(t *testing.T) {
	operator, _ := nkeys.CreateOperator()
	account, _ := nkeys.CreateAccount()
	operatorPublic, _ := operator.PublicKey()
	accountPublic, _ := account.PublicKey()
	token, err := issueJWT(operator, accountPublic, "a", accountClaims(true, 1), time.Now(), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyJWT(token, operatorPublic, accountPublic); err != nil {
		t.Fatal("valid token refused")
	}
	if _, err := verifyJWT(token, accountPublic, accountPublic); err == nil {
		t.Fatal("wrong issuer accepted")
	}
	parts := strings.Split(token, ".")
	tampered := parts[0] + "." + parts[1] + "x." + parts[2]
	if _, err := verifyJWT(tampered, operatorPublic, accountPublic); err == nil {
		t.Fatal("tampered token accepted")
	}
}

func TestStartReadyNoDuplicateStopAndRestartKeepIdentity(t *testing.T) {
	server := natsServer(t)
	dir := runtimeDir(t)
	ctx := context.Background()
	first, err := Initialize(ctx, dir, Inputs{NATSServer: server})
	if err != nil || first.Outcome != "initialized" {
		t.Fatalf("initialize: %v %+v", err, first.Outcome)
	}
	if !strings.HasPrefix(first.Manifest.Endpoint, "tls://127.0.0.1:") || first.Manifest.AccountPublicKey == first.Manifest.SystemAccountPublicKey {
		t.Fatal("unexpected manifest")
	}
	t.Cleanup(func() { _, _ = Stop(context.Background(), dir) })
	started, err := Start(ctx, dir)
	if err != nil || started.State != "running" || started.PID == 0 {
		t.Fatalf("start: %v %+v", err, started)
	}
	again, err := Start(ctx, dir)
	if err != nil || again.State != "running" || again.PID != started.PID {
		t.Fatalf("second start must report the same owned server: %v %+v", err, again)
	}
	if observed, err := Observe(ctx, dir); err != nil || observed.State != "running" {
		t.Fatalf("observe: %v %+v", err, observed)
	}
	stopped, err := Stop(ctx, dir)
	if err != nil || stopped.State != "stopped" {
		t.Fatalf("stop: %v %+v", err, stopped)
	}
	if _, _, _, alive := processStart(started.PID); alive {
		if _, _, comm, _ := processStart(started.PID); comm == "nats-server" {
			t.Fatal("server still running after stop")
		}
	}
	unchanged, err := Initialize(ctx, dir, Inputs{})
	if err != nil || unchanged.Outcome != "unchanged" || unchanged.Manifest != first.Manifest {
		t.Fatalf("rerun must keep identities: %v %s", err, unchanged.Outcome)
	}
	restarted, err := Start(ctx, dir)
	if err != nil || restarted.State != "running" || restarted.RuntimeID != first.Manifest.RuntimeID {
		t.Fatalf("restart: %v %+v", err, restarted)
	}
}

func TestStaleRecordIsClearedAndPortConflictRefused(t *testing.T) {
	server := natsServer(t)
	dir := runtimeDir(t)
	ctx := context.Background()
	result, err := Initialize(ctx, dir, Inputs{NATSServer: server})
	if err != nil {
		t.Fatal(err)
	}
	r, err := Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	stale := `{"schemaVersion":"1.0.0","runtimeId":"x","pid":999999,"startSeconds":1,"startMicros":1}` + "\n"
	if err := r.publish("runtime-process.json", []byte(stale)); err != nil {
		t.Fatal(err)
	}
	r.Close()
	if observed, _ := Observe(ctx, dir); observed.State != "stale" {
		t.Fatalf("stale record not reported: %+v", observed)
	}
	port := strings.TrimPrefix(result.Manifest.Endpoint, "tls://")
	occupied, err := netListen(port)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Start(ctx, dir); !errors.Is(err, ErrPortInUse) {
		t.Fatalf("occupied port must be refused, got %v", err)
	}
	occupied.Close()
}

func TestInterruptedInitializationResumesWithoutRegeneratingIdentities(t *testing.T) {
	server := natsServer(t)
	ctx := context.Background()
	for cut := 1; cut < len(artifacts); cut++ {
		dir := runtimeDir(t)
		if _, err := Initialize(ctx, dir, Inputs{NATSServer: server}); err != nil {
			t.Fatal(err)
		}
		kept := map[string][]byte{}
		for i, name := range artifacts {
			path := filepath.Join(dir, name)
			if i >= cut {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				continue
			}
			kept[name], _ = os.ReadFile(path)
		}
		resumed, err := Initialize(ctx, dir, Inputs{})
		if err != nil || resumed.Outcome != "recovered" {
			t.Fatalf("cut %d: %v %s", cut, err, resumed.Outcome)
		}
		for name, before := range kept {
			after, _ := os.ReadFile(filepath.Join(dir, name))
			if string(after) != string(before) {
				t.Fatalf("cut %d: retained %s changed", cut, name)
			}
		}
	}
}

func TestGapStageAndChangedInputsAreRefused(t *testing.T) {
	server := natsServer(t)
	ctx := context.Background()
	dir := runtimeDir(t)
	if _, err := Initialize(ctx, dir, Inputs{NATSServer: server}); err != nil {
		t.Fatal(err)
	}
	if _, err := Initialize(ctx, dir, Inputs{Port: 1}); !errors.Is(err, ErrInputs) {
		t.Fatalf("changed port must be refused, got %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".stage-leftover"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Initialize(ctx, dir, Inputs{}); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("leftover stage must be refused, got %v", err)
	}
	os.Remove(filepath.Join(dir, ".stage-leftover"))
	if err := os.Remove(filepath.Join(dir, "account.nk")); err != nil {
		t.Fatal(err)
	}
	if _, err := Initialize(ctx, dir, Inputs{}); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("missing earlier identity with later files must be refused, got %v", err)
	}
	other := runtimeDir(t)
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Initialize(ctx, other, Inputs{NATSServer: server}); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("non-private directory must be refused, got %v", err)
	}
}

// Review item 5: a publish interrupted after its stage was written, or after
// the stage was linked but before it was removed, must not block init or start.
func TestInterruptedPublishLeftoversAreSweptOnResumeAndStart(t *testing.T) {
	server := natsServer(t)
	ctx := context.Background()
	dir := runtimeDir(t)
	first, err := Initialize(ctx, dir, Inputs{NATSServer: server})
	if err != nil {
		t.Fatal(err)
	}
	// Linked, not yet unlinked: account.jwt has a second name.
	if err := os.Link(filepath.Join(dir, "account.jwt"), filepath.Join(dir, ".stage-0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = Stop(context.Background(), dir) })
	started, err := Start(ctx, dir)
	if err != nil || started.State != "running" {
		t.Fatalf("start after interrupted link: %v %+v", err, started)
	}
	if _, err := Stop(ctx, dir); err != nil {
		t.Fatal(err)
	}
	// Written, not yet linked: runtime.json is missing and its stage is partial.
	if err := os.Remove(filepath.Join(dir, "runtime.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".stage-fedcba9876543210"), []byte("{\"sche"), 0o600); err != nil {
		t.Fatal(err)
	}
	resumed, err := Initialize(ctx, dir, Inputs{})
	if err != nil || resumed.Outcome != "recovered" || resumed.Manifest != first.Manifest {
		t.Fatalf("resume after interrupted stage: %v %+v", err, resumed.Outcome)
	}
	names, _ := os.ReadDir(dir)
	for _, entry := range names {
		if strings.HasPrefix(entry.Name(), ".stage-") {
			t.Fatalf("stage %s left behind", entry.Name())
		}
	}
	for _, name := range artifacts {
		var st unix.Stat_t
		if err := unix.Lstat(filepath.Join(dir, name), &st); err != nil || st.Nlink != 1 {
			t.Fatalf("%s is not a single-link file", name)
		}
	}
}

// Review item 2: the runtime owns the server it started whatever the admitted
// executable is called, including a name longer than the kernel keeps.
func TestServerUnderAnotherNameIsOwnedReadyAndStopped(t *testing.T) {
	server := natsServer(t)
	raw, err := os.ReadFile(server)
	if err != nil {
		t.Fatal(err)
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	renamed := filepath.Join(base, "agentmux-nats-server-2.15.0")
	if err := os.WriteFile(renamed, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	dir := runtimeDir(t)
	if _, err := Initialize(ctx, dir, Inputs{NATSServer: renamed}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = Stop(context.Background(), dir) })
	started, err := Start(ctx, dir)
	if err != nil || started.State != "running" || started.PID == 0 {
		t.Fatalf("start: %v %+v", err, started)
	}
	if observed, err := Observe(ctx, dir); err != nil || observed.State != "running" {
		t.Fatalf("observe: %v %+v", err, observed)
	}
	if stopped, err := Stop(ctx, dir); err != nil || stopped.State != "stopped" {
		t.Fatalf("stop: %v %+v", err, stopped)
	}
	if _, _, comm, alive := processStart(started.PID); alive && comm == commandName(renamed) {
		t.Fatal("renamed server still running after stop")
	}
}

func TestRecordWithoutCommandKeepsTheHistoricalName(t *testing.T) {
	dir := runtimeDir(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	r, err := Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	old := `{"schemaVersion":"1.0.0","runtimeId":"x","pid":999999,"startSeconds":1,"startMicros":1}` + "\n"
	if err := r.publish("runtime-process.json", []byte(old)); err != nil {
		t.Fatal(err)
	}
	record, err := r.record()
	if err != nil || record.Command != "nats-server" {
		t.Fatalf("record: %v %+v", err, record)
	}
}

// Review item 8: a retained port from the temporary range can be taken by any
// outgoing connection while the runtime is stopped, so its start then fails.
func TestRuntimePortIsChosenBelowTheTemporaryRange(t *testing.T) {
	server := natsServer(t)
	first, err := unix.SysctlUint32("net.inet.ip.portrange.first")
	if err != nil {
		t.Fatal(err)
	}
	limit := 32768
	if int(first) < limit {
		limit = int(first)
	}
	result, err := Initialize(context.Background(), runtimeDir(t), Inputs{NATSServer: server})
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(result.Manifest.Endpoint, "tls://"))
	if value, _ := strconv.Atoi(port); value < 1024 || value >= limit {
		t.Fatalf("runtime port %s is in the temporary range", port)
	}
	for i := 0; i < 200; i++ {
		port, err := freePort()
		if err != nil || port < 1024 || port >= limit {
			t.Fatalf("port %d (%v) is in the temporary range", port, err)
		}
	}
}

func retainedLeaf(t *testing.T, dir string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "tls-server-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// Review item 7: every enrollment pins the root and leaf, so the certificate
// lives as long as the installation instead of expiring after 397 days.
func TestTLSLifetimeOutlivesTheInstallationAndIsReported(t *testing.T) {
	server := natsServer(t)
	dir := runtimeDir(t)
	if _, err := Initialize(context.Background(), dir, Inputs{NATSServer: server}); err != nil {
		t.Fatal(err)
	}
	leaf := retainedLeaf(t, dir)
	if leaf.NotAfter.Before(time.Now().AddDate(9, 0, 0)) {
		t.Fatalf("certificate expires %s", leaf.NotAfter)
	}
	observed, err := Observe(context.Background(), dir)
	if err != nil || observed.TLSNotAfter != leaf.NotAfter.UTC().Format(time.RFC3339) {
		t.Fatalf("status must report the certificate expiry: %v %+v", err, observed)
	}
}

// Review item 7: an expired certificate is a clear refusal, not a ten-second
// wait for a server no client will accept.
func TestExpiredCertificateIsRefusedBeforeStart(t *testing.T) {
	server := natsServer(t)
	dir := runtimeDir(t)
	if _, err := Initialize(context.Background(), dir, Inputs{NATSServer: server}); err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	expired := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "expired"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, expired, expired, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tls-server-cert.pem")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = Stop(context.Background(), dir) })
	began := time.Now()
	if _, err := Start(context.Background(), dir); !errors.Is(err, ErrTLSExpired) || time.Since(began) > 2*time.Second {
		t.Fatalf("expired certificate must be refused at once, got %v after %s", err, time.Since(began))
	}
}

func TestThreeInstallationsHaveDistinctIdentities(t *testing.T) {
	server := natsServer(t)
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		result, err := Initialize(context.Background(), runtimeDir(t), Inputs{NATSServer: server})
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{result.Manifest.RuntimeID, result.Manifest.OperatorPublicKey, result.Manifest.AccountPublicKey,
			result.Manifest.SystemAccountPublicKey, result.Manifest.LeafCertificateSHA256} {
			if seen[value] {
				t.Fatal("identity reused across installations")
			}
			seen[value] = true
		}
	}
}

func TestPrivateFileModes(t *testing.T) {
	server := natsServer(t)
	dir := runtimeDir(t)
	if _, err := Initialize(context.Background(), dir, Inputs{NATSServer: server}); err != nil {
		t.Fatal(err)
	}
	for _, name := range artifacts {
		var st unix.Stat_t
		if err := unix.Lstat(filepath.Join(dir, name), &st); err != nil || st.Mode&0o777 != 0o600 || st.Nlink != 1 {
			t.Fatalf("%s is not a private single-link file", name)
		}
	}
}

// Decision 11: the server key lives only in tls-server-key.pem, and the
// published bundle carries the certificates for that key and nothing private.
func TestTLSBundleHoldsNoPrivateKey(t *testing.T) {
	server := natsServer(t)
	dir := runtimeDir(t)
	if _, err := Initialize(context.Background(), dir, Inputs{NATSServer: server}); err != nil {
		t.Fatal(err)
	}
	bundle, _ := os.ReadFile(filepath.Join(dir, "tls.json"))
	if strings.Contains(string(bundle), "PRIVATE KEY") || strings.Contains(string(bundle), "keyPEM") {
		t.Fatal("tls.json keeps a copy of the server key")
	}
	assertKeyMatchesCertificate(t, dir)
}

// A bundle written before decision 11 has its key copy removed on the next
// initialization, and nothing else changes.
func TestOlderBundleLosesItsKeyCopyOnResume(t *testing.T) {
	server := natsServer(t)
	ctx := context.Background()
	dir := runtimeDir(t)
	if _, err := Initialize(ctx, dir, Inputs{NATSServer: server}); err != nil {
		t.Fatal(err)
	}
	writeOlderBundle(t, dir, "")
	kept := map[string][]byte{}
	for _, name := range artifacts {
		kept[name], _ = os.ReadFile(filepath.Join(dir, name))
	}
	if _, err := Initialize(ctx, dir, Inputs{}); err != nil {
		t.Fatal(err)
	}
	bundle, _ := os.ReadFile(filepath.Join(dir, "tls.json"))
	if strings.Contains(string(bundle), "PRIVATE KEY") || strings.Contains(string(bundle), "keyPEM") {
		t.Fatal("older bundle kept its key copy")
	}
	for name, before := range kept {
		after, _ := os.ReadFile(filepath.Join(dir, name))
		if name != "tls.json" && string(after) != string(before) {
			t.Fatalf("%s changed", name)
		}
	}
	var st unix.Stat_t
	if err := unix.Lstat(filepath.Join(dir, "tls.json"), &st); err != nil || st.Mode&0o777 != 0o600 || st.Nlink != 1 {
		t.Fatal("rewritten tls.json is not a private single-link file")
	}
	assertKeyMatchesCertificate(t, dir)
	if _, err := Initialize(ctx, dir, Inputs{}); err != nil {
		t.Fatal(err)
	}
}

// An older bundle whose key copy differs from the server key is refused.
func TestOlderBundleWithAnotherKeyIsRefused(t *testing.T) {
	server := natsServer(t)
	ctx := context.Background()
	dir := runtimeDir(t)
	if _, err := Initialize(ctx, dir, Inputs{NATSServer: server}); err != nil {
		t.Fatal(err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(other)
	writeOlderBundle(t, dir, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})))
	before, _ := os.ReadFile(filepath.Join(dir, "tls.json"))
	if _, err := Initialize(ctx, dir, Inputs{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("mismatched key copy must be refused, got %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "tls.json"))
	if string(after) != string(before) {
		t.Fatal("refused bundle was changed")
	}
}

// writeOlderBundle replaces tls.json with the pre-decision-11 shape, holding
// keyPEM (the retained server key when keyPEM is empty).
func writeOlderBundle(t *testing.T, dir, keyPEM string) {
	t.Helper()
	if keyPEM == "" {
		raw, _ := os.ReadFile(filepath.Join(dir, "tls-server-key.pem"))
		keyPEM = string(raw)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "tls.json"))
	var bundle map[string]string
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	bundle["keyPEM"] = keyPEM
	older, _ := json.Marshal(bundle)
	path := filepath.Join(dir, "tls.json")
	os.Remove(path)
	if err := os.WriteFile(path, append(older, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertKeyMatchesCertificate(t *testing.T, dir string) {
	t.Helper()
	rawKey, _ := os.ReadFile(filepath.Join(dir, "tls-server-key.pem"))
	rawCert, _ := os.ReadFile(filepath.Join(dir, "tls-server-cert.pem"))
	keyBlock, _ := pem.Decode(rawKey)
	certBlock, _ := pem.Decode(rawCert)
	if keyBlock == nil || certBlock == nil {
		t.Fatal("server key or certificate unreadable")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !key.PublicKey.Equal(leaf.PublicKey) {
		t.Fatal("certificate is not for the retained server key")
	}
}
