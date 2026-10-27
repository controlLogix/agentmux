//go:build darwin

package appruntime

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
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
