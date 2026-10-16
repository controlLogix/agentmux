//go:build darwin && arm64 && cgo && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/internal/darwinfixtureidentity"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/privatefs"
	"golang.org/x/sys/unix"
)

type endpointProxyOwnedConn struct {
	*net.UnixConn
	once sync.Once
	err  error
}

func (c *endpointProxyOwnedConn) Close() error {
	c.once.Do(func() { c.err = c.UnixConn.Close() })
	return c.err
}

// Only the actual owned native stream and Go's exact Unix shutdown wrapper
// qualify. Unknown wrappers, locally closed streams, EPIPE and copy errors do
// not acquire this exception. The caller must first complete Copy with nil.
func endpointProxyDisconnectedAfterEOF(stream endpointProxyStream, err error) bool {
	owned, ok := stream.(*endpointProxyOwnedConn)
	if !ok || owned == nil || owned.UnixConn == nil {
		return false
	}
	op, ok := err.(*net.OpError)
	if !ok || op == nil || op.Op != "close" || op.Net != "unix" {
		return false
	}
	call, ok := op.Err.(*os.SyscallError)
	if !ok || call == nil || call.Syscall != "shutdown" {
		return false
	}
	errno, ok := call.Err.(syscall.Errno)
	return ok && errno == syscall.ENOTCONN
}

// No caller receives API bytes. Results contain only bounded counts and flags.
type endpointProxyServer struct {
	listener         *net.UnixListener
	cancel           context.CancelFunc
	done             chan struct{}
	closeOnce        sync.Once
	closeErr         error
	mu               sync.Mutex
	active, accepted int
	failed           bool
	paused           bool
	sessions         map[*endpointProxySession]struct{}
	results          []endpointProxyStreamResult
	workers          sync.WaitGroup
}

type endpointProxySession struct {
	cancel context.CancelFunc
	done   chan struct{}
}

type endpointProxyStateFailure string

func (e endpointProxyStateFailure) Error() string {
	switch e {
	case "endpoint_proxy_stream_pause_unjoined", "endpoint_proxy_stream_pause_failed", "endpoint_proxy_resume_refused",
		"endpoint_proxy_listener_already_joined", "endpoint_proxy_join_or_stream_failed", "endpoint_proxy_original_workers_unjoined":
		return string(e)
	default:
		return "endpoint_proxy_state_unknown"
	}
}

func endpointProxyFailureStage(err error) string {
	if value, ok := err.(endpointProxyStateFailure); ok {
		return value.Error()
	}
	return "endpoint_proxy_state_unknown"
}

// Copies only mutex-protected published result values and closed-channel
// observations. It reads no live payload or output buffer and grants no
// cleanup authority. Counts explicitly distinguish published and joined work.
func (p *endpointProxyServer) diagnosticSnapshot() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	joined := 0
	for session := range p.sessions {
		select {
		case <-session.done:
			joined++
		default:
		}
	}
	listenerJoined := false
	select {
	case <-p.done:
		listenerJoined = true
	default:
	}
	return map[string]any{"active": p.active, "accepted": p.accepted, "failed": p.failed, "paused": p.paused,
		"sessionsRegistered": len(p.sessions), "sessionsJoined": joined, "listenerJoined": listenerJoined,
		"publishedResults": append([]endpointProxyStreamResult(nil), p.results...)}
}

func endpointProxyStart(path, upstream string) (*endpointProxyServer, error) {
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, errors.New("endpoint_proxy_listen_refused")
	}
	listener.SetUnlinkOnClose(false)
	ctx, cancel := context.WithCancel(context.Background())
	p := &endpointProxyServer{listener: listener, cancel: cancel, done: make(chan struct{}), sessions: make(map[*endpointProxySession]struct{})}
	go func() {
		defer close(p.done)
		defer p.workers.Wait()
		for {
			left, err := listener.AcceptUnix()
			if err != nil {
				if ctx.Err() == nil {
					p.mu.Lock()
					p.failed = true
					p.mu.Unlock()
				}
				return
			}
			ownedLeft := &endpointProxyOwnedConn{UnixConn: left}
			p.mu.Lock()
			p.accepted++
			allowed := !p.paused && endpointProxyConnectionAllowed(p.active, p.accepted)
			sessionCtx, sessionCancel := context.WithCancel(ctx)
			session := &endpointProxySession{cancel: sessionCancel, done: make(chan struct{})}
			if allowed {
				p.active++
				p.sessions[session] = struct{}{}
				p.workers.Add(1)
			} else {
				p.failed = true
			}
			p.mu.Unlock()
			if !allowed {
				sessionCancel()
				if ownedLeft.Close() != nil {
					p.mu.Lock()
					p.failed = true
					p.mu.Unlock()
				}
				cancel()
				return
			}
			go func() {
				defer close(session.done)
				defer p.workers.Done()
				defer sessionCancel()
				result := endpointProxyStreamResult{Failed: true}
				defer func() {
					p.mu.Lock()
					defer p.mu.Unlock()
					p.active--
					p.failed = p.failed || result.Failed || result.CloseFailed || !result.Joined
					p.results = append(p.results, result)
				}()
				// This is the only dial destination, copied from separately pinned
				// upstream enrollment. There is no endpoint fallback or redirect.
				dialer := net.Dialer{Timeout: 2 * time.Second}
				rawRight, dialErr := dialer.DialContext(sessionCtx, "unix", upstream)
				if dialErr != nil {
					closeErr := ownedLeft.Close()
					result = endpointProxyStreamResult{Failed: sessionCtx.Err() == nil, Cancelled: sessionCtx.Err() != nil, CloseFailed: closeErr != nil, Joined: true}
					return
				}
				right, ok := rawRight.(*net.UnixConn)
				if !ok {
					a, b := rawRight.Close(), ownedLeft.Close()
					result.CloseFailed, result.Joined = a != nil || b != nil, true
					return
				}
				ownedRight := &endpointProxyOwnedConn{UnixConn: right}
				deadline := time.Now().Add(75 * time.Second)
				if left.SetDeadline(deadline) != nil || right.SetDeadline(deadline) != nil {
					a, b := ownedLeft.Close(), ownedRight.Close()
					result.CloseFailed, result.Joined = a != nil || b != nil, true
					return
				}
				result = endpointProxyRelay(sessionCtx, ownedLeft, ownedRight, 16*1024*1024)
			}()
		}
	}()
	return p, nil
}

func (p *endpointProxyServer) pause(ctx context.Context) error {
	p.mu.Lock()
	p.paused = true
	sessions := make([]*endpointProxySession, 0, len(p.sessions))
	for session := range p.sessions {
		sessions = append(sessions, session)
	}
	p.mu.Unlock()
	for _, session := range sessions {
		session.cancel()
	}
	for _, session := range sessions {
		select {
		case <-session.done:
		case <-ctx.Done():
			return endpointProxyStateFailure("endpoint_proxy_stream_pause_unjoined")
		}
	}
	// paused prevents new registrations; Add used the same mutex. Each done
	// above is closed only after that original worker's cleanup and Done.
	p.workers.Wait()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failed || p.active != 0 {
		return endpointProxyStateFailure("endpoint_proxy_stream_pause_failed")
	}
	return nil
}

func (p *endpointProxyServer) resume() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.paused || p.active != 0 || p.failed {
		return endpointProxyStateFailure("endpoint_proxy_resume_refused")
	}
	select {
	case <-p.done:
		return endpointProxyStateFailure("endpoint_proxy_listener_already_joined")
	default:
	}
	p.paused = false
	return nil
}

func (p *endpointProxyServer) stop(ctx context.Context) error {
	p.cancel()
	p.closeOnce.Do(func() { p.closeErr = p.listener.Close() })
	select {
	case <-p.done:
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.closeErr != nil || p.active != 0 || p.failed {
			return endpointProxyStateFailure("endpoint_proxy_join_or_stream_failed")
		}
		return nil
	case <-ctx.Done():
		return endpointProxyStateFailure("endpoint_proxy_original_workers_unjoined")
	}
}

// A failed join must keep the exact original listener/workers reachable.
var endpointProxyRetained struct {
	sync.Mutex
	servers []*endpointProxyServer
}

type endpointProxyPreparation struct {
	SchemaVersion           string `json:"schemaVersion"`
	Root                    string `json:"root"`
	RootDev                 uint64 `json:"rootDev"`
	RootInode               uint64 `json:"rootInode"`
	GateDev                 uint64 `json:"gateDev"`
	GateInode               uint64 `json:"gateInode"`
	OwnerUID                uint32 `json:"ownerUid"`
	UpstreamSelectionSHA256 string `json:"upstreamSelectionSHA256"`
	SelectedSelectionSHA256 string `json:"selectedSelectionSHA256"`
}

type endpointProxyFixture struct {
	root, gate         *os.Root
	rootFD, gateFD     *os.File
	rootInfo, gateInfo os.FileInfo
	path               string
	socket             unix.Stat_t
	server             *endpointProxyServer
	servers            []*endpointProxyServer
	denied             bool
	faulted            bool
	upstream           bootstrapFixtureSelection
	evidence           *bootstrapDockerFixture
}

func endpointProxyRequire(t *testing.T, ok bool, code string) {
	t.Helper()
	if !ok {
		t.Fatal(code)
	}
}

func endpointProxyPinDir(t *testing.T, file *os.File, device, inode uint64) os.FileInfo {
	t.Helper()
	info, err := file.Stat()
	endpointProxyRequire(t, err == nil && info.IsDir(), "endpoint_proxy_directory_stat")
	s, ok := info.Sys().(*syscall.Stat_t)
	endpointProxyRequire(t, ok && uint64(s.Dev) == device && s.Ino == inode && s.Uid == 501 && s.Flags == 0 &&
		info.Mode().Perm() == 0700 && privatefs.CheckDescriptor(file, privatefs.PrivateObject) == nil, "endpoint_proxy_directory_pin")
	return info
}

func endpointProxyPrepare(t *testing.T) *endpointProxyFixture {
	t.Helper()
	endpointProxyRequire(t, os.Getuid() == 501 && os.Geteuid() == 501 && os.Getenv("HOME") == "/Users/ryan" && os.Getenv("DOCKER_CONFIG") == "" &&
		os.Getenv("AMX_BOOTSTRAP_DOCKER_AUTHORIZED") == "1", "endpoint_proxy_account_context_authorization_required")
	selected, pin := loadBootstrapFixtureSelection(t)
	upstreamPin := os.Getenv("AMX_DARWIN_ENDPOINT_UPSTREAM_SELECTION_SHA256")
	upstream, err := readBootstrapFixtureSelection(os.Getenv("AMX_DARWIN_ENDPOINT_UPSTREAM_SELECTION_FILE"), upstreamPin, bootstrapActualHost(), bootstrapOpenSelection)
	endpointProxyRequire(t, err == nil && selected.Target == "native-darwin" && upstream.Target == "native-darwin" && selected.GOARCH == "arm64", "endpoint_proxy_upstream_selection_required")
	normalized := selected
	normalized.Docker.Context, normalized.Docker.Endpoint = upstream.Docker.Context, upstream.Docker.Endpoint
	endpointProxyRequire(t, reflect.DeepEqual(normalized, upstream) && selected.Docker.Context != upstream.Docker.Context && selected.Docker.Endpoint != upstream.Docker.Endpoint,
		"endpoint_proxy_only_context_and_endpoint_may_differ")
	var prep endpointProxyPreparation
	raw := bootstrapDarwinPrivatePrerequisite(t, "AMX_DARWIN_ENDPOINT_PREPARATION", "AMX_DARWIN_ENDPOINT_PREPARATION_SHA256")
	endpointProxyRequire(t, protocol.DecodeClosedJSON(raw, &prep, 4096) == nil && prep.SchemaVersion == "1.0.0" && prep.OwnerUID == 501 &&
		prep.SelectedSelectionSHA256 == pin && prep.UpstreamSelectionSHA256 == upstreamPin, "endpoint_proxy_preparation_pin")
	base := filepath.Base(prep.Root)
	endpointProxyRequire(t, filepath.Dir(prep.Root) == "/private/tmp" && strings.HasPrefix(base, "amx-ep-") &&
		len(base) == len("amx-ep-")+16 && fullID.MatchString(strings.TrimPrefix(base, "amx-ep-")+strings.Repeat("0", 48)) &&
		selected.Docker.Context == base &&
		selected.Docker.Endpoint == "unix://"+filepath.Join(prep.Root, "gate", "docker.sock"), "endpoint_proxy_fixed_private_scope")
	p := &endpointProxyFixture{path: filepath.Join(prep.Root, "gate", "docker.sock"), upstream: upstream}
	// Reuse existing native owner/ACL/ancestor admission; no unchecked MkdirAll.
	p.root, err = openPrivateHostRoot(prep.Root, 501, []string{selected.WorkspaceRoot})
	endpointProxyRequire(t, err == nil, "endpoint_proxy_root_admission")
	t.Cleanup(func() {
		if p.root.Close() != nil {
			t.Error("endpoint_proxy_root_close")
		}
	})
	p.gate, err = openPrivateHostRoot(filepath.Join(prep.Root, "gate"), 501, []string{selected.WorkspaceRoot})
	endpointProxyRequire(t, err == nil, "endpoint_proxy_gate_admission")
	t.Cleanup(func() {
		if p.gate.Close() != nil {
			t.Error("endpoint_proxy_gate_close")
		}
	})
	p.rootFD, err = p.root.Open(".")
	endpointProxyRequire(t, err == nil, "endpoint_proxy_root_descriptor")
	t.Cleanup(func() {
		if p.rootFD.Close() != nil {
			t.Error("endpoint_proxy_root_fd_close")
		}
	})
	p.gateFD, err = p.gate.Open(".")
	endpointProxyRequire(t, err == nil, "endpoint_proxy_gate_descriptor")
	t.Cleanup(func() {
		if p.gateFD.Close() != nil {
			t.Error("endpoint_proxy_gate_fd_close")
		}
	})
	p.rootInfo = endpointProxyPinDir(t, p.rootFD, prep.RootDev, prep.RootInode)
	p.gateInfo = endpointProxyPinDir(t, p.gateFD, prep.GateDev, prep.GateInode)
	entries, err := p.gateFD.ReadDir(-1)
	endpointProxyRequire(t, err == nil && len(entries) == 0, "endpoint_proxy_gate_must_be_empty")
	// Actual upstream admission occurs only during explicitly authorized tests.
	driver, err := NewDocker(upstream.dockerConfig())
	endpointProxyRequire(t, err == nil, "endpoint_proxy_upstream_driver")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_, err = driver.Inspect(ctx)
	cancel()
	endpointProxyRequire(t, err == nil, "endpoint_proxy_actual_upstream_not_admitted")
	// One outer cleanup owns ALL listener generations. It is registered before
	// the Docker fixture, so no recovery listener is stopped ahead of engine cleanup.
	t.Cleanup(func() {
		var diagnostics []map[string]any
		for generation, server := range p.servers {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := server.stop(ctx)
			cancel()
			if err != nil {
				endpointProxyRetained.Lock()
				endpointProxyRetained.servers = append(endpointProxyRetained.servers, server)
				endpointProxyRetained.Unlock()
				t.Error("endpoint_proxy_original_owner_or_stream_cleanup_failed")
			}
			if p.evidence != nil {
				stage := "none"
				if err != nil {
					stage = endpointProxyFailureStage(err)
				}
				diagnostics = append(diagnostics, map[string]any{"generation": generation,
					"stage": stage, "snapshot": server.diagnosticSnapshot()})
			}
		}
		// Publishing can call t.Fatal on a filesystem failure. Every original
		// stop and any required retention must happen before that boundary.
		for index, diagnostic := range diagnostics {
			p.evidence.WriteEvidence(t, "endpoint-proxy-final-"+strconv.Itoa(index)+".json", diagnostic)
		}
	})
	p.bind(t)
	return p
}

func (p *endpointProxyFixture) checkDirs(t *testing.T, denied bool) {
	t.Helper()
	for i, item := range []struct {
		file *os.File
		info os.FileInfo
		path string
	}{
		{p.rootFD, p.rootInfo, filepath.Dir(filepath.Dir(p.path))},
		{p.gateFD, p.gateInfo, filepath.Dir(p.path)},
	} {
		current, err := item.file.Stat()
		endpointProxyRequire(t, err == nil && os.SameFile(item.info, current), "endpoint_proxy_held_directory_changed")
		st, ok := current.Sys().(*syscall.Stat_t)
		mode := os.FileMode(0700)
		if i == 1 && denied {
			mode = 0
		}
		endpointProxyRequire(t, ok && st.Uid == 501 && st.Flags == 0 && uint32(st.Mode)&07777 == uint32(mode) &&
			privatefs.CheckDescriptor(item.file, privatefs.PrivateObject) == nil, "endpoint_proxy_directory_access_changed")
		pathInfo, err := os.Lstat(item.path)
		endpointProxyRequire(t, err == nil && os.SameFile(current, pathInfo), "endpoint_proxy_directory_path_changed")
	}
}

func (p *endpointProxyFixture) socketInfo(t *testing.T) unix.Stat_t {
	t.Helper()
	var s unix.Stat_t
	endpointProxyRequire(t, unix.Fstatat(int(p.gateFD.Fd()), "docker.sock", &s, unix.AT_SYMLINK_NOFOLLOW) == nil &&
		s.Mode&unix.S_IFMT == unix.S_IFSOCK && s.Uid == 501 && s.Nlink == 1 && s.Flags == 0, "endpoint_proxy_owned_socket_required")
	return s
}

func endpointProxySameSocket(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode && a.Flags == b.Flags && a.Nlink == b.Nlink
}

func (p *endpointProxyFixture) checkSocket(t *testing.T) {
	t.Helper()
	p.checkDirs(t, p.denied)
	endpointProxyRequire(t, endpointProxySameSocket(p.socket, p.socketInfo(t)), "endpoint_proxy_socket_identity_changed")
}

func (p *endpointProxyFixture) bind(t *testing.T) {
	t.Helper()
	p.checkDirs(t, false)
	var before unix.Stat_t
	endpointProxyRequire(t, errors.Is(unix.Fstatat(int(p.gateFD.Fd()), "docker.sock", &before, unix.AT_SYMLINK_NOFOLLOW), unix.ENOENT), "endpoint_proxy_slot_not_absent")
	server, err := endpointProxyStart(p.path, strings.TrimPrefix(p.upstream.Docker.Endpoint, "unix://"))
	endpointProxyRequire(t, err == nil, "endpoint_proxy_bind_refused")
	p.server = server
	// Register the original owner immediately, before any post-bind assertion.
	p.servers = append(p.servers, server)
	p.socket = p.socketInfo(t)
	p.checkSocket(t)
}

func (p *endpointProxyFixture) quiesce(t *testing.T, f *bootstrapDockerFixture, closeListener bool) {
	t.Helper()
	p.checkSocket(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	var err error
	if closeListener {
		err = p.server.stop(ctx)
	} else {
		err = p.server.pause(ctx)
	}
	cancel()
	if err != nil {
		f.WriteEvidence(t, "endpoint-proxy-quiescence-failure.json", map[string]any{
			"stage": endpointProxyFailureStage(err), "snapshot": p.server.diagnosticSnapshot(),
		})
		f.RetainForRecovery(t)
		t.Fatal("endpoint_proxy_stream_quiescence_failed")
	}
	p.server.mu.Lock()
	accepted := p.server.accepted
	p.server.mu.Unlock()
	f.WriteEvidence(t, "endpoint-proxy-quiesced.json", map[string]any{"accepted": accepted, "active": 0, "originalCopiesJoined": true, "originalAcceptJoined": closeListener})
}

func endpointProxyStopRuntime(t *testing.T, f *bootstrapDockerFixture, x *composeDarwinCLIFront, signal bool, deadline time.Time) {
	t.Helper()
	endpointProxyRequire(t, x.creatorOwned() && x.output.joined && x.output.captured, "endpoint_proxy_runtime_creator_missing")
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if signal && x.lifetime.host.Signal(syscall.SIGTERM) != nil {
		f.RetainForRecovery(t)
		t.Fatal("endpoint_proxy_exact_runtime_stop_refused")
	}
	for _, proof := range append([]*darwinfixtureidentity.Proof{x.lifetime.host}, x.lifetime.roles...) {
		if proof.WaitExit(ctx) != nil {
			f.RetainForRecovery(t)
			t.Fatal("endpoint_proxy_exact_runtime_exit_unconfirmed")
		}
	}
	ids := append([]string{f.Profile.Docker.EngineID, "owner-status-service"}, bootstrapFixtureRoleLeaseIDs(f.Profile.Docker.EngineID)...)
	darwinStartupOwnerLeasesFree(t, f, ctx, ids)
	endpointProxyRequire(t, ctx.Err() == nil, "endpoint_proxy_runtime_shutdown_budget")
}

func endpointProxyNativeErrno(t *testing.T, path string, expected error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", path)
	if connection != nil {
		if connection.Close() != nil {
			t.Error("endpoint_proxy_unexpected_probe_close")
		}
		t.Fatal("endpoint_proxy_stimulus_did_not_refuse")
	}
	endpointProxyRequire(t, errors.Is(err, expected) && ctx.Err() == nil, "endpoint_proxy_actual_native_errno_not_observed")
}

func endpointProxyDiagnostic(raw []byte) bool {
	var d RequestDiagnostic
	return protocol.DecodeClosedJSON(raw, &d, 4096) == nil && ValidRequestDiagnostic(d) && d.Code == "docker_engine_check_failed" && d.Action == "check_selected_engine_access"
}

func endpointProxyScenario(t *testing.T, permission bool) {
	p := endpointProxyPrepare(t)
	f, selection, record := composeDarwinCLIEnrolledFixture(t)
	p.evidence = f
	// Fixture engine cleanup runs before the outer proxy owner cleanup. Restore
	// faulted path access before that cleanup, after every installed owner cleanup.
	t.Cleanup(func() {
		if p.faulted {
			f.RetainForRecovery(t)
		}
		if p.denied {
			p.checkDirs(t, true)
			if p.gateFD.Chmod(0700) != nil {
				t.Error("endpoint_proxy_failed_cleanup_restore")
			} else {
				p.denied = false
			}
		}
	})
	original := darwinScenarioCold(t, f, selection, record, "endpoint-positive")
	stored := darwinScenarioStored(t, f)
	stored.assertPreserved(t, f, "endpoint-positive-preservation.json")
	endpointProxyStopRuntime(t, f, original, true, time.Now().Add(f.Config.Deadlines.StopGrace+f.Config.Deadlines.ReapTimeout))
	p.faulted = true
	p.quiesce(t, f, !permission)
	oldSocket := p.socket
	if permission {
		p.checkSocket(t)
		endpointProxyRequire(t, p.gateFD.Chmod(0) == nil, "endpoint_proxy_permission_stimulus_failed")
		p.denied = true
		p.checkDirs(t, true)
		endpointProxyNativeErrno(t, p.path, syscall.EACCES)
	} else {
		p.checkSocket(t)
		endpointProxyNativeErrno(t, p.path, syscall.ECONNREFUSED)
	}
	negative := composeDarwinCLIStart(t, f, selection, record, "ensure", false)
	raw, success := negative.wait(t, f, "endpoint-negative", darwinScenarioEnsureBudget)
	attempt := ""
	if negative.creatorOwned() {
		attempt = negative.lifetime.attempt
		darwinPortNoFalseReadiness(t, f, negative, record, raw, success, true, attempt, "endpoint-negative")
		endpointProxyStopRuntime(t, f, negative, false, negative.output.started.Add(f.Config.StartupTimeout))
	} else {
		// Source-qualified pre-host path: main.go Probe failure returns before
		// PrepareHost/StartHost unless initialLookupAllowsStart admits its exact
		// connection hint. An actionable authority-wrapped engine-stage failure
		// is not that hint. An absent pin alone NEVER proves a host exited.
		endpointProxyRequire(t, !success && len(raw) == 0 && endpointProxyDiagnostic(negative.stderr.Bytes()), "endpoint_proxy_exact_prehost_stage_diagnostic_required")
		ctx, cancel := context.WithTimeout(context.Background(), darwinScenarioRefusalBudget)
		ids := append([]string{f.Profile.Docker.EngineID, "owner-status-service"}, bootstrapFixtureRoleLeaseIDs(f.Profile.Docker.EngineID)...)
		darwinStartupOwnerLeasesFree(t, f, ctx, ids)
		cancel()
	}
	status := composeDarwinCLIStart(t, f, selection, record, "status", false)
	historyRaw, statusSuccess := status.wait(t, f, "endpoint-negative-status", darwinScenarioRefusalBudget)
	endpointProxyRequire(t, !statusSuccess && !status.creatorOwned(), "endpoint_proxy_status_false_readiness_or_owner")
	if attempt != "" {
		history, code := composeCLIFailureHistoryCode(historyRaw, attempt, time.Now())
		if code == "" {
			endpointProxyRequire(t, history.Diagnostic == requestDiagnostic("docker_engine_check_failed"), "endpoint_proxy_wrong_terminal_stage")
			f.WriteEvidence(t, "endpoint-negative-history.json", history)
		} else {
			endpointProxyRequire(t, len(historyRaw) == 0 && endpointProxyDiagnostic(status.stderr.Bytes()), "endpoint_proxy_specific_stage_diagnostic_missing")
		}
	} else {
		endpointProxyRequire(t, len(historyRaw) == 0 && endpointProxyDiagnostic(status.stderr.Bytes()), "endpoint_proxy_prehost_status_stage_diagnostic_missing")
	}
	endpointProxyRequire(t, bootstrapFixtureRecord(t, f.Config, stored.sequence) == stored.record, "endpoint_proxy_data_lost_during_outage")
	if permission {
		p.checkDirs(t, true)
		endpointProxyRequire(t, p.gateFD.Chmod(0700) == nil, "endpoint_proxy_permission_restore_failed")
		p.denied = false
		p.checkSocket(t)
		endpointProxyRequire(t, p.server.resume() == nil, "endpoint_proxy_permission_resume_failed")
	} else {
		p.checkSocket(t)
		endpointProxyRequire(t, unix.Unlinkat(int(p.gateFD.Fd()), "docker.sock", 0) == nil, "endpoint_proxy_owned_stale_unlink_failed")
		p.bind(t)
		endpointProxyRequire(t, !endpointProxySameSocket(oldSocket, p.socket), "endpoint_proxy_rebind_identity_not_new")
	}
	// Permission retains the original listener/socket. Unavailable replaces
	// only the admitted stale entry and records the distinct new inode.
	p.faulted = false
	f.WriteEvidence(t, "endpoint-proxy-restored.json", p.server.diagnosticSnapshot())
	stored.assertPreserved(t, f, "endpoint-negative-preservation.json")
	f.WriteEvidence(t, "endpoint-proxy-before-recovery.json", p.server.diagnosticSnapshot())
	recovered := composeDarwinCLIStart(t, f, selection, record, "ensure", true)
	darwinScenarioResponse(t, f, recovered, record, "endpoint-recovery", darwinScenarioEnsureBudget, true)
	darwinScenarioReady(t, f, recovered, "endpoint-recovery-ready.json")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	actualEngine, engineErr := f.Driver.Inspect(ctx)
	cancel()
	endpointProxyRequire(t, engineErr == nil && actualEngine.EngineID == p.upstream.Docker.EngineID, "endpoint_proxy_recovery_engine_identity_changed")
	endpointProxyRequire(t, recovered.lifetime.attempt != attempt && recovered.lifetime.attempt != original.lifetime.attempt, "endpoint_proxy_recovery_attempt_reused")
	stored.assertPreserved(t, f, "endpoint-recovered-preservation.json")
	loaded, err := LoadProfile(f.Config.ProfilePolicy)
	endpointProxyRequire(t, err == nil && reflect.DeepEqual(loaded.Declaration(), f.Profile), "endpoint_proxy_enrollment_changed")
	p.checkSocket(t)
	f.WriteEvidence(t, "endpoint-proxy-result.json", map[string]any{
		"permissionStimulus": permission, "specificNativeErrnoObserved": true,
		"installedDiagnostic": "docker_engine_check_failed", "specificDaemonCauseClaimed": false,
		"sameEngineID": f.Profile.Docker.EngineID, "sameBrokerVolumeAndRecord": true,
		"foreignBaselinePreserved": true, "originalNegativeWaitsJoined": true,
		"negativeCreatorProofAvailable": negative.creatorOwned(), "negativeHostExitClaimed": attempt != "",
		"oldSocketInode": oldSocket.Ino, "newSocketInode": p.socket.Ino,
		"noProductEnvironmentChange": true, "phaseAcceptance": false,
	})
}

func TestInstalledCLIDarwinActualSelectedEndpointUnavailablePreservesDataAndRecovers(t *testing.T) {
	endpointProxyScenario(t, false)
}
func TestInstalledCLIDarwinActualSelectedEndpointPermissionPreservesDataAndRecovers(t *testing.T) {
	endpointProxyScenario(t, true)
}
