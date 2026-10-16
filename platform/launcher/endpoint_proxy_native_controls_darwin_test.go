//go:build darwin && arm64 && cgo && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"net"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// No listener is constructed and no network or engine operation runs here.
func TestEndpointProxyPurePauseResumeState(t *testing.T) {
	p := &endpointProxyServer{done: make(chan struct{}), sessions: make(map[*endpointProxySession]struct{})}
	if p.resume() == nil {
		t.Fatal("unpaused owner resumed")
	}
	if p.pause(context.Background()) != nil || !p.paused || p.resume() != nil || p.paused {
		t.Fatal("empty joined pause/resume refused")
	}
	p.failed = true
	if p.pause(context.Background()) == nil || p.resume() == nil {
		t.Fatal("failed streams admitted")
	}
	p.failed = false
	p.paused = true
	close(p.done)
	if p.resume() == nil {
		t.Fatal("joined listener resumed")
	}
}

func TestEndpointProxyPurePauseRequiresOriginalSessionJoin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	session := &endpointProxySession{done: make(chan struct{}), cancel: func() {}}
	p := &endpointProxyServer{done: make(chan struct{}), active: 1, sessions: map[*endpointProxySession]struct{}{session: {}}}
	if p.pause(ctx) == nil || !p.paused || p.resume() == nil {
		t.Fatal("unjoined original stream admitted")
	}
}

func TestEndpointProxyPureSocketIdentityIsExact(t *testing.T) {
	base := unix.Stat_t{Dev: 7, Ino: 9, Uid: 501, Gid: 20, Mode: unix.S_IFSOCK | 0700, Nlink: 1}
	if !endpointProxySameSocket(base, base) {
		t.Fatal("same identity refused")
	}
	for _, change := range []func(*unix.Stat_t){
		func(s *unix.Stat_t) { s.Dev++ }, func(s *unix.Stat_t) { s.Ino++ },
		func(s *unix.Stat_t) { s.Uid++ }, func(s *unix.Stat_t) { s.Gid++ },
		func(s *unix.Stat_t) { s.Mode++ }, func(s *unix.Stat_t) { s.Flags++ }, func(s *unix.Stat_t) { s.Nlink++ },
	} {
		other := base
		change(&other)
		if endpointProxySameSocket(base, other) {
			t.Fatal("changed endpoint identity admitted")
		}
	}
}

func TestEndpointProxyPureNativeErrnoProjectionIsClosed(t *testing.T) {
	wrapped := &net.OpError{Err: &os.SyscallError{Err: syscall.ENOTCONN}}
	if endpointProxyErrno(wrapped) != int(syscall.ENOTCONN) {
		t.Fatal("native errno lost through standard wrappers")
	}
	cycle := &net.OpError{}
	cycle.Err = cycle
	for _, err := range []error{fail57HostileError{}, syscall.Errno(4096), (*net.OpError)(nil), (*os.SyscallError)(nil), cycle} {
		if endpointProxyErrno(err) != 0 {
			t.Fatal("unqualified errno escaped closed projection")
		}
	}
}

func TestEndpointProxyPureStateStageIsClosed(t *testing.T) {
	if endpointProxyFailureStage(endpointProxyStateFailure("endpoint_proxy_stream_pause_failed")) != "endpoint_proxy_stream_pause_failed" ||
		endpointProxyFailureStage(fail57HostileError{}) != "endpoint_proxy_state_unknown" ||
		endpointProxyStateFailure("private untrusted text").Error() != "endpoint_proxy_state_unknown" {
		t.Fatal("state diagnostic leaked arbitrary text or lost fixed stage")
	}
}

func TestEndpointProxyPureDisconnectedWrapperIsExact(t *testing.T) {
	owned := &endpointProxyOwnedConn{UnixConn: &net.UnixConn{}}
	good := func() *net.OpError {
		return &net.OpError{Op: "close", Net: "unix", Err: &os.SyscallError{Syscall: "shutdown", Err: syscall.ENOTCONN}}
	}
	if !endpointProxyDisconnectedAfterEOF(owned, good()) {
		t.Fatal("exact native shutdown wrapper refused")
	}
	for _, mutate := range []func(*net.OpError){
		func(e *net.OpError) { e.Op = "write" },
		func(e *net.OpError) { e.Net = "tcp" },
		func(e *net.OpError) { e.Err = syscall.ENOTCONN },
		func(e *net.OpError) { e.Err.(*os.SyscallError).Syscall = "write" },
		func(e *net.OpError) { e.Err.(*os.SyscallError).Err = syscall.EPIPE },
		func(e *net.OpError) { e.Err.(*os.SyscallError).Err = syscall.EINVAL },
		func(e *net.OpError) { e.Err = net.ErrClosed },
	} {
		bad := good()
		mutate(bad)
		if endpointProxyDisconnectedAfterEOF(owned, bad) {
			t.Fatal("other failure acquired native exception")
		}
	}
	if endpointProxyDisconnectedAfterEOF(&endpointMemoryStream{}, good()) || endpointProxyDisconnectedAfterEOF(owned, fail57HostileError{}) {
		t.Fatal("unqualified stream or error wrapper admitted")
	}
}

func TestEndpointProxyPureSnapshotSeparatesJoinedAndPublished(t *testing.T) {
	live := &endpointProxySession{done: make(chan struct{})}
	joined := &endpointProxySession{done: make(chan struct{})}
	close(joined.done)
	p := &endpointProxyServer{done: make(chan struct{}), active: 1, accepted: 2,
		sessions: map[*endpointProxySession]struct{}{live: {}, joined: {}},
		results:  []endpointProxyStreamResult{{ForwardBytes: 5, Joined: true}}}
	value := p.diagnosticSnapshot()
	if value["sessionsRegistered"] != 2 || value["sessionsJoined"] != 1 || value["listenerJoined"] != false || value["active"] != 1 {
		t.Fatal("snapshot inferred joins from published results")
	}
	value["publishedResults"].([]endpointProxyStreamResult)[0].ForwardBytes = 99
	if p.results[0].ForwardBytes != 5 {
		t.Fatal("snapshot exposed mutable result backing storage")
	}
	close(live.done)
	close(p.done)
	value = p.diagnosticSnapshot()
	if value["sessionsJoined"] != 2 || value["listenerJoined"] != true {
		t.Fatal("snapshot lost exact closed-channel observations")
	}
}
