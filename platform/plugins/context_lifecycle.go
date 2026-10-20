package plugins

import "sync"

// ContextLifecycleSource belongs to one original native instance. Only the
// driver advances readiness and drain; a plugin reports its own health through
// this scoped service. Reporting health never changes another owner's state.
type ContextLifecycleSource interface {
	Snapshot() ContextLifecycleSnapshot
	DrainDone() <-chan struct{}
	ReportHealth(string) error
}

// Only the native driver can release this readiness notification. Plugin
// health reports cannot start background work before native readiness.
type nativeContextReadySource interface {
	nativeReadyDone() <-chan struct{}
}

type ContextLifecycleSnapshot struct {
	Owner  OwnerReference `json:"owner"`
	State  string         `json:"state"`
	Ready  bool           `json:"ready"`
	Health string         `json:"health"`
}

type nativeContextLifecycle struct {
	mu        sync.Mutex
	owner     OwnerReference
	state     string
	health    string
	drain     chan struct{}
	ready     chan struct{}
	readyOnce sync.Once
}

func newNativeContextLifecycle(owner OwnerReference) *nativeContextLifecycle {
	return &nativeContextLifecycle{owner: owner, state: "starting", health: "unknown", drain: make(chan struct{}), ready: make(chan struct{})}
}

func (s *nativeContextLifecycle) Snapshot() ContextLifecycleSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ContextLifecycleSnapshot{Owner: s.owner, State: s.state, Ready: s.state == "ready" && s.health != "unhealthy", Health: s.health}
}
func (s *nativeContextLifecycle) DrainDone() <-chan struct{}       { return s.drain }
func (s *nativeContextLifecycle) nativeReadyDone() <-chan struct{} { return s.ready }
func (s *nativeContextLifecycle) ReportHealth(health string) error {
	if health != "healthy" && health != "unhealthy" {
		return pluginError("context_health_invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == "draining" || s.state == "stopped" {
		return pluginError("context_owner_stale")
	}
	s.health = health
	return nil
}
func (s *nativeContextLifecycle) markReady() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != "starting" && s.state != "ready" {
		return false
	}
	s.state = "ready"
	if s.health == "unhealthy" {
		return false
	}
	s.readyOnce.Do(func() { close(s.ready) })
	return true
}
func (s *nativeContextLifecycle) beginDrain() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == "draining" || s.state == "stopped" {
		return
	}
	s.state = "draining"
	close(s.drain)
}
func (s *nativeContextLifecycle) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != "draining" && s.state != "stopped" {
		close(s.drain)
	}
	s.state = "stopped"
}
