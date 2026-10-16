//go:build darwin && cgo && agentmux_bootstrap_docker

// Package darwinfixtureidentity supports installed Darwin fixture tests only.
// Its opaque handles cannot adopt a caller's PID or serialized process token.
package darwinfixtureidentity

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"time"

	protected "github.com/controlLogix/agentmux/platform/runtime"
	"golang.org/x/sys/unix"
)

var ErrExited = errors.New("fixture_process_exited")

// failure keeps private causes available to errors.Is/As without exposing paths,
// arguments, environment values or native error text in diagnostics.
type failure struct {
	stage    string
	cause    error
	retained any
}

func (e *failure) Error() string             { return e.stage }
func (e *failure) Unwrap() error             { return e.cause }
func failed(stage string, cause error) error { return &failure{stage: stage, cause: cause} }

// Creator is tied to this process's admitted native identity.
type Creator struct {
	self      identity
	admission admissionCheck
}

// Only this package can supply admission. No serialized value or public mode
// flag can select a diagnostic ABI.
type admissionCheck interface{ check() error }
type normalAdmission struct{}

func (normalAdmission) check() error { _, _, err := nativeAdmission(); return err }

func NewCreator() (*Creator, error) { return newCreator(normalAdmission{}) }
func newCreator(admission admissionCheck) (*Creator, error) {
	if admission == nil {
		return nil, failed("fixture_native_admission_refused", nil)
	}
	if err := admission.check(); err != nil {
		return nil, failed("fixture_native_admission_refused", err)
	}
	if os.Getuid() == 0 || os.Getuid() != os.Geteuid() {
		return nil, failed("fixture_creator_credentials_refused", nil)
	}
	for _, item := range os.Environ() {
		if strings.HasPrefix(item, "DYLD_") {
			return nil, failed("fixture_loader_environment_refused", nil)
		}
	}
	id, err := observe(os.Getpid())
	if err != nil || id.UID != uint32(os.Geteuid()) || id.RealUID != uint32(os.Getuid()) {
		return nil, failed("fixture_creator_identity_refused", err)
	}
	return &Creator{self: id, admission: admission}, nil
}

// expectedImage describes an immutable protected image and its literal arguments.
// Args excludes argv[0]. Only verified runtime roles use a fixed role alias.
// Native executable paths remain independently bound to Path.
type expectedImage struct {
	assembly     *assemblyOwner
	host         *ExpectedHost
	Path, Digest string
	argv0        string
	Args         []string
}
type Launch struct {
	Path, Digest string
	Args, Env    []string
	Dir          string
	ExtraFiles   []*os.File
}

type capture struct {
	mu       sync.Mutex
	bytes    []byte
	overflow bool
}

func (c *capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	available := 64*1024 - len(c.bytes)
	n := len(p)
	if n > available {
		n = available
		c.overflow = true
	}
	c.bytes = append(c.bytes, p[:n]...)
	// Always drain both streams after the capture limit is reached.
	return len(p), nil
}

type Output struct {
	Bytes    []byte
	Overflow bool
	Err      error
}

func (c *capture) snapshot() Output {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Output{Bytes: append([]byte(nil), c.bytes...), Overflow: c.overflow}
}

type Completion struct {
	Err            error
	At             time.Time
	Stdout, Stderr Output
}

// Owned retains the original child and is its sole Wait owner.
type Owned struct{ *ownedState }
type ownedState struct {
	admissionErr        error
	cleanupIdentity     *identity
	mu                  sync.Mutex
	creator             *Creator
	cmd                 *exec.Cmd
	expected            expectedImage
	image               *protected.InstalledHostImage
	proof               *Proof
	started             time.Time
	done                chan struct{}
	completion          Completion
	waiting             bool
	imageCloseAttempted bool
	proofCloseAttempted bool
	cleanup             error
	out, errout         capture
}

// StartProtected returns Owned after a successful protected launch. Completion
// proves only that original command outcome. Call Pin explicitly when host
// lineage authority is required; a fast exit can prevent full proof admission.
func (c *Creator) StartProtected(ctx context.Context, launch Launch) (*Owned, error) {
	if c == nil || c.admission == nil {
		return nil, failed("fixture_creator_invalid", nil)
	}
	if ctx == nil {
		return nil, failed("fixture_context_invalid", nil)
	}
	if err := ctx.Err(); err != nil {
		return nil, failed("fixture_start_cancelled", err)
	}
	now, err := observe(os.Getpid())
	if err != nil || !sameIdentity(c.self, now) {
		return nil, failed("fixture_creator_changed", err)
	}
	for _, item := range launch.Env {
		if strings.HasPrefix(item, "DYLD_") {
			return nil, failed("fixture_loader_environment_refused", nil)
		}
	}
	image, err := protected.PrepareProtectedInstalledHost(ctx, launch.Path, launch.Digest, 128*1024*1024)
	if err != nil {
		return nil, failed("fixture_protected_image_refused", err)
	}
	x := &Owned{ownedState: &ownedState{creator: c, image: image, expected: expectedImage{Path: launch.Path, Digest: launch.Digest, Args: append([]string(nil), launch.Args...)}, done: make(chan struct{})}}
	x.cmd = exec.Command(launch.Path, launch.Args...)
	x.cmd.Env = append([]string{}, launch.Env...)
	x.cmd.Dir = launch.Dir
	x.cmd.ExtraFiles = append([]*os.File(nil), launch.ExtraFiles...)
	x.cmd.Stdout = &x.out
	x.cmd.Stderr = &x.errout
	x.cmd.WaitDelay = time.Second
	fresh, err := protected.PrepareProtectedInstalledHost(ctx, launch.Path, launch.Digest, 128*1024*1024)
	if err != nil {
		return nil, errors.Join(failed("fixture_prestart_image_refused", err), safeClose(image, "fixture_image_close_failed"))
	}
	if err = safeClose(fresh, "fixture_prestart_image_close_failed"); err != nil {
		return nil, errors.Join(err, safeClose(image, "fixture_image_close_failed"))
	}
	if err = x.cmd.Start(); err != nil {
		return nil, errors.Join(failed("fixture_start_failed", err), safeClose(image, "fixture_image_close_failed"))
	}
	x.started = time.Now()
	child, identityErr := observe(x.cmd.Process.Pid)
	creator, creatorErr := observe(os.Getpid())
	if identityErr != nil || creatorErr != nil || !sameIdentity(c.self, creator) || child.PID != int32(x.cmd.Process.Pid) || child.ParentUnique != c.self.Unique || child.ParentPID != c.self.PID || child.UID != c.self.UID || child.RealUID != c.self.RealUID {
		x.admissionErr = failed("fixture_cleanup_identity_unavailable", errors.Join(identityErr, creatorErr))
		x.startWait()
		return x, nil
	}
	x.cleanupIdentity = &child
	// Bind minimal cleanup authority while the original child is unreaped,
	// then attempt full image, argv and watch admission. Neither authority
	// accepts a PID from its caller.
	if _, err = x.Pin(ctx); err != nil {
		x.admissionErr = err
		x.startWait()
		return x, nil
	}
	x.startWait()
	return x, nil
}
func (x *Owned) StartedAt() time.Time {
	if x == nil || x.ownedState == nil {
		return time.Time{}
	}
	return x.started
}
func (x *Owned) startWait() {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.waiting {
		return
	}
	x.waiting = true
	go func() {
		err := x.cmd.Wait()
		var public error
		if err != nil {
			public = failed("fixture_child_wait_failed", err)
		}
		result := Completion{public, time.Now(), x.out.snapshot(), x.errout.snapshot()}
		if errors.Is(err, exec.ErrWaitDelay) {
			result.Stdout.Err = failed("fixture_output_join_incomplete", exec.ErrWaitDelay)
			result.Stderr.Err = failed("fixture_output_join_incomplete", exec.ErrWaitDelay)
		}
		x.mu.Lock()
		x.completion = result
		x.mu.Unlock()
		close(x.done)
	}()
}
func (x *Owned) Join(ctx context.Context) (Completion, error) {
	if ctx == nil {
		return Completion{}, failed("fixture_context_invalid", nil)
	}
	if x == nil || x.ownedState == nil || x.cmd == nil || x.done == nil {
		return Completion{}, failed("fixture_owned_invalid", nil)
	}
	x.startWait()
	select {
	case <-ctx.Done():
		return Completion{}, failed("fixture_join_incomplete", ctx.Err())
	case <-x.done:
		x.mu.Lock()
		defer x.mu.Unlock()
		value := x.completion
		value.Stdout.Bytes = append([]byte(nil), value.Stdout.Bytes...)
		value.Stderr.Bytes = append([]byte(nil), value.Stderr.Bytes...)
		return value, nil
	}
}
func safeClose(c io.Closer, stage string) error {
	if err := c.Close(); err != nil {
		return &failure{stage: stage, cause: err, retained: c}
	}
	return nil
}

// Identity stability excludes current PPID: reparenting changes current PPID,
// but it does not change the native creation-parent unique identity.
func sameIdentity(a, b identity) bool {
	return a.PID == b.PID && a.Version == b.Version && a.Unique == b.Unique && a.ParentUnique == b.ParentUnique && a.UID == b.UID && a.RealUID == b.RealUID
}

// Proof holds a version-bound process identity, immutable image descriptor and
// exact process event watch. Its zero value grants no authority.
type Proof struct{ *proofState }
type proofState struct {
	admission  admissionCheck
	assembly   *assemblyOwner
	watchOwned bool
	image      *protected.InstalledHostImage
	cleanup    error

	mu                    sync.Mutex
	id                    identity
	queue                 int
	valid, exited, closed bool
	expected              expectedImage
}

func (x *Owned) Pin(ctx context.Context) (*Proof, error) {
	if x == nil || x.ownedState == nil {
		return nil, failed("fixture_owned_invalid", nil)
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.proof != nil {
		return x.proof, nil
	}
	if x.admissionErr != nil {
		return nil, x.admissionErr
	}
	if x.cmd == nil || x.cmd.Process == nil || x.waiting || x.creator == nil {
		return nil, failed("fixture_pin_state_invalid", nil)
	}
	if ctx == nil {
		return nil, failed("fixture_context_invalid", nil)
	}
	if err := ctx.Err(); err != nil {
		return nil, failed("fixture_pin_cancelled", err)
	}
	before, err := observe(x.cmd.Process.Pid)
	if err != nil || before.ParentPID != x.creator.self.PID || before.ParentUnique != x.creator.self.Unique || before.UID != x.creator.self.UID || before.RealUID != x.creator.self.RealUID {
		return nil, failed("fixture_child_lineage_refused", err)
	}
	path, err := nativePath(before)
	if err != nil || path != x.expected.Path {
		return nil, failed("fixture_child_path_refused", err)
	}
	args, err := nativeArguments(before)
	if err != nil || !reflect.DeepEqual(args, append([]string{x.expected.Path}, x.expected.Args...)) {
		return nil, failed("fixture_child_arguments_refused", err)
	}
	queue, err := unix.Kqueue()
	if err != nil {
		return nil, failed("fixture_watch_unavailable", err)
	}
	unix.CloseOnExec(queue)
	p := &Proof{proofState: &proofState{id: before, queue: queue, watchOwned: true, expected: x.expected, admission: x.creator.admission}}
	change := []unix.Kevent_t{{Ident: uint64(before.PID), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT | unix.NOTE_EXEC}}
	zero := unix.Timespec{}
	var events [1]unix.Kevent_t
	n, err := unix.Kevent(queue, change, events[:], &zero)
	if err == nil && n == 0 {
		after, e := observe(int(before.PID))
		creator, ce := observe(os.Getpid())
		if e != nil || ce != nil || !sameIdentity(before, after) || !sameIdentity(x.creator.self, creator) {
			err = failed("fixture_identity_changed", errors.Join(e, ce))
		}
	} else {
		err = failed("fixture_watch_registration_refused", err)
	}
	if err == nil {
		n, err = unix.Kevent(queue, nil, events[:], &zero)
		if n != 0 {
			err = failed("fixture_admission_event_refused", err)
		}
	}
	if err != nil {
		closeErr := p.close()
		x.cleanup = errors.Join(x.cleanup, closeErr)
		return nil, errors.Join(failed("fixture_pin_refused", err), closeErr)
	}
	pathAfter, pathErr := nativePath(before)
	argsAfter, argsErr := nativeArguments(before)
	if pathErr != nil || argsErr != nil || pathAfter != x.expected.Path || !reflect.DeepEqual(args, argsAfter) {
		closeErr := p.close()
		x.cleanup = errors.Join(x.cleanup, closeErr)
		return nil, errors.Join(failed("fixture_postwatch_image_arguments_refused", errors.Join(pathErr, argsErr)), closeErr)
	}
	fresh, imageErr := protected.PrepareProtectedInstalledHost(ctx, x.expected.Path, x.expected.Digest, 128*1024*1024)
	if imageErr != nil {
		closeErr := p.close()
		x.cleanup = errors.Join(x.cleanup, closeErr)
		return nil, errors.Join(failed("fixture_postwatch_image_refused", imageErr), closeErr)
	}
	if closeErr := safeClose(fresh, "fixture_postwatch_image_close_failed"); closeErr != nil {
		x.cleanup = errors.Join(x.cleanup, closeErr, p.close())
		return nil, x.cleanup
	}
	final, finalErr := observe(int(before.PID))
	if finalErr != nil || !sameIdentity(before, final) {
		return nil, errors.Join(failed("fixture_final_identity_refused", finalErr), p.close())
	}
	p.valid = true
	x.proof = p
	return p, nil
}
func (p *Proof) event() error {
	if p == nil || p.proofState == nil || p.closed || !p.valid {
		return failed("fixture_proof_invalid", nil)
	}
	if p.exited {
		return ErrExited
	}
	zero := unix.Timespec{}
	var events [1]unix.Kevent_t
	n, err := pollWatch(func() (int, error) { return unix.Kevent(p.queue, nil, events[:], &zero) })
	if err != nil {
		p.valid = false
		return failed("fixture_watch_failed", err)
	}
	if n != 0 {
		e := events[0]
		if e.Ident == uint64(p.id.PID) && e.Filter == unix.EVFILT_PROC && e.Flags&unix.EV_ERROR == 0 && e.Fflags&unix.NOTE_EXIT != 0 && e.Fflags&unix.NOTE_EXEC == 0 {
			p.exited = true
			return ErrExited
		}
		p.valid = false
		return failed("fixture_unexpected_process_event", nil)
	}
	return nil
}
func (p *Proof) Live() error {
	if p == nil || p.proofState == nil {
		return failed("fixture_proof_invalid", nil)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.live()
}
func (p *Proof) live() error {
	if err := p.event(); err != nil {
		return err
	}
	id, err := observe(int(p.id.PID))
	if err != nil || !sameIdentity(p.id, id) {
		p.valid = false
		return failed("fixture_observation_failed", err)
	}
	return nil
}
func (p *Proof) Signal(signal syscall.Signal) error {
	if signal != syscall.SIGTERM && signal != syscall.SIGKILL {
		return failed("fixture_signal_refused", nil)
	}
	if p == nil || p.proofState == nil {
		return failed("fixture_proof_invalid", nil)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.live(); err != nil {
		return err
	}
	if err := identitySignal(p.id, int(signal)); err != nil {
		return failed("fixture_signal_failed", err)
	}
	return nil
}
func (p *Proof) WaitExit(ctx context.Context) error {
	if ctx == nil {
		return failed("fixture_context_invalid", nil)
	}
	if p == nil || p.proofState == nil {
		return failed("fixture_proof_invalid", nil)
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		p.mu.Lock()
		err := p.event()
		p.mu.Unlock()
		if errors.Is(err, ErrExited) {
			return nil
		}
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return failed("fixture_exit_wait_incomplete", ctx.Err())
		case <-ticker.C:
		}
	}
}
func (p *Proof) LiteralArgs() []string {
	if p == nil || p.proofState == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.valid || p.closed {
		return nil
	}
	return p.expected.literalArguments()
}

func (p *Proof) close() error {
	if p == nil || p.proofState == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return p.cleanup
	}
	p.closed = true
	p.valid = false
	if !p.watchOwned {
		return p.cleanup
	}
	if err := unix.Close(p.queue); err != nil {
		p.cleanup = &failure{stage: "fixture_watch_close_failed", cause: err, retained: p}
	}
	if p.assembly != nil {
		p.cleanup = errors.Join(p.cleanup, p.assembly.release())
	}
	if p.image != nil {
		image := p.image
		p.cleanup = errors.Join(p.cleanup, safeClose(image, "fixture_child_image_close_failed"))
	}
	return p.cleanup
}

// Close releases authority only after the original child has been joined. It
// never guesses a PID or sends an unbound cleanup signal.
func (x *Owned) Close() error {
	if x == nil || x.ownedState == nil {
		return nil
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	select {
	case <-x.done:
	default:
		return errors.Join(x.cleanup, failed("fixture_close_requires_join", nil))
	}
	if x.proof != nil && !x.proofCloseAttempted {
		x.proofCloseAttempted = true
		x.cleanup = errors.Join(x.cleanup, x.proof.close())
	}
	if x.image != nil && !x.imageCloseAttempted {
		x.imageCloseAttempted = true
		image := x.image
		x.cleanup = errors.Join(x.cleanup, safeClose(image, "fixture_image_close_failed"))
	}
	return x.cleanup
}

// Signal permits only cleanup of this creator's original spawned child. It
// does not grant full proof, descendant discovery or status authority.
func (x *Owned) Signal(signal syscall.Signal) error {
	if x == nil || x.ownedState == nil {
		return failed("fixture_owned_invalid", nil)
	}
	if signal != syscall.SIGTERM && signal != syscall.SIGKILL {
		return failed("fixture_signal_refused", nil)
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.cleanupIdentity == nil {
		return failed("fixture_cleanup_identity_unavailable", nil)
	}
	select {
	case <-x.done:
		return ErrExited
	default:
	}
	now, err := observe(int(x.cleanupIdentity.PID))
	if err != nil || !sameIdentity(*x.cleanupIdentity, now) || now.ParentUnique != x.creator.self.Unique {
		return failed("fixture_cleanup_identity_changed", err)
	}
	if err := identitySignal(*x.cleanupIdentity, int(signal)); err != nil {
		return failed("fixture_cleanup_signal_failed", err)
	}
	return nil
}

// A zero-time observation may be interrupted, but retries never extend into
// an unbounded wait or turn an interrupted read into an exit observation.
func pollWatch(read func() (int, error)) (n int, err error) {
	for attempt := 0; attempt < 3; attempt++ {
		n, err = read()
		if !errors.Is(err, unix.EINTR) {
			return n, err
		}
	}
	return 0, err
}
