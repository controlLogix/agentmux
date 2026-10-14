//go:build darwin && cgo

// This standalone test probe is not imported by the product. Its controls use
// disposable probe children, not Agentmux CLI or broker qualification.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	protected "github.com/controlLogix/agentmux/platform/runtime"
	"golang.org/x/sys/unix"
)

var imagePin = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var nonceShape = regexp.MustCompile(`^[a-f0-9]{32}$`)

type controlResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Limit  string `json:"limit,omitempty"`
}

type report struct {
	Kind                string          `json:"kind"`
	Status              string          `json:"status"`
	OS                  string          `json:"os"`
	Architecture        string          `json:"architecture"`
	SDK                 int64           `json:"sdk"`
	Controls            []controlResult `json:"controls"`
	CleanupVerified     bool            `json:"cleanupVerified"`
	CLIQualified        bool            `json:"installedCLIQualified"`
	NativeQualification bool            `json:"nativeQualification"`
	Failure             string          `json:"failure,omitempty"`
}

// No constructor accepts a caller-supplied PID, token or registry identifier.
// A proof can be minted only for a child started by this retained creator.
type processProof struct {
	identity identity
	queue    int
	invalid  bool
}

type ownedControl struct {
	cmd             *exec.Cmd
	gate            *os.File
	done            chan error
	proof           *processProof
	joined          bool
	waitStarted     bool
	inheritedReader *os.File
	setupFailure    error
	cleanupFailure  error
	self            string
	pin             string
	nonce           string
	image           *protected.InstalledHostImage
}

func sameIdentity(a, b identity) bool {
	return a.PID == b.PID && a.ParentPID == b.ParentPID && a.Version == b.Version &&
		a.UID == b.UID && a.RealUID == b.RealUID && a.Unique == b.Unique && a.ParentUnique == b.ParentUnique
}

func newControl(self, pin string) (*ownedControl, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	image, err := protected.PrepareProtectedInstalledHost(ctx, self, pin, 128*1024*1024)
	if err != nil {
		return nil, errors.New("protected_probe_image_refused")
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		image.Close()
		return nil, errors.New("owned_control_pipe_unavailable")
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		reader.Close()
		writer.Close()
		image.Close()
		return nil, errors.New("owned_control_nonce_unavailable")
	}
	x := &ownedControl{gate: writer, done: make(chan error, 1), self: self, pin: pin,
		nonce: hex.EncodeToString(nonce[:]), image: image}
	x.cmd = exec.Command(self, "--probe-child", x.nonce)
	x.cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	x.cmd.ExtraFiles = []*os.File{reader}
	x.cmd.WaitDelay = time.Second
	if err = x.cmd.Start(); err != nil {
		reader.Close()
		writer.Close()
		image.Close()
		return nil, errors.New("owned_control_start_failed")
	}
	if reader.Close() != nil {
		x.inheritedReader = reader
		x.setupFailure = errors.New("owned_control_inherited_reader_close_failed")
		x.cleanupFailure = x.setupFailure
	}
	// Do not reap the direct child until all signal decisions have finished.
	// Even unexpected exit must leave its PID reserved as our unreaped child
	// throughout the deliberately wrong-version native control.
	return x, nil
}

func (x *ownedControl) pinChild() (failure error) {
	if x.proof != nil || x.cmd.Process == nil {
		return errors.New("owned_control_pin_state_invalid")
	}
	creator, err := observe(os.Getpid())
	if err != nil || creator.UID != uint32(os.Geteuid()) || creator.RealUID != uint32(os.Getuid()) {
		return errors.New("native_creator_identity_unavailable")
	}
	child, err := observe(x.cmd.Process.Pid)
	if err != nil || child.ParentPID != creator.PID || child.ParentUnique != creator.Unique ||
		child.UID != creator.UID || child.RealUID != creator.RealUID {
		return errors.New("native_child_lineage_refused")
	}
	path, err := nativePath(child)
	if err != nil || path != x.self {
		return errors.New("native_child_image_path_refused")
	}
	args, err := nativeArguments(child)
	if err != nil || !reflect.DeepEqual(args, x.cmd.Args) {
		return errors.New("native_child_arguments_refused")
	}
	// Native path lookup is not a running-vnode descriptor. Admission relies on
	// immutable active root-owned releases and the product's held image checks.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	fresh, err := protected.PrepareProtectedInstalledHost(ctx, path, x.pin, 128*1024*1024)
	cancel()
	if err != nil {
		return errors.New("native_child_protected_image_refused")
	}
	defer func() {
		if fresh.Close() != nil {
			closeFailure := errors.New("native_child_fresh_image_close_failed")
			x.cleanupFailure = errors.Join(x.cleanupFailure, closeFailure)
			failure = errors.Join(failure, closeFailure)
		}
	}()
	queue, err := unix.Kqueue()
	if err != nil {
		return errors.New("native_child_watch_unavailable")
	}
	keep := false
	defer func() {
		if !keep {
			if unix.Close(queue) != nil {
				closeFailure := errors.New("native_child_failed_admission_watch_close_failed")
				x.cleanupFailure = errors.Join(x.cleanupFailure, closeFailure)
				failure = errors.Join(failure, closeFailure)
			}
		}
	}()
	change := []unix.Kevent_t{{Ident: uint64(child.PID), Filter: unix.EVFILT_PROC,
		Flags: unix.EV_ADD | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT | unix.NOTE_EXEC}}
	zero := unix.Timespec{}
	var events [1]unix.Kevent_t
	if n, err := unix.Kevent(queue, change, events[:], &zero); err != nil || n != 0 {
		return errors.New("native_child_watch_registration_refused")
	}
	after, err := observe(int(child.PID))
	creatorAfter, creatorErr := observe(os.Getpid())
	if err != nil || creatorErr != nil || !sameIdentity(child, after) || !sameIdentity(creator, creatorAfter) {
		return errors.New("native_child_admission_identity_changed")
	}
	if n, err := unix.Kevent(queue, nil, events[:], &zero); err != nil || n != 0 {
		return errors.New("native_child_admission_event_refused")
	}
	x.proof = &processProof{identity: child, queue: queue}
	keep = true
	return nil
}

func (p *processProof) live() error {
	if p == nil || p.queue < 0 || p.invalid {
		return errors.New("native_proof_not_live")
	}
	var events [1]unix.Kevent_t
	zero := unix.Timespec{}
	if n, err := unix.Kevent(p.queue, nil, events[:], &zero); err != nil || n != 0 {
		p.invalid = true
		return errors.New("native_proof_event_or_exit")
	}
	fresh, err := observe(int(p.identity.PID))
	if err != nil || !sameIdentity(p.identity, fresh) {
		return errors.New("native_proof_identity_changed")
	}
	return nil
}

func (p *processProof) signal(signal unix.Signal) error {
	if signal != unix.SIGTERM && signal != unix.SIGKILL {
		return errors.New("native_proof_signal_not_allowed")
	}
	if err := p.live(); err != nil {
		return err
	}
	// The kernel checks this same PID/version while holding its process reference.
	// A signal failure never refreshes identity or falls back to kill(pid).
	return identitySignal(p.identity, int(signal))
}

func (p *processProof) observeExit(deadline time.Time) error {
	if p == nil || p.queue < 0 || p.invalid || time.Until(deadline) <= 0 {
		return errors.New("native_exit_watch_state_invalid")
	}
	var events [1]unix.Kevent_t
	wait := unix.NsecToTimespec(int64(time.Until(deadline)))
	n, err := unix.Kevent(p.queue, nil, events[:], &wait)
	p.invalid = true
	if err != nil || n != 1 || events[0].Ident != uint64(p.identity.PID) ||
		events[0].Filter != unix.EVFILT_PROC || events[0].Flags&unix.EV_ERROR != 0 ||
		events[0].Fflags&unix.NOTE_EXIT == 0 || events[0].Fflags&unix.NOTE_EXEC != 0 {
		return errors.New("native_exact_exit_not_observed")
	}
	return nil
}

func (x *ownedControl) join(deadline time.Time, expectedSignal unix.Signal) error {
	remaining := time.Until(deadline)
	if remaining <= 0 || x.joined {
		return errors.New("owned_control_join_state_invalid")
	}
	if !x.waitStarted {
		x.waitStarted = true
		go func() { x.done <- x.cmd.Wait() }()
	}
	select {
	case err := <-x.done:
		x.joined = true
		if expectedSignal != 0 {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				return errors.New("owned_control_signal_exit_missing")
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.Signal(expectedSignal) {
				return errors.New("owned_control_signal_exit_differs")
			}
			if err := x.proof.observeExit(deadline); err != nil {
				return err
			}
		} else if err != nil {
			return errors.New("owned_control_cooperative_exit_failed")
		}
		return nil
	case <-time.After(remaining):
		return errors.New("owned_control_join_deadline")
	}
}

func (x *ownedControl) close() error {
	// Even admission failure has a creator-owned, bounded EOF cleanup path.
	// It is a probe-child control, not proof of actual Agentmux host shutdown.
	failure := x.cleanupFailure
	if x.inheritedReader != nil {
		if x.inheritedReader.Close() != nil {
			failure = errors.Join(failure, errors.New("owned_control_reader_cleanup_unverified"))
		}
		x.inheritedReader = nil
	}
	if x.gate != nil {
		if err := x.gate.Close(); err != nil {
			failure = errors.New("owned_control_gate_close_failed")
		}
		x.gate = nil
	}
	if !x.joined {
		failure = errors.Join(failure, x.join(time.Now().Add(2*time.Second), 0))
	}
	if x.proof != nil && x.proof.queue >= 0 {
		if unix.Close(x.proof.queue) != nil {
			failure = errors.Join(failure, errors.New("owned_control_watch_close_failed"))
		}
		x.proof.queue = -1
	}
	if x.image.Close() != nil {
		failure = errors.Join(failure, errors.New("owned_control_image_close_failed"))
	}
	return failure
}

func childMode(mode, nonce string) int {
	if !nonceShape.MatchString(nonce) {
		return 2
	}
	gate := os.NewFile(3, "owned-probe-gate")
	if gate == nil {
		return 2
	}
	defer gate.Close()
	info, err := gate.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		return 2
	}
	input := make(chan byte, 1)
	go func() {
		var raw [1]byte
		if _, err := io.ReadFull(gate, raw[:]); err == nil {
			input <- raw[0]
		} else {
			input <- 0
		}
	}()
	select {
	case command := <-input:
		if command == 0 {
			return 0
		}
		if command == 'E' && mode == "--probe-child" {
			self, err := os.Executable()
			if err != nil {
				return 3
			}
			flags, err := unix.FcntlInt(gate.Fd(), unix.F_GETFD, 0)
			if err != nil {
				return 3
			}
			if _, err := unix.FcntlInt(gate.Fd(), unix.F_SETFD, flags&^unix.FD_CLOEXEC); err != nil {
				return 3
			}
			if unix.Exec(self, []string{self, "--probe-after-exec", nonce}, []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}) != nil {
				return 3
			}
		}
		return 4
	case <-time.After(15 * time.Second):
		return 5
	}
}

func runControl(self, pin, name string) (failure error, cleanupVerified bool) {
	x, err := newControl(self, pin)
	if err != nil {
		return err, false
	}
	defer func() {
		cleanup := x.close()
		cleanupVerified = cleanup == nil
		failure = errors.Join(failure, cleanup)
	}()
	if x.setupFailure != nil {
		return x.setupFailure, false
	}
	if err = x.pinChild(); err != nil {
		return err, false
	}
	if err = x.proof.live(); err != nil {
		return err, false
	}
	switch name {
	case "owned-sigterm", "owned-sigkill":
		signal := unix.SIGTERM
		if name == "owned-sigkill" {
			signal = unix.SIGKILL
		}
		if err = x.proof.signal(signal); err != nil {
			return errors.New("owned_identity_signal_failed"), false
		}
		return x.join(time.Now().Add(2*time.Second), signal), false
	case "signal-zero-refused":
		if !errors.Is(identitySignal(x.proof.identity, 0), unix.EINVAL) {
			return errors.New("signal_zero_not_refused"), false
		}
		return x.proof.live(), false
	case "stale-version-refused":
		stale := x.proof.identity
		stale.Version ^= 1
		if !errors.Is(identitySignal(stale, int(unix.SIGTERM)), unix.ESRCH) {
			return errors.New("stale_version_not_refused"), false
		}
		return x.proof.live(), false
	case "exec-version-refused":
		if _, err = x.gate.Write([]byte{'E'}); err != nil {
			return errors.New("owned_exec_gate_failed"), false
		}
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			fresh, err := observe(int(x.proof.identity.PID))
			if err == nil && fresh.Version != x.proof.identity.Version {
				// Read-only observation of the successor cannot rebind the proof.
				if fresh.PID != x.proof.identity.PID || fresh.UID != x.proof.identity.UID ||
					fresh.RealUID != x.proof.identity.RealUID || fresh.Unique != x.proof.identity.Unique ||
					fresh.ParentPID != x.proof.identity.ParentPID || fresh.ParentUnique != x.proof.identity.ParentUnique {
					return errors.New("owned_exec_successor_not_observed"), false
				}
				path, pathErr := nativePath(fresh)
				args, argsErr := nativeArguments(fresh)
				if pathErr != nil || argsErr != nil || path != x.self ||
					!reflect.DeepEqual(args, []string{x.self, "--probe-after-exec", x.nonce}) {
					return errors.New("owned_exec_successor_image_or_arguments_refused"), false
				}
				if !errors.Is(identitySignal(x.proof.identity, int(unix.SIGTERM)), unix.ESRCH) {
					return errors.New("pre_exec_identifier_not_refused"), false
				}
				if x.proof.live() == nil {
					return errors.New("registry_rebound_after_exec"), false
				}
				after, err := observe(int(fresh.PID))
				if err != nil || after.Version != fresh.Version || after.Unique != fresh.Unique {
					return errors.New("exec_refusal_did_not_preserve_successor"), false
				}
				return nil, false
			}
			time.Sleep(time.Millisecond)
		}
		return errors.New("owned_exec_version_change_missing"), false
	default:
		return errors.New("unknown_probe_control"), false
	}
}

func run() (report, int) {
	r := report{Kind: "darwin-identity-probe", Status: "refused", Controls: []controlResult{}}
	if len(os.Args) != 3 || os.Args[1] != "--run-controls" || !imagePin.MatchString(os.Args[2]) || os.Geteuid() == 0 || os.Getuid() != os.Geteuid() {
		r.Failure = "ordinary_user_and_independent_protected_image_pin_required"
		return r, 2
	}
	for _, item := range os.Environ() {
		if strings.HasPrefix(item, "DYLD_") || strings.HasPrefix(item, "LD_") {
			r.Failure = "loader_override_refused"
			return r, 2
		}
	}
	version, sdk, err := nativeAdmission()
	if err != nil {
		r.Failure = "native_api_os_sdk_admission_failed"
		return r, 2
	}
	r.OS, r.SDK, r.Architecture = version, sdk, runtime.GOARCH
	if r.Architecture != "arm64" && r.Architecture != "amd64" {
		r.Failure = "native_architecture_refused"
		return r, 2
	}
	self, err := os.Executable()
	if err != nil || !filepath.IsAbs(self) || filepath.Clean(self) != self {
		r.Failure = "probe_path_invalid"
		return r, 2
	}
	r.CleanupVerified = true
	for _, name := range []string{"owned-sigterm", "owned-sigkill", "signal-zero-refused", "stale-version-refused", "exec-version-refused"} {
		err, cleaned := runControl(self, os.Args[2], name)
		r.CleanupVerified = r.CleanupVerified && cleaned
		if err != nil {
			r.Controls = append(r.Controls, controlResult{name, "failed", "Fixed safe failure; inspect source-bound native diagnostics separately."})
			r.Failure = "native_control_or_owned_cleanup_failed"
			return r, 1
		}
		r.Controls = append(r.Controls, controlResult{name, "passed", "Disposable probe child only; not the installed CLI."})
	}
	r.Controls = append(r.Controls, controlResult{"actual-pid-reuse-refusal", "unexecuted", "No PID reuse was forced or observed. Version-mismatch and exec controls do not replace actual reuse evidence."})
	r.Status = "component-controls-only"
	return r, 0
}

func main() {
	if len(os.Args) == 3 && (os.Args[1] == "--probe-child" || os.Args[1] == "--probe-after-exec") {
		os.Exit(childMode(os.Args[1], os.Args[2]))
	}
	r, code := run()
	if json.NewEncoder(os.Stdout).Encode(r) != nil {
		os.Exit(2)
	}
	os.Exit(code)
}
