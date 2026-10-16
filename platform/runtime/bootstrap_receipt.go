//go:build linux || darwin

package runtime

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"golang.org/x/sys/unix"
)

const bootstrapReceiptFDEnvironment = "AGENTMUX_BOOTSTRAP_RECEIPT_FD"

// The length header is part of the four-KiB frame bound.
const bootstrapReceiptLimit = 4096 - 4

// BootstrapReceiptBinding is correlation with the separately admitted host.
// It grants no broker, kernel, application or process authority.
type BootstrapReceiptBinding struct {
	Scope protocol.Scope `json:"scope"`
	// Native Go control encoding v1: SHA256 of encoding/json.Marshal on the
	// exact typed launcher.OwnerEnrollment schema1.0.0 in declaration order.
	// This is neither a cross-language canonical form nor a signature.
	EnrollmentDigest string `json:"enrollmentDigest"`
	ColdInvocationID string `json:"coldInvocationId"`
	RuntimeDigest    string `json:"runtimeDigest"`
}

// BootstrapReceiptRequested reports descriptor plumbing only. It neither
// validates the descriptor nor establishes admitted bootstrap ownership.
func BootstrapReceiptRequested() bool { return os.Getenv(bootstrapReceiptFDEnvironment) != "" }

// BootstrapControlReceipt is one lifecycle control frame, never an L04 status.
// Accepted means the owning operation has actually entered admitted startup.
type BootstrapControlReceipt struct {
	SchemaVersion string                  `json:"schemaVersion"`
	Kind          string                  `json:"kind"`
	Binding       BootstrapReceiptBinding `json:"binding"`
	Outcome       string                  `json:"outcome"`
}

var receiptIdentifier = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,95}$`)
var receiptVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
var receiptAttempt = regexp.MustCompile(`^attempt_[0-9a-f]{32}$`)

func receiptError(code string) error { return errors.New("bootstrap_receipt_" + code) }
func boundedReceiptContext(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil || ctx.Done() == nil {
		return false
	}
	deadline, ok := ctx.Deadline()
	return ok && deadline.After(time.Now())
}
func (b BootstrapReceiptBinding) valid() bool {
	s := b.Scope
	return receiptIdentifier.MatchString(s.HubID) && receiptIdentifier.MatchString(s.InstanceID) && receiptIdentifier.MatchString(s.ProfileID) && installedHostDigest.MatchString(s.AssemblyDigest) && installedHostDigest.MatchString(s.ReleaseManifestDigest) && len(s.ReleaseVersion) <= 96 && receiptVersion.MatchString(s.ReleaseVersion) && installedHostDigest.MatchString(b.EnrollmentDigest) && installedHostDigest.MatchString(b.RuntimeDigest) && receiptAttempt.MatchString(b.ColdInvocationID)
}
func (r BootstrapControlReceipt) valid(b BootstrapReceiptBinding) bool {
	return b.valid() && r.SchemaVersion == protocol.Version && r.Kind == "bootstrap-control-receipt" && r.Binding == b && (r.Outcome == "accepted" || r.Outcome == "contended" || r.Outcome == "failed")
}

type bootstrapReceiptPipe struct {
	reader, writer *os.File
	binding        BootstrapReceiptBinding
}

// ReceiptHostProcess adds only an owned receipt descriptor to the exact child.
// Its inherited HostProcess retains the original single Wait and detached life.
type ReceiptHostProcess struct {
	*HostProcess
	reader *bootstrapReceiptReader
}
type bootstrapReceiptReader struct {
	file         *os.File
	binding      BootstrapReceiptBinding
	originalHost *HostProcess
	originalCmd  *exec.Cmd
	originalDone chan struct{}
	factoryReady bool
	validated    BootstrapControlReceipt
	mu           sync.Mutex
	used, closed bool
	done         chan struct{}
	closeOnce    sync.Once
	closeErr     error
}

// StartHostWithBootstrapReceipt has no PID lookup or existing-owner rendezvous.
// A failed post-spawn cleanup returns the exact child as well as the error.
func (h *InstalledHostImage) StartHostWithBootstrapReceipt(ctx context.Context, invocation HostInvocation, binding BootstrapReceiptBinding) (*ReceiptHostProcess, error) {
	if !binding.valid() || binding.ColdInvocationID != invocation.InvocationID {
		return nil, receiptError("binding_invalid")
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, receiptError("pipe_unavailable")
	}
	pipe := &bootstrapReceiptPipe{reader: r, writer: w, binding: binding}
	child, err := h.startHost(ctx, invocation, pipe)
	if err != nil {
		return nil, closeReceiptBeforeStart(r, w, err)
	}
	p := &ReceiptHostProcess{HostProcess: child, reader: &bootstrapReceiptReader{file: r, binding: binding, originalHost: child, originalCmd: child.cmd, originalDone: child.done}}
	if w.Close() != nil {
		return p, receiptError("cleanup_failed")
	}
	p.reader.factoryReady = true
	return p, nil
}

// HasValidatedBootstrapReceipt proves only that this factory-created child
// supplied an accepted receipt with this exact binding. It is available after
// the sole read, EOF, descriptor close and cancellation hook have joined.
// It says nothing about current child lifetime, readiness or startup success.
func (p *ReceiptHostProcess) HasValidatedBootstrapReceipt(expected BootstrapReceiptBinding) bool {
	if p == nil || p.reader == nil || !expected.valid() {
		return false
	}
	r := p.reader
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.factoryReady || r.originalHost == nil || p.HostProcess != r.originalHost || r.originalCmd == nil || r.originalDone == nil || p.HostProcess.cmd != r.originalCmd || p.HostProcess.done != r.originalDone || r.done == nil {
		return false
	}
	select {
	case <-r.done:
		return r.validated.Outcome == "accepted" && r.validated.valid(expected)
	default:
		return false
	}
}

func (r *bootstrapReceiptReader) closeFile() {
	r.closeOnce.Do(func() {
		if r.file.Close() != nil {
			r.closeErr = receiptError("cleanup_failed")
		}
	})
}

// BootstrapReceipt reads exactly one closed frame and requires writer EOF.
// Cancellation closes and joins only receipt I/O, never the child process.
func (p *ReceiptHostProcess) BootstrapReceipt(ctx context.Context) (result BootstrapControlReceipt, failure error) {
	empty := BootstrapControlReceipt{}
	if p == nil || p.reader == nil || !boundedReceiptContext(ctx) {
		return empty, receiptError("context_invalid")
	}
	r := p.reader
	r.mu.Lock()
	if r.used || r.closed {
		r.mu.Unlock()
		return empty, receiptError("consumed")
	}
	r.used = true
	r.done = make(chan struct{})
	done := r.done
	r.mu.Unlock()
	defer close(done)
	hookDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(hookDone); r.closeFile() })
	defer func() {
		r.closeFile()
		if !stop() {
			<-hookDone
		}
		if r.closeErr != nil {
			result = empty
			failure = errors.Join(failure, r.closeErr)
		}
		r.mu.Lock()
		if failure == nil && ctx.Err() == nil && !r.closed && result.Outcome == "accepted" && result.valid(r.binding) {
			r.validated = result
		}
		r.mu.Unlock()
	}()
	var header [4]byte
	if _, err := io.ReadFull(r.file, header[:]); err != nil {
		return empty, receiptError("frame_invalid")
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > bootstrapReceiptLimit {
		return empty, receiptError("frame_invalid")
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r.file, data); err != nil {
		return empty, receiptError("frame_invalid")
	}
	var trailing [1]byte
	if n, err := r.file.Read(trailing[:]); n != 0 || err != io.EOF {
		return empty, receiptError("frame_invalid")
	}
	var receipt BootstrapControlReceipt
	if ctx.Err() != nil || protocol.DecodeClosedJSON(data, &receipt, bootstrapReceiptLimit) != nil || !receipt.valid(r.binding) {
		return empty, receiptError("frame_invalid")
	}
	return receipt, nil
}

func (p *ReceiptHostProcess) CloseBootstrapReceipt(ctx context.Context) error {
	if p == nil || p.reader == nil {
		return nil
	}
	if ctx == nil {
		return receiptError("context_invalid")
	}
	r := p.reader
	r.mu.Lock()
	r.closed = true
	done := r.done
	r.mu.Unlock()
	r.closeFile()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return receiptError("cleanup_failed")
		}
	}
	return r.closeErr
}

// BootstrapReceiptWriter can open only the inherited private write descriptor.
// The host must call Accepted only from its actual admitted enter capability.
type BootstrapReceiptWriter struct {
	file      *os.File
	binding   BootstrapReceiptBinding
	mu        sync.Mutex
	used      bool
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func OpenBootstrapReceiptWriter(binding BootstrapReceiptBinding) (*BootstrapReceiptWriter, error) {
	value := os.Getenv(bootstrapReceiptFDEnvironment)
	fd, err := strconv.Atoi(value)
	if !binding.valid() || err != nil || fd < 3 || fd > 1024 || strconv.Itoa(fd) != value {
		return nil, receiptError("descriptor_invalid")
	}
	var info unix.Stat_t
	flags, flagErr := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if unix.Fstat(fd, &info) != nil || flagErr != nil || info.Uid != uint32(os.Geteuid()) || !bootstrapReceiptPipeMetadataValid(info) || !bootstrapReceiptDescriptorValid(fd, &info, flags) {
		return nil, receiptError("descriptor_invalid")
	}
	fdFlags, fdErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if fdErr != nil {
		return nil, receiptError("descriptor_invalid")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, fdFlags|unix.FD_CLOEXEC); err != nil {
		return nil, receiptError("descriptor_invalid")
	}
	if unix.SetNonblock(fd, true) != nil {
		return nil, receiptError("descriptor_invalid")
	}
	file := os.NewFile(uintptr(fd), "bootstrap-control-receipt")
	return &BootstrapReceiptWriter{file: file, binding: binding}, nil
}

func (w *BootstrapReceiptWriter) Accepted(ctx context.Context) error { return w.emit(ctx, "accepted") }
func (w *BootstrapReceiptWriter) Contended(ctx context.Context) error {
	return w.emit(ctx, "contended")
}
func (w *BootstrapReceiptWriter) Failed(ctx context.Context) error { return w.emit(ctx, "failed") }
func (w *BootstrapReceiptWriter) closeFile() {
	w.closeOnce.Do(func() {
		if w.file.Close() != nil {
			w.closeErr = receiptError("cleanup_failed")
		}
	})
}
func (w *BootstrapReceiptWriter) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	w.used = true
	done := w.done
	w.mu.Unlock()
	w.closeFile()
	if done != nil {
		<-done
	}
	return w.closeErr
}
func (w *BootstrapReceiptWriter) emit(ctx context.Context, outcome string) (failure error) {
	if w == nil || !boundedReceiptContext(ctx) {
		return receiptError("context_invalid")
	}
	w.mu.Lock()
	if w.used {
		w.mu.Unlock()
		return receiptError("consumed")
	}
	w.used = true
	w.done = make(chan struct{})
	done := w.done
	w.mu.Unlock()
	defer close(done)
	defer func() {
		w.closeFile()
		if w.closeErr != nil {
			failure = errors.Join(failure, w.closeErr)
		}
	}()
	hookDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(hookDone); w.closeFile() })
	defer func() {
		if !stop() {
			<-hookDone
		}
	}()
	data, err := json.Marshal(BootstrapControlReceipt{protocol.Version, "bootstrap-control-receipt", w.binding, outcome})
	if err != nil || len(data) > bootstrapReceiptLimit {
		return receiptError("frame_invalid")
	}
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(data)))
	copy(frame[4:], data)
	if n, err := w.file.Write(frame); err != nil || n != len(frame) {
		return receiptError("write_failed")
	}
	return nil
}

// These are the two concrete pipe files created by this factory. Close
// consumes each handle even on error; retain causes, never retry raw FDs.
func closeReceiptBeforeStart(reader, writer *os.File, startup error) error {
	readErr := reader.Close()
	writeErr := writer.Close()
	if readErr == nil && writeErr == nil {
		return startup
	}
	return &receiptPrestartCleanupCause{cause: errors.Join(startup, readErr, writeErr)}
}

type receiptPrestartCleanupCause struct{ cause error }

func (receiptPrestartCleanupCause) Error() string                  { return "bootstrap_receipt_cleanup_failed" }
func (e receiptPrestartCleanupCause) Format(s fmt.State, _ rune)   { fmt.Fprint(s, e.Error()) }
func (e receiptPrestartCleanupCause) MarshalJSON() ([]byte, error) { return json.Marshal(e.Error()) }
func (e receiptPrestartCleanupCause) Unwrap() error                { return e.cause }
