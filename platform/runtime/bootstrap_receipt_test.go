//go:build linux || darwin

package runtime

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func receiptTestBinding() BootstrapReceiptBinding {
	digest := "sha256:" + strings.Repeat("1", 64)
	return BootstrapReceiptBinding{protocol.Scope{HubID: "receipt_hub", InstanceID: "receipt_instance", ProfileID: "receipt_profile", AssemblyDigest: digest, ReleaseManifestDigest: digest, ReleaseVersion: "1.0.0"}, digest, "attempt_" + strings.Repeat("1", 32), digest}
}
func receiptTestFrame(data []byte) []byte {
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(frame, uint32(len(data)))
	copy(frame[4:], data)
	return frame
}
func receiptTestPipe(t *testing.T) (*ReceiptHostProcess, *os.File) {
	t.Helper()
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal("fixture pipe unavailable")
	}
	p := &ReceiptHostProcess{reader: &bootstrapReceiptReader{file: r, binding: receiptTestBinding()}}
	t.Cleanup(func() {
		w.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if p.CloseBootstrapReceipt(ctx) != nil {
			t.Error("owned receipt reader cleanup failed")
		}
	})
	return p, w
}

func TestBootstrapReceiptClosedFrameAndBinding(t *testing.T) {
	valid, _ := json.Marshal(BootstrapControlReceipt{protocol.Version, "bootstrap-control-receipt", receiptTestBinding(), "accepted"})
	for _, fault := range []string{"positive", "duplicate", "unknown", "null", "wrong_scope", "wrong_enrollment", "wrong_attempt", "wrong_runtime", "outcome", "trailing", "oversize", "truncated"} {
		t.Run(fault, func(t *testing.T) {
			p, w := receiptTestPipe(t)
			data := append([]byte(nil), valid...)
			switch fault {
			case "duplicate":
				data = []byte(strings.Replace(string(data), `"outcome":"accepted"`, `"outcome":"accepted","outcome":"accepted"`, 1))
			case "unknown":
				data = []byte(strings.Replace(string(data), `"outcome":"accepted"`, `"outcome":"accepted","extra":1`, 1))
			case "null":
				data = []byte(strings.Replace(string(data), `"outcome":"accepted"`, `"outcome":null`, 1))
			case "wrong_scope":
				data = []byte(strings.Replace(string(data), "receipt_hub", "other_hub", 1))
			case "wrong_enrollment", "wrong_runtime", "wrong_attempt", "outcome":
				var r BootstrapControlReceipt
				json.Unmarshal(data, &r)
				switch fault {
				case "wrong_enrollment":
					r.Binding.EnrollmentDigest = "sha256:" + strings.Repeat("2", 64)
				case "wrong_runtime":
					r.Binding.RuntimeDigest = "sha256:" + strings.Repeat("2", 64)
				case "wrong_attempt":
					r.Binding.ColdInvocationID = "attempt_" + strings.Repeat("2", 32)
				case "outcome":
					r.Outcome = "ready"
				}
				data, _ = json.Marshal(r)
			}
			frame := receiptTestFrame(data)
			switch fault {
			case "trailing":
				frame = append(frame, 1)
			case "oversize":
				binary.BigEndian.PutUint32(frame, 4093)
			case "truncated":
				frame = frame[:7]
			}
			done := make(chan struct{})
			go func() { defer close(done); w.Write(frame); w.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			r, e := p.BootstrapReceipt(ctx)
			<-done
			if fault == "positive" {
				if e != nil || r.Outcome != "accepted" {
					t.Fatal("valid closed frame refused")
				}
				if _, e = p.BootstrapReceipt(ctx); e == nil {
					t.Fatal("receipt consumed twice")
				}
			} else if e == nil {
				t.Fatal("invalid frame admitted")
			}
		})
	}
}
func TestBootstrapReceiptCancellationJoinsReader(t *testing.T) {
	for _, stage := range []string{"header", "eof"} {
		t.Run(stage, func(t *testing.T) {
			p, w := receiptTestPipe(t)
			owner := &HostProcess{cmd: &exec.Cmd{}, done: make(chan struct{})}
			p.HostProcess, p.reader.originalHost, p.reader.factoryReady = owner, owner, true
			p.reader.originalCmd, p.reader.originalDone = owner.cmd, owner.done
			if stage == "eof" {
				data, _ := json.Marshal(BootstrapControlReceipt{protocol.Version, "bootstrap-control-receipt", receiptTestBinding(), "accepted"})
				if _, e := w.Write(receiptTestFrame(data)); e != nil {
					t.Fatal("fixture write failed")
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			before := time.Now()
			if _, e := p.BootstrapReceipt(ctx); e == nil || time.Since(before) > 200*time.Millisecond {
				t.Fatal("cancellation did not join receipt read")
			}
			if p.HasValidatedBootstrapReceipt(receiptTestBinding()) {
				t.Fatal("canceled read established proof")
			}
			join, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if p.CloseBootstrapReceipt(join) != nil {
				t.Fatal("receipt read retained after cancellation")
			}
		})
	}
}

func TestBootstrapReceiptWriterDescriptorAndEOF(t *testing.T) {
	p, w := receiptTestPipe(t)
	fd, e := unix.Dup(int(w.Fd()))
	if e != nil {
		t.Fatal(e)
	}
	w.Close()
	t.Setenv(bootstrapReceiptFDEnvironment, strconv.Itoa(fd))
	writer, e := OpenBootstrapReceiptWriter(receiptTestBinding())
	if e != nil {
		unix.Close(fd)
		t.Fatal("owned writer refused")
	}
	t.Cleanup(func() {
		if writer.Close() != nil {
			t.Error("owned writer cleanup failed")
		}
	})
	flags, e := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if e != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("receipt inherited by descendants")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if writer.Accepted(ctx) != nil {
		t.Fatal("one control write failed")
	}
	if writer.Accepted(ctx) == nil {
		t.Fatal("writer emitted twice")
	}
	r, e := p.BootstrapReceipt(ctx)
	if e != nil || r.Outcome != "accepted" {
		t.Fatal("writer did not close frame with EOF")
	}
	if writer.Close() != nil {
		t.Fatal("writer close not idempotent")
	}
}
func TestBootstrapReceiptWriterRejectsWrongDescriptor(t *testing.T) {
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	defer w.Close()
	for _, value := range []string{"", "-1", "03", strconv.Itoa(int(r.Fd()))} {
		t.Setenv(bootstrapReceiptFDEnvironment, value)
		if writer, e := OpenBootstrapReceiptWriter(receiptTestBinding()); e == nil || writer != nil {
			t.Fatal("invalid descriptor accepted")
		}
	}
}

func TestBootstrapReceiptRequiresBoundedReadWithoutConsuming(t *testing.T) {
	p, w := receiptTestPipe(t)
	if _, err := p.BootstrapReceipt(context.Background()); err == nil {
		t.Fatal("unbounded receipt read admitted")
	}
	data, _ := json.Marshal(BootstrapControlReceipt{protocol.Version, "bootstrap-control-receipt", receiptTestBinding(), "contended"})
	if _, err := w.Write(receiptTestFrame(data)); err != nil {
		t.Fatal("fixture write failed")
	}
	w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if result, err := p.BootstrapReceipt(ctx); err != nil || result.Outcome != "contended" {
		t.Fatal("bounded read or own contention receipt rejected")
	}
}

// These private-state controls test refusal and read ordering. Only the sealed
// child test proves that the public factory can establish this proof.
func TestBootstrapReceiptValidatedProofRequiresOwnedAcceptedRead(t *testing.T) {
	for _, fault := range []string{"accepted", "synthetic", "unready_factory", "contended", "failed", "malformed", "cleanup_failed"} {
		t.Run(fault, func(t *testing.T) {
			p, w := receiptTestPipe(t)
			owner := &HostProcess{cmd: &exec.Cmd{}, done: make(chan struct{})}
			p.HostProcess = owner
			if fault != "synthetic" {
				p.reader.originalHost = owner
				p.reader.originalCmd, p.reader.originalDone = owner.cmd, owner.done
				p.reader.factoryReady = fault != "unready_factory"
			}
			binding := receiptTestBinding()
			if p.HasValidatedBootstrapReceipt(binding) {
				t.Fatal("unread receipt established proof")
			}
			outcome := "accepted"
			if fault == "contended" || fault == "failed" {
				outcome = fault
			}
			data, _ := json.Marshal(BootstrapControlReceipt{protocol.Version, "bootstrap-control-receipt", binding, outcome})
			if fault == "malformed" {
				data = []byte(`{"outcome":"accepted"}`)
			}
			if _, err := w.Write(receiptTestFrame(data)); err != nil {
				t.Fatal("fixture write failed")
			}
			w.Close()
			if fault == "cleanup_failed" {
				// Existing exact file still closes; the retained cleanup result
				// independently prevents proof. No production injection seam.
				p.reader.closeErr = receiptError("cleanup_failed")
				defer func() { p.reader.closeErr = nil }()
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := p.BootstrapReceipt(ctx)
			if (fault == "malformed" || fault == "cleanup_failed") != (err != nil) {
				t.Fatal("unexpected receipt read result")
			}
			if p.HasValidatedBootstrapReceipt(binding) != (fault == "accepted") {
				t.Fatal("proof did not require exact owned accepted read")
			}
			if fault != "accepted" {
				return
			}
			changed := binding
			changed.ColdInvocationID = "attempt_" + strings.Repeat("2", 32)
			changes := []BootstrapReceiptBinding{changed}
			changed = binding
			changed.EnrollmentDigest = "sha256:" + strings.Repeat("2", 64)
			changes = append(changes, changed)
			changed = binding
			changed.RuntimeDigest = "sha256:" + strings.Repeat("2", 64)
			changes = append(changes, changed)
			for _, field := range []string{"hub", "instance", "profile", "assembly", "manifest", "version"} {
				changed = binding
				switch field {
				case "hub":
					changed.Scope.HubID = "other_hub"
				case "instance":
					changed.Scope.InstanceID = "other_instance"
				case "profile":
					changed.Scope.ProfileID = "other_profile"
				case "assembly":
					changed.Scope.AssemblyDigest = "sha256:" + strings.Repeat("2", 64)
				case "manifest":
					changed.Scope.ReleaseManifestDigest = "sha256:" + strings.Repeat("2", 64)
				case "version":
					changed.Scope.ReleaseVersion = "2.0.0"
				}
				changes = append(changes, changed)
			}
			for _, changed := range changes {
				if p.HasValidatedBootstrapReceipt(changed) {
					t.Fatal("different full binding admitted")
				}
			}
			copy := *p
			copy.HostProcess = &HostProcess{}
			if copy.HasValidatedBootstrapReceipt(binding) {
				t.Fatal("replacement child inherited proof")
			}
			copy.HostProcess = nil
			if copy.HasValidatedBootstrapReceipt(binding) {
				t.Fatal("missing child inherited proof")
			}
			if p.CloseBootstrapReceipt(ctx) != nil || !p.HasValidatedBootstrapReceipt(binding) {
				t.Fatal("normal joined close erased accepted proof")
			}
		})
	}
	var empty ReceiptHostProcess
	if empty.HasValidatedBootstrapReceipt(receiptTestBinding()) || (*ReceiptHostProcess)(nil).HasValidatedBootstrapReceipt(receiptTestBinding()) {
		t.Fatal("zero process established proof")
	}
}

func TestBootstrapReceiptValidatedProofWaitsForEOFAndJoin(t *testing.T) {
	p, w := receiptTestPipe(t)
	owner := &HostProcess{cmd: &exec.Cmd{}, done: make(chan struct{})}
	p.HostProcess, p.reader.originalHost, p.reader.factoryReady = owner, owner, true
	p.reader.originalCmd, p.reader.originalDone = owner.cmd, owner.done
	binding := receiptTestBinding()
	data, _ := json.Marshal(BootstrapControlReceipt{protocol.Version, "bootstrap-control-receipt", binding, "accepted"})
	if _, err := w.Write(receiptTestFrame(data)); err != nil {
		t.Fatal("fixture write failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	joined := make(chan error, 1)
	go func() { _, err := p.BootstrapReceipt(ctx); joined <- err }()
	if p.HasValidatedBootstrapReceipt(binding) {
		t.Fatal("frame without EOF established proof")
	}
	w.Close()
	if err := <-joined; err != nil || !p.HasValidatedBootstrapReceipt(binding) {
		t.Fatal("joined accepted read did not establish proof")
	}
}

func TestBootstrapReceiptValidatedProofRequiresCompletionSignal(t *testing.T) {
	p, _ := receiptTestPipe(t)
	owner := &HostProcess{cmd: &exec.Cmd{}, done: make(chan struct{})}
	p.HostProcess, p.reader.originalHost, p.reader.factoryReady = owner, owner, true
	p.reader.originalCmd, p.reader.originalDone = owner.cmd, owner.done
	binding := receiptTestBinding()
	// Reproduce the narrow final-defer interval: the joined cleanup has stored
	// its accepted result, but the read-completion signal has not closed yet.
	p.reader.validated = BootstrapControlReceipt{protocol.Version, "bootstrap-control-receipt", binding, "accepted"}
	p.reader.done = make(chan struct{})
	if p.HasValidatedBootstrapReceipt(binding) {
		close(p.reader.done)
		t.Fatal("proof escaped before the completion signal")
	}
	close(p.reader.done)
	if !p.HasValidatedBootstrapReceipt(binding) {
		t.Fatal("completed private-state control refused")
	}
}

func TestBootstrapReceiptValidatedProofRejectsInPlaceChildIdentity(t *testing.T) {
	for _, fault := range []string{"zero", "transplant", "command", "completion"} {
		t.Run(fault, func(t *testing.T) {
			p, w := receiptTestPipe(t)
			owner := &HostProcess{cmd: &exec.Cmd{}, done: make(chan struct{})}
			p.HostProcess, p.reader.originalHost, p.reader.factoryReady = owner, owner, true
			p.reader.originalCmd, p.reader.originalDone = owner.cmd, owner.done
			binding := receiptTestBinding()
			data, _ := json.Marshal(BootstrapControlReceipt{protocol.Version, "bootstrap-control-receipt", binding, "accepted"})
			if _, err := w.Write(receiptTestFrame(data)); err != nil {
				t.Fatal("fixture write failed")
			}
			w.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := p.BootstrapReceipt(ctx); err != nil || !p.HasValidatedBootstrapReceipt(binding) {
				t.Fatal("initial private accepted control refused")
			}
			command, completion := owner.cmd, owner.done
			// Change identity fields sequentially, without copying the mutex or
			// touching a real running child's wait/lifetime state.
			switch fault {
			case "zero":
				owner.cmd, owner.done = nil, nil
			case "transplant":
				owner.cmd, owner.done = &exec.Cmd{}, make(chan struct{})
			case "command":
				owner.cmd = &exec.Cmd{}
			case "completion":
				owner.done = make(chan struct{})
			}
			admitted := p.HasValidatedBootstrapReceipt(binding)
			owner.cmd, owner.done = command, completion
			if admitted {
				t.Fatal("same child pointer admitted changed child identity")
			}
			if !p.HasValidatedBootstrapReceipt(binding) {
				t.Fatal("restored exact identity refused")
			}
		})
	}
}
