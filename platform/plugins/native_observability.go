package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/controlLogix/agentmux/platform/privatefs"
	"golang.org/x/sys/unix"
)

// NativeObservabilityOptions declares local diagnostics, not durable audit.
// The host admits the destination directory and opens an existing private file
// for append. This owner never discovers, creates, rotates or deletes a path.
type NativeObservabilityOptions struct {
	HubID                              string
	Bindings                           map[string]PackagePin
	EventCodes, SpanCodes, MetricCodes []string
	MaxBytes                           int64
}

type nativeObservation struct {
	SchemaVersion string      `json:"schemaVersion"`
	Kind          string      `json:"kind"`
	RecordedAt    string      `json:"recordedAt"`
	Tags          ContextTags `json:"tags"`
	Code          string      `json:"code"`
	SpanHandle    string      `json:"spanHandle,omitempty"`
	Action        string      `json:"action,omitempty"`
	OutcomeCode   string      `json:"outcomeCode,omitempty"`
	Value         *float64    `json:"value,omitempty"`
}
type nativeObservationWrite struct {
	ctx    context.Context
	raw    []byte
	result chan error
}

// NativeObservability owns a duplicate of the admitted descriptor and one
// writer. Its queue holds at most 64 records of 8192 bytes each. A successful
// call means the complete diagnostic reached the file, not an audit commit.
// Close cancels queued work and joins the original writer before closing its fd.
// An unfinished or failed Close must retain this same owner.
type NativeObservability struct {
	mu              sync.Mutex
	options         NativeObservabilityOptions
	file            *os.File
	jobs            chan nativeObservationWrite
	done            chan struct{}
	lifetime        context.Context
	cancel          context.CancelFunc
	closing, closed bool
	failure         error
}

func (*NativeObservability) Format(s fmt.State, _ rune) {
	io.WriteString(s, "[private native observability owner]")
}
func (*NativeObservability) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-native-observability-owner"}`), nil
}

func NewNativeObservability(ctx context.Context, file *os.File, options NativeObservabilityOptions) (*NativeObservability, error) {
	fail := pluginError("context_observability_unavailable")
	if ctx == nil || ctx.Err() != nil || file == nil || !registryIdentifier.MatchString(options.HubID) || len(options.Bindings) == 0 || len(options.Bindings) > 64 || options.MaxBytes < 65536 || options.MaxBytes > 64<<20 || !contextCodesValid(options.EventCodes) || !contextCodesValid(options.SpanCodes) || !contextCodesValid(options.MetricCodes) {
		return nil, fail
	}
	bindings := make(map[string]PackagePin, len(options.Bindings))
	for instance, pin := range options.Bindings {
		if !registryIdentifier.MatchString(instance) || !configurationPin(pin) {
			return nil, fail
		}
		bindings[instance] = pin
	}
	options.Bindings = bindings
	options.EventCodes = append([]string(nil), options.EventCodes...)
	options.SpanCodes = append([]string(nil), options.SpanCodes...)
	options.MetricCodes = append([]string(nil), options.MetricCodes...)
	raw, err := file.SyscallConn()
	if err != nil {
		return nil, fail
	}
	fd := -1
	controlErr := raw.Control(func(original uintptr) { fd, err = unix.FcntlInt(original, unix.F_DUPFD_CLOEXEC, 0) })
	if fd < 0 {
		return nil, fail
	}
	lifetime, cancel := context.WithCancel(context.Background())
	r := &NativeObservability{options: options, file: os.NewFile(uintptr(fd), "native-observability"), jobs: make(chan nativeObservationWrite, 64), done: make(chan struct{}), lifetime: lifetime, cancel: cancel}
	if controlErr != nil || err != nil || r.checkFile(0) != nil || ctx.Err() != nil {
		r.failure = fail
		close(r.done)
		return r, fail
	}
	go r.run()
	return r, nil
}
func (r *NativeObservability) checkFile(add int64) error {
	info, err := r.file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 0 || info.Size() > r.options.MaxBytes-add {
		return pluginError("context_observability_unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || privatefs.CheckDescriptor(r.file, privatefs.PrivateObject) != nil {
		return pluginError("context_observability_unavailable")
	}
	raw, err := r.file.SyscallConn()
	if err != nil {
		return pluginError("context_observability_unavailable")
	}
	flags := 0
	if raw.Control(func(fd uintptr) { flags, err = unix.FcntlInt(fd, unix.F_GETFL, 0) }) != nil || err != nil || flags&unix.O_APPEND == 0 || flags&unix.O_ACCMODE == unix.O_RDONLY {
		return pluginError("context_observability_unavailable")
	}
	return nil
}
func (r *NativeObservability) run() {
	defer close(r.done)
	for job := range r.jobs {
		if job.ctx.Err() != nil || r.lifetime.Err() != nil {
			job.result <- pluginError("context_observability_unavailable")
			continue
		}
		r.mu.Lock()
		failure := r.failure
		r.mu.Unlock()
		if failure == nil {
			failure = r.checkFile(int64(len(job.raw)))
		}
		if failure == nil {
			n, err := r.file.Write(job.raw)
			if err != nil || n != len(job.raw) {
				failure = pluginError("context_observability_unavailable")
			}
		}
		if failure != nil {
			r.mu.Lock()
			r.failure = failure
			r.mu.Unlock()
		}
		job.result <- failure
	}
}
func (r *NativeObservability) record(ctx context.Context, observation nativeObservation) error {
	fail := pluginError("context_observability_unavailable")
	if r == nil || ctx == nil || ctx.Err() != nil || !contextOwnerValid(observation.Tags.Owner) || observation.Tags.HubID != r.options.HubID || r.options.Bindings[observation.Tags.Owner.InstanceID] != observation.Tags.Owner.Pin {
		return fail
	}
	observation.SchemaVersion = "1.0.0"
	observation.RecordedAt = time.Now().UTC().Format(time.RFC3339Nano)
	raw, err := json.Marshal(observation)
	if err != nil || len(raw) > 8191 {
		return fail
	}
	raw = append(raw, '\n')
	job := nativeObservationWrite{ctx: ctx, raw: raw, result: make(chan error, 1)}
	r.mu.Lock()
	if r.closing || r.failure != nil {
		r.mu.Unlock()
		return fail
	}
	select {
	case r.jobs <- job:
	default:
		r.mu.Unlock()
		return fail
	}
	r.mu.Unlock()
	select {
	case err := <-job.result:
		return err
	case <-ctx.Done():
		return fail
	case <-r.lifetime.Done():
		return fail
	}
}
func (r *NativeObservability) Log(ctx context.Context, record ContextLogRecord) error {
	if r == nil || !slices.Contains(r.options.EventCodes, record.EventCode) {
		return pluginError("context_observability_unavailable")
	}
	return r.record(ctx, nativeObservation{Kind: "log", Tags: record.Tags, Code: record.EventCode})
}
func (r *NativeObservability) Trace(ctx context.Context, record ContextTraceRecord) error {
	if r == nil || !slices.Contains(r.options.SpanCodes, record.SpanCode) || !strings.HasPrefix(record.SpanHandle, "span_") || !registryEpoch.MatchString(strings.TrimPrefix(record.SpanHandle, "span_")) || (record.Action != "start" && record.Action != "finish") || (record.Action == "start" && record.OutcomeCode != "") || (record.Action == "finish" && !slices.Contains([]string{"completed", "failed", "canceled"}, record.OutcomeCode)) {
		return pluginError("context_observability_unavailable")
	}
	return r.record(ctx, nativeObservation{Kind: "trace", Tags: record.Tags, Code: record.SpanCode, SpanHandle: record.SpanHandle, Action: record.Action, OutcomeCode: record.OutcomeCode})
}
func (r *NativeObservability) Metric(ctx context.Context, record ContextMetricRecord) error {
	if r == nil || !slices.Contains(r.options.MetricCodes, record.MetricCode) || math.IsNaN(record.Value) || math.IsInf(record.Value, 0) || math.Abs(record.Value) > 1e12 {
		return pluginError("context_observability_unavailable")
	}
	return r.record(ctx, nativeObservation{Kind: "metric", Tags: record.Tags, Code: record.MetricCode, Value: &record.Value})
}
func (r *NativeObservability) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if ctx == nil {
		return pluginError("context_observability_unavailable")
	}
	r.mu.Lock()
	if !r.closing {
		r.closing = true
		r.cancel()
		close(r.jobs)
	}
	r.mu.Unlock()
	select {
	case <-r.done:
	case <-ctx.Done():
		return pluginError("context_observability_cleanup_incomplete")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		if err := r.file.Close(); err != nil {
			r.failure = pluginError("context_observability_cleanup_incomplete")
		}
		r.closed = true
	}
	return r.failure
}

// CleanupComplete reports whether the original writer and descriptor have joined.
func (r *NativeObservability) CleanupComplete() bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed && completed(r.done)
}
