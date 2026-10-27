//go:build darwin

package appruntime

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"golang.org/x/sys/unix"

	"github.com/controlLogix/agentmux/platform/localtls"
)

var (
	ErrNotInitialized = errors.New("application_runtime_not_initialized")
	ErrPortInUse      = errors.New("application_runtime_port_in_use")
	ErrNotReady       = errors.New("application_runtime_not_ready")
	ErrStopUncertain  = errors.New("application_runtime_stop_uncertain")
	ErrRunningUnready = errors.New("application_runtime_running_unready")
	ErrTLSExpired     = errors.New("application_runtime_tls_expired")
)

const (
	readinessBudget = 10 * time.Second
	termGrace       = 10 * time.Second
	killGrace       = 5 * time.Second
)

// processRecord binds the owned server by PID, kernel start time and the
// command name of the admitted executable, so a reused PID is never mistaken
// for this runtime's broker.
type processRecord struct {
	SchemaVersion string `json:"schemaVersion"`
	RuntimeID     string `json:"runtimeId"`
	PID           int    `json:"pid"`
	StartSeconds  int64  `json:"startSeconds"`
	StartMicros   int32  `json:"startMicros"`
	Command       string `json:"command,omitempty"`
}

// legacyCommand is the only name records written before Command existed used.
const legacyCommand = "nats-server"

// maxCommandBytes is Darwin's MAXCOMLEN: kinfo_proc p_comm holds this many
// bytes of the executable's base name plus a terminating NUL.
const maxCommandBytes = 16

// commandName is the kernel's command name for an executable.
func commandName(executable string) string {
	name := filepath.Base(executable)
	if len(name) > maxCommandBytes {
		name = name[:maxCommandBytes]
	}
	return name
}

// Status is the closed lifecycle observation.
type Status struct {
	State     string `json:"state"`
	RuntimeID string `json:"runtimeId"`
	Endpoint  string `json:"endpoint"`
	PID       int    `json:"pid,omitempty"`
	// TLSNotAfter is when the pinned server certificate expires.
	TLSNotAfter string `json:"tlsNotAfter,omitempty"`
}

func (r *Runtime) withTLSExpiry(status Status) (Status, time.Time, error) {
	notAfter, err := r.leafNotAfter()
	if err != nil {
		return status, notAfter, err
	}
	status.TLSNotAfter = notAfter.Format(time.RFC3339)
	return status, notAfter, nil
}

func processStart(pid int) (int64, int32, string, bool) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || info == nil || int(info.Proc.P_pid) != pid {
		return 0, 0, "", false
	}
	comm := make([]byte, 0, len(info.Proc.P_comm))
	for _, c := range info.Proc.P_comm {
		if c == 0 {
			break
		}
		comm = append(comm, byte(c))
	}
	return info.Proc.P_starttime.Sec, info.Proc.P_starttime.Usec, string(comm), true
}

func (r *Runtime) record() (*processRecord, error) {
	raw, ok, err := r.read("runtime-process.json")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	var record processRecord
	if json.Unmarshal(raw, &record) != nil || record.SchemaVersion != SchemaVersion || record.PID <= 1 {
		return nil, ErrConflict
	}
	if record.Command == "" {
		record.Command = legacyCommand
	}
	return &record, nil
}

// owned reports whether the recorded process is still this runtime's server.
func owned(record *processRecord) bool {
	seconds, micros, comm, alive := processStart(record.PID)
	return alive && seconds == record.StartSeconds && micros == record.StartMicros && comm == record.Command
}

func (r *Runtime) clearRecord() error {
	if err := unix.Unlinkat(int(r.dir.Fd()), "runtime-process.json", 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return ErrStopUncertain
	}
	return unix.Fsync(int(r.dir.Fd()))
}

// Ready authenticates as the readiness user over the pinned TLS endpoint and
// requires JetStream account information from this runtime's account.
func Ready(ctx context.Context, m Manifest) error {
	trust, err := localtls.NewClientTrust(localtls.Policy{Endpoint: m.Endpoint, ServerName: m.ServerName,
		RootsPEM: []byte(m.RootsPEM), LeafCertificateSHA256: m.LeafCertificateSHA256})
	if err != nil {
		return ErrNotReady
	}
	dialer, err := trust.NewDialer(ctx, 2*time.Second)
	if err != nil {
		return ErrNotReady
	}
	conn, err := nats.Connect(m.Endpoint, nats.SetCustomDialer(dialer), nats.TLSHandshakeFirst(), nats.IgnoreDiscoveredServers(),
		nats.UserCredentials(m.ReadinessCredentials), nats.CustomInboxPrefix("_INBOX.readiness"), nats.NoReconnect(),
		nats.Timeout(2*time.Second))
	if err != nil {
		return ErrNotReady
	}
	defer conn.Close()
	js, err := conn.JetStream(nats.MaxWait(2 * time.Second))
	if err != nil {
		return ErrNotReady
	}
	if _, err := js.AccountInfo(); err != nil {
		return ErrNotReady
	}
	return nil
}

func waitReady(ctx context.Context, m Manifest, record *processRecord) error {
	deadline := time.Now().Add(readinessBudget)
	for time.Now().Before(deadline) {
		if !owned(record) {
			return ErrNotReady
		}
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := Ready(attempt, m)
		cancel()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ErrNotReady
		case <-time.After(200 * time.Millisecond):
		}
	}
	return ErrNotReady
}

func terminate(record *processRecord) error {
	for _, step := range []struct {
		signal syscall.Signal
		grace  time.Duration
	}{{syscall.SIGTERM, termGrace}, {syscall.SIGKILL, killGrace}} {
		if !owned(record) {
			return nil
		}
		if err := syscall.Kill(record.PID, step.signal); err != nil && !errors.Is(err, syscall.ESRCH) {
			return ErrStopUncertain
		}
		deadline := time.Now().Add(step.grace)
		for time.Now().Before(deadline) {
			if !owned(record) {
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	if owned(record) {
		return ErrStopUncertain
	}
	return nil
}

// Start launches the owned server once. A live owned server is reported, not
// duplicated; an unready live server is uncertainty, never replaced.
func Start(ctx context.Context, path string) (Status, error) {
	r, err := Open(path, false)
	if err != nil {
		if errors.Is(err, ErrUnsafePath) {
			return Status{}, ErrNotInitialized
		}
		return Status{}, err
	}
	defer r.Close()
	m, inputs, err := LoadManifest(r)
	if err != nil {
		return Status{}, ErrNotInitialized
	}
	status, notAfter, err := r.withTLSExpiry(Status{RuntimeID: m.RuntimeID, Endpoint: m.Endpoint})
	if err != nil {
		return status, err
	}
	record, err := r.record()
	if err != nil {
		return status, err
	}
	if record != nil {
		if owned(record) {
			status.PID = record.PID
			if Ready(ctx, m) == nil {
				status.State = "running"
				return status, nil
			}
			return status, ErrRunningUnready
		}
		if err := r.clearRecord(); err != nil {
			return status, err
		}
	}
	// Clients refuse an expired certificate, so the server would never be ready.
	if !time.Now().Before(notAfter) {
		return status, ErrTLSExpired
	}
	digest, err := AdmitNATSServer(ctx, inputs.NATSServer)
	if err != nil || digest != inputs.NATSSHA256 {
		return status, ErrServer
	}
	listener, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(inputs.Port))
	if err != nil {
		return status, ErrPortInUse
	}
	listener.Close()
	logFD, err := unix.Openat(int(r.dir.Fd()), "nats-server.log", unix.O_WRONLY|unix.O_CREAT|unix.O_APPEND|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return status, ErrUnsafePath
	}
	logFile := os.NewFile(uintptr(logFD), "nats-server.log")
	defer logFile.Close()
	cmd := exec.Command(inputs.NATSServer, "-c", r.Path("server.conf"))
	cmd.Dir = r.path
	cmd.Stdout, cmd.Stderr = logFile, logFile
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return status, ErrServer
	}
	pid := cmd.Process.Pid
	seconds, micros, comm, alive := processStart(pid)
	if !alive || comm != commandName(inputs.NATSServer) {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return status, ErrNotReady
	}
	record = &processRecord{SchemaVersion: SchemaVersion, RuntimeID: m.RuntimeID, PID: pid, StartSeconds: seconds,
		StartMicros: micros, Command: comm}
	raw, _ := json.Marshal(record)
	if err := r.publish("runtime-process.json", append(raw, '\n')); err != nil {
		_ = terminate(record)
		_ = cmd.Wait()
		return status, err
	}
	// Reap in the background while this process lives; after it exits the
	// detached session leader is reparented and the record stays authoritative.
	go func() { _ = cmd.Wait() }()
	status.PID = pid
	if err := waitReady(ctx, m, record); err != nil {
		if stopErr := terminate(record); stopErr != nil {
			return status, ErrStopUncertain
		}
		if err := r.clearRecord(); err != nil {
			return status, err
		}
		return status, ErrNotReady
	}
	status.State = "running"
	return status, nil
}

// Stop ends only the recorded owned server and keeps the record when the
// outcome is uncertain.
func Stop(ctx context.Context, path string) (Status, error) {
	r, err := Open(path, false)
	if err != nil {
		if errors.Is(err, ErrUnsafePath) {
			return Status{}, ErrNotInitialized
		}
		return Status{}, err
	}
	defer r.Close()
	m, _, err := LoadManifest(r)
	if err != nil {
		return Status{}, ErrNotInitialized
	}
	status := Status{RuntimeID: m.RuntimeID, Endpoint: m.Endpoint, State: "stopped"}
	record, err := r.record()
	if err != nil || record == nil {
		return status, err
	}
	status.PID = record.PID
	if err := terminate(record); err != nil {
		status.State = "uncertain"
		return status, err
	}
	if err := r.clearRecord(); err != nil {
		status.State = "uncertain"
		return status, err
	}
	status.PID = 0
	return status, nil
}

// Observe reports the lifecycle state without changing it.
func Observe(ctx context.Context, path string) (Status, error) {
	r, err := Open(path, false)
	if err != nil {
		if errors.Is(err, ErrUnsafePath) {
			return Status{State: "not_initialized"}, nil
		}
		return Status{}, err
	}
	defer r.Close()
	m, _, err := LoadManifest(r)
	if err != nil {
		return Status{State: "not_initialized"}, nil
	}
	status, _, err := r.withTLSExpiry(Status{RuntimeID: m.RuntimeID, Endpoint: m.Endpoint, State: "stopped"})
	if err != nil {
		return status, err
	}
	record, err := r.record()
	if err != nil || record == nil {
		return status, err
	}
	status.PID = record.PID
	switch {
	case !owned(record):
		status.State = "stale"
	case Ready(ctx, m) == nil:
		status.State = "running"
	default:
		status.State = "unready"
	}
	return status, nil
}
