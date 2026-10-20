package launcher

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// ClientDoctorCheck contains only closed diagnostics and reviewed operator actions.
// A native configuration reference is metadata, never proof of effective settings.
type ClientDoctorCheck struct {
	Name    string       `json:"name"`
	Status  DoctorStatus `json:"status"`
	Code    string       `json:"code"`
	Action  string       `json:"action"`
	Version string       `json:"version,omitempty"`
}

type ClientDoctorReport struct {
	HealthVersion     int                 `json:"healthVersion"`
	Client            string              `json:"client"`
	Checks            []ClientDoctorCheck `json:"checks"`
	DiagnosticsPassed bool                `json:"diagnosticsPassed"`
	Scope             string              `json:"scope"`
}

// ValidClientDoctorID accepts only the built-in selected-client diagnostics.
func ValidClientDoctorID(client string) bool {
	switch client {
	case "claude", "codex", "pi", "claude-desktop":
		return true
	}
	return false
}

type clientDoctorDependencies struct {
	version func(context.Context, string) (string, string)
	auth    func(context.Context, string) ClientDoctorCheck
	getenv  func(string) string
	stat    func(string) (os.FileInfo, error)
}

// RunClientDoctor observes the selected native client's prerequisites without
// changing settings, starting login, or performing provider operations.
// The caller's deadline is never widened. Unknown checks never pass diagnostics.
func RunClientDoctor(ctx context.Context, client string) ClientDoctorReport {
	return runClientDoctor(ctx, client, runtime.GOOS == "darwin" && runtime.GOARCH == "arm64",
		clientDoctorDependencies{version: runClientVersion, auth: runClientAuth, getenv: os.Getenv, stat: os.Stat})
}

func runClientDoctor(ctx context.Context, client string, native bool, deps clientDoctorDependencies) (report ClientDoctorReport) {
	report = ClientDoctorReport{HealthVersion: 1, Client: "unknown", Checks: []ClientDoctorCheck{},
		Scope: "Read-only client prerequisites; native status observations only; not provider usability, workflow qualification or application readiness."}
	if !ValidClientDoctorID(client) {
		report.Checks = append(report.Checks, ClientDoctorCheck{Name: "selection", Status: DoctorUnknown, Code: "invalid_client", Action: "Select claude, codex, pi or claude-desktop."})
		return report
	}
	report.Client = client
	report.Checks = []ClientDoctorCheck{
		{Name: "version", Status: DoctorUnknown, Code: "not_probed", Action: "Check the existing native client's version and update channel."},
		{Name: "configuration", Status: DoctorUnknown, Code: "not_probed", Action: "Inspect settings in the native client; preserve unrelated configuration."},
		{Name: "authentication", Status: DoctorUnknown, Code: "native_client_check_required", Action: "Check sign-in inside the native client. Do not copy credentials."},
	}
	if !native {
		for i := 0; i < 2; i++ {
			report.Checks[i].Code = "unsupported_host"
		}
		return report
	}
	if ctx == nil {
		for i := 0; i < 2; i++ {
			report.Checks[i].Code = "invalid_context"
		}
		return report
	}
	if ctx.Err() != nil {
		for i := 0; i < 2; i++ {
			report.Checks[i].Code = string(doctorContextCode(ctx))
		}
		return report
	}
	selectedCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	ctx = selectedCtx
	defer func() {
		report.DiagnosticsPassed = len(report.Checks) > 0
		for _, check := range report.Checks {
			if check.Status != DoctorPassed {
				report.DiagnosticsPassed = false
			}
		}
	}()
	if client == "claude-desktop" {
		report.Checks[0].Code = "native_client_check_required"
	} else {
		raw, code := deps.version(ctx, client)
		report.Checks[0].Code = code
		if code == "observed" {
			match := clientVersionPattern(client).FindStringSubmatch(strings.TrimSpace(raw))
			if len(match) != 2 {
				report.Checks[0].Code = "invalid_version"
			} else {
				report.Checks[0].Status, report.Checks[0].Version = DoctorPassed, match[1]
			}
		} else if code == "client_missing" {
			report.Checks[0].Status = DoctorUnavailable
		} else if code == "version_pipe_cleanup_incomplete" {
			report.Checks[0].Action = "Check the native client privately. Its output pipe exceeded the cleanup limit; descendant exit was not established."
		}
	}
	if (client == "codex" || client == "claude") && deps.auth != nil {
		report.Checks[2] = deps.auth(ctx, client)
	}
	if ctx.Err() != nil {
		report.Checks[1].Code = string(doctorContextCode(ctx))
		return report
	}
	home := deps.getenv("HOME")
	var root, name string
	switch client {
	case "codex":
		root, name = deps.getenv("CODEX_HOME"), "config.toml"
		if root == "" && home != "" {
			root = filepath.Join(home, ".codex")
		}
	case "claude":
		root, name = deps.getenv("CLAUDE_CONFIG_DIR"), "settings.json"
		if root == "" && home != "" {
			root = filepath.Join(home, ".claude")
		}
	case "pi":
		root, name = deps.getenv("PI_CODING_AGENT_DIR"), "settings.json"
		if root == "" && home != "" {
			root = filepath.Join(home, ".pi", "agent")
		}
	case "claude-desktop":
		name = "claude_desktop_config.json"
		if home != "" {
			root = filepath.Join(home, "Library", "Application Support", "Claude")
		}
	}
	if client == "pi" && strings.HasPrefix(root, "~/") && home != "" {
		root = filepath.Join(home, strings.TrimPrefix(root, "~/"))
	}
	if root == "" || !filepath.IsAbs(root) {
		report.Checks[1].Code = "native_config_root_unknown"
		return report
	}
	info, err := deps.stat(filepath.Join(root, name))
	if ctx.Err() != nil {
		report.Checks[1].Code = string(doctorContextCode(ctx))
		return report
	}
	switch {
	case errors.Is(err, os.ErrNotExist):
		report.Checks[1].Code = "optional_native_config_absent"
	case err != nil || info == nil || !info.Mode().IsRegular():
		report.Checks[1].Code = "native_config_metadata_unknown"
	default:
		report.Checks[1].Status, report.Checks[1].Code = DoctorPassed, "native_config_reference_present"
	}
	// Optional configuration absence and unsupported authentication remain unknown.
	return report
}

var clientNumericVersion = `((?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8}))`
var clientVersionPatterns = map[string]*regexp.Regexp{
	"codex":  regexp.MustCompile(`^codex-cli ` + clientNumericVersion + `$`),
	"claude": regexp.MustCompile(`^` + clientNumericVersion + ` \(Claude Code\)$`),
	"pi":     regexp.MustCompile(`^` + clientNumericVersion + `$`),
}

func clientVersionPattern(client string) *regexp.Regexp { return clientVersionPatterns[client] }

// The buffer is used for both streams; os/exec serializes calls to that same writer.
// Cancelling on overflow terminates the original child and Run joins its readers.
type clientDoctorOutput struct {
	data      []byte
	exceeded  bool
	readerEOF bool
	cancel    context.CancelFunc
}

// ReadFrom records actual EOF. A forced reader close can be hidden by an
// ExitError from Wait, so the exit code alone cannot establish complete output.
func (b *clientDoctorOutput) ReadFrom(reader io.Reader) (int64, error) {
	n, err := io.Copy(struct{ io.Writer }{b}, reader)
	b.readerEOF = err == nil
	return n, err
}

func (b *clientDoctorOutput) Write(p []byte) (int, error) {
	if len(p) > 65536-len(b.data) {
		b.exceeded = true
		b.cancel()
		return len(p), nil
	}
	if !b.exceeded {
		b.data = append(b.data, p...)
	}
	return len(p), nil
}

func runClientVersion(parent context.Context, client string) (string, string) {
	raw, exit, code := runClientProbe(parent, client, false)
	if code == "observed" && exit != 0 {
		return "", "version_probe_failed"
	}
	return raw, code
}

// Only this private closed selection chooses arguments. Both probes share the
// enclosing selected-client deadline and reserve time for reader cleanup.
func runClientProbe(parent context.Context, client string, auth bool) (string, int, string) {
	if client != "codex" && client != "claude" && (client != "pi" || auth) {
		return "", -1, "invalid_client"
	}
	if parent == nil {
		return "", -1, "invalid_context"
	}
	if parent.Err() != nil {
		return "", -1, string(doctorContextCode(parent))
	}
	deadline := time.Now().Add(time.Second)
	if outer, ok := parent.Deadline(); ok && outer.Before(deadline) {
		deadline = outer
	}
	workDeadline := deadline.Add(-200 * time.Millisecond)
	if time.Until(workDeadline) <= 0 {
		return "", -1, "deadline_exceeded"
	}
	ctx, cancel := context.WithDeadline(parent, workDeadline)
	defer cancel()
	command := clientDoctorProbeCommand(ctx, client, auth)
	command.WaitDelay = 200 * time.Millisecond
	output := &clientDoctorOutput{cancel: cancel}
	command.Stdout, command.Stderr = output, output
	err := command.Run() // Joins the original process and readers, not descendants.
	return clientProbeResult(ctx, err, output)
}

func clientProbeResult(ctx context.Context, err error, output *clientDoctorOutput) (string, int, string) {
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && !output.exceeded && ctx.Err() == nil {
		if !output.readerEOF {
			return "", -1, "version_pipe_cleanup_incomplete"
		}
		return string(output.data), exitError.ExitCode(), "observed"
	}
	raw, code := clientVersionResult(ctx, err, output)
	return raw, 0, code
}

func clientVersionResult(ctx context.Context, err error, output *clientDoctorOutput) (string, string) {
	if output.exceeded {
		return "", "output_limit"
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		return "", "version_pipe_cleanup_incomplete"
	}
	if ctx.Err() != nil {
		return "", string(doctorContextCode(ctx))
	}
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
		return "", "client_missing"
	}
	if err != nil {
		return "", "version_probe_failed"
	}
	if !output.readerEOF {
		return "", "version_pipe_cleanup_incomplete"
	}
	return string(output.data), "observed"
}
