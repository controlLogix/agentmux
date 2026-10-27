package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// InstalledClientAdmission owns protected path descriptors through process
// replacement or settings publication. A serialized declaration is not an owner.
type InstalledClientAdmission struct {
	mu       sync.Mutex
	id       string
	manifest ClientManifest
	backend  interface {
		recheck(context.Context) error
		close() error
	}
	frontend     *InstalledFrontendImage
	closeFailure error
}

type InstalledClientDeclaration struct {
	SchemaVersion       string   `json:"schema_version"`
	InstallationID      string   `json:"installation_id"`
	ClientID            string   `json:"client_id"`
	Command             string   `json:"command"`
	Arguments           []string `json:"arguments"`
	EnrollmentSelection string   `json:"enrollment_selection"`
	Transport           string   `json:"transport"`
}

type clientFailure struct {
	code  string
	cause error
	owner any
}

func (e *clientFailure) Error() string                { return "installed_client_" + e.code }
func (e *clientFailure) Unwrap() error                { return e.cause }
func (e *clientFailure) Format(s fmt.State, _ rune)   { fmt.Fprint(s, e.Error()) }
func (e *clientFailure) MarshalJSON() ([]byte, error) { return json.Marshal(e.Error()) }

func validClientSelection(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && len(path) <= 4096 && !strings.ContainsAny(path, "\x00\r\n")
}

func validClientProfileOperation(operation string) bool {
	switch operation {
	case "startup", "startup-json", "startup-worker", "startup-worker-json", "mcp", "mcp-worker", "dashboard", "claude-code-hook", "claude-code-hook-worker":
		return true
	default:
		return false
	}
}

func validClientRepositoryOperation(operation string) bool {
	return validClientProfileOperation(operation) && operation != "dashboard" && operation != "claude-code-hook" && operation != "claude-code-hook-worker"
}

func validClientRepositoryRoot(path string) bool {
	if !validClientSelection(path) || path == string(filepath.Separator) || !utf8.ValidString(path) || len(strings.Split(path, string(filepath.Separator))) > 128 {
		return false
	}
	for _, character := range path {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func (a *InstalledClientAdmission) Recheck(ctx context.Context) error {
	if a == nil || ctx == nil || ctx.Err() != nil {
		return &clientFailure{code: "recheck_invalid"}
	}
	ctx, cancel := clientAdmissionContext(ctx)
	defer cancel()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.backend == nil || a.frontend == nil || a.closeFailure != nil {
		return &clientFailure{code: "closed"}
	}
	if err := a.backend.recheck(ctx); err != nil {
		return &clientFailure{code: "changed", cause: err}
	}
	if err := a.frontend.Recheck(ctx); err != nil {
		return &clientFailure{code: "frontend_changed", cause: err}
	}
	return nil
}

func (a *InstalledClientAdmission) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var failure error
	owners := []any{}
	if a.backend != nil {
		owners = append(owners, a.backend)
		failure = a.backend.close()
		a.backend = nil
	}
	if a.frontend != nil {
		owners = append(owners, a.frontend)
		failure = errors.Join(failure, a.frontend.Close())
		a.frontend = nil
	}
	if failure != nil {
		a.closeFailure = &clientFailure{code: "cleanup_failed", cause: errors.Join(a.closeFailure, failure), owner: owners}
	}
	return a.closeFailure
}

func (a *InstalledClientAdmission) Declaration(ctx context.Context, selection string) (InstalledClientDeclaration, error) {
	if !validClientSelection(selection) {
		return InstalledClientDeclaration{}, &clientFailure{code: "selection_invalid"}
	}
	if err := a.Recheck(ctx); err != nil {
		return InstalledClientDeclaration{}, err
	}
	return InstalledClientDeclaration{"1.0.0", a.id, "claude-desktop", StableFrontendPath,
		[]string{"mcp", "--client-installation", a.id, "--selection", selection}, selection, "stdio"}, nil
}

// Exec replaces this process. CWD and standard streams stay owned by the same
// process; the existing Python session owns bounded startup and joined cleanup.
func (a *InstalledClientAdmission) Exec(ctx context.Context, operation, selection string) error {
	if !validClientProfileOperation(operation) && operation != "launch-claude-desktop" {
		return &clientFailure{code: "command_invalid"}
	}
	if !validClientSelection(selection) {
		return &clientFailure{code: "selection_invalid"}
	}
	// HOME remains a convenience for Python's existing user-facing defaults. It
	// cannot select enrollment, imports, a runtime, or a broker in this route.
	home, err := os.UserHomeDir()
	if err != nil || !validClientSelection(home) {
		home = ""
	}
	return a.exec(ctx, []string{operation, selection}, home)
}

// ExecRepository carries an explicit untrusted repository root into the same
// protected client. Its existing resolver must retain central enrollment before
// the final selection-based exec; the repository supplies no authority itself.
func (a *InstalledClientAdmission) ExecRepository(ctx context.Context, operation, repositoryRoot string) error {
	if !validClientRepositoryOperation(operation) {
		return &clientFailure{code: "command_invalid"}
	}
	if !validClientRepositoryRoot(repositoryRoot) {
		return &clientFailure{code: "repository_invalid"}
	}
	home, err := os.UserHomeDir()
	if err != nil || !validClientSelection(home) {
		home = ""
	}
	return a.exec(ctx, []string{"repository-client", operation, repositoryRoot}, home)
}

// ExecRegistered borrows the central owner's original descriptor. Only a
// verified duplicate crosses exec; the caller still closes its original on any
// return. Registration metadata is display context, never application authority.
func (a *InstalledClientAdmission) ExecRegistered(ctx context.Context, operation, selection string, registrationFile *os.File, registrationSHA256 string) error {
	if !validClientProfileOperation(operation) {
		return &clientFailure{code: "command_invalid"}
	}
	if !validClientSelection(selection) {
		return &clientFailure{code: "selection_invalid"}
	}
	if registrationFile == nil || !clientDigestPattern.MatchString(registrationSHA256) {
		return &clientFailure{code: "registration_invalid"}
	}
	if err := a.Recheck(ctx); err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil || !validClientSelection(home) {
		home = ""
	}
	return withClientRegistration(ctx, registrationFile, a.id, registrationSHA256, func(duplicate *os.File) error {
		args := []string{"registered-client", operation, selection, strconv.FormatUint(uint64(duplicate.Fd()), 10), registrationSHA256}
		return a.execWithRegistration(ctx, args, home, duplicate)
	})
}

// ExecRegisteredCore does not accept a caller-chosen endpoint or application identity.
func (a *InstalledClientAdmission) ExecRegisteredCore(ctx context.Context, selection string, registrationFile *os.File,
	registrationSHA256, repository string, arguments []string) error {
	if !validClientSelection(selection) || !validClientRepositoryRoot(repository) || registrationFile == nil ||
		!clientDigestPattern.MatchString(registrationSHA256) || len(arguments) == 0 || len(arguments) > 128 {
		return &clientFailure{code: "command_invalid"}
	}
	for _, argument := range arguments {
		if len(argument) > 65536 || strings.ContainsRune(argument, 0) {
			return &clientFailure{code: "command_invalid"}
		}
	}
	if err := a.Recheck(ctx); err != nil {
		return err
	}
	home, err := installedClientAccountHome()
	if err != nil {
		return err
	}
	return withClientRegistration(ctx, registrationFile, a.id, registrationSHA256, func(duplicate *os.File) error {
		args := []string{"registered-core", selection, strconv.FormatUint(uint64(duplicate.Fd()), 10), registrationSHA256, repository, "--"}
		return a.execWithRegistration(ctx, append(args, arguments...), home, duplicate)
	})
}

// ExecSetup retains the same protected admission while selecting the native
// account's settings. Ambient HOME cannot redirect the setup operation.
func (a *InstalledClientAdmission) ExecSetup(ctx context.Context, selection, receipt, operation string, apply bool) error {
	if !validClientSelection(selection) || !validClientSelection(receipt) {
		return &clientFailure{code: "selection_invalid"}
	}
	switch operation {
	case "install", "remove", "restore", "recover":
	default:
		return &clientFailure{code: "command_invalid"}
	}
	home, err := installedClientAccountHome()
	if err != nil {
		return err
	}
	if a == nil {
		return &clientFailure{code: "recheck_invalid"}
	}
	args := []string{"client-setup", "--client-installation", a.id, "--selection", selection, "--receipt", receipt, "--operation", operation}
	if apply {
		args = append(args, "--apply")
	}
	return a.exec(ctx, args, home)
}

var localEnrollmentDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ExecLocalEnrollment runs the installation's local application enrollment
// ceremony (AMUX-728) from an explicit private request and its approved
// digest. The native account home is fixed before Python starts.
func (a *InstalledClientAdmission) ExecLocalEnrollment(ctx context.Context, request, digest string) error {
	if !validClientSelection(request) || !localEnrollmentDigest.MatchString(digest) {
		return &clientFailure{code: "selection_invalid"}
	}
	home, err := installedClientAccountHome()
	if err != nil {
		return err
	}
	if a == nil {
		return &clientFailure{code: "recheck_invalid"}
	}
	return a.exec(ctx, []string{"application-enroll", "--client-installation", a.id, "--request", request, "--request-sha256", digest}, home)
}

var definitionsOwnerHub = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

// ExecDefinitionsOwnerRetirement retires a stopped profile's repository
// definitions fence (AMUX-728). The installed Python owner proves the old owner
// stopped and keeps legacy writes denied; without apply it only reports.
func (a *InstalledClientAdmission) ExecDefinitionsOwnerRetirement(ctx context.Context, repository, hub string, apply bool) error {
	if !validClientSelection(repository) || !definitionsOwnerHub.MatchString(hub) {
		return &clientFailure{code: "selection_invalid"}
	}
	home, err := installedClientAccountHome()
	if err != nil {
		return err
	}
	if a == nil {
		return &clientFailure{code: "recheck_invalid"}
	}
	args := []string{"retire-definitions-owner", "--client-installation", a.id, "--repository-root", repository, "--hub-id", hub}
	if apply {
		args = append(args, "--apply")
	}
	return a.exec(ctx, args, home)
}

// ExecClaudeHookSetup selects the account's Claude namespace before isolated
// Python starts. A present invalid override never falls back to another file.
func (a *InstalledClientAdmission) ExecClaudeHookSetup(ctx context.Context, selection, receipt, operation string, apply bool) error {
	if !validClientSelection(selection) || !validClientSelection(receipt) {
		return &clientFailure{code: "selection_invalid"}
	}
	switch operation {
	case "install", "remove", "restore", "recover":
	default:
		return &clientFailure{code: "command_invalid"}
	}
	home, err := installedClientAccountHome()
	if err != nil {
		return err
	}
	override, present := os.LookupEnv("CLAUDE_CONFIG_DIR")
	configuration, err := claudeHookSettingsPath(home, override, present)
	if err != nil {
		return err
	}
	if a == nil {
		return &clientFailure{code: "recheck_invalid"}
	}
	args := []string{"claude-hook-setup", "--configuration", configuration, "--client-installation", a.id, "--selection", selection, "--receipt", receipt, "--operation", operation}
	if apply {
		args = append(args, "--apply")
	}
	return a.exec(ctx, args, home)
}

func claudeHookSettingsPath(home, override string, present bool) (string, error) {
	if !validClientRepositoryRoot(home) {
		return "", &clientFailure{code: "account_home_unavailable"}
	}
	directory := filepath.Join(home, ".claude")
	if present {
		if !validClientRepositoryRoot(override) {
			return "", &clientFailure{code: "selection_invalid"}
		}
		directory = override
	}
	configuration := filepath.Join(directory, "settings.json")
	if !validClientRepositoryRoot(configuration) {
		return "", &clientFailure{code: "selection_invalid"}
	}
	return configuration, nil
}

func installedClientAccountHome() (string, error) {
	if os.Getuid() != os.Geteuid() {
		return "", &clientFailure{code: "account_identity_invalid"}
	}
	id := strconv.Itoa(os.Getuid())
	if id == "0" {
		return "", &clientFailure{code: "ordinary_user_required"}
	}
	account, err := user.LookupId(id)
	if err != nil || account.Uid != id || !validClientSelection(account.HomeDir) {
		return "", &clientFailure{code: "account_home_unavailable"}
	}
	return account.HomeDir, nil
}

func (a *InstalledClientAdmission) exec(ctx context.Context, arguments []string, home string) error {
	return a.execWithRegistration(ctx, arguments, home, nil)
}

func (a *InstalledClientAdmission) execWithRegistration(ctx context.Context, arguments []string, home string, registration *os.File) error {
	if err := a.Recheck(ctx); err != nil {
		return err
	}
	root := filepath.Join(InstalledClientBase, a.id)
	interpreter := filepath.Join(root, ClientInterpreter)
	args := append([]string{interpreter, "-I", "-S", filepath.Join(root, ClientBootstrap)}, arguments...)
	env := installedClientEnvironment(home)
	if ctx.Err() != nil {
		return &clientFailure{code: "deadline", cause: ctx.Err()}
	}
	if registration != nil {
		return execInstalledRegisteredClient(interpreter, args, env, registration)
	}
	return execInstalledClient(interpreter, args, env)
}

func installedClientEnvironment(home string) []string {
	env := []string{"PATH=/usr/bin:/bin", "LANG=en_US.UTF-8", "LC_CTYPE=UTF-8"}
	if home != "" {
		env = append(env, "HOME="+home)
	}
	if os.Getenv("AGENTMUX_NO_BYPASS") == "1" {
		env = append(env, "AGENTMUX_NO_BYPASS=1")
	}
	return env
}

func clientAdmissionContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, 10*time.Second)
}
