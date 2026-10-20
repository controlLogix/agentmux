//go:build darwin && arm64

package launcher

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestNativeClientDoctorProcesses requires the coordinator's serialized live
// slot. It runs disposable scripts, never installed clients or provider calls.
// Blocking direct-child fixtures use exec, preserving the original process PID.
// Inherited output is held by a separate helper owned and waited on by this test.
// The wrapper transfers its output descriptor, exits, and leaves no unowned child.
func TestNativeClientDoctorProcesses(t *testing.T) {
	if os.Getenv("AGENTMUX_CLIENT_DOCTOR_LIVE") != "1" {
		t.Skip("live process test requires the coordinator's slot and AGENTMUX_CLIENT_DOCTOR_LIVE=1")
	}
	for _, executable := range []string{"/bin/sh", "/bin/sleep", "/usr/bin/yes"} {
		info, err := os.Stat(executable)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			t.Fatal("a required native fixture executable is unavailable")
		}
	}
	cases := []struct {
		name, body, code, version string
		status                    DoctorStatus
	}{
		{"version", "printf 'codex-cli 0.162.1\\n'\n", "observed", "0.162.1", DoctorPassed},
		{"malformed_auth", "printf 'codex-cli 0.162.1\\n'\n", "observed", "0.162.1", DoctorPassed},
		{"nonzero", "printf 'PRIVATE_PROCESS_SENTINEL codex-cli 0.162.1\\n' >&2\nexit 7\n", "version_probe_failed", "", DoctorUnknown},
		{"timeout", "exec /bin/sleep 60\n", "deadline_exceeded", "", DoctorUnknown},
		{"inherited_pipe", "export AMX_CLIENT_DOCTOR_PIPE_ROLE=sender AMX_CLIENT_DOCTOR_PIPE_EXIT=0\nexec \"$AMX_CLIENT_DOCTOR_TEST_BINARY\" -test.run=^TestNativeClientDoctorPipeHelper$\n", "version_pipe_cleanup_incomplete", "", DoctorUnknown},
		{"auth_inherited_pipe", "printf 'codex-cli 0.162.1\\n'\n", "observed", "0.162.1", DoctorPassed},
		{"output_limit", "exec /usr/bin/yes PRIVATE_PROCESS_SENTINEL\n", "output_limit", "", DoctorUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			bin := filepath.Join(home, "bin")
			codexHome := filepath.Join(home, "codex configuration")
			for _, directory := range []string{bin, codexHome} {
				if err := os.Mkdir(directory, 0700); err != nil {
					t.Fatal("could not create owned fixture directory")
				}
			}
			config := filepath.Join(codexHome, "config.toml")
			sentinel := "# PRIVATE_CONFIG_SENTINEL\n"
			if err := os.WriteFile(config, []byte(sentinel), 0600); err != nil {
				t.Fatal("could not create fixture settings")
			}
			authBody := "printf 'Not logged in\\n'\nexit 1\n"
			if tc.name == "malformed_auth" {
				authBody = "printf 'Not logged in\\nLogged in using ChatGPT\\n'\nexit 0\n"
			}
			if tc.name == "auth_inherited_pipe" {
				authBody = "export AMX_CLIENT_DOCTOR_PIPE_ROLE=sender AMX_CLIENT_DOCTOR_PIPE_EXIT=1\nexec \"$AMX_CLIENT_DOCTOR_TEST_BINARY\" -test.run=^TestNativeClientDoctorPipeHelper$\n"
			}
			script := "#!/bin/sh\nif [ \"$#\" -eq 1 ] && [ \"$1\" = \"--version\" ]; then\n" + tc.body + "\nexit 0\nfi\nif [ \"$#\" -eq 2 ] && [ \"$1\" = login ] && [ \"$2\" = status ]; then\n" + authBody + "\nfi\nexit 99\n"

			if err := os.WriteFile(filepath.Join(bin, "codex"), []byte(script), 0700); err != nil {
				t.Fatal("could not create fixture executable")
			}
			t.Setenv("HOME", home)
			t.Setenv("PATH", bin)
			t.Setenv("CODEX_HOME", codexHome)
			t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, "claude"))
			t.Setenv("PI_CODING_AGENT_DIR", filepath.Join(home, "pi"))

			if tc.name == "inherited_pipe" || tc.name == "auth_inherited_pipe" {
				prepareNativeClientPipeHolder(t)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			began := time.Now()
			report := RunClientDoctor(ctx, "codex")
			elapsed := time.Since(began)
			// The runner reserves 800 ms for execution and 200 ms for reader cleanup.
			// Allow scheduler overhead here; the product deadline itself remains one second.
			if elapsed > 1500*time.Millisecond {
				t.Fatalf("client process cleanup exceeded fixture allowance: %s", elapsed)
			}
			if len(report.Checks) != 3 {
				t.Fatal("unexpected diagnostic check count")
			}
			observed := report.Checks[0]
			if observed.Code != tc.code || observed.Status != tc.status || observed.Version != tc.version {
				t.Fatalf("unexpected safe version result: status=%s code=%s version=%s", observed.Status, observed.Code, observed.Version)
			}
			wantAuth := "native_not_authenticated"
			if tc.name == "timeout" {
				wantAuth = "deadline_exceeded"
			}
			if tc.name == "auth_inherited_pipe" {
				wantAuth = "auth_pipe_cleanup_incomplete"
			}
			if tc.name == "malformed_auth" {
				wantAuth = "native_auth_status_unknown"
			}
			if report.DiagnosticsPassed || report.Checks[2].Code != wantAuth {
				t.Fatal("fixture authentication was incorrectly qualified")
			}
			if report.Checks[1].Code != "native_config_reference_present" {
				t.Fatal("fixture metadata check did not complete")
			}
			encoded, err := json.Marshal(report)
			if err != nil {
				t.Fatal("report encoding failed")
			}
			if strings.Contains(string(encoded), "PRIVATE_") || strings.Contains(string(encoded), home) {
				t.Fatal("private fixture data escaped into the report")
			}
			current, err := os.ReadFile(config)
			if err != nil || string(current) != sentinel {
				t.Fatal("native settings fixture changed")
			}
			// RunClientDoctor returns only after command.Run has waited on its original
			// process and joined its readers. Teardown stops and waits on the exact
			// separate holder process. This does not qualify arbitrary descendant termination.
			t.Logf("owned fixture process joined: case=%s elapsed=%s", tc.name, elapsed)
		})
	}
}

// TestNativeClientDoctorSignedOutLookup runs installed native status commands
// only with isolated fixture configuration. It never starts a login or model.
func TestNativeClientDoctorSignedOutLookup(t *testing.T) {
	if os.Getenv("AGENTMUX_CLIENT_DOCTOR_NATIVE_LOOKUP") != "1" {
		t.Skip("requires the coordinator's live slot and AGENTMUX_CLIENT_DOCTOR_NATIVE_LOOKUP=1")
	}
	nativePath := os.Getenv("PATH")
	for _, client := range []string{"codex", "claude"} {
		if _, err := exec.LookPath(client); err != nil {
			t.Fatalf("required native %s command is unavailable", client)
		}
	}
	home := t.TempDir()
	t.Chdir(home)
	// Remove provider credentials, helpers, account overrides and project state.
	// Test cleanup restores every inherited value after this serialized test.
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		t.Setenv(key, "")
	}
	t.Setenv("PATH", nativePath)
	t.Setenv("HOME", home)
	t.Setenv("TMPDIR", home)
	codex := filepath.Join(home, "codex configuration")
	claude := filepath.Join(home, "claude configuration")
	for _, directory := range []string{codex, claude} {
		if os.Mkdir(directory, 0700) != nil {
			t.Fatal("fixture directory creation failed")
		}
	}
	t.Setenv("CODEX_HOME", codex)
	t.Setenv("CLAUDE_CONFIG_DIR", claude)
	t.Setenv("PI_CODING_AGENT_DIR", filepath.Join(home, "pi"))
	config := filepath.Join(codex, "config.toml")
	original := []byte("cli_auth_credentials_store = \"file\"\n# PRIVATE_CONFIG_SENTINEL\n")
	settings := filepath.Join(claude, "settings.json")
	if os.WriteFile(config, original, 0600) != nil || os.WriteFile(settings, []byte("{}\n"), 0600) != nil {
		t.Fatal("fixture settings creation failed")
	}
	inspect := func(client string) ClientDoctorReport {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		report := RunClientDoctor(ctx, client)
		encoded, err := json.Marshal(report)
		if err != nil || strings.Contains(string(encoded), "PRIVATE_") || strings.Contains(string(encoded), home) {
			t.Fatal("private native fixture content escaped")
		}
		if report.DiagnosticsPassed {
			t.Fatal("signed-out fixture incorrectly passed")
		}
		return report
	}
	for _, client := range []string{"codex", "claude"} {
		report := inspect(client)
		if len(report.Checks) != 3 || report.Checks[2].Code != "native_not_authenticated" || report.Checks[2].Status != DoctorUnavailable {
			t.Fatalf("%s native signed-out lookup was not established; safe checks=%+v", client, report.Checks)
		}
	}
	if os.WriteFile(config, []byte("cli_auth_credentials_store = \"invalid-fixture-store\"\n"), 0600) != nil {
		t.Fatal("fixture update failed")
	}
	if report := inspect("codex"); report.Checks[2].Status != DoctorUnknown {
		t.Fatal("invalid native fixture config was not reported unknown")
	}
	if os.WriteFile(config, original, 0600) != nil {
		t.Fatal("fixture restore failed")
	}
	if report := inspect("codex"); report.Checks[2].Code != "native_not_authenticated" {
		t.Fatal("native fixture restore was not observed")
	}
	if data, err := os.ReadFile(config); err != nil || string(data) != string(original) {
		t.Fatal("Codex fixture settings changed")
	}
	if data, err := os.ReadFile(settings); err != nil || string(data) != "{}\n" {
		t.Fatal("Claude fixture settings changed")
	}
}

// prepareNativeClientPipeHolder gives this test the holder's original Cmd and
// Wait. The wrapper sends a descriptor over a private Unix socket; it never
// launches a descendant. No helper is found or killed by a recorded PID.
func prepareNativeClientPipeHolder(t *testing.T) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal("test executable unavailable")
	}
	directory, err := os.MkdirTemp("/tmp", "amx-client-pipe-")
	if err != nil {
		t.Fatal("socket fixture unavailable")
	}
	t.Cleanup(func() {
		if os.RemoveAll(directory) != nil {
			t.Error("socket fixture cleanup failed")
		}
	})
	socket := filepath.Join(directory, "pipe.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal("fixture listener failed")
	}
	listener.SetUnlinkOnClose(false)
	defer listener.Close()
	file, err := listener.File()
	if err != nil {
		t.Fatal("fixture listener handle failed")
	}
	defer file.Close()
	stopRead, stopWrite, err := os.Pipe()
	if err != nil {
		t.Fatal("fixture stop pipe failed")
	}
	defer stopRead.Close()
	t.Setenv("AMX_CLIENT_DOCTOR_TEST_BINARY", binary)
	t.Setenv("AMX_CLIENT_DOCTOR_PIPE_SOCKET", socket)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	command := exec.CommandContext(ctx, binary, "-test.run=^TestNativeClientDoctorPipeHelper$")
	command.Env = append(os.Environ(), "AMX_CLIENT_DOCTOR_PIPE_ROLE=owner")
	command.ExtraFiles = []*os.File{file}
	command.Stdin = stopRead
	command.Stdout, command.Stderr = io.Discard, io.Discard
	command.WaitDelay = 200 * time.Millisecond
	if command.Start() != nil {
		cancel()
		stopWrite.Close()
		t.Fatal("fixture holder start failed")
	}
	t.Cleanup(func() {
		// EOF is the explicit stop request; Wait retains the original child owner.
		stopWrite.Close()
		err := command.Wait()
		cancel()
		if err != nil {
			t.Error("owned pipe holder failed to stop and join cleanly")
		}
	})
}

// TestNativeClientDoctorPipeHelper is entered only by the owned native fixture.
// The receiver keeps the transferred pipe open until its original parent sends
// EOF on stdin. The sender exits with the selected code after an acknowledgment.
func TestNativeClientDoctorPipeHelper(t *testing.T) {
	role := os.Getenv("AMX_CLIENT_DOCTOR_PIPE_ROLE")
	if os.Getenv("AGENTMUX_CLIENT_DOCTOR_LIVE") != "1" || (role != "owner" && role != "sender") {
		t.Skip("owned native pipe fixture only")
	}
	fail := func() { os.Exit(90) }
	if role == "sender" {
		connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: os.Getenv("AMX_CLIENT_DOCTOR_PIPE_SOCKET"), Net: "unix"})
		if err != nil {
			fail()
		}
		defer connection.Close()
		connection.SetDeadline(time.Now().Add(2 * time.Second))
		exit := 0
		if os.Getenv("AMX_CLIENT_DOCTOR_PIPE_EXIT") == "1" {
			exit = 1
			os.Stdout.WriteString("Not logged in\n")
		} else {
			os.Stdout.WriteString("codex-cli 0.162.1\n")
		}
		if _, _, err = connection.WriteMsgUnix([]byte{1}, syscall.UnixRights(int(os.Stdout.Fd())), nil); err != nil {
			fail()
		}
		ack := make([]byte, 1)
		if _, err = io.ReadFull(connection, ack); err != nil || ack[0] != 1 {
			fail()
		}
		os.Exit(exit)
	}
	inherited := os.NewFile(3, "owned-listener")
	listener, err := net.FileListener(inherited)
	inherited.Close()
	if err != nil {
		fail()
	}
	defer listener.Close()
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		fail()
	}
	unixListener.SetUnlinkOnClose(false)
	unixListener.SetDeadline(time.Now().Add(2 * time.Second))
	connection, err := unixListener.AcceptUnix()
	if err != nil {
		fail()
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(2 * time.Second))
	payload, oob := make([]byte, 1), make([]byte, syscall.CmsgSpace(4))
	_, count, _, _, err := connection.ReadMsgUnix(payload, oob)
	if err != nil {
		fail()
	}
	messages, err := syscall.ParseSocketControlMessage(oob[:count])
	if err != nil || len(messages) != 1 {
		fail()
	}
	descriptors, err := syscall.ParseUnixRights(&messages[0])
	if err != nil || len(descriptors) != 1 {
		fail()
	}
	held := os.NewFile(uintptr(descriptors[0]), "owned-output")
	if _, err = connection.Write([]byte{1}); err != nil {
		held.Close()
		fail()
	}
	_, err = io.Copy(io.Discard, os.Stdin)
	held.Close()
	if err != nil {
		fail()
	}
}
