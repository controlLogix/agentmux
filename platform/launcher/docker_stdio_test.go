//go:build linux || darwin

package launcher

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func init() {
	if os.Getenv("AMX_STDIO_FIXTURE") != "1" {
		return
	}
	if strings.Join(os.Args[1:], " ") != "--context stdio-fixture system dial-stdio" {
		os.Exit(80)
	}
	if os.WriteFile(os.Getenv("AMX_STDIO_MARKER"), []byte(strconv.Itoa(os.Getpid())), 0600) != nil {
		os.Exit(81)
	}
	mode := os.Getenv("AMX_STDIO_MODE")
	if mode == "stall" {
		time.Sleep(time.Minute)
		os.Exit(82)
	}
	reader := bufio.NewReader(os.Stdin)
	var request strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			os.Exit(83)
		}
		request.WriteString(line)
		if line == "\r\n" {
			break
		}
	}
	if request.String() != dockerInfoStdioRequest {
		os.Exit(84)
	}
	// A live writer is required after the fixed request, matching the real pipe.
	inputEnded := make(chan struct{})
	go func() { reader.ReadByte(); close(inputEnded) }()
	select {
	case <-inputEnded:
		os.Exit(85)
	case <-time.After(30 * time.Millisecond):
	}
	body := `{"ID":"fixture-engine","OSType":"linux","ServerVersion":"29.8.0"}`
	if mode == "wrong-id" {
		body = strings.Replace(body, "fixture-engine", "unselected-engine", 1)
	}
	if mode == "wrong-version" {
		body = strings.Replace(body, "29.8.0", "29.9.0", 1)
	}
	if mode == "oversize" {
		body = strings.Repeat("x", 1024*1024+1)
	}
	status := "200 OK"
	if mode == "status" {
		status = "403 Forbidden"
	}
	fmt.Fprintln(os.Stderr, "fixture-private-stderr-must-not-leak")
	fmt.Fprintf(os.Stdout, "HTTP/1.1 %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, len(body), body)
	if mode == "trailing" {
		io.WriteString(os.Stdout, "extra")
	}
	os.Exit(0)
}

func stdioFixtureDocker(t *testing.T, mode string) (*Docker, string) {
	t.Helper()
	t.Setenv("DOCKER_HOST", "")
	t.Setenv("DOCKER_CONTEXT", "")
	for _, key := range []string{"AMX_DOCKER_FIXTURE", "AMX_DOCKER_READS_FIXTURE", "AMX_BROKER_INSPECT_FIXTURE"} {
		t.Setenv(key, "")
	}
	t.Setenv("AMX_STDIO_FIXTURE", "1")
	t.Setenv("AMX_STDIO_MODE", mode)
	marker := filepath.Join(t.TempDir(), "owned-pid")
	t.Setenv("AMX_STDIO_MARKER", marker)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("owned fixture executable unavailable")
	}
	d, err := NewDocker(DockerConfig{Executable: executable, Context: "stdio-fixture", Endpoint: "npipe:////./pipe/fixture", EngineID: "fixture-engine", Versions: DockerVersions{"29.8.0", "29.8.0", "5.5.1"}, Timeout: 10 * time.Second, Backend: WindowsInterop})
	if err != nil {
		t.Fatal("owned transport selection rejected")
	}
	return d, marker
}

func assertStdioChildReaped(t *testing.T, marker string) {
	t.Helper()
	raw, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal("owned child did not record its identity")
	}
	pid, err := strconv.Atoi(string(raw))
	if err != nil || pid <= 0 {
		t.Fatal("owned child identity invalid")
	}
	if syscall.Kill(pid, 0) == nil {
		t.Fatal("owned child still live after transport return")
	}
}

func TestDockerStdioActualOwnedPipeAndRefusals(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-id", "wrong-version", "oversize", "status", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			d, marker := stdioFixtureDocker(t, mode)
			info, err := d.readEngineInfoStdio(context.Background(), "29.8.0")
			assertStdioChildReaped(t, marker)
			if mode == "valid" {
				if err != nil || info.ID != "fixture-engine" || info.OS != "linux" || info.ServerVersion != "29.8.0" {
					t.Fatal("valid owned open-stdin read rejected")
				}
			} else if err == nil || info != (dockerEngineInfo{}) {
				t.Fatal("invalid engine/framing returned trusted facts")
			}
			if err != nil && strings.Contains(err.Error(), "fixture-private") {
				t.Fatal("transport exposed private stderr")
			}
		})
	}
}

func TestDockerStdioDeadlineCancellationAndNoFallback(t *testing.T) {
	for _, mode := range []string{"pre-cancel", "earlier-parent", "production-four-seconds", "unqualified-version", "configured-client", "configured-server", "native-backend"} {
		t.Run(mode, func(t *testing.T) {
			d, marker := stdioFixtureDocker(t, "stall")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			actual := "29.8.0"
			if mode == "pre-cancel" {
				cancel()
			}
			if mode == "earlier-parent" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 150*time.Millisecond)
				defer stop()
			}
			if mode == "unqualified-version" {
				actual = "29.9.0"
			}
			if mode == "configured-client" {
				d.config.Versions.Client = "29.9.0"
			}
			if mode == "configured-server" {
				d.config.Versions.Server = "29.9.0"
			}
			if mode == "native-backend" {
				d.config.Backend = NativeUnix
			}
			started := time.Now()
			info, err := d.readEngineInfoStdio(ctx, actual)
			if err == nil || info != (dockerEngineInfo{}) {
				t.Fatal("cancelled or unqualified read produced trusted facts")
			}
			if mode == "earlier-parent" || mode == "production-four-seconds" {
				assertStdioChildReaped(t, marker)
				if err.Error() != "docker_command_timeout_outcome_unknown" || time.Since(started) > 5*time.Second {
					t.Fatal("deadline or bounded cleanup was not preserved")
				}
			} else if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("refused selection started a child or fallback")
			}
		})
	}
}

func TestDockerStdioClosedResponseFraming(t *testing.T) {
	body := `{"ID":"fixture-engine","OSType":"linux","ServerVersion":"29.8.0"}`
	valid := func(headers, body string) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" + headers + "\r\n" + body)
	}
	for _, raw := range [][]byte{
		valid(fmt.Sprintf("Content-Length: %d\r\n", len(body)), body),
		valid("Transfer-Encoding: chunked\r\n", fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(body), body)),
		valid("Connection: close\r\n", body),
	} {
		if _, err := decodeDockerInfoStdio(raw); err != nil {
			t.Fatal("approved complete HTTP framing rejected")
		}
	}
	for _, raw := range [][]byte{
		valid("Transfer-Encoding: identity\r\n", body),
		valid("Content-Length: 1\r\nTransfer-Encoding: chunked\r\n", body),
		valid("Content-Length: 1\r\nContent-Length: 1\r\n", body),
		valid(fmt.Sprintf("Content-Length: %d\nContent-Length: %d\r\n", len(body), len(body)), body),
		valid("X-Unknown: one\n folded-value\r\n", body),
		valid("Content-Encoding: gzip\r\n", body),
		valid("Upgrade: other\r\n", body),
		valid("Connection: close\r\n", body+"{}"),
		valid("Connection: close\r\n", strings.Replace(body, "\"ID\"", "\"id\"", 1)),
		valid("Connection: close\r\n", strings.Replace(body, "\"ID\":", "\"ID\":\"duplicate\",\"ID\":", 1)),
		valid("Transfer-Encoding: chunked\r\nTrailer: X-Private\r\n", fmt.Sprintf("%x\r\n%s\r\n0\r\nX-Private: unknown\r\n\r\n", len(body), body)),
	} {
		if info, err := decodeDockerInfoStdio(raw); err == nil || info != (dockerEngineInfo{}) {
			t.Fatal("unapproved framing or incomplete/ambiguous JSON was admitted")
		}
	}
}
