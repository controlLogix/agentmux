//go:build linux || darwin

package launcher

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This owned executable is a controlled CLI fixture, never a Docker daemon.
func init() {
	if os.Getenv("AMX_WINDOWS_INSPECTION_FIXTURE") != "1" {
		return
	}
	args := os.Args[1:]
	if len(args) < 3 || args[0] != "--context" || args[1] != "windows-fixture" {
		os.Exit(80)
	}
	args = args[2:]
	file, err := os.OpenFile(os.Getenv("AMX_WINDOWS_INSPECTION_LOG"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		os.Exit(81)
	}
	fmt.Fprintln(file, strings.Join(args, " "))
	file.Close()
	mode := os.Getenv("AMX_WINDOWS_INSPECTION_MODE")
	switch strings.Join(args, " ") {
	case "context inspect windows-fixture --format {{json .Endpoints.docker.Host}}":
		if mode == "endpoint" {
			fmt.Println(`"npipe:////./pipe/other"`)
		} else {
			fmt.Println(`"npipe:////./pipe/windows-fixture"`)
		}
	case "version --format " + dockerVersionReadFormat:
		client, server := "29.8.0", "29.8.0"
		if mode == "client" {
			client = "29.9.0"
		}
		if mode == "server" {
			server = "29.9.0"
		}
		fmt.Printf("{\"Client\":%q,\"Server\":%q}\n", client, server)
	case "compose version --short":
		if mode == "compose" {
			fmt.Println("5.5.2")
		} else {
			fmt.Println("5.5.1")
		}
	case "system dial-stdio":
		reader := bufio.NewReader(os.Stdin)
		var request strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				os.Exit(82)
			}
			request.WriteString(line)
			if line == "\r\n" {
				break
			}
		}
		if request.String() != dockerInfoStdioRequest {
			os.Exit(83)
		}
		body := `{"ID":"fixture-engine","OSType":"linux","ServerVersion":"29.8.0"}`
		if mode == "engine" {
			body = strings.Replace(body, "fixture-engine", "unselected-engine", 1)
		}
		fmt.Printf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	default:
		os.Exit(84)
	}
	os.Exit(0)
}

func TestDockerWindowsInspectionVerifiesSelectionBeforeStdio(t *testing.T) {
	for _, mode := range []string{"valid", "endpoint", "client", "server", "compose", "engine"} {
		t.Run(mode, func(t *testing.T) {
			for _, key := range []string{"DOCKER_HOST", "DOCKER_CONTEXT", "AMX_DOCKER_FIXTURE", "AMX_DOCKER_READS_FIXTURE", "AMX_BROKER_INSPECT_FIXTURE", "AMX_STDIO_FIXTURE"} {
				t.Setenv(key, "")
			}
			t.Setenv("AMX_WINDOWS_INSPECTION_FIXTURE", "1")
			t.Setenv("AMX_WINDOWS_INSPECTION_MODE", mode)
			t.Setenv("GORACE", "atexit_sleep_ms=0")
			log := filepath.Join(t.TempDir(), "commands")
			t.Setenv("AMX_WINDOWS_INSPECTION_LOG", log)
			exe, err := os.Executable()
			if err != nil {
				t.Fatal("fixture executable unavailable")
			}
			d, err := NewDocker(DockerConfig{Executable: exe, Context: "windows-fixture", Endpoint: "npipe:////./pipe/windows-fixture", EngineID: "fixture-engine", Versions: DockerVersions{"29.8.0", "29.8.0", "5.5.1"}, Timeout: 4 * time.Second, Backend: WindowsInterop})
			if err != nil {
				t.Fatal("fixture selection refused")
			}
			actual, err := d.Inspect(context.Background())
			if mode == "valid" {
				if err != nil || actual.EngineID != "fixture-engine" || actual.Versions != d.config.Versions {
					t.Fatal("qualified Windows inspection failed")
				}
			} else if err == nil || actual != (DockerInspection{}) {
				t.Fatal("invalid selected identity returned trusted observations")
			}
			raw, err := os.ReadFile(log)
			if err != nil {
				t.Fatal("actual command evidence missing")
			}
			lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
			if lines[0] != "context inspect windows-fixture --format {{json .Endpoints.docker.Host}}" || strings.Contains(string(raw), "info --format") {
				t.Fatal("inspection bypassed endpoint admission or used the slow fallback")
			}
			usedStdio := strings.Contains(string(raw), "system dial-stdio")
			if usedStdio != (mode == "valid" || mode == "engine") || (mode == "endpoint" && len(lines) != 1) {
				t.Fatal("hidden transport ran before endpoint and version admission")
			}
		})
	}
}
