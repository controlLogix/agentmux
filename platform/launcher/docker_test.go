package launcher

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// The current test executable is a controlled process, never a Docker daemon.
func TestMain(m *testing.M) {
	if os.Getenv("AMX_DOCKER_FIXTURE") != "1" {
		os.Exit(m.Run())
	}
	args := os.Args[1:]
	if len(args) < 3 {
		os.Exit(9)
	}
	literalEndpoint := args[0] == "--host" && args[1] == "unix:///tmp/docker.sock"
	if !literalEndpoint && (args[0] != "--context" || args[1] != "fixture") {
		os.Exit(9)
	}
	args = args[2:]
	if literalEndpoint != (args[0] == "image") {
		os.Exit(9)
	}
	f, _ := os.OpenFile(os.Getenv("AMX_DOCKER_LOG"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	line := strings.Join(args, " ")
	if literalEndpoint {
		line = "literal-endpoint " + line
	}
	_, _ = fmt.Fprintln(f, line)
	_ = f.Close()
	mode := os.Getenv("AMX_DOCKER_MODE")
	if mode == "error" {
		fmt.Fprintln(os.Stderr, "synthetic-private-value")
		os.Exit(4)
	}
	if mode == "timeout" {
		time.Sleep(time.Second)
		os.Exit(0)
	}
	switch args[0] {
	case "image":
		if len(args) != 5 {
			os.Exit(9)
		}
		switch args[1] {
		case "pull":
			if args[2] != "--platform" || args[3] != "linux/arm64" || !pinnedBrokerImage(args[4]) {
				os.Exit(9)
			}
			fmt.Fprintln(os.Stdout, "synthetic-private-pull-output")
			fmt.Fprintln(os.Stderr, "synthetic-private-pull-error")
			if mode == "pull-failed" {
				os.Exit(4)
			}
			if mode == "pull-wait" {
				time.Sleep(5 * time.Second)
			}
		case "inspect":
			if !pinnedBrokerImage(args[2]) || args[3] != "--format" || args[4] != preparedBrokerImageFormat {
				os.Exit(9)
			}
			architecture := "arm64"
			if mode == "image-architecture" {
				architecture = "amd64"
			}
			digest := strings.TrimPrefix(args[2], "docker.io/library/nats@")
			if mode == "image-digest" {
				digest = "sha256:" + strings.Repeat("f", 64)
			}
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ID": "sha256:" + strings.Repeat("a", 64), "RepoDigests": []string{"nats@" + digest}, "OS": "linux", "Architecture": architecture})
		default:
			os.Exit(9)
		}
	case "context":
		if mode == "endpoint" {
			fmt.Println(`"tcp://remote:2375"`)
			break
		}
		if mode == "malformed" {
			fmt.Println(`private invalid output`)
			break
		}
		fmt.Println(`"unix:///tmp/docker.sock"`)
	case "version":
		if mode == "server-version" {
			fmt.Println(`{"Client":"29.8.0","Server":"29.8.1"}`)
			break
		}
		if mode == "version" {
			fmt.Println(`{"Client":"29.8.1","Server":"29.8.0"}`)
			break
		}
		fmt.Println(`{"Client":"29.8.0","Server":"29.8.0"}`)
	case "info":
		if mode == "os" {
			fmt.Println(`{"ID":"fixture-engine","OS":"windows"}`)
			break
		}
		if mode == "engine" {
			fmt.Println(`{"ID":"other","OS":"linux"}`)
		} else {
			fmt.Println(`{"ID":"fixture-engine","OS":"linux"}`)
		}
	case "ps":
		if mode == "hyphen-name-collision" && strings.Contains(strings.Join(args, " "), "name=fixture-") {
			fmt.Println(strings.Repeat("a", 64))
		}
		if mode == "foreign" || mode == "owned" || (mode == "name-collision" && strings.Contains(strings.Join(args, " "), "name=")) {
			fmt.Println(strings.Repeat("a", 64))
		}
	case "volume", "network":
		if mode == "volume-collision" && strings.Contains(strings.Join(args, " "), "name=") {
			fmt.Println("fixture_data")
		}
		if len(args) > 1 && args[1] == "inspect" {
			printFixtureLabels(mode)
		}
	case "container":
		if args[1] == "inspect" {
			printFixtureLabels(mode)
		} else if args[1] != "stop" {
			os.Exit(8)
		}
	case "compose":
		if args[1] == "version" {
			if mode == "compose-version" {
				fmt.Println("5.5.2")
				break
			}
			fmt.Println("5.5.1")
		} else {
			body, _ := io.ReadAll(os.Stdin)
			if sha256.Sum256(body) != sha256.Sum256(fixtureBody()) {
				os.Exit(7)
			}
		}
	default:
		os.Exit(8)
	}
	os.Exit(0)
}
func printFixtureLabels(mode string) {
	o := fixtureOwner()
	if mode == "foreign" || mode == "name-collision" || mode == "volume-collision" || mode == "hyphen-name-collision" {
		o.InstanceID = "foreign"
	}
	_ = json.NewEncoder(os.Stdout).Encode(fixtureLabels(o))
}
func fixtureOwner() OwnershipPreflight {
	return OwnershipPreflight{Project: "fixture", InstanceID: "instance", ReleaseDigest: "sha256:" + strings.Repeat("b", 64), LockHeld: true}
}
func fixtureLabels(o OwnershipPreflight) map[string]string {
	return map[string]string{"agentmux.instance.id": o.InstanceID, "agentmux.release.digest": o.ReleaseDigest, "com.docker.compose.project": o.Project}
}
func fixtureBody() []byte {
	o := fixtureOwner()
	labels := fixtureLabels(o)
	delete(labels, "com.docker.compose.project")
	body, _ := json.Marshal(composeDocument{Services: map[string]composeService{"broker": {Image: "nats@sha256:" + strings.Repeat("c", 64), Labels: labels, Environment: map[string]string{"SECRET": "synthetic-private-value;$(unsafe)"}, Volumes: []string{"data:/data"}}}, Volumes: map[string]composeResource{"data": {Labels: labels}}, Networks: map[string]composeResource{"default": {Labels: labels}}})
	return body
}
func setupDocker(t *testing.T) (*Docker, OwnershipPreflight, string) {
	t.Helper()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	log := t.TempDir() + "/commands"
	t.Setenv("AMX_DOCKER_FIXTURE", "1")
	t.Setenv("AMX_DOCKER_LOG", log)
	t.Setenv("AMX_DOCKER_MODE", "")
	t.Setenv("DOCKER_HOST", "")
	t.Setenv("DOCKER_CONTEXT", "")
	d, e := NewDocker(DockerConfig{Executable: exe, Context: "fixture", Endpoint: "unix:///tmp/docker.sock", EngineID: "fixture-engine", Versions: DockerVersions{"29.8.0", "29.8.0", "5.5.1"}, Backend: NativeUnix, Timeout: 2 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	o := fixtureOwner()
	o.ConfigDigest = sha256.Sum256(fixtureBody())
	return d, o, log
}
func commands(path string) string { b, _ := os.ReadFile(path); return string(b) }
func noMutation(t *testing.T, path string) {
	t.Helper()
	s := commands(path)
	if strings.Contains(s, " up ") || strings.Contains(s, " stop ") {
		t.Fatalf("unexpected mutation: %s", s)
	}
}
func TestDockerOwnedBoundaries(t *testing.T) {
	t.Run("cold literal stdin", func(t *testing.T) {
		d, o, log := setupDocker(t)
		if e := d.StartOwned(context.Background(), o, fixtureBody()); e != nil {
			t.Fatal(e)
		}
		if !strings.Contains(commands(log), "--pull never --no-build") {
			t.Fatal("missing mutation flags")
		}
	})
	t.Run("warm is read only", func(t *testing.T) {
		d, o, log := setupDocker(t)
		t.Setenv("AMX_DOCKER_MODE", "owned")
		o.LockHeld = false
		if _, e := d.WarmReuse(context.Background(), o); e != nil {
			t.Fatal(e)
		}
		noMutation(t, log)
	})
	for _, mode := range []string{"foreign", "engine", "error", "endpoint", "version", "server-version", "compose-version", "os", "malformed", "name-collision", "hyphen-name-collision", "volume-collision"} {
		t.Run(mode, func(t *testing.T) {
			d, o, log := setupDocker(t)
			t.Setenv("AMX_DOCKER_MODE", mode)
			e := d.StartOwned(context.Background(), o, fixtureBody())
			if e == nil {
				t.Fatal("accepted mismatch")
			}
			if strings.Contains(e.Error(), "synthetic-private-value") {
				t.Fatal("private error leaked")
			}
			noMutation(t, log)
		})
	}
	t.Run("changed environment", func(t *testing.T) {
		d, o, log := setupDocker(t)
		t.Setenv("DOCKER_HOST", "tcp://remote:2375")
		if d.StartOwned(context.Background(), o, fixtureBody()) == nil {
			t.Fatal("accepted remote override")
		}
		if commands(log) != "" {
			t.Fatal("ran subprocess")
		}
	})
	t.Run("missing lock", func(t *testing.T) {
		d, o, log := setupDocker(t)
		o.LockHeld = false
		if d.StartOwned(context.Background(), o, fixtureBody()) == nil {
			t.Fatal("accepted unlocked mutation")
		}
		if commands(log) != "" {
			t.Fatal("ran subprocess")
		}
	})
	t.Run("changed bytes", func(t *testing.T) {
		d, o, log := setupDocker(t)
		if d.StartOwned(context.Background(), o, append(fixtureBody(), ' ')) == nil {
			t.Fatal("accepted changed bytes")
		}
		if commands(log) != "" {
			t.Fatal("ran subprocess")
		}
	})
	t.Run("stop requires full identity", func(t *testing.T) {
		d, o, log := setupDocker(t)
		if d.StopOwned(context.Background(), o, "aaaa") == nil {
			t.Fatal("accepted abbreviated ID")
		}
		if commands(log) != "" {
			t.Fatal("ran subprocess")
		}
		if e := d.StopOwned(context.Background(), o, strings.Repeat("a", 64)); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("stop fresh ownership", func(t *testing.T) {
		d, o, log := setupDocker(t)
		t.Setenv("AMX_DOCKER_MODE", "foreign")
		if d.StopOwned(context.Background(), o, strings.Repeat("a", 64)) == nil {
			t.Fatal("accepted foreign stop")
		}
		noMutation(t, log)
	})
	t.Run("timeout redacted", func(t *testing.T) {
		d, _, log := setupDocker(t)
		d.config.Timeout = 20 * time.Millisecond
		t.Setenv("AMX_DOCKER_MODE", "timeout")
		start := time.Now()
		_, e := d.Inspect(context.Background())
		if e == nil || !strings.Contains(e.Error(), "outcome_unknown") || time.Since(start) > 2*time.Second {
			t.Fatal("timeout not bounded")
		}
		noMutation(t, log)
	})
}
func TestDockerConfigAdmission(t *testing.T) {
	for _, change := range []string{"bind", "external", "unlabeled", "explicit name", "unsupported", "reserved label", "public port"} {
		t.Run(change, func(t *testing.T) {
			d, o, log := setupDocker(t)
			var c map[string]any
			_ = json.Unmarshal(fixtureBody(), &c)
			switch change {
			case "public port":
				c["services"].(map[string]any)["broker"].(map[string]any)["ports"] = []string{"4222:4222"}
			case "reserved label":
				c["services"].(map[string]any)["broker"].(map[string]any)["labels"].(map[string]any)["com.docker.compose.project"] = "fixture"
			case "bind":
				c["services"].(map[string]any)["broker"].(map[string]any)["volumes"] = []string{"/host:/data"}
			case "external":
				c["volumes"].(map[string]any)["data"].(map[string]any)["external"] = true
			case "unlabeled":
				delete(c["networks"].(map[string]any)["default"].(map[string]any), "labels")
			case "explicit name":
				c["volumes"].(map[string]any)["data"].(map[string]any)["name"] = "foreign"
			case "unsupported":
				c["services"].(map[string]any)["broker"].(map[string]any)["privileged"] = true
			}
			body, _ := json.Marshal(c)
			o.ConfigDigest = sha256.Sum256(body)
			if d.StartOwned(context.Background(), o, body) == nil {
				t.Fatal("accepted unsafe config")
			}
			if commands(log) != "" {
				t.Fatal("ran subprocess before config refusal")
			}
		})
	}
}
func TestDockerSelection(t *testing.T) {
	d, _, _ := setupDocker(t)
	for _, endpoint := range []string{"tcp://remote:2375", "ssh://host", "unix:///tmp/../docker.sock"} {
		c := d.config
		c.Endpoint = endpoint
		if _, e := NewDocker(c); e == nil {
			t.Fatal("accepted remote or alias")
		}
	}
	c := d.config
	c.Backend = WindowsInterop
	c.Endpoint = "npipe:////./pipe/dockerDesktopLinuxEngine"
	if _, e := NewDocker(c); e != nil {
		t.Fatal(e)
	}
	c.Endpoint = "npipe:////remote/pipe/docker"
	if _, e := NewDocker(c); e == nil {
		t.Fatal("accepted remote pipe")
	}
}
