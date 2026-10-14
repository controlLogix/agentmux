package launcher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

type DockerBackend string

const (
	NativeUnix     DockerBackend = "native-unix"
	WindowsInterop DockerBackend = "windows-interop"
)

type DockerVersions struct{ Client, Server, Compose string }
type DockerConfig struct {
	Executable, Context, Endpoint, EngineID string
	Versions                                DockerVersions
	Timeout                                 time.Duration
	Backend                                 DockerBackend
}
type DockerInspection struct {
	Backend            DockerBackend
	Endpoint, EngineID string
	Versions           DockerVersions
}
type Docker struct{ config DockerConfig }

// LockHeld is an internal caller assertion. The bootstrap caller must hold the
// actual OS lock throughout preflight and mutation; this field grants no permission.
type OwnershipPreflight struct {
	Project, InstanceID, ReleaseDigest string
	LockHeld                           bool
	ConfigDigest                       [32]byte
}

var slug = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
var digest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var fullID = regexp.MustCompile(`^[0-9a-f]{64}$`)
var version = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
var pipe = regexp.MustCompile(`^npipe:////\./pipe/[A-Za-z0-9_.-]+$`)
var privatePort = regexp.MustCompile(`^127\.0\.0\.1:[1-9][0-9]{0,4}:[1-9][0-9]{0,4}(/tcp|/udp)?$`)

func refusal(code string) error { return errors.New("docker_" + code) }
func NewDocker(c DockerConfig) (*Docker, error) {
	if !filepath.IsAbs(c.Executable) || !slug.MatchString(c.Context) || c.EngineID == "" {
		return nil, refusal("invalid_selection")
	}
	local := c.Backend == WindowsInterop && pipe.MatchString(c.Endpoint)
	if c.Backend == NativeUnix && strings.HasPrefix(c.Endpoint, "unix:///") {
		p := strings.TrimPrefix(c.Endpoint, "unix://")
		local = filepath.IsAbs(p) && filepath.Clean(p) == p && !strings.ContainsAny(p, "%?#\r\n")
	}
	if !local {
		return nil, refusal("nonlocal_endpoint")
	}
	if !version.MatchString(c.Versions.Client) || !version.MatchString(c.Versions.Server) || !version.MatchString(c.Versions.Compose) {
		return nil, refusal("invalid_versions")
	}
	if c.Timeout <= 0 || c.Timeout > 60*time.Second {
		return nil, refusal("invalid_timeout")
	}
	d := &Docker{c}
	if err := d.environment(); err != nil {
		return nil, err
	}
	return d, nil
}
func (d *Docker) environment() error {
	for k, want := range map[string]string{"DOCKER_HOST": d.config.Endpoint, "DOCKER_CONTEXT": d.config.Context} {
		if v := os.Getenv(k); v != "" && v != want {
			return refusal("environment_conflict")
		}
	}
	return nil
}

type limitedOutput struct {
	bytes.Buffer
	exceeded bool
}

func (b *limitedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len()+n > 1024*1024 {
		b.exceeded = true
		return n, nil
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}

// run is private, uses literal arguments, and never returns subprocess text.
func (d *Docker) run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	if err := d.environment(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, d.config.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, d.config.Executable, append([]string{"--context", d.config.Context}, args...)...)
	cmd.WaitDelay = time.Second
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "DOCKER_HOST=") && !strings.HasPrefix(v, "DOCKER_CONTEXT=") {
			cmd.Env = append(cmd.Env, v)
		}
	}
	cmd.Stdin = bytes.NewReader(stdin)
	var out limitedOutput
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, refusal("command_timeout_outcome_unknown")
		}
		return nil, refusal("command_failed")
	}
	if out.exceeded {
		return nil, refusal("output_limit")
	}
	return out.Bytes(), nil
}
func (d *Docker) read(ctx context.Context, dst any, args ...string) error {
	b, e := d.run(ctx, nil, args...)
	if e != nil {
		return e
	}
	if json.Unmarshal(b, dst) != nil {
		return refusal("invalid_observation")
	}
	return nil
}
func (d *Docker) Inspect(ctx context.Context) (DockerInspection, error) {
	var endpoint string
	if e := d.read(ctx, &endpoint, "context", "inspect", d.config.Context, "--format", "{{json .Endpoints.docker.Host}}"); e != nil {
		return DockerInspection{}, e
	}
	if endpoint != d.config.Endpoint {
		return DockerInspection{}, refusal("endpoint_mismatch")
	}
	var v struct{ Client, Server string }
	if e := d.read(ctx, &v, "version", "--format", `{"Client":{{json .Client.Version}},"Server":{{json .Server.Version}}}`); e != nil {
		return DockerInspection{}, e
	}
	var info struct{ ID, OS string }
	if e := d.read(ctx, &info, "info", "--format", `{"ID":{{json .ID}},"OS":{{json .OSType}}}`); e != nil {
		return DockerInspection{}, e
	}
	b, e := d.run(ctx, nil, "compose", "version", "--short")
	if e != nil {
		return DockerInspection{}, e
	}
	got := DockerVersions{v.Client, v.Server, strings.TrimPrefix(strings.TrimSpace(string(b)), "v")}
	if info.ID != d.config.EngineID || info.OS != "linux" || got != d.config.Versions {
		return DockerInspection{}, refusal("backend_mismatch")
	}
	return DockerInspection{d.config.Backend, endpoint, info.ID, got}, nil
}
func (o OwnershipPreflight) valid(lock bool) error {
	if !slug.MatchString(o.Project) || !slug.MatchString(o.InstanceID) || !digest.MatchString(o.ReleaseDigest) || (lock && !o.LockHeld) {
		return refusal("ownership_preflight_missing")
	}
	return nil
}
func (o OwnershipPreflight) matches(labels map[string]string) bool {
	return labels["agentmux.instance.id"] == o.InstanceID && labels["agentmux.release.digest"] == o.ReleaseDigest && labels["com.docker.compose.project"] == o.Project
}
func (o OwnershipPreflight) inputLabels(labels map[string]string) bool {
	for key := range labels {
		if strings.HasPrefix(key, "com.docker.compose.") {
			return false
		}
	}
	return labels["agentmux.instance.id"] == o.InstanceID && labels["agentmux.release.digest"] == o.ReleaseDigest
}
func (d *Docker) labels(ctx context.Context, kind, id string, o OwnershipPreflight) error {
	format := "{{json .Labels}}"
	args := []string{kind, "inspect", id, "--format", format}
	if kind == "container" {
		args = []string{"container", "inspect", id, "--format", "{{json .Config.Labels}}"}
	}
	var labels map[string]string
	if e := d.read(ctx, &labels, args...); e != nil {
		return e
	}
	if !o.matches(labels) {
		return refusal("resource_owner_mismatch")
	}
	return nil
}
func (d *Docker) resources(ctx context.Context, o OwnershipPreflight) error {
	for _, kind := range []string{"container", "volume", "network"} {
		args := []string{kind, "ls", "--quiet", "--filter", "label=com.docker.compose.project=" + o.Project}
		if kind == "container" {
			args = []string{"ps", "--all", "--quiet", "--no-trunc", "--filter", "label=com.docker.compose.project=" + o.Project}
		}
		if kind == "network" {
			args = append(args, "--no-trunc")
		}
		b, e := d.run(ctx, nil, args...)
		if e != nil {
			return e
		}
		for _, id := range strings.Fields(string(b)) {
			if !regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(id) {
				return refusal("invalid_resource_identity")
			}
			if e := d.labels(ctx, kind, id, o); e != nil {
				return e
			}
		}
	}
	return nil
}

// WarmReuse observes only. It never starts, pulls, or restarts resources.
func (d *Docker) WarmReuse(ctx context.Context, o OwnershipPreflight) (DockerInspection, error) {
	if e := o.valid(false); e != nil {
		return DockerInspection{}, e
	}
	i, e := d.Inspect(ctx)
	if e == nil {
		e = d.resources(ctx, o)
	}
	return i, e
}

type composeResource struct {
	Labels   map[string]string `json:"labels"`
	Name     string            `json:"name"`
	External bool              `json:"external"`
}
type composeService struct {
	Image       string             `json:"image"`
	Labels      map[string]string  `json:"labels"`
	Volumes     []string           `json:"volumes"`
	Command     any                `json:"command,omitempty"`
	Environment map[string]string  `json:"environment,omitempty"`
	Ports       []string           `json:"ports,omitempty"`
	Healthcheck any                `json:"healthcheck,omitempty"`
	Restart     string             `json:"restart,omitempty"`
	Configs     []composeConfigRef `json:"configs,omitempty"`
	ReadOnly    bool               `json:"read_only,omitempty"`
}
type composeConfig struct {
	Content string `json:"content"`
}
type composeConfigRef struct {
	Source string `json:"source"`
	Target string `json:"target"`
	UID    string `json:"uid"`
	GID    string `json:"gid"`
	Mode   uint32 `json:"mode"`
}
type composeDocument struct {
	Name     string                     `json:"name,omitempty"`
	Services map[string]composeService  `json:"services"`
	Volumes  map[string]composeResource `json:"volumes,omitempty"`
	Networks map[string]composeResource `json:"networks"`
	Configs  map[string]composeConfig   `json:"configs,omitempty"`
}

// Compose consumes each escaped dollar pair once. A single dollar would permit
// host environment interpolation and break the private configuration binding.
func safeInlineConfig(content string) bool {
	if content == "" || len(content) > 64*1024 || !utf8.ValidString(content) || strings.ContainsRune(content, 0) {
		return false
	}
	for i := 0; i < len(content); i++ {
		if content[i] == '$' {
			if i+1 == len(content) || content[i+1] != '$' {
				return false
			}
			i++
		}
	}
	return true
}

// Inline configuration uses the qualified Compose content mechanism. Compose
// copies it into the container's writable layer; this is not a read-only mount.
// Docker administrators can read that file. Never print the private document.
func validateCompose(body []byte, o OwnershipPreflight) error {
	if len(body) > 1024*1024 || sha256.Sum256(body) != o.ConfigDigest {
		return refusal("config_binding_mismatch")
	}
	var c composeDocument
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if dec.Decode(&c) != nil || dec.Decode(new(any)) != io.EOF {
		return refusal("unsupported_compose")
	}
	if c.Name != "" && c.Name != o.Project || len(c.Services) == 0 {
		return refusal("unsupported_compose")
	}
	if _, ok := c.Networks["default"]; !ok {
		return refusal("default_network_missing")
	}
	for _, resources := range []map[string]composeResource{c.Volumes, c.Networks} {
		for key, r := range resources {
			// Generated project names avoid adopting arbitrary explicitly named resources.
			if !slug.MatchString(key) || r.Name != "" || r.External || !o.inputLabels(r.Labels) {
				return refusal("unowned_compose_resource")
			}
		}
	}
	usedConfigs := make(map[string]bool)
	for key, s := range c.Services {
		parts := strings.Split(s.Image, "@")
		if !slug.MatchString(key) || len(parts) != 2 || parts[0] == "" || !digest.MatchString(parts[1]) || !o.inputLabels(s.Labels) {
			return refusal("unowned_compose_service")
		}
		for _, port := range s.Ports {
			if !privatePort.MatchString(port) {
				return refusal("nonprivate_port")
			}
		}
		for _, mount := range s.Volumes {
			p := strings.Split(mount, ":")
			if len(p) < 2 || len(p) > 3 || !strings.HasPrefix(p[1], "/") || (len(p) == 3 && p[2] != "ro" && p[2] != "rw") {
				return refusal("unsupported_mount")
			}
			if _, ok := c.Volumes[p[0]]; !ok {
				return refusal("unsupported_mount")
			}
		}
		if s.ReadOnly && len(s.Configs) != 0 {
			return refusal("inline_config_requires_writable_layer")
		}
		for _, ref := range s.Configs {
			config, ok := c.Configs[ref.Source]
			if !ok || !slug.MatchString(ref.Source) || usedConfigs[ref.Source] || ref.Target != "/etc/nats/private.conf" || ref.UID != "0" || ref.GID != "0" || ref.Mode != 0400 || !safeInlineConfig(config.Content) {
				return refusal("unsupported_inline_config")
			}
			usedConfigs[ref.Source] = true
		}
	}
	if len(usedConfigs) != len(c.Configs) {
		return refusal("unused_inline_config")
	}
	return nil
}
func (d *Docker) StartOwned(ctx context.Context, o OwnershipPreflight, body []byte) error {
	if e := o.valid(true); e != nil {
		return e
	}
	if e := validateCompose(body, o); e != nil {
		return e
	}
	if _, e := d.WarmReuse(ctx, o); e != nil {
		return e
	}
	// Check generated names too: a foreign resource may lack the project label.
	var c composeDocument
	_ = json.Unmarshal(body, &c)
	// A container with a generated name but missing project labels must not be
	// adopted. Docker name filters may match more broadly; refusing any foreign
	// match is safer than changing it.
	for _, separator := range []string{"_", "-"} {
		b, err := d.run(ctx, nil, "ps", "--all", "--quiet", "--no-trunc", "--filter", "name="+o.Project+separator)
		if err != nil {
			return err
		}
		for _, id := range strings.Fields(string(b)) {
			if !fullID.MatchString(id) {
				return refusal("invalid_resource_identity")
			}
			if e := d.labels(ctx, "container", id, o); e != nil {
				return e
			}
		}
	}
	for kind, resources := range map[string]map[string]composeResource{"volume": c.Volumes, "network": c.Networks} {
		for key := range resources {
			name := o.Project + "_" + key
			b, e := d.run(ctx, nil, kind, "ls", "--quiet", "--filter", "name="+name)
			if e != nil {
				return e
			}
			for _, id := range strings.Fields(string(b)) {
				if e := d.labels(ctx, kind, id, o); e != nil {
					return e
				}
			}
		}
	}
	_, e := d.run(ctx, body, "compose", "--project-name", o.Project, "--file", "-", "up", "--detach", "--wait", "--wait-timeout", "60", "--pull", "never", "--no-build")
	return e
}
func (d *Docker) StopOwned(ctx context.Context, o OwnershipPreflight, id string) error {
	if e := o.valid(true); e != nil {
		return e
	}
	if !fullID.MatchString(id) {
		return refusal("full_container_id_required")
	}
	if _, e := d.Inspect(ctx); e != nil {
		return e
	}
	if e := d.labels(ctx, "container", id, o); e != nil {
		return e
	}
	_, e := d.run(ctx, nil, "container", "stop", "--time", "10", id)
	return e
}
