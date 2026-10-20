package launcher

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// Test-only dispatch happens before the package's existing TestMain. This is
// the current test executable acting as a controlled CLI, never real Docker.
func init() {
	if os.Getenv("AMX_BROKER_INSPECT_FIXTURE") == "1" {
		brokerInspectProcess()
		os.Exit(0)
	}
}
func instanceOwner() OwnershipPreflight {
	return OwnershipPreflight{Project: "instance-fixture", InstanceID: "instance", ProfileID: "profile_" + strings.Repeat("f", 32), ReleaseDigest: "sha256:" + strings.Repeat("b", 64)}
}
func instanceImage() string  { return "docker.io/library/nats@sha256:" + strings.Repeat("c", 64) }
func instanceConfig() []byte { return []byte("synthetic-private-credential-config\n") }
func instanceID() string     { return strings.Repeat("a", 64) }
func brokerInspectProcess() {
	args := os.Args[1:]
	if len(args) < 3 || args[0] != "--context" || args[1] != "instance-fixture" {
		os.Exit(3)
	}
	args = args[2:]
	if path := os.Getenv("AMX_BROKER_INSPECT_ARGV_LOG"); path != "" {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			os.Exit(19)
		}
		raw, err := json.Marshal(os.Args)
		if err != nil {
			os.Exit(19)
		}
		_, writeErr := file.Write(append(raw, '\n'))
		if closeErr := file.Close(); writeErr != nil || closeErr != nil {
			os.Exit(19)
		}
	}
	mode := os.Getenv("AMX_BROKER_INSPECT_MODE")
	f, _ := os.OpenFile(os.Getenv("AMX_BROKER_INSPECT_LOG"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	_, _ = fmt.Fprintln(f, args[0])
	_ = f.Close()
	switch args[0] {
	case "context":
		fmt.Println(`"unix:///tmp/inspect.sock"`)
	case "version":
		fmt.Println(`{"Client":"29.8.0","Server":"29.8.0"}`)
	case "info":
		fmt.Println(`{"ID":"instance-engine","OS":"linux"}`)
	case "compose":
		if len(args) != 3 || args[1] != "version" {
			os.Exit(8)
		}
		fmt.Println("5.5.1")
	case "ps":
		if mode == "query-error" {
			fmt.Fprintln(os.Stderr, "synthetic-private-credential-config")
			os.Exit(1)
		}
		if mode == "absent" {
			return
		}
		if mode == "foreign-hyphen" {
			if strings.Contains(strings.Join(args, " "), "name=instance-fixture-") {
				fmt.Println(instanceID())
			}
			return
		}
		fmt.Println(instanceID())
		if mode == "multiple" {
			fmt.Println(strings.Repeat("b", 64))
		}
	case "container":
		if args[1] != "inspect" {
			os.Exit(8)
		}
		o := instanceOwner()
		a := brokerInspection{ID: instanceID(), Image: "sha256:" + strings.Repeat("d", 64)}
		a.Config.Image = instanceImage()
		a.Config.Labels = map[string]string{"agentmux.profile.id": o.ProfileID, "agentmux.instance.id": o.InstanceID, "agentmux.release.digest": o.ReleaseDigest, "com.docker.compose.project": o.Project, "com.docker.compose.service": "nats", "com.docker.compose.oneoff": "False"}
		a.State.Status = "running"
		a.State.Running = true
		a.HostConfig.PortBindings = map[string][]brokerPort{"4222/tcp": {{HostIP: "127.0.0.1", HostPort: "43210"}}}
		a.NetworkSettings.Ports = a.HostConfig.PortBindings
		a.Mounts = []brokerMount{{Type: "volume", Name: o.Project + "_data", Destination: "/data", RW: true}}
		switch mode {
		case "stopped":
			a.State.Status = "exited"
			a.State.Running = false
			a.NetworkSettings.Ports = nil
		case "created":
			a.State.Status = "created"
			a.State.Running = false
			a.NetworkSettings.Ports = nil
		case "foreign-hyphen":
			delete(a.Config.Labels, "agentmux.instance.id")
		case "missing-profile":
			delete(a.Config.Labels, "agentmux.profile.id")
		case "foreign-profile":
			a.Config.Labels["agentmux.profile.id"] = "profile_" + strings.Repeat("e", 32)
		case "other-service":
			a.Config.Labels["com.docker.compose.service"] = "worker"
		case "one-off":
			a.Config.Labels["com.docker.compose.oneoff"] = "True"
		case "image":
			a.Config.Image = "nats:latest"
		case "actual-image":
			a.Image = "sha256:" + strings.Repeat("e", 64)
		case "paused":
			a.State.Paused = true
		case "restarting":
			a.State.Status = "restarting"
			a.State.Restarting = true
		case "dead":
			a.State.Status = "dead"
			a.State.Running = false
		case "inconsistent":
			a.State.Running = false
		case "public-port":
			a.HostConfig.PortBindings = map[string][]brokerPort{"4222/tcp": {{HostIP: "0.0.0.0", HostPort: "43210"}}}
		case "other-port":
			a.HostConfig.PortBindings = map[string][]brokerPort{"4222/tcp": {{HostIP: "127.0.0.1", HostPort: "43211"}}}
		case "active-port":
			a.NetworkSettings.Ports = map[string][]brokerPort{"4222/tcp": {{HostIP: "0.0.0.0", HostPort: "43210"}}}
		case "missing-volume":
			a.Mounts = nil
		case "foreign-volume":
			a.Mounts[0].Name = "foreign_data"
		case "extra-mount":
			a.Mounts = append(a.Mounts, brokerMount{Type: "bind", Destination: "/other"})
		}
		_ = json.NewEncoder(os.Stdout).Encode(a)
	case "image":
		fmt.Println(`"sha256:` + strings.Repeat("d", 64) + `"`)
	case "volume":
		o := instanceOwner()
		if mode == "volume-profile" {
			o.ProfileID = "profile_" + strings.Repeat("e", 32)
		}
		if mode == "volume-label" {
			o.InstanceID = "foreign"
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"agentmux.profile.id": o.ProfileID, "agentmux.instance.id": o.InstanceID, "agentmux.release.digest": o.ReleaseDigest, "com.docker.compose.project": o.Project})
	case "cp":
		if os.Getenv("AMX_BROKER_TLS_ARCHIVES") == "1" && len(args) == 3 && args[2] == "-" && (args[1] == instanceID()+":/etc/nats/server-cert.pem" || args[1] == instanceID()+":/etc/nats/server-key.pem") {
			name := strings.TrimPrefix(args[1], instanceID()+":/etc/nats/")
			_, _ = os.Stdout.Write(tlsInstanceArchive(name, mode))
		} else {
			_, _ = os.Stdout.Write(instanceArchive(mode))
		}
	default:
		os.Exit(8)
	}
}
func instanceArchive(mode string) []byte {
	body := instanceConfig()
	h := tar.Header{Name: "private.conf", Mode: 0400, Size: int64(len(body)), Typeflag: tar.TypeReg}
	switch mode {
	case "tar-name":
		h.Name = "../private.conf"
	case "tar-mode":
		h.Mode = 0444
	case "tar-owner":
		h.Uid = 1000
	case "tar-link":
		h.Typeflag = tar.TypeSymlink
		h.Linkname = "/other"
		h.Size = 0
		body = nil
	case "tar-size":
		body = bytes.Repeat([]byte{'a'}, 64*1024+1)
		h.Size = int64(len(body))
	case "tar-digest":
		body = []byte("different private data")
		h.Size = int64(len(body))
	case "tar-pax":
		h.PAXRecords = map[string]string{"comment": "unapproved"}
		h.Format = tar.FormatPAX
	}
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	_ = w.WriteHeader(&h)
	_, _ = w.Write(body)
	if mode == "tar-extra" {
		_ = w.WriteHeader(&tar.Header{Name: "other", Mode: 0400, Size: 1, Typeflag: tar.TypeReg})
		_, _ = w.Write([]byte{'x'})
	}
	_ = w.Close()
	if mode == "tar-tail" {
		_, _ = b.Write([]byte("extra private data"))
	}
	return b.Bytes()
}
func instanceSetup(t *testing.T, mode string) (*Docker, string) {
	t.Helper()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	log := t.TempDir() + "/reads"
	t.Setenv("AMX_BROKER_INSPECT_FIXTURE", "1")
	t.Setenv("AMX_BROKER_INSPECT_MODE", mode)
	t.Setenv("AMX_BROKER_INSPECT_LOG", log)
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	t.Setenv("DOCKER_HOST", "")
	t.Setenv("DOCKER_CONTEXT", "")
	d, e := NewDocker(DockerConfig{Executable: exe, Context: "instance-fixture", Endpoint: "unix:///tmp/inspect.sock", EngineID: "instance-engine", Versions: DockerVersions{"29.8.0", "29.8.0", "5.5.1"}, Backend: NativeUnix, Timeout: 2 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	return d, log
}
func TestOwnedBrokerReadOnlyStates(t *testing.T) {
	for _, mode := range []string{"running", "stopped", "created", "absent"} {
		t.Run(mode, func(t *testing.T) {
			d, log := instanceSetup(t, mode)
			got, e := d.InspectOwnedBroker(context.Background(), instanceOwner(), instanceImage(), 43210, sha256.Sum256(instanceConfig()))
			if e != nil {
				t.Fatal(e)
			}
			want := mode
			if mode == "created" {
				want = "stopped"
			}
			if got.State != want || (mode != "absent" && got.ContainerID != instanceID()) || (mode == "absent" && got.ContainerID != "") {
				t.Fatal("wrong observed state")
			}
			b, _ := os.ReadFile(log)
			for _, name := range strings.Fields(string(b)) {
				if name != "context" && name != "version" && name != "info" && name != "compose" && name != "ps" && name != "container" && name != "image" && name != "volume" && name != "cp" {
					t.Fatal("unexpected command")
				}
			}
		})
	}
}
func TestOwnedBrokerRefusesUnverifiableState(t *testing.T) {
	for _, mode := range []string{"query-error", "foreign-hyphen", "multiple", "missing-profile", "foreign-profile", "volume-profile", "other-service", "one-off", "image", "actual-image", "paused", "restarting", "dead", "inconsistent", "public-port", "other-port", "active-port", "missing-volume", "foreign-volume", "extra-mount", "volume-label", "tar-name", "tar-mode", "tar-owner", "tar-link", "tar-size", "tar-digest", "tar-pax", "tar-extra", "tar-tail"} {
		t.Run(mode, func(t *testing.T) {
			d, _ := instanceSetup(t, mode)
			got, e := d.InspectOwnedBroker(context.Background(), instanceOwner(), instanceImage(), 43210, sha256.Sum256(instanceConfig()))
			if e == nil || got.State != "" || got.ContainerID != "" {
				t.Fatal("unverifiable observation accepted")
			}
			if strings.Contains(e.Error(), "synthetic-private") || strings.Contains(e.Error(), "different private") {
				t.Fatal("private data in error")
			}
		})
	}
}
func TestOwnedBrokerMissingExpectations(t *testing.T) {
	d, log := instanceSetup(t, "absent")
	for _, profile := range []string{"", "profile_bad", "profile_" + strings.Repeat("F", 32)} {
		o := instanceOwner()
		o.ProfileID = profile
		if _, e := d.InspectOwnedBroker(context.Background(), o, instanceImage(), 43210, sha256.Sum256(instanceConfig())); e == nil {
			t.Fatal("unknown profile identity accepted")
		}
	}
	for _, port := range []int{0, 65536} {
		if _, e := d.InspectOwnedBroker(context.Background(), instanceOwner(), instanceImage(), port, sha256.Sum256(instanceConfig())); e == nil {
			t.Fatal("bad port accepted")
		}
	}
	if _, e := d.InspectOwnedBroker(context.Background(), instanceOwner(), instanceImage(), 43210, [32]byte{}); e == nil {
		t.Fatal("unknown config identity accepted")
	}
	if _, e := d.InspectOwnedBroker(nil, instanceOwner(), instanceImage(), 43210, sha256.Sum256(instanceConfig())); e == nil {
		t.Fatal("nil context accepted")
	}
	b, _ := os.ReadFile(log)
	if len(b) != 0 {
		t.Fatal("subprocess before expectation validation")
	}
}
