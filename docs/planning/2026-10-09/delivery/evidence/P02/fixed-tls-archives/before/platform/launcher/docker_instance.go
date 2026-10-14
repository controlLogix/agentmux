package launcher

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"regexp"
	"strconv"
)

// OwnedBroker reports observed process state, never authenticated readiness.
type OwnedBroker struct {
	ContainerID string
	State       string
}
type brokerPort struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}
type brokerMount struct {
	Type, Name, Destination string
	RW                      bool
}
type brokerInspection struct {
	ID     string `json:"Id"`
	Image  string
	Config struct {
		Image  string
		Labels map[string]string
	}
	State struct {
		Status                      string
		Running, Paused, Restarting bool
	}
	HostConfig      struct{ PortBindings map[string][]brokerPort }
	NetworkSettings struct{ Ports map[string][]brokerPort }
	Mounts          []brokerMount
}

var brokerImagePin = regexp.MustCompile(`^docker\.io/library/nats@sha256:[0-9a-f]{64}$`)
var brokerProfileID = regexp.MustCompile(`^profile_[0-9a-f]{32}$`)
var brokerTarTime = regexp.MustCompile(`^-?[0-9]{1,20}(\.[0-9]{1,9})?$`)

const brokerInspectFormat = `{"Id":{{json .Id}},"Image":{{json .Image}},"Config":{"Image":{{json .Config.Image}},"Labels":{"agentmux.profile.id":{{json (index .Config.Labels "agentmux.profile.id")}},"agentmux.instance.id":{{json (index .Config.Labels "agentmux.instance.id")}},"agentmux.release.digest":{{json (index .Config.Labels "agentmux.release.digest")}},"com.docker.compose.project":{{json (index .Config.Labels "com.docker.compose.project")}},"com.docker.compose.service":{{json (index .Config.Labels "com.docker.compose.service")}},"com.docker.compose.oneoff":{{json (index .Config.Labels "com.docker.compose.oneoff")}}}},"State":{"Status":{{json .State.Status}},"Running":{{json .State.Running}},"Paused":{{json .State.Paused}},"Restarting":{{json .State.Restarting}}},"HostConfig":{"PortBindings":{{json .HostConfig.PortBindings}}},"NetworkSettings":{"Ports":{{json .NetworkSettings.Ports}}},"Mounts":[{{range $i,$m := .Mounts}}{{if $i}},{{end}}{"Type":{{json $m.Type}},"Name":{{json $m.Name}},"Destination":{{json $m.Destination}},"RW":{{json $m.RW}}}{{end}}]}`

// InspectOwnedBroker is read-only. Expected image and config identity come from
// the trusted bootstrap caller, not labels. Private config is read as an archive
// in memory only; errors never contain archive bytes, paths or credentials.
func (d *Docker) InspectOwnedBroker(ctx context.Context, o OwnershipPreflight, expectedImage string, hostPort int, expectedConfig [32]byte) (OwnedBroker, error) {
	if ctx == nil {
		return OwnedBroker{}, refusal("inspection_context_missing")
	}
	if e := o.valid(false); e != nil {
		return OwnedBroker{}, e
	}
	if !brokerProfileID.MatchString(o.ProfileID) || !brokerImagePin.MatchString(expectedImage) || hostPort < 1 || hostPort > 65535 || expectedConfig == ([32]byte{}) {
		return OwnedBroker{}, refusal("broker_expectation_invalid")
	}
	if _, e := d.Inspect(ctx); e != nil {
		return OwnedBroker{}, e
	}
	ids := map[string]bool{}
	reads, e := d.parallelReads(ctx,
		[]string{"ps", "--all", "--quiet", "--no-trunc", "--filter", "label=com.docker.compose.project=" + o.Project},
		[]string{"ps", "--all", "--quiet", "--no-trunc", "--filter", "name=" + o.Project + "_"},
		[]string{"ps", "--all", "--quiet", "--no-trunc", "--filter", "name=" + o.Project + "-"})
	if e != nil {
		return OwnedBroker{}, e
	}
	for _, b := range reads {
		for _, id := range bytes.Fields(b) {
			s := string(id)
			if !fullID.MatchString(s) {
				return OwnedBroker{}, refusal("broker_id_invalid")
			}
			ids[s] = true
		}
	}
	if len(ids) == 0 {
		return OwnedBroker{State: "absent"}, nil
	}
	if len(ids) != 1 {
		return OwnedBroker{}, refusal("broker_roster_mismatch")
	}
	var id string
	for key := range ids {
		id = key
	}
	var actual brokerInspection
	if e := d.read(ctx, &actual, "container", "inspect", id, "--format", brokerInspectFormat); e != nil {
		return OwnedBroker{}, e
	}
	// No environment, command, mount source or arbitrary label value is captured.
	if actual.ID != id || actual.Config.Labels["agentmux.profile.id"] != o.ProfileID || !o.matches(actual.Config.Labels) || actual.Config.Labels["com.docker.compose.service"] != "nats" || actual.Config.Labels["com.docker.compose.oneoff"] != "False" || actual.Config.Image != expectedImage {
		return OwnedBroker{}, refusal("broker_identity_mismatch")
	}
	var imageID string
	if e := d.read(ctx, &imageID, "image", "inspect", expectedImage, "--format", "{{json .Id}}"); e != nil {
		return OwnedBroker{}, e
	}
	if imageID == "" || actual.Image != imageID {
		return OwnedBroker{}, refusal("broker_image_mismatch")
	}
	state := "stopped"
	if actual.State.Paused || actual.State.Restarting {
		return OwnedBroker{}, refusal("broker_state_unsupported")
	}
	switch actual.State.Status {
	case "running":
		if !actual.State.Running {
			return OwnedBroker{}, refusal("broker_state_inconsistent")
		}
		state = "running"
	case "created", "exited":
		if actual.State.Running {
			return OwnedBroker{}, refusal("broker_state_inconsistent")
		}
	default:
		return OwnedBroker{}, refusal("broker_state_unsupported")
	}
	want := brokerPort{HostIP: "127.0.0.1", HostPort: strconv.Itoa(hostPort)}
	bindings := actual.HostConfig.PortBindings["4222/tcp"]
	if len(actual.HostConfig.PortBindings) != 1 || len(bindings) != 1 || bindings[0] != want {
		return OwnedBroker{}, refusal("broker_port_mismatch")
	}
	for target, ports := range actual.NetworkSettings.Ports {
		if len(ports) > 0 && (target != "4222/tcp" || len(ports) != 1 || ports[0] != want) {
			return OwnedBroker{}, refusal("broker_active_port_mismatch")
		}
	}
	if state == "running" {
		ports := actual.NetworkSettings.Ports["4222/tcp"]
		if len(ports) != 1 || ports[0] != want {
			return OwnedBroker{}, refusal("broker_active_port_mismatch")
		}
	}
	if len(actual.Mounts) != 1 || actual.Mounts[0] != (brokerMount{Type: "volume", Name: o.Project + "_data", Destination: "/data", RW: true}) {
		return OwnedBroker{}, refusal("broker_data_mount_mismatch")
	}
	if e := d.labels(ctx, "volume", o.Project+"_data", o); e != nil {
		return OwnedBroker{}, e
	}
	raw, e := d.run(ctx, nil, "cp", id+":/etc/nats/private.conf", "-")
	if e != nil {
		return OwnedBroker{}, e
	}
	if e := verifyBrokerConfigArchive(raw, expectedConfig); e != nil {
		return OwnedBroker{}, e
	}
	return OwnedBroker{ContainerID: id, State: state}, nil
}
func verifyBrokerConfigArchive(raw []byte, expected [32]byte) error {
	return verifyPrivateFileArchive(raw, expected, "private.conf", 64*1024)
}

// Name and limits come only from fixed owned-broker inspection operations.
// Each archive must contain one exact regular root-owned private file.
func verifyPrivateFileArchive(raw []byte, expected [32]byte, name string, max int64) error {
	if expected == ([32]byte{}) || max < 1 || max > 64*1024 {
		return refusal("broker_config_archive_invalid")
	}
	input := bytes.NewReader(raw)
	reader := tar.NewReader(input)
	h, e := reader.Next()
	if e != nil || h.Name != name || (h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA) || h.Linkname != "" || h.Mode != 0400 || h.Uid != 0 || h.Gid != 0 || h.Size <= 0 || h.Size > max || len(h.Xattrs) != 0 {
		return refusal("broker_config_archive_invalid")
	}
	// Standard timestamp metadata is harmless; path/identity overrides and unknown
	// metadata are refused. No metadata is retained in the returned observation.
	for key, value := range h.PAXRecords {
		if (key != "mtime" && key != "atime" && key != "ctime") || !brokerTarTime.MatchString(value) {
			return refusal("broker_config_archive_metadata_invalid")
		}
	}
	body, e := io.ReadAll(io.LimitReader(reader, max+1))
	if e != nil || int64(len(body)) != h.Size || sha256.Sum256(body) != expected {
		return refusal("broker_config_identity_mismatch")
	}
	if _, e = reader.Next(); e != io.EOF {
		return refusal("broker_config_archive_extra_entry")
	}
	tail, _ := io.ReadAll(input)
	for _, b := range tail {
		if b != 0 {
			return refusal("broker_config_archive_trailing_data")
		}
	}
	return nil
}
