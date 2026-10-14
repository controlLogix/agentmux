package deployment

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const PrivateConfigTarget = "/etc/nats/private.conf"
const MaxPrivateConfigBytes = 64 * 1024

// ComposeSpec describes one enrolled local broker. The caller must independently
// qualify the host port, image, profile ownership and release before startup.
// BrokerConfig and rendered bytes contain credentials and must never be logged.
type ComposeSpec struct {
	Project, InstanceID, ProfileID, ReleaseDigest, Image string
	HostPort                                             int
	BrokerConfig                                         []byte
	ReadOnlyRootFS                                       bool
}

var composeIdentifier = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
var composeProfile = regexp.MustCompile(`^profile_[0-9a-f]{32}$`)
var composeRelease = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var composeImage = regexp.MustCompile(`^docker\.io/library/nats@sha256:[0-9a-f]{64}$`)

type renderedResource struct {
	Labels map[string]string `json:"labels"`
}
type renderedConfig struct {
	Content string `json:"content"`
}
type renderedConfigRef struct {
	Source string `json:"source"`
	Target string `json:"target"`
	UID    string `json:"uid"`
	GID    string `json:"gid"`
	Mode   uint32 `json:"mode"`
}
type renderedBroker struct {
	Image   string              `json:"image"`
	Labels  map[string]string   `json:"labels"`
	Command []string            `json:"command"`
	Ports   []string            `json:"ports"`
	Volumes []string            `json:"volumes"`
	Configs []renderedConfigRef `json:"configs"`
}
type renderedCompose struct {
	Name     string                      `json:"name"`
	Services map[string]renderedBroker   `json:"services"`
	Volumes  map[string]renderedResource `json:"volumes"`
	Networks map[string]renderedResource `json:"networks"`
	Configs  map[string]renderedConfig   `json:"configs"`
}

// RenderCompose returns deterministic private JSON for Compose stdin. It neither
// starts Docker nor proves readiness. Compose 5.5.1 copies inline content into
// the container filesystem as a 0400 root-owned file, not a read-only mount.
// Container root and Docker administrators can access that writable-layer file;
// exports and commits can retain it. Inline injection requires a writable root
// filesystem. The launcher must bind these exact bytes to its owned preflight.
func RenderCompose(s ComposeSpec) ([]byte, error) {
	if !composeIdentifier.MatchString(s.Project) || !composeIdentifier.MatchString(s.InstanceID) || !composeProfile.MatchString(s.ProfileID) || !composeRelease.MatchString(s.ReleaseDigest) {
		return nil, errors.New("compose_identity_invalid")
	}
	if !composeImage.MatchString(s.Image) {
		return nil, errors.New("compose_image_not_pinned_official_nats")
	}
	if s.HostPort < 1 || s.HostPort > 65535 {
		return nil, errors.New("compose_port_invalid")
	}
	if s.ReadOnlyRootFS {
		return nil, errors.New("compose_inline_config_requires_writable_root")
	}
	if len(s.BrokerConfig) == 0 || len(s.BrokerConfig) > MaxPrivateConfigBytes || !utf8.Valid(s.BrokerConfig) || bytes.IndexByte(s.BrokerConfig, 0) >= 0 {
		return nil, errors.New("compose_private_config_invalid")
	}
	labels := map[string]string{"agentmux.instance.id": s.InstanceID, "agentmux.profile.id": s.ProfileID, "agentmux.release.digest": s.ReleaseDigest}
	document := renderedCompose{
		Name:     s.Project,
		Services: map[string]renderedBroker{"nats": {Image: s.Image, Labels: labels, Command: []string{"--config", PrivateConfigTarget}, Ports: []string{"127.0.0.1:" + strconv.Itoa(s.HostPort) + ":4222"}, Volumes: []string{"data:/data"}, Configs: []renderedConfigRef{{Source: "broker_config", Target: PrivateConfigTarget, UID: "0", GID: "0", Mode: 0400}}}},
		Volumes:  map[string]renderedResource{"data": {Labels: labels}},
		Networks: map[string]renderedResource{"default": {Labels: labels}},
		Configs:  map[string]renderedConfig{"broker_config": {Content: strings.ReplaceAll(string(s.BrokerConfig), "$", "$$")}},
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(document) != nil {
		return nil, errors.New("compose_encode_failed")
	}
	return out.Bytes(), nil
}
