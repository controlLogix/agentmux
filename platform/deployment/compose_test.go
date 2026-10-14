package deployment

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func composeFixture() ComposeSpec {
	return ComposeSpec{Project: "amx-test", InstanceID: "instance-test", ProfileID: "profile_" + strings.Repeat("c", 32), ReleaseDigest: "sha256:" + strings.Repeat("a", 64), Image: "docker.io/library/nats@sha256:" + strings.Repeat("b", 64), HostPort: 4223, BrokerConfig: []byte("# synthetic private configuration\npassword: \"synthetic-secret\"\n$SYS.> $JS.> ${HOME} $NAME $$ $$$ $ \"<&>\" café\n")}
}

// This independent scan applies the documented Compose dollar-pair rule. It
// refuses a bare dollar instead of accidentally expanding ambient variables.
func unescapeComposePairs(t *testing.T, s string) string {
	t.Helper()
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '$' {
			if i+1 >= len(s) || s[i+1] != '$' {
				t.Fatal("unpaired dollar in rendered content")
			}
			i++
		}
		out.WriteByte(s[i])
	}
	return out.String()
}
func TestComposePrivateDeterministicShape(t *testing.T) {
	s := composeFixture()
	body, e := RenderCompose(s)
	if e != nil {
		t.Fatal(e)
	}
	again, e := RenderCompose(s)
	if e != nil || !bytes.Equal(body, again) {
		t.Fatal("renderer is not deterministic")
	}
	var c renderedCompose
	if json.Unmarshal(body, &c) != nil {
		t.Fatal("invalid JSON")
	}
	if c.Name != s.Project || len(c.Services) != 1 || len(c.Volumes) != 1 || len(c.Networks) != 1 || len(c.Configs) != 1 {
		t.Fatal("unexpected stack inventory")
	}
	n := c.Services["nats"]
	if n.Image != s.Image || len(n.Ports) != 1 || n.Ports[0] != "127.0.0.1:4223:4222" || len(n.Volumes) != 1 || n.Volumes[0] != "data:/data" || len(n.Command) != 2 || n.Command[0] != "--config" || n.Command[1] != PrivateConfigTarget {
		t.Fatal("unsafe broker shape")
	}
	if len(n.Configs) != 1 || n.Configs[0] != (renderedConfigRef{Source: "broker_config", Target: PrivateConfigTarget, UID: "0", GID: "0", Mode: 256}) {
		t.Fatal("private config reference changed")
	}
	for _, labels := range []map[string]string{n.Labels, c.Volumes["data"].Labels, c.Networks["default"].Labels} {
		if len(labels) != 3 || labels["agentmux.profile.id"] != s.ProfileID || labels["agentmux.instance.id"] != s.InstanceID || labels["agentmux.release.digest"] != s.ReleaseDigest {
			t.Fatal("resource identity missing")
		}
		for key := range labels {
			if strings.HasPrefix(key, "com.docker.compose.") {
				t.Fatal("reserved Compose label")
			}
		}
	}
	content := c.Configs["broker_config"].Content
	if unescapeComposePairs(t, content) != string(s.BrokerConfig) {
		t.Fatal("configuration bytes changed after unescaping")
	}
	s.BrokerConfig[0] = '!'
	if !bytes.Equal(body, again) {
		t.Fatal("returned bytes alias input")
	}
}
func TestComposeDollarAndSizeBoundaries(t *testing.T) {
	for _, value := range []string{"$", "$$", "$$$", "${SECRET}", "$SYS.>\n$JS.>", strings.Repeat("$", MaxPrivateConfigBytes), strings.Repeat("é", MaxPrivateConfigBytes/2)} {
		s := composeFixture()
		s.BrokerConfig = []byte(value)
		body, e := RenderCompose(s)
		if e != nil {
			t.Fatal(e)
		}
		var c renderedCompose
		_ = json.Unmarshal(body, &c)
		if unescapeComposePairs(t, c.Configs["broker_config"].Content) != value {
			t.Fatal("boundary bytes changed")
		}
	}
}
func TestComposeRejectsUnsafeInputsWithoutPrivateErrors(t *testing.T) {
	cases := []struct {
		name   string
		change func(*ComposeSpec)
	}{
		{"project interpolation", func(s *ComposeSpec) { s.Project = "${SECRET}" }},
		{"instance whitespace", func(s *ComposeSpec) { s.InstanceID = "bad instance" }},
		{"missing profile", func(s *ComposeSpec) { s.ProfileID = "" }},
		{"invalid profile", func(s *ComposeSpec) { s.ProfileID = "profile_" + strings.Repeat("G", 32) }},
		{"short profile", func(s *ComposeSpec) { s.ProfileID = "profile_abc" }},
		{"release tag", func(s *ComposeSpec) { s.ReleaseDigest = "latest" }},
		{"floating image", func(s *ComposeSpec) { s.Image = "nats:latest" }},
		{"foreign repository", func(s *ComposeSpec) { s.Image = "example.org/nats@sha256:" + strings.Repeat("b", 64) }},
		{"zero port", func(s *ComposeSpec) { s.HostPort = 0 }},
		{"port above range", func(s *ComposeSpec) { s.HostPort = 65536 }},
		{"readonly root", func(s *ComposeSpec) { s.ReadOnlyRootFS = true }},
		{"empty config", func(s *ComposeSpec) { s.BrokerConfig = nil }},
		{"oversized config", func(s *ComposeSpec) { s.BrokerConfig = bytes.Repeat([]byte{'a'}, MaxPrivateConfigBytes+1) }},
		{"invalid UTF8", func(s *ComposeSpec) { s.BrokerConfig = []byte{0xff} }},
		{"NUL", func(s *ComposeSpec) { s.BrokerConfig = []byte("synthetic-secret\x00") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := composeFixture()
			c.change(&s)
			body, e := RenderCompose(s)
			if e == nil || body != nil {
				t.Fatal("unsafe input accepted")
			}
			if strings.Contains(e.Error(), "synthetic-secret") || strings.Contains(e.Error(), "${SECRET}") {
				t.Fatal("private input leaked in error")
			}
		})
	}
}
