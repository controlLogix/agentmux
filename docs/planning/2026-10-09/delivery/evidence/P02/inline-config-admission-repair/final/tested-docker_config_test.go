package launcher

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
)

func inlineFixture() composeDocument {
	var c composeDocument
	_ = json.Unmarshal(fixtureBody(), &c)
	s := c.Services["broker"]
	s.Image = "docker.io/library/nats@sha256:" + strings.Repeat("c", 64)
	s.Environment = nil
	s.Command = []string{"--config", "/etc/nats/private.conf"}
	s.Ports = []string{"127.0.0.1:4222:4222"}
	s.Configs = []composeConfigRef{{Source: "private", Target: "/etc/nats/private.conf", UID: "0", GID: "0", Mode: 0400}}
	c.Services["broker"] = s
	c.Configs = map[string]composeConfig{"private": {Content: `{"deny":["$$SYS.>","$$JS.>"]}`}}
	return c
}

func TestInlineConfigAdmission(t *testing.T) {
	cases := []struct {
		name   string
		change func(*composeDocument)
	}{
		{"interpolation", func(c *composeDocument) { c.Configs["private"] = composeConfig{Content: `${PRIVATE_SECRET}`} }},
		{"odd_dollars", func(c *composeDocument) { c.Configs["private"] = composeConfig{Content: `$$$SYS.>`} }},
		{"empty", func(c *composeDocument) { c.Configs["private"] = composeConfig{} }},
		{"nul", func(c *composeDocument) { c.Configs["private"] = composeConfig{Content: "config\x00"} }},
		{"oversized", func(c *composeDocument) {
			c.Configs["private"] = composeConfig{Content: strings.Repeat("x", 64*1024+1)}
		}},
		{"unused", func(c *composeDocument) { c.Configs["extra"] = composeConfig{Content: "private"} }},
		{"target", func(c *composeDocument) {
			s := c.Services["broker"]
			s.Configs[0].Target = "/data/private"
			c.Services["broker"] = s
		}},
		{"mode", func(c *composeDocument) {
			s := c.Services["broker"]
			s.Configs[0].Mode = 0644
			c.Services["broker"] = s
		}},
		{"owner", func(c *composeDocument) {
			s := c.Services["broker"]
			s.Configs[0].UID = "1000"
			c.Services["broker"] = s
		}},
		{"missing", func(c *composeDocument) {
			s := c.Services["broker"]
			s.Configs[0].Source = "absent"
			c.Services["broker"] = s
		}},
		{"duplicate_reference", func(c *composeDocument) {
			s := c.Services["broker"]
			s.Configs = append(s.Configs, s.Configs[0])
			c.Services["broker"] = s
		}},
		{"readonly_layer", func(c *composeDocument) { s := c.Services["broker"]; s.ReadOnly = true; c.Services["broker"] = s }},
	}
	check := func(c composeDocument) error {
		body, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		owner := fixtureOwner()
		owner.ConfigDigest = sha256.Sum256(body)
		return validateCompose(body, owner)
	}
	if err := check(inlineFixture()); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := inlineFixture()
			tc.change(&c)
			if check(c) == nil {
				t.Fatal("unsafe inline configuration accepted")
			}
		})
	}
}

func TestInlineConfigRejectsExternalFile(t *testing.T) {
	c := inlineFixture()
	body, _ := json.Marshal(c)
	var raw map[string]any
	_ = json.Unmarshal(body, &raw)
	raw["configs"].(map[string]any)["private"].(map[string]any)["file"] = "/private/host.conf"
	body, _ = json.Marshal(raw)
	owner := fixtureOwner()
	owner.ConfigDigest = sha256.Sum256(body)
	if validateCompose(body, owner) == nil {
		t.Fatal("host file configuration accepted")
	}
}

func TestInlineConfigDecodedLimit(t *testing.T) {
	if !safeInlineConfig(strings.Repeat("$$", 64*1024)) {
		t.Fatal("valid escaped configuration at decoded limit refused")
	}
	if safeInlineConfig(strings.Repeat("$$", 64*1024+1)) {
		t.Fatal("configuration beyond decoded limit accepted")
	}
}

func TestInlineConfigUnqualifiedComposeDoesNotExecute(t *testing.T) {
	body, _ := json.Marshal(inlineFixture())
	owner := fixtureOwner()
	owner.ConfigDigest = sha256.Sum256(body)
	driver := &Docker{config: DockerConfig{Executable: "/does/not/exist", Versions: DockerVersions{Compose: "5.5.2"}}}
	err := driver.StartOwned(context.Background(), owner, body)
	if err == nil || err.Error() != "docker_inline_config_compose_version_unqualified" {
		t.Fatalf("unexpected version refusal: %v", err)
	}
}

func TestInlineConfigRejectsOtherInterpolation(t *testing.T) {
	changes := map[string]func(*composeService){
		"command":        func(s *composeService) { s.Command = []string{"--config", "${PRIVATE_PATH}"} },
		"command_object": func(s *composeService) { s.Command = map[string]string{"path": "private"} },
		"environment":    func(s *composeService) { s.Environment = map[string]string{"PRIVATE": "${PRIVATE}"} },
		"image":          func(s *composeService) { s.Image = "${PRIVATE_IMAGE}@sha256:" + strings.Repeat("c", 64) },
		"volume":         func(s *composeService) { s.Volumes = []string{"data:/${PRIVATE_PATH}"} },
		"healthcheck":    func(s *composeService) { s.Healthcheck = map[string]any{"test": []string{"CMD", "${PRIVATE}"}} },
		"extra_label":    func(s *composeService) { s.Labels["private"] = "${PRIVATE}" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			c := inlineFixture()
			s := c.Services["broker"]
			change(&s)
			c.Services["broker"] = s
			body, _ := json.Marshal(c)
			owner := fixtureOwner()
			owner.ConfigDigest = sha256.Sum256(body)
			if validateCompose(body, owner) == nil {
				t.Fatal("unqualified inline service accepted")
			}
		})
	}
}

func TestInlineConfigRejectsAmbiguousJSON(t *testing.T) {
	good, _ := json.Marshal(inlineFixture())
	cases := map[string][]byte{
		"duplicate_content":   []byte(strings.Replace(string(good), `"content":`, `"content":"private","content":`, 1)),
		"duplicate_top_level": []byte(`{"configs":{},` + string(good[1:])),
		"invalid_utf8":        []byte(strings.Replace(string(good), "$$SYS", string([]byte{0xff}), 1)),
		"excessive_depth":     []byte(strings.Repeat("[", 33) + "0" + strings.Repeat("]", 33)),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			owner := fixtureOwner()
			owner.ConfigDigest = sha256.Sum256(body)
			if validateCompose(body, owner) == nil {
				t.Fatal("ambiguous JSON accepted")
			}
		})
	}
}
