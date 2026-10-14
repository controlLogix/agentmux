//go:build (linux || darwin) && agentmux_bootstrap_docker

package launcher

import (
	"reflect"
	"strings"
	"testing"
)

// These pure controls prove a separate literal fixture selection. They do not
// discover a daemon, start Docker, or qualify WSL as native Linux.
func TestBootstrapSelectionCurrentWSLQualificationLiteral(t *testing.T) {
	selected := bootstrapCurrentWSLQualificationSelection()
	host := bootstrapFixtureHost{"linux", "amd64", true}
	raw, pin := bootstrapSelectionControlBytes(t, selected)
	actual, err := decodeBootstrapFixtureSelection(raw, pin, host)
	if err != nil || actual != selected || selected.Target == bootstrapLegacyWSLSelection().Target || selected.Docker.EngineID != "772de646-ba89-42ac-8675-45b2025fbdee" {
		t.Fatal("separate current WSL fixture tuple refused or aliased legacy")
	}
	driver := actual.dockerConfig()
	if driver.Backend != WindowsInterop || driver.Executable != bootstrapFixtureDocker || driver.Context != "desktop-linux" || driver.Endpoint != "npipe:////./pipe/dockerDesktopLinuxEngine" || driver.EngineID != selected.Docker.EngineID {
		t.Fatal("current fixture lost its explicitly selected Windows engine")
	}
	plan, err := bootstrapKernelBuild(actual, host, "/review/go", "/review/kernel", []string{"GOOS=windows", "GOARCH=386", "CGO_ENABLED=1", "CC=hostile", "SDKROOT=/wrong"})
	if err != nil || plan.Executable != "/review/go/bin/go" || !reflect.DeepEqual(plan.Args, []string{"build", "-trimpath", "-ldflags=-s -w", "-o", "/review/kernel", "./cmd/agentmux-kernel"}) {
		t.Fatal("current fixture changed fixed native kernel build arguments")
	}
	values := map[string]string{}
	for _, value := range plan.Env {
		key, item, _ := strings.Cut(value, "=")
		values[key] = item
	}
	if values["GOOS"] != "linux" || values["GOARCH"] != "amd64" || values["CGO_ENABLED"] != "0" || values["CC"] != "" || values["SDKROOT"] != "" || values["GOPROXY"] != "off" || values["GOSUMDB"] != "off" {
		t.Fatal("current WSL build adopted caller compiler or cross-target environment")
	}
	legacy := bootstrapLegacyWSLSelection()
	legacyRaw, legacyPin := bootstrapSelectionControlBytes(t, legacy)
	if restored, err := decodeBootstrapFixtureSelection(legacyRaw, legacyPin, host); err != nil || restored != legacy || legacy.Docker.EngineID != "e0f1f93d-abf1-44f2-b62a-5bfee21d2b5c" {
		t.Fatal("legacy WSL literal was replaced")
	}
}

func TestBootstrapSelectionCurrentWSLQualificationRejectsUnapprovedTuples(t *testing.T) {
	base := bootstrapCurrentWSLQualificationSelection()
	host := bootstrapFixtureHost{"linux", "amd64", true}
	changes := map[string]func(*bootstrapFixtureSelection){
		"legacy_target":  func(s *bootstrapFixtureSelection) { s.Target = "wsl-windows-interop" },
		"legacy_engine":  func(s *bootstrapFixtureSelection) { s.Docker.EngineID = bootstrapFixtureEngine },
		"unknown_engine": func(s *bootstrapFixtureSelection) { s.Docker.EngineID = "separately-hashed-but-unapproved" },
		"unknown_target": func(s *bootstrapFixtureSelection) { s.Target = "wsl-auto-discovered" },
		"native_target": func(s *bootstrapFixtureSelection) {
			s.Target = "native-linux"
			s.Docker.Backend = NativeUnix
			s.Docker.Executable = "/review/docker"
			s.Docker.Endpoint = "unix:///review/docker.sock"
		},
		"native_backend":  func(s *bootstrapFixtureSelection) { s.Docker.Backend = NativeUnix },
		"workspace":       func(s *bootstrapFixtureSelection) { s.WorkspaceRoot = "/review/other" },
		"executable":      func(s *bootstrapFixtureSelection) { s.Docker.Executable = "/review/docker.exe" },
		"context":         func(s *bootstrapFixtureSelection) { s.Docker.Context = "other-context" },
		"endpoint":        func(s *bootstrapFixtureSelection) { s.Docker.Endpoint = "npipe:////./pipe/otherEngine" },
		"client_version":  func(s *bootstrapFixtureSelection) { s.Docker.ClientVersion = "29.8.1" },
		"server_version":  func(s *bootstrapFixtureSelection) { s.Docker.ServerVersion = "29.8.1" },
		"compose_version": func(s *bootstrapFixtureSelection) { s.Docker.ComposeVersion = "5.5.2" },
		"image": func(s *bootstrapFixtureSelection) {
			s.Image = "docker.io/library/nats@sha256:" + strings.Repeat("0", 64)
		},
		"nats_version": func(s *bootstrapFixtureSelection) { s.NATSVersion = "2.15.1" },
		"compiler":     func(s *bootstrapFixtureSelection) { s.Compiler = "/usr/bin/clang" },
		"sdk":          func(s *bootstrapFixtureSelection) { s.SDKRoot = "/review/MacOSX.sdk" },
		"goos":         func(s *bootstrapFixtureSelection) { s.GOOS = "darwin" },
		"goarch":       func(s *bootstrapFixtureSelection) { s.GOARCH = "arm64" },
	}
	for name, mutate := range changes {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			// Rehashing caller bytes cannot authorize a different tuple.
			raw, callerPin := bootstrapSelectionControlBytes(t, changed)
			if _, err := decodeBootstrapFixtureSelection(raw, callerPin, host); err == nil || err.Error() != "fixture_selection_invalid_or_unpinned" {
				t.Fatal("caller hash authorized an unapproved current WSL tuple")
			}
		})
	}
}

func TestBootstrapSelectionCurrentWSLQualificationRequiresActualHostAndPin(t *testing.T) {
	selected := bootstrapCurrentWSLQualificationSelection()
	raw, pin := bootstrapSelectionControlBytes(t, selected)
	for _, host := range []bootstrapFixtureHost{{"linux", "amd64", false}, {"linux", "arm64", true}, {"darwin", "amd64", false}, {"windows", "amd64", false}} {
		if _, err := decodeBootstrapFixtureSelection(raw, pin, host); err == nil || err.Error() != "fixture_selection_invalid_or_unpinned" {
			t.Fatal("current WSL fixture admitted another actual platform")
		}
	}
	for _, callerPin := range []string{"", "sha256:" + pin, strings.ToUpper(pin), strings.Repeat("0", 64)} {
		if _, err := decodeBootstrapFixtureSelection(raw, callerPin, bootstrapFixtureHost{"linux", "amd64", true}); err == nil || err.Error() != "fixture_selection_invalid_or_unpinned" {
			t.Fatal("current WSL fixture admitted missing or mismatched pin")
		}
	}
	changed := append(append([]byte(nil), raw...), '\n')
	if _, err := decodeBootstrapFixtureSelection(changed, pin, bootstrapFixtureHost{"linux", "amd64", true}); err == nil || err.Error() != "fixture_selection_invalid_or_unpinned" {
		t.Fatal("changed current selection bytes retained old pin")
	}
}
