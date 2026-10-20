package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type clientDoctorFixtureInfo struct{}

func (clientDoctorFixtureInfo) Name() string       { return "fixture" }
func (clientDoctorFixtureInfo) Size() int64        { return 1 }
func (clientDoctorFixtureInfo) Mode() os.FileMode  { return 0600 }
func (clientDoctorFixtureInfo) ModTime() time.Time { return time.Time{} }
func (clientDoctorFixtureInfo) IsDir() bool        { return false }
func (clientDoctorFixtureInfo) Sys() any           { return nil }

func TestClientDoctorFixedClientsAndNativeReferences(t *testing.T) {
	cases := []struct{ client, version, env, path string }{
		{"codex", "codex-cli 0.162.1", "CODEX_HOME", "config.toml"},
		{"claude", "2.1.301 (Claude Code)", "CLAUDE_CONFIG_DIR", "settings.json"},
		{"pi", "1.3.0", "PI_CODING_AGENT_DIR", "settings.json"},
		{"claude-desktop", "", "", "Library/Application Support/Claude/claude_desktop_config.json"},
	}
	for _, tc := range cases {
		t.Run(tc.client, func(t *testing.T) {
			calls := 0
			report := runClientDoctor(context.Background(), tc.client, true, clientDoctorDependencies{
				version: func(ctx context.Context, client string) (string, string) {
					calls++
					if client != tc.client {
						t.Fatal("wrong fixed selection")
					}
					return tc.version, "observed"
				},
				getenv: func(key string) string {
					if key == "HOME" {
						return "/fixture/home"
					}
					if key == tc.env {
						return "/fixture/custom root"
					}
					return ""
				},
				stat: func(path string) (os.FileInfo, error) {
					want := filepath.Join("/fixture/custom root", tc.path)
					if tc.client == "claude-desktop" {
						want = filepath.Join("/fixture/home", tc.path)
					}
					if path != want {
						t.Fatalf("wrong metadata reference: %q", path)
					}
					return clientDoctorFixtureInfo{}, nil
				},
			})
			if report.DiagnosticsPassed || report.HealthVersion != 1 || report.Checks[2].Code != "native_client_check_required" {
				t.Fatal("authentication or readiness overclaimed")
			}
			if report.Checks[1].Code != "native_config_reference_present" {
				t.Fatal("metadata missing")
			}
			if tc.client == "claude-desktop" {
				if calls != 0 || report.Checks[0].Status != DoctorUnknown {
					t.Fatal("Desktop lookup inferred")
				}
			} else if calls != 1 || report.Checks[0].Status != DoctorPassed {
				t.Fatal("version not observed")
			}
		})
	}
}

func TestClientDoctorNoEffectsOnInvalidSelectionHostOrContext(t *testing.T) {
	deps := clientDoctorDependencies{version: func(context.Context, string) (string, string) { t.Fatal("unexpected command"); return "", "" }, getenv: func(string) string { t.Fatal("unexpected environment lookup"); return "" }, stat: func(string) (os.FileInfo, error) { t.Fatal("unexpected metadata lookup"); return nil, nil }}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		ctx    context.Context
		client string
		native bool
		code   string
	}{
		{context.Background(), "SENTINEL; sh", true, "invalid_client"},
		{context.Background(), "codex", false, "unsupported_host"},
		{nil, "codex", true, "invalid_context"},
		{ctx, "codex", true, "cancelled"},
	} {
		report := runClientDoctor(tc.ctx, tc.client, tc.native, deps)
		if report.Checks[0].Code != tc.code || report.DiagnosticsPassed {
			t.Fatal("wrong refusal")
		}
		raw, _ := json.Marshal(report)
		if strings.Contains(string(raw), "SENTINEL") {
			t.Fatal("selection leaked")
		}
	}
}

func TestClientDoctorUnknownAndMissingStayUnknown(t *testing.T) {
	for _, raw := range []string{"Not a version SENTINEL", "2.1.301 (Claude Code)", "codex-cli 1234567890.2.3"} {
		report := runClientDoctor(context.Background(), "codex", true, clientDoctorDependencies{
			version: func(context.Context, string) (string, string) { return raw, "observed" },
			getenv: func(key string) string {
				if key == "HOME" {
					return "/fixture/home"
				}
				return ""
			},
			stat: func(path string) (os.FileInfo, error) {
				if path != "/fixture/home/.codex/config.toml" {
					t.Fatal("wrong default home")
				}
				return nil, os.ErrNotExist
			},
		})
		if report.Checks[0].Status == DoctorPassed || report.DiagnosticsPassed || report.Checks[1].Code != "optional_native_config_absent" {
			t.Fatal("unknown check passed")
		}
		encoded, _ := json.Marshal(report)
		if strings.Contains(string(encoded), "SENTINEL") || strings.Contains(string(encoded), "/fixture") {
			t.Fatal("private diagnostic leaked")
		}
	}
}

func TestClientDoctorOutputIsBoundedAndCancels(t *testing.T) {
	cancelled := 0
	out := clientDoctorOutput{cancel: func() { cancelled++ }}
	if n, err := out.Write([]byte(strings.Repeat("x", 65536))); n != 65536 || err != nil {
		t.Fatal("bounded write failed")
	}
	out.Write([]byte("overflow"))
	out.Write([]byte("again"))
	if len(out.data) != 65536 || !out.exceeded || cancelled == 0 {
		t.Fatal("output was not bounded")
	}
}

func TestClientDoctorVersionHonorsExpiredDeadlineWithoutProcess(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	raw, code := runClientVersion(ctx, "codex")
	if raw != "" || code != "deadline_exceeded" {
		t.Fatal("expired deadline not refused")
	}
	raw, code = runClientVersion(context.Background(), "SENTINEL")
	if raw != "" || code != "invalid_client" {
		t.Fatal("invalid selection not refused")
	}
}

func TestClientDoctorPiTildeMetadataOnly(t *testing.T) {
	report := runClientDoctor(context.Background(), "pi", true, clientDoctorDependencies{
		version: func(context.Context, string) (string, string) { return "", "client_missing" },
		getenv: func(key string) string {
			if key == "HOME" {
				return "/fixture/home"
			}
			if key == "PI_CODING_AGENT_DIR" {
				return "~/custom pi"
			}
			return ""
		},
		stat: func(path string) (os.FileInfo, error) {
			if path != "/fixture/home/custom pi/settings.json" {
				t.Fatal("tilde root not expanded")
			}
			return clientDoctorFixtureInfo{}, nil
		},
	})
	if report.Checks[0].Status != DoctorUnavailable || report.DiagnosticsPassed {
		t.Fatal("missing client passed")
	}
}

func TestClientDoctorInheritedPipeExpiryStaysUnknown(t *testing.T) {
	raw, code := clientVersionResult(context.Background(), exec.ErrWaitDelay, &clientDoctorOutput{data: []byte("PRIVATE_SENTINEL")})
	if raw != "" || code != "version_pipe_cleanup_incomplete" {
		t.Fatal("pipe expiry was not distinguished without private output")
	}
	report := runClientDoctor(context.Background(), "codex", true, clientDoctorDependencies{
		version: func(context.Context, string) (string, string) { return raw, code },
		getenv: func(key string) string {
			if key == "HOME" {
				return "/fixture/home"
			}
			return ""
		},
		stat: func(string) (os.FileInfo, error) { return clientDoctorFixtureInfo{}, nil },
	})
	if report.DiagnosticsPassed || report.Checks[0].Status != DoctorUnknown || report.Checks[0].Code != code || !strings.Contains(report.Checks[0].Action, "descendant exit was not established") {
		t.Fatal("pipe expiry overclaimed process cleanup")
	}
}

func TestClientDoctorInsufficientCleanupBudgetDoesNotStartVersion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	raw, code := runClientVersion(ctx, "codex")
	if raw != "" || code != "deadline_exceeded" {
		t.Fatal("version probe started without reserved reader cleanup budget")
	}
}

type clientDoctorBrokenReader struct{}

func (clientDoctorBrokenReader) Read([]byte) (int, error) { return 0, errors.New("PRIVATE_READ_ERROR") }

func TestClientDoctorOutputRequiresObservedEOF(t *testing.T) {
	complete := &clientDoctorOutput{cancel: func() {}}
	if _, err := complete.ReadFrom(strings.NewReader("safe version")); err != nil || !complete.readerEOF {
		t.Fatal("EOF was not recorded")
	}
	incomplete := &clientDoctorOutput{cancel: func() {}}
	if _, err := incomplete.ReadFrom(clientDoctorBrokenReader{}); err == nil || incomplete.readerEOF {
		t.Fatal("failed read was marked complete")
	}
	for _, failure := range []error{nil, &exec.ExitError{}} {
		raw, _, code := clientProbeResult(context.Background(), failure, incomplete)
		if raw != "" || code != "version_pipe_cleanup_incomplete" {
			t.Fatal("exit status masked incomplete reader")
		}
	}
	raw, _, code := clientProbeResult(context.Background(), nil, &clientDoctorOutput{})
	if raw != "" || code != "version_pipe_cleanup_incomplete" {
		t.Fatal("bypassed ReadFrom did not fail closed")
	}
}
