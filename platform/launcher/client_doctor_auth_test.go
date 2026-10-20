package launcher

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestClientDoctorNativeAuthParsers(t *testing.T) {
	for _, tc := range []struct {
		client, raw string
		exit        int
		status      DoctorStatus
		code        string
	}{
		{"codex", "Not logged in", 1, DoctorUnavailable, "native_not_authenticated"},
		{"codex", "Logged in using ChatGPT", 0, DoctorPassed, "native_auth_observed"},
		{"codex", "Logged in using an API key - PRIVATE_SENTINEL", 0, DoctorPassed, "native_auth_observed"},
		{"codex", "Not logged in\nLogged in using ChatGPT", 0, DoctorUnknown, "native_auth_status_unknown"},
		{"codex", "Logged in using ChatGPT", 1, DoctorUnknown, "native_auth_status_unknown"},
		{"claude", `{"loggedIn":false,"authMethod":"none"}`, 1, DoctorUnavailable, "native_not_authenticated"},
		{"claude", `{"loggedIn":true,"authMethod":"claude.ai","email":"PRIVATE_SENTINEL"}`, 0, DoctorPassed, "native_auth_observed"},
		{"claude", `{"loggedIn":false,"loggedIn":true,"authMethod":"claude.ai"}`, 0, DoctorUnknown, "native_auth_status_unknown"},
		{"claude", `{"loggedIn":"true","authMethod":"claude.ai"}`, 0, DoctorUnknown, "native_auth_status_unknown"},
		{"claude", `{"loggedIn":true,"authMethod":"future"}`, 0, DoctorUnknown, "native_auth_status_unknown"},
		{"claude", `{"loggedIn":true,"authMethod":"claude.ai"}`, 1, DoctorUnknown, "native_auth_status_unknown"},
		{"claude", `{"loggedIn":true,"authMethod":"claude.ai"} {}`, 0, DoctorUnknown, "native_auth_status_unknown"},
		{"pi", "PRIVATE_SENTINEL", 0, DoctorUnknown, "native_client_check_required"},
	} {
		check := parseClientAuth(tc.client, tc.raw, tc.exit)
		if check.Status != tc.status || check.Code != tc.code {
			t.Fatalf("wrong safe auth result: %s %s", check.Status, check.Code)
		}
		raw, _ := json.Marshal(check)
		if strings.Contains(string(raw), "PRIVATE_SENTINEL") {
			t.Fatal("private native status leaked")
		}
	}
}

func TestClientDoctorAuthSharesVersionDeadlineAndOptionalConfigStaysUnknown(t *testing.T) {
	var versionDeadline time.Time
	report := runClientDoctor(context.Background(), "codex", true, clientDoctorDependencies{
		version: func(ctx context.Context, _ string) (string, string) {
			var ok bool
			versionDeadline, ok = ctx.Deadline()
			if !ok || time.Until(versionDeadline) > time.Second {
				t.Fatal("missing bounded selected-client deadline")
			}
			return "codex-cli 0.162.1", "observed"
		},
		auth: func(ctx context.Context, _ string) ClientDoctorCheck {
			deadline, _ := ctx.Deadline()
			if !deadline.Equal(versionDeadline) {
				t.Fatal("auth widened the selected-client deadline")
			}
			return parseClientAuth("codex", "Logged in using ChatGPT", 0)
		},
		getenv: func(key string) string {
			if key == "HOME" {
				return "/fixture"
			}
			return ""
		},
		stat: func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
	})
	if report.Checks[2].Status != DoctorPassed || report.Checks[1].Code != "optional_native_config_absent" || report.Checks[1].Status != DoctorUnknown || report.DiagnosticsPassed {
		t.Fatal("optional metadata was confused with authentication")
	}
}

func TestClientDoctorAuthCancellationHasNoProcess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	check := runClientAuth(ctx, "codex")
	if check.Status != DoctorUnknown || check.Code != "cancelled" {
		t.Fatal("cancelled auth probe not refused")
	}
	raw, _, code := runClientProbe(context.Background(), "pi", true)
	if raw != "" || code != "invalid_client" {
		t.Fatal("unsupported auth probe was executed")
	}
}
