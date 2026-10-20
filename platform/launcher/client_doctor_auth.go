package launcher

import (
	"context"
	"encoding/json"
	"io"
	"regexp"
	"strings"
)

var clientCodexLogin = regexp.MustCompile(`(?i)^Logged in using (?:ChatGPT|an API key(?: - [^\r\n]+)?)$`)

func runClientAuth(ctx context.Context, client string) ClientDoctorCheck {
	raw, exit, code := runClientProbe(ctx, client, true)
	if code != "observed" {
		check := clientAuthUnknown(code)
		if code == "client_missing" {
			check.Status = DoctorUnavailable
		}
		if code == "version_pipe_cleanup_incomplete" {
			check.Code = "auth_pipe_cleanup_incomplete"
			check.Action = "Check sign-in in the native client. Its output pipe exceeded the cleanup limit; descendant exit was not established."
		}
		return check
	}
	return parseClientAuth(client, raw, exit)
}

func clientAuthUnknown(code string) ClientDoctorCheck {
	return ClientDoctorCheck{Name: "authentication", Status: DoctorUnknown, Code: code, Action: "Check sign-in inside the native client. Do not copy credentials."}
}

func parseClientAuth(client, raw string, exit int) ClientDoctorCheck {
	check := clientAuthUnknown("native_auth_status_unknown")
	signedOut, signedIn := false, false
	if len(raw) > 65536 {
		return check
	}
	switch client {
	case "codex":
		value := strings.TrimSpace(raw)
		signedOut = (exit == 0 || exit == 1) && strings.EqualFold(value, "Not logged in")
		signedIn = exit == 0 && clientCodexLogin.MatchString(value)
	case "claude":
		// Reject duplicate top-level status fields instead of accepting the last one.
		// Account fields are discarded and never included in the report.
		decoder := json.NewDecoder(strings.NewReader(raw))
		token, err := decoder.Token()
		if err != nil || token != json.Delim('{') {
			return check
		}
		values := map[string]json.RawMessage{}
		for decoder.More() {
			token, err = decoder.Token()
			if err != nil {
				return check
			}
			key, ok := token.(string)
			if !ok {
				return check
			}
			if _, exists := values[key]; exists {
				return check
			}
			var value json.RawMessage
			if decoder.Decode(&value) != nil {
				return check
			}
			values[key] = value
		}
		if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
			return check
		}
		if _, err = decoder.Token(); err != io.EOF {
			return check
		}
		var logged *bool
		var method string
		if json.Unmarshal(values["loggedIn"], &logged) != nil || logged == nil || json.Unmarshal(values["authMethod"], &method) != nil {
			return check
		}
		signedOut = !*logged && method == "none" && (exit == 0 || exit == 1)
		switch method {
		case "claude.ai", "oauth_token", "api_key", "api_key_helper", "third_party":
			signedIn = *logged && exit == 0
		}
	default:
		return clientAuthUnknown("native_client_check_required")
	}
	if signedOut {
		check.Status = DoctorUnavailable
		check.Code = "native_not_authenticated"
		check.Action = "Sign in through the native client in your own terminal, keeping the same configuration home."
	}
	if signedIn {
		check.Status = DoctorPassed
		check.Code = "native_auth_observed"
		check.Action = "Native client reports signed in; provider usability was not tested."
	}
	return check
}
