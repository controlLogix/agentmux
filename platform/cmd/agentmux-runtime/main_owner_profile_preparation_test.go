//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/launcher"
	"golang.org/x/sys/unix"
)

func ownerPreparationTestDocument() map[string]any {
	digest := "sha256:" + strings.Repeat("a", 64)
	return map[string]any{
		"schemaVersion":          "1.0.0",
		"owner":                  map[string]any{"schemaVersion": "1.0.0", "ownerUid": os.Geteuid(), "principalId": "approved_owner", "authenticatedIdentityRef": map[string]any{"id": "approved_identity", "ownerHubId": "approved_hub", "revision": 1}, "scope": map[string]any{"organizationId": "approved_org", "projectId": nil, "workspaceId": nil}, "instanceId": "instance_" + strings.Repeat("b", 32), "profileId": "profile_" + strings.Repeat("a", 32), "releaseFingerprint": digest},
		"context":                map[string]any{"environment": "Development"},
		"clientInstallationId":   strings.Repeat("c", 64),
		"approvedWorkspaceRoots": []string{"/private/approved-repository"},
		"release":                map[string]any{"packageDirectory": "/private/approved-release", "publicKeyHex": strings.Repeat("d", 64), "releaseManifestDigest": digest, "releaseAuthority": map[string]any{"id": "approved_release", "ownerHubId": "approved_hub", "revision": 1}, "releaseVersion": "1.2.3", "kernelApiMajor": 1},
		"runtimeExecutable":      map[string]any{"path": "/private/approved-release/agentmux-runtime", "digest": digest},
		"docker":                 map[string]any{"backend": "native-unix", "executable": "/usr/local/bin/docker", "context": "approved", "endpoint": "unix:///private/docker.sock", "engineId": "approved-engine", "clientVersion": "29.1.0", "serverVersion": "29.1.0", "composeVersion": "5.5.1"},
		"hostPort":               14222, "composeProject": "agentmux_approved", "serverName": "approved_server", "domain": "approved_domain", "maxMemoryBytes": 1048576, "maxFileBytes": 4194304,
		"limits": map[string]any{"startupMilliseconds": 10000, "probeMilliseconds": 1000, "roleStartMilliseconds": 2000, "stopGraceMilliseconds": 1000, "reapMilliseconds": 1000},
	}
}

func ownerPreparationTestArgs(t *testing.T) ([]string, []byte) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(ownerPreparationTestDocument())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "request.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return []string{"prepare-owner-profile", "--request", path, "--request-sha256", ownerPreparationSHA(raw)}, raw
}

func ownerPreparationDecodeResult(t *testing.T, output []byte) ownerPreparationCommandResult {
	t.Helper()
	var result ownerPreparationCommandResult
	if json.Unmarshal(output, &result) != nil || result.Kind != "owner-profile-preparation-result" || bytes.Count(output, []byte{'\n'}) != 1 {
		t.Fatal("invalid command result")
	}
	for _, private := range []string{"approved_owner", "approved_hub", "/private/", "profile_", "instance_", "Development", "PRIVATE"} {
		if bytes.Contains(output, []byte(private)) {
			t.Fatal("private request or cause appeared in result")
		}
	}
	return result
}

func TestOwnerPreparationCommandArguments(t *testing.T) {
	args, _ := ownerPreparationTestArgs(t)
	for _, apply := range []bool{false, true} {
		selected := append([]string(nil), args...)
		if apply {
			selected = append(selected, "--apply")
		}
		parsed, err := parseOwnerProfilePreparation(selected)
		if err != nil || parsed.path != args[2] || parsed.digest != args[4] || parsed.apply != apply {
			t.Fatal("explicit arguments changed")
		}
	}
	for _, selected := range [][]string{nil, {"prepare-owner-profile"}, args[:3], append(append([]string(nil), args...), "--apply", "--apply"), append(append([]string(nil), args...), "--apply=false"), append(append([]string(nil), args...), "--request=x"), append(append([]string(nil), args...), "--password=x"), {args[0], "--request", "relative", "--request-sha256", args[4]}, {args[0], "--request", args[2], "--request-sha256", strings.TrimPrefix(args[4], "sha256:")}, append(append([]string(nil), args...), "extra")} {
		called := false
		var output bytes.Buffer
		err := runOwnerProfilePreparationWith(context.Background(), selected, &output, func(context.Context, launcher.OwnerProfilePreparationRequest) (ownerPreparationCommandOwner, error) {
			called = true
			return nil, nil
		})
		if err == nil || called || output.Len() != 0 {
			t.Fatal("invalid arguments reached preparation")
		}
	}
}

func TestOwnerPreparationRecoveryPreviewRequiresExplicitApply(t *testing.T) {
	args, _ := ownerPreparationTestArgs(t)
	args[0] = "recover-owner-profile"
	for _, apply := range []bool{false, true} {
		selected := append([]string(nil), args...)
		if apply {
			selected = append(selected, "--apply")
		}
		called := false
		owner := &centralRegistrationTestOwner{}
		var output bytes.Buffer
		err := runOwnerProfilePreparationWith(context.Background(), selected, &output, func(context.Context, launcher.OwnerProfilePreparationRequest) (ownerPreparationCommandOwner, error) {
			called = true
			return owner, nil
		})
		if err != nil || called != apply {
			t.Fatal("recovery apply boundary changed", err)
		}
		result := ownerPreparationDecodeResult(t, output.Bytes())
		if !apply && result.Outcome != "request_checked" || apply && (result.Outcome != "prepared" || owner.closes != 1) {
			t.Fatal("recovery preview or close behavior changed")
		}
	}
}

func TestOwnerPreparationClosedRequest(t *testing.T) {
	document := ownerPreparationTestDocument()
	raw, _ := json.Marshal(document)
	q, err := decodeOwnerPreparationRequest(raw)
	if err != nil || q.Context.Project != nil || q.Context.Environment == nil || *q.Context.Environment != "Development" || q.Owner.Scope.ProjectID != nil || q.StartupTimeout != 10*time.Second {
		t.Fatal("approved request changed", err)
	}
	for _, kind := range []string{"extra", "password", "private-key", "owner-alias", "owner-extra", "scope-missing", "context-null", "context-empty", "context-absent", "authority-extra", "docker-extra", "limit-overflow", "frontend-host", "other-release-host", "missing", "duplicate", "trailing", "null"} {
		t.Run(kind, func(t *testing.T) {
			d := ownerPreparationTestDocument()
			switch kind {
			case "frontend-host":
				d["runtimeExecutable"].(map[string]any)["path"] = "/Library/Application Support/Agentmux/Protected/agentmux-runtime"
			case "other-release-host":
				d["runtimeExecutable"].(map[string]any)["path"] = "/private/other-release/agentmux-runtime"
			case "extra":
				d["authority"] = "invented"
			case "password":
				d["password"] = "PRIVATE"
			case "private-key":
				d["release"].(map[string]any)["privateKey"] = "PRIVATE"
			case "owner-alias":
				d["owner"].(map[string]any)["PrincipalId"] = "other"
			case "owner-extra":
				d["owner"].(map[string]any)["accessToken"] = "PRIVATE"
			case "scope-missing":
				delete(d["owner"].(map[string]any)["scope"].(map[string]any), "projectId")
			case "context-null":
				d["context"].(map[string]any)["project"] = nil
			case "context-empty":
				d["context"].(map[string]any)["environment"] = ""
			case "context-absent":
				d["context"] = map[string]any{}
			case "authority-extra":
				d["release"].(map[string]any)["releaseAuthority"].(map[string]any)["grant"] = "invented"
			case "docker-extra":
				d["docker"].(map[string]any)["password"] = "PRIVATE"
			case "limit-overflow":
				d["limits"].(map[string]any)["startupMilliseconds"] = int64(9223372036854775807)
			case "missing":
				delete(d, "release")
			}
			raw, _ := json.Marshal(d)
			if kind == "duplicate" {
				raw = append([]byte(`{"schemaVersion":"1.0.0",`), raw[1:]...)
			}
			if kind == "trailing" {
				raw = append(raw, []byte(`{}`)...)
			}
			if kind == "null" {
				raw = []byte(`null`)
			}
			if _, err := decodeOwnerPreparationRequest(raw); err == nil {
				t.Fatal("invalid or credential-bearing request accepted")
			}
		})
	}
}

func TestOwnerPreparationCommandPreviewAndApply(t *testing.T) {
	for _, apply := range []bool{false, true} {
		t.Run(fmt.Sprint(apply), func(t *testing.T) {
			args, raw := ownerPreparationTestArgs(t)
			if apply {
				args = append(args, "--apply")
			}
			called := 0
			owner := &centralRegistrationTestOwner{}
			var output bytes.Buffer
			err := runOwnerProfilePreparationWith(context.Background(), args, &output, func(ctx context.Context, q launcher.OwnerProfilePreparationRequest) (ownerPreparationCommandOwner, error) {
				called++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 8500*time.Millisecond || time.Until(deadline) < 7*time.Second {
					t.Fatal("preparation did not retain the outer work budget")
				}
				if q.Owner.PrincipalID != "approved_owner" || q.Docker.Context != "approved" || q.Release.ReleaseVersion != "1.2.3" || q.RuntimeExecutableDigest != ownerPreparationTestDocument()["release"].(map[string]any)["releaseManifestDigest"] {
					t.Fatal("explicit declaration changed")
				}
				return owner, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			result := ownerPreparationDecodeResult(t, output.Bytes())
			if apply && (called != 1 || owner.closes != 1 || result.Outcome != "prepared") {
				t.Fatal("apply did not complete and close its owner")
			}
			if !apply && (called != 0 || owner.closes != 0 || result.Outcome != "request_checked") {
				t.Fatal("preview reached profile preparation")
			}
			after, err := os.ReadFile(args[2])
			if err != nil || !bytes.Equal(raw, after) {
				t.Fatal("command changed its request")
			}
			entries, _ := os.ReadDir(filepath.Dir(args[2]))
			if len(entries) != 1 {
				t.Fatal("command created unexpected files")
			}
		})
	}
}

func TestOwnerPreparationRequestFilesystemRefusals(t *testing.T) {
	for _, kind := range []string{"public-mode", "hardlink", "symlink", "fifo", "oversized", "digest", "ancestor-symlink"} {
		t.Run(kind, func(t *testing.T) {
			args, _ := ownerPreparationTestArgs(t)
			path := args[2]
			switch kind {
			case "public-mode":
				if os.Chmod(path, 0644) != nil {
					t.Fatal("mode control failed")
				}
			case "hardlink":
				if os.Link(path, path+"-link") != nil {
					t.Fatal("hardlink control failed")
				}
			case "symlink":
				if os.Rename(path, path+"-original") != nil || os.Symlink(path+"-original", path) != nil {
					t.Fatal("symlink control failed")
				}
			case "fifo":
				if os.Remove(path) != nil || unix.Mkfifo(path, 0600) != nil {
					t.Fatal("fifo control failed")
				}
			case "oversized":
				if os.WriteFile(path, bytes.Repeat([]byte{'x'}, ownerPreparationRequestLimit+1), 0600) != nil {
					t.Fatal("size control failed")
				}
			case "digest":
				args[4] = "sha256:" + strings.Repeat("0", 64)
			case "ancestor-symlink":
				alias := filepath.Dir(path) + "-alias"
				if os.Symlink(filepath.Dir(path), alias) != nil {
					t.Fatal("ancestor control failed")
				}
				defer os.Remove(alias)
				args[2] = filepath.Join(alias, filepath.Base(path))
			}
			called := false
			var output bytes.Buffer
			err := runOwnerProfilePreparationWith(context.Background(), append(args, "--apply"), &output, func(context.Context, launcher.OwnerProfilePreparationRequest) (ownerPreparationCommandOwner, error) {
				called = true
				return nil, nil
			})
			if err == nil || called || ownerPreparationDecodeResult(t, output.Bytes()).Outcome != "refused" {
				t.Fatal("unsafe request reached preparation")
			}
		})
	}
}

func TestOwnerPreparationCommandRetainsFailures(t *testing.T) {
	for _, kind := range []string{"preparation", "close", "request-replaced", "output"} {
		t.Run(kind, func(t *testing.T) {
			args, _ := ownerPreparationTestArgs(t)
			owner := &centralRegistrationTestOwner{}
			original := errors.New("PRIVATE admission recovery")
			var buffer bytes.Buffer
			var output interface{ Write([]byte) (int, error) } = &buffer
			if kind == "output" {
				output = preparationRefusedWriter{}
			}
			err := runOwnerProfilePreparationWith(context.Background(), append(args, "--apply"), output, func(context.Context, launcher.OwnerProfilePreparationRequest) (ownerPreparationCommandOwner, error) {
				if kind == "preparation" || kind == "output" {
					return owner, original
				}
				if kind == "close" {
					owner.failure = original
				}
				if kind == "request-replaced" {
					if os.Rename(args[2], args[2]+"-original") != nil || os.WriteFile(args[2], []byte(`{}`), 0600) != nil {
						t.Fatal("replacement control failed")
					}
				}
				return owner, nil
			})
			failure, ok := err.(*ownerPreparationCommandFailure)
			if !ok || failure.outcome != "review_required" || failure.owner.preparation != owner || failure.owner.request == nil {
				t.Fatal("failure lost original request or preparation owner")
			}
			defer failure.owner.Close()
			if kind != "close" && (owner.closes != 0 || failure.owner.request.closed) {
				t.Fatal("uncertain owner closed implicitly")
			}
			if kind == "close" && (owner.closes != 1 || !errors.Is(err, original)) {
				t.Fatal("close failure lost its original cause")
			}
			encoded, _ := json.Marshal(err)
			if strings.Contains(fmt.Sprintf("%+v %s", err, encoded), "PRIVATE") {
				t.Fatal("private cause appeared in diagnostics")
			}
			if kind != "output" && ownerPreparationDecodeResult(t, buffer.Bytes()).Outcome != "review_required" {
				t.Fatal("recovery action missing")
			}
			if _, err := failure.owner.request.entries[len(failure.owner.request.entries)-1].file.Stat(); kind != "close" && err != nil {
				t.Fatal("original request descriptor was lost")
			}
		})
	}
}

func TestOwnerPreparationCommandReportsInterruptionWithoutPrivateCause(t *testing.T) {
	for _, interruption := range []error{context.DeadlineExceeded, context.Canceled} {
		t.Run(interruption.Error(), func(t *testing.T) {
			args, _ := ownerPreparationTestArgs(t)
			owner := &centralRegistrationTestOwner{}
			var output bytes.Buffer
			err := runOwnerProfilePreparationWith(context.Background(), append(args, "--apply"), &output, func(context.Context, launcher.OwnerProfilePreparationRequest) (ownerPreparationCommandOwner, error) {
				return owner, errors.Join(errors.New("PRIVATE retained cause"), interruption)
			})
			failure, ok := err.(*ownerPreparationCommandFailure)
			if !ok || !errors.Is(err, interruption) || owner.closes != 0 {
				t.Fatal("interruption lost its cause or original owner")
			}
			defer failure.owner.Close()
			result := ownerPreparationDecodeResult(t, output.Bytes())
			word := "canceled"
			if interruption == context.DeadlineExceeded {
				word = "deadline expired"
			}
			if result.Outcome != "review_required" || result.Action != "inspect_partial_preparation_before_retry" || !strings.Contains(result.Message, word) || strings.Contains(output.String(), "PRIVATE") {
				t.Fatal("interruption diagnostic lost recovery instructions or disclosed private data")
			}
			fallback, ok := ownerProfilePreparationDiagnostic(err)
			if !ok || fallback != result {
				t.Fatal("fallback changed the interruption diagnostic")
			}
		})
	}
}

func TestOwnerPreparationDiagnosticUsesOriginalDeadline(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	fd := int(writer.Fd())
	if unix.SetNonblock(fd, true) != nil {
		t.Fatal("pipe control failed")
	}
	for {
		_, err := unix.Write(fd, bytes.Repeat([]byte{'x'}, 4096))
		if err == unix.EAGAIN {
			break
		}
		if err != nil {
			t.Fatal("pipe fill failed")
		}
	}
	if unix.SetNonblock(fd, false) != nil {
		t.Fatal("pipe mode restore failed")
	}
	owner := &centralRegistrationTestOwner{}
	failure := &ownerPreparationCommandFailure{owner: &ownerPreparationCommandOwners{preparation: owner}, cause: errors.New("PRIVATE"), outcome: "review_required"}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := writeOwnerProfilePreparationDiagnostic(ctx, writer, failure); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 250*time.Millisecond || owner.closes != 0 {
		t.Fatal("diagnostic exceeded its original deadline or consumed recovery")
	}
	if _, ok := ownerProfilePreparationDiagnostic(errors.New("owner_profile_preparation_review_required")); ok {
		t.Fatal("arbitrary error text selected an outcome")
	}
}

func TestOwnerPreparationOutputFailureAfterSuccess(t *testing.T) {
	for _, apply := range []bool{false, true} {
		t.Run(fmt.Sprint(apply), func(t *testing.T) {
			args, _ := ownerPreparationTestArgs(t)
			owner := &centralRegistrationTestOwner{}
			if apply {
				args = append(args, "--apply")
			}
			err := runOwnerProfilePreparationWith(context.Background(), args, preparationRefusedWriter{}, func(context.Context, launcher.OwnerProfilePreparationRequest) (ownerPreparationCommandOwner, error) {
				return owner, nil
			})
			failure, ok := err.(*ownerPreparationCommandFailure)
			if !ok || failure.owner == nil || !failure.owner.request.closed {
				t.Fatal("output failure lost completed request ownership")
			}
			if apply && (failure.outcome != "review_required" || failure.owner.preparation != owner || owner.closes != 1) {
				t.Fatal("published setup output failure lost its owner or retried close")
			}
			if !apply && (failure.outcome != "refused" || owner.closes != 0 || failure.owner.preparation != nil) {
				t.Fatal("preview output failure reached preparation or reported success")
			}
			failure.owner.Close()
			if apply && owner.closes != 1 {
				t.Fatal("completed preparation was closed again")
			}
		})
	}
}

type ownerPreparationPartialWriter struct{ bytes.Buffer }

func (w *ownerPreparationPartialWriter) Write(raw []byte) (int, error) {
	n, _ := w.Buffer.Write(raw[:min(8, len(raw))])
	return n, errors.New("PRIVATE partial stdout failure")
}

func TestOwnerPreparationRunnerAndDiagnosticEmitOneResult(t *testing.T) {
	for _, kind := range []string{"refused", "retained", "cleanup", "stdout-failed", "stdout-partial"} {
		t.Run(kind, func(t *testing.T) {
			args, _ := ownerPreparationTestArgs(t)
			owner := &centralRegistrationTestOwner{}
			var stdout, stderr bytes.Buffer
			var output interface{ Write([]byte) (int, error) } = &stdout
			partial := &ownerPreparationPartialWriter{}
			if kind == "stdout-failed" {
				output = preparationRefusedWriter{}
			}
			if kind == "stdout-partial" {
				output = partial
			}
			ctx, cancel := context.WithTimeout(context.Background(), ownerPreparationCommandLimit)
			defer cancel()
			err := runOwnerProfilePreparationWith(ctx, append(args, "--apply"), output, func(context.Context, launcher.OwnerProfilePreparationRequest) (ownerPreparationCommandOwner, error) {
				if kind == "refused" {
					return nil, errors.New("PRIVATE refusal")
				}
				if kind == "cleanup" {
					owner.failure = errors.New("PRIVATE cleanup failure")
					return owner, nil
				}
				return owner, errors.New("PRIVATE retained admission")
			})
			failure, ok := err.(*ownerPreparationCommandFailure)
			if !ok {
				t.Fatal("expected typed command failure")
			}
			defer failure.owner.Close()
			if err := writeOwnerProfilePreparationDiagnostic(ctx, &stderr, failure); err != nil {
				t.Fatal(err)
			}
			fallback := kind == "stdout-failed" || kind == "stdout-partial"
			if fallback {
				if failure.resultEmitted || stdout.Len() != 0 || ownerPreparationDecodeResult(t, stderr.Bytes()).Outcome != "review_required" {
					t.Fatal("stdout failure lost stderr fallback")
				}
				if kind == "stdout-partial" && (partial.Len() == 0 || bytes.Contains(partial.Bytes(), []byte{'\n'})) {
					t.Fatal("partial write control did not run")
				}
			} else {
				if !failure.resultEmitted || stderr.Len() != 0 {
					t.Fatal("complete stdout result was emitted again on stderr")
				}
				expected := "review_required"
				if kind == "refused" {
					expected = "refused"
				}
				if ownerPreparationDecodeResult(t, stdout.Bytes()).Outcome != expected {
					t.Fatal("terminal outcome changed")
				}
			}
			expectedCloses := 0
			if kind == "cleanup" {
				expectedCloses = 1
			}
			if owner.closes != expectedCloses {
				t.Fatal("diagnostic closed or retried the recovery owner")
			}
		})
	}
}
