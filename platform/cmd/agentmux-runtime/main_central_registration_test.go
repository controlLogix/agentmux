//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/launcher"
)

func centralRegistrationArgs() []string {
	return []string{"register-central-profile", "--profile-id", "profile_" + strings.Repeat("a", 32), "--client-installation", strings.Repeat("b", 64), "--workspace", "/private/work with spaces", "--environment", "Development"}
}
func TestCentralRegistrationExplicitArguments(t *testing.T) {
	for _, metadata := range [][]string{{"--environment", "Local"}, {"--project", "Console"}, {"--environment", "Staging", "--project", "Console"}} {
		args := append(centralRegistrationArgs()[:7], metadata...)
		request, err := parseCentralProfileRegistration(args)
		if err != nil {
			t.Fatal(err)
		}
		if request.ProfileID != "profile_"+strings.Repeat("a", 32) || request.ClientInstallationID != strings.Repeat("b", 64) || len(request.ApprovedWorkspaceRoots) != 1 || request.ApprovedWorkspaceRoots[0] != "/private/work with spaces" {
			t.Fatal("explicit selection changed")
		}
		if (request.Context.Environment != nil) != (metadata[0] == "--environment") || (request.Context.Project != nil) != (metadata[0] == "--project" || len(metadata) == 4) {
			t.Fatal("metadata was inferred or omitted")
		}
	}
	for _, args := range [][]string{
		nil, {"startup"}, centralRegistrationArgs()[:7],
		append(centralRegistrationArgs(), "--environment", "Other"),
		append(centralRegistrationArgs(), "--project", ""),
		append(centralRegistrationArgs(), "--profile-id", "profile_"+strings.Repeat("c", 32)),
		append(centralRegistrationArgs(), "--client-installation", strings.Repeat("c", 64)),
		append(centralRegistrationArgs(), "--workspace", "/private/work with spaces"),
		append(centralRegistrationArgs(), "--workspace", "relative"),
		append(centralRegistrationArgs(), "--workspace", "/private/../workspace"),
		append(centralRegistrationArgs(), "--project", " Console"),
		append(centralRegistrationArgs(), "--project", "one\ntwo"),
		append(centralRegistrationArgs(), "--project", strings.Repeat("x", 129)),
		append(centralRegistrationArgs(), "--selection", "/private/legacy.json"),
		append(centralRegistrationArgs(), "--apply"),
		append(centralRegistrationArgs(), "extra"),
	} {
		called := false
		var output bytes.Buffer
		err := runCentralProfileRegistrationWith(context.Background(), args, &output, func(context.Context, launcher.CentralProfileRegistrationRequest) (centralRegistrationCommandOwner, error) {
			called = true
			return nil, nil
		})
		if err == nil || called || output.Len() != 0 {
			t.Fatalf("invalid arguments reached registration: %q", args)
		}
	}
}

type centralRegistrationTestOwner struct {
	closes  int
	failure error
}

func (o *centralRegistrationTestOwner) Close() error { o.closes++; return o.failure }
func centralRegistrationDecode(t *testing.T, raw []byte) centralRegistrationCommandResult {
	t.Helper()
	var result centralRegistrationCommandResult
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	if bytes.Count(raw, []byte{'\n'}) != 1 || result.Kind != "central-profile-registration-result" {
		t.Fatal("output was not one closed registration frame")
	}
	for _, secret := range []string{"private-secret", "/private/", "Development", "profile_", "instance_", "hub_"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("private declaration or runtime identity leaked")
		}
	}
	return result
}
func TestCentralRegistrationSuccessClosesBeforeReporting(t *testing.T) {
	owner := &centralRegistrationTestOwner{}
	var output bytes.Buffer
	err := runCentralProfileRegistrationWith(context.Background(), centralRegistrationArgs(), &output, func(ctx context.Context, request launcher.CentralProfileRegistrationRequest) (centralRegistrationCommandOwner, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 8500*time.Millisecond || time.Until(deadline) < 8*time.Second {
			t.Fatal("registration work did not keep the bounded response allowance")
		}
		if request.Context.Project != nil || request.Context.Environment == nil || *request.Context.Environment != "Development" {
			t.Fatal("registration metadata changed")
		}
		return owner, nil
	})
	if err != nil || owner.closes != 1 {
		t.Fatal("successful registration did not close its original owner", err)
	}
	result := centralRegistrationDecode(t, output.Bytes())
	if result.Outcome != "registered" || strings.Contains(result.Message, "ready") {
		t.Fatal("registration claimed readiness")
	}
}
func TestCentralRegistrationFailureRetainsOriginalOwner(t *testing.T) {
	for _, kind := range []string{"publication-uncertain", "cleanup-failed", "refused", "missing-owner"} {
		t.Run(kind, func(t *testing.T) {
			owner := &centralRegistrationTestOwner{}
			var output bytes.Buffer
			err := runCentralProfileRegistrationWith(context.Background(), centralRegistrationArgs(), &output, func(context.Context, launcher.CentralProfileRegistrationRequest) (centralRegistrationCommandOwner, error) {
				switch kind {
				case "publication-uncertain":
					return owner, errors.New("private-secret /private/registration.json")
				case "cleanup-failed":
					owner.failure = errors.New("private-secret /private/handle")
					return owner, nil
				case "refused":
					return nil, errors.New("private-secret /private/profile.json")
				default:
					return nil, nil
				}
			})
			failure, ok := err.(*centralRegistrationCommandFailure)
			if !ok {
				t.Fatal("registration failure absent")
			}
			result := centralRegistrationDecode(t, output.Bytes())
			if kind == "publication-uncertain" || kind == "cleanup-failed" {
				if failure.owner != owner || result.Outcome != "review_required" || result.Action != "inspect_registration_before_retry" {
					t.Fatal("uncertainty lost original owner or recovery action")
				}
				expectedCloses := 0
				if kind == "cleanup-failed" {
					expectedCloses = 1
				}
				if owner.closes != expectedCloses {
					t.Fatal("uncertain owner was closed implicitly or retried")
				}
			} else if result.Outcome != "refused" || failure.owner != nil {
				t.Fatal("refusal claimed registration")
			}
			encoded, _ := json.Marshal(failure)
			if strings.Contains(fmt.Sprintf("%+v %s", failure, encoded), "private-secret") {
				t.Fatal("failure formatting leaked cause")
			}
			diagnostic, handled := centralProfileRegistrationDiagnostic(failure)
			if !handled || diagnostic != result {
				t.Fatal("static diagnostic lost recovery outcome")
			}
		})
	}
}
func TestCentralRegistrationOutputFailureKeepsOriginalOwner(t *testing.T) {
	owner := &centralRegistrationTestOwner{}
	err := runCentralProfileRegistrationWith(context.Background(), centralRegistrationArgs(), preparationRefusedWriter{}, func(context.Context, launcher.CentralProfileRegistrationRequest) (centralRegistrationCommandOwner, error) {
		return owner, errors.New("private-secret")
	})
	failure, ok := err.(*centralRegistrationCommandFailure)
	if !ok || failure.owner != owner || failure.outcome != "review_required" || owner.closes != 0 {
		t.Fatal("output failure consumed recovery owner")
	}
	if _, ok = centralProfileRegistrationDiagnostic(errors.New("central_profile_registration_review_required")); ok {
		t.Fatal("untrusted error text classified as registration outcome")
	}
}

func TestCentralRegistrationDiagnosticFullPipeHonorsOuterDeadline(t *testing.T) {
	for _, kind := range []string{"parse-error", "retained-owner"} {
		t.Run(kind, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			fd := int(writer.Fd())
			if unix.SetNonblock(fd, true) != nil {
				t.Fatal("pipe fill control failed")
			}
			chunk := bytes.Repeat([]byte{'x'}, 4096)
			for {
				_, err := unix.Write(fd, chunk)
				if err == unix.EAGAIN {
					break
				}
				if err != nil {
					t.Fatal("pipe fill failed")
				}
			}
			if unix.SetNonblock(fd, false) != nil {
				t.Fatal("pipe blocking mode restore failed")
			}
			var failure error
			owner := &centralRegistrationTestOwner{}
			if kind == "parse-error" {
				_, failure = parseCentralProfileRegistration([]string{"register-central-profile"})
			} else {
				failure = &centralRegistrationCommandFailure{owner: owner, cause: errors.New("private-secret"), outcome: "review_required"}
			}
			outer, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
			defer cancel()
			deadline, _ := outer.Deadline()
			started := time.Now()
			if err = writeCentralProfileRegistrationDiagnostic(outer, writer, failure); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("full stderr did not obey original deadline: %v", err)
			}
			if time.Since(started) > 250*time.Millisecond {
				t.Fatal("diagnostic restarted or exceeded command budget")
			}
			current, _ := outer.Deadline()
			if !current.Equal(deadline) || owner.closes != 0 {
				t.Fatal("diagnostic changed deadline or consumed recovery owner")
			}
		})
	}
}
func TestCentralRegistrationDiagnosticPreservesTypedOutcomeAndCancellation(t *testing.T) {
	owner := &centralRegistrationTestOwner{}
	failure := &centralRegistrationCommandFailure{owner: owner, cause: errors.New("private-secret"), outcome: "review_required"}
	var output bytes.Buffer
	if err := writeCentralProfileRegistrationDiagnostic(context.Background(), &output, failure); err != nil {
		t.Fatal(err)
	}
	result := centralRegistrationDecode(t, output.Bytes())
	if result != centralRegistrationResult("review_required") || failure.owner != owner || owner.closes != 0 {
		t.Fatal("diagnostic changed typed outcome or original owner")
	}
	for _, expired := range []bool{false, true} {
		var ctx context.Context
		var cancel context.CancelFunc
		if expired {
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		} else {
			ctx, cancel = context.WithCancel(context.Background())
			cancel()
		}
		output.Reset()
		err := writeCentralProfileRegistrationDiagnostic(ctx, &output, failure)
		cancel()
		if err == nil || output.Len() != 0 || owner.closes != 0 {
			t.Fatal("cancelled diagnostic wrote output or consumed recovery owner")
		}
	}
}
