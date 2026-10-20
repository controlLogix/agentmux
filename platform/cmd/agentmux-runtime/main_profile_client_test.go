//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func profileClientArgs(operation string) []string {
	return []string{"profile-client", "--profile-id", "profile_" + strings.Repeat("a", 32), "--repository-root", "/approved/repo 'quotes' $(literal)", "--operation", operation}
}

type offlineProfileClientOwner struct {
	execs, closes     int
	operation         string
	execErr, closeErr error
}

func (o *offlineProfileClientOwner) ExecClient(ctx context.Context, operation string) error {
	if ctx.Err() != nil || o.closes != 0 {
		return errors.New("offline_original_owner_closed")
	}
	o.execs++
	o.operation = operation
	return o.execErr
}
func (o *offlineProfileClientOwner) Close() error { o.closes++; return o.closeErr }

func TestProfileClientClosedOperationsRetainOriginalOwnerUntilExec(t *testing.T) {
	for _, operation := range []string{"startup", "startup-json", "startup-worker", "startup-worker-json", "mcp", "mcp-worker", "dashboard", "claude-code-hook", "claude-code-hook-worker"} {
		owner := &offlineProfileClientOwner{}
		calls := 0
		err := runProfileClientWith(context.Background(), profileClientArgs(operation), func(ctx context.Context, id, repository string) (profileClientOwner, error) {
			calls++
			if id != profileClientArgs(operation)[2] || repository != profileClientArgs(operation)[4] {
				t.Fatal("literal profile or approved root changed")
			}
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("native resolution is unbounded")
			}
			return owner, nil
		})
		if err != nil || calls != 1 || owner.execs != 1 || owner.closes != 1 || owner.operation != operation {
			t.Fatal("original resolution was replaced or closed before exec", err)
		}
	}
}

func TestProfileClientRefusalAndCleanupKeepExactOwnerWithoutRetry(t *testing.T) {
	for _, during := range []string{"resolve", "exec", "close"} {
		owner := &offlineProfileClientOwner{}
		if during == "exec" {
			owner.execErr = errors.New("PRIVATE_EXEC")
		}
		if during == "close" {
			owner.closeErr = errors.New("PRIVATE_CLOSE")
		}
		calls := 0
		err := runProfileClientWith(context.Background(), profileClientArgs("mcp"), func(context.Context, string, string) (profileClientOwner, error) {
			calls++
			if during == "resolve" {
				return owner, errors.New("PRIVATE_RESOLVE")
			}
			return owner, nil
		})
		failure, ok := err.(*profileClientFailure)
		if !ok || failure.owner != owner || calls != 1 || owner.closes != 1 || (during == "resolve" && owner.execs != 0) {
			t.Fatal("failure lost or replaced its original owner")
		}
		var output bytes.Buffer
		if emitRequestDiagnostic(&output, err) != nil || strings.Contains(output.String(), "PRIVATE") || strings.Contains(fmt.Sprint(err), "PRIVATE") {
			t.Fatal("private failure escaped")
		}
		var diagnostic profileClientCommandDiagnostic
		decoder := json.NewDecoder(&output)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&diagnostic) != nil || diagnostic.SchemaVersion != "1.0.0" || diagnostic.Kind != "client-profile-diagnostic" {
			t.Fatal("invalid closed diagnostic")
		}
		if during == "close" && diagnostic.Code != "profile_cleanup_pending" {
			t.Fatal("uncertain cleanup was hidden")
		}
		if during != "close" && diagnostic.Code != "setup_required" {
			t.Fatal("refusal did not report setup required")
		}
	}
	err := runProfileClientWith(context.Background(), profileClientArgs("startup"), func(context.Context, string, string) (profileClientOwner, error) {
		return nil, errors.New("unknown profile")
	})
	if diagnostic, ok := profileClientDiagnostic(err); !ok || diagnostic.Code != "setup_required" {
		t.Fatal("unknown profile did not refuse")
	}
}

func TestProfileClientRejectsAmbiguousInputsBeforeResolution(t *testing.T) {
	base := profileClientArgs("startup")
	variants := [][]string{{"profile-client"}, append(append([]string{}, base...), "--selection", "/private/foreign"), append(append([]string{}, base...), "--profile-id", base[2])}
	for _, change := range []struct {
		index int
		value string
	}{{2, "profile_../escape"}, {2, "profile_" + strings.Repeat("A", 32)}, {4, "relative"}, {4, "/approved/../repo"}, {4, "//approved/repo"}, {4, "/"}, {4, "/approved/\nrepo"}, {6, "ensure"}, {6, "application-services"}, {6, "launch-claude-desktop"}} {
		args := append([]string{}, base...)
		args[change.index] = change.value
		variants = append(variants, args)
	}
	for _, args := range variants {
		calls := 0
		err := runProfileClientWith(context.Background(), args, func(context.Context, string, string) (profileClientOwner, error) { calls++; return nil, nil })
		if err == nil || err.Error() != "profile_client_arguments_invalid" || calls != 0 {
			t.Fatal("invalid input reached native resolution")
		}
		var output bytes.Buffer
		if err := run(context.Background(), args, &output); err == nil || output.Len() != 0 {
			t.Fatal("invalid route printed protocol output")
		}
	}
}

func TestCentralRegistrationRouteRejectsBeforeOwnerAdmission(t *testing.T) {
	var output bytes.Buffer
	if err := run(context.Background(), []string{"register-central-profile"}, &output); err == nil || err.Error() != "central_profile_registration_arguments_invalid" || output.Len() != 0 {
		t.Fatal("registration dispatcher bypassed its closed parser")
	}
}
