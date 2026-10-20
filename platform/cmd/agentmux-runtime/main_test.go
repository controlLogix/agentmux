//go:build linux || darwin

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/controlLogix/agentmux/platform/launcher"
	protected "github.com/controlLogix/agentmux/platform/runtime"
	"strings"
	"testing"
)

func TestInstalledLauncherLiteralCommands(t *testing.T) {
	for _, operation := range []string{"ensure", "status", "host"} {
		args := []string{operation, "--host-policy", "/private/host-policy.json", "--workspace", "/work/one", "--workspace", "/work/two"}
		if operation == "host" {
			args = append(args, "--invocation-id", "attempt_"+strings.Repeat("a", 32))
		}
		o, err := parse(args)
		if err != nil || o.operation != operation || len(o.roots) != 2 {
			t.Fatal("valid literal command rejected")
		}
	}
	for _, args := range [][]string{nil, {"stop"}, {"ensure"}, {"status", "--host-policy", "/private/policy", "--workspace", "/work", "--invocation-id", "attempt_" + strings.Repeat("a", 32)}, {"host", "--host-policy", "/private/policy", "--workspace", "/work"}, {"ensure", "--host-policy", "/private/policy", "--workspace", "/work", "unexpected"}, {"ensure", "--host-policy", "/private/policy", "--workspace", "/work", "--exec", "arbitrary"}} {
		if _, err := parse(args); err == nil {
			t.Fatal("invalid command accepted")
		}
	}
}

func TestInitialLookupNeverStartsOnStatusOrHardFailure(t *testing.T) {
	for _, code := range []string{"owner_bridge_connection_unavailable", "owner_bridge_reply_unavailable", "owner_bridge_no_responders"} {
		err := errors.New(code)
		if !initialLookupAllowsStart("ensure", err) || initialLookupAllowsStart("status", err) {
			t.Fatal("initial lookup did not preserve ensure-only admission")
		}
		if initialLookupAllowsStart("ensure", errors.Join(err, errors.New("owner_bridge_owned_connection_cleanup_failed"))) {
			t.Fatal("an unavailable hint masked owned cleanup failure")
		}
	}
	for _, err := range []error{nil, errors.New("owner_bridge_authority_rejected"), errors.New("owner_bridge_reply_invalid"), errors.New("owner_bridge_deadline")} {
		if initialLookupAllowsStart("ensure", err) {
			t.Fatal("a successful lookup or hard failure authorized startup")
		}
	}
	if progressObservationUnavailable(errors.New("owner_bridge_no_responders")) {
		t.Fatal("initial probe hint changed the final request fallback")
	}
}

func TestInstalledLauncherFailedObservationEmitsStatusAndFails(t *testing.T) {
	for _, operation := range []string{"ensure", "status"} {
		for _, disposition := range []string{"failed", "unconfigured", "started", "reused", "starting"} {
			t.Run(operation+"/"+disposition, func(t *testing.T) {
				var output bytes.Buffer
				observation := launcher.StartupStatusObservation{SchemaVersion: "1.0.0", Disposition: disposition}
				err := emitObservation(&output, observation, operation)
				wantFailure := disposition == "failed" || disposition == "unconfigured"
				if (err != nil) != wantFailure {
					t.Fatal("command exit result did not match the authenticated observation")
				}
				var actual launcher.StartupStatusObservation
				if json.Unmarshal(output.Bytes(), &actual) != nil || actual.Disposition != disposition {
					t.Fatal("authenticated status was lost on failure")
				}
			})
		}
	}
}

func TestInstalledLauncherReceiptDoesNotInventInstanceDetails(t *testing.T) {
	for _, outcome := range []string{"accepted", "failed", "contended"} {
		var output bytes.Buffer
		receipt := protected.BootstrapControlReceipt{SchemaVersion: "1.0.0", Kind: "bootstrap-control-receipt", Outcome: outcome}
		err := emitBootstrapProgress(&output, receipt)
		if (err == nil) != (outcome == "accepted") {
			t.Fatal("unconfirmed child receipt was treated as accepted startup")
		}
		var document map[string]json.RawMessage
		if json.Unmarshal(output.Bytes(), &document) != nil {
			t.Fatal("progress document unavailable")
		}
		if string(document["kind"]) != `"bootstrap-progress"` || string(document["detailsAvailable"]) != "false" {
			t.Fatal("receipt was presented as an authenticated instance observation")
		}
		if string(document["instanceState"]) != `"unknown"` {
			t.Fatal("historical admission was presented as current instance state")
		}
		for _, field := range []string{"services", "persistence", "connectedHubs", "work", "runningVersion", "ready"} {
			if _, ok := document[field]; ok {
				t.Fatal("unobserved instance detail was invented")
			}
		}
		if _, ok := document["disposition"]; ok {
			t.Fatal("receipt reused the authenticated L04 disposition field")
		}
	}
}

func TestInstalledLauncherProgressNeverMasksAuthorityOrCleanupFailure(t *testing.T) {
	for _, code := range []string{"owner_bridge_authority_rejected", "owner_bridge_reply_invalid", "host_policy_owner_enrollment_invalid", "owner_bridge_owned_connection_cleanup_failed"} {
		if progressObservationUnavailable(errors.New(code)) {
			t.Fatal("hard failure was eligible for a startup receipt fallback")
		}
	}
	if progressObservationUnavailable(errors.Join(errors.New("owner_bridge_connection_unavailable"), errors.New("owner_bridge_owned_connection_cleanup_failed"))) {
		t.Fatal("connection failure hid retained cleanup failure")
	}
}
