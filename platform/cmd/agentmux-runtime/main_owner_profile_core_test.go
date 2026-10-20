//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/controlLogix/agentmux/platform/launcher"
)

func TestOwnerCoreRequestOptionalExactPin(t *testing.T) {
	for _, included := range []bool{false, true} {
		document := ownerPreparationTestDocument()
		pin := launcher.CoreHubSelection{Selection: "/private/core 'literal' $(selection).json", SHA256: "sha256:" + strings.Repeat("e", 64)}
		if included {
			document["coreHub"] = pin
		}
		raw, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		q, err := decodeOwnerPreparationRequest(raw)
		if err != nil {
			t.Fatal(err)
		}
		if included && (q.CoreHub == nil || *q.CoreHub != pin) || !included && q.CoreHub != nil {
			t.Fatal("optional core pin changed")
		}
		for _, operation := range []string{"prepare-owner-profile", "recover-owner-profile"} {
			args, _ := ownerPreparationTestArgs(t)
			args[0] = operation
			args[4] = ownerPreparationSHA(raw)
			if err := os.WriteFile(args[2], raw, 0600); err != nil {
				t.Fatal(err)
			}
			owner := &centralRegistrationTestOwner{}
			calls := 0
			var output bytes.Buffer
			err := runOwnerProfilePreparationWith(context.Background(), append(args, "--apply"), &output, func(_ context.Context, selected launcher.OwnerProfilePreparationRequest) (ownerPreparationCommandOwner, error) {
				calls++
				if included && (selected.CoreHub == nil || *selected.CoreHub != pin) || !included && selected.CoreHub != nil {
					t.Fatal("command changed selected core pin")
				}
				return owner, nil
			})
			if err != nil || calls != 1 || owner.closes != 1 {
				t.Fatal("command did not hand off exact request and close owner", err)
			}
			ownerPreparationDecodeResult(t, output.Bytes())
		}
	}
}

func TestOwnerCoreRequestRejectsMalformedPin(t *testing.T) {
	valid := map[string]any{"selection": "/private/core.json", "sha256": "sha256:" + strings.Repeat("e", 64)}
	for _, mode := range []string{"null", "string", "array", "missing-path", "missing-digest", "extra", "wrong-key", "relative", "unclean", "control", "digest", "null-path", "null-digest", "numeric-path", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			document := ownerPreparationTestDocument()
			pin := map[string]any{"selection": valid["selection"], "sha256": valid["sha256"]}
			document["coreHub"] = pin
			switch mode {
			case "null":
				document["coreHub"] = nil
			case "string":
				document["coreHub"] = "core"
			case "array":
				document["coreHub"] = []any{pin}
			case "missing-path":
				delete(pin, "selection")
			case "missing-digest":
				delete(pin, "sha256")
			case "extra":
				pin["credential"] = "untrusted"
			case "wrong-key":
				delete(pin, "sha256")
				pin["digest"] = valid["sha256"]
			case "relative":
				pin["selection"] = "core.json"
			case "unclean":
				pin["selection"] = "/private/../core.json"
			case "control":
				pin["selection"] = "/private/core\n.json"
			case "digest":
				pin["sha256"] = "sha256:bad"
			case "null-path":
				pin["selection"] = nil
			case "null-digest":
				pin["sha256"] = nil
			case "numeric-path":
				pin["selection"] = 1
			}
			raw, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "duplicate" {
				raw = bytes.Replace(raw, []byte(`"coreHub":{`), []byte(`"coreHub":{"selection":"/private/other.json",`), 1)
			}
			if _, err := decodeOwnerPreparationRequest(raw); err == nil {
				t.Fatal("malformed core pin accepted")
			}
		})
	}
}
