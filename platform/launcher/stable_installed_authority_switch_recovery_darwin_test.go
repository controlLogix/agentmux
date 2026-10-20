//go:build darwin && arm64 && cgo && agentmux_bootstrap_docker

package launcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

type stableInstalledAuthoritySwitchRecoveryResult struct {
	SchemaVersion             string `json:"schemaVersion"`
	Result                    string `json:"result"`
	ClosedWriteRefused        bool   `json:"closedWriteRefused"`
	MismatchedFenceRefused    bool   `json:"mismatchedFenceRefused"`
	ExactBrokerRetryConfirmed bool   `json:"exactBrokerRetryConfirmed"`
	GuardedStoreOpened        bool   `json:"guardedStoreOpened"`
}

func stableInstalledAuthoritySwitchRecoveryConfirmed(raw []byte) bool {
	var result stableInstalledAuthoritySwitchRecoveryResult
	return protocol.DecodeClosedJSON(raw, &result, 4096) == nil &&
		result.SchemaVersion == protocol.Version && result.Result == "signed-recovery-confirmed" &&
		result.ClosedWriteRefused && result.MismatchedFenceRefused &&
		result.ExactBrokerRetryConfirmed && result.GuardedStoreOpened
}

func TestStableInstalledClientDarwinAuthoritySwitchRecovery(t *testing.T) {
	if os.Getenv("AMX_INSTALLED_CLIENT_COLD_FAILURE_HOLD") != "1" {
		t.Fatal("installed recovery failure hold required")
	}
	if _, finite := t.Deadline(); finite {
		t.Fatal("installed recovery collector requires timeout disabled")
	}
	material := bootstrapDarwinPrivatePrerequisite(t,
		"AMX_INSTALLED_AUTHORITY_SWITCH_RECOVERY_MATERIAL",
		"AMX_INSTALLED_AUTHORITY_SWITCH_RECOVERY_MATERIAL_SHA256")
	var header struct {
		SchemaVersion    string `json:"schemaVersion"`
		ServiceSelection struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"serviceSelection"`
	}
	if json.Unmarshal(material, &header) != nil || header.SchemaVersion != protocol.Version {
		t.Fatal("installed recovery material invalid")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal("prepared recovery tools required")
	}
	pin, clientID := stableInstalledClientPrerequisites(t)
	packageAdmission, err := protected.PrepareInstalledClient(context.Background(), clientID)
	if err != nil {
		t.Fatal("installed recovery package admission failed")
	}
	t.Cleanup(func() {
		if packageAdmission.Close() != nil {
			t.Error("installed recovery package cleanup failed")
		}
	})
	packageRoot := filepath.Join(protected.InstalledClientBase, clientID)
	python := filepath.Join(packageRoot, protected.ClientInterpreter)
	application := stableInstalledApplicationPrerequisites(t, clientID)
	if application == nil || application.selected.ApplicationServices.Selection != header.ServiceSelection.Path ||
		application.selected.ApplicationServices.SHA256 != header.ServiceSelection.SHA256 {
		t.Fatal("recovery material selected a different installed service")
	}
	application.serviceCheck = func(t *testing.T, f *bootstrapDockerFixture, cold *composeDarwinCLIFront) {
		cold.lifetime.assertUnchanged(t, f)
		input, err := json.Marshal(map[string]any{"recoveryMaterial": map[string]string{
			"path":   os.Getenv("AMX_INSTALLED_AUTHORITY_SWITCH_RECOVERY_MATERIAL"),
			"sha256": os.Getenv("AMX_INSTALLED_AUTHORITY_SWITCH_RECOVERY_MATERIAL_SHA256"),
		}})
		if err != nil {
			cold.lifetime.admissionFailure(err)
			return
		}
		defer clear(input)
		output, err := os.CreateTemp(filepath.Dir(header.ServiceSelection.Path), "authority-switch-recovery-*.private.out")
		if err != nil {
			cold.lifetime.admissionFailure(err)
			return
		}
		diagnostic, err := os.CreateTemp(filepath.Dir(header.ServiceSelection.Path), "authority-switch-recovery-*.private.err")
		if err != nil {
			output.Close()
			cold.lifetime.admissionFailure(err)
			return
		}
		command := exec.Command(python, "-B", "-I", "-S",
			"platform/launcher/testdata/installed_authority_switch_package_bootstrap.py")
		command.Dir = root
		command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + filepath.Dir(header.ServiceSelection.Path),
			"AMX_INSTALLED_AUTHORITY_SWITCH_PACKAGE_ROOT=" + packageRoot,
			"AMX_INSTALLED_AUTHORITY_SWITCH_PACKAGE_ID=" + clientID,
			"PYTHONDONTWRITEBYTECODE=1"}
		command.Stdin, command.Stdout, command.Stderr = bytes.NewReader(input), output, diagnostic
		// Run owns this checker's sole wait. The original application host stays
		// reachable through cold.lifetime until the result is fully admitted.
		waitErr := command.Run()
		outputCloseErr, diagnosticCloseErr := output.Close(), diagnostic.Close()
		if waitErr != nil || outputCloseErr != nil || diagnosticCloseErr != nil {
			cold.lifetime.admissionFailure(errors.New("installed_authority_switch_recovery_run_unconfirmed"))
			return
		}
		if packageAdmission.Recheck(context.Background()) != nil {
			cold.lifetime.admissionFailure(errors.New("installed_authority_switch_package_changed"))
			return
		}
		resultFile, err := os.Open(output.Name())
		if err != nil {
			cold.lifetime.admissionFailure(err)
			return
		}
		raw, readErr := io.ReadAll(io.LimitReader(resultFile, 4097))
		resultCloseErr := resultFile.Close()
		if readErr != nil || resultCloseErr != nil || len(raw) > 4096 {
			clear(raw)
			cold.lifetime.admissionFailure(errors.New("installed_authority_switch_recovery_result_unavailable"))
			return
		}
		defer clear(raw)
		if !stableInstalledAuthoritySwitchRecoveryConfirmed(raw) {
			cold.lifetime.admissionFailure(errors.New("installed_authority_switch_recovery_result_unconfirmed"))
			return
		}
	}
	f, s, record := stableInstalledClientFixture(t)
	stableInstalledClientScenario(t, f, s, record, pin, clientID, true, application)
}

func TestStableInstalledAuthoritySwitchRecoveryResultIsClosed(t *testing.T) {
	good := []byte(`{"schemaVersion":"1.0.0","result":"signed-recovery-confirmed","closedWriteRefused":true,"mismatchedFenceRefused":true,"exactBrokerRetryConfirmed":true,"guardedStoreOpened":true}`)
	if !stableInstalledAuthoritySwitchRecoveryConfirmed(good) {
		t.Fatal("exact installed recovery result refused")
	}
	for _, changed := range [][]byte{
		bytes.Replace(good, []byte(`"closedWriteRefused":true`), []byte(`"closedWriteRefused":false`), 1),
		bytes.Replace(good, []byte(`"mismatchedFenceRefused":true`), []byte(`"mismatchedFenceRefused":false`), 1),
		bytes.Replace(good, []byte(`"exactBrokerRetryConfirmed":true`), []byte(`"exactBrokerRetryConfirmed":false`), 1),
		bytes.Replace(good, []byte(`"guardedStoreOpened":true`), []byte(`"guardedStoreOpened":false`), 1),
		bytes.Replace(good, []byte(`"schemaVersion"`), []byte(`"extra":true,"schemaVersion"`), 1),
		append(bytes.Clone(good), []byte(` {}`)...),
	} {
		if stableInstalledAuthoritySwitchRecoveryConfirmed(changed) {
			t.Fatal("open or incomplete installed recovery result accepted")
		}
	}
	if stableInstalledAuthoritySwitchRecoveryConfirmed([]byte(strings.Repeat("x", 4097))) {
		t.Fatal("oversized installed recovery result accepted")
	}
}
