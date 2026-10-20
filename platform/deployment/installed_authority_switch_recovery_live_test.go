//go:build darwin && arm64 && cgo && agentmux_bootstrap_docker

package deployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

type installedAuthoritySwitchRecoveryMaterial struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type installedAuthoritySwitchRecoveryEnrollment struct {
	SchemaVersion    string                                   `json:"schemaVersion"`
	Enrollment       string                                   `json:"enrollment"`
	SHA256           string                                   `json:"sha256"`
	RecoveryMaterial installedAuthoritySwitchRecoveryMaterial `json:"recoveryMaterial"`
}

func TestInstalledAuthoritySwitchRecoveryBorrowedJWTBroker(t *testing.T) {
	runInstalledApplicationServicesBorrowedJWTBroker(t, false, true)
}

// Recovery writes custody beside its admitted host policy. Give it a copied
// policy and enrollment directory under one cleanup-owned private parent.
func installedAuthoritySwitchRecoveryInputs(t *testing.T, host installedServiceHostInput, preparationDirectory string, environment map[string]string) (installedServiceHostInput, string, map[string]string) {
	t.Helper()
	raw, err := teamReadPrivate(filepath.Dir(host.HostPolicy), filepath.Base(host.HostPolicy), uint32(os.Geteuid()))
	if err != nil || len(raw) > 65536 {
		clear(raw)
		t.Fatal("private installed recovery host policy refused")
	}
	defer clear(raw)
	sum := sha256.Sum256(raw)
	if host.HostPolicySHA256 != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatal("installed recovery host policy changed")
	}
	parent, err := os.MkdirTemp(filepath.Dir(preparationDirectory), "authority-switch-recovery-")
	if err != nil {
		t.Fatal("private installed recovery parent unavailable")
	}
	t.Cleanup(func() {
		if os.RemoveAll(parent) != nil {
			t.Error("private installed recovery cleanup incomplete")
		}
	})
	if os.Chmod(parent, 0700) != nil {
		t.Fatal("private installed recovery parent unavailable")
	}
	parent, err = filepath.EvalSymlinks(parent)
	if err != nil {
		t.Fatal("canonical installed recovery parent unavailable")
	}
	policy := filepath.Join(parent, "host-policy.json")
	file, err := os.OpenFile(policy, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("private installed recovery policy copy unavailable")
	}
	_, writeErr := file.Write(raw)
	syncErr, closeErr := file.Sync(), file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		t.Fatal("private installed recovery policy copy incomplete")
	}
	directory := filepath.Join(parent, "enrollment")
	if os.Mkdir(directory, 0700) != nil {
		t.Fatal("private installed recovery enrollment unavailable")
	}
	selected := make(map[string]string, len(environment))
	for key, value := range environment {
		selected[key] = value
	}
	selected["AMX_INSTALLED_CLIENT_HOST_POLICY"] = policy
	selected["AMX_INSTALLED_CLIENT_HOST_POLICY_SHA256"] = host.HostPolicySHA256
	host.HostPolicy = policy
	return host, directory, selected
}

func installedAuthoritySwitchDecodeRecoveryResult(raw []byte, directory string) (installedAuthoritySwitchRecoveryEnrollment, error) {
	var value installedAuthoritySwitchRecoveryEnrollment
	if protocol.DecodeClosedJSON(raw, &value, 16384) != nil || value.SchemaVersion != protocol.Version ||
		!installedServiceDigest.MatchString(value.SHA256) || !installedServiceDigest.MatchString(value.RecoveryMaterial.SHA256) {
		return installedAuthoritySwitchRecoveryEnrollment{}, errors.New("installed_authority_switch_preparation_output_invalid")
	}
	for _, path := range []string{value.Enrollment, value.RecoveryMaterial.Path} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) != directory {
			return installedAuthoritySwitchRecoveryEnrollment{}, errors.New("installed_authority_switch_preparation_output_invalid")
		}
	}
	if filepath.Base(value.RecoveryMaterial.Path) != "authority-switch-recovery-material.json" || value.Enrollment == value.RecoveryMaterial.Path {
		return installedAuthoritySwitchRecoveryEnrollment{}, errors.New("installed_authority_switch_preparation_output_invalid")
	}
	return value, nil
}

func installedAuthoritySwitchRecoveryEnvironment(environment []string, enrollment installedAuthoritySwitchRecoveryEnrollment) []string {
	overrides := map[string]string{
		"AMX_INSTALLED_AUTHORITY_SWITCH_RECOVERY_MATERIAL":        enrollment.RecoveryMaterial.Path,
		"AMX_INSTALLED_AUTHORITY_SWITCH_RECOVERY_MATERIAL_SHA256": enrollment.RecoveryMaterial.SHA256,
	}
	selected := make([]string, 0, len(environment)+len(overrides))
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		if _, replaced := overrides[key]; !replaced {
			selected = append(selected, entry)
		}
	}
	for key, value := range overrides {
		selected = append(selected, key+"="+value)
	}
	return selected
}

func installedAuthoritySwitchRecoveryCollectorCommand(goTool, root string, enrollment installedAuthoritySwitchRecoveryEnrollment, environment []string) *exec.Cmd {
	selected := installedAuthoritySwitchRecoveryEnvironment(environment, enrollment)
	return installedServiceFixedCollectorCommand(goTool, root, installedServiceEnrollment{
		SchemaVersion: enrollment.SchemaVersion, Enrollment: enrollment.Enrollment, SHA256: enrollment.SHA256,
	}, selected, "-run=^TestStableInstalledClientDarwinAuthoritySwitchRecovery$")
}

func TestInstalledAuthoritySwitchRecoveryPreparationResultKeepsClosedPins(t *testing.T) {
	good := []byte(`{"schemaVersion":"1.0.0","enrollment":"/private/fixture/client-selection.json","sha256":"sha256:` + strings.Repeat("a", 64) + `","recoveryMaterial":{"path":"/private/fixture/authority-switch-recovery-material.json","sha256":"sha256:` + strings.Repeat("b", 64) + `"}}`)
	if _, err := installedAuthoritySwitchDecodeRecoveryResult(good, "/private/fixture"); err != nil {
		t.Fatal("closed recovery preparation result refused")
	}
	for _, changed := range [][]byte{
		bytes.Replace(good, []byte("/private/fixture/authority-switch-recovery-material.json"), []byte("/private/other/authority-switch-recovery-material.json"), 1),
		bytes.Replace(good, []byte(`"recoveryMaterial":{`), []byte(`"recoveryMaterial":{"extra":true,`), 1),
		bytes.Replace(good, []byte(`"schemaVersion"`), []byte(`"extra":true,"schemaVersion"`), 1),
		bytes.Replace(good, []byte("authority-switch-recovery-material.json"), []byte("unselected.json"), 1),
	} {
		if _, err := installedAuthoritySwitchDecodeRecoveryResult(changed, "/private/fixture"); err == nil {
			t.Fatal("open or substituted recovery material accepted")
		}
	}
}

func TestInstalledAuthoritySwitchRecoveryInputsUseDisposablePolicyParent(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal("owned home unavailable")
	}
	original, err := os.MkdirTemp(home, "agentmux-recovery-input-")
	if err != nil {
		t.Fatal("private source policy parent unavailable")
	}
	t.Cleanup(func() { os.RemoveAll(original) })
	if os.Chmod(original, 0700) != nil {
		t.Fatal("private source policy parent unavailable")
	}
	teamPrivateACL(t, original, "-N")
	raw := []byte(`{"schemaVersion":"1.0.0"}`)
	policy := filepath.Join(original, "host-policy.json")
	if os.WriteFile(policy, raw, 0600) != nil {
		t.Fatal("private source policy unavailable")
	}
	teamPrivateACL(t, policy, "-N")
	preparation := filepath.Join(original, "original-enrollment")
	if os.Mkdir(preparation, 0700) != nil {
		t.Fatal("private original enrollment unavailable")
	}
	teamPrivateACL(t, preparation, "-N")
	sum := sha256.Sum256(raw)
	host := installedServiceHostInput{HostPolicy: policy,
		HostPolicySHA256: "sha256:" + hex.EncodeToString(sum[:])}
	selected, directory, environment := installedAuthoritySwitchRecoveryInputs(t, host, preparation,
		map[string]string{"AMX_INSTALLED_CLIENT_HOST_POLICY": policy,
			"AMX_INSTALLED_CLIENT_HOST_POLICY_SHA256": host.HostPolicySHA256})
	if selected.HostPolicy == policy || filepath.Dir(selected.HostPolicy) != filepath.Dir(directory) ||
		environment["AMX_INSTALLED_CLIENT_HOST_POLICY"] != selected.HostPolicy ||
		environment["AMX_INSTALLED_CLIENT_HOST_POLICY_SHA256"] != host.HostPolicySHA256 {
		t.Fatal("recovery input did not bind its disposable policy parent")
	}
	copy, err := os.ReadFile(selected.HostPolicy)
	info, statErr := os.Lstat(selected.HostPolicy)
	if err != nil || statErr != nil || !bytes.Equal(copy, raw) || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("recovery policy copy is not the exact private source")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatal("recovery enrollment directory is not initially empty")
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(policy), "authority-switch")); !os.IsNotExist(err) {
		t.Fatal("recovery input touched the original policy parent")
	}
}

func TestInstalledAuthoritySwitchRecoveryCollectorKeepsFixedTarget(t *testing.T) {
	enrollment := installedAuthoritySwitchRecoveryEnrollment{SchemaVersion: protocol.Version,
		Enrollment: "/private/fixture/client-selection.json", SHA256: "sha256:" + strings.Repeat("a", 64),
		RecoveryMaterial: installedAuthoritySwitchRecoveryMaterial{Path: "/private/fixture/authority-switch-recovery-material.json", SHA256: "sha256:" + strings.Repeat("b", 64)}}
	command := installedAuthoritySwitchRecoveryCollectorCommand("/prepared/go", "/approved/repository", enrollment,
		[]string{"SDKROOT=/approved/sdk", "AMX_INSTALLED_AUTHORITY_SWITCH_RECOVERY_MATERIAL=/other"})
	if command.Cancel != nil || command.WaitDelay != 0 || command.Dir != "/approved/repository/platform" ||
		!strings.Contains(strings.Join(command.Args, " "), "-run=^TestStableInstalledClientDarwinAuthoritySwitchRecovery$") {
		t.Fatal("recovery collector changed target or original wait ownership")
	}
	var material int
	for _, entry := range command.Env {
		if strings.HasPrefix(entry, "AMX_INSTALLED_AUTHORITY_SWITCH_RECOVERY_MATERIAL=") {
			material++
			if entry != "AMX_INSTALLED_AUTHORITY_SWITCH_RECOVERY_MATERIAL="+enrollment.RecoveryMaterial.Path {
				t.Fatal("recovery material path was overridden")
			}
		}
	}
	if material != 1 {
		t.Fatal("recovery material path is ambiguous")
	}
}
