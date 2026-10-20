//go:build darwin && arm64 && cgo && agentmux_bootstrap_docker

package deployment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

const installedOperatorPreparationFailurePrefix = "installed operator preparation failure: "

var installedOperatorPreparationFailureCategories = map[string]struct{}{
	"application_account_binding_mismatch":          {},
	"application_account_not_authorized":            {},
	"application_account_resolution_invalid":        {},
	"application_account_unavailable":               {},
	"attestation_time_invalid":                      {},
	"audience_mismatch":                             {},
	"authority_organization_mismatch":               {},
	"authority_owner_mismatch":                      {},
	"authority_reference_ambiguous":                 {},
	"authority_time_invalid":                        {},
	"contract_destination_mismatch":                 {},
	"contract_kind_mismatch":                        {},
	"contract_failure":                              {},
	"envelope_binding_mismatch":                     {},
	"installed_operator_preparation_broker_failure": {},
	"installed_operator_resolution_refused":         {},
	"schema_invalid":                                {},
	"semantic_invalid":                              {},
	"secret_custody_busy":                           {},
	"secret_custody_changed":                        {},
	"secret_custody_invalid":                        {},
	"secret_custody_native_refused":                 {},
	"secret_custody_not_authorized":                 {},
	"secret_custody_recovery_required":              {},
	"secret_custody_unavailable":                    {},
	"secret_custody_write_uncertain":                {},
	"signature_invalid":                             {},
	"unexpected_failure":                            {},
}

var installedOperatorPreparationFailureStages = map[string]struct{}{
	"materials": {}, "base_provision": {}, "authority_resolution": {},
	"secret_custody": {}, "binding_resolution": {}, "custody_write": {}, "result_write": {},
}

func installedOperatorPreparationFailure(stderr []byte) (string, bool) {
	for _, line := range strings.Split(string(stderr), "\n") {
		if !strings.HasPrefix(line, installedOperatorPreparationFailurePrefix) {
			continue
		}
		value := strings.TrimPrefix(line, installedOperatorPreparationFailurePrefix)
		parts := strings.Split(value, ":")
		if len(parts) != 2 {
			return value, false
		}
		_, stageAllowed := installedOperatorPreparationFailureStages[parts[0]]
		_, categoryAllowed := installedOperatorPreparationFailureCategories[parts[1]]
		return value, stageAllowed && categoryAllowed
	}
	return "", false
}

func TestInstalledOperatorPreparationFailureIsClosed(t *testing.T) {
	category, ok := installedOperatorPreparationFailure([]byte(
		"installed operator preparation failure: materials:schema_invalid\n" + installedServicePreparationHold + "\n"))
	if !ok || category != "materials:schema_invalid" {
		t.Fatal("allowlisted installed operator preparation failure was refused")
	}
	if _, ok := installedOperatorPreparationFailure([]byte(
		"installed operator preparation failure: private-detail\n")); ok {
		t.Fatal("unlisted installed operator preparation failure was accepted")
	}
}

type installedOperatorEnrollment struct {
	SchemaVersion           string `json:"schemaVersion"`
	Enrollment              string `json:"enrollment"`
	SHA256                  string `json:"sha256"`
	ServiceSelection        string `json:"serviceSelection"`
	ServiceSelectionSHA256  string `json:"serviceSelectionSHA256"`
	CustodyRoot             string `json:"custodyRoot"`
	ResolutionRequest       string `json:"resolutionRequest"`
	ResolutionRequestSHA256 string `json:"resolutionRequestSHA256"`
	OriginalOperationID     string `json:"originalOperationId"`
}

type installedOperatorHostInput struct {
	SchemaVersion string                    `json:"schemaVersion"`
	Host          installedServiceHostInput `json:"host"`
	Directory     string                    `json:"directory"`
}

type installedOperatorReceipt struct {
	SchemaVersion          string   `json:"schemaVersion"`
	Kind                   string   `json:"kind"`
	EffectID               string   `json:"effectId"`
	Stream                 string   `json:"stream"`
	RouteGeneration        uint64   `json:"routeGeneration"`
	RouteStreams           []string `json:"routeStreams"`
	RouterCredentialDigest string   `json:"routerCredentialDigest"`
}

func installedOperatorDecodeResult(raw []byte, directory string) (installedOperatorEnrollment, error) {
	var value installedOperatorEnrollment
	if protocol.DecodeClosedJSON(raw, &value, 16384) != nil || value.SchemaVersion != protocol.Version ||
		!installedServiceDigest.MatchString(value.SHA256) ||
		!installedServiceDigest.MatchString(value.ServiceSelectionSHA256) ||
		!installedServiceDigest.MatchString(value.ResolutionRequestSHA256) ||
		value.OriginalOperationID != "fixture_operator_operation" {
		return installedOperatorEnrollment{}, errInstalledOperatorResult
	}
	for _, path := range []string{value.Enrollment, value.ServiceSelection, value.ResolutionRequest} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) != directory {
			return installedOperatorEnrollment{}, errInstalledOperatorResult
		}
	}
	if !filepath.IsAbs(value.CustodyRoot) || filepath.Clean(value.CustodyRoot) != value.CustodyRoot ||
		filepath.Dir(value.CustodyRoot) != directory {
		return installedOperatorEnrollment{}, errInstalledOperatorResult
	}
	return value, nil
}

var errInstalledOperatorResult = &installedOperatorError{"installed_operator_preparation_output_invalid"}

type installedOperatorError struct{ code string }

func (e *installedOperatorError) Error() string { return e.code }

func TestInstalledIntegrationOperatorBorrowedJWTBroker(t *testing.T) {
	if _, finite := t.Deadline(); finite {
		t.Fatal("borrowed installed operator requires -timeout=0 for its failure hold")
	}
	if os.Getenv("AMX_BOOTSTRAP_DOCKER_AUTHORIZED") != "1" {
		t.Fatal("explicit installed operator fixture authorization required")
	}
	inputPath, inputDigest := os.Getenv("AMX_INSTALLED_SERVICE_HOST_INPUT"), os.Getenv("AMX_INSTALLED_SERVICE_HOST_INPUT_SHA256")
	if !filepath.IsAbs(inputPath) || filepath.Clean(inputPath) != inputPath ||
		!installedServiceDigest.MatchString(inputDigest) {
		t.Fatal("explicit private installed host input required")
	}
	raw, err := teamReadPrivate(filepath.Dir(inputPath), filepath.Base(inputPath), uint32(os.Geteuid()))
	if err != nil {
		t.Fatal("private installed host input refused")
	}
	defer clear(raw)
	sum := sha256.Sum256(raw)
	var input installedOperatorHostInput
	if inputDigest != "sha256:"+hex.EncodeToString(sum[:]) ||
		protocol.DecodeClosedJSON(raw, &input, 16384) != nil || input.SchemaVersion != protocol.Version {
		t.Fatal("closed pinned installed host input required")
	}
	host := input.Host
	if !installedServiceDigest.MatchString(host.HostPolicySHA256) ||
		!installedServiceInstallation.MatchString(host.InstallationID) || len(host.Workspaces) != 1 ||
		!filepath.IsAbs(host.HostPolicy) || filepath.Clean(host.HostPolicy) != host.HostPolicy ||
		!filepath.IsAbs(host.Workspaces[0]) {
		t.Fatal("installed operator input differs from selected host pins")
	}
	preparationOnly := os.Getenv("AMX_INSTALLED_OPERATOR_PREPARATION_ONLY") == "1"
	directPackage := os.Getenv("AMX_INSTALLED_OPERATOR_DIRECT_PACKAGE") == "1"
	var packageAdmission *protected.InstalledClientAdmission
	if !preparationOnly && !directPackage {
		packageAdmission, err = protected.PrepareInstalledClient(context.Background(), host.InstallationID)
		if err != nil {
			t.Fatalf("installed operator package admission failed: %v", err)
		}
		t.Cleanup(func() {
			if packageAdmission.Close() != nil {
				t.Error("installed operator package cleanup failed")
			}
		})
	}
	packageRoot := filepath.Join(protected.InstalledClientBase, host.InstallationID)
	python := filepath.Join(packageRoot, protected.ClientInterpreter)
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal("repository root unavailable")
	}
	directory := input.Directory
	resolved, resolveErr := filepath.EvalSymlinks(directory)
	metadata, statErr := os.Lstat(directory)
	entries, readErr := os.ReadDir(directory)
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || resolveErr != nil ||
		resolved != directory || statErr != nil || !metadata.IsDir() || metadata.Mode().Perm()&0077 != 0 ||
		readErr != nil || len(entries) != 0 {
		t.Fatal("canonical private operator preparation directory unavailable")
	}
	fixture := newJWTWorkerStorageFixture(t)
	owner := &installedServiceBorrow{fixture: fixture}
	peer, err := fixture.publisher.TLSConnectionState()
	if err != nil || len(peer.PeerCertificates) == 0 {
		t.Fatal("verified fixture TLS peer unavailable")
	}
	leaf := sha256.Sum256(peer.PeerCertificates[0].Raw)
	seed, err := fixture.account.Seed()
	if err != nil {
		t.Fatal("fixture account seed unavailable")
	}
	defer clear(seed)
	verifierAccount, err := nkeys.FromSeed(bytes.Clone(seed))
	if err != nil {
		t.Fatal("fixture verifier account unavailable")
	}
	t.Cleanup(verifierAccount.Wipe)
	plan, err := json.Marshal(map[string]any{"schemaVersion": protocol.Version, "host": host,
		"directory": directory, "broker": map[string]string{"endpoint": fixture.policy.Endpoint,
			"rootsPEM": string(fixture.policy.TLSRootsPEM), "serverName": fixture.policy.TLSServerName,
			"domain": fixture.policy.ExpectedDomain, "leafPin": "sha256:" + hex.EncodeToString(leaf[:]),
			"accountSeed": string(seed)}})
	if err != nil {
		t.Fatal("private installed operator plan encoding failed")
	}
	preparation := exec.Command(python, "-B", "-I", "-S", "platform/launcher/testdata/installed_operator_package_bootstrap.py")
	preparation.Dir = root
	preparation.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + directory, "TMPDIR=" + directory,
		"AMX_INSTALLED_OPERATOR_PACKAGE_ROOT=" + packageRoot,
		"AMX_INSTALLED_OPERATOR_PACKAGE_ID=" + host.InstallationID,
		"PYTHONDONTWRITEBYTECODE=1"}
	preparation.Stdin = bytes.NewReader(plan)
	releaseRead, releaseWrite, err := os.Pipe()
	if err != nil {
		t.Fatal("installed operator preparation release channel unavailable")
	}
	preparation.ExtraFiles = []*os.File{releaseRead}
	owner.onHold = func() { _ = releaseWrite.Close() }
	prepared, bounded, err := owner.run(t, preparation, 16384)
	owner.onHold = nil
	_ = releaseRead.Close()
	_ = releaseWrite.Close()
	clear(plan)
	clear(seed)
	preparationDiagnostic, diagnosticBounded := owner.outputs[len(owner.outputs)-1].result()
	defer clear(preparationDiagnostic)
	if err != nil || !bounded {
		if category, reported := installedOperatorPreparationFailure(preparationDiagnostic); reported && diagnosticBounded {
			t.Fatalf("installed_operator_preparation_failed: %s", category)
		}
		t.Fatal("installed_operator_preparation_unconfirmed")
	}
	if packageAdmission != nil && packageAdmission.Recheck(context.Background()) != nil {
		t.Fatal("installed_operator_package_changed")
	}
	enrollment, err := installedOperatorDecodeResult(prepared, directory)
	if err != nil {
		t.Fatal("installed_operator_preparation_output_refused")
	}
	request, err := teamReadPrivate(directory, filepath.Base(enrollment.ResolutionRequest), uint32(os.Geteuid()))
	if err != nil {
		t.Fatal("installed_operator_resolution_request_unavailable")
	}
	defer clear(request)
	requestSum := sha256.Sum256(request)
	if enrollment.ResolutionRequestSHA256 != "sha256:"+hex.EncodeToString(requestSum[:]) || !json.Valid(request) {
		t.Fatal("installed_operator_resolution_request_changed")
	}
	if preparationOnly {
		t.Log("installed operator preparation completed and original waits and readers joined")
		return
	}
	var commandInput []byte
	var command *exec.Cmd
	var lease *os.File
	if directPackage {
		commandInput, err = json.Marshal(map[string]any{"schemaVersion": protocol.Version,
			"kind": "integration-effect-provision", "selection": enrollment.ServiceSelection,
			"selectionSHA256": enrollment.ServiceSelectionSHA256, "hostPolicy": host.HostPolicy,
			"ownerUid": os.Geteuid(), "workspaces": host.Workspaces, "kernelScope": host.KernelScope,
			"protectedHostAccount": map[string]any{"kind": "named-password", "account": "HOST",
				"broker": map[string]string{"endpoint": fixture.policy.Endpoint,
					"serverName":   fixture.policy.ExpectedServerName,
					"configSha256": "sha256:" + strings.Repeat("0", 64)}},
			"custodyRoot":             enrollment.CustodyRoot,
			"originalOperationId":     enrollment.OriginalOperationID,
			"resolutionRequestBase64": base64.StdEncoding.EncodeToString(request), "leaseFd": 3})
		leasePath := filepath.Join(directory, "direct-operator-lease")
		lease, err = os.OpenFile(leasePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err == nil {
			defer os.Remove(leasePath)
			command = exec.Command(python, "-B", "-I", "-S",
				"platform/launcher/testdata/installed_operator_command_diagnostic.py")
			command.Dir = root
			command.ExtraFiles = []*os.File{lease}
		}
	} else {
		commandInput, err = json.Marshal(map[string]any{"schemaVersion": protocol.Version,
			"kind":                "integration-effect-provision-request",
			"originalOperationId": enrollment.OriginalOperationID,
			"resolutionRequest":   json.RawMessage(request)})
		command = exec.Command(protected.StableFrontendPath, "provision-integration-effect",
			"--host-policy", host.HostPolicy, "--workspace", host.Workspaces[0],
			"--application-services-installation", host.InstallationID,
			"--application-services-selection", enrollment.ServiceSelection,
			"--application-services-selection-sha256", enrollment.ServiceSelectionSHA256,
			"--custody-root", enrollment.CustodyRoot)
	}
	if err != nil {
		t.Fatal("installed_operator_request_encoding_failed")
	}
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=en_US.UTF-8", "LC_CTYPE=UTF-8",
		"AMX_INSTALLED_OPERATOR_PACKAGE_ROOT=" + packageRoot,
		"AMX_INSTALLED_OPERATOR_PACKAGE_ID=" + host.InstallationID,
		"PYTHONDONTWRITEBYTECODE=1"}
	command.Stdin = bytes.NewReader(commandInput)
	result, bounded, err := owner.run(t, command, 16384)
	if lease != nil {
		_ = lease.Close()
	}
	clear(commandInput)
	if err != nil || !bounded {
		if directPackage {
			diagnostic, complete := owner.outputs[len(owner.outputs)-1].result()
			defer clear(diagnostic)
			for _, line := range strings.Split(string(diagnostic), "\n") {
				if complete && strings.HasPrefix(line, "installed operator command failure: ") {
					code := strings.TrimPrefix(line, "installed operator command failure: ")
					if regexp.MustCompile(`^[a-z][a-z0-9_]{0,95}$`).MatchString(code) {
						t.Fatalf("installed_operator_command_failed: %s", code)
					}
				}
			}
		}
		t.Fatal("installed_operator_command_unconfirmed")
	}
	stderr, stderrComplete := owner.outputs[len(owner.outputs)-1].result()
	defer clear(stderr)
	var receipt installedOperatorReceipt
	if !stderrComplete || len(stderr) != 0 || protocol.DecodeClosedJSON(result, &receipt, 16384) != nil ||
		receipt.SchemaVersion != protocol.Version || receipt.Kind != "integration-effect-provisioned" ||
		receipt.RouteGeneration != 1 || len(receipt.RouteStreams) != 1 || receipt.RouteStreams[0] != receipt.Stream ||
		!installedServiceDigest.MatchString(receipt.RouterCredentialDigest) || receipt.EffectID == "" || receipt.Stream == "" {
		t.Fatal("installed_operator_receipt_refused")
	}
	verifier := jwtWorkerKey(t, nkeys.CreateUser)
	infoSubjects := []string{"$JS.API.STREAM.INFO." + receipt.Stream,
		"$JS." + fixture.policy.ExpectedDomain + ".API.STREAM.INFO." + receipt.Stream}
	token := jwtWorkerUser(t, verifierAccount, verifier, infoSubjects, []string{"_INBOX.>"})
	connection, err := jwtWorkerConnect(fixture, token, verifier, func(*nats.Conn, *nats.Subscription, error) {})
	if err != nil {
		t.Fatal("installed_operator_verifier_connection_failed")
	}
	defer connection.Close()
	js, err := connection.JetStream(nats.Domain(fixture.policy.ExpectedDomain), nats.MaxWait(2*time.Second))
	if err != nil {
		t.Fatal("installed_operator_verifier_unavailable")
	}
	info, err := js.StreamInfo(receipt.Stream)
	if err != nil || info.Config.Name != receipt.Stream || info.State.Msgs != 0 {
		t.Fatal("installed_operator_stream_unconfirmed")
	}
	t.Log("installed operator command, stream check, original waits and readers joined")
}
