//go:build (darwin && arm64) || ((linux || darwin) && agentmux_application_services)

package launcher

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

const integrationOperatorOutputLimit = 16 * 1024

type integrationOperatorRequest struct {
	SchemaVersion           string                          `json:"schemaVersion"`
	Kind                    string                          `json:"kind"`
	Selection               string                          `json:"selection"`
	SelectionSHA256         string                          `json:"selectionSHA256"`
	HostPolicy              string                          `json:"hostPolicy"`
	OwnerUID                uint32                          `json:"ownerUid"`
	Workspaces              []string                        `json:"workspaces"`
	KernelScope             protocol.Scope                  `json:"kernelScope"`
	ProtectedHostAccount    applicationProtectedHostAccount `json:"protectedHostAccount"`
	CustodyRoot             string                          `json:"custodyRoot"`
	OriginalOperationID     string                          `json:"originalOperationId"`
	ResolutionRequestBase64 string                          `json:"resolutionRequestBase64"`
	LeaseFD                 int                             `json:"leaseFd"`
}

type integrationOperatorReceipt struct {
	SchemaVersion          string   `json:"schemaVersion"`
	Kind                   string   `json:"kind"`
	EffectID               string   `json:"effectId"`
	Stream                 string   `json:"stream"`
	RouteGeneration        uint64   `json:"routeGeneration"`
	RouteStreams           []string `json:"routeStreams"`
	RouterCredentialDigest string   `json:"routerCredentialDigest"`
}

type boundedOperatorOutput struct {
	buffer   bytes.Buffer
	overflow bool
}

func (w *boundedOperatorOutput) Write(raw []byte) (int, error) {
	count := len(raw)
	remaining := integrationOperatorOutputLimit - w.buffer.Len()
	if remaining > 0 {
		if len(raw) > remaining {
			raw = raw[:remaining]
		}
		_, _ = w.buffer.Write(raw)
	}
	if count > remaining {
		w.overflow = true
	}
	return count, nil
}

var integrationOperatorID = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,95}$`)
var integrationOperatorStream = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func validateIntegrationOperatorReceipt(raw []byte) error {
	var receipt integrationOperatorReceipt
	if len(raw) == 0 || len(raw) > integrationOperatorOutputLimit || protocol.DecodeClosedJSON(bytes.TrimSpace(raw), &receipt, integrationOperatorOutputLimit) != nil ||
		receipt.SchemaVersion != protocol.Version || receipt.Kind != "integration-effect-provisioned" ||
		!integrationOperatorID.MatchString(receipt.EffectID) || !integrationOperatorStream.MatchString(receipt.Stream) ||
		receipt.RouteGeneration == 0 || receipt.RouteGeneration > protocol.MaxRevision || len(receipt.RouteStreams) == 0 || len(receipt.RouteStreams) > 100000 ||
		!kernelStatusDigest.MatchString(receipt.RouterCredentialDigest) {
		return serviceProcessError("operator_receipt_invalid", nil)
	}
	seen := map[string]bool{}
	for _, stream := range receipt.RouteStreams {
		if !integrationOperatorStream.MatchString(stream) || seen[stream] {
			return serviceProcessError("operator_receipt_invalid", nil)
		}
		seen[stream] = true
	}
	return nil
}

// ProvisionIntegrationEffect runs one separately owned operator process. The
// long-lived application-service process never receives custody or administrator
// material. Signed request bytes travel on stdin and are not process arguments.
func (host *EnrolledHostPolicy) ProvisionIntegrationEffect(parent context.Context,
	selected ApplicationServiceProcessSelection, custodyRoot string,
	originalOperationID string, resolutionRequest []byte, output io.Writer) (failure error) {
	if host == nil || parent == nil || parent.Err() != nil || output == nil ||
		!integrationOperatorID.MatchString(originalOperationID) || len(resolutionRequest) == 0 || len(resolutionRequest) > 65536 {
		return serviceProcessError("operator_request_invalid", nil)
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	// The short-lived operator uses its separately admitted custody root. Older
	// installed selections therefore do not need the long-lived service switch.
	start, admission, err := host.prepareApplicationServices(ctx, selected, nil, false)
	if err != nil {
		return err
	}
	defer func() { failure = errors.Join(failure, admission.Close()) }()
	root, err := openPrivateHostRoot(custodyRoot, host.selection.OwnerUID, host.selection.WorkspaceRoots)
	if err != nil {
		return serviceProcessError("operator_custody_invalid", err)
	}
	if err := root.Close(); err != nil {
		return serviceProcessError("operator_custody_cleanup_failed", err, root)
	}
	lease, err := AcquireBootstrapLock(ctx, host.record.ProfileDirectory, host.record.InstanceID, "integration-operator")
	if err != nil {
		return serviceProcessError("operator_lease_unavailable", err)
	}
	defer func() { failure = errors.Join(failure, lease.Close()) }()
	request := integrationOperatorRequest{protocol.Version, "integration-effect-provision",
		start.Selection, start.SelectionSHA256, start.HostPolicy, start.OwnerUID,
		append([]string(nil), start.Workspaces...), start.KernelScope,
		start.ProtectedHostAccount, custodyRoot, originalOperationID,
		base64.StdEncoding.EncodeToString(resolutionRequest), 3}
	raw, err := json.Marshal(request)
	if err != nil || len(raw) > 131072 {
		return serviceProcessError("operator_request_invalid", err)
	}
	if err := admission.Recheck(ctx); err != nil {
		return serviceProcessError("package_changed", err, admission)
	}
	packageRoot := filepath.Join(protected.InstalledClientBase, selected.InstallationID)
	command := exec.CommandContext(ctx, filepath.Join(packageRoot, protected.ClientInterpreter),
		"-B", "-I", "-S", filepath.Join(packageRoot, protected.ClientBootstrap), "integration-operator")
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=en_US.UTF-8", "LC_CTYPE=UTF-8"}
	command.Stdin = bytes.NewReader(raw)
	command.ExtraFiles = []*os.File{lease.file}
	command.WaitDelay = time.Second
	stdout, stderr := &boundedOperatorOutput{}, &boundedOperatorOutput{}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil {
		return serviceProcessError("operator_process_failed", errors.Join(err, ctx.Err()))
	}
	if stdout.overflow || stderr.overflow || stderr.buffer.Len() != 0 || validateIntegrationOperatorReceipt(stdout.buffer.Bytes()) != nil {
		return serviceProcessError("operator_output_invalid", nil)
	}
	if _, err := output.Write(stdout.buffer.Bytes()); err != nil {
		return serviceProcessError("operator_output_failed", err)
	}
	return nil
}
