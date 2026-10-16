//go:build (linux || darwin) && agentmux_bootstrap_docker

package launcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

type composeCLIExit struct {
	err error
	at  time.Time
}

// Platform code alone launches, joins and proves ownership. These buffer references
// keep Linux wrappers intact and let Darwin use Owned without exposing its command.
// Read either buffer only after the platform's sole wait has joined output copying.
type composeCLIOutput struct {
	stdout, stderr *bytes.Buffer
	started        time.Time
	terminal       composeCLIExit
	joined         bool
	captureName    string
	captured       bool
}

type composeCLIReceiptDocument struct {
	SchemaVersion      string                            `json:"schemaVersion"`
	Kind               string                            `json:"kind"`
	RequestDisposition string                            `json:"requestDisposition"`
	InstanceState      string                            `json:"instanceState"`
	Receipt            protected.BootstrapControlReceipt `json:"receipt"`
	DetailsAvailable   bool                              `json:"detailsAvailable"`
	Message            string                            `json:"message"`
}

// Save the actual bytes privately before any assertion. The .private suffix
// excludes this unvalidated output from the public JSON evidence cohort.
func composeCLICaptureOutput(directory, name string, raw []byte) error {
	return composeCLICaptureStream(directory, name, "stdout", raw)
}

func composeCLICaptureStream(directory, name, stream string, raw []byte) error {
	if len(raw) > 64*1024 || name == "" || filepath.Base(name) != name {
		return errors.New("cli_output_capture_bounds")
	}
	if stream != "stdout" && stream != "stderr" {
		return errors.New("cli_output_capture_bounds")
	}
	file, err := os.OpenFile(filepath.Join(directory, name+"-"+stream+".private"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cli_output_capture_open")
	}
	n, writeErr := file.Write(raw)
	closeErr := file.Close()
	if writeErr != nil || n != len(raw) || closeErr != nil {
		return errors.New("cli_output_capture_write")
	}
	return nil
}

func (x *composeCLIOutput) captureJoined(directory string) error {
	if x == nil || !x.joined {
		return errors.New("cli_output_capture_unjoined")
	}
	if x.captured {
		return nil
	}
	if err := composeCLICaptureOutput(directory, x.captureName, x.stdout.Bytes()); err != nil {
		return err
	}
	if err := composeCLICaptureStream(directory, x.captureName, "stderr", x.stderr.Bytes()); err != nil {
		return err
	}
	x.captured = true
	return nil
}

func (x *composeCLIOutput) writeCapture(t *testing.T, f *bootstrapDockerFixture) {
	t.Helper()
	if x.captureName == "" {
		x.captureName = "frontend-cleanup-" + bootstrapFixtureRandom(t, 4)
	}
	if err := x.captureJoined(f.EvidenceDirectory); err != nil {
		t.Error(err.Error())
		return
	}
	f.WriteEvidence(t, x.captureName+"-output-capture.json", map[string]any{"privateCapture": true, "frontendWaitJoined": true, "bytes": x.stdout.Len(), "sha256": releaseDigest(x.stdout.Bytes()), "stderrBytes": x.stderr.Len(), "stderrSHA256": releaseDigest(x.stderr.Bytes())})
}

func composeCLIReceiptCode(raw []byte, allowReceipt bool) (composeCLIReceiptDocument, string) {
	var out composeCLIReceiptDocument
	var shape map[string]json.RawMessage
	if len(raw) > 64*1024 || json.Unmarshal(raw, &shape) != nil || shape == nil {
		return out, "cli_output_json_invalid"
	}
	if !allowReceipt {
		return out, "cli_authenticated_response_required"
	}
	if len(shape) != 7 || protocol.DecodeClosedJSON(raw, &out, 64*1024) != nil {
		return out, "cli_receipt_shape_invalid"
	}
	if out.SchemaVersion != protocol.Version || out.Kind != "bootstrap-progress" {
		return out, "cli_receipt_version_or_kind_invalid"
	}
	if out.RequestDisposition != "accepted" || out.Receipt.Outcome != "accepted" {
		return out, "cli_receipt_not_accepted"
	}
	if out.InstanceState != "unknown" || out.DetailsAvailable {
		return out, "cli_receipt_readiness_overclaimed"
	}
	return out, ""
}

func composeCLIReceiptBindingCode(binding protected.BootstrapReceiptBinding, scope protocol.Scope, enrollment, attempt, image string, creatorOwned bool) string {
	if binding.Scope != scope || binding.EnrollmentDigest != enrollment || !ownerBridgeInvocation.MatchString(binding.ColdInvocationID) {
		return "cli_receipt_enrollment_binding_invalid"
	}
	if !creatorOwned || attempt == "" || binding.ColdInvocationID != attempt || binding.RuntimeDigest != image {
		return "cli_receipt_creator_or_image_binding_invalid"
	}
	return ""
}

// Creator binding comes only from platform-owned admission, never output or a PID.
func composeCLIOutputObservation(t *testing.T, f *bootstrapDockerFixture, x *composeCLIOutput, r hostPolicyRecord, raw []byte, name string, allowReceipt bool, attempt string, creatorOwned bool) *StartupStatusObservation {
	t.Helper()
	if x == nil || !x.joined || !x.captured {
		t.Fatal("cli_output_capture_unavailable")
	}
	var shape map[string]json.RawMessage
	if json.Unmarshal(raw, &shape) != nil {
		t.Fatal("cli_output_json_invalid")
	}
	if _, receipt := shape["kind"]; receipt {
		out, code := composeCLIReceiptCode(raw, allowReceipt)
		if code != "" {
			t.Fatal(code)
		}
		if code := composeCLIReceiptBindingCode(out.Receipt.Binding, f.Config.Kernel.Scope, releaseDigest(mustStatusJSON(f.BridgeEnrollment.Owner)), attempt, r.RuntimeExecutable.Digest, creatorOwned); code != "" {
			t.Fatal(code)
		}
		f.WriteEvidence(t, name+"-receipt-expected.json", map[string]any{"source": "Actual creating frontend child arguments and held image admission", "coldInvocationId": attempt, "runtimeDigest": r.RuntimeExecutable.Digest, "scope": f.Config.Kernel.Scope, "enrollmentDigest": releaseDigest(mustStatusJSON(f.BridgeEnrollment.Owner))})
		f.WriteEvidence(t, name+".json", out)
		return nil
	}
	var out StartupStatusObservation
	if protocol.DecodeClosedJSON(raw, &out, 64*1024) != nil || (out.Disposition != "starting" && out.Disposition != "started" && out.Disposition != "reused") || out.Instance.InstanceID == nil || *out.Instance.InstanceID != f.Profile.InstanceID {
		t.Fatal("actual L04 CLI output rejected")
	}
	owner := f.BridgeEnrollment.Owner
	if out.SchemaVersion != protocol.Version || out.StartupAttemptID == nil || !ownerBridgeInvocation.MatchString(*out.StartupAttemptID) || out.Caller.PrincipalID != owner.PrincipalID || out.Caller.Identity != owner.Identity || !reflect.DeepEqual(out.Caller.Scope, owner.Scope) || out.Instance.ProfileID == nil || *out.Instance.ProfileID != owner.ProfileID || out.SourceRevision == 0 || !kernelStatusID.MatchString(out.ObservationID) {
		t.Fatal("actual L04 CLI output does not match enrolled owner")
	}
	if out.Disposition == "starting" && !bridgeStartingUnknown(out) {
		t.Fatal("starting CLI observation overclaims readiness")
	}
	f.WriteEvidence(t, name+".json", out)
	return &out
}

func composeCLIRefresh(t *testing.T, f *bootstrapDockerFixture, startupDeadline time.Time) StartupStatusObservation {
	t.Helper()
	client, err := LoadOwnerBridgeClient(f.Config, *f.BridgeEnrollment)
	if err != nil {
		t.Fatal("actual authenticated refresh client refused")
	}
	ctx, cancel := context.WithDeadline(context.Background(), startupDeadline)
	defer cancel()
	for ctx.Err() == nil {
		request, stop := context.WithTimeout(ctx, 5*time.Second)
		out, e := client.Request(request, "status", "attempt_"+bootstrapFixtureRandom(t, 16))
		stop()
		code := "none"
		if e != nil {
			switch e.Error() {
			case "owner_bridge_connection_unavailable", "owner_bridge_reply_unavailable", "owner_bridge_deadline":
				code = e.Error()
			default:
				code = "closed_unclassified_failure"
			}
		}
		f.WriteEvidence(t, "refresh-attempt-"+bootstrapFixtureRandom(t, 4)+".json", map[string]any{"errorCode": code, "deadlineExpired": ctx.Err() != nil, "disposition": out.Disposition})
		if e == nil && (out.Disposition == "started" || out.Disposition == "reused") {
			if out.Instance.RunningVersion == nil || out.Instance.Readiness != "degraded" || out.Work.State != "unavailable" || out.Hubs.InventoryState != "unavailable" {
				t.Fatal("actual completed status lacks current kernel evidence")
			}
			for _, role := range protocol.Roles() {
				found := false
				for _, service := range out.Instance.Services {
					if service.ServiceID == role && service.Readiness == "ready" && service.ObservedAt != nil && service.SourceRevision != nil {
						found = true
					}
				}
				if !found {
					t.Fatal("actual completed role lacks current readiness")
				}
			}
			return out
		}
		if e != nil && e.Error() != "owner_bridge_connection_unavailable" && e.Error() != "owner_bridge_reply_unavailable" && e.Error() != "owner_bridge_deadline" {
			t.Fatal("actual refresh authority or runtime failed")
		}
		if e == nil && out.Disposition != "starting" {
			t.Fatal("actual startup failed")
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("actual installed runtime did not complete within startup budget")
	return StartupStatusObservation{}
}

// Platform callers supply a terminal record only after their sole wait has joined.
func (x *composeCLIOutput) joinedDiagnostic(creatorOwned bool) map[string]any {
	code := "failed"
	if x.terminal.err == nil {
		code = "success"
	}
	var exitStatus any = nil
	var processExit *exec.ExitError
	if x.terminal.err == nil {
		exitStatus = 0
	} else if errors.As(x.terminal.err, &processExit) {
		exitStatus = processExit.ExitCode()
	}
	return map[string]any{"frontendWaitJoined": true, "entryToExitNanoseconds": x.terminal.at.Sub(x.started).Nanoseconds(), "exitOutcome": code, "exitStatus": exitStatus, "stdoutBytes": x.stdout.Len(), "stderrBytes": x.stderr.Len(), "exactHostPinned": creatorOwned}
}

func TestComposeCLICommonCaptureRequiresJoinedState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		output *composeCLIOutput
	}{
		{"nil", nil},
		{"unjoined", &composeCLIOutput{captureName: "unjoined"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			if err := tc.output.captureJoined(directory); err == nil || err.Error() != "cli_output_capture_unjoined" {
				t.Fatal("missing joined state was not refused")
			}
			if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
				t.Fatal("unjoined capture touched the filesystem")
			}
		})
	}
}

func TestComposeCLICommonCaptureBoundsAndExclusiveFiles(t *testing.T) {
	directory := t.TempDir()
	stdout, stderr := bytes.NewBuffer(bytes.Repeat([]byte("x"), 64*1024)), bytes.NewBufferString("private stderr")
	output := &composeCLIOutput{stdout: stdout, stderr: stderr, joined: true, captureName: "bounded"}
	if err := output.captureJoined(directory); err != nil || !output.captured {
		t.Fatal("joined boundary-sized capture failed")
	}
	if err := output.captureJoined(directory); err != nil {
		t.Fatal("completed capture was not reused")
	}
	for stream, expected := range map[string][]byte{"stdout": stdout.Bytes(), "stderr": stderr.Bytes()} {
		path := filepath.Join(directory, "bounded-"+stream+".private")
		raw, err := os.ReadFile(path)
		info, statErr := os.Stat(path)
		if err != nil || statErr != nil || !bytes.Equal(raw, expected) || info.Mode().Perm() != 0600 {
			t.Fatal("private joined capture differs")
		}
	}
	replacement := &composeCLIOutput{stdout: bytes.NewBufferString("replacement"), stderr: new(bytes.Buffer), joined: true, captureName: "bounded"}
	if err := replacement.captureJoined(directory); err == nil || err.Error() != "cli_output_capture_open" || replacement.captured {
		t.Fatal("exclusive capture accepted a replacement")
	}
	raw, err := os.ReadFile(filepath.Join(directory, "bounded-stdout.private"))
	if err != nil || !bytes.Equal(raw, stdout.Bytes()) {
		t.Fatal("refused replacement changed the original capture")
	}
	for _, stream := range []string{"stdout", "stderr"} {
		t.Run(stream+"_oversized", func(t *testing.T) {
			directory := t.TempDir()
			output := &composeCLIOutput{stdout: new(bytes.Buffer), stderr: new(bytes.Buffer), joined: true, captureName: "oversized"}
			if stream == "stdout" {
				output.stdout.Write(bytes.Repeat([]byte("x"), 64*1024+1))
			} else {
				output.stderr.Write(bytes.Repeat([]byte("x"), 64*1024+1))
			}
			if err := output.captureJoined(directory); err == nil || err.Error() != "cli_output_capture_bounds" || output.captured {
				t.Fatal("oversized stream was not refused")
			}
			if _, err := os.Stat(filepath.Join(directory, "oversized-"+stream+".private")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("oversized stream created a capture")
			}
		})
	}
}

func TestComposeCLICommonBoundReceiptAndOverclaim(t *testing.T) {
	sha := "sha256:" + strings.Repeat("a", 64)
	scope := protocol.Scope{HubID: "fixture_hub", InstanceID: "fixture_instance", ProfileID: "fixture_profile", AssemblyDigest: sha, ReleaseManifestDigest: sha, ReleaseVersion: "1.0.0"}
	attempt := "attempt_" + strings.Repeat("b", 32)
	binding := protected.BootstrapReceiptBinding{Scope: scope, EnrollmentDigest: sha, ColdInvocationID: attempt, RuntimeDigest: sha}
	accepted := composeCLIReceiptDocument{SchemaVersion: protocol.Version, Kind: "bootstrap-progress", RequestDisposition: "accepted", InstanceState: "unknown", Receipt: protected.BootstrapControlReceipt{SchemaVersion: protocol.Version, Kind: "bootstrap-control-receipt", Binding: binding, Outcome: "accepted"}, Message: "Current details are unavailable."}
	encode := func(document composeCLIReceiptDocument) []byte {
		t.Helper()
		raw, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	raw := encode(accepted)
	out, code := composeCLIReceiptCode(raw, true)
	if code != "" || !reflect.DeepEqual(out, accepted) || composeCLIReceiptBindingCode(out.Receipt.Binding, scope, sha, attempt, sha, true) != "" {
		t.Fatal("complete matching receipt was refused or changed")
	}
	if _, code := composeCLIReceiptCode(raw, false); code != "cli_authenticated_response_required" {
		t.Fatal("receipt replaced required authenticated status")
	}
	if code := composeCLIReceiptBindingCode(out.Receipt.Binding, scope, sha, attempt, sha, false); code != "cli_receipt_creator_or_image_binding_invalid" {
		t.Fatal("receipt supplied creator authority")
	}
	for _, tc := range []struct {
		name   string
		change func(*composeCLIReceiptDocument)
	}{
		{"ready", func(document *composeCLIReceiptDocument) { document.InstanceState = "ready" }},
		{"details", func(document *composeCLIReceiptDocument) { document.DetailsAvailable = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			document := accepted
			tc.change(&document)
			if _, code := composeCLIReceiptCode(encode(document), true); code != "cli_receipt_readiness_overclaimed" {
				t.Fatal("fully bound receipt overclaimed readiness")
			}
		})
	}
}

func TestComposeCLICommonJoinedDiagnosticCompletedState(t *testing.T) {
	started := time.Unix(1700000000, 0)
	output := &composeCLIOutput{stdout: bytes.NewBufferString("private output"), stderr: bytes.NewBufferString("private stderr"), started: started, terminal: composeCLIExit{at: started.Add(time.Second)}, joined: true}
	for _, creatorOwned := range []bool{false, true} {
		expected := map[string]any{"frontendWaitJoined": true, "entryToExitNanoseconds": int64(time.Second), "exitOutcome": "success", "exitStatus": 0, "stdoutBytes": len("private output"), "stderrBytes": len("private stderr"), "exactHostPinned": creatorOwned}
		if row := output.joinedDiagnostic(creatorOwned); !reflect.DeepEqual(row, expected) {
			t.Fatal("completed joined diagnostic differs")
		}
	}
	output.terminal.err = errors.New("private terminal error")
	row := output.joinedDiagnostic(false)
	if row["exitOutcome"] != "failed" || row["exitStatus"] != nil || row["exactHostPinned"] != false || row["frontendWaitJoined"] != true {
		t.Fatal("joined failure fabricated success or creator authority")
	}
	raw, err := json.Marshal(row)
	if err != nil || bytes.Contains(raw, []byte("private")) {
		t.Fatal("joined diagnostic exposed private data")
	}
}
