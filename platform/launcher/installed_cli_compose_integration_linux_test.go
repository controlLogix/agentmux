//go:build linux && agentmux_bootstrap_docker

package launcher

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
	"golang.org/x/sys/unix"
)

// These cases use the actual enrolled Docker executable. No inspection wrapper
// or standalone NATS process can supply an instance observation here.
func composeCLIPolicy(t *testing.T, f *bootstrapDockerFixture) (HostPolicySelection, hostPolicyRecord) {
	t.Helper()
	if f.BridgeEnrollment == nil || f.Config.OwnerBridge == nil {
		t.Fatal("actual HOST enrollment missing")
	}
	directory := filepath.Join(f.EvidenceDirectory, "installed")
	if os.Mkdir(directory, 0700) != nil {
		t.Fatal("private runtime installation unavailable")
	}
	binary := filepath.Join(directory, "agentmux-runtime")
	installedCLIBuild(t, "./cmd/agentmux-runtime", binary)
	bootstrapCheckNativeKernel(t, binary, bootstrapActualHost().GOARCH)
	content, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal("actual runtime bytes unavailable")
	}
	p := f.HostPolicy.ExternalRelease
	r := hostPolicyRecord{SchemaVersion: protocol.Version, OwnerUID: f.Profile.OwnerUID, ProfileDirectory: f.Profile.ProfileDirectory, ProfileID: f.Profile.ProfileID, InstanceID: f.Profile.InstanceID, Owner: f.BridgeEnrollment.Owner, ServerName: f.Config.Health.ServerName, Domain: f.Config.Health.Domain, PublicEndpoint: f.Profile.NATSEndpoint, PublicContextName: f.Profile.Docker.Context, RuntimeExecutable: hostPolicyExecutable{binary, releaseDigest(content)}, Limits: hostPolicyLimits{60000, 3000, 10000, 2000, 3000}, OwnerBridge: &f.BridgeEnrollment.Credentials, Release: hostPolicyRelease{p.PackageDirectory, hex.EncodeToString(p.PublicKey), p.ReleaseManifestDigest, p.ReleaseAuthority, p.ReleaseVersion, p.KernelAPIMajor}}
	s := HostPolicySelection{Path: filepath.Join(directory, "host-policy.json"), OwnerUID: f.Profile.OwnerUID, WorkspaceRoots: append([]string(nil), f.HostPolicy.Profile.WorkspaceRoots...)}
	writeInstalledHostPolicy(t, s.Path, r)
	h, err := LoadEnrolledHostPolicy(s)
	if err != nil {
		t.Fatal("actual installed policy refused")
	}
	c, _, err := h.Load()
	loaded, profileErr := LoadProfile(c.ProfilePolicy)
	if err != nil || profileErr != nil || loaded.Declaration().Docker.Executable != f.Profile.Docker.Executable {
		t.Fatal("actual Docker selection changed during installed admission")
	}
	return s, r
}

type composeCLIExit struct {
	err error
	at  time.Time
}

type composeCLIFront struct {
	cmd             *exec.Cmd
	stdout, stderr  bytes.Buffer
	started         time.Time
	done            chan composeCLIExit
	joined          bool
	hostFD, hostPID int
	hostAttempt     string
	roleFDs         []int
	mustOwnHost     bool
	captureName     string
	captured        bool
}

func composeCLIStart(t *testing.T, f *bootstrapDockerFixture, s HostPolicySelection, r hostPolicyRecord, operation string) *composeCLIFront {
	x := composeCLIPrepare(t, f, s, r, operation)
	if x.launch() != nil {
		t.Fatal("actual installed frontend start failed")
	}
	return x
}

func (x *composeCLIFront) launch() error {
	x.started = time.Now()
	if err := x.cmd.Start(); err != nil {
		return err
	}
	go func() { err := x.cmd.Wait(); x.done <- composeCLIExit{err, time.Now()} }()
	return nil
}

func composeCLIPrepare(t *testing.T, f *bootstrapDockerFixture, s HostPolicySelection, r hostPolicyRecord, operation string) *composeCLIFront {
	t.Helper()
	args := []string{operation, "--host-policy", s.Path}
	for _, root := range s.WorkspaceRoots {
		args = append(args, "--workspace", root)
	}
	x := &composeCLIFront{done: make(chan composeCLIExit, 1), hostFD: -1}
	x.cmd = exec.Command(r.RuntimeExecutable.Path, args...)
	x.cmd.Stdout, x.cmd.Stderr = &x.stdout, &x.stderr
	// Install ownership cleanup before any admission, output or timing assertion.
	t.Cleanup(func() {
		if x.cmd.Process != nil && !x.joined {
			x.pinHost(s, r)
		}
		if !x.joined && x.cmd.Process != nil {
			x.cmd.Process.Signal(unix.SIGTERM)
			select {
			case result := <-x.done:
				x.joined = true
				composeCLICaptureJoined(t, f, x)
				f.WriteEvidence(t, "frontend-cleanup-"+bootstrapFixtureRandom(t, 4)+".json", composeCLIJoinedDiagnostic(x, result))
			case <-time.After(3 * time.Second):
				x.cmd.Process.Kill()
				select {
				case result := <-x.done:
					x.joined = true
					composeCLICaptureJoined(t, f, x)
					f.WriteEvidence(t, "frontend-cleanup-"+bootstrapFixtureRandom(t, 4)+".json", composeCLIJoinedDiagnostic(x, result))
				case <-time.After(2 * time.Second):
					f.RetainForRecovery(t)
					t.Error("frontend cleanup did not join")
				}
				t.Error("frontend required forced cleanup")
			}
		}
		if x.hostFD >= 0 {
			poll := []unix.PollFd{{Fd: int32(x.hostFD), Events: unix.POLLIN}}
			n, err := unix.Poll(poll, 0)
			if err != nil || n == 0 {
				if unix.PidfdSendSignal(x.hostFD, unix.SIGTERM, nil, 0) != nil {
					f.RetainForRecovery(t)
					t.Error("exact installed host stop failed")
				}
				n, err = unix.Poll(poll, int((f.Config.Deadlines.StopGrace+f.Config.Deadlines.ReapTimeout)/time.Millisecond))
				if err != nil || n != 1 {
					f.RetainForRecovery(t)
					t.Error("exact installed host was not joined within its shutdown budget")
				}
			}
			unix.Close(x.hostFD)
			for _, fd := range x.roleFDs {
				poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
				if n, e := unix.Poll(poll, 1000); e != nil || n != 1 {
					f.RetainForRecovery(t)
					t.Error("owned role was not reaped")
				}
				unix.Close(fd)
			}
		} else if x.mustOwnHost {
			f.RetainForRecovery(t)
			t.Error("newly spawned host ownership was not established; fixture retained")
		}
	})
	return x
}

func (x *composeCLIFront) pinHost(s HostPolicySelection, r hostPolicyRecord) {
	if x.hostFD >= 0 {
		return
	}
	for _, pid := range installedCLIChildren(x.cmd.Process.Pid) {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		parts := strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00")
		if err != nil || len(parts) < 6 || parts[1] != "host" || parts[2] != "--host-policy" || parts[3] != s.Path || parts[4] != "--invocation-id" || !ownerBridgeInvocation.MatchString(parts[5]) {
			continue
		}
		args := []string{"host", "--host-policy", s.Path, "--invocation-id", parts[5]}
		for _, root := range s.WorkspaceRoots {
			args = append(args, "--workspace", root)
		}
		fd, child := installedCLIPinChild(x.cmd.Process.Pid, r.RuntimeExecutable.Digest, args)
		if fd >= 0 {
			x.hostFD, x.hostPID, x.hostAttempt = fd, child, parts[5]
			return
		}
	}
}

func composeCLIWait(t *testing.T, f *bootstrapDockerFixture, x *composeCLIFront, s HostPolicySelection, r hostPolicyRecord, name string) []byte {
	t.Helper()
	x.captureName = name
	deadline := x.started.Add(10 * time.Second)
	for {
		x.pinHost(s, r)
		select {
		case result := <-x.done:
			x.joined = true
			composeCLICaptureJoined(t, f, x)
			f.WriteEvidence(t, name+"-joined-diagnostic.json", composeCLIJoinedDiagnostic(x, result))
			elapsed := result.at.Sub(x.started)
			f.WriteEvidence(t, name+"-timing.json", map[string]any{"entryToExitNanoseconds": elapsed.Nanoseconds(), "boundNanoseconds": int64(10 * time.Second), "exitSuccess": result.err == nil, "stdoutBytes": x.stdout.Len(), "stderrBytes": x.stderr.Len()})
			if result.err != nil || elapsed > 10*time.Second {
				t.Fatal("actual installed frontend failed or exceeded ten seconds")
			}
			return append([]byte(nil), x.stdout.Bytes()...)
		default:
		}
		if time.Now().After(deadline) {
			f.WriteEvidence(t, name+"-deadline-failure.json", map[string]any{"observedElapsedNanoseconds": time.Since(x.started).Nanoseconds(), "boundNanoseconds": int64(10 * time.Second), "frontendWaitJoined": false, "outputCaptureAvailable": false})
			t.Fatal("actual installed frontend exceeded ten seconds")
		}
		time.Sleep(time.Millisecond)
	}
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

func (x *composeCLIFront) captureJoined(directory string) error {
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

func composeCLICaptureJoined(t *testing.T, f *bootstrapDockerFixture, x *composeCLIFront) {
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

func TestComposeCLIReceiptRefusalCodes(t *testing.T) {
	accepted := composeCLIReceiptDocument{SchemaVersion: protocol.Version, Kind: "bootstrap-progress", RequestDisposition: "accepted", InstanceState: "unknown", Receipt: protected.BootstrapControlReceipt{Outcome: "accepted"}, Message: "Current details are unavailable."}
	encode := func(v any) []byte {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for _, tc := range []struct {
		name  string
		raw   []byte
		allow bool
		code  string
	}{
		{"accepted_historical", encode(accepted), true, ""},
		{"authenticated_pending_requires_nats", encode(accepted), false, "cli_authenticated_response_required"},
		{"invalid_json", []byte("{"), true, "cli_output_json_invalid"},
		{"null", []byte("null"), true, "cli_output_json_invalid"},
		{"oversized", bytes.Repeat([]byte(" "), 64*1024+1), true, "cli_output_json_invalid"},
		{"missing_field", []byte(`{"schemaVersion":"1.0.0","kind":"bootstrap-progress"}`), true, "cli_receipt_shape_invalid"},
		{"duplicate_field", append([]byte(`{"kind":"bootstrap-progress",`), encode(accepted)[1:]...), true, "cli_receipt_shape_invalid"},
		{"unknown_field", bytes.Replace(encode(accepted), []byte(`"message":`), []byte(`"extra":false,"message":`), 1), true, "cli_receipt_shape_invalid"},
		{"case_alias", bytes.Replace(encode(accepted), []byte(`"kind"`), []byte(`"Kind"`), 1), true, "cli_receipt_shape_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, code := composeCLIReceiptCode(tc.raw, tc.allow)
			if code != tc.code {
				t.Fatalf("refusal code differs: got %s want %s", code, tc.code)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*composeCLIReceiptDocument)
		code   string
	}{
		{"wrong_version", func(d *composeCLIReceiptDocument) { d.SchemaVersion = "2.0.0" }, "cli_receipt_version_or_kind_invalid"},
		{"wrong_kind", func(d *composeCLIReceiptDocument) { d.Kind = "starting" }, "cli_receipt_version_or_kind_invalid"},
		{"unconfirmed", func(d *composeCLIReceiptDocument) { d.RequestDisposition = "unconfirmed" }, "cli_receipt_not_accepted"},
		{"receipt_unconfirmed", func(d *composeCLIReceiptDocument) { d.Receipt.Outcome = "unconfirmed" }, "cli_receipt_not_accepted"},
		{"ready_claim", func(d *composeCLIReceiptDocument) { d.InstanceState = "ready" }, "cli_receipt_readiness_overclaimed"},
		{"details_claim", func(d *composeCLIReceiptDocument) { d.DetailsAvailable = true }, "cli_receipt_readiness_overclaimed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			document := accepted
			tc.change(&document)
			_, code := composeCLIReceiptCode(encode(document), true)
			if code != tc.code {
				t.Fatalf("refusal code differs: got %s want %s", code, tc.code)
			}
		})
	}
}

func TestComposeCLIPrivateOutputCapture(t *testing.T) {
	directory := t.TempDir()
	raw := []byte("not JSON: captured before validation\n")
	if err := composeCLICaptureOutput(directory, "pending", raw); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "pending-stdout.private")
	actual, err := os.ReadFile(path)
	info, statErr := os.Stat(path)
	if err != nil || statErr != nil || !bytes.Equal(actual, raw) || info.Mode().Perm() != 0600 {
		t.Fatal("private exact output capture differs")
	}
	if err := composeCLICaptureOutput(directory, "pending", []byte("replacement")); err == nil {
		t.Fatal("existing private capture replaced")
	}
	actual, _ = os.ReadFile(path)
	if !bytes.Equal(actual, raw) {
		t.Fatal("original capture changed")
	}
	for _, name := range []string{"", "../outside"} {
		if err := composeCLICaptureOutput(directory, name, raw); err == nil {
			t.Fatal("unsafe capture name accepted")
		}
	}
	if err := composeCLICaptureOutput(directory, "large", bytes.Repeat([]byte("x"), 64*1024+1)); err == nil {
		t.Fatal("unbounded capture accepted")
	}
	if _, err := os.Stat(filepath.Join(directory, "large-stdout.private")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unbounded capture created a file")
	}
}

func TestComposeCLIOutputCaptureRequiresJoinedWait(t *testing.T) {
	directory := t.TempDir()
	x := &composeCLIFront{captureName: "nonzero-exit"}
	x.stdout.WriteString("unvalidated failed output")
	if err := x.captureJoined(directory); err == nil || x.captured {
		t.Fatal("unjoined output captured")
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Fatal("unjoined capture touched directory")
	}
	// This disposable process qualifies buffer completion for a nonzero exit;
	// it supplies no host, broker or instance authority.
	x.stdout.Reset()
	x.cmd = exec.Command("/bin/sh", "-c", "printf 'unvalidated failed output'; printf 'private diagnostic' >&2; exit 7")
	x.cmd.Stdout, x.cmd.Stderr = &x.stdout, &x.stderr
	x.done = make(chan composeCLIExit, 1)
	t.Cleanup(func() {
		if x.cmd.Process != nil && !x.joined {
			_ = x.cmd.Process.Kill()
			select {
			case <-x.done:
				x.joined = true
			case <-time.After(3 * time.Second):
				t.Error("owned capture process cleanup did not join")
			}
		}
	})
	if err := x.launch(); err != nil {
		t.Fatal("owned capture process start failed")
	}
	var result composeCLIExit
	select {
	case result = <-x.done:
	case <-time.After(3 * time.Second):
		t.Fatal("owned capture process did not join")
	}
	x.joined = true
	var exit *exec.ExitError
	if !errors.As(result.err, &exit) || exit.ExitCode() != 7 {
		t.Fatal("owned nonzero exit differs")
	}
	if err := x.captureJoined(directory); err != nil {
		t.Fatal(err)
	}
	if err := x.captureJoined(directory); err != nil {
		t.Fatal("joined capture repeated instead of reused")
	}
	actual, err := os.ReadFile(filepath.Join(directory, "nonzero-exit-stdout.private"))
	if err != nil || string(actual) != "unvalidated failed output" {
		t.Fatal("failed output capture differs")
	}
	actual, err = os.ReadFile(filepath.Join(directory, "nonzero-exit-stderr.private"))
	if err != nil || string(actual) != "private diagnostic" {
		t.Fatal("failed stderr capture differs")
	}
	row := composeCLIJoinedDiagnostic(x, result)
	if row["exitStatus"] != 7 || row["exitOutcome"] != "failed" || row["stderrBytes"] != len("private diagnostic") {
		t.Fatal("normal joined failure diagnostic differs")
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 2 {
		t.Fatal("capture created public or duplicate output")
	}
}

func TestComposeCLIReceiptBindingRefusalCodes(t *testing.T) {
	attempt := "attempt_" + strings.Repeat("a", 32)
	good := protected.BootstrapReceiptBinding{ColdInvocationID: attempt, EnrollmentDigest: "enrolled", RuntimeDigest: "image"}
	for _, tc := range []struct {
		name   string
		change func(*protected.BootstrapReceiptBinding)
		owned  bool
		code   string
	}{
		{"matching_actual_expected", func(*protected.BootstrapReceiptBinding) {}, true, ""},
		{"scope", func(b *protected.BootstrapReceiptBinding) { b.Scope.InstanceID = "other" }, true, "cli_receipt_enrollment_binding_invalid"},
		{"enrollment", func(b *protected.BootstrapReceiptBinding) { b.EnrollmentDigest = "other" }, true, "cli_receipt_enrollment_binding_invalid"},
		{"attempt_grammar", func(b *protected.BootstrapReceiptBinding) { b.ColdInvocationID = "reported-pid" }, true, "cli_receipt_enrollment_binding_invalid"},
		{"different_creator", func(b *protected.BootstrapReceiptBinding) { b.ColdInvocationID = "attempt_" + strings.Repeat("b", 32) }, true, "cli_receipt_creator_or_image_binding_invalid"},
		{"different_image", func(b *protected.BootstrapReceiptBinding) { b.RuntimeDigest = "other" }, true, "cli_receipt_creator_or_image_binding_invalid"},
		{"creator_not_owned", func(*protected.BootstrapReceiptBinding) {}, false, "cli_receipt_creator_or_image_binding_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binding := good
			tc.change(&binding)
			code := composeCLIReceiptBindingCode(binding, good.Scope, good.EnrollmentDigest, attempt, good.RuntimeDigest, tc.owned)
			if code != tc.code {
				t.Fatalf("binding refusal code differs: got %s want %s", code, tc.code)
			}
		})
	}
}

func composeCLIObservation(t *testing.T, f *bootstrapDockerFixture, x *composeCLIFront, r hostPolicyRecord, raw []byte, name string, allowReceipt bool) *StartupStatusObservation {
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
		attempt := ""
		owned := x != nil && x.hostFD >= 0
		if x != nil {
			attempt = x.hostAttempt
		}
		if code := composeCLIReceiptBindingCode(out.Receipt.Binding, f.Config.Kernel.Scope, releaseDigest(mustStatusJSON(f.BridgeEnrollment.Owner)), attempt, r.RuntimeExecutable.Digest, owned); code != "" {
			t.Fatal(code)
		}
		f.WriteEvidence(t, name+"-receipt-expected.json", map[string]any{"source": "Actual creating frontend child arguments and held image admission", "coldInvocationId": x.hostAttempt, "runtimeDigest": r.RuntimeExecutable.Digest, "scope": f.Config.Kernel.Scope, "enrollmentDigest": releaseDigest(mustStatusJSON(f.BridgeEnrollment.Owner))})
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

// composeCLICreatorObservation borrows only the creator handle already retained by
// the fixture. Exit or an unknown observation is a failure hint, never readiness.
func composeCLICreatorObservation(x *composeCLIFront) string {
	return composeCLICreatorPollObservation(x).Result
}

type composeCLICreatorPollFacts struct {
	Result        string  `json:"result"`
	Performed     bool    `json:"pollPerformed"`
	Count         *int    `json:"pollCount,omitempty"`
	Revents       *uint16 `json:"pollRevents,omitempty"`
	ErrnoCategory string  `json:"pollErrnoCategory"`
}

// These facts come from the same single nonblocking call that supplies the
// existing result. They retain no descriptor, process ID, attempt or raw error.
func composeCLICreatorPollObservation(x *composeCLIFront) composeCLICreatorPollFacts {
	facts := composeCLICreatorPollFacts{Result: "creator_host_observation_unknown", ErrnoCategory: "not_observed"}
	if x == nil {
		facts.Result = "not_provided"
		return facts
	}
	if x.hostFD < 0 || int64(x.hostFD) > 2147483647 || !ownerBridgeInvocation.MatchString(x.hostAttempt) {
		return facts
	}
	poll := []unix.PollFd{{Fd: int32(x.hostFD), Events: unix.POLLIN}}
	n, err := unix.Poll(poll, 0)
	bits := uint16(poll[0].Revents)
	facts.Performed = true
	facts.Count = &n
	facts.Revents = &bits
	facts.ErrnoCategory = "none"
	if err != nil {
		facts.ErrnoCategory = "unclassified"
		if errno, ok := err.(syscall.Errno); ok {
			switch errno {
			case unix.EINTR:
				facts.ErrnoCategory = "interrupted"
			case unix.EBADF:
				facts.ErrnoCategory = "invalid_descriptor"
			case unix.EINVAL:
				facts.ErrnoCategory = "invalid_argument"
			default:
				facts.ErrnoCategory = "other_errno"
			}
		}
		return facts
	}
	if n == 0 && poll[0].Revents == 0 {
		facts.Result = "live"
		return facts
	}
	if n == 1 && poll[0].Revents == unix.POLLIN {
		facts.Result = "creator_host_exited"
		return facts
	}
	return facts
}

func composeCLIRefresh(t *testing.T, f *bootstrapDockerFixture, startupDeadline time.Time) StartupStatusObservation {
	t.Helper()
	return composeCLIRefreshForCreator(t, f, startupDeadline, nil)
}

func composeCLIRefreshForCreator(t *testing.T, f *bootstrapDockerFixture, startupDeadline time.Time, x *composeCLIFront) StartupStatusObservation {
	t.Helper()
	client, err := LoadOwnerBridgeClient(f.Config, *f.BridgeEnrollment)
	if err != nil {
		t.Fatal("actual authenticated refresh client refused")
	}
	ctx, cancel := context.WithDeadline(context.Background(), startupDeadline)
	defer cancel()
	lastCode := "none"
	checkCreator := func() {
		observed := composeCLICreatorPollObservation(x)
		fact := observed.Result
		if fact == "not_provided" || fact == "live" {
			return
		}
		attempt := ""
		if observed.Performed && ownerBridgeInvocation.MatchString(x.hostAttempt) {
			attempt = x.hostAttempt
		}
		f.WriteEvidence(t, "creator-refresh-failure.json", map[string]any{"errorCode": fact, "coldInvocationId": attempt, "deadlineExpired": ctx.Err() != nil, "lastRequestErrorCode": lastCode, "creatorPoll": observed})
		t.Fatal("actual creator host exited or its retained handle could not be observed")
	}
	for ctx.Err() == nil {
		checkCreator()
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
		lastCode = code
		checkCreator()
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

func composeCLIPinRoles(t *testing.T, f *bootstrapDockerFixture, x *composeCLIFront) {
	t.Helper()
	if x.hostFD < 0 {
		f.RetainForRecovery(t)
		t.Fatal("actual creator-owned host handle missing")
	}
	seen := map[string]bool{}
	for _, pid := range installedCLIChildren(x.hostPID) {
		fd, e := unix.PidfdOpen(pid, 0)
		if e != nil {
			continue
		}
		x.roleFDs = append(x.roleFDs, fd)
		image, ie := os.ReadFile(fmt.Sprintf("/proc/%d/exe", pid))
		status, se := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		env, ee := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
		args, ae := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		role := ""
		for _, candidate := range protocol.Roles() {
			for _, item := range strings.Split(string(env), "\x00") {
				if item == "AGENTMUX_NATS_CREDS_FILE="+filepath.Join(f.Profile.ProfileDirectory, candidate+".json") {
					role = candidate
				}
			}
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, pe := unix.Poll(poll, 0)
		if ie != nil || se != nil || ee != nil || ae != nil || pe != nil || n != 0 || role == "" || seen[role] || !strings.Contains(string(status), fmt.Sprintf("PPid:\t%d\n", x.hostPID)) || len(strings.Split(strings.TrimSuffix(string(args), "\x00"), "\x00")) != 1 {
			t.Fatal("actual owned role identity rejected")
		}
		member, err := os.ReadFile(filepath.Join(f.HostPolicy.ExternalRelease.PackageDirectory, "bin", role))
		if err != nil || releaseDigest(member) != releaseDigest(image) {
			t.Fatal("actual owned role image differs")
		}
		seen[role] = true
	}
	if len(seen) != 4 {
		t.Fatal("actual installed host lacks four distinct protected roles")
	}
}

func TestInstalledCLIRealComposeColdWarmAndRefresh(t *testing.T) {
	f := newBootstrapDockerFixtureWithHost(t, true)
	s, r := composeCLIPolicy(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	before, e := f.ObserveBroker(ctx)
	cancel()
	if e != nil || before.State != "absent" {
		t.Fatal("cold real broker is not absent")
	}
	x := composeCLIStart(t, f, s, r, "ensure")
	x.mustOwnHost = true
	raw := composeCLIWait(t, f, x, s, r, "cold")
	composeCLIObservation(t, f, x, r, raw, "cold", true)
	fresh := composeCLIRefreshForCreator(t, f, x.started.Add(f.Config.StartupTimeout), x)
	composeCLIPinRoles(t, f, x)
	bootstrapFixtureRoleLeases(t, f, true)
	poll := []unix.PollFd{{Fd: int32(x.hostFD), Events: unix.POLLIN}}
	if n, e := unix.Poll(poll, 0); e != nil || n != 0 {
		t.Fatal("host did not survive frontend exit")
	}
	f.WriteEvidence(t, "refresh.json", fresh)
	broker := bootstrapFixtureBroker(t, f)
	ctx, cancel = context.WithTimeout(context.Background(), 60*time.Second)
	volume, e := f.volume(ctx)
	cancel()
	if e != nil {
		t.Fatal("actual volume identity unavailable")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	record, e := deployment.Observe(ctx, deployment.ObserveOptions{ProbeOptions: f.Config.Health, ReadExistingRecord: true})
	cancel()
	if e != nil || record.RecordSequence == 0 {
		t.Fatal("actual persistence record unavailable")
	}
	original := bootstrapFixtureRecord(t, f.Config, record.RecordSequence)
	f.AssertBaselineUnchanged(t)
	for _, operation := range []string{"ensure", "status"} {
		warm := composeCLIStart(t, f, s, r, operation)
		out := composeCLIObservation(t, f, warm, r, composeCLIWait(t, f, warm, s, r, "warm-"+operation), "warm-"+operation, false)
		if out == nil || out.Disposition != "reused" || warm.hostFD >= 0 {
			t.Fatal("warm CLI spawned a host or failed reuse")
		}
		for _, fd := range append(append([]int(nil), x.roleFDs...), x.hostFD) {
			poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			if n, e := unix.Poll(poll, 0); e != nil || n != 0 {
				t.Fatal("warm CLI replaced an exact owned host or role")
			}
		}
		if len(installedCLIChildren(x.hostPID)) != 4 {
			t.Fatal("warm CLI added or removed an actual protected child")
		}
	}
	if bootstrapFixtureBroker(t, f).ContainerID != broker.ContainerID {
		t.Fatal("warm CLI replaced real broker")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 60*time.Second)
	afterVolume, e := f.volume(ctx)
	cancel()
	if e != nil || !reflect.DeepEqual(volume, afterVolume) || bootstrapFixtureRecord(t, f.Config, record.RecordSequence) != original {
		t.Fatal("warm CLI changed volume or original record")
	}
	f.AssertBaselineUnchanged(t)
}

func TestInstalledCLIRealComposeConcurrentCold(t *testing.T) {
	f := newBootstrapDockerFixtureWithHost(t, true)
	s, r := composeCLIPolicy(t, f)
	a := composeCLIPrepare(t, f, s, r, "ensure")
	b := composeCLIPrepare(t, f, s, r, "ensure")
	barrier := make(chan struct{})
	launched := make(chan error, 2)
	for _, x := range []*composeCLIFront{a, b} {
		go func(x *composeCLIFront) { <-barrier; launched <- x.launch() }(x)
	}
	close(barrier)
	first, second := <-launched, <-launched
	if first != nil || second != nil {
		t.Fatal("concurrent actual frontend start failed")
	}
	// Pin both creating frontends while both are alive, before joining either.
	for time.Since(a.started) < 10*time.Second && (a.hostFD < 0 || b.hostFD < 0) {
		a.pinHost(s, r)
		b.pinHost(s, r)
		if a.hostFD >= 0 && b.hostFD >= 0 {
			break
		}
		if len(a.done) != 0 && len(b.done) != 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	composeCLIObservation(t, f, a, r, composeCLIWait(t, f, a, s, r, "concurrent-a"), "concurrent-a", true)
	composeCLIObservation(t, f, b, r, composeCLIWait(t, f, b, s, r, "concurrent-b"), "concurrent-b", true)
	fresh := composeCLIRefresh(t, f, a.started.Add(f.Config.StartupTimeout))
	f.WriteEvidence(t, "concurrent-refresh.json", fresh)
	var retained []*composeCLIFront
	for _, x := range []*composeCLIFront{a, b} {
		if x.hostFD >= 0 {
			poll := []unix.PollFd{{Fd: int32(x.hostFD), Events: unix.POLLIN}}
			if n, e := unix.Poll(poll, 0); e == nil && n == 0 {
				retained = append(retained, x)
			}
		}
	}
	if len(retained) != 1 {
		f.RetainForRecovery(t)
		t.Fatal("concurrent installed frontends did not converge on one retained host")
	}
	composeCLIPinRoles(t, f, retained[0])
	bootstrapFixtureRoleLeases(t, f, true)
	f.AssertBaselineUnchanged(t)
}

func TestInstalledCLIRealComposeAuthenticatedPending(t *testing.T) {
	f := newBootstrapDockerFixtureWithHost(t, true)
	s, r := composeCLIPolicy(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	lease, e := AcquireBootstrapLock(ctx, f.Profile.ProfileDirectory, f.Profile.InstanceID, f.Profile.Docker.EngineID)
	cancel()
	if e != nil {
		t.Fatal("actual pending arbitration lease unavailable")
	}
	defer lease.Close()
	// The mutating driver requires the actual arbitration lease. Keep this same
	// lease while the installed host enters genuine Bootstrap and waits its turn.
	owner := f.Owner
	owner.LockHeld = true
	ctx, cancel = context.WithTimeout(context.Background(), 60*time.Second)
	if startErr := f.Driver.StartOwned(ctx, owner, f.Config.Compose); startErr != nil {
		f.WriteEvidence(t, "pending-start-failure.json", map[string]any{"failureCode": bootstrapFixtureFailureCode(startErr), "failureStage": bootstrapFixtureFailureStage(startErr), "contextExpired": ctx.Err() != nil, "actualLeaseHeld": true})
		cancel()
		t.Fatal("actual factory broker start failed")
	}
	cancel()
	x := composeCLIStart(t, f, s, r, "ensure")
	x.mustOwnHost = true
	out := composeCLIObservation(t, f, x, r, composeCLIWait(t, f, x, s, r, "pending"), "pending", false)
	if out == nil || out.Disposition != "starting" || out.StartupAttemptID == nil || *out.StartupAttemptID != x.hostAttempt {
		t.Fatal("actual pending response lacks owning attempt")
	}
	if lease.Close() != nil {
		t.Fatal("pending arbitration release failed")
	}
	f.WriteEvidence(t, "pending-completion.json", composeCLIRefreshForCreator(t, f, x.started.Add(f.Config.StartupTimeout), x))
	composeCLIPinRoles(t, f, x)
	f.AssertBaselineUnchanged(t)
}

func TestInstalledCLIRealComposeAbruptHostRestart(t *testing.T) {
	f := newBootstrapDockerFixtureWithHost(t, true)
	s, r := composeCLIPolicy(t, f)
	original := composeCLIStart(t, f, s, r, "ensure")
	original.mustOwnHost = true
	composeCLIObservation(t, f, original, r, composeCLIWait(t, f, original, s, r, "abrupt-cold"), "abrupt-cold", true)
	f.WriteEvidence(t, "abrupt-original-status.json", composeCLIRefreshForCreator(t, f, original.started.Add(f.Config.StartupTimeout), original))
	composeCLIPinRoles(t, f, original)
	bootstrapFixtureRoleLeases(t, f, true)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	beforeKernel, err := ObserveKernel(ctx, f.Config.Kernel)
	cancel()
	if err != nil || beforeKernel.KernelReadiness != "ready" {
		t.Fatal("original genuine kernel incarnation unavailable")
	}
	broker := bootstrapFixtureBroker(t, f)
	ctx, cancel = context.WithTimeout(context.Background(), 60*time.Second)
	volume, err := f.volume(ctx)
	cancel()
	if err != nil {
		t.Fatal("original owned volume identity unavailable")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	record, err := deployment.Observe(ctx, deployment.ObserveOptions{ProbeOptions: f.Config.Health, ReadExistingRecord: true})
	cancel()
	if err != nil || record.RecordSequence == 0 {
		t.Fatal("original actual persistence record unavailable")
	}
	oldRecord := bootstrapFixtureRecord(t, f.Config, record.RecordSequence)
	f.AssertBaselineUnchanged(t)
	// This is an explicit disposable failure injection. The fd was pinned through
	// the creating frontend and its exact held executable before frontend exit.
	killedAt := time.Now()
	if unix.PidfdSendSignal(original.hostFD, unix.SIGKILL, nil, 0) != nil {
		t.Fatal("exact owned host failure injection refused")
	}
	deadline := killedAt.Add(f.Config.Deadlines.StopGrace + f.Config.Deadlines.ReapTimeout)
	for _, fd := range append([]int{original.hostFD}, original.roleFDs...) {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			f.RetainForRecovery(t)
			t.Fatal("abrupt owned lifetime exceeded shared shutdown budget")
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if n, e := unix.Poll(poll, int(remaining/time.Millisecond)); e != nil || n != 1 {
			f.RetainForRecovery(t)
			t.Fatal("abrupt host death did not reap exact protected descendants")
		}
	}
	bootstrapFixtureRoleLeases(t, f, false)
	ctx, cancel = context.WithDeadline(context.Background(), deadline)
	serviceLease, err := AcquireBootstrapLock(ctx, f.Profile.ProfileDirectory, f.Profile.InstanceID, "owner-status-service")
	cancel()
	if err != nil {
		f.RetainForRecovery(t)
		t.Fatal("abrupt host did not release its actual service lease")
	}
	if serviceLease.Close() != nil {
		f.RetainForRecovery(t)
		t.Fatal("released service lease cleanup failed")
	}
	f.WriteEvidence(t, "abrupt-exit.json", map[string]any{"injection": "SIGKILL to previously held creator-proven host pidfd only", "exactHostExited": true, "exactRoleExitCount": len(original.roleFDs), "sharedShutdownBudgetNanoseconds": int64(f.Config.Deadlines.StopGrace + f.Config.Deadlines.ReapTimeout), "elapsedNanoseconds": time.Since(killedAt).Nanoseconds(), "roleLeasesReleased": 4, "serviceLeaseReleased": true})
	recovered := composeCLIStart(t, f, s, r, "ensure")
	recovered.mustOwnHost = true
	composeCLIObservation(t, f, recovered, r, composeCLIWait(t, f, recovered, s, r, "abrupt-recovery"), "abrupt-recovery", true)
	f.WriteEvidence(t, "abrupt-recovery-status.json", composeCLIRefreshForCreator(t, f, recovered.started.Add(f.Config.StartupTimeout), recovered))
	composeCLIPinRoles(t, f, recovered)
	if recovered.hostPID == original.hostPID || recovered.hostAttempt == original.hostAttempt {
		t.Fatal("actual restart reused the dead creating host")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 60*time.Second)
	afterKernel, err := ObserveKernel(ctx, f.Config.Kernel)
	cancel()
	if err != nil || afterKernel.KernelReadiness != "ready" || afterKernel.Incarnation == beforeKernel.Incarnation {
		t.Fatal("actual restart did not establish a new genuine kernel incarnation")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 60*time.Second)
	afterVolume, err := f.volume(ctx)
	cancel()
	if err != nil || !reflect.DeepEqual(volume, afterVolume) || bootstrapFixtureBroker(t, f).ContainerID != broker.ContainerID || bootstrapFixtureRecord(t, f.Config, record.RecordSequence) != oldRecord {
		t.Fatal("actual restart changed broker, volume or original persistence record")
	}
	bootstrapFixtureRoleLeases(t, f, true)
	f.AssertBaselineUnchanged(t)
	f.WriteEvidence(t, "abrupt-recovery-preservation.json", map[string]any{"newCreatorProvenHost": true, "newKernelIncarnation": true, "sameBroker": true, "sameVolume": true, "originalRecordRetained": true, "newExactRoleCount": len(recovered.roleFDs)})
}

// Read output sizes only after the sole Wait has joined its copy goroutines.
func composeCLIJoinedDiagnostic(x *composeCLIFront, result composeCLIExit) map[string]any {
	code := "failed"
	if result.err == nil {
		code = "success"
	}
	var exitStatus any = nil
	var processExit *exec.ExitError
	if result.err == nil {
		exitStatus = 0
	} else if errors.As(result.err, &processExit) {
		exitStatus = processExit.ExitCode()
	}
	return map[string]any{"frontendWaitJoined": true, "entryToExitNanoseconds": result.at.Sub(x.started).Nanoseconds(), "exitOutcome": code, "exitStatus": exitStatus, "stdoutBytes": x.stdout.Len(), "stderrBytes": x.stderr.Len(), "exactHostPinned": x.hostFD >= 0}
}
func TestComposeCLIJoinedDiagnosticIsClosed(t *testing.T) {
	x := &composeCLIFront{started: time.Now(), hostFD: -1}
	x.stdout.WriteString("private-output")
	x.stderr.WriteString("private-error")
	row := composeCLIJoinedDiagnostic(x, composeCLIExit{errors.New("secret-password"), x.started.Add(time.Second)})
	raw, err := json.Marshal(row)
	if err != nil || bytes.Contains(raw, []byte("secret")) || bytes.Contains(raw, []byte("private")) || row["exitOutcome"] != "failed" || row["stdoutBytes"] != len("private-output") || row["exactHostPinned"] != false {
		t.Fatal("joined diagnostic leaked or fabricated host authority")
	}
	if composeCLIJoinedDiagnostic(x, composeCLIExit{nil, x.started.Add(time.Second)})["exitOutcome"] != "success" {
		t.Fatal("successful joined outcome lost")
	}
}
