//go:build linux || darwin

// agentmux-runtime starts or queries the explicitly enrolled local host.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"github.com/controlLogix/agentmux/platform/launcher"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

type workspaces []string

func (w *workspaces) String() string     { return "explicit workspace roots" }
func (w *workspaces) Set(s string) error { *w = append(*w, s); return nil }

type options struct {
	operation, policy, invocation, client   string
	applicationSelection, applicationDigest string
	services                                applicationServicesOptions
	roots                                   workspaces
}

const (
	frontendEnsureLimit         = 10 * time.Second
	frontendStatusLimit         = 5 * time.Second
	frontendReceiptCleanupLimit = time.Second
	frontendResponseAllowance   = 500 * time.Millisecond
)

func frontendTotalContext(parent context.Context, operation string, entered time.Time) (context.Context, context.CancelFunc) {
	limit := frontendEnsureLimit
	if operation == "status" || operation == "doctor" {
		limit = frontendStatusLimit
	} else if operation == "prepare" {
		limit = launcher.BrokerImagePreparationLimit
	}
	return context.WithDeadline(parent, entered.Add(limit))
}

func frontendWorkContext(total context.Context) (context.Context, context.CancelFunc) {
	deadline, ok := total.Deadline()
	if !ok {
		work, cancel := context.WithCancel(total)
		cancel()
		return work, cancel
	}
	// Receipt cleanup keeps its existing one-second bound. Response and normal
	// process exit get an allowance within the original total, not extra time.
	return context.WithDeadline(total, deadline.Add(-frontendReceiptCleanupLimit-frontendResponseAllowance))
}

func frontendCleanupContext(total context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(total, frontendReceiptCleanupLimit)
}

func emitObservation(output io.Writer, observation launcher.StartupStatusObservation, operation string) error {
	if err := json.NewEncoder(output).Encode(observation); err != nil {
		return errors.New("output_failed")
	}
	if observation.Disposition == "failed" || observation.Disposition == "unconfigured" ||
		(operation == "ensure" && observation.Disposition != "started" && observation.Disposition != "reused" && observation.Disposition != "starting") {
		return errors.New("startup_failed")
	}
	return nil
}

func parse(args []string) (options, error) {
	var o options
	if len(args) == 0 || (args[0] != "ensure" && args[0] != "status" && args[0] != "host" && args[0] != "doctor" && args[0] != "prepare") {
		return o, errors.New("command_invalid")
	}
	o.operation = args[0]
	f := flag.NewFlagSet("agentmux-runtime", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&o.client, "client", "", "Selected client diagnostics; doctor only")
	f.StringVar(&o.policy, "host-policy", "", "Private installed host policy")
	f.StringVar(&o.invocation, "invocation-id", "", "Actual launch invocation")
	applicationPath := singleApplicationFlag{value: &o.applicationSelection}
	applicationDigest := singleApplicationFlag{value: &o.applicationDigest}
	f.Var(&applicationPath, "application-attestor-selection", "Explicit private application attestor selection; ensure or host only")
	f.Var(&applicationDigest, "application-attestor-selection-sha256", "Independent application attestor selection digest")
	serviceInstallation := singleApplicationFlag{value: &o.services.installationID}
	servicePath := singleApplicationFlag{value: &o.services.path}
	serviceDigest := singleApplicationFlag{value: &o.services.digest}
	f.Var(&serviceInstallation, "application-services-installation", "Explicit protected application service package; ensure or host only")
	f.Var(&servicePath, "application-services-selection", "Explicit private application service selection")
	f.Var(&serviceDigest, "application-services-selection-sha256", "Independent application service selection digest")
	f.Var(&o.roots, "workspace", "Explicit workspace root")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 || o.policy == "" || len(o.roots) == 0 || len(o.roots) > 16 || (o.operation != "host" && o.invocation != "") || (o.operation == "host" && !regexp.MustCompile(`^attempt_[0-9a-f]{32}$`).MatchString(o.invocation)) {
		return options{}, errors.New("arguments_invalid")
	}
	clientSelected := false
	f.Visit(func(selected *flag.Flag) {
		if selected.Name == "client" {
			clientSelected = true
		}
	})
	if clientSelected && (o.operation != "doctor" || !launcher.ValidClientDoctorID(o.client)) {
		return options{}, errors.New("arguments_invalid")
	}
	if err := validateApplicationFlags(o, applicationPath.present, applicationDigest.present); err != nil {
		return options{}, err
	}
	if err := validateApplicationServiceFlags(o, serviceInstallation.present, servicePath.present, serviceDigest.present); err != nil {
		return options{}, err
	}
	return o, nil
}

func run(ctx context.Context, args []string, output io.Writer) (failure error) {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("request_context_invalid")
	}
	if len(args) > 0 && (args[0] == "prepare-owner-profile" || args[0] == "recover-owner-profile") {
		return runOwnerProfilePreparation(ctx, args, output)
	}
	if len(args) > 0 && args[0] == "provision-integration-effect" {
		return runIntegrationOperator(ctx, args, os.Stdin, output)
	}
	if len(args) > 0 && args[0] == "register-central-profile" {
		return runCentralProfileRegistration(ctx, args, output)
	}
	if len(args) > 0 && args[0] == "application-runtime" {
		return runApplicationRuntime(ctx, args, output)
	}
	if len(args) > 0 && args[0] == "profile-core" {
		return runProfileCore(ctx, args)
	}
	if len(args) > 0 && args[0] == "profile-client" {
		return runProfileClient(ctx, args)
	}
	if len(args) > 0 && (args[0] == "mcp" || args[0] == "startup" || args[0] == "dashboard" || args[0] == "client-setup" || args[0] == "claude-hook-setup" || args[0] == "launch-claude-desktop" || args[0] == "claude-code-hook" || args[0] == "application-enroll" || args[0] == "retire-definitions-owner") {
		// Client admission has a bounded check. A long-lived MCP session uses
		// the existing Python lifetime after direct process replacement.
		return runInstalledClient(ctx, args)
	}
	// The frontend budget includes argument and policy admission. The owning
	// host has its separately enrolled startup and signal lifetime.
	entered := time.Now()
	frontend, cancelFrontend := frontendTotalContext(ctx, "ensure", entered)
	defer cancelFrontend()
	o, err := parse(args)
	if err != nil {
		return err
	}
	if o.operation == "status" || o.operation == "doctor" || o.operation == "prepare" {
		cancelFrontend()
		frontend, cancelFrontend = frontendTotalContext(ctx, o.operation, entered)
		defer cancelFrontend()
	}
	h, err := launcher.LoadEnrolledHostPolicy(launcher.HostPolicySelection{Path: o.policy, OwnerUID: uint32(os.Geteuid()), WorkspaceRoots: append([]string(nil), o.roots...)})
	if err != nil {
		return err
	}
	if o.operation == "doctor" {
		return runDoctorWithClient(frontend, h, o.client, output)
	}
	if o.operation == "prepare" {
		return prepareBrokerImage(frontend, h, output)
	}
	if o.operation == "host" {
		if o.applicationSelection != "" {
			selection, err := h.ReadApplicationAttestorHostSelection(ctx, o.applicationSelection, o.applicationDigest)
			if err != nil {
				return err
			}
			return runApplicationHost(ctx, h, o, selection)
		}
		server, budget, err := h.BridgeServerForInvocation(o.invocation)
		if err != nil {
			return err
		}
		startup, cancel := context.WithTimeout(ctx, budget)
		defer cancel()
		return server.Run(startup, ctx, o.invocation)
	}
	invocation, err := h.BeginEnsure()
	if err != nil {
		return err
	}
	requestCtx, cancelWork := frontendWorkContext(frontend)
	defer cancelWork()
	var observation launcher.StartupStatusObservation
	if o.operation == "ensure" {
		// Probe only the initial lookup. A broker with no owner subscriber can
		// return its native hint without consuming the normal reply wait.
		observation, err = invocation.Probe(requestCtx)
	} else {
		observation, err = invocation.Request(requestCtx, o.operation)
	}
	if err == nil {
		return emitObservation(output, observation, o.operation)
	}
	if !initialLookupAllowsStart(o.operation, err) {
		if o.operation == "status" {
			if emitted, historyErr := statusHistoryFallback(frontend, output, h, err); emitted {
				return historyErr
			}
		}
		return err
	}
	image, err := h.PrepareHost(requestCtx)
	if err != nil {
		return err
	}
	defer func() { failure = errors.Join(failure, image.Close()) }()
	selection := h.Invocation()
	selection.InvocationID = invocation.ID()
	selection.ApplicationAttestorSelectionPath = o.applicationSelection
	selection.ApplicationAttestorSelectionSHA256 = o.applicationDigest
	selection.ApplicationServicesInstallationID = o.services.installationID
	selection.ApplicationServicesSelectionPath = o.services.path
	selection.ApplicationServicesSelectionSHA256 = o.services.digest
	binding, err := h.BootstrapReceiptBinding(invocation.ID())
	if err != nil {
		return err
	}
	child, err := image.StartHostWithBootstrapReceipt(requestCtx, selection, binding)
	if child != nil {
		defer func() {
			cleanup, cancel := frontendCleanupContext(frontend)
			defer cancel()
			failure = errors.Join(failure, child.CloseBootstrapReceipt(cleanup))
		}()
	}
	if err != nil {
		return err
	}
	// This is lifecycle correlation with our exact admitted child. All instance
	// details, readiness and connected hubs still come from authenticated NATS.
	receipt, receiptErr := child.BootstrapReceipt(requestCtx)
	if requestCtx.Err() == nil {
		observation, err = invocation.Request(requestCtx, "ensure")
		if err == nil {
			return emitObservation(output, observation, "ensure")
		}
		if !progressObservationUnavailable(err) {
			return err
		}
	} else {
		// No final request was possible within the original work deadline.
		err = requestCtx.Err()
	}
	if receiptErr != nil {
		return receiptErr
	}
	if receipt.Outcome == "accepted" {
		requestFailure := err
		if emitted, historyErr := creatorHistoryFallback(frontend, output, invocation, child, requestFailure); emitted {
			return historyErr
		}
	}
	return emitOwnedBootstrapProgress(frontend, output, child, receipt)
}

func initialLookupAllowsStart(operation string, err error) bool {
	if operation != "ensure" || err == nil {
		return false
	}
	// A hint permits normal host admission; it provides no startup authority.
	// Joined cleanup errors and authentication failures must remain failures.
	switch err.Error() {
	case "owner_bridge_connection_unavailable", "owner_bridge_reply_unavailable", "owner_bridge_no_responders":
		return true
	}
	return false
}

func emitOwnedBootstrapProgress(ctx context.Context, output io.Writer, child *protected.ReceiptHostProcess, receipt protected.BootstrapControlReceipt) error {
	if ctx == nil || ctx.Err() != nil || child == nil || child.HostProcess == nil {
		return errors.New("startup_unconfirmed")
	}
	select {
	case <-child.Done():
		// This handle belongs to the exact spawned child. Done means its sole
		// wait has completed; an earlier receipt cannot establish current startup.
		return errors.New("host_unavailable")
	default:
	}
	return emitBootstrapProgress(output, receipt)
}

func progressObservationUnavailable(err error) bool {
	if err == nil {
		return false
	}
	// Exact safe outcomes only. Wrapped cleanup, enrollment, authentication and
	// malformed-reply failures stay failures even if the deadline also expired.
	switch err.Error() {
	case "owner_bridge_connection_unavailable", "owner_bridge_reply_unavailable", "owner_bridge_deadline":
		return true
	}
	return false
}

// A lifecycle receipt is deliberately a different document from an L04 reply.
// It cannot provide current service, persistence, work or hub observations.
func emitBootstrapProgress(output io.Writer, receipt protected.BootstrapControlReceipt) error {
	disposition := "unconfirmed"
	if receipt.Outcome == "accepted" {
		disposition = "accepted"
	}
	document := struct {
		SchemaVersion      string                            `json:"schemaVersion"`
		Kind               string                            `json:"kind"`
		RequestDisposition string                            `json:"requestDisposition"`
		InstanceState      string                            `json:"instanceState"`
		Receipt            protected.BootstrapControlReceipt `json:"receipt"`
		DetailsAvailable   bool                              `json:"detailsAvailable"`
		Message            string                            `json:"message"`
	}{"1.0.0", "bootstrap-progress", disposition, "unknown", receipt, false,
		"The receipt records this startup request. Current instance details are unavailable. Run status again when the local NATS service is available."}
	if json.NewEncoder(output).Encode(document) != nil {
		return errors.New("output_failed")
	}
	if disposition != "accepted" {
		return errors.New("startup_unconfirmed")
	}
	return nil
}
func main() {
	if len(os.Args) > 1 && os.Args[1] == "profile-core" {
		if err := runProfileClientCommandWith(context.Background(), os.Args[1:], os.Stderr, runProfileCore); err != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "profile-client" {
		if err := runProfileClientCommand(context.Background(), os.Args[1:], os.Stderr); err != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && (os.Args[1] == "mcp" || os.Args[1] == "startup" || os.Args[1] == "dashboard" || os.Args[1] == "client-setup" || os.Args[1] == "claude-hook-setup" || os.Args[1] == "launch-claude-desktop" || os.Args[1] == "claude-code-hook" || os.Args[1] == "application-enroll" || os.Args[1] == "retire-definitions-owner") {
		// Keep normal process signals through exec. Infrastructure cancellation
		// handlers must not consume a signal just before the Python replacement.
		if err := runInstalledClientCommand(context.Background(), os.Args[1:], os.Stderr); err != nil {
			os.Exit(1)
		}
		return
	}
	preparation := len(os.Args) > 1 && os.Args[1] == "prepare"
	registration := len(os.Args) > 1 && os.Args[1] == "register-central-profile"
	ownerPreparation := len(os.Args) > 1 && (os.Args[1] == "prepare-owner-profile" || os.Args[1] == "recover-owner-profile")
	applicationRuntime := len(os.Args) > 1 && os.Args[1] == "application-runtime"
	signals := []os.Signal{syscall.SIGINT, syscall.SIGTERM}
	if preparation || registration || ownerPreparation || applicationRuntime {
		// These explicit foreground owners must finish owned work when their terminal closes.
		// The shared host and ordinary frontend keep their existing lifetime.
		signals = append(signals, syscall.SIGHUP)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), signals...)
	defer cancel()
	if preparation {
		var stop context.CancelFunc
		ctx, stop = context.WithTimeout(ctx, launcher.BrokerImagePreparationLimit)
		defer stop()
	}
	if registration {
		var stop context.CancelFunc
		ctx, stop = context.WithTimeout(ctx, centralProfileRegistrationLimit)
		defer stop()
	}
	if ownerPreparation {
		var stop context.CancelFunc
		ctx, stop = context.WithTimeout(ctx, ownerPreparationCommandLimit)
		defer stop()
	}
	if applicationRuntime {
		var stop context.CancelFunc
		ctx, stop = context.WithTimeout(ctx, applicationRuntimeCommandLimit)
		defer stop()
	}
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		// This fixed diagnostic is separate from authenticated L04 output. Its
		// static fields never include underlying error text or private objects.
		if preparation {
			_ = writePreparationJSON(ctx, os.Stderr, launcher.ProjectRequestDiagnostic(err))
		} else if ownerPreparation {
			_ = writeOwnerProfilePreparationDiagnostic(ctx, os.Stderr, err)
		} else if registration {
			_ = writeCentralProfileRegistrationDiagnostic(ctx, os.Stderr, err)
		} else if applicationRuntime {
			_ = writeApplicationRuntimeDiagnostic(os.Stderr, err)
		} else {
			_ = emitRequestDiagnostic(os.Stderr, err)
		}
		os.Exit(1)
	}
}

func emitRequestDiagnostic(output io.Writer, failure error) error {
	if diagnostic, ok := centralProfileRegistrationDiagnostic(failure); ok {
		return json.NewEncoder(output).Encode(diagnostic)
	}
	if diagnostic, ok := profileClientDiagnostic(failure); ok {
		return json.NewEncoder(output).Encode(diagnostic)
	}
	if failure == errDoctorChecksIncomplete {
		return json.NewEncoder(output).Encode(launcher.RequestDiagnostic{
			SchemaVersion: "1.0.0", Kind: "launcher-diagnostic", Code: "doctor_checks_incomplete", Action: "read_doctor_checks",
			Message: "Some diagnostic checks failed or remain unknown. Read the individual checks; this report does not establish application readiness.",
		})
	}
	return json.NewEncoder(output).Encode(launcher.ProjectRequestDiagnostic(failure))
}
