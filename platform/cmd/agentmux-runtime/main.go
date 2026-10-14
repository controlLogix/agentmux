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
	operation, policy, invocation string
	roots                         workspaces
}

const (
	frontendEnsureLimit         = 10 * time.Second
	frontendStatusLimit         = 5 * time.Second
	frontendReceiptCleanupLimit = time.Second
	frontendResponseAllowance   = 500 * time.Millisecond
)

func frontendTotalContext(parent context.Context, operation string, entered time.Time) (context.Context, context.CancelFunc) {
	limit := frontendEnsureLimit
	if operation == "status" {
		limit = frontendStatusLimit
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
	if operation == "ensure" && observation.Disposition != "started" && observation.Disposition != "reused" && observation.Disposition != "starting" {
		return errors.New("startup_failed")
	}
	return nil
}

func parse(args []string) (options, error) {
	var o options
	if len(args) == 0 || (args[0] != "ensure" && args[0] != "status" && args[0] != "host") {
		return o, errors.New("command_invalid")
	}
	o.operation = args[0]
	f := flag.NewFlagSet("agentmux-runtime", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&o.policy, "host-policy", "", "Private installed host policy")
	f.StringVar(&o.invocation, "invocation-id", "", "Actual launch invocation")
	f.Var(&o.roots, "workspace", "Explicit workspace root")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 || o.policy == "" || len(o.roots) == 0 || len(o.roots) > 16 || (o.operation != "host" && o.invocation != "") || (o.operation == "host" && !regexp.MustCompile(`^attempt_[0-9a-f]{32}$`).MatchString(o.invocation)) {
		return options{}, errors.New("arguments_invalid")
	}
	return o, nil
}

func run(ctx context.Context, args []string, output io.Writer) (failure error) {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("request_context_invalid")
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
	if o.operation == "status" {
		cancelFrontend()
		frontend, cancelFrontend = frontendTotalContext(ctx, "status", entered)
		defer cancelFrontend()
	}
	h, err := launcher.LoadEnrolledHostPolicy(launcher.HostPolicySelection{Path: o.policy, OwnerUID: uint32(os.Geteuid()), WorkspaceRoots: append([]string(nil), o.roots...)})
	if err != nil {
		return err
	}
	if o.operation == "host" {
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
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		// This fixed diagnostic is separate from authenticated L04 output. Its
		// static fields never include underlying error text or private objects.
		_ = emitRequestDiagnostic(os.Stderr, err)
		os.Exit(1)
	}
}

func emitRequestDiagnostic(output io.Writer, failure error) error {
	return json.NewEncoder(output).Encode(launcher.ProjectRequestDiagnostic(failure))
}
