package plugins

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func nativeProcessBinding(t *testing.T, admission ContextInstanceAdmission, contract string) string {
	t.Helper()
	selected := ""
	for _, route := range admission.DomainBindings {
		if route.ContractID == contract {
			if selected != "" {
				t.Fatal("duplicate admitted Process route")
			}
			selected = route.ID
		}
	}
	if selected == "" {
		t.Fatal("required admitted Process route missing")
	}
	return selected
}

func nativeProcessWaitReady(t *testing.T, ctx context.Context, directory, name string) {
	t.Helper()
	nativeLiveWait(t, ctx, directory, name, func(raw []byte) bool {
		var signal struct {
			Ready bool `json:"ready"`
		}
		if nativeLiveDecode(raw, &signal) != nil {
			t.Fatal("Process fixture handoff invalid")
		}
		return signal.Ready
	})
}

// The Python owner controls enrollment, the actual task, owner restart and
// cleanup. Go uses the public typed handles and retains each original intent.
func nativeProcessCapabilityFlow(t *testing.T, ctx context.Context, directory string, ready nativeCapabilityLiveReady,
	binding ContextBinding, admission ContextInstanceAdmission, operation ContextOperationAdmission,
	authority *NativeContextAuthority, gateway *NativeCapabilityGateway, retained **CapabilityHandles) {
	t.Helper()
	var input struct {
		Plan ContextReference `json:"planRef"`
	}
	if nativeLiveDecode(ready.RequestInput, &input) != nil || !contextReferenceValid(input.Plan) {
		t.Fatal("Process plan reference invalid")
	}
	handles, err := OpenCapabilityHandles(ctx, binding, admission, operation,
		CapabilityHandlePorts{Authority: authority, Domain: gateway.Domain, Now: time.Now})
	if err != nil {
		t.Fatal("typed Process handle construction refused", err)
	}
	*retained = handles
	mutation, err := handles.Process.PrepareStart(ctx, ready.ResourceRef, input.Plan)
	if err != nil {
		t.Fatal("typed Process preparation refused", err)
	}
	recovery, err := mutation.RecoveryBytes()
	if err != nil {
		t.Fatal("original Process recovery unavailable")
	}
	token, err := mutation.Reconciliation()
	if err != nil {
		t.Fatal("prepared Process identity unavailable")
	}
	nativeLiveWrite(t, directory, "process-mutation.json", json.RawMessage(recovery))
	nativeProcessWaitReady(t, ctx, directory, "process-dispatch-ready.json")
	first, firstErr := handles.Process.Start(ctx, mutation, ready.ResourceRef, input.Plan)
	var run ContextReference
	if firstErr != nil {
		// This is an observation of the same original, never a replacement Start.
		observed, observeErr := handles.Reconcile(ctx, mutation)
		var present bool
		run, present = observed.Record()
		if observeErr != nil || observed.Outcome() != "committed" || !present || !contextReferenceValid(run) {
			t.Fatal("uncertain Process admission did not recover its original", firstErr, observeErr)
		}
	} else {
		run = first.Reference()
		if first.Outcome() != "accepted" || !contextReferenceValid(run) {
			t.Fatal("typed Process admission was not accepted")
		}
	}
	nativeLiveWrite(t, directory, "process-accepted.json", map[string]any{"receiptRef": run, "operationId": token.OperationID(), "payloadDigest": token.PayloadDigest()})
	nativeProcessWaitReady(t, ctx, directory, "process-enrolled.json")
	restored, err := RestoreCapabilityMutation(recovery)
	if err != nil {
		t.Fatal("original Process mutation restore refused")
	}
	before, err := restored.Reconciliation()
	if err != nil || before.OperationID() != token.OperationID() || before.PayloadDigest() != token.PayloadDigest() {
		t.Fatal("restored Process mutation changed identity")
	}
	// Dispatch this same accepted original once. Its five-second observer can
	// expire while the service finishes owned work; Python checks physical truth.
	dispatched, dispatchErr := handles.Process.Start(ctx, restored, ready.ResourceRef, input.Plan)
	if dispatchErr == nil && (dispatched.Outcome() != "accepted" || dispatched.Reference() != run) {
		t.Fatal("Process dispatch replaced its accepted original")
	}
	nativeLiveWrite(t, directory, "process-dispatched.json", map[string]any{"phase": "dispatched"})
	nativeProcessWaitReady(t, ctx, directory, "process-observe-ready.json")
	observed, err := handles.Reconcile(ctx, restored)
	record, present := observed.Record()
	if err != nil || observed.Outcome() != "committed" || !present || record != run {
		t.Fatal("restarted Process host lost original recovery", err)
	}
	cancelMutation, err := handles.Process.PrepareCancel(ctx, ready.ResourceRef, run)
	if err != nil {
		t.Fatal("typed Process cancellation preparation refused", err)
	}
	cancelRecovery, err := cancelMutation.RecoveryBytes()
	if err != nil {
		t.Fatal("original Process cancellation recovery unavailable")
	}
	nativeLiveWrite(t, directory, "process-cancel-mutation.json", json.RawMessage(cancelRecovery))
	cancelled, cancelErr := handles.Process.Cancel(ctx, cancelMutation, ready.ResourceRef, run)
	if cancelErr == nil && cancelled.Outcome() != "pending" && cancelled.Outcome() != "stopped" && cancelled.Outcome() != "uncertain" {
		t.Fatal("typed Process cancellation refused")
	}
	nativeLiveWrite(t, directory, "process-cancel-dispatched.json", map[string]any{"phase": "dispatched"})
	nativeLiveWait(t, ctx, directory, "fixture-ready.json", func(raw []byte) bool {
		var next nativeCapabilityLiveReady
		if nativeLiveDecode(raw, &next) != nil {
			t.Fatal("Process revocation handoff invalid")
		}
		return next.Revoked
	})
	// Establish that this refusal occurs before the original business lifetime,
	// rather than accepting an expired original as evidence of parent revocation.
	var original struct {
		Deadline string `json:"deadline"`
	}
	if json.Unmarshal(operation.Operation, &original) != nil {
		t.Fatal("Process original deadline missing")
	}
	deadline, err := time.Parse(time.RFC3339Nano, original.Deadline)
	if err != nil || !time.Now().Before(deadline) {
		t.Fatal("Process parent revocation exceeded the original business deadline")
	}
	if _, err := handles.Reconcile(ctx, restored); err == nil {
		t.Fatal("revoked Process parent retained recovery access")
	}
	if authority.Recheck(ctx, binding.Owner, admission, &operation) == nil {
		t.Fatal("actual Process parent revocation retained source authority")
	}
}
