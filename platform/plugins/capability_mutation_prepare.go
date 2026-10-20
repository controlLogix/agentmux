package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
)

// PrepareCompareAndSwap freezes a write without dispatching it. Persist the
// returned mutation's RecoveryBytes before calling CompareAndSwap with it.
func (h *StorageHandle) PrepareCompareAndSwap(ctx context.Context, resource ContextReference, value []byte) (*CapabilityMutation, error) {
	if h == nil {
		return nil, pluginError("capability_access_refused")
	}
	if len(value) > contextWireLimit/2 || strictDocument(value) != nil {
		return nil, pluginError("capability_request_invalid")
	}
	return h.session.prepareMutation(ctx, "capability-storage-write", resource, struct {
		Value json.RawMessage `json:"value"`
	}{bytes.Clone(value)})
}
func (h *SecretHandle) PrepareUse(ctx context.Context, secret, consumer, purpose ContextReference) (*CapabilityMutation, error) {
	if h == nil || h.session == nil {
		return nil, pluginError("capability_access_refused")
	}
	if !contextReferenceValid(consumer) || !contextReferenceValid(purpose) {
		return nil, pluginError("capability_request_invalid")
	}
	if !slices.Contains(h.session.instance.SecretReferences, secret) {
		return nil, pluginError("capability_access_refused")
	}
	return h.session.prepareMutation(ctx, "capability-secret-use", secret, struct {
		Consumer ContextReference `json:"consumerRef"`
		Purpose  ContextReference `json:"purposeRef"`
	}{consumer, purpose})
}
func (h *ProcessHandle) PrepareStart(ctx context.Context, executor, plan ContextReference) (*CapabilityMutation, error) {
	if h == nil {
		return nil, pluginError("capability_access_refused")
	}
	if !contextReferenceValid(plan) {
		return nil, pluginError("capability_request_invalid")
	}
	return h.session.prepareMutation(ctx, "capability-process-start", executor, struct {
		Plan ContextReference `json:"planRef"`
	}{plan})
}
func (h *ProcessHandle) PrepareCancel(ctx context.Context, executor, run ContextReference) (*CapabilityMutation, error) {
	if h == nil {
		return nil, pluginError("capability_access_refused")
	}
	if !contextReferenceValid(run) {
		return nil, pluginError("capability_request_invalid")
	}
	return h.session.prepareMutation(ctx, "capability-process-cancel", executor, struct {
		Run ContextReference `json:"runRef"`
	}{run})
}
func (h *DecisionHandle) PrepareRequest(ctx context.Context, decision, proposal ContextReference) (*CapabilityMutation, error) {
	if h == nil {
		return nil, pluginError("capability_access_refused")
	}
	if !contextReferenceValid(proposal) {
		return nil, pluginError("capability_request_invalid")
	}
	return h.session.prepareMutation(ctx, "capability-decision-request", decision, struct {
		Proposal ContextReference `json:"proposalRef"`
	}{proposal})
}
