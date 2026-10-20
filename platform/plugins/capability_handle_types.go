package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"
)

type StorageHandle struct{ session *capabilityHandleSession }
type ArtifactHandle struct{ session *capabilityHandleSession }
type SecretHandle struct{ session *capabilityHandleSession }
type WorkspaceHandle struct{ session *capabilityHandleSession }
type ProcessHandle struct{ session *capabilityHandleSession }
type PolicyHandle struct{ session *capabilityHandleSession }
type DecisionHandle struct{ session *capabilityHandleSession }

// CapabilityContent reveals bytes only through an explicit copy. Ordinary
// formatting cannot turn a private record, artifact or workspace file into logs.
type CapabilityContent struct{ data []byte }

func (c CapabilityContent) Bytes() []byte { return bytes.Clone(c.data) }
func (CapabilityContent) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private capability content]")
}
func (CapabilityContent) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-capability-content"}`), nil
}

type CapabilityReceipt struct {
	reference   ContextReference
	outcome     string
	resource    ContextReference
	hasResource bool
}

func (r CapabilityReceipt) Reference() ContextReference { return r.reference }
func (r CapabilityReceipt) Outcome() string             { return r.outcome }

// ResourceReference returns the original storage result's resource revision.
// It is absent for an uncertain storage result and for non-storage receipts.
func (r CapabilityReceipt) ResourceReference() (ContextReference, bool) {
	return r.resource, r.hasResource
}
func (CapabilityReceipt) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[capability receipt]")
}
func (CapabilityReceipt) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"capability-receipt"}`), nil
}

type capabilityContentReply struct {
	Resource ContextReference `json:"resourceRef"`
	Data     *[]byte          `json:"data"`
}
type capabilityReceiptReply struct {
	Receipt ContextReference `json:"receiptRef"`
	Outcome string           `json:"outcome"`
}

func (s *capabilityHandleSession) content(ctx context.Context, contract string, resource ContextReference, input any) (CapabilityContent, error) {
	var reply capabilityContentReply
	if err := s.call(ctx, contract, resource, input, &reply, nil, false); err != nil {
		return CapabilityContent{}, err
	}
	if reply.Resource != resource || reply.Data == nil {
		return CapabilityContent{}, pluginError("capability_reply_invalid")
	}
	return CapabilityContent{data: bytes.Clone(*reply.Data)}, nil
}
func (s *capabilityHandleSession) receipt(ctx context.Context, contract string, resource ContextReference, input any, mutation *CapabilityMutation, allowed ...string) (CapabilityReceipt, error) {
	var reply capabilityReceiptReply
	if err := s.call(ctx, contract, resource, input, &reply, mutation, false); err != nil {
		return CapabilityReceipt{}, err
	}
	if !contextReferenceValid(reply.Receipt) {
		return CapabilityReceipt{}, pluginError("capability_reply_invalid")
	}
	for _, outcome := range allowed {
		if outcome == reply.Outcome {
			return CapabilityReceipt{reference: reply.Receipt, outcome: reply.Outcome}, nil
		}
	}
	return CapabilityReceipt{}, pluginError("capability_reply_invalid")
}

type storageReceiptReply struct {
	Receipt  json.RawMessage `json:"receiptRef"`
	Outcome  string          `json:"outcome"`
	Resource json.RawMessage `json:"resourceRef"`
}

func (s *capabilityHandleSession) storageReceipt(ctx context.Context, resource ContextReference, input any, mutation *CapabilityMutation) (CapabilityReceipt, error) {
	var reply storageReceiptReply
	if err := s.call(ctx, "capability-storage-write", resource, input, &reply, mutation, false); err != nil {
		return CapabilityReceipt{}, err
	}
	encoded, err := json.Marshal(reply)
	if err != nil || len(reply.Resource) == 0 || nativeCapabilitySchema("capability-storage-write-reply", encoded) != nil {
		return CapabilityReceipt{}, pluginError("capability_reply_invalid")
	}
	var receipt ContextReference
	if json.Unmarshal(reply.Receipt, &receipt) != nil || !contextReferenceValid(receipt) || receipt.OwnerHubID != resource.OwnerHubID {
		return CapabilityReceipt{}, pluginError("capability_reply_invalid")
	}
	result := CapabilityReceipt{reference: receipt, outcome: reply.Outcome}
	if reply.Outcome == "uncertain" {
		return result, nil
	}
	var observed ContextReference
	if json.Unmarshal(reply.Resource, &observed) != nil || !contextReferenceValid(observed) || observed.ID != resource.ID || observed.OwnerHubID != resource.OwnerHubID {
		return CapabilityReceipt{}, pluginError("capability_reply_invalid")
	}
	result.resource, result.hasResource = observed, true
	return result, nil
}

// Read returns one owner-defined record, without exposing SQL or a database.
func (h *StorageHandle) Read(ctx context.Context, resource ContextReference) (CapabilityContent, error) {
	if h == nil {
		return CapabilityContent{}, pluginError("capability_access_refused")
	}
	return h.session.content(ctx, "capability-storage-read", resource, struct{}{})
}

// CompareAndSwap preserves the expected owner revision and exact JSON value.
// The remote owner owns durability and rejects conflicts; this client never
// silently overwrites, retries, migrates or deletes stored records.
func (h *StorageHandle) CompareAndSwap(ctx context.Context, mutation *CapabilityMutation, resource ContextReference, value []byte) (CapabilityReceipt, error) {
	if h == nil {
		return CapabilityReceipt{}, pluginError("capability_access_refused")
	}
	if len(value) > contextWireLimit/2 || strictDocument(value) != nil {
		return CapabilityReceipt{}, pluginError("capability_request_invalid")
	}
	return h.session.storageReceipt(ctx, resource, struct {
		Value json.RawMessage `json:"value"`
	}{bytes.Clone(value)}, mutation)
}
func (h *ArtifactHandle) Read(ctx context.Context, resource ContextReference, digest string) (CapabilityContent, error) {
	if h == nil {
		return CapabilityContent{}, pluginError("capability_access_refused")
	}
	if len(digest) != 71 || !strings.HasPrefix(digest, "sha256:") {
		return CapabilityContent{}, pluginError("capability_request_invalid")
	}
	for _, c := range digest[7:] {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return CapabilityContent{}, pluginError("capability_request_invalid")
		}
	}
	result, err := h.session.content(ctx, "capability-artifact-read", resource, struct {
		Digest string `json:"digest"`
	}{digest})
	if err != nil {
		return CapabilityContent{}, err
	}
	if checksum(result.data) != digest {
		return CapabilityContent{}, pluginError("capability_artifact_mismatch")
	}
	return result, nil
}

// Use asks the secret owner to disclose to an explicitly authorized consumer
// for the intended operation. This handle never returns secret values.
func (h *SecretHandle) Use(ctx context.Context, mutation *CapabilityMutation, secret, consumer, purpose ContextReference) (CapabilityReceipt, error) {
	if h == nil {
		return CapabilityReceipt{}, pluginError("capability_access_refused")
	}
	if !contextReferenceValid(consumer) || !contextReferenceValid(purpose) {
		return CapabilityReceipt{}, pluginError("capability_request_invalid")
	}
	if h.session == nil || !slices.Contains(h.session.instance.SecretReferences, secret) {
		return CapabilityReceipt{}, pluginError("capability_access_refused")
	}
	return h.session.receipt(ctx, "capability-secret-use", secret, struct {
		Consumer ContextReference `json:"consumerRef"`
		Purpose  ContextReference `json:"purposeRef"`
	}{consumer, purpose}, mutation, "accepted", "rejected", "uncertain")
}

// ReadFile accepts a relative path inside an owner-resolved workspace. The
// remote owner must also enforce real filesystem/symlink containment.
func (h *WorkspaceHandle) ReadFile(ctx context.Context, workspace ContextReference, relative string) (CapabilityContent, error) {
	if h == nil {
		return CapabilityContent{}, pluginError("capability_access_refused")
	}
	if relative == "" || len(relative) > 1024 || path.IsAbs(relative) || path.Clean(relative) != relative || relative == "." || relative == ".." || strings.HasPrefix(relative, "../") || strings.ContainsAny(relative, "\\\x00\r\n") {
		return CapabilityContent{}, pluginError("capability_request_invalid")
	}
	return h.session.content(ctx, "capability-workspace-read", workspace, struct {
		Path string `json:"relativePath"`
	}{relative})
}

// Start references an owner-approved execution plan. There is no shell command,
// environment, credential or arbitrary working-directory argument.
func (h *ProcessHandle) Start(ctx context.Context, mutation *CapabilityMutation, executor, plan ContextReference) (CapabilityReceipt, error) {
	if h == nil {
		return CapabilityReceipt{}, pluginError("capability_access_refused")
	}
	if !contextReferenceValid(plan) {
		return CapabilityReceipt{}, pluginError("capability_request_invalid")
	}
	return h.session.receipt(ctx, "capability-process-start", executor, struct {
		Plan ContextReference `json:"planRef"`
	}{plan}, mutation, "accepted", "rejected", "uncertain")
}

// Cancel requests cancellation; acceptance does not prove the process stopped.
func (h *ProcessHandle) Cancel(ctx context.Context, mutation *CapabilityMutation, executor, run ContextReference) (CapabilityReceipt, error) {
	if h == nil {
		return CapabilityReceipt{}, pluginError("capability_access_refused")
	}
	if !contextReferenceValid(run) {
		return CapabilityReceipt{}, pluginError("capability_request_invalid")
	}
	return h.session.receipt(ctx, "capability-process-cancel", executor, struct {
		Run ContextReference `json:"runRef"`
	}{run}, mutation, "pending", "stopped", "rejected", "uncertain")
}

// Evaluate queries the current policy owner. An allow receipt is not a grant;
// effect owners must still revalidate authority at their own mutation boundary.
func (h *PolicyHandle) Evaluate(ctx context.Context, policy ContextReference, access CapabilityAccess) (CapabilityReceipt, error) {
	if h == nil {
		return CapabilityReceipt{}, pluginError("capability_access_refused")
	}
	if !capabilityAccessValid(access) {
		return CapabilityReceipt{}, pluginError("capability_request_invalid")
	}
	return h.session.receipt(ctx, "capability-policy-evaluate", policy, struct {
		Action        string `json:"action"`
		ResourceClass string `json:"resourceClass"`
		ResourceID    string `json:"resourceId"`
	}{access.Action, access.ResourceClass, access.ResourceID}, nil, "allow", "deny", "approval_required")
}

// Request references an owned decision request. It does not accept a task or
// approve an action locally, and cannot substitute a model result for authority.
func (h *DecisionHandle) Request(ctx context.Context, mutation *CapabilityMutation, decision, proposal ContextReference) (CapabilityReceipt, error) {
	if h == nil {
		return CapabilityReceipt{}, pluginError("capability_access_refused")
	}
	if !contextReferenceValid(proposal) {
		return CapabilityReceipt{}, pluginError("capability_request_invalid")
	}
	return h.session.receipt(ctx, "capability-decision-request", decision, struct {
		Proposal ContextReference `json:"proposalRef"`
	}{proposal}, mutation, "pending", "approved", "rejected", "uncertain")
}
