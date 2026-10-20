package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// CapabilityMutation is one explicit intended effect, retained by the caller
// through uncertain outcomes. Reuse this same value for reconciliation/retry;
// creating another value means requesting another business operation. It grants
// no authority. Generic formatting never exposes its recovery contents.
type CapabilityMutation struct {
	mu       sync.Mutex
	state    capabilityMutationState
	inFlight bool
}
type capabilityMutationState struct {
	SourceOperationID string           `json:"sourceOperationId"`
	RequestID         string           `json:"requestId"`
	Contract          string           `json:"contractId"`
	Resource          ContextReference `json:"resourceRef"`
	Owner             OwnerReference   `json:"owner"`
	SourceDigest      string           `json:"sourceDigest"`
	Payload           []byte           `json:"payload"`
	OperationID       string           `json:"operationId"`
	PayloadDigest     string           `json:"payloadDigest"`
}

// NewMutation allocates identity explicitly, bound to this exact operation and
// instance before any effect can be sent. Retain it; a new value is a new intent.
func (h *CapabilityHandles) NewMutation() (*CapabilityMutation, error) {
	if h == nil || h.session == nil || !h.session.active() {
		return nil, pluginError("capability_handle_stale")
	}
	var source struct {
		OperationID string `json:"operationId"`
	}
	if json.Unmarshal(h.session.operation.Operation, &source) != nil || !registryIdentifier.MatchString(source.OperationID) {
		return nil, pluginError("capability_mutation_invalid")
	}
	nonce, err := randomControlID()
	if err != nil {
		return nil, pluginError("capability_service_unavailable")
	}
	return &CapabilityMutation{state: capabilityMutationState{RequestID: "request_" + nonce, Owner: h.session.owner, SourceOperationID: source.OperationID, SourceDigest: checksum(h.session.operation.Operation)}}, nil
}

func (*CapabilityMutation) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private capability mutation]")
}
func (*CapabilityMutation) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-capability-mutation"}`), nil
}

// RecoveryBytes explicitly discloses private recovery data for protected caller
// storage. Persist the complete snapshot returned after Prepare before dispatch.
// This package creates no second ledger.
func (m *CapabilityMutation) RecoveryBytes() ([]byte, error) {
	if m == nil {
		return nil, pluginError("capability_mutation_invalid")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return json.Marshal(m.state)
}
func RestoreCapabilityMutation(raw []byte) (*CapabilityMutation, error) {
	if len(raw) > 2*contextWireLimit || strictDocument(raw) != nil {
		return nil, pluginError("capability_mutation_invalid")
	}
	var state capabilityMutationState
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || !contextRequestID.MatchString(state.RequestID) || !contextOwnerValid(state.Owner) || !registryIdentifier.MatchString(state.SourceOperationID) || !capabilityDigestValid(state.SourceDigest) {
		return nil, pluginError("capability_mutation_invalid")
	}
	if state.Contract != "" {
		if !capabilityMutationOperation(state.Contract) || !contextOwnerValid(state.Owner) || !contextReferenceValid(state.Resource) || !registryIdentifier.MatchString(state.SourceOperationID) || !capabilityDigestValid(state.SourceDigest) || len(state.Payload) > contextWireLimit || strictDocument(state.Payload) != nil {
			return nil, pluginError("capability_mutation_invalid")
		}
	} else if state.Resource != (ContextReference{}) || len(state.Payload) != 0 || state.OperationID != "" || state.PayloadDigest != "" {
		return nil, pluginError("capability_mutation_invalid")
	}
	if (state.OperationID == "") != (state.PayloadDigest == "") || (state.OperationID != "" && (state.OperationID != capabilityMutationOperationID(state.SourceOperationID, state.RequestID) || !capabilityDigestValid(state.PayloadDigest))) {
		return nil, pluginError("capability_mutation_invalid")
	}
	state.Payload = bytes.Clone(state.Payload)
	return &CapabilityMutation{state: state}, nil
}
func capabilityMutationOperation(contract string) bool {
	switch contract {
	case "capability-storage-write", "capability-secret-use", "capability-process-start", "capability-process-cancel", "capability-decision-request":
		return true
	}
	return false
}
func capabilityDigestValid(value string) bool {
	if len(value) != 71 || value[:7] != "sha256:" {
		return false
	}
	for _, c := range value[7:] {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (m *CapabilityMutation) begin(owner OwnerReference, source []byte, contract string, resource ContextReference, payload []byte) (string, error) {
	if m == nil {
		return "", pluginError("capability_mutation_required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !contextRequestID.MatchString(m.state.RequestID) {
		return "", pluginError("capability_mutation_invalid")
	}
	if m.inFlight {
		return "", pluginError("capability_mutation_in_flight")
	}
	if m.state.Owner != owner || m.state.SourceDigest != checksum(source) {
		return "", pluginError("capability_mutation_changed")
	}
	if m.state.Contract != "" {
		if m.state.Contract != contract || m.state.Resource != resource || !bytes.Equal(m.state.Payload, payload) {
			return "", pluginError("capability_mutation_changed")
		}
	} else {
		m.state.Contract = contract
		m.state.Resource = resource
		m.state.Payload = bytes.Clone(payload)
	}
	m.inFlight = true
	return m.state.RequestID, nil
}
func (m *CapabilityMutation) finish() { m.mu.Lock(); m.inFlight = false; m.mu.Unlock() }
func (m *CapabilityMutation) approved(raw []byte) error {
	var envelope struct {
		Operation struct {
			ID     string `json:"operationId"`
			Digest string `json:"payloadDigest"`
		} `json:"operation"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return pluginError("capability_mutation_invalid")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// The enrolled authority must preserve this explicit business ID in every
	// freshly signed attempt. Its payloadDigest uses the shared canonical codec;
	// the local byte comparison in begin is not a replacement for that digest.
	if envelope.Operation.ID != capabilityMutationOperationID(m.state.SourceOperationID, m.state.RequestID) || !capabilityDigestValid(envelope.Operation.Digest) || (m.state.PayloadDigest != "" && m.state.PayloadDigest != envelope.Operation.Digest) {
		return pluginError("capability_mutation_changed")
	}
	m.state.OperationID = envelope.Operation.ID
	m.state.PayloadDigest = envelope.Operation.Digest
	return nil
}

type CapabilityReconciliation struct {
	operationID, payloadDigest string
	resource                   ContextReference
	contract                   string
}

func (r CapabilityReconciliation) OperationID() string        { return r.operationID }
func (r CapabilityReconciliation) PayloadDigest() string      { return r.payloadDigest }
func (r CapabilityReconciliation) Resource() ContextReference { return r.resource }
func (CapabilityReconciliation) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private capability reconciliation]")
}
func (CapabilityReconciliation) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-capability-reconciliation"}`), nil
}
func (m *CapabilityMutation) Reconciliation() (CapabilityReconciliation, error) {
	if m == nil {
		return CapabilityReconciliation{}, pluginError("capability_mutation_invalid")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.OperationID == "" {
		return CapabilityReconciliation{}, pluginError("capability_mutation_not_prepared")
	}
	return CapabilityReconciliation{m.state.OperationID, m.state.PayloadDigest, m.state.Resource, m.state.Contract}, nil
}

type CapabilityOutcome struct {
	record   *ContextReference
	outcome  string
	resource *ContextReference
}

func (o CapabilityOutcome) Record() (ContextReference, bool) {
	if o.record == nil {
		return ContextReference{}, false
	}
	return *o.record, true
}
func (o CapabilityOutcome) Outcome() string { return o.outcome }

// ResourceReference returns the original storage result under current recovery
// authority, even when the original write request can no longer be replayed.
func (o CapabilityOutcome) ResourceReference() (ContextReference, bool) {
	if o.resource == nil {
		return ContextReference{}, false
	}
	return *o.resource, true
}
func (CapabilityOutcome) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private capability outcome]")
}
func (CapabilityOutcome) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-capability-outcome"}`), nil
}

// Reconcile queries the same owner aggregate using the exact operation ID and
// canonical payload digest retained before dispatch. The remote owner delegates
// to state_owner.OwnerLedger.outcome(operation_id, payload_digest). An absent
// record is not proof an earlier effect stopped. This method never retries it.
func (h *CapabilityHandles) Reconcile(ctx context.Context, m *CapabilityMutation) (CapabilityOutcome, error) {
	if h == nil || h.session == nil {
		return CapabilityOutcome{}, pluginError("capability_handles_invalid")
	}
	token, err := m.Reconciliation()
	if err != nil {
		return CapabilityOutcome{}, err
	}
	h.session.mu.Lock()
	_, originalRoute := h.session.routes[token.contract]
	h.session.mu.Unlock()
	if !originalRoute {
		return CapabilityOutcome{}, pluginError("capability_access_refused")
	}
	var reply struct {
		OperationID   string          `json:"operationId"`
		PayloadDigest string          `json:"payloadDigest"`
		Record        json.RawMessage `json:"recordRef"`
		Outcome       string          `json:"outcome"`
		Contract      json.RawMessage `json:"contractId,omitempty"`
		Resource      json.RawMessage `json:"resourceRef,omitempty"`
	}
	input := struct {
		Contract      string `json:"contractId"`
		OperationID   string `json:"operationId"`
		PayloadDigest string `json:"payloadDigest"`
	}{token.contract, token.operationID, token.payloadDigest}
	if err := h.session.call(ctx, "capability-outcome-query", token.resource, input, &reply, nil, false); err != nil {
		return CapabilityOutcome{}, err
	}
	if reply.OperationID != token.operationID || reply.PayloadDigest != token.payloadDigest {
		return CapabilityOutcome{}, pluginError("capability_reply_invalid")
	}
	encoded, err := json.Marshal(reply)
	if err != nil || len(reply.Record) == 0 || nativeCapabilitySchema("capability-outcome-query-reply", encoded) != nil {
		return CapabilityOutcome{}, pluginError("capability_reply_invalid")
	}
	var resultResource *ContextReference
	if token.contract == "capability-storage-write" {
		var originalContract string
		if json.Unmarshal(reply.Contract, &originalContract) != nil || originalContract != token.contract || len(reply.Resource) == 0 {
			return CapabilityOutcome{}, pluginError("capability_reply_invalid")
		}
		if reply.Outcome != "absent" {
			var observed ContextReference
			if json.Unmarshal(reply.Resource, &observed) != nil || !contextReferenceValid(observed) || observed.ID != token.resource.ID || observed.OwnerHubID != token.resource.OwnerHubID {
				return CapabilityOutcome{}, pluginError("capability_reply_invalid")
			}
			resultResource = &observed
		}
	} else if len(reply.Contract) != 0 || len(reply.Resource) != 0 {
		return CapabilityOutcome{}, pluginError("capability_reply_invalid")
	}
	if reply.Outcome == "absent" && bytes.Equal(reply.Record, []byte("null")) {
		return CapabilityOutcome{outcome: "absent"}, nil
	}
	var record ContextReference
	decoder := json.NewDecoder(bytes.NewReader(reply.Record))
	decoder.DisallowUnknownFields()
	if (reply.Outcome != "committed" && reply.Outcome != "rejected") || decoder.Decode(&record) != nil || !contextReferenceValid(record) || (token.contract == "capability-storage-write" && record.OwnerHubID != token.resource.OwnerHubID) {
		return CapabilityOutcome{}, pluginError("capability_reply_invalid")
	}
	return CapabilityOutcome{record: &record, outcome: reply.Outcome, resource: resultResource}, nil
}

func capabilityMutationOperationID(sourceID, requestID string) string {
	id, _ := ContextDownstreamOperationID(sourceID, requestID)
	return id
}

// prepareMutation obtains current authority and freezes exact intent without
// calling the remote effect owner. The caller can persist RecoveryBytes before
// invoking the mutating method. Authority is checked again during dispatch.
func (s *capabilityHandleSession) prepareMutation(ctx context.Context, contract string, resource ContextReference, input any) (*CapabilityMutation, error) {
	handles := CapabilityHandles{session: s}
	mutation, err := handles.NewMutation()
	if err != nil {
		return nil, err
	}
	if !capabilityMutationOperation(contract) {
		return nil, pluginError("capability_mutation_invalid")
	}
	if err := s.call(ctx, contract, resource, input, nil, mutation, true); err != nil {
		return nil, err
	}
	return mutation, nil
}
