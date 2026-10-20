package plugins

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"time"
)

var contextRequestID = regexp.MustCompile(`^request_[a-f0-9]{64}$`)

func (l *contextLease) serviceLoop() {
	defer close(l.serviceRun)
	for {
		raw, err := l.transport.Receive(l.ctx, false)
		if err != nil {
			l.Invalidate()
			return
		}
		var request contextServiceRequest
		if decodeContextJSON("plugin-context-request", raw, &request) != nil {
			// A malformed body cannot select an arbitrary reply subject or carry
			// diagnostic text. A valid correlation ID permits a fixed refusal.
			var header struct {
				RequestID string `json:"requestId"`
			}
			if strictDocument(raw) == nil && json.Unmarshal(raw, &header) == nil && contextRequestID.MatchString(header.RequestID) {
				l.reply(header.RequestID, nil, "context_request_invalid")
			}
			continue
		}
		l.mu.Lock()
		if l.closing {
			l.mu.Unlock()
			return
		}
		if l.requests[request.RequestID] {
			l.mu.Unlock()
			l.reply(request.RequestID, nil, "context_request_repeated")
			continue
		}
		select {
		case l.permits <- struct{}{}:
		default:
			l.mu.Unlock()
			l.reply(request.RequestID, nil, "context_capacity_exceeded")
			continue
		}
		l.requests[request.RequestID] = true
		l.workers.Add(1)
		l.mu.Unlock()
		go func() {
			defer l.workers.Done()
			defer func() {
				<-l.permits
				l.mu.Lock()
				delete(l.requests, request.RequestID)
				l.mu.Unlock()
			}()
			value, code := l.serve(request)
			l.reply(request.RequestID, value, code)
		}()
	}
}

func (l *contextLease) reply(request string, value []byte, code string) {
	outcome := "completed"
	if code != "ok" {
		outcome, value = "rejected", []byte("null")
	}
	if len(value) == 0 {
		value = []byte("null")
	}
	reply := contextServiceReply{SchemaVersion: "1.0.0", Kind: "plugin-context-reply", RequestID: request,
		Owner: l.binding.Owner, Outcome: outcome, Code: code, Value: value}
	raw := contextJSON(reply)
	if len(raw) > contextWireLimit || validateContextJSON("plugin-context-reply", raw) != nil {
		reply.Outcome, reply.Code, reply.Value = "rejected", "context_service_unavailable", []byte("null")
		raw = contextJSON(reply)
	}
	// WaitStopping may finish after invalidation. The original connection remains
	// owned until these workers join, allowing one bounded final reply.
	parent, budget := l.ctx, contextCallBudget
	if completed(l.done) {
		parent, budget = context.Background(), 100*time.Millisecond
	}
	ctx, cancel := context.WithTimeout(parent, budget)
	err := l.transport.Publish(ctx, l.bootstrap.transport.ReplySubject, raw)
	cancel()
	if err != nil {
		l.Invalidate()
	}
}

func (l *contextLease) serve(request contextServiceRequest) ([]byte, string) {
	if request.Owner != l.binding.Owner || l.handles[request.Service] != request.HandleID || completed(l.done) || !l.ports.Now().Before(l.grantUntil) {
		return nil, "context_owner_stale"
	}
	var op *contextOperation
	var admitted *ContextOperationAdmission
	parent := l.ctx
	if request.OperationHandle != nil {
		l.mu.Lock()
		op = l.operations[*request.OperationHandle]
		if op == nil || l.closing || op.ctx.Err() != nil {
			l.mu.Unlock()
			return nil, "context_operation_stale"
		}
		op.users.Add(1)
		l.mu.Unlock()
		defer op.users.Done()
		admitted, parent = operationAdmissionPointer(op.admission), op.ctx
	}
	var parameters struct {
		EventCode          string          `json:"eventCode"`
		DurationMS         int64           `json:"durationMs"`
		SpanCode           string          `json:"spanCode"`
		SpanHandle         string          `json:"spanHandle"`
		OutcomeCode        string          `json:"outcomeCode"`
		MetricCode         string          `json:"metricCode"`
		Value              float64         `json:"value"`
		BindingID          string          `json:"bindingId"`
		ContractID         string          `json:"contractId"`
		Payload            json.RawMessage `json:"payload"`
		AfterRevision      uint64          `json:"afterRevision"`
		Health             string          `json:"health"`
		SubscriptionHandle string          `json:"subscriptionHandle"`
	}
	_ = json.Unmarshal(request.Parameters, &parameters)
	if request.Service == "domainGateway" && (request.Method == "request" || request.Method == "subscribe") {
		bound := false
		for _, domain := range l.admission.DomainBindings {
			if domain.ID == parameters.BindingID && domain.ContractID == parameters.ContractID {
				bound = true
				break
			}
		}
		if !bound {
			return nil, "context_domain_unavailable"
		}
		if request.Method == "subscribe" && !l.subscriptionBinding(ContextDomainCall{BindingID: parameters.BindingID, ContractID: parameters.ContractID}) {
			return nil, "context_domain_unavailable"
		}
	}
	ctx, cancel := context.WithTimeout(parent, contextCallBudget)
	defer cancel()
	if l.ports.Authority.Recheck(ctx, l.binding.Owner, cloneInstanceAdmission(l.admission), admitted) != nil {
		return nil, "context_authority_unavailable"
	}
	if ctx.Err() != nil || completed(l.done) {
		return nil, "context_operation_canceled"
	}
	switch request.Service + "." + request.Method {
	case "logger.record", "logger.record-instance":
		if !slices.Contains(l.ports.EventCodes, parameters.EventCode) {
			return nil, "context_code_undeclared"
		}
		if l.ports.Log(ctx, ContextLogRecord{Tags: l.tags(op), EventCode: parameters.EventCode}) != nil {
			return nil, "context_service_unavailable"
		}
	case "config.read", "config.wait-change":
		if l.configuration == nil {
			return nil, "context_configuration_unavailable"
		}
		var snapshot ContextConfigurationSnapshot
		var err error
		if request.Method == "read" {
			snapshot, err = l.configuration.Read(ctx)
		} else {
			snapshot, err = l.configuration.Next(ctx, parameters.AfterRevision)
		}
		if err != nil {
			return nil, "context_configuration_unavailable"
		}
		if l.ports.Authority.Recheck(ctx, l.binding.Owner, cloneInstanceAdmission(l.admission), admitted) != nil {
			return nil, "context_authority_unavailable"
		}
		if ctx.Err() != nil || completed(l.done) {
			return nil, "context_operation_canceled"
		}
		return contextJSON(map[string]any{"configurationBytes": base64.StdEncoding.EncodeToString(snapshot.Configuration.Bytes()),
			"configurationRevision": snapshot.Revision, "checksum": snapshot.Configuration.Checksum(), "secretReferences": snapshot.SecretReferences}), "ok"
	case "lifecycle.status":
		return contextJSON(l.binding.Lifecycle.Snapshot()), "ok"
	case "lifecycle.report-health":
		if l.binding.Lifecycle.ReportHealth(parameters.Health) != nil {
			return nil, "context_owner_stale"
		}
	case "lifecycle.wait-stopping":
		select {
		case <-l.binding.Lifecycle.DrainDone():
		case <-l.done:
		case <-ctx.Done():
			return nil, "context_operation_canceled"
		}
		if l.ports.Authority.Recheck(ctx, l.binding.Owner, cloneInstanceAdmission(l.admission), admitted) != nil || ctx.Err() != nil {
			return nil, "context_authority_unavailable"
		}
		return contextJSON(l.binding.Lifecycle.Snapshot()), "ok"
	case "clock.now":
		return contextJSON(map[string]any{"now": l.ports.Now().UTC().Format("2006-01-02T15:04:05.999999Z")}), "ok"
	case "clock.elapsed":
		// time.Since uses the monotonic reading captured when this lease opened.
		// UTC clock adjustments do not change the elapsed duration.
		if l.elapsedOrigin.IsZero() {
			return nil, "context_service_unavailable"
		}
		elapsed := time.Since(l.elapsedOrigin).Milliseconds()
		if elapsed < 0 || uint64(elapsed) > maxGeneration {
			return nil, "context_service_unavailable"
		}
		return contextJSON(map[string]int64{"elapsedMs": elapsed}), "ok"
	case "clock.wait":
		// This wait belongs to the operation, not the short admission call above.
		timer := time.NewTimer(time.Duration(parameters.DurationMS) * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
			if op.ctx.Err() != nil {
				return nil, "context_operation_canceled"
			}
		case <-op.ctx.Done():
			return nil, "context_operation_canceled"
		}
		check, stopCheck := context.WithTimeout(op.ctx, contextCallBudget)
		err := l.ports.Authority.Recheck(check, l.binding.Owner, cloneInstanceAdmission(l.admission), operationAdmissionPointer(op.admission))
		checkErr := check.Err()
		stopCheck()
		if err != nil || checkErr != nil {
			return nil, "context_authority_unavailable"
		}
		return []byte("null"), "ok"
	case "tracing.start":
		if !slices.Contains(l.ports.SpanCodes, parameters.SpanCode) {
			return nil, "context_code_undeclared"
		}
		op.mu.Lock()
		defer op.mu.Unlock()
		if ctx.Err() != nil || completed(l.done) {
			return nil, "context_operation_canceled"
		}
		if len(op.spans) >= contextSpanLimit {
			return nil, "context_capacity_exceeded"
		}
		nonce, err := randomControlID()
		if err != nil {
			return nil, "context_service_unavailable"
		}
		handle := "span_" + nonce
		if l.ports.Trace(ctx, ContextTraceRecord{Tags: l.tags(op), SpanHandle: handle, SpanCode: parameters.SpanCode, Action: "start"}) != nil {
			return nil, "context_service_unavailable"
		}
		op.spans[handle] = parameters.SpanCode
		if ctx.Err() != nil || completed(l.done) {
			return nil, "context_operation_canceled"
		}
		return contextJSON(map[string]string{"spanHandle": handle}), "ok"
	case "tracing.finish":
		op.mu.Lock()
		defer op.mu.Unlock()
		if ctx.Err() != nil || completed(l.done) {
			return nil, "context_operation_canceled"
		}
		code, exists := op.spans[parameters.SpanHandle]
		if !exists {
			return nil, "context_span_stale"
		}
		err := l.ports.Trace(ctx, ContextTraceRecord{Tags: l.tags(op), SpanHandle: parameters.SpanHandle, SpanCode: code, Action: "finish", OutcomeCode: parameters.OutcomeCode})
		delete(op.spans, parameters.SpanHandle)
		if err != nil {
			l.rememberFailure()
			return nil, "context_service_unavailable"
		}
	case "metrics.add":
		if !slices.Contains(l.ports.MetricCodes, parameters.MetricCode) {
			return nil, "context_code_undeclared"
		}
		if l.ports.Metric(ctx, ContextMetricRecord{Tags: l.tags(op), MetricCode: parameters.MetricCode, Value: parameters.Value}) != nil {
			return nil, "context_service_unavailable"
		}
	case "domainGateway.request":
		call := ContextDomainCall{RequestID: request.RequestID, BindingID: parameters.BindingID, ContractID: parameters.ContractID, Payload: bytes.Clone(parameters.Payload)}
		approved, err := l.ports.Authority.PrepareDomainCall(ctx, l.binding.Owner, cloneOperationAdmission(op.admission), call)
		if err != nil || approved.BindingID != parameters.BindingID || !contextApprovedFor(approved.Envelope, op.admission.Operation, call) {
			return nil, "context_domain_unavailable"
		}
		if ctx.Err() != nil || completed(l.done) {
			return nil, "context_operation_canceled"
		}
		result, err := l.ports.Domain(ctx, approved.Clone())
		if err != nil || strictDocument(result) != nil {
			return nil, "context_domain_unavailable"
		}
		if ctx.Err() != nil || completed(l.done) {
			return nil, "context_operation_canceled"
		}
		// Domain ownership may await I/O. Recheck the original operation before
		// returning its private result through this context's reply channel.
		if l.ports.Authority.Recheck(ctx, l.binding.Owner, cloneInstanceAdmission(l.admission), operationAdmissionPointer(op.admission)) != nil {
			return nil, "context_authority_unavailable"
		}
		if ctx.Err() != nil || completed(l.done) {
			return nil, "context_operation_canceled"
		}
		return bytes.Clone(result), "ok"
	case "domainGateway.subscribe":
		return l.subscribeDomain(ctx, op, ContextDomainCall{RequestID: request.RequestID, BindingID: parameters.BindingID, ContractID: parameters.ContractID, Payload: bytes.Clone(parameters.Payload)})
	case "domainGateway.next":
		return l.nextDomainEvent(ctx, op, parameters.SubscriptionHandle)
	case "domainGateway.unsubscribe":
		return l.unsubscribeDomain(ctx, op, parameters.SubscriptionHandle)
	default:
		return nil, "context_request_invalid"
	}
	if ctx.Err() != nil || completed(l.done) {
		return nil, "context_operation_canceled"
	}
	return []byte("null"), "ok"
}

func contextApprovedFor(raw, original []byte, call ContextDomainCall) bool {
	if strictDocument(raw) != nil {
		return false
	}
	var envelope struct {
		ContractID string          `json:"contractId"`
		Payload    json.RawMessage `json:"payload"`
		Operation  json.RawMessage `json:"operation"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.ContractID != call.ContractID || !sameContextJSON(envelope.Payload, call.Payload) || validateContextJSON("operation-context", envelope.Operation) != nil {
		return false
	}
	var source, target map[string]json.RawMessage
	if json.Unmarshal(original, &source) != nil || json.Unmarshal(envelope.Operation, &target) != nil {
		return false
	}
	for _, field := range []string{"caller", "scope", "traceId", "effectiveActorRef", "taskId", "runId", "attemptId", "delegationRef", "cancellationRef"} {
		if !sameContextJSON(source[field], target[field]) {
			return false
		}
	}
	var sourceID, targetID, causation, sourceDeadline, targetDeadline string
	if json.Unmarshal(source["operationId"], &sourceID) != nil || json.Unmarshal(target["operationId"], &targetID) != nil || json.Unmarshal(target["causationId"], &causation) != nil || json.Unmarshal(source["deadline"], &sourceDeadline) != nil || json.Unmarshal(target["deadline"], &targetDeadline) != nil {
		return false
	}
	expected, err := ContextDownstreamOperationID(sourceID, call.RequestID)
	if err != nil || targetID != expected || causation != sourceID {
		return false
	}
	before, e1 := time.Parse(time.RFC3339Nano, sourceDeadline)
	after, e2 := time.Parse(time.RFC3339Nano, targetDeadline)
	if e1 != nil || e2 != nil || after.After(before) {
		return false
	}
	// Expected entity version, payload digest, grant and approval references
	// may change for the downstream destination. Its trusted authority and
	// receiving owner must verify those bindings; equality is not authority.
	return true
}

// ContextDownstreamOperationID binds a downstream operation to its original
// operation and stable service request. Retries use the same pair and payload;
// the receiving owner remains responsible for durable deduplication/conflicts.
func ContextDownstreamOperationID(operationID, requestID string) (string, error) {
	if !registryIdentifier.MatchString(operationID) || !contextRequestID.MatchString(requestID) {
		return "", pluginError("context_request_invalid")
	}
	return fmt.Sprintf("downstream_%x", sha256.Sum256([]byte(operationID+"\x00"+requestID))), nil
}
