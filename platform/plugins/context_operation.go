package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"sync"
	"time"
)

type contextOperationClaims struct {
	OperationID string `json:"operationId"`
	Caller      struct {
		PrincipalID              string           `json:"principalId"`
		Kind                     string           `json:"kind"`
		AuthenticatedIdentityRef ContextReference `json:"authenticatedIdentityRef"`
	} `json:"caller"`
	EffectiveActorRef ContextReference  `json:"effectiveActorRef"`
	DelegationRef     *ContextReference `json:"delegationRef"`
	Scope             struct {
		OrganizationID string  `json:"organizationId"`
		ProjectID      *string `json:"projectId"`
		WorkspaceID    *string `json:"workspaceId"`
	} `json:"scope"`
	TraceID     string `json:"traceId"`
	CausationID string `json:"causationId"`
	Deadline    string `json:"deadline"`
}

type contextOperation struct {
	handle    string
	admission ContextOperationAdmission
	claims    contextOperationClaims
	ctx       context.Context
	cancel    context.CancelFunc
	result    chan contextOperationResult
	users     sync.WaitGroup
	mu        sync.Mutex
	spans     map[string]string
}

func (l *contextLease) start() {
	go l.serviceLoop()
	go l.resultLoop()
	go func() {
		defer close(l.monitorRun)
		duration := l.grantUntil.Sub(l.ports.Now())
		timer := time.NewTimer(max(duration, 0))
		defer timer.Stop()
		select {
		case <-l.binding.LifetimeDone:
		case <-l.binding.ParentLifetime:
		case <-l.transport.Done():
		case <-l.configurationDone:
		case <-timer.C:
		case <-l.done:
		}
		l.Invalidate()
	}()
	go func() {
		<-l.done
		<-l.serviceRun
		<-l.resultRun
		<-l.monitorRun
		l.workers.Wait()
		l.transport.Close()
		<-l.transport.Done()
		close(l.workJoined)
	}()
}

func (l *contextLease) resultLoop() {
	defer close(l.resultRun)
	for {
		raw, err := l.transport.Receive(l.ctx, true)
		if err != nil {
			l.Invalidate()
			return
		}
		var result contextOperationResult
		if decodeContextJSON("plugin-context-operation", raw, &result) != nil || result.Kind != "plugin-operation-result" || result.Owner != l.binding.Owner {
			continue
		}
		l.mu.Lock()
		op := l.operations[result.OperationHandle]
		if op != nil && !l.closing && op.ctx.Err() == nil {
			select {
			case op.result <- result:
			default:
			}
		}
		l.mu.Unlock()
	}
}

func (l *contextLease) Dispatch(ctx context.Context, envelope []byte) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || strictDocument(envelope) != nil {
		return nil, pluginError("context_request_invalid")
	}
	envelope = bytes.Clone(envelope)
	l.mu.Lock()
	if l.closing || !l.binding.Lifecycle.Snapshot().Ready || completed(l.binding.Lifecycle.DrainDone()) || !l.ports.Now().Before(l.grantUntil) {
		l.mu.Unlock()
		return nil, pluginError("context_owner_stale")
	}
	select {
	case l.admissions <- struct{}{}:
	default:
		l.mu.Unlock()
		return nil, pluginError("context_capacity_exceeded")
	}
	l.workers.Add(1)
	l.mu.Unlock()
	defer l.workers.Done()
	defer func() { <-l.admissions }()
	work, cancel := context.WithCancel(ctx)
	stopLifetime := context.AfterFunc(l.ctx, cancel)
	defer stopLifetime()
	defer cancel()
	admit, stopAdmission := context.WithTimeout(work, contextCallBudget)
	defer stopAdmission()
	admission, err := l.ports.Authority.AdmitOperation(admit, l.binding.Owner, bytes.Clone(envelope))
	if err != nil {
		return nil, pluginError("context_authority_unavailable")
	}
	admission = cloneOperationAdmission(admission)
	var outer struct {
		Operation json.RawMessage `json:"operation"`
	}
	var claims contextOperationClaims
	if !contextReferenceValid(admission.AuthorityRef) || json.Unmarshal(envelope, &outer) != nil ||
		decodeContextJSON("operation-context", admission.Operation, &claims) != nil || !sameContextJSON(outer.Operation, admission.Operation) {
		return nil, pluginError("context_admission_invalid")
	}
	deadline, err := time.Parse(time.RFC3339Nano, claims.Deadline)
	remaining := min(deadline.Sub(l.ports.Now()), l.grantUntil.Sub(l.ports.Now()), 180*time.Second)
	if err != nil || remaining <= 0 || admit.Err() != nil {
		return nil, pluginError("context_operation_stale")
	}
	if l.ports.Authority.Recheck(admit, l.binding.Owner, cloneInstanceAdmission(l.admission), operationAdmissionPointer(admission)) != nil || admit.Err() != nil {
		return nil, pluginError("context_authority_unavailable")
	}
	stopAdmission()
	nonce, err := randomControlID()
	if err != nil {
		return nil, err
	}
	// Admission work consumes the signed deadline; it cannot renew it.
	remaining = min(deadline.Sub(l.ports.Now()), l.grantUntil.Sub(l.ports.Now()), remaining)
	if remaining <= 0 {
		return nil, pluginError("context_operation_stale")
	}
	opContext, opCancel := context.WithTimeout(work, remaining)
	op := &contextOperation{handle: "operation_" + nonce, admission: admission, claims: claims, ctx: opContext, cancel: opCancel,
		result: make(chan contextOperationResult, 1), spans: map[string]string{}}
	l.mu.Lock()
	if l.closing || !l.binding.Lifecycle.Snapshot().Ready || completed(l.binding.Lifecycle.DrainDone()) || len(l.operations) >= contextOperationLimit || op.ctx.Err() != nil {
		l.mu.Unlock()
		opCancel()
		return nil, pluginError("context_capacity_exceeded")
	}
	for _, existing := range l.operations {
		if existing.claims.OperationID == claims.OperationID {
			l.mu.Unlock()
			opCancel()
			return nil, pluginError("context_operation_repeated")
		}
	}
	l.operations[op.handle] = op
	l.mu.Unlock()
	defer l.finishOperation(op)
	invoke := contextJSON(map[string]any{"schemaVersion": "1.0.0", "kind": "plugin-operation-invoke", "owner": l.binding.Owner,
		"operationHandle": op.handle, "operation": json.RawMessage(admission.Operation), "envelope": json.RawMessage(envelope)})
	if validateContextJSON("plugin-context-operation", invoke) != nil {
		return nil, pluginError("context_request_invalid")
	}
	send, stop := context.WithTimeout(op.ctx, contextCallBudget)
	err = l.transport.Publish(send, l.bootstrap.transport.InvokeSubject, invoke)
	stop()
	if err != nil {
		l.Invalidate()
		return nil, pluginError("context_transport_unavailable")
	}
	select {
	case result := <-op.result:
		if op.ctx.Err() != nil || completed(l.done) {
			return nil, pluginError("context_operation_canceled")
		}
		check, stopCheck := context.WithTimeout(op.ctx, contextCallBudget)
		err := l.ports.Authority.Recheck(check, l.binding.Owner, cloneInstanceAdmission(l.admission), operationAdmissionPointer(admission))
		checkErr := check.Err()
		stopCheck()
		if err != nil || checkErr != nil {
			return nil, pluginError("context_authority_unavailable")
		}
		if result.Outcome != "completed" {
			return nil, pluginError("context_operation_failed")
		}
		return bytes.Clone(result.Value), nil
	case <-op.ctx.Done():
		reason := "canceled"
		if completed(l.done) {
			reason = "owner_stale"
		} else if op.ctx.Err() == context.DeadlineExceeded {
			reason = "deadline"
		}
		message := contextJSON(map[string]any{"schemaVersion": "1.0.0", "kind": "plugin-operation-cancel", "owner": l.binding.Owner, "operationHandle": op.handle, "reason": reason})
		// The original transport stays owned until Dispatch joins. This bounded
		// cancellation notice does not claim that a remote business effect stopped.
		cleanup, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
		_ = l.transport.Publish(cleanup, l.bootstrap.transport.CancelSubject, message)
		stop()
		return nil, pluginError("context_operation_canceled")
	}
}

func (l *contextLease) finishOperation(op *contextOperation) {
	// Service admission holds this same mutex while checking cancellation and
	// adding a user. No new user may appear after the join starts.
	l.mu.Lock()
	op.cancel()
	l.mu.Unlock()
	op.users.Wait()
	l.joinOperationSubscriptions(op)
	for handle, code := range op.spans {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		err := l.ports.Trace(cleanup, ContextTraceRecord{Tags: l.tags(op), SpanHandle: handle, SpanCode: code, Action: "finish", OutcomeCode: "canceled"})
		cancel()
		if err != nil {
			l.rememberFailure()
		}
		delete(op.spans, handle)
	}
	l.mu.Lock()
	delete(l.operations, op.handle)
	l.mu.Unlock()
}

func operationAdmissionPointer(a ContextOperationAdmission) *ContextOperationAdmission {
	copy := cloneOperationAdmission(a)
	return &copy
}

func sameContextJSON(a, b []byte) bool {
	// This compares duplicated JSON values. It does not produce canonical signing
	// bytes or verify a signature; those remain the enrolled authority's duty.
	if strictDocument(a) != nil || strictDocument(b) != nil {
		return false
	}
	var first, second any
	left, right := json.NewDecoder(bytes.NewReader(a)), json.NewDecoder(bytes.NewReader(b))
	left.UseNumber()
	right.UseNumber()
	// Distinct numeric spellings are conservatively refused. Converting payload
	// numbers to float64 could accept a different signed value after rounding.
	return left.Decode(&first) == nil && right.Decode(&second) == nil && reflect.DeepEqual(first, second)
}

func (l *contextLease) tags(op *contextOperation) ContextTags {
	tags := ContextTags{Owner: l.binding.Owner, HubID: l.bootstrap.transportHub()}
	if op != nil {
		tags.OperationID, tags.PrincipalID, tags.CallerKind = op.claims.OperationID, op.claims.Caller.PrincipalID, op.claims.Caller.Kind
		identity, actor := op.claims.Caller.AuthenticatedIdentityRef, op.claims.EffectiveActorRef
		tags.AuthenticatedIdentityRef, tags.EffectiveActorRef = &identity, &actor
		if op.claims.DelegationRef != nil {
			delegation := *op.claims.DelegationRef
			tags.DelegationRef = &delegation
		}
		tags.OrganizationID, tags.TraceID, tags.CausationID = op.claims.Scope.OrganizationID, op.claims.TraceID, op.claims.CausationID
		if op.claims.Scope.ProjectID != nil {
			value := *op.claims.Scope.ProjectID
			tags.ProjectID = &value
		}
		if op.claims.Scope.WorkspaceID != nil {
			value := *op.claims.Scope.WorkspaceID
			tags.WorkspaceID = &value
		}
	}
	return tags
}

func (b ContextBootstrap) transportHub() string {
	var descriptor struct {
		HubID string `json:"hubId"`
	}
	_ = json.Unmarshal(b.descriptor, &descriptor)
	return descriptor.HubID
}
