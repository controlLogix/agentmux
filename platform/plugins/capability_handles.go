package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"
)

// CapabilityHandles is an operation-bound set of typed remote clients. Only the
// trusted context host constructs it from an admission. No connection, service
// implementation, environment, filesystem or credentials are exposed to callers.
// Close invalidates all clients and joins calls before the context owner releases
// its original transport. It never closes borrowed services or deletes data.
type CapabilityHandles struct {
	Storage   *StorageHandle
	Artifact  *ArtifactHandle
	Secret    *SecretHandle
	Workspace *WorkspaceHandle
	Process   *ProcessHandle
	Policy    *PolicyHandle
	Decision  *DecisionHandle
	session   *capabilityHandleSession
}

// CapabilityHandlePorts are trusted host dependencies borrowed from the context.
// Domain must authenticate the owner reply; it must not return arbitrary broker data.
type CapabilityHandlePorts struct {
	Authority ContextAuthority
	Domain    func(context.Context, ContextApprovedEnvelope) ([]byte, error)
	Now       func() time.Time
}

type capabilityHandleSession struct {
	owner                    OwnerReference
	instance                 ContextInstanceAdmission
	operation                ContextOperationAdmission
	ports                    CapabilityHandlePorts
	routes                   map[string]ContextDomainBinding
	resourceIDs              []string
	until                    time.Time
	ctx                      context.Context
	cancel                   context.CancelFunc
	lifetime, parentLifetime <-chan struct{}
	mu                       sync.Mutex
	closing                  bool
	calls                    sync.WaitGroup
	joined                   chan struct{}
	permits                  chan struct{}
}

// These fixed operation IDs are registered in the shared contract registry.
// A production binding also requires an installed, authenticated owner service.
// There is deliberately no caller-selected contract or arbitrary method API.
var capabilityHandleOperations = map[string]struct{ class, action string }{
	"capability-storage-read":     {"storage", "read"},
	"capability-storage-write":    {"storage", "write"},
	"capability-artifact-read":    {"artifact", "read"},
	"capability-secret-use":       {"secret", "use"},
	"capability-workspace-read":   {"workspace", "read"},
	"capability-process-start":    {"process", "start"},
	"capability-process-cancel":   {"process", "cancel"},
	"capability-policy-evaluate":  {"policy", "evaluate"},
	"capability-outcome-query":    {"outcome", "inspect"},
	"capability-decision-request": {"decision", "request"},
}

// OpenCapabilityHandles borrows the existing authority and domain gateway. The
// ctx must be the original operation lifetime, not a temporary admission context.
// The host must pass the exact admitted operation and original instance lifetime;
// plugin-supplied JSON is not an admission. Every call rechecks current authority.
func OpenCapabilityHandles(ctx context.Context, binding ContextBinding, instance ContextInstanceAdmission, operation ContextOperationAdmission, ports CapabilityHandlePorts) (*CapabilityHandles, error) {
	if ctx == nil || ctx.Err() != nil || !contextOwnerValid(binding.Owner) || binding.Package.Pin() != binding.Owner.Pin || binding.LifetimeDone == nil ||
		(binding.Parent != nil && binding.ParentLifetime == nil) || (nilContextDependency(ports.Authority) || ports.Domain == nil || ports.Now == nil) || !contextReferenceValid(operation.AuthorityRef) {
		return nil, pluginError("capability_handles_invalid")
	}
	var claims contextOperationClaims
	if decodeContextJSON("operation-context", operation.Operation, &claims) != nil {
		return nil, pluginError("capability_handles_invalid")
	}
	var grant struct {
		SubjectInstanceID string `json:"subjectInstanceId"`
		Scope             struct {
			OrganizationID string  `json:"organizationId"`
			ProjectID      *string `json:"projectId"`
			WorkspaceID    *string `json:"workspaceId"`
		} `json:"scope"`
		Actions     []string `json:"actions"`
		ResourceIDs []string `json:"resourceIds"`
		IssuedAt    string   `json:"issuedAt"`
		ExpiresAt   string   `json:"expiresAt"`
	}
	if strictDocument(instance.EffectiveGrant) != nil || json.Unmarshal(instance.EffectiveGrant, &grant) != nil || grant.SubjectInstanceID != binding.Owner.InstanceID ||
		!capabilityIdentifiers(grant.Actions, false) || !capabilityIdentifiers(grant.ResourceIDs, true) ||
		grant.Scope.OrganizationID != claims.Scope.OrganizationID || !capabilitySameOptional(grant.Scope.ProjectID, claims.Scope.ProjectID) || !capabilitySameOptional(grant.Scope.WorkspaceID, claims.Scope.WorkspaceID) {
		return nil, pluginError("capability_handles_invalid")
	}
	issued, e1 := time.Parse(time.RFC3339Nano, grant.IssuedAt)
	expires, e2 := time.Parse(time.RFC3339Nano, grant.ExpiresAt)
	deadline, e3 := time.Parse(time.RFC3339Nano, claims.Deadline)
	now := ports.Now()
	if e1 != nil || e2 != nil || e3 != nil || now.IsZero() || !capabilityTimeValid(issued, expires, now) || !now.Before(deadline) || completed(binding.LifetimeDone) || completed(binding.ParentLifetime) {
		return nil, pluginError("capability_handle_stale")
	}
	if deadline.Before(expires) {
		expires = deadline
	}
	if len(instance.DomainBindings) > contextServiceLimit {
		return nil, pluginError("capability_handles_invalid")
	}
	routes := map[string]ContextDomainBinding{}
	seen := map[string]bool{}
	for _, route := range instance.DomainBindings {
		if !registryIdentifier.MatchString(route.ID) || seen[route.ID] {
			return nil, pluginError("capability_handles_invalid")
		}
		seen[route.ID] = true
		spec, known := capabilityHandleOperations[route.ContractID]
		if !known {
			continue
		}
		if _, duplicate := routes[route.ContractID]; duplicate || route.Action != spec.action || route.ResourceClass != spec.class {
			return nil, pluginError("capability_handles_invalid")
		}
		declared := false
		for _, d := range binding.Package.Manifest().RequestedCapabilities {
			if d.Action == spec.action && d.ResourceClass == spec.class {
				declared = true
			}
		}
		if !declared || !slices.Contains(grant.Actions, spec.action) {
			return nil, pluginError("capability_handles_invalid")
		}
		routes[route.ContractID] = route
	}
	if len(routes) == 0 {
		return nil, pluginError("capability_handles_unavailable")
	}
	check, stop := context.WithTimeout(ctx, contextCallBudget)
	err := ports.Authority.Recheck(check, binding.Owner, cloneInstanceAdmission(instance), operationAdmissionPointer(operation))
	checkErr := check.Err()
	stop()
	if err != nil || checkErr != nil || !ports.Now().Before(expires) || completed(binding.LifetimeDone) || completed(binding.ParentLifetime) {
		return nil, pluginError("capability_authority_unavailable")
	}
	lifetime, cancel := context.WithCancel(ctx)
	s := &capabilityHandleSession{owner: binding.Owner, instance: cloneInstanceAdmission(instance), operation: cloneOperationAdmission(operation), ports: ports, routes: routes,
		resourceIDs: slices.Clone(grant.ResourceIDs), until: expires, ctx: lifetime, cancel: cancel, lifetime: binding.LifetimeDone, parentLifetime: binding.ParentLifetime, joined: make(chan struct{}), permits: make(chan struct{}, contextOperationLimit)}
	h := &CapabilityHandles{session: s}
	for _, r := range routes {
		switch r.ResourceClass {
		case "storage":
			h.Storage = &StorageHandle{s}
		case "artifact":
			h.Artifact = &ArtifactHandle{s}
		case "secret":
			h.Secret = &SecretHandle{s}
		case "workspace":
			h.Workspace = &WorkspaceHandle{s}
		case "process":
			h.Process = &ProcessHandle{s}
		case "policy":
			h.Policy = &PolicyHandle{s}
		case "decision":
			h.Decision = &DecisionHandle{s}
		}
	}
	go func() {
		timer := time.NewTimer(max(expires.Sub(ports.Now()), 0))
		defer timer.Stop()
		select {
		case <-s.lifetime:
		case <-s.parentLifetime:
		case <-s.ctx.Done():
		case <-timer.C:
		}
		s.invalidate()
		s.calls.Wait()
		close(s.joined)
	}()
	return h, nil
}
func capabilitySameOptional(a, b *string) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}
func (s *capabilityHandleSession) invalidate() {
	s.mu.Lock()
	s.closing = true
	s.cancel()
	s.mu.Unlock()
}
func (h *CapabilityHandles) Close(ctx context.Context) error {
	if h == nil || h.session == nil || ctx == nil {
		return pluginError("capability_handles_invalid")
	}
	h.session.invalidate()
	select {
	case <-h.session.joined:
		return nil
	case <-ctx.Done():
		return pluginError("capability_cleanup_incomplete")
	}
}
func (CapabilityHandles) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[operation capability handles]")
}
func (CapabilityHandles) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"operation-capability-handles"}`), nil
}
func (*capabilityHandleSession) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private capability handle session]")
}

func (s *capabilityHandleSession) call(ctx context.Context, contract string, resource ContextReference, input any, out any, mutation *CapabilityMutation, prepareOnly bool) error {
	if s == nil || ctx == nil || ctx.Err() != nil || !contextReferenceValid(resource) {
		return pluginError("capability_request_invalid")
	}
	s.mu.Lock()
	if s.closing || !s.active() {
		s.mu.Unlock()
		return pluginError("capability_handle_stale")
	}
	route, exists := s.routes[contract]
	if !exists || !slices.Contains(s.resourceIDs, resource.ID) {
		s.mu.Unlock()
		return pluginError("capability_access_refused")
	}
	select {
	case s.permits <- struct{}{}:
	default:
		s.mu.Unlock()
		return pluginError("capability_capacity_exceeded")
	}
	s.calls.Add(1)
	s.mu.Unlock()
	defer func() { <-s.permits; s.calls.Done() }()
	work, cancel := context.WithTimeout(ctx, min(s.until.Sub(s.ports.Now()), contextCallBudget))
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	if s.ports.Authority.Recheck(work, s.owner, cloneInstanceAdmission(s.instance), operationAdmissionPointer(s.operation)) != nil || work.Err() != nil || !s.active() {
		return pluginError("capability_authority_unavailable")
	}
	payload, err := json.Marshal(struct {
		Resource ContextReference `json:"resourceRef"`
		Input    any              `json:"input"`
	}{resource, input})
	if err != nil || len(payload) > contextWireLimit || strictDocument(payload) != nil {
		return pluginError("capability_request_invalid")
	}
	var requestID string
	if capabilityMutationOperation(contract) {
		var err error
		requestID, err = mutation.begin(s.owner, s.operation.Operation, contract, resource, payload)
		if err != nil {
			return err
		}
		defer mutation.finish()
		if !prepareOnly {
			if _, err := mutation.Reconciliation(); err != nil {
				return err
			}
		}
	} else {
		if mutation != nil {
			return pluginError("capability_mutation_invalid")
		}
		nonce, err := randomControlID()
		if err != nil {
			return pluginError("capability_service_unavailable")
		}
		requestID = "request_" + nonce
	}
	call := ContextDomainCall{RequestID: requestID, BindingID: route.ID, ContractID: contract, Payload: payload}
	approved, err := s.ports.Authority.PrepareDomainCall(work, s.owner, cloneOperationAdmission(s.operation), call)
	if err != nil || approved.BindingID != route.ID || !contextApprovedFor(approved.Envelope, s.operation.Operation, call) {
		return pluginError("capability_authority_unavailable")
	}
	if mutation != nil {
		if err := mutation.approved(approved.Envelope); err != nil {
			return err
		}
	}
	if work.Err() != nil || !s.active() {
		return pluginError("capability_handle_stale")
	}
	if prepareOnly {
		return nil
	}
	raw, err := s.ports.Domain(work, approved.Clone())
	// Never retry uncertain effects. The owner keeps durable operation outcomes.
	if err != nil || work.Err() != nil || !s.active() {
		return pluginError("capability_outcome_unavailable")
	}
	if len(raw) > contextWireLimit || strictDocument(raw) != nil {
		return pluginError("capability_reply_invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil {
		return pluginError("capability_reply_invalid")
	}
	if s.ports.Authority.Recheck(work, s.owner, cloneInstanceAdmission(s.instance), operationAdmissionPointer(s.operation)) != nil || work.Err() != nil || !s.active() {
		return pluginError("capability_authority_unavailable")
	}
	return nil
}

func (s *capabilityHandleSession) active() bool {
	return s.ctx.Err() == nil && !completed(s.lifetime) && !completed(s.parentLifetime) && s.ports.Now().Before(s.until)
}
